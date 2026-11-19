"""Vulnerability scanning for MapZero.

Two engines, both driven by real tools rather than reimplemented here:

  nmap    - NSE scripts from the "vuln" category. nmap is already a
            dependency, so this works on a bare device.
  nuclei  - the nuclei binary, when it is installed. It needs a template
            directory; without one it does nothing, so its absence is
            reported rather than treated as a failure.

Both produce the same Finding records, so the UI does not care which engine
found what. A scan can target one host or the whole network.
"""

import json
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

NMAP = "nmap"
NUCLEI = "nuclei"

# NSE scripts that only report a problem, without sending anything that
# could break the service they are testing.
NSE_SCRIPTS = "vuln and safe"

# Where nuclei keeps its templates. The binary is useless without them.
NUCLEI_TEMPLATE_PATHS = (
    os.path.expanduser("~/.config/nuclei-templates"),
    os.path.expanduser("~/nuclei-templates"),
    "/usr/share/nuclei-templates",
    "/opt/nuclei-templates",
)

# CVSS v3 bands, high to low.
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    """One vulnerability, from whichever engine found it."""

    cve: str = ""
    cvss: float = 0.0
    title: str = ""
    host: str = ""
    source: str = ""          # "nmap" or "nuclei"
    script: str = ""

    @property
    def severity(self):
        """The band this finding falls into, by its CVSS score."""
        if self.cvss >= 9.0:
            return "critical"
        if self.cvss >= 7.0:
            return "high"
        if self.cvss >= 4.0:
            return "medium"
        if self.cvss > 0.0:
            return "low"
        return "info"

    @property
    def label(self):
        return self.cve or self.title or self.script or "finding"


def severity_rank(name):
    """Sort key for a severity name, most severe first."""
    try:
        return SEVERITIES.index(name)
    except ValueError:
        return len(SEVERITIES)


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# vulners prints one finding per line: a CPE, then tab separated
# "CVE-XXXX-YYYY <cvss> <url>" fields.
_VULNERS_LINE = re.compile(
    r"(CVE-\d{4}-\d+)\s+(\d+(?:\.\d+)?)", re.IGNORECASE)
# Other NSE scripts put the score in the free text.
_CVSS_LINE = re.compile(r"CVSS(?:\s*[:=]\s*|\s+)(\d+(?:\.\d+)?)",
                        re.IGNORECASE)
_CVE_LINE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def parse_nmap_findings(xml_text, ip=""):
    """Pull findings out of an nmap XML scan.

    Two shapes matter: the vulners script, which lists CVEs with a score,
    and the per-vulnerability scripts, whose output mentions the CVE in
    prose and sometimes the score.
    """
    findings = []
    if not xml_text.strip():
        return findings
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        host_ip = address.get("addr") if address is not None else ip
        for script in host.iter("script"):
            script_id = script.get("id") or ""
            output = script.get("output") or ""
            if not output.strip():
                continue
            if script_id == "vulners":
                findings += _parse_vulners(output, host_ip)
            elif "vuln" in script_id:
                findings += _parse_vuln_script(script_id, output, host_ip)
    return findings


def _parse_vulners(output, host_ip):
    """Parse the vulners script output: CPE lines with CVE and CVSS."""
    findings = []
    for line in output.splitlines():
        # A line can carry more than one CVE, so every match counts.
        for match in _VULNERS_LINE.finditer(line):
            cve = match.group(1).upper()
            cvss = _float(match.group(2))
            title = ""
            if "cpe:" in line:
                title = line.split("\t")[0].strip()
                title = title.replace("cpe:/", "").replace(":", " ").strip()
            findings.append(Finding(cve=cve, cvss=cvss, title=title[:48],
                                     host=host_ip, source="nmap",
                                     script="vulners"))
    return findings


def _parse_vuln_script(script_id, output, host_ip):
    """Parse the output of a single vulnerability script."""
    findings = []
    cve = ""
    match = _CVE_LINE.search(output)
    if match:
        cve = match.group(0).upper()
    cvss = 0.0
    score = _CVSS_LINE.search(output)
    if score:
        cvss = _float(score.group(1))
    title = ""
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith("ERROR") and "CVSS" not in line:
            title = line
            break
    if not (cve or title):
        return findings
    findings.append(Finding(cve=cve, cvss=cvss, title=title[:48],
                             host=host_ip, source="nmap", script=script_id))
    return findings


def parse_nmap_services(xml_text):
    """Pull the detected services out of an nmap XML scan.

    Returns {ip: [{port, name, product, version}]} for the open ports. The
    product and version are what make a service worth reporting: "http" on
    its own says little, "nginx 1.18.0" says a lot.
    """
    services = {}
    if not xml_text.strip():
        return services
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return services
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
        ip = address.get("addr")
        found = []
        for port in host.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            service = port.find("service")
            try:
                number = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            found.append({
                "port": number,
                "name": (service.get("name") if service is not None else "") or "",
                "product": (service.get("product") if service is not None else "") or "",
                "version": (service.get("version") if service is not None else "") or "",
            })
        if found:
            services[ip] = found
    return services


def parse_nuclei_findings(text):
    """Parse nuclei's JSONL output into findings."""
    findings = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        info = record.get("info") or {}
        classification = info.get("classification") or {}
        cve = ""
        cves = classification.get("cve-id") or []
        if cves:
            cve = cves[0].upper()
        severity = (info.get("severity") or "").lower()
        cvss = _float(classification.get("cvss-score"))
        if not cvss and severity:
            cvss = {"critical": 9.5, "high": 8.0, "medium": 5.5,
                    "low": 2.5}.get(severity, 0.0)
        findings.append(Finding(
            cve=cve,
            cvss=cvss,
            title=(info.get("name") or "")[:48],
            host=record.get("matched-at") or record.get("host") or "",
            source="nuclei",
            script=record.get("template-id") or "",
        ))
    return findings


def nuclei_templates():
    """The template directory to use, or None when there is none."""
    env = os.environ.get("NUCLEI_TEMPLATES")
    if env and os.path.isdir(env):
        return env
    for path in NUCLEI_TEMPLATE_PATHS:
        if os.path.isdir(path) and os.listdir(path):
            return path
    return None


def nuclei_binary():
    """The nuclei executable, or None when it is not installed."""
    return shutil.which(NUCLEI)


def has_nuclei():
    """True when nuclei and its templates are both present."""
    return bool(nuclei_binary()) and bool(nuclei_templates())


def _run_child(cmd, timeout, cancelled):
    """Run a scanner, stopping it as soon as the user cancels.

    Returns (stdout, stderr, was_cancelled). The child is polled, so a
    cancel takes effect at once instead of waiting out the whole timeout -
    on a device this small that matters, and a scanner left running would
    keep eating the battery.
    """
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        return "", str(exc), False

    deadline = time.time() + timeout if timeout else None
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=0.5)
                return out, err, False
            except subprocess.TimeoutExpired:
                if cancelled is not None and cancelled():
                    proc.terminate()
                    try:
                        out, err = proc.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        out, err = proc.communicate()
                    return out, err, True
                if deadline and time.time() > deadline:
                    proc.kill()
                    out, err = proc.communicate()
                    return out, err, False
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def run_nmap_vuln(targets, ports="", timeout=300, cancelled=None,
                   progress=None, scripts=NSE_SCRIPTS, service_scan=False):
    """Run an nmap pass over the given targets: services and vulnerabilities.

    Returns (findings, error, services). The scan is a plain connect scan
    with the vuln NSE scripts attached, so it needs no root. With
    `service_scan` the port set is widened and the versions are detected,
    which is what a single host check wants.
    """
    if not targets:
        return [], "", {}
    cmd = [NMAP, "-sT", "-n", "-T4", "--script", scripts,
           "--script-timeout", "30s", "--host-timeout", "60s"]
    if service_scan:
        # A single host is worth the wider port set and the version probes.
        cmd += ["-sV", "--top-ports", "100"]
    elif ports:
        cmd += ["-p", ports]
    cmd += ["-oX", "-"] + list(targets)
    out, err, was_cancelled = _run_child(cmd, timeout, cancelled)
    if was_cancelled:
        return [], "scan cancelled", {}
    findings = parse_nmap_findings(out)
    services = parse_nmap_services(out)
    if progress:
        progress("nmap vuln scan", 1, 1, len(findings))
    if not findings and err and "nmap" in err[:40].lower():
        return findings, err.strip().splitlines()[0][:60], services
    return findings, "", services


def run_nuclei(targets, timeout=600, cancelled=None, progress=None):
    """Run nuclei over the given targets.

    Returns (findings, error). Nuclei needs a template directory; without
    one it cannot run at all, and that is reported rather than hidden.
    """
    binary = nuclei_binary()
    if not binary:
        return [], "nuclei is not installed"
    templates = nuclei_templates()
    if not templates:
        return [], "nuclei has no templates"

    # -duc: do not phone home for an update check on every scan.
    cmd = [binary, "-jsonl", "-silent", "-no-color", "-duc", "-t", templates]
    for target in targets:
        cmd += ["-u", target]
    out, err, was_cancelled = _run_child(cmd, timeout, cancelled)
    if was_cancelled:
        return [], "scan cancelled"
    findings = parse_nuclei_findings(out)
    if progress:
        progress("nuclei scan", 1, 1, len(findings))
    return findings, ""


def scan(targets, ports="", engines=("nmap", "nuclei"), timeout=600,
         cancelled=None, progress=None, service_scan=False):
    """Run the requested engines over the targets.

    Returns (findings, error, services). The engines are independent: one
    failing does not stop the other, and the error names what did not work.
    The services are what nmap detected, so the caller can show the
    products and versions it found.
    """
    findings = []
    problems = []
    services = {}
    for engine in engines:
        if cancelled is not None and cancelled():
            return findings, "scan cancelled", services
        if engine == "nmap":
            found, error, found_services = run_nmap_vuln(
                targets, ports=ports, timeout=timeout, cancelled=cancelled,
                progress=progress, service_scan=service_scan)
            services.update(found_services)
        elif engine == "nuclei":
            found, error = run_nuclei(targets, timeout=timeout,
                                      cancelled=cancelled, progress=progress)
        else:
            continue
        findings += found
        if error:
            problems.append(error)
    # The same CVE can be reported by both engines; keep the worst score.
    merged = {}
    for finding in findings:
        key = (finding.host, finding.cve or finding.script, finding.title)
        previous = merged.get(key)
        if previous is None or finding.cvss > previous.cvss:
            merged[key] = finding
    unique = list(merged.values())
    unique.sort(key=lambda f: (-f.cvss, f.cve or f.title))
    error = "; ".join(problems)
    return unique, error, services
