"""nmap-driven host discovery for MapZero.

Everything here shells out to nmap and parses its XML output; no nmap
internals are reimplemented. Discovery uses an unprivileged TCP connect scan
(-sT) so the app works without root on the Cardputer Zero.

nmap XML reference: https://nmap.org/book/man-brief-output.html
"""

import ipaddress
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

NMAP = "nmap"

# Ports that identify a host quickly. Kept short on purpose: a connect scan
# to a closed port has to time out, so every extra port costs scan time.
QUICK_PORTS = "22,23,53,80,443,445,554,8080,8443"

# Hosts per nmap invocation. Chunking gives the UI real progress and keeps
# one slow host from stalling the whole scan.
CHUNK_SIZE = 64


@dataclass
class Port:
    number: int
    proto: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    ports: list = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.hostname or self.ip

    @property
    def open_ports(self) -> list:
        return [p for p in self.ports if p.state == "open"]


def _run(cmd, timeout=300):
    """Run a command, return stdout as text. Returns "" on any failure."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout


def _run_cancellable(cmd, timeout=300, cancelled=None):
    """Run a command, killing it when `cancelled()` becomes true.

    Returns (stdout, stderr, was_cancelled). nmap is stopped with SIGTERM so
    it does not keep burning CPU on a battery-powered device after the user
    left the scan screen.
    """
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except OSError:
        return "", "", False

    was_cancelled = False
    deadline = time.time() + timeout if timeout else None
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=0.5)
                return out, err, was_cancelled
            except subprocess.TimeoutExpired:
                if cancelled is not None and cancelled():
                    was_cancelled = True
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


def local_addresses():
    """Return (ipv4, gateway) for the primary interface."""
    routes = _run(["ip", "-4", "route"])
    addr = ""
    gw = ""
    for line in routes.splitlines():
        m = re.match(r"default via (\S+).*src (\S+)", line)
        if m and not gw:
            gw, addr = m.group(1), m.group(2)
    if not addr:
        addrs = _run(["ip", "-4", "-o", "addr", "show"])
        for line in addrs.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", line)
            if m and not m.group(1).startswith("127."):
                addr = m.group(1)
                break
    return addr, gw


def local_cidr() -> str:
    """Return the network of this device as 'a.b.c.0/nn'.

    The prefix comes from the interface address, so a /23 or /16 network is
    scanned in full instead of just its first /24.
    """
    addr, _gw = local_addresses()
    if not addr:
        return ""
    prefix = _interface_prefix(addr)
    net = ipaddress.ip_network("%s/%d" % (addr, prefix), strict=False)
    return str(net)


def _interface_prefix(addr: str) -> int:
    """Return the prefix length configured on the interface holding addr."""
    try:
        out = _run(["ip", "-4", "-o", "addr", "show"])
    except OSError:
        out = ""
    for line in out.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m and m.group(1) == addr:
            return int(m.group(2))
    return 24


def gateway_ip() -> str:
    """Return the default gateway address, or ""."""
    return local_addresses()[1]


def arp_table():
    """Return {ip: mac} from the kernel ARP cache."""
    table = {}
    try:
        with open("/proc/net/arp") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "0x0":
                    table[parts[0]] = parts[3]
    except OSError:
        pass
    return table


def parse_nmap_xml(xml_text: str) -> list:
    """Parse nmap XML into a list of Host objects."""
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    arp = arp_table()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor", "")
        if not ip:
            continue
        if set(mac) <= {"0", ":"}:
            mac = ""  # nmap's placeholder for "could not resolve the MAC"
        if not mac:
            mac = arp.get(ip, "")
        if set(mac) <= {"0", ":"}:
            mac = ""

        hostname = ""
        for hn in host.findall("hostnames"):
            for name in hn.findall("hostname"):
                if name.get("name"):
                    hostname = name.get("name")
                    break
            if hostname:
                break

        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            ports.append(
                Port(
                    number=int(port.get("portid")),
                    proto=port.get("protocol", "tcp"),
                    state=state.get("state") if state is not None else "unknown",
                    service=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                )
            )

        hosts.append(Host(ip=ip, mac=mac, hostname=hostname, ports=ports))
    return hosts


def _chunk_hosts(network, size):
    hosts = list(network.hosts())
    for i in range(0, len(hosts), size):
        yield hosts[i : i + size]


def _nmap_refused_targets(stderr: str) -> bool:
    """True when nmap complained about the target list itself.

    An empty result set is normal (a chunk of dead hosts), so only a real
    resolution error justifies rescanning the chunk host by host.
    """
    return "Failed to resolve" in stderr or "Error resolving" in stderr


def scan_network(cidr: str, thorough: bool = False, timeout=180, progress=None,
                 cancelled=None):
    """Scan a CIDR and return (hosts, error).

    `hosts` is a list of Host. `error` is "" on success or a message the UI
    can show (missing nmap, timeout, ...). `progress` is an optional callable
    invoked with (text, chunks_done, chunks_total, hosts_found) after every
    chunk, so the UI can draw a progress bar and a live host count.
    `cancelled` is an optional callable; when it returns True the running
    nmap is terminated and the scan stops.
    """
    if not os.path.exists("/usr/bin/" + NMAP) and not _which(NMAP):
        return [], "nmap is not installed (apt install nmap)"

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return [], "bad subnet: %s" % exc

    def stopped():
        return cancelled is not None and cancelled()

    chunks = list(_chunk_hosts(network, CHUNK_SIZE))
    hosts = []
    for index, chunk in enumerate(chunks):
        if stopped():
            return hosts, "scan cancelled"
        if progress:
            progress("scanning %s" % cidr, index, len(chunks), len(hosts))
        cmd = [NMAP, "-sT", "-n", "--max-retries", "0",
               "--host-timeout", "30s"]
        if thorough:
            cmd += ["--top-ports", "100"]
        else:
            cmd += ["-p", QUICK_PORTS]
        cmd += ["-oX", "-"] + [str(h) for h in chunk]
        out, err, was_cancelled = _run_cancellable(cmd, timeout=timeout,
                                                   cancelled=stopped)
        if was_cancelled:
            return hosts, "scan cancelled"
        found = parse_nmap_xml(out)
        if not found and _nmap_refused_targets(err):
            # nmap could not use the target list; retry one host at a time.
            found = []
            for host in chunk:
                if stopped():
                    return hosts, "scan cancelled"
                single = cmd[:-len(chunk)] + [str(host)]
                out, err, was_cancelled = _run_cancellable(single, timeout=60,
                                                           cancelled=stopped)
                if was_cancelled:
                    return hosts, "scan cancelled"
                found += parse_nmap_xml(out)
        hosts += found
        if progress:
            progress("scanning %s" % cidr, index + 1, len(chunks), len(hosts))

    return hosts, ""


def _which(name):
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""
