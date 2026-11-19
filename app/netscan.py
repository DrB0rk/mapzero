"""nmap-driven host discovery for MapZero.

Everything here shells out to nmap and parses its XML output; no nmap
internals are reimplemented. Discovery uses an unprivileged TCP connect scan
(-sT) so the app works without root on the Cardputer Zero.

nmap XML reference: https://nmap.org/book/man-brief-output.html
"""

import ipaddress
import os
import re
import socket
import subprocess
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
    """Return the /24 network of this device as 'a.b.c.0/24'."""
    addr, _gw = local_addresses()
    if not addr:
        return ""
    net = ipaddress.ip_network(addr + "/24", strict=False)
    return str(net)


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
        if not mac:
            mac = arp.get(ip, "")

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


def scan_network(cidr: str, thorough: bool = False, timeout=180, progress=None):
    """Scan a CIDR and return (hosts, error).

    `hosts` is a list of Host. `error` is "" on success or a message the UI
    can show (missing nmap, timeout, ...). `progress` is an optional callable
    invoked with a human-readable status string after every chunk.
    """
    if not os.path.exists("/usr/bin/" + NMAP) and not _which(NMAP):
        return [], "nmap is not installed (apt install nmap)"

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return [], "bad subnet: %s" % exc

    chunks = list(_chunk_hosts(network, CHUNK_SIZE))
    hosts = []
    for index, chunk in enumerate(chunks):
        if progress:
            progress("scanning %s (%d/%d)" % (cidr, index + 1, len(chunks)))
        cmd = [NMAP, "-sT", "-n", "-Pn", "--max-retries", "0",
               "--host-timeout", "30s"]
        if thorough:
            cmd += ["--top-ports", "100"]
        else:
            cmd += ["-p", QUICK_PORTS]
        cmd += ["-oX", "-", ", ".join(str(h) for h in chunk)]
        found = parse_nmap_xml(_run(cmd, timeout=timeout))
        if not found:
            # Some nmap builds refuse host lists with commas; retry one by one.
            found = []
            for host in chunk:
                single = cmd[:-1] + [str(host)]
                found += parse_nmap_xml(_run(single, timeout=60))
        hosts += found

    return hosts, ""


def scan_host(ip: str, timeout=120):
    """Detail scan of a single host: version detection on all ports."""
    cmd = [NMAP, "-sT", "-n", "-Pn", "--max-retries", "0",
           "-sV", "--version-light", "-p", "1-1024", "-oX", "-", ip]
    hosts = parse_nmap_xml(_run(cmd, timeout=timeout))
    return hosts[0] if hosts else Host(ip=ip)


def reverse_lookup(ip: str, timeout=1.5):
    """Best-effort reverse DNS. Returns "" when it does not resolve."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def _which(name):
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""
