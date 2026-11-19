"""Topology model + on-disk store for MapZero.

The topology is a graph: the gateway is the root, discovered hosts hang off
it, and every host carries its open ports and any vulnerabilities found on
it. It is saved as JSON so a scan can be reopened later without re-scanning.
"""

import json
import os
import time

SAVE_DIR = os.path.expanduser("~/.local/share/mapzero/maps")
SAVE_FORMAT = 2


def _node_from_host(host):
    services = []
    for port in host.open_ports:
        label = port.service or "unknown"
        if port.product:
            label += " (%s" % port.product
            if port.version:
                label += " %s" % port.version
            label += ")"
        services.append({"port": port.number, "name": label})
    return {
        "ip": host.ip,
        "mac": host.mac,
        "hostname": host.hostname,
        "services": services,
        "findings": [],
    }


def build_topology(hosts, gateway="", subnet="", previous=None):
    """Build a topology dict from scanned hosts.

    `previous` is an earlier topology: its findings and the product and
    version details are carried over, so a rescan does not throw away what
    a vulnerability check already learned.
    """
    old = {}
    for node in (previous or {}).get("nodes", []):
        old[node.get("ip")] = node

    nodes = []
    seen = set()
    for host in hosts:
        if host.ip in seen:
            continue
        seen.add(host.ip)
        node = _node_from_host(host)
        before = old.get(host.ip)
        if before:
            node["findings"] = list(before.get("findings", []))
            node["services"] = _merge_services(before.get("services", []),
                                               node["services"])
        nodes.append(node)

    edges = []
    if gateway:
        for node in nodes:
            if node["ip"] == gateway:
                continue
            edges.append({"from": gateway, "to": node["ip"]})

    return {
        "format": SAVE_FORMAT,
        "created": time.time(),
        "subnet": subnet,
        "gateway": gateway,
        "nodes": nodes,
        "edges": edges,
    }


def _merge_services(before, after):
    """Combine the known services with the ones just detected.

    A service the deep scan found carries a product and a version; the
    quick scan only knows the port. The richer label wins.
    """
    merged = {}
    for service in before:
        merged[service.get("port")] = service
    for service in after:
        port = service.get("port")
        known = merged.get(port)
        if known and len(known.get("name", "")) > len(service.get("name", "")):
            merged[port] = known
        else:
            merged[port] = service
    return [merged[p] for p in sorted(merged)]


def save_dir():
    os.makedirs(SAVE_DIR, exist_ok=True)
    return SAVE_DIR


def save_topology(topology, name=""):
    """Save a topology, return the file path."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(topology.get("created", time.time())))
    filename = "%s-%s.json" % (name or "map", stamp)
    path = os.path.join(save_dir(), filename)
    with open(path, "w") as fh:
        json.dump(topology, fh, indent=1)
    return path


def list_maps():
    """Return saved map files, newest first."""
    try:
        names = os.listdir(save_dir())
    except OSError:
        return []
    maps = []
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(save_dir(), name)
        try:
            maps.append((os.path.getmtime(path), path))
        except OSError:
            continue
    maps.sort(reverse=True)
    return [path for _mtime, path in maps]


def load_topology(path):
    """Load a topology file, return the dict or None."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def delete_topology(path):
    try:
        os.remove(path)
    except OSError:
        pass
