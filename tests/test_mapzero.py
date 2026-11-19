"""Tests for MapZero: nmap XML parsing, topology building and the store."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import netscan
import topology

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -oX - 10.0.0.0/24" start="1" version="7.94">
<host><status state="up" reason="arp-response"/>
 <address addr="10.0.0.1" addrtype="ipv4"/>
 <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
 <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
 <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4"/></port>
  <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port></ports>
</host>
<host><status state="up" reason="conn-refused"/>
 <address addr="10.0.0.5" addrtype="ipv4"/>
 <address addr="11:22:33:44:55:66" addrtype="mac"/>
 <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port></ports>
</host>
<host><status state="down" reason="no-response"/>
 <address addr="10.0.0.9" addrtype="ipv4"/>
</host>
</nmaprun>
"""


class ParseTest(unittest.TestCase):
    def test_only_up_hosts_are_returned(self):
        hosts = netscan.parse_nmap_xml(NMAP_XML)
        self.assertEqual([h.ip for h in hosts], ["10.0.0.1", "10.0.0.5"])

    def test_ports_services_and_hostname(self):
        host = netscan.parse_nmap_xml(NMAP_XML)[0]
        self.assertEqual(host.hostname, "router.lan")
        self.assertEqual(host.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual([p.number for p in host.open_ports], [22])
        self.assertEqual(host.open_ports[0].service, "ssh")
        self.assertEqual(host.open_ports[0].product, "OpenSSH")

    def test_empty_and_broken_xml(self):
        self.assertEqual(netscan.parse_nmap_xml(""), [])
        self.assertEqual(netscan.parse_nmap_xml("<not xml"), [])


class TopologyTest(unittest.TestCase):
    def setUp(self):
        self.hosts = netscan.parse_nmap_xml(NMAP_XML)
        self.topo = topology.build_topology(
            self.hosts, gateway="10.0.0.1", subnet="10.0.0.0/24"
        )

    def test_graph_shape(self):
        self.assertEqual(len(self.topo["nodes"]), 2)
        self.assertEqual(self.topo["gateway"], "10.0.0.1")
        # the gateway itself is not linked to itself
        self.assertEqual([e["to"] for e in self.topo["edges"]], ["10.0.0.5"])

    def test_services_carry_port_and_label(self):
        node = self.topo["nodes"][0]
        self.assertEqual(node["services"], [{"port": 22, "name": "ssh (OpenSSH 8.4)"}])

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = topology.SAVE_DIR
            topology.SAVE_DIR = tmp
            try:
                path = topology.save_topology(self.topo, name="test")
                self.assertTrue(os.path.exists(path))
                loaded = topology.load_topology(path)
                self.assertEqual(loaded["nodes"], self.topo["nodes"])
                self.assertEqual([os.path.basename(p) for p in topology.list_maps()],
                                 [os.path.basename(path)])
                topology.delete_topology(path)
                self.assertEqual(topology.list_maps(), [])
            finally:
                topology.SAVE_DIR = original


class RenderTest(unittest.TestCase):
    """The screens must render without a framebuffer present."""

    def test_screens_render(self):
        import mapzero

        app = mapzero.App(fb_path=None)
        try:
            app.topo = topology.build_topology(
                netscan.parse_nmap_xml(NMAP_XML), gateway="10.0.0.1"
            )
            for screen in ("menu", "hosts", "map", "maps"):
                app.screen = screen
                img = app.render()
                self.assertEqual(img.size, (mapzero.W, mapzero.H))
        finally:
            for fd in app.input_fds:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
