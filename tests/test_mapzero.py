"""Tests for MapZero: nmap XML parsing, topology building and the store."""

import os
import sys
import tempfile
import unittest
import unittest.mock

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

    def test_findings_survive_a_save_and_load(self):
        """A saved map keeps the findings, so reopening shows them."""
        with tempfile.TemporaryDirectory() as tmp:
            original = topology.SAVE_DIR
            topology.SAVE_DIR = tmp
            try:
                topo = topology.build_topology(self.hosts, gateway="10.0.0.1")
                topo["nodes"][0]["findings"] = [
                    {"cve": "CVE-2021-44228", "cvss": 10.0,
                     "severity": "critical", "title": "Log4Shell",
                     "source": "nmap"},
                ]
                path = topology.save_topology(topo, name="test")
                loaded = topology.load_topology(path)
                self.assertEqual(loaded["nodes"][0]["findings"][0]["cve"],
                                 "CVE-2021-44228")
            finally:
                topology.SAVE_DIR = original

    def test_a_rebuild_keeps_the_findings(self):
        """A rescan must not throw away what a check already found."""
        topo = topology.build_topology(self.hosts, gateway="10.0.0.1")
        topo["nodes"][0]["findings"] = [{"cve": "CVE-1", "cvss": 9.0,
                                         "severity": "critical"}]
        again = topology.build_topology(self.hosts, gateway="10.0.0.1",
                                         previous=topo)
        self.assertEqual(again["nodes"][0]["findings"][0]["cve"], "CVE-1")

    def test_a_rebuild_keeps_the_detailed_service_names(self):
        """The product and version a deep scan found are not lost."""
        topo = topology.build_topology(self.hosts, gateway="10.0.0.1")
        topo["nodes"][0]["services"] = [{"port": 22, "name": "ssh (OpenSSH 8.4)"}]
        again = topology.build_topology(self.hosts, gateway="10.0.0.1",
                                         previous=topo)
        self.assertEqual(again["nodes"][0]["services"][0]["name"],
                         "ssh (OpenSSH 8.4)")


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


class ScanCmdTest(unittest.TestCase):
    def test_targets_are_separate_args(self):
        """nmap must get one target per argv entry.

        Joining targets with ", " makes nmap try to resolve "10.0.0.1," and
        fail, which silently fell back to scanning every host on its own.
        """
        import netscan

        seen = {}

        def fake_run(cmd, timeout=300, cancelled=None):
            seen["cmd"] = cmd
            return "<nmaprun></nmaprun>", "", False, 0

        original = netscan._run_cancellable
        netscan._run_cancellable = fake_run
        try:
            netscan.scan_network("10.0.0.0/30")
        finally:
            netscan._run_cancellable = original
        cmd = seen["cmd"]
        self.assertEqual(cmd[-2:], ["10.0.0.1", "10.0.0.2"])
        for target in cmd[-2:]:
            self.assertNotIn(" ", target)

    def test_empty_chunk_is_not_rescanned_host_by_host(self):
        """A chunk of dead hosts yields no XML, but nmap did not fail.

        Rescanning it host by host turned a 10 s /24 sweep into minutes.
        """
        import netscan

        calls = []

        def fake_run(cmd, timeout=300, cancelled=None):
            calls.append(cmd)
            return "<nmaprun></nmaprun>", "", False, 0

        original = netscan._run_cancellable
        netscan._run_cancellable = fake_run
        try:
            netscan.scan_network("10.0.0.0/30")
        finally:
            netscan._run_cancellable = original
        self.assertEqual(len(calls), 1)

    def test_a_failing_nmap_is_reported(self):
        """A broken scan must say so, not look like an empty network."""
        import netscan

        def fake_run(cmd, timeout=300, cancelled=None):
            return "", "nmap: unrecognized option '--bogus'\n", False, 255

        original = netscan._run_cancellable
        netscan._run_cancellable = fake_run
        try:
            hosts, error = netscan.scan_network("10.0.0.0/30")
        finally:
            netscan._run_cancellable = original
        self.assertEqual(hosts, [])
        self.assertIn("unrecognized option", error)

    def test_an_empty_but_successful_scan_is_not_an_error(self):
        """No hosts on the wire is a result, not a failure."""
        import netscan

        def fake_run(cmd, timeout=300, cancelled=None):
            return "<nmaprun></nmaprun>", "", False, 0

        original = netscan._run_cancellable
        netscan._run_cancellable = fake_run
        try:
            hosts, error = netscan.scan_network("10.0.0.0/30")
        finally:
            netscan._run_cancellable = original
        self.assertEqual(hosts, [])
        self.assertEqual(error, "")


class FramebufferTest(unittest.TestCase):
    def test_mismatched_framebuffer_is_refused(self):
        """The app must not draw 320x170 into an arbitrary framebuffer."""
        import mapzero

        class FakeFd:
            pass

        with unittest.mock.patch("os.open", return_value=FakeFd()), \
                unittest.mock.patch("fcntl.ioctl") as ioctl:
            def fake_ioctl(fd, request, buf, mutate):
                import struct
                struct.pack_into("=II", buf, 0, 1920, 1080)
                return 0

            ioctl.side_effect = fake_ioctl
            with self.assertRaises(OSError):
                mapzero.check_framebuffer(FakeFd())


if __name__ == "__main__":
    unittest.main()
