"""Headless drive of the MapZero UI: simulated keys, stubbed scan."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero
import netscan
import topology
import vulnscan


class UiFlowTest(unittest.TestCase):
    def setUp(self):
        self.app = mapzero.App(fb_path=None)
        self.keys = []
        self.app_module_keys = mapzero.read_keycodes

        def fake_read(fds, timeout=0.15):
            out = self.keys
            self.keys = []
            return out

        mapzero.read_keycodes = fake_read

    def tearDown(self):
        mapzero.read_keycodes = self.app_module_keys
        for fd in self.app.input_fds:
            os.close(fd)

    def stub_scan(self):
        hosts = []
        for ip, name in (("10.0.0.1", "router.lan"), ("10.0.0.5", "nas")):
            h = netscan.Host(ip=ip, mac="AA:BB:CC:00:00:01", hostname=name)
            h.ports.append(
                netscan.Port(number=22, proto="tcp", state="open", service="ssh")
            )
            hosts.append(h)
        self.app.scanner.hosts = hosts
        self.app.scanner.error = ""
        self.app.scanner.done = True

    def test_menu_scan_then_hosts_then_map(self):
        self.app.start_scan()
        self.assertEqual(self.app.screen, "scanning")

        self.stub_scan()
        self.app.finish_scan()
        self.assertEqual(self.app.screen, "hosts")
        self.assertEqual(len(self.app.topo["nodes"]), 2)

        self.keys = [mapzero.KEY_ENTER]
        self.app.hosts_keys(self.keys[0])
        self.assertEqual(self.app.screen, "map")

        self.keys = [mapzero.KEY_ESC]
        self.app.map_keys(self.keys[0])
        self.assertEqual(self.app.screen, "hosts")

    def test_save_writes_a_map(self):
        self.app.start_scan()
        self.stub_scan()
        self.app.finish_scan()

        import tempfile
        original = topology.SAVE_DIR
        with tempfile.TemporaryDirectory() as tmp:
            topology.SAVE_DIR = tmp
            try:
                self.keys = [mapzero.KEY_S]
                self.app.hosts_keys(self.keys[0])
                self.assertEqual(len(topology.list_maps()), 1)
                self.assertIn("saved", self.app.status)
            finally:
                topology.SAVE_DIR = original

    def test_menu_navigation_wraps(self):
        count = len(mapzero.MENU)
        self.app.menu_index = 0
        self.keys = [mapzero.KEY_DOWN]
        self.app.menu_keys(self.keys[0])
        self.assertEqual(self.app.menu_index, 1)
        for _ in range(count - 1):
            self.app.menu_keys(mapzero.KEY_DOWN)
        self.assertEqual(self.app.menu_index, 0)  # wrapped around

    def test_saved_maps_screen_lists_and_opens(self):
        import tempfile
        original = topology.SAVE_DIR
        with tempfile.TemporaryDirectory() as tmp:
            topology.SAVE_DIR = tmp
            try:
                topo = topology.build_topology([], gateway="10.0.0.1")
                topology.save_topology(topo, name="demo")
                self.app.maps = topology.list_maps()
                self.assertEqual(len(self.app.maps), 1)
                self.app.open_map(self.app.maps[0])
                self.assertEqual(self.app.screen, "hosts")
            finally:
                topology.SAVE_DIR = original

    def test_delete_asks_twice(self):
        """One stray D must not wipe a saved map."""
        import tempfile
        original = topology.SAVE_DIR
        with tempfile.TemporaryDirectory() as tmp:
            topology.SAVE_DIR = tmp
            try:
                topo = topology.build_topology([], gateway="10.0.0.1")
                topology.save_topology(topo, name="demo")
                self.app.maps = topology.list_maps()
                self.app.screen = "maps"

                self.app.maps_keys(mapzero.KEY_D)
                self.assertTrue(self.app.confirm_delete)
                self.assertEqual(len(topology.list_maps()), 1)

                self.app.maps_keys(mapzero.KEY_D)
                self.assertFalse(self.app.confirm_delete)
                self.assertEqual(len(topology.list_maps()), 0)
            finally:
                topology.SAVE_DIR = original

    def test_v_key_checks_the_selected_host(self):
        """V runs a vulnerability scan of the host under the cursor."""
        hosts = []
        for ip in ("10.0.0.1", "10.0.0.5"):
            h = netscan.Host(ip=ip, mac="", hostname="")
            h.ports.append(netscan.Port(number=22, proto="tcp", state="open",
                                         service="ssh"))
            hosts.append(h)
        self.app.topo = topology.build_topology(hosts, gateway="10.0.0.1")
        self.app.screen = "hosts"
        self.app.sel = 1

        started = {}
        self.app.vuln_scanner.start = lambda targets, **kw: started.update(
            targets=targets, **kw)
        self.app.hosts_keys(mapzero.KEY_V)
        self.assertEqual(self.app.screen, "vulnscan")
        self.assertEqual(started["targets"], ["10.0.0.5"])
        # Only the ports that host actually has open are worth checking.
        self.assertEqual(started["ports"], "22")

    def test_checking_the_whole_network_targets_every_host(self):
        hosts = []
        for ip in ("10.0.0.1", "10.0.0.5"):
            hosts.append(netscan.Host(ip=ip, mac="", hostname=""))
        self.app.topo = topology.build_topology(hosts, gateway="10.0.0.1")
        self.app.screen = "hosts"

        started = {}
        self.app.vuln_scanner.start = lambda targets, **kw: started.update(
            targets=targets, **kw)
        self.app.start_vuln_scan(whole_network=True)
        self.assertEqual(self.app.screen, "vulnscan")
        self.assertEqual(started["targets"], ["10.0.0.1", "10.0.0.5"])

    def test_findings_land_on_the_vulnerability_screen(self):
        self.app.findings = []
        self.app.vuln_scanner.findings = [
            vulnscan.Finding(cve="CVE-2021-44228", cvss=10.0,
                             title="Log4Shell", host="10.0.0.1"),
        ]
        self.app.vuln_scanner.error = ""
        self.app.vuln_origin = "hosts"
        self.app.finish_vuln_scan()
        self.assertEqual(self.app.screen, "vulns")
        self.assertEqual(len(self.app.findings), 1)

    def test_vulnerability_screen_scrolls(self):
        self.app.findings = [vulnscan.Finding(cve="CVE-%d" % i, cvss=5.0)
                             for i in range(4)]
        self.app.screen = "vulns"
        self.app.vulns_keys(mapzero.KEY_DOWN)
        self.assertEqual(self.app.vuln_index, 1)
        self.app.vulns_keys(mapzero.KEY_UP)
        self.assertEqual(self.app.vuln_index, 0)

    def test_escape_leaves_the_vulnerability_screen(self):
        self.app.screen = "vulns"
        self.app.vuln_origin = "hosts"
        self.app.vulns_keys(mapzero.KEY_ESC)
        self.assertEqual(self.app.screen, "hosts")

    def test_escape_cancels_a_delete(self):
        import tempfile
        original = topology.SAVE_DIR
        with tempfile.TemporaryDirectory() as tmp:
            topology.SAVE_DIR = tmp
            try:
                topo = topology.build_topology([], gateway="10.0.0.1")
                topology.save_topology(topo, name="demo")
                self.app.maps = topology.list_maps()
                self.app.screen = "maps"
                self.app.maps_keys(mapzero.KEY_D)
                self.app.maps_keys(mapzero.KEY_ESC)
                self.assertFalse(self.app.confirm_delete)
                self.assertEqual(self.app.screen, "maps")
                self.assertEqual(len(topology.list_maps()), 1)
            finally:
                topology.SAVE_DIR = original

    def test_saved_maps_list_scrolls_to_the_selection(self):
        """More than seven saved maps must still be reachable."""
        import tempfile
        original = topology.SAVE_DIR
        with tempfile.TemporaryDirectory() as tmp:
            topology.SAVE_DIR = tmp
            try:
                topo = topology.build_topology([], gateway="10.0.0.1")
                for i in range(12):
                    topology.save_topology(topo, name="net%02d" % i)
                self.app.maps = topology.list_maps()
                self.app.screen = "maps"
                for _ in range(9):
                    self.app.maps_keys(mapzero.KEY_DOWN)
                self.app.render()
                self.assertEqual(self.app.map_index, 9)
                # The window followed the selection, so the highlighted row
                # is on screen.
                self.assertGreater(self.app.scroll, 0)
                self.assertLessEqual(self.app.map_index,
                                     self.app.scroll + 6)
            finally:
                topology.SAVE_DIR = original

    def test_map_highlight_matches_the_selected_host(self):
        """With many hosts the map must still point at the right machine."""
        hosts = []
        for i in range(30):
            h = netscan.Host(ip="10.0.0.%d" % (i + 1), mac="",
                             hostname="host%d" % i)
            h.ports.append(netscan.Port(number=22, proto="tcp", state="open",
                                         service="ssh"))
            hosts.append(h)
        self.app.topo = topology.build_topology(hosts, gateway="10.0.0.1",
                                                 subnet="10.0.0.0/24")
        self.app.screen = "hosts"
        self.app.sel = 20
        self.app.hosts_keys(mapzero.KEY_ENTER)
        self.assertEqual(self.app.screen, "map")
        self.app.render()
        self.assertEqual(self.app.map_sel, 20)


if __name__ == "__main__":
    unittest.main()
