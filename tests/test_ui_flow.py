"""Headless drive of the MapZero UI: simulated keys, stubbed scan."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero
import netscan
import topology


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
        self.app.menu_index = 0
        self.keys = [mapzero.KEY_DOWN]
        self.app.menu_keys(self.keys[0])
        self.assertEqual(self.app.menu_index, 1)
        self.keys = [mapzero.KEY_DOWN, mapzero.KEY_DOWN]
        for code in self.keys:
            self.app.menu_keys(code)
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


if __name__ == "__main__":
    unittest.main()
