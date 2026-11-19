"""Cancellation and rescan behaviour."""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero
import netscan


class CancelTest(unittest.TestCase):
    def test_scan_stops_when_cancelled(self):
        """A cancelled scan returns promptly and kills the nmap child."""
        state = {"stop": False}

        def cancelled():
            return state["stop"]

        def flip():
            time.sleep(1.0)
            state["stop"] = True

        import threading
        threading.Thread(target=flip, daemon=True).start()

        start = time.time()
        hosts, error = netscan.scan_network(
            "10.255.255.0/24", cancelled=cancelled, timeout=60
        )
        elapsed = time.time() - start
        self.assertEqual(error, "scan cancelled")
        self.assertLess(elapsed, 30, "cancelled scan did not stop early")

    def test_no_nmap_process_survives_cancel(self):
        before = subprocess.run(["pgrep", "-c", "nmap"], capture_output=True,
                                text=True).stdout.strip() or "0"
        state = {"stop": False}

        def cancelled():
            return state["stop"]

        import threading
        threading.Thread(target=lambda: (time.sleep(1.0), state.update(stop=True)),
                         daemon=True).start()
        netscan.scan_network("10.255.255.0/24", cancelled=cancelled, timeout=60)
        time.sleep(1.5)
        after = subprocess.run(["pgrep", "-c", "nmap"], capture_output=True,
                               text=True).stdout.strip() or "0"
        self.assertLessEqual(int(after), int(before))


class RescanTest(unittest.TestCase):
    def setUp(self):
        self.app = mapzero.App(fb_path=None)

    def tearDown(self):
        for fd in self.app.input_fds:
            os.close(fd)

    def test_r_key_triggers_silent_rescan(self):
        self.app.topo = {"nodes": [], "edges": [], "gateway": "", "subnet": ""}
        self.app.screen = "hosts"
        started = {}
        self.app.start_scan = lambda silent=False: started.setdefault("silent", silent)
        self.app.hosts_keys(mapzero.KEY_R)
        self.assertTrue(started.get("silent"))

    def test_auto_refresh_rescans_when_interval_set(self):
        self.app.refresh_interval = 1
        self.app.screen = "hosts"
        self.app.last_refresh = 0
        started = {}
        self.app.start_scan = lambda silent=False: started.setdefault("silent", silent)
        self.app.maybe_auto_refresh()
        self.assertTrue(started.get("silent"))

    def test_auto_refresh_off_by_default(self):
        self.app.refresh_interval = 0
        self.app.screen = "hosts"
        started = {}
        self.app.start_scan = lambda silent=False: started.setdefault("silent", silent)
        self.app.maybe_auto_refresh()
        self.assertFalse(started)


if __name__ == "__main__":
    unittest.main()
