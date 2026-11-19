"""End-to-end run loop: the app must react to real key events."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero


class RunLoopTest(unittest.TestCase):
    def setUp(self):
        # A regular file works as a framebuffer for mmap purposes.
        self.fb = tempfile.NamedTemporaryFile(delete=False)
        self.fb.write(b"\0" * (mapzero.W * mapzero.H * mapzero.BPP))
        self.fb.flush()
        self.fb.close()

        self.app = mapzero.App(fb_path=self.fb.name)
        self.keys = []
        self.original_read = mapzero.read_keycodes

    def tearDown(self):
        mapzero.read_keycodes = self.original_read
        if self.app.mm is not None:
            self.app.mm.close()
        if self.app.fd is not None:
            os.close(self.app.fd)
        os.unlink(self.fb.name)

    def run_frames(self, frames):
        """Drive the real run() loop for the given key batches."""
        queue = [list(k) for k in frames]

        def fake_read(fds, timeout=0.15):
            if not queue:
                raise SystemExit(0)
            return queue.pop(0)

        mapzero.read_keycodes = fake_read
        try:
            self.app.run()
        except SystemExit:
            pass

    def test_menu_scan_flow_through_run_loop(self):
        self.app.start_scan = lambda silent=False: setattr(
            self.app, "screen", "scanning"
        )
        self.run_frames([[mapzero.KEY_ENTER]])
        self.assertEqual(self.app.screen, "scanning")

    def test_esc_during_scan_cancels(self):
        self.app.start_scan = lambda silent=False: setattr(
            self.app, "screen", "scanning"
        )
        self.run_frames([[mapzero.KEY_ENTER], [mapzero.KEY_ESC]])
        self.assertTrue(self.app.scanner.cancelled)
        # A scan the user called off is not an error, and the view they
        # came from is still there.
        self.assertEqual(self.app.screen, "menu")
        self.assertEqual(self.app.error, "")
        self.assertIn("stopped", self.app.status)

    def test_cancelling_a_rescan_stays_on_the_hosts_screen(self):
        self.app.scan_origin = "hosts"
        self.app.screen = "scanning"
        self.run_frames([[mapzero.KEY_ESC]])
        self.assertEqual(self.app.screen, "hosts")
        self.assertTrue(self.app.scanner.cancelled)

    def test_framebuffer_is_written(self):
        """The app must actually put pixels into the framebuffer."""
        self.run_frames([[]])
        with open(self.fb.name, "rb") as fh:
            data = fh.read()
        self.assertTrue(any(data), "framebuffer stayed blank")


if __name__ == "__main__":
    unittest.main()
