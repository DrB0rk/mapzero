"""Rendering, layout and configuration robustness."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero
import netscan


class LabelTest(unittest.TestCase):
    def test_non_ascii_hostname_falls_back_to_ip_octet(self):
        node = {"ip": "10.0.0.5", "hostname": "naïve-høst"}
        self.assertEqual(mapzero.host_label(node), "10.0.0.5".split(".")[-1])

    def test_ascii_hostname_is_used(self):
        node = {"ip": "10.0.0.5", "hostname": "nas"}
        self.assertEqual(mapzero.host_label(node), "nas")

    def test_empty_hostname_falls_back(self):
        node = {"ip": "10.0.0.5", "hostname": "  "}
        self.assertEqual(mapzero.host_label(node), "5")


class ConfigTest(unittest.TestCase):
    def test_bad_refresh_value_is_ignored(self):
        self.assertEqual(mapzero._int_or_zero("abc"), 0)
        self.assertEqual(mapzero._int_or_zero(None), 0)
        self.assertEqual(mapzero._int_or_zero(-5), 0)
        self.assertEqual(mapzero._int_or_zero("30"), 30)

    def test_zero_mac_is_treated_as_unknown(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host><status state="up" reason="user-set"/>
        <address addr="10.0.0.9" addrtype="ipv4"/>
        <address addr="00:00:00:00:00:00" addrtype="mac"/>
        <hostnames></hostnames>
        <ports><port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh"/></port></ports></host></nmaprun>"""
        hosts = netscan.parse_nmap_xml(xml)
        self.assertEqual(hosts[0].mac, "")


class Rgb565Test(unittest.TestCase):
    def test_packing_matches_reference(self):
        """The fast translate-table packing must be bit-identical."""
        import random
        from PIL import Image

        random.seed(11)
        img = Image.new("RGB", (mapzero.W, mapzero.H))
        px = img.load()
        for y in range(mapzero.H):
            for x in range(mapzero.W):
                px[x, y] = (random.randrange(256), random.randrange(256),
                            random.randrange(256))

        expected = bytearray()
        for y in range(mapzero.H):
            for x in range(mapzero.W):
                r, g, b = px[x, y]
                v = mapzero.rgb565(r, g, b)
                expected += bytes((v & 0xFF, (v >> 8) & 0xFF))

        self.assertEqual(mapzero.image_to_rgb565(img), bytes(expected))


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.app = mapzero.App(fb_path=None)

    def tearDown(self):
        for fd in self.app.input_fds:
            os.close(fd)

    def test_hosts_columns_do_not_overlap(self):
        """Columns are measured, so they must stay apart with any font."""
        self.app.topo = {
            "nodes": [
                {"ip": "10.0.0.150", "mac": "00:09:b0:9e:fd:15",
                 "hostname": "", "services": [{"port": 80}, {"port": 8080}]},
            ],
            "edges": [], "gateway": "", "subnet": "",
        }
        self.app.screen = "hosts"
        img = self.app.render()
        self.assertEqual(img.size, (mapzero.W, mapzero.H))

    def test_framebuffer_bpp_mismatch_is_refused(self):
        import fcntl
        import struct
        import unittest.mock

        class FakeFd:
            pass

        def fake_ioctl(fd, request, buf, mutate):
            struct.pack_into("=II", buf, 0, 320, 170)
            struct.pack_into("=I", buf, 24, 32)
            return 0

        with unittest.mock.patch("fcntl.ioctl", side_effect=fake_ioctl):
            with self.assertRaises(OSError):
                mapzero.check_framebuffer(FakeFd())


if __name__ == "__main__":
    unittest.main()
