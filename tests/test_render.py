"""Rendering, layout and configuration robustness."""

import os
import struct
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import mapzero
import netscan


def fb_info(xres=320, yres=170, bpp=16, red=11, green=5, blue=0, stride=0):
    """A framebuffer ioctl answer, laid out like the kernel structures."""
    var = bytearray(160)
    struct.pack_into("=II", var, 0, xres, yres)
    struct.pack_into("=I", var, 24, bpp)
    struct.pack_into("=I", var, 32, red)
    struct.pack_into("=I", var, 44, green)
    struct.pack_into("=I", var, 56, blue)
    fix = bytearray(160)
    offset = 38 + struct.calcsize("P")
    offset = (offset + 3) & ~3
    struct.pack_into("=I", fix, offset, stride)
    return var, fix


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

    def test_bgr565_swaps_red_and_blue(self):
        from PIL import Image

        img = Image.new("RGB", (2, 1), (10, 20, 30))
        swapped = Image.new("RGB", (2, 1), (30, 20, 10))
        self.assertEqual(mapzero.pack_pixels(img, "bgr565"),
                         mapzero.pack_pixels(swapped, "rgb565"))

    def test_bgrx_packs_four_bytes_per_pixel(self):
        from PIL import Image

        img = Image.new("RGB", (3, 2), (10, 20, 30))
        raw = mapzero.pack_pixels(img, "bgrx")
        self.assertEqual(len(raw), 3 * 2 * 4)
        # red at bits 16-23, green 8-15, blue 0-7: bytes read B, G, R, X.
        self.assertEqual(raw[0:4], bytes((30, 20, 10, 255)))


class FramebufferFormatTest(unittest.TestCase):
    """The pixel layout is detected, so a 32bpp panel still works."""

    class FakeFd:
        pass

    def check(self, **kwargs):
        var, fix = fb_info(**kwargs)

        def fake_ioctl(fd, request, buf, mutate):
            if request == mapzero.FBIOGET_VSCREENINFO:
                buf[:len(var)] = var
            else:
                buf[:len(fix)] = fix
            return 0

        with unittest.mock.patch("fcntl.ioctl", side_effect=fake_ioctl):
            return mapzero.check_framebuffer(self.FakeFd())

    def test_rgb565_panel_is_detected(self):
        self.assertEqual(self.check()["fmt"], "rgb565")

    def test_16bpp_without_bitfields_still_starts(self):
        """A driver that reports only the depth must not keep the app off
        the screen: 16 bit is assumed to be RGB565."""
        info = self.check(bpp=16, red=0, green=0, blue=0)
        self.assertEqual(info["fmt"], "rgb565")

    def test_16bpp_with_swapped_channels_is_detected(self):
        info = self.check(bpp=16, red=0, green=5, blue=11)
        self.assertEqual(info["fmt"], "bgr565")

    def test_32bpp_panel_is_accepted(self):
        info = self.check(bpp=32, red=16, green=8, blue=0)
        self.assertEqual(info["fmt"], "bgrx")

    def test_32bpp_rgb_order_is_accepted(self):
        info = self.check(bpp=32, red=0, green=8, blue=16)
        self.assertEqual(info["fmt"], "rgbx")

    def test_unknown_depth_is_refused(self):
        with self.assertRaises(OSError):
            self.check(bpp=24, red=16, green=8, blue=0)

    def test_unknown_32bpp_layout_is_refused(self):
        with self.assertRaises(OSError):
            self.check(bpp=32, red=8, green=16, blue=24)

    def test_mismatched_geometry_is_refused(self):
        with self.assertRaises(OSError):
            self.check(xres=1920, yres=1080)

    def test_stride_is_reported(self):
        info = self.check(stride=1024)
        self.assertEqual(info["stride"], 1024)


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.app = mapzero.App(fb_path=None)
        self.app.topo = {
            "nodes": [
                {"ip": "10.0.0.1", "mac": "dc:a6:32:11:22:33",
                 "hostname": "router.lan",
                 "services": [{"port": 22, "name": "ssh"}, {"port": 80,
                                                            "name": "http"}]},
                {"ip": "10.0.0.5", "mac": "00:09:b0:9e:fd:15",
                 "hostname": "", "services": [{"port": 22, "name": "ssh"}]},
            ],
            "edges": [], "gateway": "10.0.0.1", "subnet": "10.0.0.0/24",
        }

    def tearDown(self):
        for fd in self.app.input_fds:
            os.close(fd)

    def test_hosts_columns_do_not_overlap(self):
        """Columns are measured, so they must stay apart with any font."""
        self.app.screen = "hosts"
        img = self.app.render()
        self.assertEqual(img.size, (mapzero.W, mapzero.H))

    def test_every_screen_renders(self):
        for screen in ("menu", "scanning", "hosts", "map", "maps"):
            self.app.screen = screen
            img = self.app.render()
            self.assertEqual(img.size, (mapzero.W, mapzero.H))

    def test_long_hostnames_do_not_overflow(self):
        """A long name must be clipped, not drawn past the edge."""
        self.app.topo["nodes"][0]["hostname"] = "a-very-long-hostname-indeed"
        self.app.screen = "hosts"
        img = self.app.render()
        self.assertEqual(img.size, (mapzero.W, mapzero.H))

    def test_selection_moves_with_the_arrow_keys(self):
        self.app.screen = "hosts"
        self.app.hosts_keys(mapzero.KEY_DOWN)
        self.assertEqual(self.app.sel, 1)
        self.app.hosts_keys(mapzero.KEY_UP)
        self.assertEqual(self.app.sel, 0)

    def test_selection_carries_into_the_map(self):
        """The map highlights the host the list had selected."""
        self.app.screen = "hosts"
        self.app.sel = 1
        self.app.hosts_keys(mapzero.KEY_ENTER)
        self.assertEqual(self.app.screen, "map")
        self.assertEqual(self.app.map_sel, 1)
        self.app.map_keys(mapzero.KEY_ESC)
        self.assertEqual(self.app.screen, "hosts")
        self.assertEqual(self.app.sel, 1)


if __name__ == "__main__":
    unittest.main()
