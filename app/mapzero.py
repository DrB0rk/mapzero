#!/usr/bin/env python3
"""MapZero - network topology mapper for the M5 Cardputer Zero.

Scans the local network with nmap, draws the resulting topology on the
320x170 framebuffer and saves it as JSON.

Keys:
  Up/Down (or F/X)  - move in menus
  Enter             - select
  S                 - save the current map
  D                 - delete the selected saved map
  Esc               - back / quit
"""

import glob
import json
import math
import mmap
import os
import select
import struct
import subprocess
import sys
import threading
import time

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import netscan
import topology

FB_DEV = "/dev/fb0"
W, H = 320, 170
BPP = 2
FBIOGET_VSCREENINFO = 0x4600

FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
)
CONFIG_PATH = os.path.expanduser("~/.config/mapzero/config.json")

EV_FORMAT = "llHHi"
EV_SIZE = struct.calcsize(EV_FORMAT)
EV_KEY = 0x01

KEY_ESC = 1
KEY_ENTER = 28
KEY_UP = 103
KEY_DOWN = 108
KEY_LEFT = 105
KEY_RIGHT = 106
KEY_F = 33
KEY_X = 45
KEY_Z = 44
KEY_C = 46
KEY_S = 31
KEY_D = 32
KEY_R = 19

BG = (16, 18, 22)
FG = (222, 226, 232)
DIM = (130, 136, 146)
ACCENT = (230, 106, 44)
OK = (58, 125, 68)
WARN = (185, 74, 44)

MENU = ("Scan network", "Saved maps", "Quit")


def rgb565(r, g, b):
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)


# Byte-wise maps for the RGB565 packing, so the hot loop runs in C.
_R5 = bytes(i & 0xF8 for i in range(256))
_GHI = bytes(i >> 5 for i in range(256))
_GLO = bytes((i & 0x1C) << 3 for i in range(256))
_BLO = bytes((i & 0xF8) >> 3 for i in range(256))


def image_to_rgb565(img):
    """Pack an RGB image into little-endian RGB565 bytes.

    PIL has no RGB565 mode, so the packing is done here. Each channel is
    mapped through a translate table (C speed) and the two bytes are
    interleaved with a slice assignment (also C speed).
    """
    raw = img.tobytes()
    # high byte = (r & 0xF8) | (g >> 5)
    high = bytes(x | y for x, y in
                 zip(raw[0::3].translate(_R5), raw[1::3].translate(_GHI)))
    # low byte = ((g & 0x1C) << 3) | ((b & 0xF8) >> 3)
    low = bytes(x | y for x, y in
                zip(raw[1::3].translate(_GLO), raw[2::3].translate(_BLO)))
    out = bytearray(len(raw) // 3 * 2)
    out[0::2] = low
    out[1::2] = high
    return bytes(out)


def load_font(size):
    for path in FONT_PATHS:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                pass
    return ImageFont.load_default()


def _int_or_zero(value):
    """Coerce a config value to a non-negative int, 0 on anything odd."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0


def host_label(node):
    """A short, drawable label for a host: hostname else the last octet.

    Names from mDNS or DNS can be non-ASCII, which the bitmap fallback font
    cannot draw at all. Rather than mangle them into a wrong name, fall back
    to the address.
    """
    name = (node.get("hostname") or "").strip()
    if not name or not all(32 <= ord(ch) < 127 for ch in name):
        return node["ip"].split(".")[-1]
    return name[:8]


def read_config():
    try:
        with open(CONFIG_PATH) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def open_input_devices():
    """Open every /dev/input/event* node in non-blocking mode."""
    fds = []
    candidates = []
    env = os.environ.get("INPUT_DEV", "").strip()
    if env:
        candidates.append(env)
    candidates.extend(sorted(glob.glob("/dev/input/event*")))
    seen = set()
    for path in candidates:
        try:
            real = os.path.realpath(path)
        except OSError:
            real = path
        if real in seen:
            continue
        seen.add(real)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            continue
        fds.append(fd)
    return fds


def read_keycodes(fds, timeout=0.15):
    """Return the keycodes pressed since the last call."""
    pressed = []
    if not fds:
        return pressed
    try:
        dr, _, _ = select.select(fds, [], [], timeout)
    except (OSError, ValueError):
        return pressed
    for fd in dr:
        try:
            data = os.read(fd, EV_SIZE * 64)
        except (BlockingIOError, OSError):
            continue
        for off in range(0, len(data) - EV_SIZE + 1, EV_SIZE):
            _s, _us, etype, code, value = struct.unpack(
                EV_FORMAT, data[off:off + EV_SIZE]
            )
            if etype == EV_KEY and value == 1:
                pressed.append(code)
    return pressed


class Scanner:
    """Runs an nmap scan in a thread and reports progress.

    `cancel()` stops the scan: the running nmap is terminated and no further
    chunks are started.
    """

    def __init__(self):
        self.hosts = []
        self.error = ""
        self.done = False
        self.progress = ""
        self.cancelled = False
        self._thread = None

    def start(self, cidr, thorough=False):
        """Start a scan, replacing any scan that is still running."""
        self.stop()
        self.hosts = []
        self.error = ""
        self.done = False
        self.cancelled = False
        self.progress = "scanning %s" % cidr
        self._thread = threading.Thread(
            target=self._run, args=(cidr, thorough), daemon=True
        )
        self._thread.start()

    def stop(self):
        """Cancel a running scan and wait for its thread to finish."""
        if self._thread is None:
            return
        self.cancelled = True
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._thread = None

    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def cancel(self):
        """Ask the running scan to stop."""
        self.cancelled = True

    def is_cancelled(self):
        return self.cancelled

    def _set_progress(self, text):
        self.progress = text

    def _run(self, cidr, thorough):
        try:
            hosts, error = netscan.scan_network(
                cidr,
                thorough=thorough,
                progress=self._set_progress,
                cancelled=self.is_cancelled,
            )
        except Exception as exc:  # keep the UI alive on any scan failure
            self.error = str(exc)
            self.done = True
            return
        self.hosts = hosts
        self.error = error
        self.done = True


def check_framebuffer(fd):
    """Refuse to draw on a framebuffer that is not the device's 320x170 panel.

    Writing 320x170 of pixels into an arbitrary framebuffer corrupts whatever
    else is using it, so fail loudly instead. The pixel depth matters too:
    RGB565 data on a 32bpp panel would come out as garbage colours.
    """
    try:
        import fcntl
        import struct as _struct
        buf = bytearray(160)
        fcntl.ioctl(fd, FBIOGET_VSCREENINFO, buf, True)
        xres, yres = _struct.unpack("=II", bytes(buf[:8]))
        bpp = _struct.unpack("=I", bytes(buf[24:28]))[0]
    except OSError:
        return  # cannot query: trust the device
    if (xres, yres) != (W, H):
        raise OSError(
            "%s is %dx%d, expected %dx%d" % (FB_DEV, xres, yres, W, H)
        )
    if bpp and bpp != BPP * 8:
        raise OSError(
            "%s is %d bpp, expected %d" % (FB_DEV, bpp, BPP * 8)
        )


class App:
    def __init__(self, fb_path=FB_DEV):
        self.font = load_font(13)
        self.font_sm = load_font(11)
        self.font_title = load_font(15)
        self.screen = "menu"
        self.menu_index = 0
        self.scroll = 0
        self.maps = []
        self.map_index = 0
        self.topo = None
        self.gateway = ""
        self.subnet = ""
        self.status = ""
        self.error = ""
        self.silent_scan = False
        self.refresh_interval = _int_or_zero(read_config().get("refresh", 0))
        self.last_refresh = time.time()
        self.scanner = Scanner()
        self.fd = None
        self.mm = None
        self._last_raw = None
        if fb_path is not None:
            self.fd = os.open(fb_path, os.O_RDWR)
            check_framebuffer(self.fd)
            try:
                self.mm = mmap.mmap(self.fd, W * H * BPP, mmap.MAP_SHARED,
                                    mmap.PROT_WRITE | mmap.PROT_READ)
            except (OSError, ValueError) as exc:
                raise OSError("cannot map %dx%d framebuffer: %s"
                              % (W, H, exc))
        self.input_fds = open_input_devices()

    # ---------------- rendering ----------------

    def blit(self, img):
        if self.mm is None:
            return
        raw = img.tobytes()
        if raw == self._last_raw:
            return  # nothing changed: skip the expensive conversion
        self._last_raw = raw
        self.mm.seek(0)
        self.mm.write(image_to_rgb565(img))

    def new_image(self):
        return Image.new("RGB", (W, H), BG)

    def header(self, draw, title, right=""):
        draw.rectangle([0, 0, W - 1, 17], fill=(28, 32, 38))
        draw.text((5, 2), title, font=self.font_title, fill=ACCENT)
        if right:
            draw.text((W - 5 - draw.textlength(right, font=self.font_sm), 4),
                      right, font=self.font_sm, fill=DIM)

    def footer(self, draw, text):
        draw.line([(0, H - 14), (W - 1, H - 14)], fill=(40, 44, 50))
        draw.text((5, H - 13), text, font=self.font_sm, fill=DIM)

    def draw_menu(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        self.header(d, "MapZero", "v1.0")
        y = 30
        for i, item in enumerate(MENU):
            color = ACCENT if i == self.menu_index else FG
            if i == self.menu_index:
                d.rectangle([2, y - 2, W - 3, y + 13], outline=ACCENT)
            d.text((10, y), item, font=self.font, fill=color)
            y += 20
        if self.error:
            d.text((8, H - 44), self.error[:52], font=self.font_sm, fill=WARN)
        self.footer(d, "Up/Down select   Enter open   Esc quit")
        return img

    def draw_scanning(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        self.header(d, "Scanning", self.subnet)
        d.text((10, 40), self.scanner.progress or "starting nmap...", font=self.font,
               fill=FG)
        d.text((10, 62), "nmap is running. Esc cancels the scan.",
               font=self.font_sm, fill=DIM)
        self.footer(d, "Esc cancel scan")
        return img

    def draw_hosts(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        self.header(d, "Hosts", "%d found" % len(self.topo["nodes"]))
        nodes = self.topo["nodes"]
        rows = 8
        visible = nodes[self.scroll:self.scroll + rows]

        def mac_of(node):
            mac = (node.get("mac") or "").strip()
            if set(mac) <= {"0", ":"}:  # nmap's "unknown" MAC
                return ""
            return mac[:17]

        def fit_services(node):
            """Shorten the port list until it fits the remaining width."""
            ports = [str(s["port"]) for s in node["services"][:8]]
            while ports:
                text = ",".join(ports)
                if x_svc + d.textlength(text, font=self.font_sm) <= W - 4:
                    return text
                ports.pop()
            return ""

        # Measure the columns instead of guessing x positions: the font is
        # wider than the bitmap fallback on the device.
        ip_w = max([d.textlength(n["ip"], font=self.font_sm) for n in visible]
                   or [0])
        mac_w = max([d.textlength(mac_of(n), font=self.font_sm) for n in visible]
                    or [0])
        x_ip = 6
        x_mac = int(x_ip + ip_w + 6)
        x_svc = int(x_mac + mac_w + 8)

        y = 22
        for node in visible:
            d.text((x_ip, y), node["ip"], font=self.font_sm, fill=FG)
            mac = mac_of(node)
            if mac:
                d.text((x_mac, y), mac, font=self.font_sm, fill=DIM)
            svc = fit_services(node)
            if svc:
                d.text((x_svc, y), svc, font=self.font_sm, fill=OK)
            y += 15
        if not nodes:
            d.text((10, 60), "no hosts found", font=self.font, fill=DIM)
        if self.status:
            d.text((6, H - 26), self.status[:40], font=self.font_sm, fill=DIM)
        self.footer(d, "Enter map   R rescan   S save   Esc back")
        return img

    def draw_map(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        nodes = self.topo["nodes"]
        self.header(d, "Topology", "%d hosts" % len(nodes))
        cx, cy = W // 2, (H + 16) // 2
        radius = 52

        gw = self.topo.get("gateway") or ""
        gw_node = next((n for n in nodes if n["ip"] == gw), None)
        gw_ip = gw_node["ip"] if gw_node else gw

        # gateway in the middle
        d.ellipse([cx - 16, cy - 16, cx + 16, cy + 16], outline=ACCENT, width=2)
        gw_label = "GW"
        gw_w = d.textlength(gw_label, font=self.font_sm)
        d.text((cx - gw_w / 2, cy - gw_w / 2 - 1), gw_label,
               font=self.font_sm, fill=ACCENT)

        others = [n for n in nodes if n["ip"] != gw_ip]
        count = len(others)
        # Two rings once a single ring would overlap labels.
        rings = [(radius, others)] if count <= 8 else [
            (radius, others[: count // 2]),
            (radius - 22, others[count // 2:]),
        ]
        for r, ring in rings:
            for i, node in enumerate(ring):
                angle = 2 * math.pi * i / len(ring) - math.pi / 2
                x = cx + int(r * math.cos(angle))
                y = cy + int(r * math.sin(angle))
                d.line([(cx, cy), (x, y)], fill=(58, 64, 74))
                d.ellipse([x - 3, y - 3, x + 3, y + 3], fill=OK)
                label = host_label(node)
                tw = d.textlength(label, font=self.font_sm)
                lx = x + 5
                if lx + tw > W - 4:
                    lx = x - 5 - tw
                ly = y - 5
                if ly < 20:
                    ly = y + 4
                if ly > H - 26:
                    ly = y - 14
                d.text((lx, ly), label, font=self.font_sm, fill=FG)

        if self.status:
            d.text((6, H - 26), self.status[:40], font=self.font_sm, fill=DIM)
        self.footer(d, "Esc back   R rescan   S save")
        return img

    def draw_maps(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        self.header(d, "Saved maps", "%d" % len(self.maps))
        y = 24
        for path in self.maps[self.scroll:self.scroll + 9]:
            name = os.path.basename(path)
            selected = self.maps.index(path) == self.map_index
            d.text((8, y), ("> " if selected else "  ") + name[:36],
                   font=self.font_sm, fill=ACCENT if selected else FG)
            y += 15
        if not self.maps:
            d.text((10, 60), "no saved maps", font=self.font, fill=DIM)
        self.footer(d, "Enter open   D delete   Esc back")
        return img

    def render(self):
        if self.screen == "menu":
            return self.draw_menu()
        if self.screen == "scanning":
            return self.draw_scanning()
        if self.screen == "hosts":
            return self.draw_hosts()
        if self.screen == "map":
            return self.draw_map()
        return self.draw_maps()

    # ---------------- actions ----------------

    def start_scan(self, silent=False):
        """Start a scan. A silent scan keeps the current screen and only
        replaces the topology when it finishes."""
        config = read_config()
        subnet = config.get("subnet") or netscan.local_cidr()
        if not subnet:
            self.error = "no network interface found"
            return
        self.subnet = subnet
        self.gateway = netscan.gateway_ip()
        self.error = ""
        self.scanner.start(subnet, thorough=bool(config.get("thorough")))
        self.silent_scan = silent
        if not silent:
            self.screen = "scanning"

    def finish_scan(self):
        if self.scanner.cancelled:
            self.error = "scan cancelled"
            self.screen = "menu"
            return
        if self.scanner.error:
            self.error = self.scanner.error
            self.screen = "menu"
            return
        self.topo = topology.build_topology(
            self.scanner.hosts, gateway=self.gateway, subnet=self.subnet
        )
        self.scroll = 0
        self.screen = "hosts"

    def apply_silent_scan(self):
        """Fold a background rescan into the current view."""
        self.silent_scan = False
        self.scanner.done = False
        if self.scanner.cancelled or self.scanner.error:
            return
        self.topo = topology.build_topology(
            self.scanner.hosts, gateway=self.gateway, subnet=self.subnet
        )
        self.status = "updated %s" % time.strftime("%H:%M:%S")

    def maybe_auto_refresh(self):
        """Rescan on a timer when the user enabled a refresh interval."""
        interval = self.refresh_interval
        if not interval or self.screen not in ("hosts", "map"):
            return
        if self.scanner.running():
            return  # a scan is already running
        now = time.time()
        if now - self.last_refresh < interval:
            return
        self.last_refresh = now
        self.start_scan(silent=True)
        self.status = "auto-refreshing..."

    def rescan(self):
        """Re-run the scan in the background and refresh the view."""
        if self.scanner.running():
            self.status = "scan already running"
            return
        self.start_scan(silent=True)
        self.status = "rescanning..."

    def save_current(self):
        if not self.topo:
            return
        path = topology.save_topology(self.topo, name=self.subnet.replace("/", "_"))
        self.status = "saved %s" % os.path.basename(path)

    def open_map(self, path):
        topo = topology.load_topology(path)
        if topo:
            self.topo = topo
            self.subnet = topo.get("subnet", "")
            self.scroll = 0
            self.screen = "hosts"

    # ---------------- main loop ----------------

    def run(self):
        while True:
            self.blit(self.render())

            codes = read_keycodes(self.input_fds, timeout=0.1)
            if self.screen == "scanning":
                if self.scanner.done:
                    self.finish_scan()
                elif KEY_ESC in codes:
                    # Stop the nmap child, then leave the screen.
                    self.scanner.cancel()
                    self.error = "scan cancelled"
                    self.screen = "menu"
                continue
            if self.scanner.done and self.silent_scan:
                self.apply_silent_scan()
            self.maybe_auto_refresh()
            if not codes:
                continue

            # One key event at a time: a batch of codes must not collapse
            # into a single action.
            for code in codes:
                if self.screen == "menu":
                    self.menu_keys(code)
                elif self.screen == "hosts":
                    self.hosts_keys(code)
                elif self.screen == "map":
                    self.map_keys(code)
                elif self.screen == "maps":
                    self.maps_keys(code)

    def menu_keys(self, code):
        if code in (KEY_UP, KEY_Z):
            self.menu_index = (self.menu_index - 1) % len(MENU)
        elif code in (KEY_DOWN, KEY_X):
            self.menu_index = (self.menu_index + 1) % len(MENU)
        elif code == KEY_ENTER:
            choice = MENU[self.menu_index]
            if choice == "Scan network":
                self.start_scan()
            elif choice == "Saved maps":
                self.maps = topology.list_maps()
                self.map_index = 0
                self.scroll = 0
                self.screen = "maps"
            else:
                raise SystemExit(0)
        elif code == KEY_ESC:
            raise SystemExit(0)

    def hosts_keys(self, code):
        nodes = self.topo["nodes"]
        if code in (KEY_DOWN, KEY_X):
            self.scroll = min(self.scroll + 1, max(0, len(nodes) - 8))
        elif code in (KEY_UP, KEY_Z):
            self.scroll = max(0, self.scroll - 1)
        elif code == KEY_ENTER:
            self.screen = "map"
        elif code == KEY_S:
            self.save_current()
        elif code == KEY_R:
            self.rescan()
        elif code == KEY_ESC:
            self.screen = "menu"

    def map_keys(self, code):
        if code == KEY_S:
            self.save_current()
        elif code == KEY_R:
            self.rescan()
        elif code in (KEY_ESC, KEY_ENTER):
            self.screen = "hosts"

    def maps_keys(self, code):
        if code in (KEY_DOWN, KEY_X):
            self.map_index = min(self.map_index + 1, max(0, len(self.maps) - 1))
        elif code in (KEY_UP, KEY_Z):
            self.map_index = max(0, self.map_index - 1)
        elif code == KEY_ENTER and self.maps:
            self.open_map(self.maps[self.map_index])
        elif code == KEY_D and self.maps:
            topology.delete_topology(self.maps[self.map_index])
            self.maps = topology.list_maps()
            self.map_index = min(self.map_index, max(0, len(self.maps) - 1))
        elif code == KEY_ESC:
            self.screen = "menu"


def main():
    try:
        app = App()
    except OSError as exc:
        print("mapzero: %s" % exc, file=sys.stderr)
        return 3
    try:
        app.run()
    except KeyboardInterrupt:
        return 0
    except SystemExit:
        return 0
    finally:
        for fd in app.input_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if app.mm is not None:
            app.mm.close()
        if app.fd is not None:
            os.close(app.fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
