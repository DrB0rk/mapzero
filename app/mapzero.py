#!/usr/bin/env python3
"""MapZero - network topology mapper for the M5 Cardputer Zero.

Scans the local network with nmap, draws the resulting topology on the
320x170 framebuffer and saves it as JSON.

The screen is a small instrument face, so the UI is drawn as a chart sheet:
a deep prussian ground, hairline rules, amber for whatever is under the
cursor and mint for anything that answered. Labels are sans, addresses and
port numbers are mono so the columns line up.

Keys:
  Up/Down (F/X)     - move the selection
  Right/Left (C/Z)  - step sideways between the list and the map
  Enter             - open / confirm
  R                 - rescan the network
  S                 - save the current map
  D                 - delete the selected saved map
  Esc               - back / quit
"""

import ctypes
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
FBIOGET_FSCREENINFO = 0x4602

FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
)
FONT_BOLD_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
)
FONT_MONO_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
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

# The Cardputer Zero has no cursor keys: F, Z, X and C sit where a d-pad
# would, and the vendor asks apps to read them as arrows.
UP_KEYS = (KEY_UP, KEY_F)
DOWN_KEYS = (KEY_DOWN, KEY_X)
LEFT_KEYS = (KEY_LEFT, KEY_Z)
RIGHT_KEYS = (KEY_RIGHT, KEY_C)

# Palette: cyanotype ink on prussian paper.
BG = (13, 31, 45)          # ground
PANEL = (18, 41, 59)       # header, footer and info bands
PANEL_HI = (31, 68, 94)    # the row under the cursor
RULE = (43, 84, 110)       # hairlines and rings
INK = (226, 240, 247)      # primary text
INK_DIM = (139, 176, 196)  # secondary text
INK_FAINT = (92, 130, 152)  # grid, hints
AMBER = (243, 180, 66)     # selection, focus, the gateway
MINT = (99, 213, 172)      # something that answered
CORAL = (241, 111, 97)     # failures

# Layout, in pixels.
HDR_H = 17                 # header band, hairline under it
RULE_Y = 17
BODY_TOP = 19
COL_Y = 20                 # column captions
COL_RULE = 33
BODY_BOT = 135
INFO_RULE = 136            # info band under the body
INFO_TOP = 137
INFO_BOT = 151
FTR_RULE = 153             # key legend at the very bottom
FTR_TOP = 154
FTR_BOT = 169

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


def load_font(size, bold=False, mono=False):
    """Load DejaVu at the given size, falling back to the bitmap font."""
    if mono:
        paths = FONT_MONO_PATHS
    elif bold:
        paths = FONT_BOLD_PATHS
    else:
        paths = FONT_PATHS
    for path in paths + FONT_PATHS:
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
        real = os.path.realpath(path)
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
        self.done_chunks = 0
        self.total_chunks = 0
        self.found = 0
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
        self.done_chunks = 0
        self.total_chunks = 0
        self.found = 0
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

    def _set_progress(self, text, done=0, total=0, found=0):
        self.progress = text
        self.done_chunks = done
        self.total_chunks = total
        self.found = found

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


class FbBitfield(ctypes.Structure):
    _fields_ = [
        ("offset", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("msb_right", ctypes.c_uint32),
    ]


class FbVarScreeninfo(ctypes.Structure):
    """struct fb_var_screeninfo, exactly as the kernel writes it.

    The whole structure must be declared: the ioctl copies sizeof(var) bytes
    into the caller's buffer, so a struct that stops early makes the kernel
    write past the end of it. Every field is a fixed width integer, so the
    layout is the same on 32 and 64 bit.
    """

    _fields_ = [
        ("xres", ctypes.c_uint32),
        ("yres", ctypes.c_uint32),
        ("xres_virtual", ctypes.c_uint32),
        ("yres_virtual", ctypes.c_uint32),
        ("xoffset", ctypes.c_uint32),
        ("yoffset", ctypes.c_uint32),
        ("bits_per_pixel", ctypes.c_uint32),
        ("grayscale", ctypes.c_uint32),
        ("red", FbBitfield),
        ("green", FbBitfield),
        ("blue", FbBitfield),
        ("transp", FbBitfield),
        ("nonstd", ctypes.c_uint32),
        ("activate", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
        ("width", ctypes.c_uint32),
        ("accel_flags", ctypes.c_uint32),
        ("pixclock", ctypes.c_uint32),
        ("left_margin", ctypes.c_uint32),
        ("right_margin", ctypes.c_uint32),
        ("upper_margin", ctypes.c_uint32),
        ("lower_margin", ctypes.c_uint32),
        ("hsync_len", ctypes.c_uint32),
        ("vsync_len", ctypes.c_uint32),
        ("sync", ctypes.c_uint32),
        ("vmode", ctypes.c_uint32),
        ("rotate", ctypes.c_uint32),
        ("colorspace", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 4),
    ]


class FbFixScreeninfo(ctypes.Structure):
    """The head of struct fb_fix_screeninfo.

    c_ulong is the native size of a long, so smem_start and mmio_start land
    where the kernel expects them on both 32 and 64 bit. Hand counted byte
    offsets would read the wrong field on the device.
    """

    _fields_ = [
        ("id", ctypes.c_char * 16),
        ("smem_start", ctypes.c_ulong),
        ("smem_len", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("type_aux", ctypes.c_uint32),
        ("visual", ctypes.c_uint32),
        ("xpanstep", ctypes.c_uint16),
        ("ypanstep", ctypes.c_uint16),
        ("ywrapstep", ctypes.c_uint16),
        ("line_length", ctypes.c_uint32),
        ("mmio_start", ctypes.c_ulong),
        ("mmio_len", ctypes.c_uint32),
        ("accel", ctypes.c_uint32),
        ("capabilities", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16 * 2),
    ]


def read_framebuffer(fd):
    """Return the panel geometry and pixel layout of a framebuffer.

    Returns a dict with xres, yres, bpp, the red/green/blue bit offsets, the
    visible origin and the stride of one line, or None when the kernel does
    not answer.
    """
    import fcntl
    var = FbVarScreeninfo()
    try:
        fcntl.ioctl(fd, FBIOGET_VSCREENINFO, var, True)
    except (OSError, ValueError, SystemError):
        # SystemError means the kernel had more to write than the buffer
        # held. Treat the panel as unknown rather than crashing.
        return None
    fix = FbFixScreeninfo()
    stride = 0
    try:
        fcntl.ioctl(fd, FBIOGET_FSCREENINFO, fix, True)
        stride = fix.line_length
    except (OSError, ValueError, SystemError):
        stride = 0
    return {
        "xres": var.xres, "yres": var.yres, "bpp": var.bits_per_pixel,
        "red": var.red.offset, "green": var.green.offset, "blue": var.blue.offset,
        "xoffset": var.xoffset, "yoffset": var.yoffset,
        "stride": stride,
    }


def pixel_format(info):
    """Name the pixel layout of a framebuffer, or None if it is exotic.

    The bit offsets say where each channel sits inside the pixel value, so
    the same 32 bit panel can be BGRX or RGBX depending on the driver.

    A 16 bit panel is assumed to be RGB565 unless the driver says the
    channels are swapped: several simple fbdev drivers report the depth and
    leave the bitfields empty, and refusing to start over a missing detail
    would keep the app off the screen entirely.
    """
    if info is None:
        return "rgb565"
    bpp = info["bpp"]
    red, green, blue = info["red"], info["green"], info["blue"]
    if bpp == 16:
        if (red, green, blue) == (0, 5, 11):
            return "bgr565"
        return "rgb565"
    if bpp == 32:
        if (red, green, blue) == (16, 8, 0):
            return "bgrx"
        if (red, green, blue) == (0, 8, 16):
            return "rgbx"
        return None
    if not bpp:
        return "rgb565"  # the kernel did not say: trust the device
    return None


def pack_pixels(img, fmt):
    """Pack an RGB image into the bytes the panel expects."""
    if fmt == "rgb565":
        return image_to_rgb565(img)
    if fmt == "bgr565":
        r, g, b = img.split()
        return image_to_rgb565(Image.merge("RGB", (b, g, r)))
    if fmt == "bgrx":
        # red at bits 16-23, green 8-15, blue 0-7: the bytes read B, G, R, X.
        raw = bytearray(img.tobytes("raw", "BGRX"))
        raw[3::4] = b"\xff" * (img.width * img.height)
        return bytes(raw)
    if fmt == "rgbx":
        return img.tobytes("raw", "RGBX")
    raise ValueError("unsupported pixel format %r" % fmt)


def check_framebuffer(fd):
    """Refuse to draw on a framebuffer that is not the device's 320x170 panel.

    Writing 320x170 of pixels into an arbitrary framebuffer corrupts whatever
    else is using it, so fail loudly instead. The pixel layout matters too:
    RGB565 data on a 32bpp panel comes out as garbage colours, so the layout
    is detected and the pixels are packed to match it.
    """
    info = read_framebuffer(fd)
    if info is None:
        # Cannot query: trust the device and assume a plain RGB565 panel.
        return {"fmt": "rgb565", "stride": 0, "xoffset": 0, "yoffset": 0}
    if (info["xres"], info["yres"]) != (W, H):
        raise OSError("%s is %dx%d, expected %dx%d"
                      % (FB_DEV, info["xres"], info["yres"], W, H))
    fmt = pixel_format(info)
    if fmt is None:
        raise OSError("%s uses %d bpp at r=%d g=%d b=%d, which is not a "
                      "supported layout" % (FB_DEV, info["bpp"], info["red"],
                                            info["green"], info["blue"]))
    info["fmt"] = fmt
    return info


class App:
    def __init__(self, fb_path=FB_DEV):
        self.font_h = load_font(13, bold=True)
        self.font = load_font(12)
        self.font_s = load_font(11)
        self.font_xs = load_font(10)
        self.font_m = load_font(12, mono=True)
        self.font_ms = load_font(10, mono=True)
        self.font_logo = load_font(22, bold=True)
        self.screen = "menu"
        self.menu_index = 0
        self.scroll = 0
        self.sel = 0
        self.map_sel = 0
        self.maps = []
        self.map_index = 0
        self.topo = None
        self.gateway = ""
        self.subnet = ""
        self.status = ""
        self.error = ""
        self.updated = ""
        self.confirm_delete = False
        self.silent_scan = False
        self.scan_origin = "menu"
        self.refresh_interval = _int_or_zero(read_config().get("refresh", 0))
        self.last_refresh = time.time()
        self.scanner = Scanner()
        self.fd = None
        self.mm = None
        self.fmt = "rgb565"
        self.stride = 0
        self.origin = (0, 0)
        self._last_raw = None
        self._net_cache = None
        self._maps_cache = (0, [])
        if fb_path is not None:
            self.fd = os.open(fb_path, os.O_RDWR)
            info = check_framebuffer(self.fd)
            self.fmt = info["fmt"]
            self.stride = info["stride"]
            self.origin = (info["xoffset"] * self.fmt_bytes(),
                           info["yoffset"] * self.stride)
            row = W * self.fmt_bytes()
            if not self.stride or self.stride < row:
                self.stride = row
            length = self.stride * (H + info["yoffset"])
            try:
                self.mm = mmap.mmap(self.fd, length, mmap.MAP_SHARED,
                                    mmap.PROT_WRITE | mmap.PROT_READ)
            except (OSError, ValueError) as exc:
                raise OSError("cannot map %dx%d framebuffer: %s"
                              % (W, H, exc))
        self.input_fds = open_input_devices()

    def fmt_bytes(self):
        return 4 if self.fmt in ("bgrx", "rgbx") else 2

    # ---------------- rendering ----------------

    def blit(self, img):
        if self.mm is None:
            return
        raw = pack_pixels(img, self.fmt)
        if raw == self._last_raw:
            return  # nothing changed: skip the conversion
        self._last_raw = raw
        row = W * self.fmt_bytes()
        xoff, yoff = self.origin
        if self.stride == row and not xoff and not yoff:
            self.mm.seek(0)
            self.mm.write(raw)
            return
        # The panel pads its lines, and the visible area can start part way
        # into the buffer: write one row at a time.
        for y in range(H):
            self.mm.seek(yoff + y * self.stride + xoff)
            self.mm.write(raw[y * row:(y + 1) * row])

    def new_image(self):
        return Image.new("RGB", (W, H), BG)

    # ---- drawing helpers ----

    def rule(self, draw, y, color=RULE):
        draw.line([(0, y), (W - 1, y)], fill=color)

    def text_right(self, draw, text, y, font, fill):
        w = draw.textlength(text, font=font)
        draw.text((W - 8 - w, y), text, font=font, fill=fill)

    def header(self, draw, title, right=""):
        draw.rectangle([0, 0, W - 1, HDR_H - 1], fill=PANEL)
        draw.text((8, 2), title, font=self.font_h, fill=INK)
        if right:
            self.text_right(draw, right, 4, self.font_ms, INK_DIM)
        self.rule(draw, RULE_Y)

    def info_strip(self, draw, left="", right="", color=None):
        """The band under the body: context about the current selection."""
        draw.rectangle([0, INFO_TOP, W - 1, INFO_BOT], fill=PANEL)
        self.rule(draw, INFO_RULE)
        if left:
            draw.text((8, INFO_TOP + 3), left, font=self.font_ms,
                      fill=color or INK_DIM)
        if right:
            self.text_right(draw, right, INFO_TOP + 3, self.font_ms,
                            color or INK_DIM)

    def status_line(self):
        """The transient message to show, if any. Errors outrank notices."""
        if self.error:
            return self.error, CORAL
        if self.status:
            return self.status, MINT
        return "", None

    def notice(self, draw):
        """A transient message takes over the info band while it lasts."""
        text, color = self.status_line()
        if not text:
            return
        self.info_strip(draw, text, "", color)

    def footer(self, draw, items):
        """The key legend: amber key names, dim action words."""
        draw.rectangle([0, FTR_TOP, W - 1, FTR_BOT], fill=PANEL)
        self.rule(draw, FTR_RULE)
        x = 8
        y = FTR_TOP + 3
        for key, action in items:
            kw = draw.textlength(key, font=self.font_s)
            aw = draw.textlength(action, font=self.font_s) if action else 0
            if x + kw + aw > W - 8:
                break  # never let the legend run off the panel
            draw.text((x, y), key, font=self.font_s, fill=AMBER)
            x += kw + 3
            if action:
                draw.text((x, y), action, font=self.font_s, fill=INK_DIM)
                x += aw
            x += 8

    def fit(self, draw, text, font, maxw):
        """Shorten text with an ellipsis until it fits maxw."""
        if draw.textlength(text, font=font) <= maxw:
            return text
        while text and draw.textlength(text + "…", font=font) > maxw:
            text = text[:-1]
        return text + "…"

    # ---- screen data ----

    def local_network(self):
        """Cached (subnet, gateway) of this device."""
        if self._net_cache is None:
            try:
                self._net_cache = (netscan.local_cidr(), netscan.gateway_ip())
            except OSError:
                self._net_cache = ("", "")
        return self._net_cache

    def saved_maps(self):
        """Cached list of saved maps, refreshed at most every few seconds."""
        now = time.time()
        stamp, maps = self._maps_cache
        if now - stamp > 5:
            maps = topology.list_maps()
            self._maps_cache = (now, maps)
        return maps

    def hosts(self):
        if not self.topo:
            return []
        return self.topo["nodes"]

    def gateway_ip(self):
        return (self.topo or {}).get("gateway") or ""

    def service_ports(self, node, limit=4):
        """Port numbers of a node, as a short comma separated list."""
        services = node.get("services", [])
        ports = [str(s["port"]) for s in services[:limit]]
        extra = len(services) - len(ports)
        return ", ".join(ports) + (" +%d" % extra if extra > 0 else "")

    def service_names(self, node, limit=3):
        """Service names of a node, without the version noise."""
        names = []
        for svc in node.get("services", [])[:limit]:
            names.append((svc.get("name") or "?").split(" (")[0])
        return ", ".join(names)

    # ---- screens ----

    def draw_menu(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        subnet, gateway = self.local_network()
        maps = self.saved_maps()

        d.text((10, 4), "MapZero", font=self.font_logo, fill=AMBER)
        d.text((12, 30), "network topology mapper", font=self.font_s,
               fill=INK_DIM)
        d.line([(12, 47), (12 + d.textlength("network topology mapper",
                                             font=self.font_s), 47)],
               fill=RULE)

        y = 56
        for i, item in enumerate(MENU):
            if i == self.menu_index:
                d.rectangle([6, y - 3, 9, y + 13], fill=AMBER)
                d.text((18, y), item, font=self.font, fill=INK)
            else:
                d.text((18, y), item, font=self.font, fill=INK_DIM)
            if item == "Scan network" and subnet:
                self.text_right(d, subnet, y + 1, self.font_ms, INK_FAINT)
            elif item == "Saved maps" and maps:
                self.text_right(d, "%d saved" % len(maps), y + 1,
                                self.font_ms, INK_FAINT)
            y += 22

        if subnet:
            d.text((18, 120), "target", font=self.font_xs, fill=INK_FAINT)
            d.text((70, 119), subnet, font=self.font_ms, fill=INK_DIM)
        if gateway:
            d.text((18, 132), "gateway", font=self.font_xs, fill=INK_FAINT)
            d.text((70, 131), gateway, font=self.font_ms, fill=INK_DIM)

        self.notice(d)
        self.footer(d, [("up/dn", "move"), ("enter", "open"), ("esc", "quit")])
        self.text_right(d, "v1.0", FTR_TOP + 3, self.font_ms, INK_FAINT)
        return img

    def draw_scanning(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        self.header(d, "Scanning", self.subnet)
        sc = self.scanner

        d.text((14, 32), "nmap -sT", font=self.font_m, fill=MINT)
        d.text((14, 52), "sweeping the subnet", font=self.font, fill=INK)

        bx, by, bw, bh = 14, 78, W - 28, 8
        d.rectangle([bx, by, bx + bw, by + bh], fill=RULE)
        if sc.total_chunks:
            filled = int(bw * sc.done_chunks / sc.total_chunks)
            d.rectangle([bx, by, bx + max(1, filled) - 1, by + bh], fill=AMBER)
        d.text((14, 94), "chunk %d of %d" % (sc.done_chunks, sc.total_chunks),
               font=self.font_s, fill=INK_DIM)
        self.text_right(d, "%d found" % sc.found, 94, self.font_s, MINT)

        d.text((14, 114), self.fit(d, sc.progress or "starting nmap...",
                                   self.font_xs, W - 28),
               font=self.font_xs, fill=INK_FAINT)
        self.footer(d, [("esc", "cancel scan")])
        return img

    def hosts_layout(self, draw, visible):
        """Where each column of the host list starts and how wide it is.

        Kept separate from the drawing so the invariants can be checked:
        the columns must not overlap and nothing may run off the panel.
        """
        ip_w = max([draw.textlength(n["ip"], font=self.font_m)
                    for n in visible] or [70])
        ip_w = min(ip_w, 92)
        x_ip = 14
        x_host = x_ip + ip_w + 10
        x_port = W - 8
        # The port column is right aligned, so the name column only gets
        # what is left after the widest port list.
        port_w = max([draw.textlength(self.service_ports(n), font=self.font_ms)
                      for n in visible] or [0])
        port_w = min(port_w, 120)
        name_room = x_port - port_w - 8 - x_host
        return {"ip": x_ip, "host": x_host, "port": x_port,
                "ip_w": ip_w, "port_w": port_w, "name_room": name_room}

    def draw_hosts(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        nodes = self.hosts()
        gw = self.gateway_ip()
        self.header(d, "Hosts", "%d found" % len(nodes))

        rows = 7
        if self.sel >= len(nodes):
            self.sel = max(0, len(nodes) - 1)
        if self.sel < self.scroll:
            self.scroll = self.sel
        if self.sel >= self.scroll + rows:
            self.scroll = self.sel - rows + 1
        visible = nodes[self.scroll:self.scroll + rows]

        col = self.hosts_layout(d, visible)
        x_ip, x_host, x_port = col["ip"], col["host"], col["port"]
        name_room = col["name_room"]

        d.text((x_ip, COL_Y), "Address", font=self.font_xs, fill=INK_DIM)
        if name_room > 40:
            d.text((x_host, COL_Y), "Host", font=self.font_xs, fill=INK_DIM)
        self.text_right(d, "Ports", COL_Y, self.font_xs, INK_DIM)
        self.rule(d, COL_RULE)

        y = COL_RULE + 5
        for offset, node in enumerate(visible):
            selected = (self.scroll + offset) == self.sel
            if selected:
                d.rectangle([0, y - 2, W - 1, y + 12], fill=PANEL_HI)
                d.rectangle([0, y - 2, 3, y + 12], fill=AMBER)
            d.text((x_ip, y), node["ip"], font=self.font_m,
                   fill=AMBER if selected else INK)
            name = node.get("hostname") or ""
            if not name and node["ip"] == gw:
                name = "gateway"
            if name and name_room > 40:
                d.text((x_host, y + 1), self.fit(d, name, self.font, name_room),
                       font=self.font_s, fill=INK_DIM)
            ports = self.service_ports(node)
            if ports:
                pw = d.textlength(ports, font=self.font_ms)
                d.text((x_port - pw, y + 1), ports, font=self.font_ms, fill=MINT)
            y += 14

        if not nodes:
            d.text((14, 70), "no hosts answered", font=self.font, fill=INK_DIM)
            d.text((14, 88), "check the interface and scan again",
                   font=self.font_s, fill=INK_FAINT)

        node = nodes[self.sel] if nodes else None
        left = ""
        if node:
            left = self.fit(d, "%s  %s" % (node["ip"],
                                            node.get("mac") or "no mac"),
                            self.font_ms, 210)
        self.info_strip(d, left, self.updated)
        self.notice(d)
        self.footer(d, [("up/dn", "move"), ("enter", "map"), ("R", "rescan"),
                         ("S", "save"), ("esc", "back")])
        return img

    def draw_map(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        nodes = self.hosts()
        gw = self.gateway_ip()
        self.header(d, "Topology", "%d hosts" % len(nodes))

        cx, cy = W // 2, (BODY_TOP + BODY_BOT) // 2 + 2

        # The gateway sits in the middle, the other hosts on rings around it.
        # Rings get smaller and busier as the network grows, so every host
        # still gets a mark and the selection never points at the wrong one.
        others = [n for n in nodes if n["ip"] != gw]
        ring_specs = [(114, 36, 12), (84, 28, 10), (60, 20, 8),
                      (42, 14, 6), (28, 9, 5)]
        rings = []
        left = others
        for rx, ry, cap in ring_specs:
            if not left:
                break
            take = left[:cap]
            left = left[cap:]
            rings.append((take, (rx, ry)))
        overflow = left  # a /24 can hold more hosts than there are rings
        # Labels need elbow room: past a dozen hosts the chart shows marks
        # only, and the info band names the one under the cursor.
        crowded = len(others) > 12

        # Where every node sits, keyed by address so a node that could not
        # be placed can never shift the highlight onto another machine.
        spots = {}
        for ring, (rx, ry) in rings:
            for i, node in enumerate(ring):
                ang = -math.pi / 2 + 2 * math.pi * i / len(ring)
                spots[node["ip"]] = (cx + int(rx * math.cos(ang)),
                                     cy + int(ry * math.sin(ang)), ang)
        spots[gw] = (cx, cy, 0.0)

        # The rings and the links are the paper the nodes sit on, so they go
        # down first: the gateway disc is painted over them afterwards.
        for _ring, (rx, ry) in rings:
            d.ellipse([cx - rx, cy - ry, cx + rx, cy + ry], outline=RULE)
        for ip, (x, y, _ang) in spots.items():
            if ip == gw:
                continue
            dx, dy = x - cx, y - cy
            dist = math.hypot(dx, dy) or 1
            d.line([(cx + dx / dist * 14, cy + dy / dist * 14), (x, y)],
                   fill=RULE)

        # The gateway anchors the chart: amber, in the middle.
        d.ellipse([cx - 13, cy - 13, cx + 13, cy + 13], fill=AMBER)
        gw_text = "GW"
        gw_w = d.textlength(gw_text, font=self.font_s)
        d.text((cx - gw_w / 2, cy - 7), gw_text, font=self.font_s, fill=BG)

        self.map_sel = max(0, min(self.map_sel, len(nodes) - 1))
        selected_node = nodes[self.map_sel] if nodes else None
        selected_ip = selected_node["ip"] if selected_node else ""
        for node in nodes:
            spot = spots.get(node["ip"])
            if spot is None:
                continue  # too many hosts for the chart; the list has it
            x, y, ang = spot
            selected = node["ip"] == selected_ip
            if node["ip"] == gw:
                if selected:
                    d.rectangle([x - 17, y - 17, x + 17, y + 17], outline=AMBER)
                continue
            if selected:
                d.rectangle([x - 7, y - 7, x + 7, y + 7], fill=BG)
                d.rectangle([x - 6, y - 6, x + 6, y + 6], outline=AMBER)
            live = bool(node.get("services"))
            d.rectangle([x - 4, y - 4, x + 4, y + 4], fill=BG)
            d.rectangle([x - 3, y - 3, x + 3, y + 3],
                        fill=MINT if live else INK_FAINT)
            # A crowded chart cannot carry a label for every host: only the
            # selected one is named, the rest are marks to look up in the
            # list.
            if not selected and crowded:
                continue
            label = host_label(node)
            tw = d.textlength(label, font=self.font_xs)
            sin_a, cos_a = math.sin(ang), math.cos(ang)
            if sin_a < -0.5:
                lx, ly = x - tw / 2, y - 19
            elif sin_a > 0.5:
                lx, ly = x - tw / 2, y + 9
            elif cos_a >= 0:
                lx, ly = x + 9, y - 6
            else:
                lx, ly = x - 9 - tw, y - 6
            lx = max(3, min(W - 3 - tw, lx))
            ly = max(BODY_TOP, min(BODY_BOT - 12, ly))
            # A backing plate keeps the label legible over the rules.
            d.rectangle([lx - 2, ly - 1, lx + tw + 2, ly + 11], fill=BG)
            d.text((lx, ly), label, font=self.font_xs,
                   fill=INK if selected else INK_DIM)

        left = ""
        if selected_node:
            left = self.fit(d, "%s  %s" % (selected_node["ip"],
                                            self.service_names(selected_node)
                                            or "-"),
                            self.font_ms, 210)
        right = "%d hosts" % len(nodes)
        if overflow:
            right = "%d hosts, %d more" % (len(nodes) - len(overflow),
                                           len(overflow))
        self.info_strip(d, left, right)
        self.notice(d)
        self.footer(d, [("up/dn", "host"), ("enter", "back"), ("R", "rescan"),
                         ("S", "save"), ("esc", "back")])
        return img

    def draw_maps(self):
        img = self.new_image()
        d = ImageDraw.Draw(img)
        maps = self.maps
        self.header(d, "Saved maps", "%d" % len(maps))

        if not maps:
            d.text((14, 70), "no saved maps", font=self.font, fill=INK_DIM)
            d.text((14, 88), "press S on a scan to keep one",
                   font=self.font_s, fill=INK_FAINT)
        else:
            rows = 7
            self.map_index = max(0, min(self.map_index, len(maps) - 1))
            # The window follows the selection, so every saved map is
            # reachable however many there are.
            if self.map_index < self.scroll:
                self.scroll = self.map_index
            if self.map_index >= self.scroll + rows:
                self.scroll = self.map_index - rows + 1
            y = BODY_TOP + 4
            for path in maps[self.scroll:self.scroll + rows]:
                selected = path == maps[self.map_index]
                if selected:
                    d.rectangle([0, y - 2, W - 1, y + 12], fill=PANEL_HI)
                    d.rectangle([0, y - 2, 3, y + 12], fill=AMBER)
                net, stamp = self.map_label(path)
                d.text((14, y), net, font=self.font_m,
                       fill=AMBER if selected else INK)
                if stamp:
                    self.text_right(d, stamp, y + 1, self.font_ms,
                                    INK_DIM if selected else INK_FAINT)
                y += 14
            if len(maps) > rows:
                first = self.scroll + 1
                self.text_right(d, "%d of %d" % (first, len(maps)),
                                BODY_BOT - 12, self.font_ms, INK_FAINT)

        if self.confirm_delete:
            self.info_strip(d, "press D again to delete", "esc cancels", CORAL)
        else:
            where = os.path.dirname(self.maps[self.map_index]) if maps else ""
            self.info_strip(d, self.fit(d, where, self.font_ms, 210), "")
        if not self.confirm_delete:
            self.notice(d)
        self.footer(d, [("up/dn", "move"), ("enter", "open"), ("D", "delete"),
                         ("esc", "back")])
        return img

    def map_label(self, path):
        """Split a saved file name into its network and its timestamp."""
        name = os.path.basename(path)
        if name.endswith(".json"):
            name = name[:-5]
        parts = name.rsplit("-", 2)
        if len(parts) == 3:
            net, day, clock = parts
            return net.replace("_", "/"), "%s-%s %s:%s" % (
                day[4:6], day[6:8], clock[:2], clock[2:4])
        return name.replace("_", "/"), ""

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
            self.scan_origin = self.screen
            self.screen = "scanning"

    def finish_scan(self):
        if self.scanner.cancelled:
            self.status = "scan stopped"
            self.screen = self.scan_origin
            return
        if self.scanner.error:
            self.error = self.scanner.error
            self.screen = self.scan_origin
            return
        self.topo = topology.build_topology(
            self.scanner.hosts, gateway=self.gateway, subnet=self.subnet
        )
        self.scroll = 0
        self.sel = 0
        self.map_sel = 0
        self.updated = "updated %s" % time.strftime("%H:%M")
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
        self.updated = "updated %s" % time.strftime("%H:%M")
        self.status = self.updated

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
        self.status = "refreshing..."

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
            self.sel = 0
            self.map_sel = 0
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
                    # Stop the nmap child, then leave the screen. A scan
                    # the user called off is not a failure, and the view
                    # they came from is still there.
                    self.scanner.cancel()
                    self.status = "scan stopped"
                    self.screen = self.scan_origin
                continue
            if self.scanner.done and self.silent_scan:
                self.apply_silent_scan()
            self.maybe_auto_refresh()
            if not codes:
                continue

            # One key event at a time: a batch of codes must not collapse
            # into a single action.
            for code in codes:
                self.status = ""
                self.error = ""
                if self.screen == "menu":
                    self.menu_keys(code)
                elif self.screen == "hosts":
                    self.hosts_keys(code)
                elif self.screen == "map":
                    self.map_keys(code)
                elif self.screen == "maps":
                    self.maps_keys(code)

    def menu_keys(self, code):
        if code in UP_KEYS:
            self.menu_index = (self.menu_index - 1) % len(MENU)
        elif code in DOWN_KEYS:
            self.menu_index = (self.menu_index + 1) % len(MENU)
        elif code == KEY_ENTER:
            choice = MENU[self.menu_index]
            if choice == "Scan network":
                self.start_scan()
            elif choice == "Saved maps":
                self.maps = topology.list_maps()
                self.map_index = 0
                self.scroll = 0
                self.confirm_delete = False
                self.screen = "maps"
            else:
                raise SystemExit(0)
        elif code == KEY_ESC:
            raise SystemExit(0)

    def hosts_keys(self, code):
        nodes = self.hosts()
        if code in DOWN_KEYS:
            self.sel = min(self.sel + 1, max(0, len(nodes) - 1))
        elif code in UP_KEYS:
            self.sel = max(0, self.sel - 1)
        elif code in (KEY_ENTER, KEY_RIGHT):
            self.map_sel = self.sel
            self.screen = "map"
        elif code == KEY_S:
            self.save_current()
        elif code == KEY_R:
            self.rescan()
        elif code == KEY_ESC:
            self.screen = "menu"

    def map_keys(self, code):
        nodes = self.hosts()
        if code in DOWN_KEYS:
            self.map_sel = min(self.map_sel + 1, max(0, len(nodes) - 1))
        elif code in UP_KEYS:
            self.map_sel = max(0, self.map_sel - 1)
        elif code == KEY_S:
            self.save_current()
        elif code == KEY_R:
            self.rescan()
        elif code in (KEY_ESC, KEY_ENTER, KEY_LEFT):
            self.sel = self.map_sel
            self.screen = "hosts"

    def maps_keys(self, code):
        if code in DOWN_KEYS:
            self.map_index = min(self.map_index + 1, max(0, len(self.maps) - 1))
            self.confirm_delete = False
        elif code in UP_KEYS:
            self.map_index = max(0, self.map_index - 1)
            self.confirm_delete = False
        elif code == KEY_ENTER and self.maps:
            self.open_map(self.maps[self.map_index])
        elif code == KEY_D and self.maps:
            if self.confirm_delete:
                topology.delete_topology(self.maps[self.map_index])
                self.maps = topology.list_maps()
                self.map_index = min(self.map_index, max(0, len(self.maps) - 1))
                self.confirm_delete = False
                self.status = "map deleted"
            else:
                self.confirm_delete = True
        elif code == KEY_ESC:
            if self.confirm_delete:
                self.confirm_delete = False
            else:
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
