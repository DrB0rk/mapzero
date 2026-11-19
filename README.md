# MapZero

A network topology mapper for the **M5 Cardputer Zero** (Raspberry Pi CM0, arm64
Linux). It scans the network the device is attached to with **nmap**, draws the
discovered hosts and their open services as a topology on the 320x170 screen, and
saves every scan as JSON so it can be reopened later.

![hosts](screenshots/hosts.png)
![topology](screenshots/map.png)

## What it does

- **Scan network** - discovers hosts on the local `/24` and the services they
  expose. The scan runs in a background thread so the UI stays responsive; `Esc`
  cancels it.
- **Hosts** - one row per host: address, name and open ports. The row under the
  cursor also shows the MAC address of that host.
- **Topology** - the gateway in the middle, hosts around it on a ring. Networks
  with more than ten hosts get a second, inner ring.
- **Saved maps** - scans are stored as JSON in `~/.local/share/mapzero/maps` and
  can be reopened (and deleted) from the app.

## The screen

The panel is 320x170, so the interface is built like a chart sheet rather than a
desktop app:

- A **header** names the screen and counts what is on it.
- The **body** holds the content. Lists have their own caption row, the current
  row is marked with an amber bar and a lit background.
- An **info band** under the body explains the current selection - the MAC of
  the selected host, its services, the last scan time. Transient messages
  ("saved ...", "scan cancelled") take over that band while they last.
- A **key legend** along the bottom names every key that does something on the
  current screen, so the controls are discoverable without a manual.

Labels are set in DejaVu Sans, addresses and port numbers in DejaVu Sans Mono so
the columns line up and digits do not jitter.

## Keys

| Key | Action |
| --- | --- |
| `Up` / `Down` (or `F` / `X`) | move the selection |
| `Right` / `Left` (or `C` / `Z`) | step between the host list and the map |
| `Enter` | open / confirm |
| `R` | rescan the network in the background and refresh the view |
| `S` | save the current map |
| `D` | delete the selected saved map (press twice to confirm) |
| `Esc` | back / quit (during a scan: stop the scan) |

The Cardputer Zero has no cursor keys: `F`, `Z`, `X` and `C` sit where a d-pad
would, and the vendor asks apps to read them as arrows, so both spellings work.

The selection follows you between the host list and the topology view - the
machine picked in the list is the one picked on the map.

`Esc` during a scan really stops it - the running nmap process is terminated,
not just hidden.

## Install on the device

The app is a plain Debian package that registers itself with the APPLaunch
launcher.

```bash
# on the Cardputer Zero
sudo apt install nmap            # the scanner itself
sudo bash install.sh             # builds and installs the .deb
systemctl restart APPLaunch.service
```

`MapZero` then appears in the launcher carousel with its icon.

To install by hand:

```bash
bash build-deb.sh
sudo apt install ./build/mapzero_1.0.0_all.deb
```

The `.deb` pulls in `python3`, `python3-pil`, `nmap` and `fonts-dejavu-core`.
`postinst` adds the desktop user to the `video` and `input` groups so the app
can open `/dev/fb0` and read the matrix keyboard; restart the session (or
`APPLaunch.service`) for the group change to take effect.

## Configuration

Optional, `~/.config/mapzero/config.json`:

```json
{
  "subnet": "192.168.1.0/24",
  "thorough": false,
  "refresh": 0
}
```

`subnet` overrides the automatically detected network. `thorough` makes nmap
scan the top 100 ports instead of a short list of common ones - slower, but it
finds more services. `refresh` is the auto-refresh interval in seconds; `0`
(disabled) means the topology only changes when you press `R`.

## How the scan works

Discovery uses an **unprivileged TCP connect scan** (`nmap -sT`), so no root is
needed:

```
nmap -sT -n --max-retries 0 --host-timeout 30s -p 22,23,53,80,443,445,554,8080,8443 -oX - <host> <host> ...
```

The subnet is split into chunks of 64 hosts so the progress bar advances and
one slow host cannot stall the whole scan. Each host is passed as its own
argument - nmap cannot parse a comma-separated list, and trying to made it scan
every host on its own. nmap's XML output is parsed into hosts, ports,
services and (from the kernel ARP cache) MAC addresses.

## Limitations

The scan is an **unprivileged TCP connect scan** (`-sT`), which is what a
non-root app can do. That means:

- Hosts that ignore every scanned port are invisible, even though the kernel
  ARP cache knows them.
- No MAC/vendor data comes from nmap; MACs are read from `/proc/net/arp`.
- There are no traceroute hops - the topology is a flat star around the
  gateway, not a routed path map.
- The scan covers the device's own subnet only.

## Layout

```
app/mapzero.py    framebuffer UI, key handling, screens
app/netscan.py    nmap invocation and XML parsing
app/topology.py   topology model, JSON store
packaging/        desktop entry, launcher wrapper, icon
debian/           .deb control and postinst
tests/            unit tests (parsing, topology, UI flow)
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Status

**Verified on the Cardputer Zero itself** (BorkPuter, Raspberry Pi CM0, aarch64,
Debian 13):

- The `.deb` installs with `apt-get`, the desktop entry lands in
  `/usr/share/APPLaunch/applications/` and the launcher picks it up.
- The panel is 320x170 at 16 bpp RGB565 with a line length of 640; the app
  detects the layout and packs its pixels for it.
- The menu, the host list and the topology view were captured straight out of
  `/dev/fb0` on the device and are three distinct frames.
- A scan of the device's own `10.0.1.0/24` found 8 hosts in 13.7 seconds, and a
  saved map was written and read back.
- The 46-key matrix keyboard is read from `/dev/input/event3`.

Also verified on a development host: real nmap sweeps of a live /24, the
framebuffer renderer in 16 and 32 bit pixel layouts, the packaged `.deb`, and
the store manifest.

**Publishing to the store still needs a short video of the app running on real
hardware**, posted on the pull request.

## Legal

Only scan networks you own or are authorised to test.
