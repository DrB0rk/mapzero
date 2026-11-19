#!/usr/bin/env python3
"""Render the store screenshots from a live scan.

Run from the repository root:

    python3 tools/make-screenshots.py

The store requires 320x170 PNGs, so this renders the same screens the app
draws, but with a real scan behind them.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "app"))

import mapzero  # noqa: E402
import netscan  # noqa: E402
import topology  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "screenshots")


def main():
    app = mapzero.App(fb_path=None)
    try:
        subnet = netscan.local_cidr()
        if not subnet:
            print("no network interface found", file=sys.stderr)
            return 1
        hosts, error = netscan.scan_network(subnet)
        if error:
            print("scan failed: %s" % error, file=sys.stderr)
            return 1
        gw = netscan.gateway_ip()
        app.topo = topology.build_topology(hosts, gateway=gw, subnet=subnet)
        app.subnet = subnet
        app.gateway = gw
        app.updated = "updated %s" % __import__("time").strftime("%H:%M")

        os.makedirs(OUT, exist_ok=True)
        app.screen = "hosts"
        app.render().save(os.path.join(OUT, "hosts.png"))
        app.screen = "map"
        app.render().save(os.path.join(OUT, "map.png"))
        print("wrote hosts.png and map.png (%d hosts)" % len(hosts))
    finally:
        for fd in app.input_fds:
            os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
