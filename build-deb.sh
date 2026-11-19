#!/bin/bash
# Build mapzero_<version>_all.deb into ./build. Needs dpkg-deb.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' app-builder.json | head -1)
PKG=mapzero

python3 -m py_compile app/mapzero.py app/netscan.py app/topology.py

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"

install -D -m 0644 app/mapzero.py  "$root/usr/share/APPLaunch/apps/$PKG/mapzero.py"
install -D -m 0644 app/netscan.py  "$root/usr/share/APPLaunch/apps/$PKG/netscan.py"
install -D -m 0644 app/topology.py "$root/usr/share/APPLaunch/apps/$PKG/topology.py"
install -D -m 0644 packaging/mapzero.desktop "$root/usr/share/APPLaunch/applications/$PKG.desktop"
install -D -m 0644 packaging/icon.png "$root/usr/share/APPLaunch/share/images/$PKG.png"
install -D -m 0755 packaging/mapzero.sh "$root/usr/share/APPLaunch/bin/$PKG"

install -d -m 0755 "$root/DEBIAN"
sed "s/@VERSION@/$VERSION/" debian/control.in > "$root/DEBIAN/control"
install -m 0755 debian/postinst "$root/DEBIAN/postinst"
echo "Installed-Size: $(du -sk --exclude=DEBIAN "$root" | cut -f1)" >> "$root/DEBIAN/control"

mkdir -p build
dpkg-deb --root-owner-group -Zxz --build "$root" "build/${PKG}_${VERSION}_all.deb"
echo "built: build/${PKG}_${VERSION}_all.deb"
