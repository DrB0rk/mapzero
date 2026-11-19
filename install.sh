#!/bin/bash
# Build the .deb and install it on this device. Run: sudo bash install.sh
set -euo pipefail
(( EUID == 0 )) || { echo "Run with sudo"; exit 1; }
cd "$(dirname "$0")"

bash build-deb.sh
deb="$(ls -t build | grep '^mapzero_.*_all\.deb$' | head -1)"

# The scanner itself is nmap; make sure it is there before the app is used.
if ! command -v nmap >/dev/null 2>&1; then
    apt-get update && apt-get install -y nmap
fi

cp "build/$deb" /tmp/ && apt-get install -y "/tmp/$deb" && rm -f "/tmp/$deb"

systemctl restart APPLaunch.service || true
echo "INSTALLED. Open \"MapZero\" in the launcher. Uninstall: sudo apt remove mapzero"
