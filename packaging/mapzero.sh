#!/bin/sh
# Launch MapZero from the APPLaunch launcher.
#
# APPLaunch starts this wrapper without a TTY, so stdout/stderr go to a log
# file to make silent failures diagnosable.
set -eu

APP_DIR=/usr/share/APPLaunch/apps/mapzero
LOG=/tmp/mapzero.log

: >>"$LOG" 2>/dev/null || LOG=/dev/null
{
    echo "--- mapzero launch $(date -Iseconds) ---"
    echo "user=$(id -un) uid=$(id -u) groups=$(id -Gn)"
} >>"$LOG" 2>&1

exec python3 "$APP_DIR/mapzero.py" >>"$LOG" 2>&1
