#!/bin/sh
# Launch MapZero from the APPLaunch launcher.
#
# APPLaunch starts this wrapper without a TTY, so stdout/stderr go to a log
# file to make silent failures diagnosable. The log lives in the user's cache
# rather than /tmp: /tmp is a small tmpfs on the device, and a log that
# grows there would eat into the space the launcher needs.
set -eu

APP_DIR=/usr/share/APPLaunch/apps/mapzero
LOG_DIR=${XDG_CACHE_HOME:-$HOME/.cache}/mapzero
LOG=$LOG_DIR/app.log

mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR=/tmp
# Truncate: one launch's output is enough to diagnose a failure, and the
# file must not grow without bound.
: >"$LOG" 2>/dev/null || LOG=/dev/null
{
    echo "--- mapzero launch $(date -Iseconds) ---"
    echo "user=$(id -un) uid=$(id -u) groups=$(id -Gn)"
} >>"$LOG" 2>&1

exec python3 "$APP_DIR/mapzero.py" >>"$LOG" 2>&1
