#!/bin/zsh
# Install Network Scanner to /Applications and launch it. Run from Terminal.app after ./build.sh.
set -e
cd "$(dirname "$0")"
APP=/Applications/NetworkScanner.app
pkill -x NetworkScanner 2>/dev/null || true
sleep 0.5
rm -rf "$APP"
ditto --norsrc NetworkScanner.app "$APP"
# Sign after stripping xattrs, so a sync client (Dropbox, iCloud) can't slip any in between.
xattr -cr "$APP"
codesign --force --sign - "$APP"
# Ad-hoc signing changes identity on every rebuild, which silently voids old privacy grants.
tccutil reset All com.jonpike.networkscanner >/dev/null 2>&1 || true
echo "Installed $APP"
open "$APP"
echo
echo "Network Scanner launched."
echo "Allow Local Network access when macOS asks, or scans will find nothing."
