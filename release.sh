#!/bin/zsh
# Build a release: universal (Apple Silicon + Intel) app with an installer, written to
# updates/NetworkScanner.zip + updates/latest.json. Committing and pushing updates/ ships it:
# every installed copy's "Check for Updates" reads latest.json from this repo on GitHub.
#   1. bump CFBundleShortVersionString in Info.plist
#   2. UPDATE_NOTES="What changed" ./release.sh
set -e
cd "$(dirname "$0")"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)
BUILD=$(git rev-list --count HEAD 2>/dev/null || echo 0)
CACHE="${TMPDIR:-/tmp}/networkscanner-modcache"
SOURCES=(NetworkScanner.swift Scanner.swift Identify.swift Updater.swift)
mkdir -p "$CACHE" "$CACHE-x86"
echo "Building arm64…"
swiftc -O -target arm64-apple-macos14 -module-cache-path "$CACHE" \
  -o "$CACHE/NetworkScanner-arm64" -parse-as-library $SOURCES
echo "Building x86_64…"
swiftc -O -target x86_64-apple-macos14 -module-cache-path "$CACHE-x86" \
  -o "$CACHE/NetworkScanner-x86_64" -parse-as-library $SOURCES

DIST="$CACHE/dist"
rm -rf "$DIST"
APP="$DIST/NetworkScanner/NetworkScanner.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/NetworkScanner" "$CACHE/NetworkScanner-arm64" "$CACHE/NetworkScanner-x86_64"
cp Info.plist "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" -c "Add :BuildDate string $(date -u +%Y-%m-%dT%H:%M:%SZ)" "$APP/Contents/Info.plist"
cp NetworkScanner.icns "$APP/Contents/Resources/"
codesign --force --sign - "$APP"

cat > "$DIST/NetworkScanner/Install Network Scanner.command" <<'INSTALL'
#!/bin/bash
# Network Scanner installer: copies the app to /Applications and launches it.
cd "$(dirname "$0")"
echo "Installing Network Scanner…"
pkill -x NetworkScanner 2>/dev/null; sleep 0.5
rm -rf /Applications/NetworkScanner.app
ditto --norsrc NetworkScanner.app /Applications/NetworkScanner.app
# Clear the download quarantine and re-sign locally so macOS trusts it on this Mac.
xattr -dr com.apple.quarantine /Applications/NetworkScanner.app 2>/dev/null
codesign --force --sign - /Applications/NetworkScanner.app
tccutil reset All com.jonpike.networkscanner >/dev/null 2>&1
open /Applications/NetworkScanner.app
echo
echo "Done! Network Scanner is in your Applications folder."
echo "Allow Local Network access when macOS asks, or scans will find nothing."
INSTALL
chmod +x "$DIST/NetworkScanner/Install Network Scanner.command"

cat > "$DIST/NetworkScanner/README.txt" <<README
Network Scanner v$VERSION (build $BUILD): see what's on your network, for macOS 14+
https://github.com/jonpikereally/NetworkScanner

INSTALL
1. Double-click "Install Network Scanner.command".
   If macOS blocks it: right-click it, choose Open, then Open again.
2. Allow Local Network access when macOS asks (System Settings → Privacy & Security →
   Local Network). Without it, scans find nothing.

USE
• Open Network Scanner from Applications. It scans when it opens; ⌘R rescans.
• Select a device to see its details; Deep Scan checks about 1,100 ports on it.
• Devices new since the last scan are marked NEW. Double-click a device to name it.
• Right-click a device to copy its address or open its web page.

PRIVACY
Scans stay on your network. Network Scanner fetches two things from the internet: a small
version file from the GitHub repo above (to see whether an update exists), and, unless you
turn off "Look Up Device Makers", the public MAC maker list from wireshark.org once a month.
README

mkdir -p updates
(cd "$DIST" && ditto -c -k --norsrc --noextattr --noqtn --keepParent NetworkScanner "$OLDPWD/updates/NetworkScanner.zip.tmp")
mv -f updates/NetworkScanner.zip.tmp updates/NetworkScanner.zip
# Manifest last, so a checking app never sees it pointing at a half-written zip.
/usr/bin/python3 -c 'import json,sys; print(json.dumps({"version": sys.argv[1], "url": "NetworkScanner.zip", "notes": sys.argv[2]}))' \
  "$VERSION" "${UPDATE_NOTES:-}" > updates/latest.json.tmp
mv -f updates/latest.json.tmp updates/latest.json

./build.sh >/dev/null
echo "Release v$VERSION (build $BUILD) written to updates/. Ship it by committing and pushing updates/."
