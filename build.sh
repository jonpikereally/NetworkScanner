#!/bin/zsh
# Rebuild NetworkScanner.app for this Mac. Command Line Tools only, no Xcode.
# NetworkScanner.icns is prebuilt (see README). The bundle's Info.plist gets a build number
# (the repo's commit count) and the build time, both shown in the menu.
set -e
cd "$(dirname "$0")"
CACHE="${TMPDIR:-/tmp}/networkscanner-modcache"
APP=NetworkScanner.app
mkdir -p "$CACHE" $APP/Contents/MacOS $APP/Contents/Resources
cp Info.plist $APP/Contents/
cp NetworkScanner.icns $APP/Contents/Resources/
BUILD=$(git rev-list --count HEAD 2>/dev/null || echo 0)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" -c "Add :BuildDate string $(date -u +%Y-%m-%dT%H:%M:%SZ)" $APP/Contents/Info.plist
swiftc -O -module-cache-path "$CACHE" -parse-as-library NetworkScanner.swift Scanner.swift Updater.swift \
  -o $APP/Contents/MacOS/NetworkScanner
xattr -cr $APP
codesign --force --sign - $APP
echo "Built $APP $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist) (build $BUILD)"
