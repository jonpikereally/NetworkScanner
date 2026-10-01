# Network Scanner

Regular macOS windowed app (AppKit + a SwiftUI table; not a menu bar app) that lists devices on the local network.
Plain swiftc, no Xcode project, no dependencies, macOS 14+.

- `NetworkScanner.swift`: app delegate, main menu, Dock badge, devices window, remembered devices.
- `Scanner.swift`: interface/gateway discovery, TCP probes, ARP cache, reverse DNS, Bonjour, OUI makers.
- `Updater.swift`: the shared self-update scheme (same as PasteStack and Curtain). Keep it in sync with those.

## Building

- `./build.sh` builds `NetworkScanner.app` (gitignored) for this Mac; `./install.sh` copies it to /Applications.
- Build number = `git rev-list --count HEAD`, build time = UTC, both stamped into the bundle's Info.plist.
- CI (`.github/workflows/build.yml`) runs `release.sh` on macOS, so every push proves the universal build compiles.

## Releases

Bump `CFBundleShortVersionString` in Info.plist, run `UPDATE_NOTES="…" ./release.sh`, then commit and push
`updates/` to main. Installed copies read `updates/latest.json` from raw.githubusercontent.com (main branch)
at launch and every 6 hours. `./build.sh` alone publishes nothing.

## Known traps

- Ad-hoc signing: every rebuild voids privacy grants. install.sh and the updater run `tccutil reset All`.
- macOS 15+ Local Network privacy: without it every probe fails, and the window shows a hint.
  New Bonjour types must also be added to `NSBonjourServices` in Info.plist.
