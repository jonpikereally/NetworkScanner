# Network Scanner

Regular macOS windowed app (AppKit + a SwiftUI table; not a menu bar app) that lists devices on the local network.
Plain swiftc, no Xcode project, no dependencies, macOS 14+.

- `NetworkScanner.swift`: app delegate, main menu, Dock badge, devices window, remembered devices.
- `Scanner.swift`: interface/gateway discovery, TCP probes, ARP cache, reverse DNS, Bonjour (incl. TXT details), OUI makers, `Device` and its type guess.
- `Identify.swift`: the identify pass after each scan (UPnP/SSDP, web titles, NetBIOS names, SSH banners) and Deep Scan.
- `Updater.swift`: the shared self-update scheme (same as PasteStack and Curtain). Keep it in sync with those.

## Building

- `./build.sh` builds `NetworkScanner.app` (gitignored) for this Mac; `./install.sh` copies it to /Applications.
- Build number = `git rev-list --count HEAD`, build time = UTC, both stamped into the bundle's Info.plist.
- CI (`.github/workflows/build.yml`) runs `release.sh` on macOS for branches and PRs, so every change proves the universal build compiles.

## Releases

Releases ship automatically: bump `CFBundleShortVersionString` in Info.plist and update `RELEASE_NOTES.txt` in the
same PR. On every push to main, `.github/workflows/release.yml` builds on macOS and, if Info.plist's version is newer
than `updates/latest.json`, commits `updates/NetworkScanner.zip` + `latest.json` to main as github-actions[bot].
Never hand-edit `updates/`. Installed copies read `updates/latest.json` from raw.githubusercontent.com (main branch)
at launch and every 6 hours. Manual fallback: `UPDATE_NOTES="…" ./release.sh`, then push `updates/`.
`./build.sh` alone publishes nothing.

## Known traps

- Ad-hoc signing: every rebuild voids privacy grants. install.sh and the updater run `tccutil reset All`.
- Plain-HTTP requests to devices rely on `NSAllowsLocalNetworking` in Info.plist (ATS). Identify only fetches from IP addresses on the LAN.
- macOS 15+ Local Network privacy: without it every probe fails, and the window shows a hint.
  New Bonjour types must also be added to `NSBonjourServices` in Info.plist.
