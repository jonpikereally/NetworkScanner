# Network Scanner

A small Mac app that shows what's on your local network: every device's IP address, name, type, maker, MAC address and open ports. Devices that weren't there last time are marked **NEW**. It's three Swift files with no Xcode project and no dependencies, and it doesn't need admin rights.

## Using it

- **Open it** like any app. It scans as soon as it opens; **Scan → Scan Now** (⌘R) rescans. Closing the window quits it.
- **The window** shows your network and device count at the top and lists everything found. Click a column to sort, type in Filter to search, and **Copy List** puts the table on the clipboard (tab separated, pastes into a spreadsheet).
- **Double-click a device** to give it a name. Names are remembered by MAC address. Right-click for Copy IP/MAC and **Open in Browser** for devices with a web page (routers, printers, NAS).
- A **green dot** means the device answered this scan. A **grey dot** means it's in the Mac's ARP cache but didn't answer: usually a sleeping phone, or something that left in the last few minutes.
- The **Scan** menu has **Rescan Every 10 Minutes** (on by default, while the app is open), **Look Up Device Makers** and **Forget Remembered Devices…**, which clears names and NEW tracking.

## How it finds devices

1. **TCP probes**: a non-blocking connect to ~25 common ports (SSH, HTTP/S, SMB, AirPlay, Cast, IPP, Sonos, Plex, the iPhone sync port…) on every address in the subnet, 48 hosts at a time. Any answer, even a refusal, means something is there. Networks larger than /22 are cut down to the /24 around the Mac.
2. **ARP cache**: the probes make macOS ARP every address, so `arp -an` afterwards lists devices that ignore TCP entirely (most phones, smart plugs) along with their MAC addresses.
3. **Names**: Bonjour browsing (AirPlay, Chromecast, HomeKit, printers, file sharing and ~25 other types) gives friendly names like "Living Room" and models like `AppleTV14,1`; reverse DNS fills in the rest.
4. **Makers**: the first half of the MAC address, looked up in Wireshark's copy of the IEEE OUI list. Phones and laptops using a *private Wi-Fi address* show "Private address" instead, since those MACs are random.
5. **Type** is a best guess from all of the above (Bonjour model and services first, then open ports, then maker).

A scan of a /24 takes about 10 seconds.

## Build and install

```bash
./build.sh      # swiftc → NetworkScanner.app, ad-hoc signed
./install.sh    # copies to /Applications and launches it
```

Requires macOS 14+ and the Command Line Tools (`xcode-select --install`). Run `install.sh` from Terminal.

### Permissions

macOS 15 and later ask for **Local Network** access the first time it scans. Allow it: without it no device can answer, and the Devices window shows a warning with a button to the right Settings pane. The app is signed ad-hoc, so each rebuild or update can make macOS ask again.

### Updates

Network Scanner checks `updates/latest.json` in this repo shortly after launch and every 6 hours. When a newer version exists, the Dock icon gets a ↑ badge, the window shows an **⬆︎ Update to vX…** button, and the Network Scanner menu shows **⬆︎ Install Update to vX…** in place of **Check for Updates…**. Installing shows the release notes and asks first, then downloads `updates/NetworkScanner.zip`, quits, swaps the app in place, resets its permissions and relaunches. **Update Source…** in the Network Scanner menu can point it at a different feed, such as a local file for testing.

To ship a release:

```bash
# 1. bump CFBundleShortVersionString in Info.plist
UPDATE_NOTES="What changed" ./release.sh   # universal build → updates/NetworkScanner.zip + updates/latest.json
# 2. commit and push to main, including updates/
```

`raw.githubusercontent.com` caches for about 5 minutes, so a fresh release can take a moment to show up. Update checks only work while the repo is public.

### Version and build

The Network Scanner menu shows the version, build number and build time, e.g. *Version 1.0 (build 12) · 1 Oct 2026 at 14:03*. The build number is the repo's commit count and the time is stamped into the bundle's Info.plist by `build.sh` / `release.sh`.

### Icon

`NetworkScanner.icns` is prebuilt. To regenerate it: `pip3 install pillow && python3 tools/make_icon.py`.

## Privacy

Scans stay on your network. The only things fetched from the internet are `updates/latest.json` from this repo, and (unless you turn off **Look Up Device Makers**) the public maker list from wireshark.org, about once a month, cached in `~/Library/Application Support/NetworkScanner/`.
