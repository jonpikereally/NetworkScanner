# Network Scanner

A small Mac app that shows what's on your local network: every device's icon, IP and IPv6 addresses, name, type, maker, model, MAC address, hostname, open ports and when it was last seen. Devices that weren't there last time are marked **NEW**. It's five Swift files with no Xcode project and no dependencies, and it doesn't need admin rights.

## Using it

- **Open it** like any app. It scans as soon as it opens; **Scan → Scan Now** (⌘R) rescans. Closing the window quits it.
- **The window** shows your network at the top, lists everything found, and has a status bar with device counts and the countdown to the next automatic scan. Right-click a column header to show or hide columns (Open Ports is hidden by default). Click a column to sort, type in Filter to search, and **Copy List** puts the table on the clipboard (tab separated, pastes into a spreadsheet).
- **Select a device** to see everything known about it in the details pane on the right: what it announces over UPnP and Bonjour, its web page title, Windows computer name, SSH banner, and every open port. **Copy Details** puts it all on the clipboard.
- **Deep Scan** (in the details pane or the right-click menu) checks about 1,100 ports on one device instead of the usual 26 and takes a few seconds. Ports it finds are kept for the rest of the session.
- **Double-click a device** to give it a name. Names are remembered by MAC address. Right-click for Copy IP/MAC and **Open in Browser** for devices with a web page (routers, printers, NAS).
- A **green dot** means the device answered this scan. A **grey dot** means it's in the Mac's ARP cache but didn't answer: usually a sleeping phone, or something that left in the last few minutes.
- **Offline devices**: devices seen in the last 30 days but not found now stay in the list, greyed out with their **Last Seen** time (turn off with **Scan → Show Offline Devices**).
- Devices that don't announce a name are shown as *Maker device* (e.g. "Nintendo device"), or *Private device* when they use a private Wi-Fi address.
- The **Scan** menu has **Scan Automatically** (off, or every 1, 5, 10 or 30 minutes; 5 by default, while the app is open), **Show Offline Devices**, **Look Up Device Makers** and **Forget Remembered Devices…**, which clears names and NEW tracking.

## How it finds devices

1. **TCP probes**: a non-blocking connect to ~25 common ports (SSH, HTTP/S, SMB, AirPlay, Cast, IPP, Sonos, Plex, the iPhone sync port…) on every address in the subnet, 48 hosts at a time. Any answer, even a refusal, means something is there. Networks larger than /22 are cut down to the /24 around the Mac.
2. **ARP cache**: the probes make macOS ARP every address, so `arp -an` afterwards lists devices that ignore TCP entirely (most phones, smart plugs) along with their MAC addresses.
3. **Names**: Bonjour browsing (AirPlay, Chromecast, HomeKit, printers, file sharing and ~25 other types) gives friendly names like "Living Room" and models like `AppleTV14,1`; reverse DNS fills in the rest.
4. **Makers**: the first half of the MAC address, looked up in Wireshark's copy of the IEEE OUI list. Phones and laptops using a *private Wi-Fi address* show "Private address" instead, since those MACs are random.
5. **Identify pass**, after each scan:
   - **UPnP**: one multicast search; TVs, routers, Sonos, consoles, NAS and smart hubs answer with a description giving their friendly name, manufacturer, model and often firmware.
   - **Bonjour details**: printer model and location, HomeKit category (light, plug, thermostat…), Chromecast model and what's playing, AirPlay model and OS version.
   - **Web**: the page title and `Server` header of devices with a web page (e.g. "ASUS RT-AX86U", "Synology DiskStation").
   - **Windows networking**: a NetBIOS name query returns Windows PCs' and Samba NAS boxes' computer names and workgroups.
   - **SSH**: the banner on port 22 names the server software and often the OS (e.g. Ubuntu, Raspbian).
   - **mDNS hostname**: a direct PTR query to each device's port 5353 returns its `name.local`.
6. **IPv6**: a ping to the all-nodes multicast address fills the NDP cache, and `ndp -an` maps each device's IPv6 addresses to its MAC.
7. **Model names**: Apple model identifiers (`iPad8,9`) are shown as marketing names ("iPad Pro 11-inch (2nd gen)").
8. **Type** is a best guess from all of the above (Bonjour model and category and UPnP first, then services, open ports, maker, and web/SSH hints).

A scan of a /24 takes about 10–15 seconds, including the identify pass.

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

To ship a release, bump `CFBundleShortVersionString` in `Info.plist`, write what changed in `RELEASE_NOTES.txt`, and merge to `main`. The **Release** workflow (`.github/workflows/release.yml`) builds every push to `main` on a GitHub Mac runner. When `Info.plist`'s version is newer than the one in `updates/latest.json`, it commits the universal `updates/NetworkScanner.zip` and `updates/latest.json` back to `main`, which ships it. Pushes that don't bump the version ship nothing. You can also run it by hand from the Actions tab.

To ship from your own Mac instead (the PasteStack/Curtain way):

```bash
UPDATE_NOTES="What changed" ./release.sh   # or omit UPDATE_NOTES to use RELEASE_NOTES.txt
# then commit and push updates/ to main
```

`raw.githubusercontent.com` caches for about 5 minutes, so a fresh release can take a moment to show up. Update checks only work while the repo is public.

### Version and build

The Network Scanner menu shows the version, build number and build time, e.g. *Version 1.0 (build 12) · 1 Oct 2026 at 14:03*. The build number is the repo's commit count and the time is stamped into the bundle's Info.plist by `build.sh` / `release.sh`.

### Icon

`NetworkScanner.icns` is prebuilt. To regenerate it: `pip3 install pillow && python3 tools/make_icon.py`.

## Privacy

Scans stay on your network: the identify pass only talks to addresses on your local network. The only things fetched from the internet are `updates/latest.json` from this repo, and (unless you turn off **Look Up Device Makers**) the public maker list from wireshark.org, about once a month, cached in `~/Library/Application Support/NetworkScanner/`.
