import AppKit
import SwiftUI

// Network Scanner: a Mac app that lists the devices on the local network.
// Scanning lives in Scanner.swift, in-app updates in Updater.swift.

// MARK: - Remembered devices

/// Devices seen before, keyed by MAC (or IP when there is none), so new arrivals can be flagged
/// and the names people give devices stick.
struct KnownDevice: Codable {
    var firstSeen: Date
    var lastSeen: Date
    var label: String?
}

enum KnownDevices {
    private static let key = "KnownDevices"

    static func load() -> [String: KnownDevice] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let known = try? JSONDecoder().decode([String: KnownDevice].self, from: data) else { return [:] }
        return known
    }

    static func save(_ known: [String: KnownDevice]) {
        if let data = try? JSONEncoder().encode(known) { UserDefaults.standard.set(data, forKey: key) }
    }
}

// MARK: - State shared by the menu and the window

final class ScanStore: ObservableObject {
    @Published var devices: [Device] = []
    @Published var network: NetworkInfo?
    @Published var scannedCIDR = ""
    @Published var trimmed = false
    @Published var scanning = false
    @Published var progress = 0.0
    @Published var status = ""
    @Published var lastScan: Date?
    @Published var error: String?
    @Published var nothingAnswered = false
    /// Newer version waiting on GitHub, shown as a button in the window.
    @Published var updateVersion: String?
    var onChange: () -> Void = {}
    var onInstallUpdate: () -> Void = {}

    func scan() {
        guard !scanning else { return }
        scanning = true
        progress = 0
        status = "Starting\u{2026}"
        error = nil
        onChange()
        Scanner.scan(progress: { [weak self] p, s in
            self?.progress = p
            self?.status = s
        }, completion: { [weak self] result in
            guard let self else { return }
            self.scanning = false
            self.status = ""
            switch result {
            case .success(let outcome): self.apply(outcome)
            case .failure(let e): self.error = e.localizedDescription
            }
            self.lastScan = Date()
            self.onChange()
        })
    }

    private func apply(_ outcome: ScanOutcome) {
        var known = KnownDevices.load()
        let firstEverScan = known.isEmpty
        let now = Date()
        devices = outcome.devices.map { d in
            var d = d
            if var k = known[d.knownKey] {
                k.lastSeen = now
                d.label = k.label
                d.firstSeen = k.firstSeen
                known[d.knownKey] = k
            } else {
                d.isNew = !firstEverScan && !d.isSelf
                d.firstSeen = now
                known[d.knownKey] = KnownDevice(firstSeen: now, lastSeen: now, label: nil)
            }
            return d
        }
        KnownDevices.save(known)
        network = outcome.network
        scannedCIDR = outcome.scannedCIDR
        trimmed = outcome.trimmed
        nothingAnswered = outcome.nothingAnswered
    }

    func rename(_ device: Device, to label: String?) {
        let clean = label?.trimmingCharacters(in: .whitespacesAndNewlines)
        let value = (clean?.isEmpty ?? true) ? nil : clean
        var known = KnownDevices.load()
        var k = known[device.knownKey] ?? KnownDevice(firstSeen: device.firstSeen, lastSeen: Date(), label: nil)
        k.label = value
        known[device.knownKey] = k
        KnownDevices.save(known)
        if let i = devices.firstIndex(where: { $0.id == device.id }) { devices[i].label = value }
        onChange()
    }

    /// Re-applies makers once the OUI list has loaded (it may arrive after the first scan).
    func refreshVendors() {
        for i in devices.indices {
            devices[i].vendor = devices[i].mac.flatMap { VendorDB.shared.lookup($0) }
        }
        onChange()
    }

    var summary: String {
        if scanning { return status.isEmpty ? "Scanning\u{2026}" : status }
        if let error { return error }
        guard let lastScan else { return "Not scanned yet" }
        let n = devices.count
        let new = devices.filter(\.isNew).count
        var s = "\(n) device\(n == 1 ? "" : "s")"
        if new > 0 { s += ", \(new) new" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return s + " \u{00B7} scanned \(f.localizedString(for: lastScan, relativeTo: Date()))"
    }

    var networkLine: String {
        guard let n = network else { return "No network" }
        var s = "\(n.interfaceName) \u{00B7} \(scannedCIDR.isEmpty ? n.cidr : scannedCIDR)"
        if let gw = n.gateway { s += " \u{00B7} router \(IPv4.string(gw))" }
        s += " \u{00B7} this Mac \(IPv4.string(n.address))"
        return s
    }

    func text(of rows: [Device]) -> String {
        var lines = ["IP Address\tName\tType\tMaker\tMAC Address\tOpen Ports\tServices"]
        for d in rows {
            lines.append([d.ip, d.displayName, d.kind, d.vendor ?? "", d.mac ?? "", d.portSummary, d.serviceSummary]
                .joined(separator: "\t"))
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - Devices window

struct DevicesView: View {
    @ObservedObject var store: ScanStore
    @State private var sortOrder = [KeyPathComparator(\Device.ipKey)]
    @State private var filter = ""
    @State private var selection = Set<Device.ID>()

    private var rows: [Device] {
        let q = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let shown = q.isEmpty ? store.devices : store.devices.filter { d in
            [d.ip, d.displayName, d.kind, d.vendor ?? "", d.mac ?? "", d.hostname ?? "", d.serviceSummary]
                .contains { $0.lowercased().contains(q) }
        }
        return shown.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if store.nothingAnswered && !store.scanning { localNetworkHint }
            table
        }
        .frame(minWidth: 820, minHeight: 360)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(store.networkLine).font(.headline)
                if store.scanning {
                    ProgressView(value: store.progress) { EmptyView() }
                        .progressViewStyle(.linear)
                        .frame(maxWidth: 320)
                    Text(store.status).font(.caption).foregroundStyle(.secondary)
                } else {
                    Text(store.summary + (store.trimmed ? " \u{00B7} large network, scanned only the /24 around this Mac" : ""))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let v = store.updateVersion {
                Button("\u{2B06}\u{FE0E} Update to v\(v)\u{2026}") { store.onInstallUpdate() }
                    .buttonStyle(.borderedProminent)
                    .help("A new version of Network Scanner is ready to install")
            }
            TextField("Filter", text: $filter)
                .textFieldStyle(.roundedBorder)
                .frame(width: 180)
            Button("Copy List") {
                copy(store.text(of: rows))
            }
            .disabled(store.devices.isEmpty)
            Button(store.scanning ? "Scanning\u{2026}" : "Scan Now") { store.scan() }
                .disabled(store.scanning)
        }
        .padding(12)
    }

    private var localNetworkHint: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            Text("No device answered. Network Scanner needs Local Network access: turn it on in System Settings \u{2192} Privacy & Security \u{2192} Local Network, then scan again.")
                .font(.callout)
            Spacer()
            Button("Open Settings") {
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork") {
                    NSWorkspace.shared.open(url)
                }
            }
        }
        .padding(10)
        .background(Color.yellow.opacity(0.12))
    }

    private var table: some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("", value: \.statusRank) { d in
                Circle()
                    .fill(d.responded ? Color.green : Color.secondary.opacity(0.5))
                    .frame(width: 8, height: 8)
                    .help(d.responded ? "Answered this scan" : "In the Mac's ARP cache but didn't answer a probe (asleep, or left recently)")
            }
            .width(16)
            TableColumn("IP Address", value: \.ipKey) { d in
                Text(d.ip).monospacedDigit()
            }
            .width(min: 100, ideal: 115)
            TableColumn("Name", value: \.sortName) { d in
                HStack(spacing: 6) {
                    Text(d.displayName.isEmpty ? "\u{2014}" : d.displayName)
                        .foregroundStyle(d.displayName.isEmpty ? Color.secondary : Color.primary)
                        .help(d.hostname.map { "Hostname: \($0)" } ?? "")
                    if d.isNew {
                        Text("NEW").font(.caption2.bold()).foregroundStyle(.white)
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(Capsule().fill(Color.accentColor))
                    }
                }
            }
            .width(min: 140, ideal: 200)
            TableColumn("Type", value: \.kind) { d in
                Text(d.kind).help(d.model.map { "Model: \($0)" } ?? "")
            }
            .width(min: 100, ideal: 150)
            TableColumn("Maker", value: \.sortVendor) { d in
                Text(d.vendor ?? (d.randomizedMAC ? "Private address" : "\u{2014}"))
                    .foregroundStyle(d.vendor == nil ? Color.secondary : Color.primary)
                    .help(d.randomizedMAC ? "This device uses a private (randomized) Wi-Fi address, so its maker can't be looked up." : "")
            }
            .width(min: 100, ideal: 160)
            TableColumn("MAC Address", value: \.sortMAC) { d in
                Text(d.mac ?? "\u{2014}").font(.system(.body, design: .monospaced))
            }
            .width(min: 130, ideal: 140)
            TableColumn("Open Ports", value: \.portCount) { d in
                Text(d.portSummary.isEmpty ? "\u{2014}" : d.portSummary)
                    .foregroundStyle(d.portSummary.isEmpty ? Color.secondary : Color.primary)
                    .help(d.serviceSummary.isEmpty ? "" : "Bonjour: \(d.serviceSummary)")
            }
            .width(min: 100, ideal: 180)
        }
        .contextMenu(forSelectionType: Device.ID.self) { ids in
            if let d = device(ids) {
                Button("Rename\u{2026}") { rename(d) }
                if d.label != nil { Button("Clear Name") { store.rename(d, to: nil) } }
                Divider()
                Button("Copy IP Address") { copy(d.ip) }
                if let mac = d.mac { Button("Copy MAC Address") { copy(mac) } }
                if let url = d.webURL {
                    Divider()
                    Button("Open \(url.absoluteString) in Browser") { NSWorkspace.shared.open(url) }
                }
            } else if !ids.isEmpty {
                Button("Copy \(ids.count) Rows") {
                    copy(store.text(of: rows.filter { ids.contains($0.id) }))
                }
            }
        } primaryAction: { ids in
            if let d = device(ids) { rename(d) }
        }
    }

    private func device(_ ids: Set<Device.ID>) -> Device? {
        guard ids.count == 1, let id = ids.first else { return nil }
        return store.devices.first { $0.id == id }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    private func rename(_ d: Device) {
        let alert = NSAlert()
        alert.messageText = "Name for \(d.ip)"
        alert.informativeText = "Network Scanner remembers this device by its MAC address"
            + (d.mac.map { " (\($0))" } ?? "") + ". Leave empty to use the name it announces."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        field.stringValue = d.label ?? ""
        field.placeholderString = d.bonjourName ?? d.hostname ?? "Name"
        alert.accessoryView = field
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        store.rename(d, to: field.stringValue)
    }
}

// MARK: - App

@main
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private static var retained: AppDelegate?

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        retained = delegate
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }

    private let store = ScanStore()
    private var window: NSWindow?
    private var autoTimer: Timer?
    private var checkingForUpdates = false

    private var autoScan: Bool {
        get { UserDefaults.standard.object(forKey: "AutoScan") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "AutoScan") }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.mainMenu = buildMainMenu()

        store.onChange = { [weak self] in self?.render() }
        store.onInstallUpdate = { [weak self] in self?.checkForUpdates() }
        Updater.shared.onChange = { [weak self] in self?.render() }
        Updater.shared.startAutomaticChecks()
        VendorDB.shared.prepare { [weak self] in self?.store.refreshVendors() }

        showDevices()
        render()
        scheduleAutoScan()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in self?.store.scan() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showDevices()
        return false
    }

    /// Mirrors update and scan state into the window, its title and the Dock icon.
    /// An update waiting shows as an arrow badge on the Dock icon and a button in the window.
    private func render() {
        let available = Updater.shared.available?.version
        if store.updateVersion != available { store.updateVersion = available }
        NSApp.dockTile.badgeLabel = available != nil ? "\u{2191}" : nil
        window?.subtitle = store.summary
    }

    // MARK: menus

    private func buildMainMenu() -> NSMenu {
        let main = NSMenu()

        let app = NSMenu(title: "Network Scanner")
        app.delegate = self
        app.addItem(withTitle: "About Network Scanner", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        app.addItem(.separator())
        // Update items are filled in by menuNeedsUpdate so their titles stay current.
        app.addItem(.separator())
        app.addItem(withTitle: "Hide Network Scanner", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = app.addItem(withTitle: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        app.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        app.addItem(.separator())
        app.addItem(withTitle: "Quit Network Scanner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        main.addItem(submenu(app))

        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        main.addItem(submenu(edit))

        let scan = NSMenu(title: "Scan")
        scan.delegate = self
        main.addItem(submenu(scan))

        let window = NSMenu(title: "Window")
        window.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        window.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        window.addItem(.separator())
        window.addItem(item("Devices", #selector(showDevices), key: "1"))
        main.addItem(submenu(window))
        NSApp.windowsMenu = window

        let help = NSMenu(title: "Help")
        help.addItem(item("Network Scanner on GitHub", #selector(openGitHub)))
        main.addItem(submenu(help))
        NSApp.helpMenu = help
        return main
    }

    private func submenu(_ menu: NSMenu) -> NSMenuItem {
        let i = NSMenuItem(title: menu.title, action: nil, keyEquivalent: "")
        i.submenu = menu
        return i
    }

    private func item(_ title: String, _ action: Selector, key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: key)
        i.target = self
        return i
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        switch menu.title {
        case "Scan": fillScanMenu(menu)
        case "Network Scanner": fillUpdateItems(menu)
        default: break
        }
    }

    private func fillScanMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        let scan = item(store.scanning ? "Scanning\u{2026}" : "Scan Now", #selector(scanNow), key: "r")
        scan.isEnabled = !store.scanning
        menu.addItem(scan)
        let auto = item("Rescan Every 10 Minutes", #selector(toggleAutoScan))
        auto.state = autoScan ? .on : .off
        menu.addItem(auto)
        menu.addItem(.separator())
        let makers = item("Look Up Device Makers", #selector(toggleMakers))
        makers.state = VendorDB.shared.enabled ? .on : .off
        makers.toolTip = "Downloads the public MAC address maker list from wireshark.org about once a month."
        menu.addItem(makers)
        menu.addItem(item("Forget Remembered Devices\u{2026}", #selector(forgetDevices)))
    }

    /// The update block sits between the first two separators of the app menu.
    private func fillUpdateItems(_ menu: NSMenu) {
        let tag = 77
        menu.items.filter { $0.tag == tag }.forEach(menu.removeItem)
        let updateTitle = Updater.shared.available.map { "\u{2B06}\u{FE0E} Install Update to v\($0.version)\u{2026}" }
            ?? "Check for Updates\u{2026}"
        let update = item(checkingForUpdates ? "Checking for Updates\u{2026}" : updateTitle, #selector(checkForUpdates))
        update.isEnabled = !checkingForUpdates
        var versionTitle = "Version \(AppVersion.version) (build \(AppVersion.build))"
        if let date = AppVersion.buildDate {
            versionTitle += " \u{00B7} \(date.formatted(date: .abbreviated, time: .shortened))"
        }
        let version = NSMenuItem(title: versionTitle, action: nil, keyEquivalent: "")
        version.isEnabled = false
        let items = [update, item("Update Source\u{2026}", #selector(editUpdateSource)),
                     item("Network Scanner on GitHub", #selector(openGitHub)), version]
        let at = (menu.items.firstIndex { $0.isSeparatorItem } ?? 0) + 1
        for (n, i) in items.enumerated() {
            i.tag = tag
            menu.insertItem(i, at: at + n)
        }
    }

    // MARK: actions

    @objc private func scanNow() { store.scan() }

    @objc private func showDevices() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 560),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            w.title = "Network Scanner"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: DevicesView(store: store))
            w.setFrameAutosaveName("DevicesWindow")
            if !w.setFrameUsingName("DevicesWindow") { w.center() }
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        render()
    }

    @objc private func toggleAutoScan() {
        autoScan.toggle()
        scheduleAutoScan()
    }

    private func scheduleAutoScan() {
        autoTimer?.invalidate()
        autoTimer = nil
        guard autoScan else { return }
        let t = Timer(timeInterval: 600, repeats: true) { [weak self] _ in self?.store.scan() }
        RunLoop.main.add(t, forMode: .common)
        autoTimer = t
    }

    @objc private func toggleMakers() {
        VendorDB.shared.enabled.toggle()
        if VendorDB.shared.enabled {
            VendorDB.shared.prepare { [weak self] in self?.store.refreshVendors() }
        }
        store.refreshVendors()
    }

    @objc private func forgetDevices() {
        let alert = NSAlert()
        alert.messageText = "Forget remembered devices?"
        alert.informativeText = "Network Scanner forgets every device it has seen and the names you gave them. "
            + "The next scan starts fresh, so nothing will be marked new."
        alert.addButton(withTitle: "Forget")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        KnownDevices.save([:])
        store.devices = store.devices.map { var d = $0; d.label = nil; d.isNew = false; return d }
        render()
    }

    // MARK: updates

    @objc private func checkForUpdates() {
        if let m = Updater.shared.available {
            offerInstall(m)
            return
        }
        checkingForUpdates = true
        Updater.shared.check { [weak self] result in
            guard let self else { return }
            self.checkingForUpdates = false
            self.render()
            switch result {
            case .success(let m?):
                self.offerInstall(m)
            case .success(nil):
                let alert = NSAlert()
                alert.messageText = "Network Scanner is up to date"
                alert.informativeText = "You're running v\(AppVersion.version), the newest version available."
                alert.runModal()
            case .failure(let error):
                self.showUpdateError(error)
            }
        }
    }

    private func offerInstall(_ m: UpdateManifest) {
        let alert = NSAlert()
        alert.messageText = "Update to Network Scanner v\(m.version)?"
        var info = "You have v\(AppVersion.version)."
        if let notes = m.notes, !notes.isEmpty { info += "\n\nWhat's new:\n\(notes)" }
        info += "\n\nNetwork Scanner will quit, update itself and reopen. Your device names are kept."
            + "\n\nAfterwards macOS may ask again for Local Network access. Allow it, or scans will find nothing."
        alert.informativeText = info
        alert.addButton(withTitle: "Install and Relaunch")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        Updater.shared.install(m) { [weak self] error in
            self?.showUpdateError(error)
        }
    }

    private func showUpdateError(_ error: Error) {
        let alert = NSAlert()
        alert.messageText = "Couldn't update Network Scanner"
        alert.informativeText = error.localizedDescription
        if case UpdateError.noFeed = error {
            alert.addButton(withTitle: "Set Update Source\u{2026}")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn { editUpdateSource() }
            return
        }
        alert.runModal()
    }

    @objc private func editUpdateSource() {
        let alert = NSAlert()
        alert.messageText = "Update Source"
        alert.informativeText = "Where Network Scanner looks for new versions: a web link or a file path to a latest.json feed. "
            + "Leave it empty to use the built-in source:\n\(AppVersion.updateFeed)"
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.stringValue = UserDefaults.standard.string(forKey: "UpdateFeed") ?? ""
        field.placeholderString = AppVersion.updateFeed
        alert.accessoryView = field
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if !value.isEmpty && Updater.url(from: value) == nil {
            showUpdateError(UpdateError.badFeed(value))
            return
        }
        Updater.shared.feed = value
        Updater.shared.check { _ in }
    }

    @objc private func openGitHub() {
        if let url = URL(string: AppVersion.repo) { NSWorkspace.shared.open(url) }
    }
}
