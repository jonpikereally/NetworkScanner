import Foundation
import Darwin
import SystemConfiguration

// Finding devices on the local network without root:
//   1. TCP connect probes to common ports on every address in the subnet. Any answer, even a
//      refusal, proves a host is there, and the attempts make macOS ARP for every address.
//   2. The ARP cache then lists everything that answered ARP, including phones and IoT devices
//      that ignore TCP entirely, with their MAC addresses.
//   3. Bonjour (mDNS) browsing and reverse DNS supply names, models and services.
//   4. The MAC's first bytes give the maker, from the public IEEE OUI list (optional).
//   Then Identify.swift asks each device for more (UPnP, web page, NetBIOS, SSH).

// MARK: - Address helpers

enum IPv4 {
    static func string(_ a: UInt32) -> String {
        "\(a >> 24).\((a >> 16) & 255).\((a >> 8) & 255).\(a & 255)"
    }

    static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var out: UInt32 = 0
        for p in parts {
            guard let n = UInt32(p), n < 256 else { return nil }
            out = out << 8 | n
        }
        return out
    }

    static func socketAddress(_ a: UInt32, port: UInt16 = 0) -> sockaddr_in {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        sa.sin_addr = in_addr(s_addr: a.bigEndian)
        return sa
    }

    /// IPv4 address from a sockaddr blob (Bonjour hands these out as Data).
    static func from(_ data: Data) -> UInt32? {
        data.withUnsafeBytes { raw -> UInt32? in
            guard raw.count >= MemoryLayout<sockaddr_in>.size else { return nil }
            let sa = raw.loadUnaligned(as: sockaddr_in.self)
            guard sa.sin_family == sa_family_t(AF_INET) else { return nil }
            return UInt32(bigEndian: sa.sin_addr.s_addr)
        }
    }
}

enum MAC {
    /// Lowercase, colon separated, two digits per byte ("0:1b:..." from arp becomes "00:1b:...").
    static func normalize(_ s: String) -> String? {
        let parts = s.split(separator: ":")
        guard parts.count == 6 else { return nil }
        var out: [String] = []
        for p in parts {
            guard p.count <= 2, let b = UInt8(p, radix: 16) else { return nil }
            out.append(String(format: "%02x", b))
        }
        let joined = out.joined(separator: ":")
        return joined == "00:00:00:00:00:00" || joined == "ff:ff:ff:ff:ff:ff" ? nil : joined
    }

    /// Locally administered bit: phones and laptops use these "private Wi-Fi addresses",
    /// so they have no maker and may change.
    static func isRandomized(_ mac: String) -> Bool {
        guard let first = UInt8(mac.prefix(2), radix: 16) else { return false }
        return first & 0x02 != 0
    }
}

// MARK: - The network this Mac is on

struct NetworkInfo {
    let interface: String        // BSD name, e.g. en0
    let interfaceName: String    // "Wi-Fi", "Ethernet"
    let address: UInt32
    let netmask: UInt32
    let mac: String?
    let gateway: UInt32?
    /// Every IPv4 address this Mac has on any interface (Wi-Fi and Ethernet both on the same
    /// network, say), with that interface's MAC.
    var localAddresses: [UInt32: String] = [:]

    var prefix: Int { netmask.nonzeroBitCount }
    var network: UInt32 { address & netmask }
    var cidr: String { "\(IPv4.string(network))/\(prefix)" }

    func contains(_ a: UInt32) -> Bool { a & netmask == network }

    /// Addresses to probe. Subnets bigger than /22 (1022 hosts) are cut down to the /24 around
    /// this Mac, which is where home devices nearly always are.
    var scanRange: (hosts: [UInt32], cidr: String, trimmed: Bool) {
        var mask = netmask
        var trimmed = false
        if prefix < 22 { mask = 0xFFFF_FF00; trimmed = true }
        let net = address & mask
        let broadcast = net | ~mask
        guard broadcast > net + 1 else { return ([address], "\(IPv4.string(address))/32", trimmed) }
        let hosts = Array((net + 1)..<broadcast)
        return (hosts, "\(IPv4.string(net))/\(mask.nonzeroBitCount)", trimmed)
    }

    static func current() -> NetworkInfo? {
        let route = shell("/sbin/route", ["-n", "get", "default"])
        var iface: String?
        var gateway: UInt32?
        for line in route.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            if parts[0] == "interface" { iface = parts[1] }
            if parts[0] == "gateway" { gateway = IPv4.parse(parts[1]) }
        }

        // Interface addresses: the default route's interface, else the first private IPv4 one.
        var v4: [String: (UInt32, UInt32)] = [:]
        var order: [String] = []
        var macs: [String: String] = [:]
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            guard let sa = ifa.ifa_addr else { continue }
            let name = String(cString: ifa.ifa_name)
            let flags = Int32(ifa.ifa_flags)
            if sa.pointee.sa_family == UInt8(AF_INET), flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0,
               let mask = ifa.ifa_netmask {
                let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                if v4[name] == nil { v4[name] = (addr, m); order.append(name) }
            } else if sa.pointee.sa_family == UInt8(AF_LINK) {
                // sockaddr_dl: 8 header bytes, then the interface name, then the link-level address.
                sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { dl in
                    let d = dl.pointee
                    guard d.sdl_alen == 6 else { return }
                    let base = UnsafeRawPointer(dl).advanced(by: 8 + Int(d.sdl_nlen))
                    let bytes = (0..<6).map { String(format: "%02x", base.load(fromByteOffset: $0, as: UInt8.self)) }
                    macs[name] = MAC.normalize(bytes.joined(separator: ":"))
                }
            }
        }

        func isPrivate(_ a: UInt32) -> Bool {
            a >> 24 == 10 || a >> 20 == 0xAC1 || a >> 16 == 0xC0A8 || a >> 22 == 0x191  // 10/8, 172.16/12, 192.168/16, 100.64/10
        }
        let chosen = iface.flatMap { v4[$0] != nil ? $0 : nil }
            ?? order.first { $0.hasPrefix("en") && isPrivate(v4[$0]!.0) }
            ?? order.first { !$0.hasPrefix("utun") && isPrivate(v4[$0]!.0) }
        guard let name = chosen, let pair = v4[name] else { return nil }
        let (addr, mask) = pair
        let gw = gateway.flatMap { (addr & mask) == ($0 & mask) ? $0 : nil }
        var info = NetworkInfo(interface: name, interfaceName: displayName(bsd: name) ?? name,
                               address: addr, netmask: mask, mac: macs[name], gateway: gw)
        for (ifname, (a, _)) in v4 { info.localAddresses[a] = macs[ifname] ?? "" }
        return info
    }

    private static func displayName(bsd: String) -> String? {
        guard let all = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return nil }
        for i in all where (SCNetworkInterfaceGetBSDName(i) as String?) == bsd {
            return SCNetworkInterfaceGetLocalizedDisplayName(i) as String?
        }
        return nil
    }
}

/// Runs a tool and returns its stdout ("" on failure).
func shell(_ tool: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: tool)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}

// MARK: - TCP probing

enum Probe {
    static let ports: [UInt16: String] = [
        21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
        445: "SMB", 515: "LPD", 548: "AFP", 554: "RTSP", 631: "IPP", 1400: "Sonos", 1883: "MQTT",
        3389: "RDP", 3689: "DAAP", 5000: "UPnP", 5900: "VNC", 7000: "AirPlay", 8008: "Cast",
        8009: "Cast", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer", 32400: "Plex", 62078: "iOS",
    ]
    static let webPorts: [UInt16] = [80, 8080, 443, 8443]

    private static let nameLock = NSLock()
    private static var nameCache: [UInt16: String] = [:]

    /// Short service name for a port: our own list first, then /etc/services.
    static func name(_ port: UInt16) -> String? {
        if let n = ports[port] { return n }
        nameLock.lock(); defer { nameLock.unlock() }
        if let n = nameCache[port] { return n.isEmpty ? nil : n }
        let n = getservbyport(Int32(port.bigEndian), "tcp").map { String(cString: $0.pointee.s_name) } ?? ""
        nameCache[port] = n
        return n.isEmpty ? nil : n
    }

    /// One non-blocking connect per port, all polled together. A host is alive if any port
    /// accepts or actively refuses; silence and "host unreachable" mean nobody's there.
    static func probe(_ host: UInt32, ports list: [UInt16]? = nil, timeoutMs: Int = 700) -> (alive: Bool, open: [UInt16]) {
        var alive = false
        var open: [UInt16] = []
        var pending: [Int32: UInt16] = [:]
        for port in list ?? Array(ports.keys) {
            let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            guard fd >= 0 else { continue }
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
            var sa = IPv4.socketAddress(host, port: port)
            let r = withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            let err = errno
            if r == 0 {
                alive = true; open.append(port); close(fd)
            } else if err == EINPROGRESS {
                pending[fd] = port
            } else {
                if err == ECONNREFUSED { alive = true }
                close(fd)
            }
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        while !pending.isEmpty {
            let remaining = Int32(deadline.timeIntervalSinceNow * 1000)
            guard remaining > 0 else { break }
            var fds = pending.keys.map { pollfd(fd: $0, events: Int16(POLLOUT), revents: 0) }
            let n = poll(&fds, nfds_t(fds.count), remaining)
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { break }
            for p in fds where p.revents != 0 {
                var soErr: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(p.fd, SOL_SOCKET, SO_ERROR, &soErr, &len)
                if soErr == 0, let port = pending[p.fd] { alive = true; open.append(port) }
                else if soErr == ECONNREFUSED { alive = true }
                close(p.fd)
                pending[p.fd] = nil
            }
        }
        pending.keys.forEach { close($0) }
        return (alive, open.sorted())
    }

    /// Each probe holds ~26 sockets; GUI apps start with a 256 file limit.
    static func raiseFileLimit() {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0 else { return }
        let want = min(rlim_t(4096), rl.rlim_max)
        if rl.rlim_cur < want {
            rl.rlim_cur = want
            setrlimit(RLIMIT_NOFILE, &rl)
        }
    }
}

// MARK: - ARP cache and reverse DNS

enum ARP {
    /// IP → MAC for complete entries on the given interface.
    static func table(interface: String) -> [UInt32: String] {
        // "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]"
        var out: [UInt32: String] = [:]
        for line in shell("/usr/sbin/arp", ["-an"]).split(separator: "\n") {
            let f = line.split(separator: " ")
            guard f.count >= 6, f[2] == "at", f[4] == "on", f[5] == interface else { continue }
            guard let ip = IPv4.parse(f[1].trimmingCharacters(in: CharacterSet(charactersIn: "()"))),
                  let mac = MAC.normalize(String(f[3])) else { continue }
            out[ip] = mac
        }
        return out
    }
}

/// IPv6 neighbours. Pinging the all-nodes multicast address makes every IPv6 device on the
/// link answer, which fills the NDP cache; `ndp -an` then maps their addresses to MACs.
enum NDP {
    static func wake(interface: String) {
        _ = shell("/sbin/ping6", ["-c", "2", "-q", "ff02::1%\(interface)"])
    }

    /// MAC → IPv6 addresses on the interface, link-local (fe80::) first.
    static func table(interface: String) -> [String: [String]] {
        // "fe80::1c4e:bf04:aa:bb%en0   5a:49:58:56:a3:ac   en0 23h59m58s S R"
        var out: [String: [String]] = [:]
        for line in shell("/usr/sbin/ndp", ["-an"]).split(separator: "\n") {
            let f = line.split(separator: " ", omittingEmptySubsequences: true)
            guard f.count >= 3, f[2] == interface, let mac = MAC.normalize(String(f[1])) else { continue }
            let addr = String(f[0].split(separator: "%").first ?? f[0])
            guard addr.contains(":") else { continue }
            out[mac, default: []].append(addr)
        }
        for (mac, list) in out {
            out[mac] = list.sorted { a, b in
                let la = a.hasPrefix("fe80"), lb = b.hasPrefix("fe80")
                return la != lb ? la : a < b
            }
        }
        return out
    }
}

enum DNS {
    static func reverse(_ ip: UInt32) -> String? {
        var sa = IPv4.socketAddress(ip)
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let r = host.withUnsafeMutableBufferPointer { buf in
            withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), buf.baseAddress, socklen_t(buf.count), nil, 0, NI_NAMEREQD)
                }
            }
        }
        guard r == 0 else { return nil }
        var name = String(cString: host)
        while name.hasSuffix(".") { name.removeLast() }
        return name.isEmpty || name == IPv4.string(ip) ? nil : name
    }
}

// MARK: - Bonjour

struct BonjourHost {
    var name: String?
    var namePriority = Int.max
    var types: Set<String> = []
    var model: String?
    var category: String?
    var hostname: String?        // "Jons-iPad.local", from mDNS
    var facts: [Fact] = []

    mutating func add(_ label: String, _ value: String?) {
        guard let v = Net.clean(value) else { return }
        let f = Fact(source: "Bonjour", label: label, value: v)
        if !facts.contains(f) { facts.append(f) }
    }

    /// Learns from one advertised service: its type ("_airplay._tcp"), instance name and TXT record.
    /// Shared by the NetService browser and the direct mDNS queries in Identify.swift.
    mutating func ingest(type: String, instance: String, txt: [String: String]) {
        func t(_ key: String) -> String? { txt[key].flatMap { $0.isEmpty ? nil : $0 } }
        types.insert(type)
        if type.hasPrefix("_device-info") {
            if let m = t("model"), !Self.isSpoofModel(m) { model = model ?? m; add("Model", m) }
            return
        }
        var name = instance
        if type.hasPrefix("_raop"), let at = name.firstIndex(of: "@") { name = String(name[name.index(after: at)...]) }
        if type.hasPrefix("_googlecast"), let fn = t("fn") { name = fn }
        if type.hasPrefix("_sleep-proxy"), let sp = name.firstIndex(of: " ") { name = String(name[name.index(after: sp)...]) }
        let priority = BonjourBrowser.types.firstIndex { type.hasPrefix($0) } ?? BonjourBrowser.types.count
        if priority < namePriority, !Self.looksLikeID(name), !Self.isGeneric(name) { self.name = name; namePriority = priority }

        let isPrinter = ["_ipp", "_ipps", "_printer", "_pdl-datastream"].contains { type.hasPrefix($0) }
        let m = isPrinter ? (t("ty") ?? t("product").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "()")) })
            : type.hasPrefix("_raop") ? t("am")
            : type.hasPrefix("_companion-link") ? t("rpMd")
            : t("model") ?? t("md")
        if let m, !Self.isSpoofModel(m) {
            if model == nil { model = m }
            add("Model", m)
        }
        if isPrinter {
            category = "Printer"
            add("Printer location", t("note"))
            add("Admin page", t("adminurl"))
        }
        if type.hasPrefix("_hap"), let ci = t("ci").flatMap({ Int($0) }), let c = homeKitCategories[ci] {
            category = c
            add("HomeKit category", c)
        }
        if type.hasPrefix("_googlecast") {
            add("Cast name", t("fn"))
            add("Now playing", t("rs"))
        }
        if type.hasPrefix("_airplay") {
            add("OS version", t("osvers"))
            add("AirPlay version", t("srcvers"))
        }
    }

    /// Combines what two sources learned about the same address.
    mutating func merge(_ o: BonjourHost) {
        if o.namePriority < namePriority, let n = o.name { name = n; namePriority = o.namePriority }
        types.formUnion(o.types)
        model = model ?? o.model
        category = category ?? o.category
        hostname = hostname ?? o.hostname
        for f in o.facts where !facts.contains(f) { facts.append(f) }
    }

    /// Service names that are serial numbers or UUIDs rather than something a person chose.
    static func looksLikeID(_ s: String) -> Bool {
        let hex = s.filter { $0.isHexDigit }.count
        if s.count >= 12 && hex >= s.count - s.filter { $0 == "-" || $0 == ":" }.count { return true }
        // "f4:e8:c7:ca:41:9f@fe80::f6e8:…-supportsRP-24" (_apple-mobdev2) and other MAC-prefixed names
        if s.contains("@fe80") || s.range(of: "^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}", options: .regularExpression) != nil { return true }
        return false
    }

    /// Placeholder names many devices announce instead of a real one.
    static func isGeneric(_ s: String) -> Bool {
        let l = s.lowercased().replacingOccurrences(of: " ", with: "")
        return ["spotifyconnect", "android", "localhost", "espressif", "esp32", "esp8266", "unknown", "device", "linux"].contains(l)
    }

    /// Models some NAS boxes and Samba servers announce so Finder shows a server icon.
    static func isSpoofModel(_ s: String) -> Bool {
        ["xserve", "rackmac", "macsamba", "powermac", "timecapsule"].contains { s.lowercased().hasPrefix($0) }
    }
}

/// HomeKit accessory categories (the "ci" TXT key).
private let homeKitCategories: [Int: String] = [
    2: "HomeKit bridge", 3: "Fan", 4: "Garage door opener", 5: "Light", 6: "Door lock", 7: "Smart plug",
    8: "Switch", 9: "Thermostat", 10: "Sensor", 11: "Security system", 12: "Door", 13: "Window",
    14: "Window covering", 15: "Button", 16: "Range extender", 17: "Camera", 18: "Video doorbell",
    19: "Air purifier", 20: "Heater", 21: "Air conditioner", 22: "Humidifier", 23: "Dehumidifier",
    28: "Sprinkler", 29: "Faucet", 30: "Shower", 31: "TV", 32: "Remote", 33: "Wi-Fi router",
    34: "Audio receiver", 35: "TV box", 36: "Streaming stick",
]

/// Browses common service types for a few seconds and maps what it finds to IPv4 addresses.
/// Runs on the main run loop.
final class BonjourBrowser: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    /// Order matters: earlier types give better device names.
    static let types = [
        "_companion-link._tcp", "_airplay._tcp", "_googlecast._tcp", "_raop._tcp", "_sonos._tcp",
        "_spotify-connect._tcp", "_amzn-wplay._tcp", "_hap._tcp", "_homekit._tcp", "_matter._tcp",
        "_hue._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp",
        "_scanner._tcp", "_smb._tcp", "_afpovertcp._tcp", "_rfb._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
        "_apple-mobdev2._tcp", "_touch-able._tcp", "_airport._tcp", "_workstation._tcp", "_http._tcp",
        "_device-info._tcp",
    ]

    private var browsers: [NetServiceBrowser] = []
    private var services: [NetService] = []
    private(set) var hosts: [UInt32: BonjourHost] = [:]
    /// _device-info has no address of its own; its name matches the host's other services.
    private var modelsByName: [String: String] = [:]
    private var started = Date()

    func start() {
        started = Date()
        for type in Self.types {
            let b = NetServiceBrowser()
            b.delegate = self
            b.searchForServices(ofType: type, inDomain: "local.")
            browsers.append(b)
        }
    }

    /// Lets browsing run for at least `minimum` seconds in total, then stops and reports.
    func finish(minimum: TimeInterval, completion: @escaping ([UInt32: BonjourHost]) -> Void) {
        let wait = max(0, minimum - Date().timeIntervalSince(started))
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [self] in
            browsers.forEach { $0.stop() }
            services.forEach { $0.stop(); $0.stopMonitoring() }
            browsers = []
            services = []
            var out = hosts
            for (ip, h) in out where h.model == nil {
                if let n = h.name, let m = modelsByName[n] { out[ip]?.model = m; out[ip]?.add("Model", m) }
            }
            completion(out)
        }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        services.append(service)
        service.delegate = self
        if service.type.hasPrefix("_device-info") { service.startMonitoring() }
        service.resolve(withTimeout: 4)
    }

    func netServiceDidResolveAddress(_ sender: NetService) { record(sender) }

    func netService(_ sender: NetService, didUpdateTXTRecord data: Data) {
        if sender.type.hasPrefix("_device-info") { record(sender) }
    }

    private func record(_ s: NetService) {
        let type = s.type.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let raw = s.txtRecordData().map { NetService.dictionary(fromTXTRecord: $0) } ?? [:]
        var txt: [String: String] = [:]
        for (k, v) in raw { txt[k] = String(data: v, encoding: .utf8) }
        if type.hasPrefix("_device-info") {
            if let m = txt["model"], !m.isEmpty, !BonjourHost.isSpoofModel(m) { modelsByName[s.name] = m }
            return
        }
        for addr in s.addresses ?? [] {
            guard let ip = IPv4.from(addr) else { continue }
            var h = hosts[ip] ?? BonjourHost()
            h.ingest(type: type, instance: s.name, txt: txt)
            if h.hostname == nil, let host = s.hostName { h.hostname = host.hasSuffix(".") ? String(host.dropLast()) : host }
            hosts[ip] = h
        }
    }
}

// MARK: - Maker lookup (IEEE OUI registry, via Nmap's or Wireshark's copy)

final class VendorDB {
    static let shared = VendorDB()
    /// The IEEE registry as the Nmap project publishes it (kept current, ~52,000 entries), then
    /// Wireshark's copy as a fallback. Either format is understood.
    static let sources = [
        URL(string: "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes")!,
        URL(string: "https://www.wireshark.org/download/automated/data/manuf")!,
    ]

    private let lock = NSLock()
    private var tables: [Int: [UInt64: String]] = [:]   // prefix length in bits → prefix → maker
    private var loading = false

    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "LookUpMakers") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "LookUpMakers") }
    }

    var isLoaded: Bool { lock.lock(); defer { lock.unlock() }; return !tables.isEmpty }

    private var file: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("NetworkScanner", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("oui.txt")
    }

    /// Loads the cached list, downloading it if missing or older than 30 days.
    /// Completion runs on the main thread, only when something new was loaded.
    func prepare(completion: @escaping () -> Void) {
        guard enabled, !loading else { return }
        loading = true
        DispatchQueue.global(qos: .utility).async { [self] in
            defer { loading = false }
            let attrs = try? FileManager.default.attributesOfItem(atPath: file.path)
            let age = (attrs?[.modificationDate] as? Date).map { -$0.timeIntervalSinceNow } ?? .infinity
            if !isLoaded, let text = try? String(contentsOf: file, encoding: .utf8), let t = Self.parse(text) {
                lock.lock(); tables = t; lock.unlock()
                DispatchQueue.main.async(execute: completion)
            }
            guard age > 30 * 86400 else { return }
            for source in Self.sources {
                var req = URLRequest(url: source, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
                req.setValue("NetworkScanner/\(AppVersion.version)", forHTTPHeaderField: "User-Agent")
                guard let res = HTTP.fetch(req), res.1.statusCode == 200,
                      let text = String(data: res.0, encoding: .utf8), let t = Self.parse(text) else { continue }
                try? res.0.write(to: file, options: .atomic)
                lock.lock(); tables = t; lock.unlock()
                DispatchQueue.main.async(execute: completion)
                return
            }
        }
    }

    /// Understands both list formats:
    ///   Nmap:      "001132 Synology Incorporated"  (6, 7 or 9 hex digits = 24/28/36-bit prefix)
    ///   Wireshark: "00:11:32<TAB>Synology<TAB>Synology Incorporated", "00:1B:C5:00:00:00/36<TAB>…"
    /// Returns nil unless it looks like a real list (a download error page, say).
    static func parse(_ text: String) -> [Int: [UInt64: String]]? {
        var t: [Int: [UInt64: String]] = [:]
        var count = 0
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            var hex = "", bits = 0, name = ""
            if line.contains("\t") {
                let f = line.split(separator: "\t", omittingEmptySubsequences: false)
                guard f.count >= 2 else { continue }
                let spec = f[0].split(separator: "/")
                hex = spec[0].replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "")
                bits = spec.count > 1 ? Int(spec[1]) ?? 24 : hex.count * 4
                let long = f.count > 2 ? f[2].trimmingCharacters(in: .whitespaces) : ""
                name = long.isEmpty ? f[1].trimmingCharacters(in: .whitespaces) : long
            } else {
                guard let sp = line.firstIndex(of: " ") else { continue }
                hex = String(line[..<sp])
                bits = hex.count * 4
                name = line[line.index(after: sp)...].trimmingCharacters(in: .whitespaces)
            }
            guard bits % 4 == 0, bits >= 24, bits <= hex.count * 4, !name.isEmpty,
                  let value = UInt64(hex.prefix(bits / 4), radix: 16) else { continue }
            t[bits, default: [:]][value] = name
            count += 1
        }
        return count > 1000 ? t : nil
    }

    func lookup(_ mac: String) -> String? {
        guard enabled, !MAC.isRandomized(mac) else { return nil }
        let hex = mac.replacingOccurrences(of: ":", with: "")
        lock.lock(); defer { lock.unlock() }
        for bits in tables.keys.sorted(by: >) {
            if let v = UInt64(hex.prefix(bits / 4), radix: 16), let name = tables[bits]?[v] { return name }
        }
        return nil
    }
}

// MARK: - Scan

struct Device: Identifiable, Hashable {
    /// Unique per row: the IP for devices seen this scan, the remembered key for offline ones.
    var id: String { isOffline ? "offline:\(knownKey)" : ip }
    let ip: String
    let ipKey: UInt32
    var mac: String?
    var hostname: String?
    var bonjourName: String?
    var model: String?
    var services: [String] = []
    var openPorts: [UInt16] = []
    var vendor: String?
    var responded = false      // answered a probe this scan (vs. only present in the ARP cache)
    var isSelf = false
    var isGateway = false
    var isNew = false
    var label: String?
    var firstSeen = Date()
    var category: String?        // HomeKit category or "Printer", from Bonjour
    var bonjourFacts: [Fact] = []
    var identity = Identity()    // filled in by the identify pass (Identify.swift)
    var deepScanned = false
    var ipv6: [String] = []
    var lastSeen = Date()
    /// Remembered from an earlier scan but not found in this one.
    var isOffline = false
    /// What was known about this device (by MAC) last time it was seen. Used for offline rows,
    /// and as a fallback for online devices that don't announce themselves on this scan.
    var savedName: String?
    var savedKind: String?
    var savedMaker: String?
    var savedModel: String?

    var randomizedMAC: Bool { mac.map(MAC.isRandomized) ?? false }

    /// The name the device announces (or that was given to it), without fallbacks.
    var realName: String? {
        label ?? bonjourName ?? identity.upnp?.friendlyName ?? identity.netbios?.name ?? hostLabel ?? savedName
    }
    /// Hostname without ".local" and with dashes as spaces, e.g. "Jonathans-MacBook-Pro.local" → "Jonathans MacBook Pro".
    private var hostLabel: String? {
        guard let h = bestHostname else { return nil }
        var s = h
        if s.lowercased().hasSuffix(".local") { s = String(s.dropLast(6)) }
        guard !BonjourHost.isGeneric(s), !BonjourHost.looksLikeID(s) else { return nil }
        guard !s.contains(".") else { return h }
        return s.replacingOccurrences(of: "-", with: " ")
    }
    var bestHostname: String? { hostname ?? identity.mdnsName }

    /// realName, or "<Maker> device" / "Unidentified device" when it doesn't announce one.
    var displayName: String {
        if let n = realName, !n.isEmpty { return n }
        if let m = maker { return "\(Maker.short(m)) device" }
        return randomizedMAC ? "Private device" : "Unidentified device"
    }
    var hasRealName: Bool { !(realName ?? "").isEmpty }

    /// What the device says about itself (UPnP) first, then the MAC's registered maker, then
    /// "Apple" for Apple devices using private Wi-Fi addresses, then what was known before.
    var maker: String? { identity.upnp?.manufacturer ?? vendor ?? (looksApple ? "Apple" : nil) ?? savedMaker }

    /// Apple-only signals: an Apple model identifier, Apple-only services, the iOS sync port,
    /// or an Apple-style hostname.
    var looksApple: Bool {
        if let m = model?.lowercased(),
           ["iphone", "ipad", "mac", "imac", "appletv", "audioaccessory", "watch"].contains(where: { m.hasPrefix($0) }) { return true }
        let s = Set(services.map { $0.components(separatedBy: ".").first ?? $0 })
        if s.contains("_companion-link") || s.contains("_apple-mobdev2") || openPorts.contains(62078) { return true }
        let h = (bestHostname ?? "").lowercased()
        return ["iphone", "ipad", "macbook", "imac", "mac-mini", "mac-studio"].contains { h.contains($0) }
    }
    /// Marketing name when the identifier is a known Apple model ("iPad8,9" → "iPad Pro 11-inch (2nd gen)").
    var modelName: String? {
        if let m = model { return AppleModels.name(m) ?? m }
        return identity.upnp?.model ?? savedModel
    }
    var icon: String { DeviceIcon.symbol(for: kind) }

    /// Everything learned about the device, grouped by where it came from.
    var facts: [Fact] {
        var f: [Fact] = []
        func add(_ source: String, _ label: String, _ value: String?) {
            if let v = Net.clean(value) { f.append(Fact(source: source, label: label, value: v)) }
        }
        if let u = identity.upnp {
            add("UPnP", "Name", u.friendlyName)
            add("UPnP", "Manufacturer", u.manufacturer)
            add("UPnP", "Model", u.model)
            add("UPnP", "Description", u.modelDescription)
            add("UPnP", "Device type", u.shortType)
            add("UPnP", "Firmware", u.firmware)
            add("UPnP", "Admin page", u.presentationURL)
        }
        add("UPnP", "Server", identity.upnpServer)
        f += bonjourFacts
        if let w = identity.web {
            add("Web", "Page title", w.title)
            add("Web", "Server", w.server)
            add("Web", "Address", w.url)
        }
        add("Bonjour", "Hostname (mDNS)", identity.mdnsName)
        if let n = identity.netbios {
            add("Windows networking", "Computer name", n.name)
            add("Windows networking", "Workgroup", n.workgroup)
        }
        add("SSH", "Banner", identity.ssh)
        return f
    }
    var knownKey: String { mac ?? "ip:\(ip)" }
    var webURL: URL? {
        if let p = identity.upnp?.presentationURL, let u = URL(string: p), u.host == ip { return u }
        if openPorts.contains(443) { return URL(string: "https://\(ip)") }
        if openPorts.contains(80) { return URL(string: "http://\(ip)") }
        if openPorts.contains(8443) { return URL(string: "https://\(ip):8443") }
        if openPorts.contains(8080) { return URL(string: "http://\(ip):8080") }
        return nil
    }

    // Sort keys for the table
    var statusRank: Int { isOffline ? 4 : isSelf ? 0 : isGateway ? 1 : responded ? 2 : 3 }
    var sortName: String { (hasRealName ? "0" : "1") + displayName.lowercased() }
    var sortVendor: String { (maker ?? "\u{FFFF}").lowercased() }
    var sortModel: String { (modelName ?? "\u{FFFF}").lowercased() }
    var sortMAC: String { mac ?? "\u{FFFF}" }
    var sortIPv6: String { ipv6.first ?? "\u{FFFF}" }
    var sortHost: String { (bestHostname ?? "\u{FFFF}").lowercased() }
    var portCount: Int { openPorts.count }

    var portSummary: String {
        openPorts.map { p in Probe.name(p).map { "\($0) (\(p))" } ?? "\(p)" }.joined(separator: ", ")
    }

    var serviceSummary: String {
        services.map { s -> String in
            let bare = s.replacingOccurrences(of: "._tcp", with: "").replacingOccurrences(of: "._udp", with: "")
            return bare.hasPrefix("_") ? String(bare.dropFirst()) : bare
        }.sorted().joined(separator: ", ")
    }

    /// Best guess at what the device is: Bonjour model and category, UPnP, then services,
    /// ports, maker and what its web page and SSH banner say.
    var kind: String {
        if isOffline, let k = savedKind { return k }
        let k = detectedKind
        if let saved = savedKind, ["Unknown", "Phone / laptop", "Web-managed device"].contains(k) { return saved }
        return k
    }

    private var detectedKind: String {
        if isSelf { return "This Mac" }
        if isGateway { return "Router" }
        if let c = category { return c }
        if let m = model?.lowercased() {
            if m.hasPrefix("macbook") { return "Mac laptop" }
            if m.hasPrefix("imac") || m.hasPrefix("macmini") || m.hasPrefix("macpro") || m.hasPrefix("mac") { return "Mac" }
            if m.hasPrefix("appletv") { return "Apple TV" }
            if m.hasPrefix("audioaccessory") { return "HomePod" }
            if m.hasPrefix("iphone") { return "iPhone" }
            if m.hasPrefix("ipad") { return "iPad" }
            if m.hasPrefix("watch") { return "Apple Watch" }
            if m.contains("chromecast") || m.contains("google") { return "Chromecast / Google device" }
        }
        let s = Set(services.map { $0.components(separatedBy: ".").first ?? $0 })
        let v = (maker ?? "").lowercased()
        let p = Set(openPorts)
        let u = identity.upnp
        let um = ((u?.model ?? "") + " " + (u?.friendlyName ?? "")).lowercased()
        let hints = [identity.web?.title, identity.web?.server, identity.upnpServer, identity.ssh]
            .compactMap { $0?.lowercased() }.joined(separator: " ")
        switch u?.shortType ?? "" {
        case "InternetGatewayDevice", "WANDevice", "WANConnectionDevice": return "Router"
        case "ZonePlayer": return "Sonos speaker"
        case "Printer": return "Printer"
        case "MediaServer": return "Media server / NAS"
        default: break
        }
        if um.contains("xbox") || um.contains("playstation") || v.contains("nintendo") { return "Game console" }
        if um.contains("roku") || v.contains("roku") { return "Roku" }
        if um.contains("hue bridge") || (v.contains("philips") && um.contains("hue")) { return "Hue bridge" }
        if u?.shortType == "MediaRenderer" || u?.deviceType?.contains("dial") == true,
           s.isDisjoint(with: ["_googlecast", "_airplay", "_raop", "_sonos"]) {
            return ["samsung", "lg ", "lg electronics", "sony", "vizio", "tcl", "hisense", "panasonic", "philips"]
                .contains { v.contains($0) || um.contains($0) } ? "TV" : "Media player"
        }
        if hints.contains("synology") || hints.contains("diskstation") || hints.contains("qnap") || hints.contains("truenas") { return "NAS" }
        if hints.contains("openwrt") || hints.contains("routeros") || hints.contains("unifi") || hints.contains("dd-wrt") { return "Network device" }
        let host = (bestHostname ?? "").lowercased()
        if host.contains("iphone") { return "iPhone" }
        if host.contains("ipad") { return "iPad" }
        if host.contains("macbook") { return "Mac laptop" }
        if host.contains("imac") || host.contains("mac-mini") || host.contains("mac-studio") { return "Mac" }
        if ["synology", "qnap", "western digital", "buffalo", "asustor", "terramaster"].contains(where: { v.contains($0) }) { return "NAS" }
        if s.contains("_googlecast") && (s.contains("_raop") || s.contains("_spotify-connect")) { return "Speaker / soundbar" }
        if s.contains("_googlecast") { return "Chromecast / Google TV" }
        if ["harman", "jbl", "bose", "bang & olufsen", "denon", "marantz", "yamaha"].contains(where: { v.contains($0) }) { return "Speaker" }
        if s.contains("_sonos") || p.contains(1400) || v.contains("sonos") { return "Sonos speaker" }
        if !s.isDisjoint(with: ["_ipp", "_ipps", "_printer", "_pdl-datastream"]) || p.contains(9100) || p.contains(631) { return "Printer" }
        if !s.isDisjoint(with: ["_uscan", "_scanner"]) { return "Scanner" }
        if s.contains("_airplay") { return "AirPlay TV / speaker" }
        if s.contains("_raop") { return "AirPlay speaker" }
        if s.contains("_amzn-wplay") || v.contains("amazon") { return "Amazon device" }
        if s.contains("_hap") || s.contains("_homekit") || s.contains("_matter") || s.contains("_hue") { return "Smart home device" }
        if p.contains(62078) || s.contains("_apple-mobdev2") { return "iPhone / iPad" }
        if s.contains("_companion-link") { return "Apple device" }
        if host.contains("android") || host.contains("galaxy") || host.contains("pixel") { return "Android device" }
        if s.contains("_spotify-connect") { return "Speaker" }
        if v.contains("raspberry") { return "Raspberry Pi" }
        if v.contains("nintendo") || v.contains("sony interactive") || v.contains("microsoft") && p.isEmpty { return "Game console" }
        if v.contains("roku") { return "Roku" }
        if v.contains("espressif") || v.contains("tuya") || v.contains("shelly") || v.contains("ring") || v.contains("nest") { return "Smart home device" }
        if !s.isDisjoint(with: ["_smb", "_afpovertcp", "_workstation"]) || p.contains(445) || p.contains(548) { return "Computer / NAS" }
        if identity.netbios != nil { return "Windows PC / file server" }
        if hints.contains("raspbian") { return "Raspberry Pi" }
        if hints.contains("ubuntu") || hints.contains("debian") || hints.contains("fedora") || hints.contains("linux") { return "Linux computer" }
        if s.contains("_rfb") || s.contains("_ssh") || s.contains("_sftp-ssh") || p.contains(22) || p.contains(3389) { return "Computer" }
        if v.contains("apple") { return "Apple device" }
        if v.contains("samsung") || v.contains("lg electronics") || v.contains("vizio") || v.contains("tcl") || v.contains("hisense") { return "TV / appliance" }
        if ["tp-link", "eero", "netgear", "ubiquiti", "linksys", "asustek", "plume", "google fiber"].contains(where: { v.contains($0) }),
           p.contains(80) || p.contains(443) { return "Wi-Fi access point" }
        if p.contains(80) || p.contains(443) || p.contains(8080) { return "Web-managed device" }
        if randomizedMAC { return "Phone / laptop" }
        return "Unknown"
    }
}

struct ScanOutcome {
    let network: NetworkInfo
    let scannedCIDR: String
    let trimmed: Bool
    let devices: [Device]
    /// Nothing answered at all, which on macOS 15+ usually means Local Network access is off.
    let nothingAnswered: Bool
}

enum ScanError: LocalizedError {
    case noNetwork
    var errorDescription: String? { "This Mac isn't connected to a local IPv4 network." }
}

enum Scanner {
    /// Call on the main thread; progress and completion arrive there too.
    static func scan(progress: @escaping (Double, String) -> Void,
                     completion: @escaping (Result<ScanOutcome, Error>) -> Void) {
        let bonjour = BonjourBrowser()
        bonjour.start()
        DispatchQueue.global(qos: .userInitiated).async {
            guard let net = NetworkInfo.current() else {
                DispatchQueue.main.async {
                    bonjour.finish(minimum: 0) { _ in completion(.failure(ScanError.noNetwork)) }
                }
                return
            }
            Probe.raiseFileLimit()
            // UPnP discovery listens while the sweep runs.
            var ssdp: [UInt32: SSDP.Answer] = [:]
            let ssdpDone = DispatchGroup()
            ssdpDone.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                ssdp = SSDP.discover(from: net.address, duration: 4)
                ssdpDone.leave()
            }
            let range = net.scanRange
            let targets = range.hosts.filter { $0 != net.address }
            let lock = NSLock()
            var alive: [UInt32: [UInt16]] = [:]
            var done = 0

            let queue = OperationQueue()
            queue.maxConcurrentOperationCount = 48
            for host in targets {
                queue.addOperation {
                    let r = Probe.probe(host)
                    lock.lock()
                    if r.alive { alive[host] = r.open }
                    done += 1
                    let d = done
                    lock.unlock()
                    if d % 8 == 0 || d == targets.count {
                        DispatchQueue.main.async {
                            progress(0.7 * Double(d) / Double(max(1, targets.count)), "Probing \(d) of \(targets.count) addresses\u{2026}")
                        }
                    }
                }
            }
            queue.waitUntilAllOperationsAreFinished()

            // Give stragglers' ARP replies a moment to land, then read the cache.
            Thread.sleep(forTimeInterval: 0.5)
            var arp = ARP.table(interface: net.interface)
            var ips = Set(alive.keys)
            for ip in arp.keys where net.contains(ip) && ip != net.network && ip != (net.network | ~net.netmask) { ips.insert(ip) }
            ips.insert(net.address)
            if let gw = net.gateway { ips.insert(gw) }

            DispatchQueue.main.async { progress(0.75, "Looking up names\u{2026}") }
            var names: [UInt32: String] = [:]
            let dns = OperationQueue()
            dns.maxConcurrentOperationCount = 16
            dns.addOperation { NDP.wake(interface: net.interface) }
            var mdns: [UInt32: BonjourHost] = [:]
            let mdnsTargets = Array(ips)
            dns.addOperation {
                let found = MDNS.discover(mdnsTargets, from: net.address)
                lock.lock(); mdns = found; lock.unlock()
            }
            for ip in ips {
                dns.addOperation {
                    if let n = DNS.reverse(ip) { lock.lock(); names[ip] = n; lock.unlock() }
                }
            }
            dns.waitUntilAllOperationsAreFinished()
            // Devices that only answered the multicast mDNS query (ARP-silent until now).
            let extra = mdns.keys.filter { net.contains($0) && !ips.contains($0) && $0 != net.network }
            if !extra.isEmpty {
                ips.formUnion(extra)
                arp = ARP.table(interface: net.interface)
            }
            let ndp = NDP.table(interface: net.interface)
            ssdpDone.wait()

            DispatchQueue.main.async {
                bonjour.finish(minimum: 6) { bj in
                    var devices: [Device] = []
                    for ip in ips {
                        var d = Device(ip: IPv4.string(ip), ipKey: ip)
                        d.isSelf = net.localAddresses[ip] != nil
                        d.isGateway = ip == net.gateway
                        if let m = net.localAddresses[ip] { d.mac = m.isEmpty ? nil : m } else { d.mac = arp[ip] }
                        d.hostname = names[ip]
                        d.openPorts = alive[ip] ?? []
                        d.responded = d.isSelf || alive[ip] != nil
                        var merged = bj[ip]
                        if let m = mdns[ip] {
                            if merged == nil { merged = m } else { merged?.merge(m) }
                        }
                        if let b = merged {
                            d.identity.mdnsName = b.hostname
                            d.bonjourName = b.name
                            d.model = b.model
                            d.services = Array(b.types)
                            d.category = b.category
                            d.bonjourFacts = b.facts
                        }
                        d.vendor = d.mac.flatMap { VendorDB.shared.lookup($0) }
                        d.ipv6 = d.mac.flatMap { ndp[$0] } ?? []
                        devices.append(d)
                    }
                    progress(0.85, "Identifying \(devices.count) devices\u{2026}")
                    DispatchQueue.global(qos: .userInitiated).async {
                        let identified = Identify.run(devices, ssdp: ssdp)
                        DispatchQueue.main.async {
                            completion(.success(ScanOutcome(network: net, scannedCIDR: range.cidr, trimmed: range.trimmed,
                                                            devices: identified.sorted { $0.ipKey < $1.ipKey },
                                                            nothingAnswered: alive.isEmpty)))
                        }
                    }
                }
            }
        }
    }
}
