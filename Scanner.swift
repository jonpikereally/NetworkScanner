import Foundation
import Darwin
import SystemConfiguration

// Finding devices on the local network without root:
//   1. TCP connect probes to common ports on every address in the subnet. Any answer, even a
//      refusal, proves a host is there, and the attempts make macOS ARP for every address.
//   2. The ARP cache then lists everything that answered ARP, including phones and IoT devices
//      that ignore TCP entirely, with their MAC addresses.
//   3. Bonjour (mDNS) browsing and reverse DNS supply names, models and services.
//   4. The MAC's first bytes give the maker, from Wireshark's public OUI list (optional).

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
        return NetworkInfo(interface: name, interfaceName: displayName(bsd: name) ?? name,
                           address: addr, netmask: mask, mac: macs[name], gateway: gw)
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

    /// One non-blocking connect per port, all polled together. A host is alive if any port
    /// accepts or actively refuses; silence and "host unreachable" mean nobody's there.
    static func probe(_ host: UInt32, timeoutMs: Int = 700) -> (alive: Bool, open: [UInt16]) {
        var alive = false
        var open: [UInt16] = []
        var pending: [Int32: UInt16] = [:]
        for port in ports.keys {
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
}

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
                if let n = h.name, let m = modelsByName[n] { out[ip]?.model = m }
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
        let txt = s.txtRecordData().map { NetService.dictionary(fromTXTRecord: $0) } ?? [:]
        func t(_ key: String) -> String? {
            txt[key].flatMap { String(data: $0, encoding: .utf8) }.flatMap { $0.isEmpty ? nil : $0 }
        }
        if type.hasPrefix("_device-info") {
            if let m = t("model") { modelsByName[s.name] = m }
            return
        }
        var name = s.name
        if type.hasPrefix("_raop"), let at = name.firstIndex(of: "@") { name = String(name[name.index(after: at)...]) }
        if type.hasPrefix("_googlecast"), let fn = t("fn") { name = fn }
        let priority = Self.types.firstIndex { type.hasPrefix($0) } ?? Self.types.count
        let model = t("model") ?? t("md")

        for addr in s.addresses ?? [] {
            guard let ip = IPv4.from(addr) else { continue }
            var h = hosts[ip] ?? BonjourHost()
            h.types.insert(type)
            if priority < h.namePriority { h.name = name; h.namePriority = priority }
            if h.model == nil { h.model = model }
            hosts[ip] = h
        }
    }
}

// MARK: - Maker lookup (IEEE OUI via Wireshark's manuf list)

final class VendorDB {
    static let shared = VendorDB()
    static let source = URL(string: "https://www.wireshark.org/download/automated/data/manuf")!

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
        return dir.appendingPathComponent("manuf.txt")
    }

    /// Loads the cached list, downloading it if missing or older than 30 days.
    /// Completion runs on the main thread, only when something new was loaded.
    func prepare(completion: @escaping () -> Void) {
        guard enabled, !loading else { return }
        loading = true
        DispatchQueue.global(qos: .utility).async { [self] in
            let attrs = try? FileManager.default.attributesOfItem(atPath: file.path)
            let age = (attrs?[.modificationDate] as? Date).map { -$0.timeIntervalSinceNow } ?? .infinity
            if !isLoaded, let text = try? String(contentsOf: file, encoding: .utf8) {
                load(text)
                DispatchQueue.main.async(execute: completion)
            }
            guard age > 30 * 86400 else { loading = false; return }
            var req = URLRequest(url: Self.source, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
            req.setValue("NetworkScanner/\(AppVersion.version)", forHTTPHeaderField: "User-Agent")
            URLSession.shared.dataTask(with: req) { data, response, _ in
                defer { self.loading = false }
                guard let data, (response as? HTTPURLResponse)?.statusCode == 200,
                      let text = String(data: data, encoding: .utf8), text.contains("\t") else { return }
                try? data.write(to: self.file, options: .atomic)
                self.load(text)
                DispatchQueue.main.async(execute: completion)
            }.resume()
        }
    }

    /// Lines look like "00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc" or, for smaller blocks,
    /// "00:1B:C5:00:00:00/36<TAB>Short<TAB>Long name".
    private func load(_ text: String) {
        var t: [Int: [UInt64: String]] = [:]
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard f.count >= 2 else { continue }
            let spec = f[0].split(separator: "/")
            let hex = spec[0].replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "")
            let bits = spec.count > 1 ? Int(spec[1]) ?? 24 : hex.count * 4
            guard bits % 4 == 0, bits <= hex.count * 4, let value = UInt64(hex.prefix(bits / 4), radix: 16) else { continue }
            let long = f.count > 2 ? f[2].trimmingCharacters(in: .whitespaces) : ""
            let name = long.isEmpty ? f[1].trimmingCharacters(in: .whitespaces) : long
            t[bits, default: [:]][value] = name
        }
        lock.lock(); tables = t; lock.unlock()
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
    var id: String { ip }
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

    var randomizedMAC: Bool { mac.map(MAC.isRandomized) ?? false }
    var displayName: String { label ?? bonjourName ?? hostname ?? "" }
    var knownKey: String { mac ?? "ip:\(ip)" }
    var webURL: URL? {
        if openPorts.contains(443) { return URL(string: "https://\(ip)") }
        if openPorts.contains(80) { return URL(string: "http://\(ip)") }
        if openPorts.contains(8443) { return URL(string: "https://\(ip):8443") }
        if openPorts.contains(8080) { return URL(string: "http://\(ip):8080") }
        return nil
    }

    // Sort keys for the table
    var statusRank: Int { isSelf ? 0 : isGateway ? 1 : responded ? 2 : 3 }
    var sortName: String { displayName.isEmpty ? "\u{FFFF}" : displayName.lowercased() }
    var sortVendor: String { (vendor ?? "\u{FFFF}").lowercased() }
    var sortMAC: String { mac ?? "\u{FFFF}" }
    var portCount: Int { openPorts.count }

    var portSummary: String {
        openPorts.map { p in Probe.ports[p].map { "\($0) (\(p))" } ?? "\(p)" }.joined(separator: ", ")
    }

    var serviceSummary: String {
        services.map { s -> String in
            let bare = s.replacingOccurrences(of: "._tcp", with: "").replacingOccurrences(of: "._udp", with: "")
            return bare.hasPrefix("_") ? String(bare.dropFirst()) : bare
        }.sorted().joined(separator: ", ")
    }

    /// Best guess at what the device is, from Bonjour model, services, ports and maker.
    var kind: String {
        if isSelf { return "This Mac" }
        if isGateway { return "Router" }
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
        let v = (vendor ?? "").lowercased()
        let p = Set(openPorts)
        if s.contains("_googlecast") { return "Chromecast / Google TV" }
        if s.contains("_sonos") || p.contains(1400) || v.contains("sonos") { return "Sonos speaker" }
        if !s.isDisjoint(with: ["_ipp", "_ipps", "_printer", "_pdl-datastream"]) || p.contains(9100) || p.contains(631) { return "Printer" }
        if !s.isDisjoint(with: ["_uscan", "_scanner"]) { return "Scanner" }
        if s.contains("_airplay") { return "AirPlay TV / speaker" }
        if s.contains("_raop") { return "AirPlay speaker" }
        if s.contains("_amzn-wplay") || v.contains("amazon") { return "Amazon device" }
        if s.contains("_hap") || s.contains("_homekit") || s.contains("_matter") || s.contains("_hue") { return "Smart home device" }
        if p.contains(62078) || s.contains("_apple-mobdev2") { return "iPhone / iPad" }
        if s.contains("_companion-link") { return "Apple device" }
        if s.contains("_spotify-connect") { return "Speaker" }
        if v.contains("raspberry") { return "Raspberry Pi" }
        if v.contains("nintendo") || v.contains("sony interactive") || v.contains("microsoft") && p.isEmpty { return "Game console" }
        if v.contains("roku") { return "Roku" }
        if v.contains("espressif") || v.contains("tuya") || v.contains("shelly") || v.contains("ring") || v.contains("nest") { return "Smart home device" }
        if !s.isDisjoint(with: ["_smb", "_afpovertcp", "_workstation"]) || p.contains(445) || p.contains(548) { return "Computer / NAS" }
        if s.contains("_rfb") || s.contains("_ssh") || s.contains("_sftp-ssh") || p.contains(22) || p.contains(3389) { return "Computer" }
        if v.contains("apple") { return "Apple device" }
        if v.contains("samsung") || v.contains("lg electronics") || v.contains("vizio") || v.contains("tcl") || v.contains("hisense") { return "TV / appliance" }
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
                            progress(0.85 * Double(d) / Double(max(1, targets.count)), "Probing \(d) of \(targets.count) addresses\u{2026}")
                        }
                    }
                }
            }
            queue.waitUntilAllOperationsAreFinished()

            // Give stragglers' ARP replies a moment to land, then read the cache.
            Thread.sleep(forTimeInterval: 0.5)
            let arp = ARP.table(interface: net.interface)
            var ips = Set(alive.keys)
            for ip in arp.keys where net.contains(ip) && ip != net.network && ip != (net.network | ~net.netmask) { ips.insert(ip) }
            ips.insert(net.address)
            if let gw = net.gateway { ips.insert(gw) }

            DispatchQueue.main.async { progress(0.9, "Looking up names\u{2026}") }
            var names: [UInt32: String] = [:]
            let dns = OperationQueue()
            dns.maxConcurrentOperationCount = 16
            for ip in ips {
                dns.addOperation {
                    if let n = DNS.reverse(ip) { lock.lock(); names[ip] = n; lock.unlock() }
                }
            }
            dns.waitUntilAllOperationsAreFinished()

            DispatchQueue.main.async {
                bonjour.finish(minimum: 6) { bj in
                    var devices: [Device] = []
                    for ip in ips {
                        var d = Device(ip: IPv4.string(ip), ipKey: ip)
                        d.isSelf = ip == net.address
                        d.isGateway = ip == net.gateway
                        d.mac = d.isSelf ? net.mac : arp[ip]
                        d.hostname = names[ip]
                        d.openPorts = alive[ip] ?? []
                        d.responded = d.isSelf || alive[ip] != nil
                        if let b = bj[ip] {
                            d.bonjourName = b.name
                            d.model = b.model
                            d.services = Array(b.types)
                        }
                        d.vendor = d.mac.flatMap { VendorDB.shared.lookup($0) }
                        devices.append(d)
                    }
                    completion(.success(ScanOutcome(network: net, scannedCIDR: range.cidr, trimmed: range.trimmed,
                                                    devices: devices.sorted { $0.ipKey < $1.ipKey },
                                                    nothingAnswered: alive.isEmpty)))
                }
            }
        }
    }
}
