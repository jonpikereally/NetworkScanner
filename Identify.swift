import Foundation
import Darwin

// The identify pass runs after each scan and asks every device what it is:
//   • UPnP/SSDP: one multicast M-SEARCH, then each answering device's description XML
//     (friendly name, manufacturer, model, firmware). TVs, routers, Sonos, consoles, NAS.
//   • Web: the <title> and Server header of devices with a web page.
//   • NetBIOS: a node status query on UDP 137 gives Windows / Samba computer names.
//   • SSH: the banner on port 22 names the server software and often the OS.
//   • mDNS: a unicast PTR query to each device's port 5353 returns its "name.local" hostname.
// Bonjour TXT details are gathered by BonjourBrowser in Scanner.swift.
// Deep Scan (one device, ~1,100 ports) lives here too.

// MARK: - What was learned

struct Fact: Hashable, Identifiable {
    let source: String   // "UPnP", "Bonjour", "Web", "Windows networking", "SSH"
    let label: String
    let value: String
    var id: String { "\(source)|\(label)|\(value)" }
}

struct UPnPInfo: Hashable {
    var friendlyName: String?
    var manufacturer: String?
    var modelName: String?
    var modelNumber: String?
    var modelDescription: String?
    var deviceType: String?
    var firmware: String?
    var presentationURL: String?

    /// "urn:schemas-upnp-org:device:MediaRenderer:1" → "MediaRenderer"
    var shortType: String? {
        guard let t = deviceType else { return nil }
        let parts = t.split(separator: ":")
        return parts.count >= 2 ? String(parts[parts.count - 2]) : t
    }

    var model: String? {
        let parts = [modelName, modelNumber].compactMap { $0 }.filter { !$0.isEmpty }
        guard !parts.isEmpty else { return nil }
        // Skip the number when the name already contains it ("RT-AX86U" + "RT-AX86U").
        if parts.count == 2, parts[0].localizedCaseInsensitiveContains(parts[1]) { return parts[0] }
        return parts.joined(separator: " ")
    }
}

struct WebInfo: Hashable {
    var url: String
    var title: String?
    var server: String?
}

struct NetBIOSInfo: Hashable {
    var name: String
    var workgroup: String?
}

struct Identity: Hashable {
    var upnp: UPnPInfo?
    var upnpServer: String?
    var web: WebInfo?
    var netbios: NetBIOSInfo?
    var ssh: String?
    var mdnsName: String?
}

// MARK: - Small socket helpers

enum Net {
    /// Non-blocking TCP connect; returns the connected (still non-blocking) socket, or nil.
    static func connect(_ ip: UInt32, port: UInt16, timeout: TimeInterval) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        var sa = IPv4.socketAddress(ip, port: port)
        let r = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if r == 0 { return fd }
        guard errno == EINPROGRESS else { close(fd); return nil }
        var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&p, 1, Int32(timeout * 1000)) > 0 else { close(fd); return nil }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
        guard err == 0 else { close(fd); return nil }
        return fd
    }

    /// Reads whatever arrives within the timeout, up to `max` bytes.
    static func read(_ fd: Int32, timeout: TimeInterval, max: Int = 512) -> Data {
        var out = Data()
        let deadline = Date().addingTimeInterval(timeout)
        var buf = [UInt8](repeating: 0, count: max)
        while out.count < max {
            let remaining = Int32(deadline.timeIntervalSinceNow * 1000)
            guard remaining > 0 else { break }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, remaining) > 0 else { break }
            let n = recv(fd, &buf, max - out.count, 0)
            guard n > 0 else { break }
            out.append(contentsOf: buf[0..<n])
            if out.contains(0x0A) { break }   // a full line is enough for banners
        }
        return out
    }

    static func clean(_ s: String?) -> String? {
        guard let s else { return nil }
        let t = s.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }
}

// MARK: - HTTP (UPnP descriptions and web pages)

/// Local devices mostly use self-signed certificates; accept them, but only for this session,
/// which only ever talks to addresses on the local network.
private final class LocalTrust: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

enum HTTP {
    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 4
        c.timeoutIntervalForResource = 6
        c.httpCookieStorage = nil
        c.urlCache = nil
        return URLSession(configuration: c, delegate: LocalTrust(), delegateQueue: nil)
    }()

    /// Blocking GET. Returns the body (first 256 KB) and response, or nil.
    static func get(_ url: URL) -> (Data, HTTPURLResponse)? {
        var req = URLRequest(url: url)
        req.setValue("NetworkScanner/\(AppVersion.version)", forHTTPHeaderField: "User-Agent")
        let sem = DispatchSemaphore(value: 0)
        var out: (Data, HTTPURLResponse)?
        session.dataTask(with: req) { data, response, _ in
            if let data, let http = response as? HTTPURLResponse { out = (data.prefix(262_144), http) }
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 8)
        return out
    }
}

// MARK: - UPnP / SSDP

enum SSDP {
    struct Answer {
        var location: URL?
        var server: String?
    }

    /// Multicasts M-SEARCH twice and collects answers for `duration` seconds.
    static func discover(from local: UInt32, duration: TimeInterval = 3) -> [UInt32: Answer] {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [:] }
        defer { close(fd) }
        var ttl: UInt8 = 2
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, socklen_t(1))
        var iface = in_addr(s_addr: local.bigEndian)
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &iface, socklen_t(MemoryLayout<in_addr>.size))

        let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        let bytes = Array(search.utf8)
        var dest = IPv4.socketAddress(0xEFFF_FFFA, port: 1900)   // 239.255.255.250
        func send() {
            _ = withUnsafePointer(to: &dest) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        send()
        var resent = false

        var answers: [UInt32: Answer] = [:]
        let start = Date()
        var buf = [UInt8](repeating: 0, count: 2048)
        let cap = buf.count
        while true {
            let elapsed = Date().timeIntervalSince(start)
            if elapsed >= duration { break }
            if !resent && elapsed > 1 { send(); resent = true }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 250) > 0 else { continue }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, cap, 0, $0, &len) }
            }
            guard n > 0 else { continue }
            let ip = UInt32(bigEndian: from.sin_addr.s_addr)
            var a = answers[ip] ?? Answer()
            for line in String(decoding: buf[0..<n], as: UTF8.self).components(separatedBy: "\r\n") {
                guard let colon = line.firstIndex(of: ":") else { continue }
                let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if key == "location", a.location == nil { a.location = URL(string: value) }
                if key == "server", a.server == nil { a.server = Net.clean(value) }
            }
            answers[ip] = a
        }
        return answers
    }

    /// Reads the root device's fields from a UPnP description document.
    static func describe(_ url: URL) -> UPnPInfo? {
        guard let host = url.host, IPv4.parse(host) != nil, let res = HTTP.get(url),
              (200..<300).contains(res.1.statusCode) else { return nil }
        let parser = XMLParser(data: res.0)
        let reader = DescriptionReader()
        parser.delegate = reader
        parser.parse()
        var info = reader.info
        if let p = info.presentationURL, URL(string: p)?.scheme == nil {
            info.presentationURL = URL(string: p, relativeTo: url)?.absoluteString
        }
        return info == UPnPInfo() ? nil : info
    }

    /// Takes the first occurrence of each field, which is the root device's.
    private final class DescriptionReader: NSObject, XMLParserDelegate {
        var info = UPnPInfo()
        private var text = ""

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                    qualifiedName: String?, attributes: [String: String] = [:]) { text = "" }

        func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            let v = Net.clean(text)
            text = ""
            guard let v else { return }
            switch name {
            case "friendlyName": if info.friendlyName == nil { info.friendlyName = v }
            case "manufacturer": if info.manufacturer == nil { info.manufacturer = v }
            case "modelName": if info.modelName == nil { info.modelName = v }
            case "modelNumber": if info.modelNumber == nil { info.modelNumber = v }
            case "modelDescription": if info.modelDescription == nil { info.modelDescription = v }
            case "deviceType": if info.deviceType == nil { info.deviceType = v }
            case "softwareVersion", "firmwareVersion", "swVersion": if info.firmware == nil { info.firmware = v }
            case "presentationURL": if info.presentationURL == nil { info.presentationURL = v }
            default: break
            }
        }
    }
}

// MARK: - Web pages

enum Web {
    static func identify(_ ip: UInt32, ports: [UInt16]) -> WebInfo? {
        let host = IPv4.string(ip)
        let candidates: [(UInt16, String)] = [(80, "http://\(host)"), (443, "https://\(host)"),
                                               (8080, "http://\(host):8080"), (8443, "https://\(host):8443")]
        for (port, base) in candidates where ports.contains(port) {
            guard let url = URL(string: base + "/"), let res = HTTP.get(url) else { continue }
            let title = titleOf(String(decoding: res.0, as: UTF8.self))
            let server = Net.clean(res.1.value(forHTTPHeaderField: "Server"))
            if title != nil || server != nil { return WebInfo(url: base, title: title, server: server) }
        }
        return nil
    }

    private static func titleOf(_ html: String) -> String? {
        guard let r = html.range(of: "<title[^>]*>([\\s\\S]*?)</title>", options: [.regularExpression, .caseInsensitive]) else { return nil }
        var t = String(html[r])
        t = t.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
        for (entity, char) in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&nbsp;", " ")] {
            t = t.replacingOccurrences(of: entity, with: char)
        }
        return Net.clean(t)
    }
}

// MARK: - NetBIOS (Windows / Samba names)

enum NetBIOS {
    /// One node-status query (NBSTAT for "*") per host from a single UDP socket.
    static func names(for ips: [UInt32], timeout: TimeInterval = 1.5) -> [UInt32: NetBIOSInfo] {
        guard !ips.isEmpty else { return [:] }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [:] }
        defer { close(fd) }

        // Header: id, flags 0, 1 question. Name "*" padded with NULs, first-level encoded.
        var q: [UInt8] = [0x4E, 0x53, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20]
        let raw: [UInt8] = [0x2A] + [UInt8](repeating: 0, count: 15)
        for b in raw { q += [0x41 + (b >> 4), 0x41 + (b & 0x0F)] }
        q += [0x00, 0x00, 0x21, 0x00, 0x01]   // end of name, type NBSTAT, class IN

        for ip in ips {
            var sa = IPv4.socketAddress(ip, port: 137)
            _ = withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        var out: [UInt32: NetBIOSInfo] = [:]
        let deadline = Date().addingTimeInterval(timeout)
        var buf = [UInt8](repeating: 0, count: 1024)
        let cap = buf.count
        while out.count < ips.count {
            let remaining = Int32(deadline.timeIntervalSinceNow * 1000)
            guard remaining > 0 else { break }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, remaining) > 0 else { break }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, cap, 0, $0, &len) }
            }
            guard n > 0, let info = parse(Array(buf[0..<n])) else { continue }
            out[UInt32(bigEndian: from.sin_addr.s_addr)] = info
        }
        return out
    }

    /// 12-byte header, 34-byte name, 10 bytes type/class/TTL/length, then a count and
    /// 18-byte entries: 15-byte name, 1-byte suffix, 2-byte flags (0x8000 = group).
    private static func parse(_ r: [UInt8]) -> NetBIOSInfo? {
        let start = 56
        guard r.count > start else { return nil }
        let count = Int(r[start])
        var name: String?
        var group: String?
        for i in 0..<count {
            let o = start + 1 + i * 18
            guard o + 18 <= r.count else { break }
            let n = String(decoding: r[o..<(o + 15)], as: UTF8.self).trimmingCharacters(in: .whitespaces)
            let suffix = r[o + 15]
            let isGroup = r[o + 16] & 0x80 != 0
            guard suffix == 0x00, !n.isEmpty else { continue }
            if isGroup { group = group ?? n } else { name = name ?? n }
        }
        return name.map { NetBIOSInfo(name: $0, workgroup: group) }
    }
}

// MARK: - mDNS reverse lookup

/// Asks each device directly (unicast to port 5353, which Apple devices, Avahi and most IoT
/// responders answer) for the PTR record of its own address, i.e. its "name.local" hostname.
enum MDNS {
    static func names(for ips: [UInt32], timeout: TimeInterval = 1.5) -> [UInt32: String] {
        guard !ips.isEmpty else { return [:] }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return [:] }
        defer { close(fd) }

        for (n, ip) in ips.enumerated() {
            var q: [UInt8] = [UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
            let labels = [ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24].map { String($0) } + ["in-addr", "arpa"]
            for l in labels { q.append(UInt8(l.utf8.count)); q += Array(l.utf8) }
            q += [0, 0, 12, 0, 1]   // end of name, type PTR, class IN
            var sa = IPv4.socketAddress(ip, port: 5353)
            _ = withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        var out: [UInt32: String] = [:]
        let deadline = Date().addingTimeInterval(timeout)
        var buf = [UInt8](repeating: 0, count: 1500)
        let cap = buf.count
        while out.count < ips.count {
            let remaining = Int32(deadline.timeIntervalSinceNow * 1000)
            guard remaining > 0 else { break }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, remaining) > 0 else { break }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, cap, 0, $0, &len) }
            }
            guard n > 0, let name = firstPTR(Array(buf[0..<n])) else { continue }
            out[UInt32(bigEndian: from.sin_addr.s_addr)] = name
        }
        return out
    }

    /// The target of the first PTR answer in a DNS response.
    private static func firstPTR(_ m: [UInt8]) -> String? {
        guard m.count >= 12 else { return nil }
        let qd = Int(m[4]) << 8 | Int(m[5])
        let an = Int(m[6]) << 8 | Int(m[7])
        var o = 12
        for _ in 0..<qd {
            guard let q = name(m, at: o), q.1 + 4 <= m.count else { return nil }
            o = q.1 + 4
        }
        for _ in 0..<an {
            guard let a = name(m, at: o), a.1 + 10 <= m.count else { return nil }
            let next = a.1
            let type = Int(m[next]) << 8 | Int(m[next + 1])
            let rdlen = Int(m[next + 8]) << 8 | Int(m[next + 9])
            let rdata = next + 10
            guard rdata + rdlen <= m.count else { return nil }
            if type == 12, let target = name(m, at: rdata)?.0 {
                return target.hasSuffix(".") ? String(target.dropLast()) : target
            }
            o = rdata + rdlen
        }
        return nil
    }

    /// Decodes a (possibly compressed) DNS name; returns it and the offset just past it.
    private static func name(_ m: [UInt8], at start: Int) -> (String, Int)? {
        var labels: [String] = []
        var o = start
        var end: Int?
        var jumps = 0
        while o < m.count {
            let len = Int(m[o])
            if len == 0 { if end == nil { end = o + 1 }; return (labels.joined(separator: "."), end!) }
            if len & 0xC0 == 0xC0 {
                guard o + 1 < m.count, jumps < 16 else { return nil }
                if end == nil { end = o + 2 }
                o = (len & 0x3F) << 8 | Int(m[o + 1])
                jumps += 1
                continue
            }
            guard o + 1 + len <= m.count else { return nil }
            labels.append(String(decoding: m[(o + 1)..<(o + 1 + len)], as: UTF8.self))
            o += 1 + len
        }
        return nil
    }
}

// MARK: - SSH banners

enum SSH {
    static func banner(_ ip: UInt32) -> String? {
        guard let fd = Net.connect(ip, port: 22, timeout: 2) else { return nil }
        defer { close(fd) }
        let line = String(decoding: Net.read(fd, timeout: 3), as: UTF8.self)
            .components(separatedBy: .newlines).first ?? ""
        return line.hasPrefix("SSH-") ? Net.clean(line) : nil
    }
}

// MARK: - Running it

enum Identify {
    /// Fills in `identity` for every device. Blocking; call off the main thread.
    static func run(_ devices: [Device], ssdp: [UInt32: SSDP.Answer]) -> [Device] {
        let lock = NSLock()
        var ids: [UInt32: Identity] = [:]
        func update(_ ip: UInt32, _ change: (inout Identity) -> Void) {
            lock.lock(); change(&ids[ip, default: Identity()]); lock.unlock()
        }

        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 16
        let others = devices.filter { !$0.isSelf }

        queue.addOperation {
            let names = NetBIOS.names(for: others.map(\.ipKey))
            for (ip, n) in names { update(ip) { $0.netbios = n } }
        }
        queue.addOperation {
            let names = MDNS.names(for: devices.map(\.ipKey))
            for (ip, n) in names { update(ip) { $0.mdnsName = n } }
        }
        for (ip, answer) in ssdp {
            if let server = answer.server { update(ip) { $0.upnpServer = server } }
            guard let location = answer.location else { continue }
            queue.addOperation {
                if let info = SSDP.describe(location) { update(ip) { $0.upnp = info } }
            }
        }
        for d in others {
            let ip = d.ipKey
            if !Set(d.openPorts).isDisjoint(with: Probe.webPorts) {
                queue.addOperation {
                    if let w = Web.identify(ip, ports: d.openPorts) { update(ip) { $0.web = w } }
                }
            }
            if d.openPorts.contains(22) {
                queue.addOperation {
                    if let b = SSH.banner(ip) { update(ip) { $0.ssh = b } }
                }
            }
        }
        queue.waitUntilAllOperationsAreFinished()

        return devices.map { d in
            var d = d
            if let id = ids[d.ipKey] { d.identity = id }
            return d
        }
    }

    /// Re-runs the per-device checks (web, SSH) after a deep scan found more ports.
    static func refresh(_ device: Device) -> Device {
        var d = device
        if d.identity.web == nil, !Set(d.openPorts).isDisjoint(with: Probe.webPorts) {
            d.identity.web = Web.identify(d.ipKey, ports: d.openPorts)
        }
        if d.identity.ssh == nil, d.openPorts.contains(22) {
            d.identity.ssh = SSH.banner(d.ipKey)
        }
        return d
    }
}

// MARK: - Deep scan

enum DeepScan {
    /// Ports 1–1024 plus the well-known higher ones home devices use.
    static let ports: [UInt16] = {
        let extra: [UInt16] = [
            1080, 1194, 1400, 1433, 1443, 1521, 1720, 1723, 1883, 1900, 1935, 2000, 2049, 2082, 2083,
            2181, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 3478, 3689, 4000, 4040, 4443, 4567, 4711,
            5000, 5001, 5050, 5060, 5222, 5357, 5432, 5555, 5601, 5672, 5800, 5900, 5901, 5938, 5984,
            6000, 6379, 6443, 6600, 6667, 7000, 7001, 7100, 7547, 7676, 8000, 8001, 8008, 8009, 8010,
            8060, 8080, 8081, 8086, 8088, 8090, 8096, 8123, 8181, 8200, 8291, 8443, 8448, 8500, 8554,
            8686, 8843, 8880, 8883, 8888, 9000, 9001, 9080, 9090, 9091, 9100, 9200, 9295, 9443, 9999,
            10000, 10001, 10243, 11211, 20000, 27017, 32400, 32469, 49152, 49153, 49154, 49155, 50000,
            51827, 55443, 62078,
        ]
        return Array(Set(Array(UInt16(1)...1024) + extra)).sorted()
    }()

    /// Probes in batches of 200 sockets; about 6 seconds for a device that's awake.
    static func run(_ ip: UInt32, progress: @escaping (Double) -> Void) -> [UInt16] {
        Probe.raiseFileLimit()
        var open: [UInt16] = []
        let batches = stride(from: 0, to: ports.count, by: 200).map { Array(ports[$0..<min($0 + 200, ports.count)]) }
        for (i, batch) in batches.enumerated() {
            open += Probe.probe(ip, ports: batch, timeoutMs: 1000).open
            let p = Double(i + 1) / Double(batches.count)
            DispatchQueue.main.async { progress(p) }
        }
        return open.sorted()
    }
}
