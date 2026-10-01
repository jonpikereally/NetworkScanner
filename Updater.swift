import AppKit

// In-app updates, the same scheme as PasteStack and Curtain: every installed copy reads updates/latest.json from
// the GitHub repo, and installing swaps the app bundle in place and relaunches it.

enum AppVersion {
    static var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }
    /// Stamped by build.sh / release.sh: the repo's commit count and the UTC build time.
    static var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0" }
    static var buildDate: Date? {
        (Bundle.main.object(forInfoDictionaryKey: "BuildDate") as? String).flatMap { ISO8601DateFormatter().date(from: $0) }
    }
    static let updateFeed = "https://raw.githubusercontent.com/jonpikereally/NetworkScanner/main/updates/latest.json"
    static let repo = "https://github.com/jonpikereally/NetworkScanner"
}

/// Update feed format (latest.json):
///   {"version": "1.20", "url": "NetworkScanner.zip", "notes": "What changed"}
/// `url` may be absolute or relative to the feed's own location.
struct UpdateManifest: Decodable {
    let version: String
    let url: String
    let notes: String?
}

enum UpdateError: LocalizedError {
    case noFeed
    case badFeed(String)
    case unreadable(String)
    case badPackage(String)

    var errorDescription: String? {
        switch self {
        case .noFeed:
            return "No update source is set. Use “Update Source…” in the menu to set one."
        case .badFeed(let s):
            return "The update source isn't a valid location: \(s)"
        case .unreadable(let why):
            return "Couldn't read the update: \(why)"
        case .badPackage(let why):
            return "The downloaded update isn't usable: \(why)"
        }
    }
}

final class Updater {
    static let shared = Updater()

    /// Newer version found by the most recent check, if any.
    private(set) var available: UpdateManifest?
    var onChange: () -> Void = {}
    private var timer: Timer?

    /// User override first, then the feed baked in at build time.
    var feed: String? {
        get {
            if let s = UserDefaults.standard.string(forKey: "UpdateFeed"), !s.isEmpty { return s }
            return AppVersion.updateFeed.isEmpty ? nil : AppVersion.updateFeed
        }
        set {
            let trimmed = newValue?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            UserDefaults.standard.set(trimmed.isEmpty ? nil : trimmed, forKey: "UpdateFeed")
        }
    }

    static func url(from s: String) -> URL? {
        if s.hasPrefix("http://") || s.hasPrefix("https://") || s.hasPrefix("file://") {
            return URL(string: s)
        }
        guard s.hasPrefix("/") || s.hasPrefix("~") else { return nil }
        return URL(fileURLWithPath: (s as NSString).expandingTildeInPath)
    }

    static func isNewer(_ a: String, than b: String) -> Bool {
        let pa = a.split(separator: ".").map { Int($0) ?? 0 }
        let pb = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(pa.count, pb.count) {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    /// Silent check shortly after launch and every 6 hours after that.
    func startAutomaticChecks() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            self?.check { _ in }
        }
        let t = Timer(timeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            self?.check { _ in }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// Completion runs on the main thread with the newer manifest, or nil if up to date.
    func check(completion: @escaping (Result<UpdateManifest?, Error>) -> Void) {
        guard let feed else { completion(.failure(UpdateError.noFeed)); return }
        guard let feedURL = Self.url(from: feed) else {
            completion(.failure(UpdateError.badFeed(feed))); return
        }
        DispatchQueue.global(qos: .utility).async {
            let result: Result<UpdateManifest?, Error>
            do {
                let data = try Self.read(feedURL)
                let manifest = try JSONDecoder().decode(UpdateManifest.self, from: data)
                result = .success(Self.isNewer(manifest.version, than: AppVersion.version) ? manifest : nil)
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                if case .success(let newer) = result {
                    self.available = newer
                    self.onChange()
                }
                completion(result)
            }
        }
    }

    /// Download, unpack and verify the update, then hand off to a helper script that swaps the app
    /// bundle once this process has quit and relaunches it. Completion only runs on failure.
    func install(_ manifest: UpdateManifest, completion: @escaping (Error) -> Void) {
        guard let feed, let feedURL = Self.url(from: feed),
              let zipURL = URL(string: manifest.url, relativeTo: feedURL)?.absoluteURL
        else { completion(UpdateError.noFeed); return }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let work = FileManager.default.temporaryDirectory
                    .appendingPathComponent("NetworkScanner-update-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
                let zip = work.appendingPathComponent("update.zip")
                try Self.read(zipURL).write(to: zip)

                try Self.run("/usr/bin/ditto", ["-x", "-k", zip.path, work.path])
                guard let newApp = Self.findApp(in: work) else {
                    throw UpdateError.badPackage("no NetworkScanner.app inside the zip")
                }
                let newBundle = Bundle(url: newApp)
                guard newBundle?.bundleIdentifier == Bundle.main.bundleIdentifier else {
                    throw UpdateError.badPackage("it's a different app (bundle ID doesn't match)")
                }
                guard let exe = newBundle?.executableURL,
                      FileManager.default.isExecutableFile(atPath: exe.path) else {
                    throw UpdateError.badPackage("the app has no executable")
                }

                let script = work.appendingPathComponent("swap.sh")
                try Self.swapScript.write(to: script, atomically: false, encoding: .utf8)
                let helper = Process()
                helper.executableURL = URL(fileURLWithPath: "/bin/bash")
                helper.arguments = [script.path,
                                    String(ProcessInfo.processInfo.processIdentifier),
                                    newApp.path,
                                    Bundle.main.bundleURL.path,
                                    Bundle.main.bundleIdentifier ?? "com.jonpike.networkscanner"]
                try helper.run()

                DispatchQueue.main.async { NSApp.terminate(nil) }
            } catch {
                DispatchQueue.main.async { completion(error) }
            }
        }
    }

    // MARK: - Helpers

    private static func read(_ url: URL) throws -> Data {
        if url.isFileURL {
            do { return try Data(contentsOf: url) }
            catch { throw UpdateError.unreadable("\(url.path) — \(error.localizedDescription)") }
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 60)
        request.httpMethod = "GET"
        let sem = DispatchSemaphore(value: 0)
        var out: Result<Data, Error> = .failure(UpdateError.unreadable("no response"))
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                out = .failure(UpdateError.unreadable(error.localizedDescription))
            } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                out = .failure(UpdateError.unreadable("server returned HTTP \(http.statusCode)"))
            } else {
                out = .success(data ?? Data())
            }
            sem.signal()
        }.resume()
        sem.wait()
        return try out.get()
    }

    private static func run(_ tool: String, _ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            throw UpdateError.badPackage("\((tool as NSString).lastPathComponent) failed (\(p.terminationStatus))")
        }
    }

    private static func findApp(in dir: URL) -> URL? {
        guard let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil) else { return nil }
        for case let url as URL in e {
            if url.lastPathComponent == "NetworkScanner.app" { return url }
            if url.pathExtension == "app" { e.skipDescendants() }
        }
        return nil
    }

    /// Waits for the old process to exit, swaps bundles (rolling back if the copy fails), and relaunches.
    /// The permission reset matters: an ad-hoc-signed rebuild invalidates old privacy grants while
    /// System Settings still shows them switched on, so clear them and let the new build ask.
    private static let swapScript = """
    #!/bin/bash
    PID="$1"; NEW="$2"; DEST="$3"; BID="$4"
    for _ in $(seq 1 150); do kill -0 "$PID" 2>/dev/null || break; sleep 0.2; done
    rm -rf "$DEST.old"
    if mv "$DEST" "$DEST.old" && /usr/bin/ditto --norsrc "$NEW" "$DEST"; then
        rm -rf "$DEST.old"
    else
        rm -rf "$DEST"
        mv "$DEST.old" "$DEST"
    fi
    /usr/bin/xattr -dr com.apple.quarantine "$DEST" 2>/dev/null
    /usr/bin/codesign --force --sign - "$DEST" 2>/dev/null
    /usr/bin/tccutil reset All "$BID" >/dev/null 2>&1
    /usr/bin/open "$DEST"
    """
}
