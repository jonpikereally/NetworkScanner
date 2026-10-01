import AppKit

// Lookup tables: Apple model identifiers → marketing names, device types → icons,
// and shortening maker names for "<Maker> device" labels.

enum AppleModels {
    /// Marketing name for an identifier like "iPad8,9", or nil if unknown.
    static func name(_ identifier: String) -> String? {
        names[identifier]
    }

    private static let names: [String: String] = {
        var n: [String: String] = [:]
        func add(_ name: String, _ ids: String...) { for i in ids { n[i] = name } }

        // iPhone
        add("iPhone 8", "iPhone10,1", "iPhone10,4")
        add("iPhone 8 Plus", "iPhone10,2", "iPhone10,5")
        add("iPhone X", "iPhone10,3", "iPhone10,6")
        add("iPhone XS", "iPhone11,2")
        add("iPhone XS Max", "iPhone11,4", "iPhone11,6")
        add("iPhone XR", "iPhone11,8")
        add("iPhone 11", "iPhone12,1")
        add("iPhone 11 Pro", "iPhone12,3")
        add("iPhone 11 Pro Max", "iPhone12,5")
        add("iPhone SE (2nd gen)", "iPhone12,8")
        add("iPhone 12 mini", "iPhone13,1")
        add("iPhone 12", "iPhone13,2")
        add("iPhone 12 Pro", "iPhone13,3")
        add("iPhone 12 Pro Max", "iPhone13,4")
        add("iPhone 13 Pro", "iPhone14,2")
        add("iPhone 13 Pro Max", "iPhone14,3")
        add("iPhone 13 mini", "iPhone14,4")
        add("iPhone 13", "iPhone14,5")
        add("iPhone SE (3rd gen)", "iPhone14,6")
        add("iPhone 14", "iPhone14,7")
        add("iPhone 14 Plus", "iPhone14,8")
        add("iPhone 14 Pro", "iPhone15,2")
        add("iPhone 14 Pro Max", "iPhone15,3")
        add("iPhone 15", "iPhone15,4")
        add("iPhone 15 Plus", "iPhone15,5")
        add("iPhone 15 Pro", "iPhone16,1")
        add("iPhone 15 Pro Max", "iPhone16,2")
        add("iPhone 16 Pro", "iPhone17,1")
        add("iPhone 16 Pro Max", "iPhone17,2")
        add("iPhone 16", "iPhone17,3")
        add("iPhone 16 Plus", "iPhone17,4")
        add("iPhone 16e", "iPhone17,5")

        // iPad
        add("iPad Pro 11-inch", "iPad8,1", "iPad8,2", "iPad8,3", "iPad8,4")
        add("iPad Pro 12.9-inch (3rd gen)", "iPad8,5", "iPad8,6", "iPad8,7", "iPad8,8")
        add("iPad Pro 11-inch (2nd gen)", "iPad8,9", "iPad8,10")
        add("iPad Pro 12.9-inch (4th gen)", "iPad8,11", "iPad8,12")
        add("iPad (8th gen)", "iPad11,6", "iPad11,7")
        add("iPad Air (3rd gen)", "iPad11,3", "iPad11,4")
        add("iPad mini (5th gen)", "iPad11,1", "iPad11,2")
        add("iPad (9th gen)", "iPad12,1", "iPad12,2")
        add("iPad Air (4th gen)", "iPad13,1", "iPad13,2")
        add("iPad Pro 11-inch (3rd gen)", "iPad13,4", "iPad13,5", "iPad13,6", "iPad13,7")
        add("iPad Pro 12.9-inch (5th gen)", "iPad13,8", "iPad13,9", "iPad13,10", "iPad13,11")
        add("iPad Air (5th gen)", "iPad13,16", "iPad13,17")
        add("iPad (10th gen)", "iPad13,18", "iPad13,19")
        add("iPad mini (6th gen)", "iPad14,1", "iPad14,2")
        add("iPad Pro 11-inch (4th gen)", "iPad14,3", "iPad14,4")
        add("iPad Pro 12.9-inch (6th gen)", "iPad14,5", "iPad14,6")
        add("iPad Air 11-inch (M2)", "iPad14,8", "iPad14,9")
        add("iPad Air 13-inch (M2)", "iPad14,10", "iPad14,11")
        add("iPad Pro 11-inch (M4)", "iPad16,3", "iPad16,4")
        add("iPad Pro 13-inch (M4)", "iPad16,5", "iPad16,6")

        // Mac
        add("MacBook Pro 13-inch (M1)", "MacBookPro17,1")
        add("MacBook Pro 16-inch (2021)", "MacBookPro18,1", "MacBookPro18,2")
        add("MacBook Pro 14-inch (2021)", "MacBookPro18,3", "MacBookPro18,4")
        add("MacBook Air (M1)", "MacBookAir10,1")
        add("MacBook Air 13-inch (M2)", "Mac14,2")
        add("MacBook Air 15-inch (M2)", "Mac14,15")
        add("MacBook Pro 13-inch (M2)", "Mac14,7")
        add("MacBook Pro 14-inch (2023)", "Mac14,5", "Mac14,9")
        add("MacBook Pro 16-inch (2023)", "Mac14,6", "Mac14,10")
        add("MacBook Pro 14-inch (M3)", "Mac15,3", "Mac15,6", "Mac15,8", "Mac15,10")
        add("MacBook Pro 16-inch (M3)", "Mac15,7", "Mac15,9", "Mac15,11")
        add("MacBook Air 13-inch (M3)", "Mac15,12")
        add("MacBook Air 15-inch (M3)", "Mac15,13")
        add("MacBook Pro 14-inch (M4)", "Mac16,1", "Mac16,6", "Mac16,8")
        add("MacBook Pro 16-inch (M4)", "Mac16,5", "Mac16,7")
        add("MacBook Air 13-inch (M4)", "Mac16,12")
        add("MacBook Air 15-inch (M4)", "Mac16,13")
        add("Mac mini (M1)", "Macmini9,1")
        add("Mac mini (2023)", "Mac14,3", "Mac14,12")
        add("Mac mini (M4)", "Mac16,10", "Mac16,11")
        add("iMac 24-inch (M1)", "iMac21,1", "iMac21,2")
        add("iMac 24-inch (M3)", "Mac15,4", "Mac15,5")
        add("iMac 24-inch (M4)", "Mac16,2", "Mac16,3")
        add("Mac Studio (2022)", "Mac13,1", "Mac13,2")
        add("Mac Studio (2023)", "Mac14,13", "Mac14,14")

        // Apple TV and HomePod
        add("Apple TV HD", "AppleTV5,3")
        add("Apple TV 4K", "AppleTV6,2")
        add("Apple TV 4K (2nd gen)", "AppleTV11,1")
        add("Apple TV 4K (3rd gen)", "AppleTV14,1")
        add("HomePod", "AudioAccessory1,1", "AudioAccessory1,2")
        add("HomePod mini", "AudioAccessory5,1")
        add("HomePod (2nd gen)", "AudioAccessory6,1")
        return n
    }()
}

enum DeviceIcon {
    /// SF Symbol for a device type (the strings Device.kind returns).
    static func symbol(for kind: String) -> String {
        let k = kind.lowercased()
        let table: [(String, String)] = [
            ("this mac", "laptopcomputer"), ("mac laptop", "laptopcomputer"), ("mac", "desktopcomputer"),
            ("router", "wifi.router"), ("network device", "network"), ("range extender", "wifi"), ("access point", "wifi"),
            ("android", "candybarphone"),
            ("iphone", "iphone"), ("ipad", "ipad"), ("apple watch", "applewatch"), ("apple tv", "appletv"),
            ("homepod", "homepod"), ("chromecast", "tv"), ("tv box", "appletv"), ("streaming", "tv"), ("tv", "tv"),
            ("media player", "play.tv"), ("roku", "play.tv"), ("media server", "externaldrive.connected.to.line.below"),
            ("nas", "externaldrive.connected.to.line.below"), ("printer", "printer"), ("scanner", "scanner"),
            ("sonos", "hifispeaker"), ("speaker", "hifispeaker"), ("airplay", "hifispeaker"), ("audio receiver", "hifispeaker"),
            ("game console", "gamecontroller"), ("amazon", "homepod.mini"), ("light", "lightbulb"), ("hue", "lightbulb"),
            ("plug", "poweroutlet.type.b"), ("switch", "lightswitch.on"), ("thermostat", "thermometer.medium"),
            ("sensor", "sensor"), ("lock", "lock"), ("camera", "video"), ("doorbell", "video"),
            ("garage", "door.garage.closed"), ("fan", "fan"), ("smart home", "house"), ("homekit", "house"),
            ("raspberry pi", "cpu"), ("linux", "terminal"), ("windows", "pc"), ("computer", "desktopcomputer"),
            ("phone / laptop", "iphone"), ("web-managed", "globe"), ("apple device", "applelogo"),
        ]
        for (needle, symbol) in table where k.contains(needle) && exists(symbol) { return symbol }
        return "questionmark.circle"
    }

    private static var cache: [String: Bool] = [:]
    private static func exists(_ symbol: String) -> Bool {
        if let c = cache[symbol] { return c }
        let ok = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) != nil
        cache[symbol] = ok
        return ok
    }
}

enum Maker {
    /// "TP-Link Systems Inc" → "TP-Link", "Nintendo Co.,Ltd" → "Nintendo".
    static func short(_ name: String) -> String {
        var s = name.components(separatedBy: ",").first ?? name
        let drop: Set<String> = ["inc", "inc.", "incorporated", "co", "co.", "corp", "corp.", "corporation", "ltd", "ltd.",
                                 "llc", "limited", "gmbh", "ag", "sa", "s.a.", "bv", "b.v.", "technologies", "technology",
                                 "systems", "electronics", "communications", "international", "international,"]
        var words = s.split(separator: " ").map(String.init)
        while let last = words.last, words.count > 1, drop.contains(last.lowercased()) { words.removeLast() }
        s = words.joined(separator: " ")
        return s.trimmingCharacters(in: .whitespaces)
    }
}
