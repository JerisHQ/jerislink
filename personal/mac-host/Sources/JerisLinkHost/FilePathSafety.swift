import Foundation

/// Path rules for names received in a file session (design D14).
///
/// A received path is relative, made of `/`-separated components, and is
/// only ever joined under a destination folder the receiver chose. Anything
/// that could leave that folder or confuse it is refused, never repaired:
/// the sender gets REJECT `bad_path`.
enum FilePathSafety {
    static let maxComponentBytes = 255
    static let maxPathBytes = 1024
    static let maxDepth = 32

    enum Rejection: Equatable {
        case notUTF8, empty, absolute, backslash, controlChar, emptyComponent
        case dotComponent, driveLetter, componentTooLong, pathTooLong, tooDeep
    }

    enum Verdict: Equatable {
        case ok(String)          // NFC-normalised path, safe to join under a folder
        case rejected(Rejection)
    }

    /// Validate the raw UTF-8 bytes of an ENTRY path.
    static func validate(_ raw: [UInt8]) -> Verdict {
        // The stdlib decoder replaces invalid or overlong sequences with
        // U+FFFD, so a lossless round trip means the bytes were valid UTF-8.
        let s = String(decoding: raw, as: UTF8.self)
        guard Array(s.utf8) == raw else { return .rejected(.notUTF8) }
        return validate(s)
    }

    static func validate(_ path: String) -> Verdict {
        if path.isEmpty { return .rejected(.empty) }
        // NFC first, so every length and name check sees what is written.
        let nfc = path.precomposedStringWithCanonicalMapping
        // Work on UTF-8 bytes, never Characters: Swift joins "/" and a
        // following combining mark into one Character, so a Character split
        // would not see that slash and "../\u{338}x" would pass as one name.
        let b = Array(nfc.utf8)
        if b.count > maxPathBytes { return .rejected(.pathTooLong) }
        if b.first == 0x2F { return .rejected(.absolute) }
        for c in b {
            if c == 0x5C { return .rejected(.backslash) }
            if c < 0x20 || c == 0x7F { return .rejected(.controlChar) }
        }
        let parts = b.split(separator: 0x2F, omittingEmptySubsequences: false)
        if parts.count > maxDepth { return .rejected(.tooDeep) }
        for (i, part) in parts.enumerated() {
            if part.isEmpty { return .rejected(.emptyComponent) }
            if Array(part) == [0x2E] || Array(part) == [0x2E, 0x2E] { return .rejected(.dotComponent) }
            if part.count > maxComponentBytes { return .rejected(.componentTooLong) }
            if i == 0, isDriveLetter(Array(part)) { return .rejected(.driveLetter) }
        }
        return .ok(nfc)
    }

    /// "C:" or "C:anything": a Windows drive, even though ':' is legal on macOS.
    private static func isDriveLetter(_ part: [UInt8]) -> Bool {
        guard part.count >= 2, part[1] == 0x3A else { return false }
        return (part[0] >= 0x41 && part[0] <= 0x5A) || (part[0] >= 0x61 && part[0] <= 0x7A)
    }

    /// Finder-style name for the `n`th clash (n >= 2): "report 2.pdf",
    /// "notes 2", ".profile 2". The extension is what follows the last dot
    /// that is not the first character. The base is shortened, on a
    /// character boundary, so the result stays within 255 bytes.
    static func clashName(_ name: String, attempt n: Int) -> String {
        precondition(n >= 2)
        var base = name
        var ext = ""
        if let dot = name.lastIndex(of: "."), dot != name.startIndex {
            base = String(name[..<dot])
            ext = String(name[dot...])
        }
        let suffix = " \(n)"
        while !base.isEmpty, base.utf8.count + suffix.utf8.count + ext.utf8.count > maxComponentBytes {
            base.removeLast()
        }
        return base + suffix + ext
    }
}
