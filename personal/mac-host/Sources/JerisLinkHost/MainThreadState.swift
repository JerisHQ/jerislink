import Foundation
import AppKit
import Carbon

/// Host state that AppKit/TIS only serve on the main thread: the general
/// pasteboard's contents and the current keyboard input source. Callers on
/// the control service's socket threads go through these types so a main
/// thread hop happens only when there is something new to read.
///
/// `MainThreadHops` counts every `DispatchQueue.main.sync` these types make,
/// for the control stats line (`main_hops=`).
enum MainThreadHops {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var count: UInt64 = 0

    static var total: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return count
    }

    /// Run `body` on the main thread; counts a hop when the caller is not on it.
    static func sync<T>(_ body: () -> T) -> T {
        if Thread.isMainThread { return body() }
        lock.lock(); count &+= 1; lock.unlock()
        return DispatchQueue.main.sync(execute: body)
    }
}

// MARK: - Clipboard

/// What the clipboard session needs from the pasteboard.
protocol ClipboardBackend: AnyObject, Sendable {
    /// Cheap and callable from any thread: the session polls it every 100 ms.
    func changeCount() -> Int
    /// The string contents. May hop to the main thread.
    func readText() -> String?
    /// Replace the contents with `text`; returns the new change count, or nil
    /// when the write failed. May hop to the main thread.
    func writeText(_ text: String) -> Int?
}

/// `NSPasteboard.general`. `changeCount` is read on the calling thread: it is
/// a counter the pasteboard server keeps per pasteboard name, with no view or
/// window state behind it, so the 100 ms poll no longer needs the main
/// thread. Contents are still read and written on the main thread, as before,
/// and only when the count has moved.
final class SystemClipboard: ClipboardBackend, @unchecked Sendable {
    static let shared = SystemClipboard()

    func changeCount() -> Int {
        NSPasteboard.general.changeCount
    }

    func readText() -> String? {
        MainThreadHops.sync { NSPasteboard.general.string(forType: .string) }
    }

    func writeText(_ text: String) -> Int? {
        MainThreadHops.sync {
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            guard pasteboard.setString(text, forType: .string) else { return nil }
            return pasteboard.changeCount
        }
    }
}

// MARK: - Keyboard input source

/// What Caps Lock handling needs from Text Input Sources.
protocol InputSourceBackend: AnyObject, Sendable {
    /// Current keyboard input source id. May hop to the main thread.
    func currentID() -> String?
    /// Select the input source `id`. May hop to the main thread.
    func select(id: String) -> Bool
    /// Same as `currentID()`, for a caller already on the main thread.
    func currentIDOnMain() -> String?
}

/// TIS. Its calls must run on the main thread (macOS 14 asserts this).
final class SystemInputSource: InputSourceBackend, @unchecked Sendable {
    static let shared = SystemInputSource()

    private static func string(_ source: TISInputSource, _ key: CFString) -> String? {
        guard let property = TISGetInputSourceProperty(source, key) else { return nil }
        return Unmanaged<CFString>.fromOpaque(property).takeUnretainedValue() as String
    }

    func currentIDOnMain() -> String? {
        guard let source = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue() else { return nil }
        return Self.string(source, kTISPropertyInputSourceID)
    }

    func currentID() -> String? {
        MainThreadHops.sync { currentIDOnMain() }
    }

    func select(id: String) -> Bool {
        MainThreadHops.sync {
            guard let sources = TISCreateInputSourceList(nil, false)?.takeRetainedValue() as? [TISInputSource],
                  let source = sources.first(where: { Self.string($0, kTISPropertyInputSourceID) == id }) else {
                return false
            }
            return TISSelectInputSource(source) == noErr
        }
    }
}

/// The current keyboard input source id, kept up to date by the system's
/// "selected input source changed" distributed notification, so the per-key
/// path reads a locked value instead of asking TIS on the main thread.
///
/// Distributed notifications are delivered on the main run loop (the host's
/// async `main` runs it), so the refresh reads TIS right there with no hop.
/// Until the first refresh lands the value is unknown (`nil`).
final class InputSourceCache: @unchecked Sendable {
    static let shared = InputSourceCache(backend: SystemInputSource.shared,
                                         notification: kTISNotifySelectedKeyboardInputSourceChanged as String)

    let backend: InputSourceBackend
    private let notification: String
    private let lock = NSLock()
    private var value: String?
    private var started = false
    private var refreshCount: UInt64 = 0

    init(backend: InputSourceBackend, notification: String) {
        self.backend = backend
        self.notification = notification
    }

    /// The cached id; never touches TIS or the main thread.
    var current: String? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    /// Notification refreshes so far (self-test).
    var refreshes: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return refreshCount
    }

    /// Store a value the caller just read or selected itself (Caps Lock path),
    /// so the cache does not wait for the notification.
    func store(_ id: String?) {
        lock.lock(); value = id; lock.unlock()
    }

    /// Register for the notification once and queue the first read on the
    /// main thread. Safe to call from any thread, any number of times; never
    /// blocks on the main thread.
    func start() {
        lock.lock()
        if started { lock.unlock(); return }
        started = true
        lock.unlock()

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDistributedCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                Unmanaged<InputSourceCache>.fromOpaque(observer).takeUnretainedValue().refreshOnMain()
            },
            notification as CFString, nil, .deliverImmediately)
        DispatchQueue.main.async { [self] in refreshOnMain() }
    }

    private func refreshOnMain() {
        let id = backend.currentIDOnMain()
        lock.lock()
        value = id
        refreshCount &+= 1
        lock.unlock()
    }
}
