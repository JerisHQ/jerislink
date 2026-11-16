import Foundation
import Darwin

/// Opens files the viewer pulls without letting a macOS privacy prompt hang
/// the file session (F3 r2).
///
/// Files in Desktop, Documents, Downloads and on removable or network volumes
/// sit behind TCC "Files & Folders". The first open() by JerisLinkHost under
/// one of them shows "JerisLinkHost would like to access files in your
/// Downloads folder" on the Mac and blocks inside the kernel until someone
/// clicks. On the session thread that held every REQUEST, PING and FILE_END
/// for minutes while Windows saw nothing. Here the open runs on a background
/// queue; the caller waits a short time and otherwise hears `.pending`. Only
/// one open is outstanding at a time: while a prompt is up, every other open
/// is `.pending` at once instead of queueing behind it. An open that finishes
/// after its caller gave up is closed.
///
/// `probe` opens and closes copied files in the background when the user
/// copies them in Finder, so a needed prompt shows at copy time, before
/// anyone pastes on Windows. TCC remembers the answer per folder class for
/// this bundle id and signing requirement, so updates keep it.
final class FileOpenGate: @unchecked Sendable {  // state behind `cond`
    enum Result: Equatable {
        case fd(Int32)
        /// An open is still waiting, most likely on a Mac privacy prompt.
        case pending
        /// The Mac refused access (EPERM/EACCES): privacy settings said no.
        case denied
        case failed
    }

    /// open(2) stand-in: returns (fd, errno). Tests inject a slow or refusing one.
    typealias Opener = @Sendable (String) -> (Int32, Int32)

    static let shared = FileOpenGate()
    static let systemOpener: Opener = { path in
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        return (fd, fd >= 0 ? 0 : errno)
    }

    private let opener: Opener
    private let queue = DispatchQueue(label: "org.jeris.jerislink.file-open", qos: .userInitiated)
    private let cond = NSCondition()
    private var busy = false  // guarded by cond

    init(opener: @escaping Opener = FileOpenGate.systemOpener) {
        self.opener = opener
    }

    private final class Slot: @unchecked Sendable {  // fields behind `lock`
        let lock = NSLock()
        var done = false
        var abandoned = false
        var fd: Int32 = -1
        var err: Int32 = 0
    }

    /// Opens `path` read-only with no symlink at the leaf, waiting at most
    /// `waitMs` in all (including for an earlier open or probe to finish). A
    /// `.fd` belongs to the caller.
    func open(_ path: String, waitMs: Int = 2500) -> Result {
        let deadline = Date().addingTimeInterval(Double(waitMs) / 1000)
        cond.lock()
        while busy {
            if !cond.wait(until: deadline) { cond.unlock(); return .pending }
        }
        busy = true
        cond.unlock()

        let slot = Slot()
        let sem = DispatchSemaphore(value: 0)
        queue.async { [opener] in
            let (fd, err) = opener(path)
            slot.lock.lock()
            if slot.abandoned {
                if fd >= 0 { Darwin.close(fd) }
            } else {
                slot.fd = fd
                slot.err = err
                slot.done = true
            }
            slot.lock.unlock()
            self.release()
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + max(0, deadline.timeIntervalSinceNow))
        slot.lock.lock()
        defer { slot.lock.unlock() }
        guard slot.done else {
            slot.abandoned = true
            return .pending
        }
        if slot.fd >= 0 { return .fd(slot.fd) }
        return slot.err == EPERM || slot.err == EACCES ? .denied : .failed
    }

    /// Opens and closes each path in the background, one after another, and
    /// returns at once. Skipped while another open is outstanding.
    func probe(_ paths: [String]) {
        guard !paths.isEmpty else { return }
        cond.lock()
        if busy { cond.unlock(); return }
        busy = true
        cond.unlock()
        queue.async { [opener] in
            for p in paths {
                let (fd, _) = opener(p)
                if fd >= 0 { Darwin.close(fd) }
            }
            self.release()
        }
    }

    private func release() {
        cond.lock()
        busy = false
        cond.broadcast()
        cond.unlock()
    }

    /// True while an open or probe is outstanding (tests).
    var isBusy: Bool { cond.lock(); defer { cond.unlock() }; return busy }
}
