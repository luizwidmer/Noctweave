import Foundation

/// A small FIFO gate for serializing state transactions across suspension points.
///
/// Swift actors are reentrant: another operation can run while an actor method is
/// awaiting network I/O. Ratchet state must instead be mutated as one logical
/// transaction, so callers acquire this gate before loading state and release it
/// only after the resulting state has been saved.
public final class AsyncOperationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isAcquired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func acquire() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if isAcquired {
                waiters.append(continuation)
                lock.unlock()
            } else {
                isAcquired = true
                lock.unlock()
                continuation.resume()
            }
        }
    }

    public func release() {
        lock.lock()
        if waiters.isEmpty {
            isAcquired = false
            lock.unlock()
            return
        }
        let continuation = waiters.removeFirst()
        lock.unlock()
        continuation.resume()
    }
}
