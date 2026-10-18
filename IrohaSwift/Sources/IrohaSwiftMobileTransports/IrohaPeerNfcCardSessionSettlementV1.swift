import Foundation

/// Completion of one card presentation's wallet callbacks, independently
/// of its radio lifetime. Capture the controller's handle for that presentation
/// before starting a replacement. A successful wait means no further Request
/// preparation/authorization, payment admission, or durable commit callback can
/// start, all such reserved callbacks have returned, and this presentation's
/// durability lease has been released. Event notifications are not wallet work.
/// Settlement does not mean the payment or any callback succeeded, nor that a
/// different presentation is idle.
///
/// `.ended` remains a radio lifecycle event and does not wait for this handle.
/// Cancelling a waiter removes only that waiter: wallet work is never cancelled
/// or declared complete merely because the radio or the caller stopped.
public final class IrohaPeerNfcCardSessionSettlementV1: @unchecked Sendable {
    private let lock = NSLock()
    private var sealed = false
    private var outstandingCallbacks = 0
    private var waiters: [UUID: Waiter] = [:]

    init() {}

    /// Waits for this presentation's callback settlement. Multiple callers can
    /// wait independently. A callback that never returns keeps the handle pending.
    public func wait() async throws {
        let identifier = UUID()
        let waiter = Waiter()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in
                waiter.install(continuation)
                register(waiter, identifier: identifier)
            }
            try Task.checkCancellation()
        } onCancel: { [self] in
            waiter.resolve(.failure(CancellationError()))
            removeWaiter(identifier)
        }
    }

    /// Called synchronously before dispatch, including before a callback can
    /// queue on another actor. A sealed presentation cannot reserve more work.
    func reserveCallback() throws -> Callback {
        lock.lock()
        defer { lock.unlock() }
        guard !sealed else { throw CancellationError() }
        outstandingCallbacks += 1
        return Callback(settlement: self)
    }

    /// Launches callback work independently of any timeout/cancellation waiter.
    /// The reservation exists before the task can queue on another actor.
    func startCallback<Value: Sendable>(
        operation: @escaping @Sendable () async throws -> Value
    ) throws -> Task<Value, Error> {
        let callback = try reserveCallback()
        return Task.detached {
            defer { callback.finish() }
            return try await operation()
        }
    }

    /// Only the owner that has stopped dispatching callbacks may seal a handle.
    func seal() {
        lock.lock()
        sealed = true
        let waiting = takeSettledWaiters()
        lock.unlock()
        waiting.forEach { $0.resolve(.success(())) }
    }

    var isSettled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return sealed && outstandingCallbacks == 0
    }

    var pendingWaiterCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return waiters.count
    }

    private func finishCallback() {
        lock.lock()
        precondition(outstandingCallbacks > 0)
        outstandingCallbacks -= 1
        let waiting = takeSettledWaiters()
        lock.unlock()
        waiting.forEach { $0.resolve(.success(())) }
    }

    /// Called only while holding `lock`.
    private func takeSettledWaiters() -> [Waiter] {
        guard sealed && outstandingCallbacks == 0 else { return [] }
        let waiting = Array(waiters.values)
        waiters.removeAll()
        return waiting
    }

    private func register(_ waiter: Waiter, identifier: UUID) {
        lock.lock()
        let settled = sealed && outstandingCallbacks == 0
        if !settled, !waiter.isResolved { waiters[identifier] = waiter }
        lock.unlock()
        if settled { waiter.resolve(.success(())) }
    }

    private func removeWaiter(_ identifier: UUID) {
        lock.lock()
        waiters.removeValue(forKey: identifier)
        lock.unlock()
    }

    final class Callback: @unchecked Sendable {
        private let lock = NSLock()
        private var settlement: IrohaPeerNfcCardSessionSettlementV1?

        fileprivate init(settlement: IrohaPeerNfcCardSessionSettlementV1) {
            self.settlement = settlement
        }

        /// Call only after the actual callback returns and any lease is released.
        /// Finishing twice is harmless; dropping a token is not completion.
        func finish() {
            lock.lock()
            let settlement = self.settlement
            self.settlement = nil
            lock.unlock()
            settlement?.finishCallback()
        }
    }

    private final class Waiter: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Error>?
        private var result: Result<Void, Error>?

        var isResolved: Bool {
            lock.lock()
            defer { lock.unlock() }
            return result != nil
        }

        func install(_ continuation: CheckedContinuation<Void, Error>) {
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(with: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }

        func resolve(_ result: Result<Void, Error>) {
            lock.lock()
            guard self.result == nil else { lock.unlock(); return }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume(with: result)
        }
    }
}
