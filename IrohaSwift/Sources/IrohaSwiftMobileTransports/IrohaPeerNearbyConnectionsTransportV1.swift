import Foundation
import IrohaSwift

public enum IrohaPeerNearbyConnectionsStateV1: Equatable, Sendable {
    case idle
    case advertising
    case discovering
    case connecting(peerID: String)
    case verificationRequired(peerID: String, code: String)
    case connected(peerID: String)
    case stopped
    case failed(IrohaPeerNearbyConnectionsErrorV1)
}

public enum IrohaPeerNearbyConnectionsErrorV1: Error, Equatable, Sendable {
    case unavailable
    case busy
    case invalidDiscoveryContext
    case verificationRejected
    case connectionFailed
    case disconnected
    case invalidMessage
    case messageTooLarge
    case timedOut
    case cancelled
}

public struct IrohaPeerNearbyConnectionsConfigurationV1: Equatable, Sendable {
    public let operationTimeout: TimeInterval
    public let maximumRecordBytes: Int
    public let maximumPendingSends: Int
    public let maximumPendingWorkerActions: Int
    public let maximumPendingCallbacks: Int
    public let maximumPendingReceiveCallbacks: Int
    /// Records one connection delivers at most. The payer receives four: hello,
    /// authentication, the receiver's Request and the Credited acknowledgement;
    /// the receiver receives three: hello, authentication and the Payment.
    public let maximumReceiveRecordsPerConnection: Int

    public init(
        operationTimeout: TimeInterval = 90,
        maximumRecordBytes: Int = IrohaPeerNearbyV1.maximumMessageBytes + 64,
        maximumPendingSends: Int = 8,
        maximumPendingWorkerActions: Int = 64,
        maximumPendingCallbacks: Int = 16,
        maximumPendingReceiveCallbacks: Int = 4,
        maximumReceiveRecordsPerConnection: Int = 4
    ) {
        precondition(Self.isValidOperationTimeout(operationTimeout))
        precondition(maximumRecordBytes > 0 && maximumRecordBytes <= 32 * 1_024)
        precondition((1...64).contains(maximumPendingSends))
        precondition((1...256).contains(maximumPendingWorkerActions))
        precondition((1...64).contains(maximumPendingCallbacks))
        precondition((1...4).contains(maximumPendingReceiveCallbacks))
        precondition((maximumPendingReceiveCallbacks...4).contains(maximumReceiveRecordsPerConnection))
        self.operationTimeout = operationTimeout
        self.maximumRecordBytes = maximumRecordBytes
        self.maximumPendingSends = maximumPendingSends
        self.maximumPendingWorkerActions = maximumPendingWorkerActions
        self.maximumPendingCallbacks = maximumPendingCallbacks
        self.maximumPendingReceiveCallbacks = maximumPendingReceiveCallbacks
        self.maximumReceiveRecordsPerConnection = maximumReceiveRecordsPerConnection
    }

    static func isValidOperationTimeout(_ value: TimeInterval) -> Bool {
        value.isFinite && value > 0 && value <= 300
    }
}

/// UI and application callbacks for the Google Nearby radio adapter.
///
/// There is intentionally no default verification implementation. If the
/// delegate disappears while a verification is pending, the transport rejects
/// the connection.
public protocol IrohaPeerNearbyConnectionsTransportDelegateV1: AnyObject {
    func nearbyTransport(
        _ transport: IrohaPeerNearbyConnectionsTransportV1,
        didChange state: IrohaPeerNearbyConnectionsStateV1
    )

    /// Pair by picture: `token` is the connection's pairing token
    /// (`IrohaPeerNearbyPairingTokenV1`); derive the picture with
    /// `IrohaPeerNearbyPictureCodeV1.targetIndex(token:)` and never display the token.
    func nearbyTransport(
        _ transport: IrohaPeerNearbyConnectionsTransportV1,
        verify token: String,
        peerID: String,
        decision: @escaping (Bool) -> Void
    )

    func nearbyTransport(
        _ transport: IrohaPeerNearbyConnectionsTransportV1,
        didReceive data: Data,
        from peerID: String
    )

    /// Called after discovery selected the receiver's nonzero request context
    /// and before the radio connection is requested. Senders must bind their
    /// IPN1 session to this exact context instead of learning it from a hello.
    func nearbyTransport(
        _ transport: IrohaPeerNearbyConnectionsTransportV1,
        didResolvePeerContext context: IrohaPeerNearbyDiscoveryContextV1,
        peerID: String
    )
}

enum IrohaPeerNearbyConnectionsModeV1: Equatable {
    case advertising
    case discovering
}

enum IrohaPeerNearbyStartDecisionV1: Equatable {
    case start
    case keepActiveReplay
    case keepActiveConflict
}

enum IrohaPeerNearbyConnectionsReducerV1 {
    static func decideStart(
        activeMode: IrohaPeerNearbyConnectionsModeV1?,
        activeContext: IrohaPeerNearbyDiscoveryContextV1?,
        requestedMode: IrohaPeerNearbyConnectionsModeV1,
        requestedContext: IrohaPeerNearbyDiscoveryContextV1
    ) -> IrohaPeerNearbyStartDecisionV1 {
        guard let activeMode else { return .start }
        guard activeMode == requestedMode,
              activeContext == requestedContext else {
            return .keepActiveConflict
        }
        return .keepActiveReplay
    }

    static func isCurrentConnectedPayloadSource(
        managerMatches: Bool,
        activePeerID: String?,
        state: IrohaPeerNearbyConnectionsStateV1,
        endpointID: String
    ) -> Bool {
        guard managerMatches,
              activePeerID == endpointID,
              case .connected(let connectedPeerID) = state else { return false }
        return connectedPeerID == endpointID
    }
}

/// Radio-independent bookkeeping for Google payload delivery. A send is not
/// complete when the framework accepts it; only a terminal TransferUpdate for
/// the exact epoch, peer and payload may release the caller's barrier.
struct IrohaPeerNearbyDeliveryBarrierV1 {
    struct CompletionAction {
        let completion: (Result<Void, Error>) -> Void
        let result: Result<Void, Error>

        func perform() {
            completion(result)
        }
    }

    private struct Pending {
        let epoch: UInt64
        let peerID: String
        var cancelTransfer: (() -> Void)?
        var cancelTimeout: (() -> Void)?
        let completion: (Result<Void, Error>) -> Void
    }

    private(set) var pendingCount = 0
    private var pending: [Int64: Pending] = [:]
    private let maximumPendingCount: Int

    init(maximumPendingCount: Int = 8) {
        self.maximumPendingCount = max(1, maximumPendingCount)
    }

    mutating func register(
        payloadID: Int64,
        epoch: UInt64,
        peerID: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) -> Bool {
        guard pending[payloadID] == nil,
              pending.count < maximumPendingCount else {
            return false
        }
        pending[payloadID] = Pending(
            epoch: epoch,
            peerID: peerID,
            cancelTransfer: nil,
            cancelTimeout: nil,
            completion: completion
        )
        pendingCount = pending.count
        return true
    }

    @discardableResult
    mutating func attachTimeoutCancellation(
        payloadID: Int64,
        _ cancellation: @escaping () -> Void
    ) -> Bool {
        guard var entry = pending[payloadID] else { return false }
        entry.cancelTimeout = cancellation
        pending[payloadID] = entry
        return true
    }

    @discardableResult
    mutating func attachCancellation(
        payloadID: Int64,
        _ cancellation: @escaping () -> Void
    ) -> Bool {
        guard var entry = pending[payloadID] else { return false }
        entry.cancelTransfer = cancellation
        pending[payloadID] = entry
        return true
    }

    mutating func resolve(
        payloadID: Int64,
        epoch: UInt64,
        peerID: String,
        result: Result<Void, Error>
    ) -> CompletionAction? {
        guard let entry = pending[payloadID],
              entry.epoch == epoch,
              entry.peerID == peerID else {
            return nil
        }
        pending.removeValue(forKey: payloadID)
        pendingCount = pending.count
        entry.cancelTimeout?()
        if case .failure = result { entry.cancelTransfer?() }
        return CompletionAction(
            completion: entry.completion,
            result: result
        )
    }

    mutating func drain(
        result: Result<Void, Error>
    ) -> [CompletionAction] {
        let entries = Array(pending.values)
        entries.forEach {
            $0.cancelTimeout?()
            if case .failure = result { $0.cancelTransfer?() }
        }
        let actions = entries.map {
            CompletionAction(
                completion: $0.completion,
                result: result
            )
        }
        pending.removeAll(keepingCapacity: true)
        pendingCount = 0
        return actions
    }
}

/// Linearizes callback admission with lifecycle invalidation. The lock is
/// deliberately released before invoking application code so a delegate can
/// synchronously stop without forming a gate/lifecycle ABBA. Work admitted
/// before invalidation may finish; work not yet admitted is suppressed.
final class IrohaPeerNearbyCallbackEpochGateV1: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var currentEpoch: UInt64

    init(initialEpoch: UInt64 = 0) {
        currentEpoch = initialEpoch
    }

    func update(to epoch: UInt64) {
        lock.lock()
        currentEpoch = epoch
        lock.unlock()
    }

    func isCurrent(_ epoch: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return currentEpoch == epoch
    }

    @discardableResult
    func performIfCurrent(_ epoch: UInt64, _ action: () -> Void) -> Bool {
        lock.lock()
        guard currentEpoch == epoch else {
            lock.unlock()
            return false
        }
        lock.unlock()
        action()
        return true
    }
}

enum IrohaPeerNearbyPublicActionAdmissionV1: Equatable {
    case accepted
    case full
}

/// Bounded admission around the transport's serial GCD queue. The submission
/// recursive lock makes generation capture plus ordinary enqueue linearizable with
/// lifecycle invalidation plus its non-rejectable control enqueue. The count
/// includes both queued and executing ordinary actions, so captured records
/// remain bounded even when the serial queue is blocked for a long time.
final class IrohaPeerNearbyPublicActionPumpV1: @unchecked Sendable {
    private final class ControlSlot {
        var action: () -> Void

        init(action: @escaping () -> Void) {
            self.action = action
        }
    }

    // One recursive lock owns admission, generation and submission order. A
    // separate submission/generation pair creates an AB/BA deadlock when an
    // action reentrantly stops while another thread is invalidating it.
    private let lock = NSRecursiveLock()
    private let queue: DispatchQueue
    private let maximumPendingCount: Int
    private var generation: UInt64 = 1
    private var pendingCountStorage = 0
    private var lastControlSlot: ControlSlot?

    init(maximumPendingCount: Int, queue: DispatchQueue) {
        precondition(maximumPendingCount > 0)
        self.maximumPendingCount = maximumPendingCount
        self.queue = queue
    }

    var pendingCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return pendingCountStorage
    }

    @discardableResult
    func enqueue(
        onDropped: @escaping () -> Void = {},
        afterCurrentCheck: (() -> Void)? = nil,
        action: @escaping () -> Void
    ) -> IrohaPeerNearbyPublicActionAdmissionV1 {
        lock.lock()
        guard pendingCountStorage < maximumPendingCount else {
            lock.unlock()
            return .full
        }
        let capturedGeneration = generation
        pendingCountStorage += 1
        lastControlSlot = nil
        queue.async { [self] in
            lock.lock()
            let isCurrent = generation == capturedGeneration
            if isCurrent {
                afterCurrentCheck?()
                action()
            }
            lock.unlock()
            if !isCurrent { onDropped() }

            lock.lock()
            pendingCountStorage -= 1
            lock.unlock()
        }
        lock.unlock()
        return .accepted
    }

    /// Invalidates already-submitted ordinary work and queues lifecycle
    /// control while holding the same lock. Adjacent repeated
    /// controls coalesce, but an intervening ordinary action forces a distinct
    /// control slot so FIFO stop-before-restart order is preserved.
    @discardableResult
    func invalidateAndEnqueueControl(
        afterInvalidation: (() -> Void)? = nil,
        _ action: @escaping () -> Void
    ) -> UInt64 {
        lock.lock()
        generation &+= 1
        if generation == 0 { generation = 1 }
        let invalidatedGeneration = generation
        afterInvalidation?()
        if let lastControlSlot {
            lastControlSlot.action = action
        } else {
            let slot = ControlSlot(action: action)
            lastControlSlot = slot
            queue.async { [self, slot] in
                lock.lock()
                let control = slot.action
                if lastControlSlot === slot { lastControlSlot = nil }
                lock.unlock()
                control()
            }
        }
        lock.unlock()
        return invalidatedGeneration
    }

    /// Cancels ordinary actions captured before this point without enqueueing
    /// another lifecycle control. Internal terminal failures use this while
    /// already running on the serial transport queue.
    @discardableResult
    func invalidateOrdinaryActions() -> UInt64 {
        lock.lock()
        generation &+= 1
        if generation == 0 { generation = 1 }
        let invalidatedGeneration = generation
        lock.unlock()
        return invalidatedGeneration
    }

    /// Runs a callback-gate transition without holding the public-action lock,
    /// then reacquires it and reports whether lifecycle invalidation won. This
    /// is used only by start's epoch transition to avoid a pump -> callback
    /// gate / callback -> stop -> pump lock cycle.
    func performUnlockedIfCurrent(_ action: () -> Void) -> Bool {
        let capturedGeneration = generation
        lock.unlock()
        action()
        lock.lock()
        return generation == capturedGeneration
    }
}

/// Bounded serial fallback for terminal completions. Saturation executes on
/// the producer context: exact + bounded + nonblocking cannot simultaneously
/// guarantee the configured callback context or global FIFO order under a
/// permanently stalled queue. Each lane remains ordered for a serial producer;
/// normal callback delivery never uses this exceptional lane.
final class IrohaPeerNearbyCompletionFallbackV1: @unchecked Sendable {
    static let shared = IrohaPeerNearbyCompletionFallbackV1()

    private let lock = NSLock()
    private let queue: DispatchQueue
    private let maximumPendingCount: Int
    private var pendingCountStorage = 0

    init(
        maximumPendingCount: Int = 64,
        queue: DispatchQueue = DispatchQueue(
            label: "org.hyperledger.iroha.peer-nearby-v1-completions"
        )
    ) {
        precondition(maximumPendingCount > 0)
        self.maximumPendingCount = maximumPendingCount
        self.queue = queue
    }

    var pendingCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return pendingCountStorage
    }

    func execute(_ action: @escaping () -> Void) {
        lock.lock()
        guard pendingCountStorage < maximumPendingCount else {
            lock.unlock()
            action()
            return
        }
        pendingCountStorage += 1
        lock.unlock()
        queue.async { [self] in
            action()
            lock.lock()
            pendingCountStorage -= 1
            lock.unlock()
        }
    }
}

/// One-runnable callback FIFO. Listener work is rejected at its bound while
/// terminal send completions use a reserved configured-queue lane and the
/// bounded nonblocking fallback above on saturation.
final class IrohaPeerNearbyCallbackDispatcherV1: @unchecked Sendable {
    private struct Pending {
        let completion: Bool
        let action: () -> Void
    }

    private let condition = NSCondition()
    private let maximumPendingListenerCount: Int
    private let maximumPendingCompletionCount: Int
    private let callbackQueue: DispatchQueue
    private let completionFallback: IrohaPeerNearbyCompletionFallbackV1
    private let queueKey = DispatchSpecificKey<UInt8>()
    private var pending: [Pending] = []
    private var pendingListenerCount = 0
    private var pendingCompletionCount = 0
    private var drainScheduled = false

    init(
        maximumPendingCount: Int,
        maximumPendingCompletionCount: Int,
        callbackQueue: DispatchQueue,
        completionFallback: IrohaPeerNearbyCompletionFallbackV1 = .shared
    ) {
        precondition(maximumPendingCount > 0 && maximumPendingCompletionCount > 0)
        self.maximumPendingListenerCount = maximumPendingCount
        self.maximumPendingCompletionCount = maximumPendingCompletionCount
        self.callbackQueue = callbackQueue
        self.completionFallback = completionFallback
        callbackQueue.setSpecific(key: queueKey, value: 1)
    }

    var pendingCount: Int {
        condition.lock()
        defer { condition.unlock() }
        return pendingListenerCount + pendingCompletionCount
    }

    @discardableResult
    func execute(_ action: @escaping () -> Void) -> Bool {
        enqueue(completion: false, action: action)
    }

    func executeCritical(_ action: @escaping () -> Void) {
        condition.lock()
        if pendingCompletionCount >= maximumPendingCompletionCount {
            let isConfiguredQueue = DispatchQueue.getSpecific(key: queueKey) == 1
            condition.unlock()
            if isConfiguredQueue { action() } else { completionFallback.execute(action) }
            return
        }
        appendLocked(completion: true, action: action)
        condition.unlock()
    }

    private func enqueue(completion: Bool, action: @escaping () -> Void) -> Bool {
        condition.lock()
        guard completion || pendingListenerCount < maximumPendingListenerCount else {
            condition.unlock()
            return false
        }
        appendLocked(completion: completion, action: action)
        condition.unlock()
        return true
    }

    private func appendLocked(completion: Bool, action: @escaping () -> Void) {
        if completion { pendingCompletionCount += 1 } else { pendingListenerCount += 1 }
        pending.append(Pending(completion: completion, action: action))
        guard !drainScheduled else { return }
        drainScheduled = true
        callbackQueue.async { self.drain() }
    }

    private func drain() {
        let next: Pending
        condition.lock()
        guard !pending.isEmpty else {
            drainScheduled = false
            condition.broadcast()
            condition.unlock()
            return
        }
        next = pending.removeFirst()
        condition.unlock()

        next.action()

        condition.lock()
        if next.completion { pendingCompletionCount -= 1 } else { pendingListenerCount -= 1 }
        condition.broadcast()
        if pending.isEmpty {
            drainScheduled = false
        } else {
            // Yield between callbacks so a continuously refilled transport
            // cannot monopolize the configured UI/callback queue.
            callbackQueue.async { self.drain() }
        }
        condition.unlock()
    }

}

/// Owns one admitted public send until it either enters the radio delivery
/// barrier or is rejected. Lifecycle invalidation and deinit can therefore
/// release the captured record and complete it exactly once without relying
/// on the transport object still being alive.
private final class IrohaPeerNearbyPublicSendSubmissionV1: @unchecked Sendable {
    private struct Contents {
        var data: Data
        let completion: ((Result<Void, Error>) -> Void)?
    }

    private let lock = NSLock()
    private var contents: Contents?

    init(data: Data, completion: ((Result<Void, Error>) -> Void)?) {
        contents = Contents(data: data, completion: completion)
    }

    func take() -> (data: Data, completion: ((Result<Void, Error>) -> Void)?)? {
        lock.lock()
        defer { lock.unlock() }
        guard let contents else { return nil }
        self.contents = nil
        return (contents.data, contents.completion)
    }

    func fail(
        _ error: IrohaPeerNearbyConnectionsErrorV1,
        callbackDispatcher: IrohaPeerNearbyCallbackDispatcherV1
    ) {
        let completion: ((Result<Void, Error>) -> Void)?
        lock.lock()
        guard var contents else {
            lock.unlock()
            return
        }
        self.contents = nil
        if !contents.data.isEmpty {
            contents.data.resetBytes(in: contents.data.startIndex..<contents.data.endIndex)
        }
        completion = contents.completion
        lock.unlock()
        guard let completion else { return }
        callbackDispatcher.executeCritical { completion(.failure(error)) }
    }
}

enum IrohaPeerNearbyReceiveAdmissionV1: Equatable {
    case accepted
    case inactive
    case full
    case budgetExceeded
}

/// Bounded one-runnable receive pump. Records are tied to the exact connection
/// epoch and peer; advancing lifecycle state clears retained data immediately.
final class IrohaPeerNearbyReceiveCallbackPumpV1: @unchecked Sendable {
    private struct Phase: Equatable {
        let epoch: UInt64
        let peerID: String
    }

    private struct Pending {
        let phase: Phase
        let action: () -> Void
    }

    private let lock = NSRecursiveLock()
    private let maximumPendingCount: Int
    private let maximumRecordsPerPhase: Int
    private let schedule: (@escaping () -> Void) -> Bool
    private var activePhase: Phase?
    private var pending: [Pending] = []
    private var drainScheduled = false
    private var delivering = false
    private var admittedRecordCount = 0

    init(
        maximumPendingCount: Int,
        maximumRecordsPerPhase: Int,
        schedule: @escaping (@escaping () -> Void) -> Bool
    ) {
        precondition(maximumPendingCount > 0 && maximumRecordsPerPhase >= maximumPendingCount)
        self.maximumPendingCount = maximumPendingCount
        self.maximumRecordsPerPhase = maximumRecordsPerPhase
        self.schedule = schedule
    }

    var pendingCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return pending.count + (delivering ? 1 : 0)
    }

    func activate(epoch: UInt64, peerID: String) {
        let phase = Phase(epoch: epoch, peerID: peerID)
        lock.lock()
        if activePhase != phase {
            pending.removeAll(keepingCapacity: true)
            admittedRecordCount = 0
        }
        activePhase = phase
        lock.unlock()
    }

    func deactivate() {
        lock.lock()
        activePhase = nil
        pending.removeAll(keepingCapacity: true)
        admittedRecordCount = 0
        lock.unlock()
    }

    func enqueue(
        epoch: UInt64,
        peerID: String,
        action: @escaping () -> Void
    ) -> IrohaPeerNearbyReceiveAdmissionV1 {
        let phase = Phase(epoch: epoch, peerID: peerID)
        lock.lock()
        guard activePhase == phase else {
            lock.unlock()
            return .inactive
        }
        guard admittedRecordCount < maximumRecordsPerPhase else {
            lock.unlock()
            return .budgetExceeded
        }
        guard pending.count + (delivering ? 1 : 0) < maximumPendingCount else {
            lock.unlock()
            return .full
        }
        pending.append(Pending(phase: phase, action: action))
        admittedRecordCount += 1
        if !drainScheduled {
            drainScheduled = true
            guard schedule({ [weak self] in self?.drain() }) else {
                pending.removeAll(keepingCapacity: true)
                drainScheduled = false
                delivering = false
                lock.unlock()
                return .full
            }
        }
        lock.unlock()
        return .accepted
    }

    private func drain() {
        while true {
            let entry: Pending
            lock.lock()
            guard !pending.isEmpty else {
                delivering = false
                drainScheduled = false
                lock.unlock()
                return
            }
            entry = pending.removeFirst()
            delivering = true
            let isCurrent = activePhase == entry.phase
            lock.unlock()

            if isCurrent { entry.action() }

            lock.lock()
            delivering = false
            lock.unlock()
        }
    }
}

/// A single cancel-removing dispatch deadline. Replacing or cancelling a
/// deadline clears its event handler immediately instead of retaining a
/// cancelled `asyncAfter` work item until the old deadline passes.
final class IrohaPeerNearbyDeadlineV1: @unchecked Sendable {
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var token: UInt64 = 0

    var retainedTimerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return timer == nil ? 0 : 1
    }

    func schedule(
        on queue: DispatchQueue,
        after delay: TimeInterval,
        action: @escaping () -> Void
    ) {
        precondition(delay > 0)
        lock.lock()
        cancelLocked()
        token &+= 1
        if token == 0 { token = 1 }
        let scheduledToken = token
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + delay)
        source.setEventHandler { [weak self] in
            self?.fire(token: scheduledToken, action: action)
        }
        timer = source
        source.resume()
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        cancelLocked()
        lock.unlock()
    }

    private func fire(token scheduledToken: UInt64, action: () -> Void) {
        lock.lock()
        guard token == scheduledToken, let source = timer else {
            lock.unlock()
            return
        }
        timer = nil
        source.setEventHandler {}
        source.cancel()
        lock.unlock()
        action()
    }

    private func cancelLocked() {
        token &+= 1
        if token == 0 { token = 1 }
        timer?.setEventHandler {}
        timer?.cancel()
        timer = nil
    }

    deinit { cancel() }
}

#if canImport(NearbyConnections)
@preconcurrency import NearbyConnections

public final class IrohaPeerNearbyConnectionsTransportV1: NSObject, @unchecked Sendable {
    public static let isAvailable = true

    public weak var delegate: IrohaPeerNearbyConnectionsTransportDelegateV1?

    private let configuration: IrohaPeerNearbyConnectionsConfigurationV1
    private let queue: DispatchQueue
    private let publicActionPump: IrohaPeerNearbyPublicActionPumpV1
    private let callbackDispatcher: IrohaPeerNearbyCallbackDispatcherV1
    private let receiveCallbackPump: IrohaPeerNearbyReceiveCallbackPumpV1
    private var operationEpoch: UInt64 = 0
    private var mode: IrohaPeerNearbyConnectionsModeV1?
    private var localContext: IrohaPeerNearbyDiscoveryContextV1?
    private var activePeerID: String?
    private var connectionManager: ConnectionManager?
    private var advertiser: Advertiser?
    private var discoverer: Discoverer?
    private let connectionDeadline = IrohaPeerNearbyDeadlineV1()
    private var verificationDecision: ((Bool) -> Void)?
    private var state: IrohaPeerNearbyConnectionsStateV1 = .idle
    private var deliveryBarrier: IrohaPeerNearbyDeliveryBarrierV1
    private let callbackEpochGate = IrohaPeerNearbyCallbackEpochGateV1()

    public init(
        configuration: IrohaPeerNearbyConnectionsConfigurationV1 = .init(),
        callbackQueue: DispatchQueue = .main
    ) {
        self.configuration = configuration
        let queue = DispatchQueue(label: "org.hyperledger.iroha.peer-nearby-v1")
        self.queue = queue
        self.publicActionPump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: configuration.maximumPendingWorkerActions,
            queue: queue
        )
        let callbackDispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: configuration.maximumPendingCallbacks,
            maximumPendingCompletionCount: configuration.maximumPendingSends + 1,
            callbackQueue: callbackQueue
        )
        self.callbackDispatcher = callbackDispatcher
        self.receiveCallbackPump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: configuration.maximumPendingReceiveCallbacks,
            maximumRecordsPerPhase: configuration.maximumReceiveRecordsPerConnection,
            schedule: { action in callbackDispatcher.execute(action) }
        )
        self.deliveryBarrier = IrohaPeerNearbyDeliveryBarrierV1(
            maximumPendingCount: configuration.maximumPendingSends
        )
        super.init()
    }

    deinit {
        connectionDeadline.cancel()
        verificationDecision?(false)
        receiveCallbackPump.deactivate()
        let pendingActions = deliveryBarrier
            .drain(result: .failure(IrohaPeerNearbyConnectionsErrorV1.cancelled))
        if !pendingActions.isEmpty {
            callbackDispatcher.executeCritical {
                pendingActions.forEach { $0.perform() }
            }
        }
        discoverer?.stopDiscovery()
        advertiser?.stopAdvertising()
        if let activePeerID {
            connectionManager?.disconnect(from: activePeerID)
        }
    }

    public func startAdvertising(context: IrohaPeerNearbyDiscoveryContextV1) {
        publicActionPump.enqueue { [weak self] in
            self?.start(mode: .advertising, context: context)
        }
    }

    public func startDiscovering(context: IrohaPeerNearbyDiscoveryContextV1) {
        publicActionPump.enqueue { [weak self] in
            self?.start(mode: .discovering, context: context)
        }
    }

    public func send(_ data: Data, completion: ((Result<Void, Error>) -> Void)? = nil) {
        guard !data.isEmpty, data.count <= configuration.maximumRecordBytes else {
            completeOnCallbackQueue(
                completion,
                result: .failure(IrohaPeerNearbyConnectionsErrorV1.messageTooLarge)
            )
            return
        }
        let submission = IrohaPeerNearbyPublicSendSubmissionV1(
            data: Data(data),
            completion: completion
        )
        let callbackDispatcher = self.callbackDispatcher
        let admission = publicActionPump.enqueue(
            onDropped: {
                submission.fail(.cancelled, callbackDispatcher: callbackDispatcher)
            }
        ) { [weak self] in
            guard let self else {
                submission.fail(.cancelled, callbackDispatcher: callbackDispatcher)
                return
            }
            guard let accepted = submission.take() else { return }
            self.sendLocked(accepted.data, completion: accepted.completion)
        }
        if admission == .full {
            submission.fail(.busy, callbackDispatcher: callbackDispatcher)
        }
    }

    public func stop() {
        receiveCallbackPump.deactivate()
        callbackEpochGate.update(to: .max)
        publicActionPump.invalidateAndEnqueueControl { [weak self] in
            self?.stopLocked(finalState: .stopped)
        }
    }

    public func suspend() {
        receiveCallbackPump.deactivate()
        callbackEpochGate.update(to: .max)
        publicActionPump.invalidateAndEnqueueControl { [weak self] in
            self?.stopLocked(finalState: .failed(.cancelled))
        }
    }

    private func sendLocked(
        _ data: Data,
        completion: ((Result<Void, Error>) -> Void)?
    ) {
        guard case .connected(let peerID) = state,
              activePeerID == peerID,
              let connectionManager else {
            completeOnCallbackQueue(
                completion,
                result: .failure(IrohaPeerNearbyConnectionsErrorV1.disconnected)
            )
            return
        }
        let epoch = operationEpoch
        let payloadID = PayloadID.unique()
        let completion = completion ?? { _ in }
        guard deliveryBarrier.register(
            payloadID: payloadID,
            epoch: epoch,
            peerID: peerID,
            completion: completion
        ) else {
            completeOnCallbackQueue(
                completion,
                result: .failure(IrohaPeerNearbyConnectionsErrorV1.busy)
            )
            return
        }
        let token = connectionManager.send(
            data,
            to: [peerID],
            id: payloadID
        ) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.callbackEpochGate.performIfCurrent(epoch) {
                    guard let error,
                          let action = self.deliveryBarrier.resolve(
                            payloadID: payloadID,
                            epoch: epoch,
                            peerID: peerID,
                            result: .failure(error)
                          ) else {
                        // A nil attempt callback is only queue acceptance. The
                        // terminal TransferUpdate owns successful completion.
                        return
                    }
                    self.callbackDispatcher.executeCritical { action.perform() }
                    self.failLocked(.connectionFailed)
                }
            }
        }
        if !deliveryBarrier.attachCancellation(
            payloadID: payloadID,
            { token.cancel() }
        ) {
            // A synchronous attempt failure may already have removed it.
            token.cancel()
        }
        let sendDeadline = IrohaPeerNearbyDeadlineV1()
        let timeoutAction = { [weak self] in
            guard let self else { return }
            self.callbackEpochGate.performIfCurrent(epoch) {
                guard let action = self.deliveryBarrier.resolve(
                        payloadID: payloadID,
                        epoch: epoch,
                        peerID: peerID,
                        result: .failure(IrohaPeerNearbyConnectionsErrorV1.timedOut)
                ) else { return }
                self.callbackDispatcher.executeCritical { action.perform() }
                self.failLocked(.timedOut)
            }
        }
        if deliveryBarrier.attachTimeoutCancellation(
            payloadID: payloadID,
            { sendDeadline.cancel() }
        ) {
            sendDeadline.schedule(
                on: queue,
                after: configuration.operationTimeout,
                action: timeoutAction
            )
        } else {
            sendDeadline.cancel()
        }
    }

    private func start(
        mode: IrohaPeerNearbyConnectionsModeV1,
        context: IrohaPeerNearbyDiscoveryContextV1
    ) {
        let startDecision = IrohaPeerNearbyConnectionsReducerV1.decideStart(
            activeMode: self.mode,
            activeContext: localContext,
            requestedMode: mode,
            requestedContext: context
        )
        guard startDecision == .start else {
            // SwiftUI and process-lifecycle delivery can legitimately repeat
            // the same start request. It is idempotent. A conflicting start
            // must likewise leave the live operation and connected state
            // untouched; publishing `.failed(.busy)` here used to poison a
            // healthy connection while its Google session kept running.
            return
        }
        switch mode {
        case .advertising:
            guard context.role == .receiver else {
                publish(.failed(.invalidDiscoveryContext))
                return
            }
        case .discovering:
            guard context.role == .sender else {
                publish(.failed(.invalidDiscoveryContext))
                return
            }
        }
        guard advanceEpochForPublicStart() else { return }
        self.mode = mode
        localContext = context
        activePeerID = nil
        let manager = ConnectionManager(
            serviceID: IrohaPeerNearbyV1.serviceID,
            strategy: .pointToPoint,
            queue: queue
        )
        manager.delegate = self
        manager.enableBLEV2()
        connectionManager = manager
        scheduleTimeout(epoch: operationEpoch)
        switch mode {
        case .advertising:
            let advertiser = Advertiser(connectionManager: manager)
            advertiser.delegate = self
            self.advertiser = advertiser
            publish(.advertising)
            let epoch = operationEpoch
            advertiser.startAdvertising(
                using: Data(context.encodeRadioDiscovery().utf8)
            ) { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    self.callbackEpochGate.performIfCurrent(epoch) {
                        guard epoch == self.operationEpoch else { return }
                        if error != nil {
                            self.failLocked(.connectionFailed)
                        }
                    }
                }
            }
        case .discovering:
            let discoverer = Discoverer(connectionManager: manager)
            discoverer.delegate = self
            self.discoverer = discoverer
            publish(.discovering)
            let epoch = operationEpoch
            discoverer.startDiscovery { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    self.callbackEpochGate.performIfCurrent(epoch) {
                        guard epoch == self.operationEpoch else { return }
                        if error != nil {
                            self.failLocked(.connectionFailed)
                        }
                    }
                }
            }
        }
    }

    private func resolveContext(
        _ remote: Data,
        expectedRole: IrohaPeerNearbyRoleV1
    ) -> (
        remote: IrohaPeerNearbyDiscoveryContextV1,
        selectedLocal: IrohaPeerNearbyDiscoveryContextV1
    )? {
        guard let localContext,
              remote.count == 75,
              let representation = String(data: remote, encoding: .ascii),
              Data(representation.utf8) == remote,
              let decoded = try? IrohaPeerNearbyDiscoveryContextV1
                  .decodeRadioDiscovery(representation),
              let selected = IrohaPeerNearbyDiscoveryMatcherV1.selectLocalContext(
                  local: localContext,
                  remote: decoded,
                  expectedRemoteRole: expectedRole
              ) else {
            return nil
        }
        return (decoded, selected)
    }

    private func publishResolvedPeerContext(
        _ context: IrohaPeerNearbyDiscoveryContextV1,
        peerID: String
    ) -> Bool {
        guard delegate != nil else {
            failLocked(.busy)
            return false
        }
        let epoch = operationEpoch
        guard callbackDispatcher.execute({ [weak self] in
            guard let self else { return }
            self.callbackEpochGate.performIfCurrent(epoch) {
                guard let delegate = self.delegate else {
                    self.queue.async {
                        guard self.operationEpoch == epoch,
                              self.activePeerID == peerID else { return }
                        self.failLocked(.busy)
                    }
                    return
                }
                delegate.nearbyTransport(
                    self,
                    didResolvePeerContext: context,
                    peerID: peerID
                )
            }
        }) else {
            failLocked(.busy)
            return false
        }
        return true
    }

    private func scheduleTimeout(epoch: UInt64) {
        connectionDeadline.schedule(on: queue, after: configuration.operationTimeout) { [weak self] in
            guard let self else { return }
            self.callbackEpochGate.performIfCurrent(epoch) {
                guard epoch == self.operationEpoch, self.mode != nil else { return }
                self.failLocked(.timedOut)
            }
        }
    }

    @discardableResult
    private func publish(_ state: IrohaPeerNearbyConnectionsStateV1) -> Bool {
        self.state = state
        let epoch = operationEpoch
        let requiresDelivery: Bool
        let connectedPeerID: String?
        if case .connected(let peerID) = state {
            requiresDelivery = true
            connectedPeerID = peerID
        } else {
            requiresDelivery = false
            connectedPeerID = nil
        }
        if requiresDelivery && delegate == nil { return false }
        return callbackDispatcher.execute { [weak self] in
            guard let self else { return }
            self.callbackEpochGate.performIfCurrent(epoch) {
                guard let delegate = self.delegate else {
                    if let connectedPeerID {
                        self.queue.async {
                            guard self.operationEpoch == epoch,
                                  self.activePeerID == connectedPeerID else { return }
                            self.failLocked(.busy)
                        }
                    }
                    return
                }
                delegate.nearbyTransport(self, didChange: state)
            }
        }
    }

    private func failLocked(_ error: IrohaPeerNearbyConnectionsErrorV1) {
        publicActionPump.invalidateOrdinaryActions()
        stopLocked(finalState: .failed(error))
    }

    private func stopLocked(finalState: IrohaPeerNearbyConnectionsStateV1) {
        guard mode != nil || state != .stopped else { return }
        let pendingError: IrohaPeerNearbyConnectionsErrorV1
        switch finalState {
        case .failed(let error): pendingError = error
        case .stopped: pendingError = .cancelled
        default: pendingError = .connectionFailed
        }
        let pendingActions = deliveryBarrier.drain(
            result: .failure(pendingError)
        )
        advanceEpoch()
        connectionDeadline.cancel()
        verificationDecision?(false)
        verificationDecision = nil
        discoverer?.stopDiscovery()
        advertiser?.stopAdvertising()
        if let activePeerID {
            connectionManager?.disconnect(from: activePeerID)
        }
        discoverer?.delegate = nil
        advertiser?.delegate = nil
        connectionManager?.delegate = nil
        discoverer = nil
        advertiser = nil
        connectionManager = nil
        activePeerID = nil
        localContext = nil
        mode = nil
        publish(finalState)
        if !pendingActions.isEmpty {
            callbackDispatcher.executeCritical {
                pendingActions.forEach { $0.perform() }
            }
        }
    }

    private func advanceEpoch() {
        receiveCallbackPump.deactivate()
        operationEpoch &+= 1
        if operationEpoch == 0 { operationEpoch = 1 }
        callbackEpochGate.update(to: operationEpoch)
    }

    private func advanceEpochForPublicStart() -> Bool {
        receiveCallbackPump.deactivate()
        operationEpoch &+= 1
        if operationEpoch == 0 { operationEpoch = 1 }
        let nextEpoch = operationEpoch
        let isCurrent = publicActionPump.performUnlockedIfCurrent {
            callbackEpochGate.update(to: nextEpoch)
        }
        if !isCurrent {
            receiveCallbackPump.deactivate()
            callbackEpochGate.update(to: .max)
        }
        return isCurrent
    }

    private func completeOnCallbackQueue(
        _ completion: ((Result<Void, Error>) -> Void)?,
        result: Result<Void, Error>
    ) {
        guard let completion else { return }
        callbackDispatcher.executeCritical { completion(result) }
    }
}

extension IrohaPeerNearbyConnectionsTransportV1: AdvertiserDelegate {
    public func advertiser(
        _ advertiser: Advertiser,
        didReceiveConnectionRequestFrom endpointID: EndpointID,
        with context: Data,
        connectionRequestHandler: @escaping (Bool) -> Void
    ) {
        let callbackEpoch = operationEpoch
        guard callbackEpochGate.performIfCurrent(callbackEpoch, {
            guard self.advertiser === advertiser,
                  mode == .advertising,
                  activePeerID == nil,
                  let resolved = resolveContext(context, expectedRole: .sender) else {
                connectionRequestHandler(false)
                return
            }
            localContext = resolved.selectedLocal
            activePeerID = endpointID
            guard publishResolvedPeerContext(resolved.remote, peerID: endpointID) else {
                connectionRequestHandler(false)
                return
            }
            publish(.connecting(peerID: endpointID))
            connectionRequestHandler(true)
        }) else {
            connectionRequestHandler(false)
            return
        }
    }
}

extension IrohaPeerNearbyConnectionsTransportV1: DiscovererDelegate {
    public func discoverer(
        _ discoverer: Discoverer,
        didFind endpointID: EndpointID,
        with context: Data
    ) {
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard self.discoverer === discoverer,
                  mode == .discovering,
                  activePeerID == nil,
                  let resolved = resolveContext(context, expectedRole: .receiver) else {
                return
            }
            localContext = resolved.selectedLocal
            activePeerID = endpointID
            guard publishResolvedPeerContext(resolved.remote, peerID: endpointID) else { return }
            publish(.connecting(peerID: endpointID))
            discoverer.requestConnection(
                to: endpointID,
                using: Data(resolved.selectedLocal.encodeRadioDiscovery().utf8)
            ) { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    self.callbackEpochGate.performIfCurrent(callbackEpoch) {
                        guard self.operationEpoch == callbackEpoch,
                              self.activePeerID == endpointID else { return }
                        if error != nil {
                            self.failLocked(.connectionFailed)
                        }
                    }
                }
            }
        }
    }

    public func discoverer(_ discoverer: Discoverer, didLose endpointID: EndpointID) {
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard self.discoverer === discoverer,
                  activePeerID == endpointID,
                  case .connecting = state else { return }
            activePeerID = nil
            publish(.discovering)
        }
    }
}

extension IrohaPeerNearbyConnectionsTransportV1: ConnectionManagerDelegate {
    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didReceive verificationCode: String,
        from endpointID: EndpointID,
        verificationHandler: @escaping (Bool) -> Void
    ) {
        let callbackEpoch = operationEpoch
        guard callbackEpochGate.performIfCurrent(callbackEpoch, {
            guard self.connectionManager === connectionManager,
                  activePeerID == endpointID,
                  verificationDecision == nil else {
                verificationHandler(false)
                return
            }
            // Google's Swift API passes the pairing token as `verificationCode`.
            guard IrohaPeerNearbyPairingTokenV1.isValid(verificationCode) else {
                verificationHandler(false)
                failLocked(.verificationRejected)
                return
            }
            verificationDecision = verificationHandler
            publish(.verificationRequired(peerID: endpointID, code: verificationCode))
            guard callbackDispatcher.execute({ [weak self] in
                guard let self else { return }
                self.callbackEpochGate.performIfCurrent(callbackEpoch) {
                    guard let delegate = self.delegate else {
                        self.queue.async {
                            self.finishVerification(
                                false,
                                endpointID: endpointID,
                                epoch: callbackEpoch
                            )
                        }
                        return
                    }
                    delegate.nearbyTransport(
                        self,
                        verify: verificationCode,
                        peerID: endpointID
                    ) { [weak self] accepted in
                        self?.queue.async {
                            self?.finishVerification(
                                accepted,
                                endpointID: endpointID,
                                epoch: callbackEpoch
                            )
                        }
                    }
                }
            }) else {
                finishVerification(false, endpointID: endpointID, epoch: callbackEpoch)
                return
            }
        }) else {
            verificationHandler(false)
            return
        }
    }

    private func finishVerification(
        _ accepted: Bool,
        endpointID: String,
        epoch: UInt64
    ) {
        callbackEpochGate.performIfCurrent(epoch) {
            guard operationEpoch == epoch,
                  activePeerID == endpointID,
                  let verificationDecision else { return }
            self.verificationDecision = nil
            verificationDecision(accepted)
            if !accepted {
                failLocked(.verificationRejected)
            }
        }
    }

    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didReceive data: Data,
        withID payloadID: PayloadID,
        from endpointID: EndpointID
    ) {
        _ = payloadID
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard self.connectionManager === connectionManager,
                  activePeerID == endpointID,
                  case .connected = state else { return }
            guard !data.isEmpty, data.count <= configuration.maximumRecordBytes else {
                failLocked(data.count > configuration.maximumRecordBytes ? .messageTooLarge : .invalidMessage)
                return
            }
            switch receiveCallbackPump.enqueue(
                epoch: callbackEpoch,
                peerID: endpointID,
                action: { [weak self] in
                    guard let self else { return }
                    self.callbackEpochGate.performIfCurrent(callbackEpoch) {
                        guard let delegate = self.delegate else {
                            self.queue.async {
                                guard self.operationEpoch == callbackEpoch,
                                      self.activePeerID == endpointID else { return }
                                self.failLocked(.busy)
                            }
                            return
                        }
                        delegate.nearbyTransport(self, didReceive: data, from: endpointID)
                    }
                }
            ) {
            case .accepted, .inactive:
                return
            case .full, .budgetExceeded:
                failLocked(.busy)
            }
        }
    }

    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didReceive stream: InputStream,
        withID payloadID: PayloadID,
        from endpointID: EndpointID,
        cancellationToken token: CancellationToken
    ) {
        _ = stream
        _ = payloadID
        token.cancel()
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: self.connectionManager === connectionManager,
                activePeerID: activePeerID,
                state: state,
                endpointID: endpointID
            ) else { return }
            failLocked(.invalidMessage)
        }
    }

    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didStartReceivingResourceWithID payloadID: PayloadID,
        from endpointID: EndpointID,
        at localURL: URL,
        withName name: String,
        cancellationToken token: CancellationToken
    ) {
        _ = payloadID
        _ = localURL
        _ = name
        token.cancel()
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: self.connectionManager === connectionManager,
                activePeerID: activePeerID,
                state: state,
                endpointID: endpointID
            ) else { return }
            failLocked(.invalidMessage)
        }
    }

    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didReceiveTransferUpdate update: TransferUpdate,
        from endpointID: EndpointID,
        forPayload payloadID: PayloadID
    ) {
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard self.connectionManager === connectionManager,
                  activePeerID == endpointID else { return }
            let result: Result<Void, Error>
            switch update {
            case .success:
                result = .success(())
            case .failure, .canceled:
                result = .failure(IrohaPeerNearbyConnectionsErrorV1.connectionFailed)
            case .progress:
                return
            }
            guard let action = deliveryBarrier.resolve(
                payloadID: payloadID,
                epoch: callbackEpoch,
                peerID: endpointID,
                result: result
            ) else {
                // Incoming payloads also emit updates; they are not local sends.
                return
            }
            callbackDispatcher.executeCritical { action.perform() }
            if case .failure = result {
                failLocked(.connectionFailed)
            }
        }
    }

    public func connectionManager(
        _ connectionManager: ConnectionManager,
        didChangeTo state: ConnectionState,
        for endpointID: EndpointID
    ) {
        let callbackEpoch = operationEpoch
        callbackEpochGate.performIfCurrent(callbackEpoch) {
            guard self.connectionManager === connectionManager,
                  activePeerID == endpointID else { return }
            switch state {
            case .connecting:
                publish(.connecting(peerID: endpointID))
            case .connected:
                discoverer?.stopDiscovery()
                advertiser?.stopAdvertising()
                receiveCallbackPump.activate(epoch: callbackEpoch, peerID: endpointID)
                guard publish(.connected(peerID: endpointID)) else {
                    failLocked(.busy)
                    return
                }
                connectionDeadline.cancel()
            case .rejected:
                failLocked(.verificationRejected)
            case .disconnected:
                failLocked(.disconnected)
            }
        }
    }
}

#else

public final class IrohaPeerNearbyConnectionsTransportV1: @unchecked Sendable {
    public static let isAvailable = false
    public weak var delegate: IrohaPeerNearbyConnectionsTransportDelegateV1?

    public init(
        configuration: IrohaPeerNearbyConnectionsConfigurationV1 = .init(),
        callbackQueue: DispatchQueue = .main
    ) {
        _ = configuration
        _ = callbackQueue
    }

    public func startAdvertising(context: IrohaPeerNearbyDiscoveryContextV1) {
        _ = context
        delegate?.nearbyTransport(self, didChange: .failed(.unavailable))
    }

    public func startDiscovering(context: IrohaPeerNearbyDiscoveryContextV1) {
        _ = context
        delegate?.nearbyTransport(self, didChange: .failed(.unavailable))
    }

    public func send(_ data: Data, completion: ((Result<Void, Error>) -> Void)? = nil) {
        _ = data
        completion?(.failure(IrohaPeerNearbyConnectionsErrorV1.unavailable))
    }

    public func stop() {}
    public func suspend() {}
}

#endif
