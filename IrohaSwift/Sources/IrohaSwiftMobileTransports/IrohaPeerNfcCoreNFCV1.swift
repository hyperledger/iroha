import Foundation
import IrohaSwift

enum IrohaPeerNfcDurabilityDeadlineErrorV1: Error, Equatable, Sendable {
    case timedOut
    case saturated
}

/// One process-wide, queue-free durability lease shared by admission and
/// COMMIT. Timeout/cancellation never releases a lease whose application
/// callback is still running; process restart is the recovery for a callback
/// that never returns.
final class IrohaPeerNfcDurabilityLeaseGateV1: @unchecked Sendable {
    struct Lease: Equatable, Sendable {
        fileprivate let identifier: UInt64
    }

    static let shared = IrohaPeerNfcDurabilityLeaseGateV1()

    private let lock = NSLock()
    private var nextIdentifier: UInt64 = 1
    private var activeIdentifier: UInt64?

    func acquire() -> Lease? {
        lock.lock()
        defer { lock.unlock() }
        guard activeIdentifier == nil else { return nil }
        let identifier = nextIdentifier
        nextIdentifier &+= 1
        if nextIdentifier == 0 { nextIdentifier = 1 }
        activeIdentifier = identifier
        return Lease(identifier: identifier)
    }

    func release(_ lease: Lease) {
        lock.lock()
        if activeIdentifier == lease.identifier { activeIdentifier = nil }
        lock.unlock()
    }

    var isOccupied: Bool {
        lock.lock()
        defer { lock.unlock() }
        return activeIdentifier != nil
    }
}

private final class IrohaPeerNfcDurabilityRaceV1<Value: Sendable>:
    @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var pendingResult: Result<Value, Error>?
    private var timeoutTask: Task<Void, Never>?
    private var resolved = false

    func install(_ continuation: CheckedContinuation<Value, Error>) {
        lock.lock()
        if let pendingResult {
            lock.unlock()
            continuation.resume(with: pendingResult)
            return
        }
        if resolved {
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func installTimeoutTask(_ task: Task<Void, Never>) {
        lock.lock()
        guard !resolved else {
            lock.unlock()
            task.cancel()
            return
        }
        timeoutTask = task
        lock.unlock()
    }

    func resolve(
        _ result: Result<Value, Error>,
        cancelTimeout: Bool
    ) {
        lock.lock()
        guard !resolved else {
            lock.unlock()
            return
        }
        resolved = true
        let timeoutToCancel = cancelTimeout ? timeoutTask : nil
        timeoutTask = nil
        if let continuation {
            self.continuation = nil
            lock.unlock()
            timeoutToCancel?.cancel()
            continuation.resume(with: result)
        } else {
            pendingResult = result
            lock.unlock()
            timeoutToCancel?.cancel()
        }
    }
}

/// Races an application durability callback against a fixed deadline without
/// structurally awaiting a child that ignores task cancellation. A late value
/// is discarded; durable storage is restored by the next receiver start.
func irohaPeerNfcWithDurabilityDeadlineV1<Value: Sendable>(
    timeoutNanoseconds: UInt64,
    leaseGate: IrohaPeerNfcDurabilityLeaseGateV1 = .shared,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value {
    precondition(timeoutNanoseconds > 0)
    try Task.checkCancellation()
    guard let lease = leaseGate.acquire() else {
        throw IrohaPeerNfcDurabilityDeadlineErrorV1.saturated
    }
    let race = IrohaPeerNfcDurabilityRaceV1<Value>()
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
            race.install(continuation)
            let timeoutTask = Task.detached {
                do {
                    try await Task.sleep(nanoseconds: timeoutNanoseconds)
                } catch {
                    return
                }
                race.resolve(
                    .failure(IrohaPeerNfcDurabilityDeadlineErrorV1.timedOut),
                    cancelTimeout: false
                )
            }
            race.installTimeoutTask(timeoutTask)
            Task.detached {
                let result: Result<Value, Error>
                do {
                    result = .success(try await operation())
                } catch {
                    result = .failure(error)
                }
                // Releasing here, and nowhere in timeout/cancellation paths,
                // makes a hung callback consume exactly one process-wide slot.
                leaseGate.release(lease)
                race.resolve(result, cancelTimeout: true)
            }
        }
    } onCancel: {
        race.resolve(.failure(CancellationError()), cancelTimeout: true)
    }
}

#if os(iOS) && canImport(CoreNFC)
@preconcurrency import CoreNFC
@preconcurrency import UIKit

public enum IrohaPeerNfcCoreNFCErrorV1: Error, Equatable, LocalizedError, Sendable {
    case invalidCommandAPDU
    case unavailable
    case cardEmulationUnavailable
    case cardEmulationIneligible
    case cardSessionSystemUnavailable
    case cardSessionAccessNotAccepted
    case cardSessionRadioDisabled
    case invalidTag
    case cancelled
    case operationInProgress
    case retryExhausted
    case readerOperationTimedOut
    case cardSessionTimedOut
    case presentmentIntentFailed
    case platformCallTimedOut

    public var errorDescription: String? {
        switch self {
        case .invalidCommandAPDU:
            return "CoreNFC could not represent the Iroha peer NFC V1 command."
        case .unavailable:
            return "NFC reading is unavailable on this device."
        case .cardEmulationUnavailable:
            return "NFC card emulation is unavailable on this device."
        case .cardEmulationIneligible:
            return "This device is not eligible for NFC card emulation."
        case .cardSessionSystemUnavailable:
            return "iOS cannot start NFC card emulation because the system is unavailable."
        case .cardSessionAccessNotAccepted:
            return "iOS did not grant this app access to NFC card emulation."
        case .cardSessionRadioDisabled:
            return "The NFC radio is disabled."
        case .invalidTag:
            return "The detected NFC tag is not an Iroha peer V1 endpoint."
        case .cancelled:
            return "The NFC exchange was cancelled."
        case .operationInProgress:
            return "Another NFC card session is still settling."
        case .retryExhausted:
            return "The NFC contact could not be restored within the retry limit."
        case .readerOperationTimedOut:
            return "No NFC peer was detected before the reader timed out."
        case .cardSessionTimedOut:
            return "NFC card emulation did not become ready in time."
        case .presentmentIntentFailed:
            return "iOS could not prepare this app for NFC presentation."
        case .platformCallTimedOut:
            return "Core NFC did not respond before the operation deadline."
        }
    }
}

private final class IrohaPeerNfcISO7816TagBoxV1: @unchecked Sendable {
    let tag: NFCISO7816Tag

    init(_ tag: NFCISO7816Tag) {
        self.tag = tag
    }
}

private final class IrohaPeerNfcCheckpointBoxV1: @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?

    init(_ data: Data?) { self.data = data }

    func load() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return data
    }

    func store(_ data: Data) {
        lock.lock()
        self.data = Data(data)
        lock.unlock()
    }
}

@available(iOS 17.4, *)
private final class IrohaPeerNfcCardSessionBoxV1: @unchecked Sendable {
    let session: CardSession

    init(_ session: CardSession) {
        self.session = session
    }
}

@available(iOS 17.4, *)
private enum IrohaPeerNfcPresentmentIntentResultV1: Sendable {
    case acquired(NFCPresentmentIntentAssertion)
    case unavailable
}

@available(iOS 17.4, *)
private struct IrohaPeerNfcCardStartupResourcesV1: @unchecked Sendable {
    let cardSession: IrohaPeerNfcCardSessionBoxV1
    let presentmentIntentAssertion: NFCPresentmentIntentAssertion?
}

/// Marks a locally unrepresentable extended APDU as retryable only after the
/// operation has actually switched to its portable chunk limits.
private struct IrohaPeerNfcRetryableTransportErrorV1:
    IrohaPeerNfcAmbiguousResponseErrorV1 {}

/// Thin CoreNFC hooks around the transport-neutral `IrohaPeerNfcV1` core.
/// Applications retain lifecycle, entitlement, UI, and durable-store policy;
/// this adapter only converts commands, responses, and CardSession APDUs.
public enum IrohaPeerNfcCoreNFCAdapterV1 {
    @available(iOS 15.0, *)
    public static func readerAPDU(
        for command: IrohaPeerNfcCommandV1
    ) throws -> NFCISO7816APDU {
        let bytes = try IrohaPeerNfcAPDUCodecV1.encode(command)
        guard let apdu = NFCISO7816APDU(data: bytes) else {
            throw IrohaPeerNfcCoreNFCErrorV1.invalidCommandAPDU
        }
        return apdu
    }

    /// Sends one typed command without hiding non-success status words. This
    /// lets the application reconcile ambiguous RF loss with `GET_STATUS`.
    @available(iOS 15.0, *)
    public static func transceive(
        _ command: IrohaPeerNfcCommandV1,
        using tag: NFCISO7816Tag
    ) async throws -> IrohaPeerNfcAPDUResponseV1 {
        let apdu = try readerAPDU(for: command)
        let box = IrohaPeerNfcISO7816TagBoxV1(tag)
        return try await withCheckedThrowingContinuation { continuation in
            box.tag.sendCommand(apdu: apdu) { responseData, sw1, sw2, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                let rawStatusWord = UInt16(sw1) << 8 | UInt16(sw2)
                guard let statusWord = IrohaPeerNfcStatusWordV1(rawValue: rawStatusWord) else {
                    continuation.resume(
                        throwing: IrohaPeerNfcCoreNFCErrorV1.invalidCommandAPDU
                    )
                    return
                }
                guard responseData.count <= IrohaPeerNfcV1.maximumChunkBytes else {
                    continuation.resume(
                        throwing: IrohaPeerNfcCoreNFCErrorV1.invalidCommandAPDU
                    )
                    return
                }
                continuation.resume(
                    returning: IrohaPeerNfcAPDUResponseV1(
                        data: responseData,
                        statusWord: statusWord
                    )
                )
            }
        }
    }

    /// Decodes the raw APDU delivered by iOS card emulation.
    @available(iOS 17.4, *)
    public static func cardCommand(
        from apdu: CardSession.APDU
    ) throws -> IrohaPeerNfcCommandV1 {
        try IrohaPeerNfcAPDUCodecV1.decode(apdu.payload)
    }

    /// Responds with `data || SW1 || SW2`. State and durable effects must be
    /// latched before calling this method because RF delivery can be ambiguous.
    @available(iOS 17.4, *)
    public static func respond(
        to apdu: CardSession.APDU,
        with response: IrohaPeerNfcAPDUResponseV1,
        validateBeforeRetry: @escaping @Sendable () throws -> Void = {}
    ) async throws {
        try validateBeforeRetry()
        do {
            try await apdu.respond(response: response.encoded)
        } catch let error as CardSession.Error {
            guard error == .transmissionError else { throw error }
            try validateBeforeRetry()
            try await apdu.respond(response: response.encoded)
        }
        try validateBeforeRetry()
    }
}

/// App-owned presentation strings and bounded CardSession deadlines.
/// The AID is deliberately not configurable: every V1 implementation uses
/// `IrohaPeerNfcV1.applicationIdentifier` and fails closed on entitlement or
/// provisioning mismatches.
public struct IrohaPeerNfcCoreNFCConfigurationV1: Equatable, Sendable {
    public static let maximumDurabilityTimeoutMilliseconds: UInt64 = 5_000
    public static let maximumReaderOperationTimeoutMilliseconds: UInt64 = 60_000
    public static let maximumPlatformCallTimeoutMilliseconds: UInt64 = 10_000
    public static let maximumCardSessionStartupTimeoutMilliseconds: UInt64 = 15_000
    public let cardAlertMessage: String
    public let readerAlertMessage: String
    public let completionAlertMessage: String
    public let durabilityTimeoutMilliseconds: UInt64
    public let readerOperationTimeoutMilliseconds: UInt64
    public let platformCallTimeoutMilliseconds: UInt64
    public let cardSessionStartupTimeoutMilliseconds: UInt64

    public init(
        cardAlertMessage: String,
        readerAlertMessage: String,
        completionAlertMessage: String,
        durabilityTimeoutMilliseconds: UInt64 = 5_000,
        readerOperationTimeoutMilliseconds: UInt64 = 30_000,
        platformCallTimeoutMilliseconds: UInt64 = 3_000,
        cardSessionStartupTimeoutMilliseconds: UInt64 = 10_000
    ) {
        precondition(Self.isValidDurabilityTimeout(durabilityTimeoutMilliseconds))
        precondition(Self.isValidReaderOperationTimeout(readerOperationTimeoutMilliseconds))
        precondition(Self.isValidPlatformCallTimeout(platformCallTimeoutMilliseconds))
        precondition(Self.isValidCardSessionStartupTimeout(
            cardSessionStartupTimeoutMilliseconds
        ))
        self.cardAlertMessage = cardAlertMessage
        self.readerAlertMessage = readerAlertMessage
        self.completionAlertMessage = completionAlertMessage
        self.durabilityTimeoutMilliseconds = durabilityTimeoutMilliseconds
        self.readerOperationTimeoutMilliseconds = readerOperationTimeoutMilliseconds
        self.platformCallTimeoutMilliseconds = platformCallTimeoutMilliseconds
        self.cardSessionStartupTimeoutMilliseconds = cardSessionStartupTimeoutMilliseconds
    }

    static func isValidDurabilityTimeout(_ milliseconds: UInt64) -> Bool {
        (1...maximumDurabilityTimeoutMilliseconds).contains(milliseconds)
    }

    static func isValidReaderOperationTimeout(_ milliseconds: UInt64) -> Bool {
        (1...maximumReaderOperationTimeoutMilliseconds).contains(milliseconds)
    }

    static func isValidPlatformCallTimeout(_ milliseconds: UInt64) -> Bool {
        (1...maximumPlatformCallTimeoutMilliseconds).contains(milliseconds)
    }

    static func isValidCardSessionStartupTimeout(_ milliseconds: UInt64) -> Bool {
        (1...maximumCardSessionStartupTimeoutMilliseconds).contains(milliseconds)
    }

    var durabilityTimeoutNanoseconds: UInt64 {
        durabilityTimeoutMilliseconds * 1_000_000
    }

    var readerOperationTimeoutNanoseconds: UInt64 {
        readerOperationTimeoutMilliseconds * 1_000_000
    }

    var platformCallTimeoutNanoseconds: UInt64 {
        platformCallTimeoutMilliseconds * 1_000_000
    }
}

public enum IrohaPeerNfcCardAvailabilityV1: Equatable, Sendable {
    case available
    case unavailable
    case unsupported
    case ineligible
}

public enum IrohaPeerNfcCardFailureV1: Error, Equatable, Sendable {
    case authorizationRejected
    case authorizationCancelled
    case paymentAdmissionRejected
    case paymentAdmissionPersistenceFailed
    case paymentAdmissionTimedOut
    case paymentAdmissionCancelled
    case durabilityWorkerSaturated
    case durableCommitRejected
    case durableCommitPersistenceFailed
    case durableCommitTimedOut
    case durableCommitCancelled
    case invalidDurableCommitResult
    case platformCallTimedOut
    case transportFailure
}

public enum IrohaPeerNfcCardEventV1: Equatable, Sendable {
    case emulationStarted
    case paymentAdmitted
    case acknowledgementReady
    case acknowledgementConfirmed
    case failed(IrohaPeerNfcCardFailureV1)
    case ended
}

/// CoreNFC CardSession lifecycle for the V1 receiver core. The application
/// commit callback must atomically persist payment ingest and the returned
/// `IDA1` record. The runtime installs it before replying `9000` to COMMIT.
@available(iOS 17.4, *)
public final class IrohaPeerNfcCardSessionControllerV1: @unchecked Sendable {
    public typealias AuthorizeRequest = @Sendable () async throws -> Void
    public typealias AdmitPayment = @Sendable (
        IrohaPeerNfcPaymentAdmissionContextV1
    ) async throws -> IrohaPeerNfcDurablePaymentAdmissionV1
    public typealias DurableCommit = @Sendable (
        IrohaPeerNfcCommitContextV1
    ) async throws -> IrohaPeerNfcDurableAcknowledgementV1
    public typealias EventHandler = @Sendable (IrohaPeerNfcCardEventV1) -> Void

    public static func availability(
        configuration: IrohaPeerNfcCoreNFCConfigurationV1
    ) async -> IrohaPeerNfcCardAvailabilityV1 {
        let budget = IrohaPeerNfcDeadlineBudgetV1(
            timeoutMilliseconds: configuration.cardSessionStartupTimeoutMilliseconds,
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        do {
            try await requireAvailability(configuration: configuration, budget: budget)
            return .available
        } catch let error as IrohaPeerNfcCoreNFCErrorV1 {
            switch error {
            case .cardEmulationUnavailable:
                return CardSession.isSupported ? .unavailable : .unsupported
            case .cardEmulationIneligible, .presentmentIntentFailed:
                return .ineligible
            default:
                return .unavailable
            }
        } catch {
            return .unavailable
        }
    }

    private let configuration: IrohaPeerNfcCoreNFCConfigurationV1
    private let lock = NSLock()
    private var runtime: IrohaPeerNfcCardRuntimeV1?

    public init(configuration: IrohaPeerNfcCoreNFCConfigurationV1) {
        self.configuration = configuration
    }

    @discardableResult
    public func start(
        sessionID: Data,
        receiveRequest: Data,
        restoredDurableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1? = nil,
        restoredPaymentAdmission: IrohaPeerNfcDurablePaymentAdmissionV1? = nil,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1 = .default,
        onEvent: @escaping EventHandler,
        authorizeRequest: @escaping AuthorizeRequest,
        admitPayment: @escaping AdmitPayment,
        durableCommit: @escaping DurableCommit
    ) async throws -> IrohaPeerNfcRequestIdentityV1 {
        let startupBudget = IrohaPeerNfcDeadlineBudgetV1(
            timeoutMilliseconds: configuration.cardSessionStartupTimeoutMilliseconds,
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        try await Self.requireAvailability(
            configuration: configuration,
            budget: startupBudget
        )

        let receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: receiveRequest,
            durableAcknowledgement: restoredDurableAcknowledgement,
            restoredPaymentAdmission: restoredPaymentAdmission,
            profilePolicy: profilePolicy,
            limits: limits
        )
        let replacement = IrohaPeerNfcCardRuntimeV1(
            owner: self,
            configuration: configuration,
            receiver: receiver,
            onEvent: onEvent,
            authorizeRequest: authorizeRequest,
            admitPayment: admitPayment,
            durableCommit: durableCommit
        )
        lock.lock()
        guard runtime == nil else {
            lock.unlock()
            throw IrohaPeerNfcCoreNFCErrorV1.operationInProgress
        }
        runtime = replacement
        lock.unlock()
        do {
            try await withTaskCancellationHandler {
                try await replacement.start(startupBudget: startupBudget)
            } onCancel: {
                replacement.stop()
            }
            return receiver.identity
        } catch {
            lock.lock()
            if runtime === replacement { runtime = nil }
            lock.unlock()
            replacement.stop()
            throw error
        }
    }

    public func stop() {
        lock.lock()
        let active = runtime
        lock.unlock()
        active?.stop()
    }

    fileprivate func runtimeDidSettle(_ settled: IrohaPeerNfcCardRuntimeV1) {
        lock.lock()
        if runtime === settled { runtime = nil }
        lock.unlock()
    }

    private static func requireAvailability(
        configuration: IrohaPeerNfcCoreNFCConfigurationV1,
        budget: IrohaPeerNfcDeadlineBudgetV1
    ) async throws {
        guard NFCReaderSession.readingAvailable else {
            throw IrohaPeerNfcCoreNFCErrorV1.unavailable
        }
        guard CardSession.isSupported else {
            throw IrohaPeerNfcCoreNFCErrorV1.cardEmulationUnavailable
        }
        let remaining = budget.remainingNanoseconds(
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        guard remaining > 0 else {
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        }
        let isEligible: Bool
        do {
            isEligible = try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: remaining,
                operation: { await CardSession.isEligible }
            )
        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        }
        guard isEligible else {
            throw IrohaPeerNfcCoreNFCErrorV1.cardEmulationIneligible
        }
    }
}

@available(iOS 17.4, *)
private final class IrohaPeerNfcCardRuntimeV1: @unchecked Sendable {
    private weak var owner: IrohaPeerNfcCardSessionControllerV1?
    private let configuration: IrohaPeerNfcCoreNFCConfigurationV1
    private var receiver: IrohaPeerNfcReceiverSessionV1
    private let onEvent: IrohaPeerNfcCardSessionControllerV1.EventHandler
    private let authorizeRequest: IrohaPeerNfcCardSessionControllerV1.AuthorizeRequest
    private let admitPayment: IrohaPeerNfcCardSessionControllerV1.AdmitPayment
    private let durableCommit: IrohaPeerNfcCardSessionControllerV1.DurableCommit
    private let lock = NSLock()
    private var cardSession: CardSession?
    private var presentmentIntentAssertion: NFCPresentmentIntentAssertion?
    private var backgroundObserver: NSObjectProtocol?
    private var startupTask: Task<IrohaPeerNfcCardStartupResourcesV1, Error>?
    private var eventTask: Task<Void, Never>?
    private var didPublishEmulation = false
    private var requestAuthorized = false
    private var protectedBoundaryInFlight = false
    private var terminalEventGate = IrohaPeerNfcTerminalEventGateV1()
    private var startGate = IrohaPeerNfcCardRuntimeStartGateV1()
    private let startupSignal = IrohaPeerNfcAsyncSignalV1()

    init(
        owner: IrohaPeerNfcCardSessionControllerV1,
        configuration: IrohaPeerNfcCoreNFCConfigurationV1,
        receiver: IrohaPeerNfcReceiverSessionV1,
        onEvent: @escaping IrohaPeerNfcCardSessionControllerV1.EventHandler,
        authorizeRequest: @escaping IrohaPeerNfcCardSessionControllerV1.AuthorizeRequest,
        admitPayment: @escaping IrohaPeerNfcCardSessionControllerV1.AdmitPayment,
        durableCommit: @escaping IrohaPeerNfcCardSessionControllerV1.DurableCommit
    ) {
        self.owner = owner
        self.configuration = configuration
        self.receiver = receiver
        self.onEvent = onEvent
        self.authorizeRequest = authorizeRequest
        self.admitPayment = admitPayment
        self.durableCommit = durableCommit
    }

    func start(startupBudget: IrohaPeerNfcDeadlineBudgetV1) async throws {
        lock.lock()
        let mayStart = startGate.beginStart()
        lock.unlock()
        guard mayStart else {
            publishEndedOnce()
            throw IrohaPeerNfcCoreNFCErrorV1.cancelled
        }

        let configuration = self.configuration
        let startupTask = Task.detached {
            try await Self.makeStartupResources(
                configuration: configuration,
                budget: startupBudget
            )
        }
        lock.lock()
        guard !startGate.stopRequested else {
            lock.unlock()
            startupTask.cancel()
            publishEndedOnce()
            throw IrohaPeerNfcCoreNFCErrorV1.cancelled
        }
        self.startupTask = startupTask
        lock.unlock()

        let resources: IrohaPeerNfcCardStartupResourcesV1
        do {
            resources = try await startupTask.value
        } catch {
            lock.lock()
            self.startupTask = nil
            let mayInstall = startGate.finishSessionCreation()
            lock.unlock()
            if !mayInstall { publishEndedOnce() }
            throw error
        }
        let session = resources.cardSession.session
        session.alertMessage = configuration.cardAlertMessage
        lock.lock()
        self.startupTask = nil
        guard startGate.finishSessionCreation() else {
            lock.unlock()
            session.invalidate()
            publishEndedOnce()
            throw IrohaPeerNfcCoreNFCErrorV1.cancelled
        }
        cardSession = session
        presentmentIntentAssertion = resources.presentmentIntentAssertion?.isValid == true
            ? resources.presentmentIntentAssertion
            : nil
        backgroundObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.stop()
        }
        eventTask = Task { [self] in
            await run(session)
            finishEventLoop()
        }
        lock.unlock()

        let remaining = startupBudget.remainingNanoseconds(
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        guard remaining > 0 else {
            stop()
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        }
        do {
            try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: remaining,
                operation: { [startupSignal] in
                    try await startupSignal.wait()
                }
            )
        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
            stop()
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        } catch is CancellationError {
            stop()
            throw IrohaPeerNfcCoreNFCErrorV1.cancelled
        } catch {
            stop()
            throw Self.mapCardStartupError(error)
        }
    }

    func stop() {
        lock.lock()
        let startupTask = self.startupTask
        self.startupTask = nil
        let mustDefer = protectedBoundaryInFlight
        let task = mustDefer ? nil : eventTask
        let session = mustDefer ? nil : cardSession
        let backgroundObserver = mustDefer ? nil : self.backgroundObserver
        if !mustDefer {
            eventTask = nil
            cardSession = nil
            presentmentIntentAssertion = nil
            self.backgroundObserver = nil
        }
        let shouldPublishEnded = startGate.requestStop(
            hasActiveSessionOrTask: eventTask != nil || cardSession != nil
                || task != nil || session != nil || startupTask != nil
        )
        lock.unlock()
        startupTask?.cancel()
        if mustDefer { return }
        task?.cancel()
        session?.invalidate()
        if let backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
        }
        startupSignal.resolve(.failure(CancellationError()))
        if shouldPublishEnded { publishEndedOnce() }
    }

    private func run(_ session: CardSession) async {
        do {
            for try await event in session.eventStream {
                try Task.checkCancellation()
                guard mayContinue(session) else { return }
                switch event {
                case .sessionStarted, .readerDetected:
                    try await ensureEmulation(session)
                    try Task.checkCancellation()
                    guard mayContinue(session) else { return }
                    startupSignal.resolve(.success(()))
                    if !didPublishEmulation {
                        didPublishEmulation = true
                        onEvent(.emulationStarted)
                    }
                case .received(let apdu):
                    let command = try? IrohaPeerNfcCoreNFCAdapterV1.cardCommand(from: apdu)
                    let response: IrohaPeerNfcAPDUResponseV1
                    var protectedCommand = false
                    var terminalFailure: IrohaPeerNfcCardFailureV1?
                    if let command, Self.exposesRequest(command), !requestAuthorized {
                        do {
                            try await authorizeRequest()
                            try Task.checkCancellation()
                            guard mayContinue(session) else { return }
                            requestAuthorized = true
                            response = receiver.process(apdu: apdu.payload)
                        } catch is CancellationError {
                            terminalFailure = .authorizationCancelled
                            response = IrohaPeerNfcAPDUResponseV1(
                                statusWord: .securityStatusNotSatisfied
                            )
                        } catch {
                            terminalFailure = .authorizationRejected
                            response = IrohaPeerNfcAPDUResponseV1(
                                statusWord: .securityStatusNotSatisfied
                            )
                        }
                    } else if let command, case .beginPayment = command {
                        do {
                            switch try receiver.preparePaymentAdmission(command) {
                            case .alreadyAdmitted:
                                response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                                // A replay after process restart is also a state observation for
                                // the application. Events are intentionally idempotent.
                                onEvent(.paymentAdmitted)
                            case .requiresDurableAdmission(let context):
                                guard beginProtectedBoundary(session) else { return }
                                protectedCommand = true
                                let record: IrohaPeerNfcDurablePaymentAdmissionV1
                                do {
                                    record = try await irohaPeerNfcWithDurabilityDeadlineV1(
                                        timeoutNanoseconds: configuration
                                            .durabilityTimeoutNanoseconds,
                                        operation: { [admitPayment] in
                                            try await admitPayment(context)
                                        }
                                    )
                                } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
                                    terminalFailure = failure == .timedOut
                                        ? .paymentAdmissionTimedOut
                                        : .durabilityWorkerSaturated
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                } catch is CancellationError {
                                    terminalFailure = .paymentAdmissionCancelled
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                } catch {
                                    terminalFailure = .paymentAdmissionPersistenceFailed
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                }
                                do {
                                    guard mayInstallProtectedResult(session) else {
                                        terminalFailure = .paymentAdmissionCancelled
                                        response = IrohaPeerNfcAPDUResponseV1(
                                            statusWord: .storageFailure
                                        )
                                        break
                                    }
                                    guard record.context == context else {
                                        throw IrohaPeerNfcErrorV1.continuityMismatch
                                    }
                                    try receiver.installPaymentAdmission(record)
                                    response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                                    onEvent(.paymentAdmitted)
                                } catch {
                                    terminalFailure = .paymentAdmissionRejected
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .conditionsNotSatisfied
                                    )
                                }
                            }
                        } catch {
                            terminalFailure = .paymentAdmissionRejected
                            response = IrohaPeerNfcAPDUResponseV1(
                                statusWord: .conditionsNotSatisfied
                            )
                        }
                    } else if let command, case .commit = command {
                        do {
                            switch try receiver.prepareCommit(command) {
                            case .alreadyCommitted:
                                response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                                onEvent(.acknowledgementReady)
                            case .requiresDurableCommit(let context):
                                guard beginProtectedBoundary(session) else { return }
                                protectedCommand = true
                                let record: IrohaPeerNfcDurableAcknowledgementV1
                                do {
                                    record = try await irohaPeerNfcWithDurabilityDeadlineV1(
                                        timeoutNanoseconds: configuration
                                            .durabilityTimeoutNanoseconds,
                                        operation: { [durableCommit] in
                                            try await durableCommit(context)
                                        }
                                    )
                                } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
                                    terminalFailure = failure == .timedOut
                                        ? .durableCommitTimedOut
                                        : .durabilityWorkerSaturated
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                } catch is CancellationError {
                                    terminalFailure = .durableCommitCancelled
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                } catch {
                                    terminalFailure = .durableCommitPersistenceFailed
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .storageFailure
                                    )
                                    break
                                }
                                do {
                                    guard mayInstallProtectedResult(session) else {
                                        terminalFailure = .durableCommitCancelled
                                        response = IrohaPeerNfcAPDUResponseV1(
                                            statusWord: .storageFailure
                                        )
                                        break
                                    }
                                    try receiver.installDurableAcknowledgement(record)
                                    response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                                    onEvent(.acknowledgementReady)
                                } catch {
                                    terminalFailure = .invalidDurableCommitResult
                                    response = IrohaPeerNfcAPDUResponseV1(
                                        statusWord: .conditionsNotSatisfied
                                    )
                                }
                            }
                        } catch {
                            terminalFailure = .durableCommitRejected
                            response = IrohaPeerNfcAPDUResponseV1(
                                statusWord: .conditionsNotSatisfied
                            )
                        }
                    } else {
                        response = receiver.process(apdu: apdu.payload)
                    }
                    if !protectedCommand {
                        try Task.checkCancellation()
                        guard mayContinue(session) else { return }
                    }
                    if let terminalFailure { publishFailureOnce(terminalFailure) }
                    let responseGate = IrohaPeerNfcAsyncOperationGateV1()
                    do {
                        try await irohaPeerNfcWithDeadlineV1(
                            timeoutNanoseconds: configuration
                                .platformCallTimeoutNanoseconds,
                            operation: {
                                try await IrohaPeerNfcCoreNFCAdapterV1.respond(
                                    to: apdu,
                                    with: response,
                                    validateBeforeRetry: {
                                        try responseGate.validate()
                                    }
                                )
                            },
                            onTimeout: { responseGate.invalidate() },
                            onCancel: { responseGate.invalidate() }
                        )
                        responseGate.invalidate()
                    } catch let error as CardSession.Error {
                        responseGate.invalidate()
                        guard error == .transmissionError else {
                            if protectedCommand, response.statusWord == .success {
                                _ = finishProtectedBoundary(session)
                                session.invalidate()
                                return
                            }
                            throw error
                        }
                        if response.statusWord == .success,
                           command.map(Self.isConfirmation) == true {
                            // CONFIRM_ACK was latched before response delivery;
                            // finish below even when the RF response was lost.
                        } else {
                            // Keep request bytes, payment progress, and any
                            // durable ACK available. readerDeselected re-arms
                            // emulation for the reader's same-session retry.
                            if protectedCommand {
                                let shouldStop = finishProtectedBoundary(session)
                                if terminalFailure != nil || shouldStop {
                                    session.invalidate()
                                    return
                                }
                            }
                            continue
                        }
                    } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
                        responseGate.invalidate()
                        if protectedCommand {
                            _ = finishProtectedBoundary(session)
                        }
                        publishFailureOnce(.platformCallTimedOut)
                        session.invalidate()
                        return
                    }
                    if protectedCommand {
                        let shouldStop = finishProtectedBoundary(session)
                        if terminalFailure != nil || shouldStop {
                            session.invalidate()
                            return
                        }
                    } else {
                        try Task.checkCancellation()
                        guard mayContinue(session) else { return }
                        if terminalFailure != nil {
                            session.invalidate()
                            return
                        }
                    }
                    if response.statusWord == .success,
                       command.map(Self.isConfirmation) == true {
                        onEvent(.acknowledgementConfirmed)
                        await stopEmulationBestEffort(session, status: .success)
                        session.invalidate()
                        return
                    }
                case .readerDeselected:
                    // Receiver state remains latched. Proactive re-arming
                    // avoids depending on a later readerDetected callback.
                    try await ensureEmulation(session)
                case .sessionInvalidated(let reason):
                    // CardSession can report startup failures through its event
                    // stream instead of throwing from initialization or start.
                    // Preserve that reason so callers receive the actionable
                    // eligibility, availability, access, or radio error.
                    startupSignal.resolve(
                        .failure(Self.mapCardStartupError(reason))
                    )
                    return
                @unknown default:
                    break
                }
            }
        } catch is CancellationError {
            startupSignal.resolve(.failure(CancellationError()))
            return
        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
            startupSignal.resolve(
                .failure(IrohaPeerNfcCoreNFCErrorV1.platformCallTimedOut)
            )
            publishFailureOnce(.platformCallTimedOut)
            session.invalidate()
        } catch {
            startupSignal.resolve(.failure(error))
            publishFailureOnce(Self.mapCardFailure(error))
            session.invalidate()
        }
    }

    private func ensureEmulation(_ session: CardSession) async throws {
        lock.lock()
        if presentmentIntentAssertion?.isValid == false {
            presentmentIntentAssertion = nil
        }
        lock.unlock()
        let sessionBox = IrohaPeerNfcCardSessionBoxV1(session)
        let inProgress = try await irohaPeerNfcWithDeadlineV1(
            timeoutNanoseconds: configuration.platformCallTimeoutNanoseconds,
            operation: { await sessionBox.session.isEmulationInProgress }
        )
        guard !inProgress else { return }
        try await irohaPeerNfcWithDeadlineV1(
            timeoutNanoseconds: configuration.platformCallTimeoutNanoseconds,
            operation: { try await sessionBox.session.startEmulation() },
            onDiscardedSuccess: { _ in sessionBox.session.invalidate() }
        )
    }

    private func stopEmulationBestEffort(
        _ session: CardSession,
        status: CardSession.EmulationUIStatus
    ) async {
        let sessionBox = IrohaPeerNfcCardSessionBoxV1(session)
        let inProgress = try? await irohaPeerNfcWithDeadlineV1(
            timeoutNanoseconds: configuration.platformCallTimeoutNanoseconds,
            operation: { await sessionBox.session.isEmulationInProgress }
        )
        guard inProgress == true else { return }
        _ = try? await irohaPeerNfcWithDeadlineV1(
            timeoutNanoseconds: configuration.platformCallTimeoutNanoseconds,
            operation: {
                await sessionBox.session.stopEmulation(status: status)
            }
        )
    }

    private func publishEndedOnce() {
        lock.lock()
        let shouldPublish = terminalEventGate.claimEndedPublication()
        lock.unlock()
        if shouldPublish { onEvent(.ended) }
    }

    private func publishFailureOnce(_ failure: IrohaPeerNfcCardFailureV1) {
        lock.lock()
        let shouldPublish = terminalEventGate.claimFailurePublication()
        lock.unlock()
        if shouldPublish { onEvent(.failed(failure)) }
    }

    private func beginProtectedBoundary(_ session: CardSession) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard cardSession === session,
              !startGate.stopRequested,
              !protectedBoundaryInFlight else { return false }
        protectedBoundaryInFlight = true
        return true
    }

    /// Ends the admission/commit barrier only after state installation and the
    /// APDU response attempt. A stop requested meanwhile is honored now.
    private func finishProtectedBoundary(_ session: CardSession) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard cardSession === session, protectedBoundaryInFlight else { return true }
        protectedBoundaryInFlight = false
        return startGate.stopRequested
    }

    /// Awaited authorization and unprotected APDU callbacks may finish after a
    /// synchronous stop. Durable admission/commit deliberately do not use this
    /// check: their protected boundary must install the returned record and
    /// attempt the APDU response before honoring a deferred stop.
    private func mayContinue(_ session: CardSession) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cardSession === session && !startGate.stopRequested
    }

    /// A stop requested during admission/COMMIT is deferred until the durable
    /// result is installed and its bounded APDU response has been attempted.
    private func mayInstallProtectedResult(_ session: CardSession) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cardSession === session && protectedBoundaryInFlight
    }

    private func finishEventLoop() {
        lock.lock()
        eventTask = nil
        cardSession = nil
        presentmentIntentAssertion = nil
        protectedBoundaryInFlight = false
        let backgroundObserver = self.backgroundObserver
        self.backgroundObserver = nil
        lock.unlock()
        if let backgroundObserver {
            NotificationCenter.default.removeObserver(backgroundObserver)
        }
        startupSignal.resolve(.failure(CancellationError()))
        owner?.runtimeDidSettle(self)
        publishEndedOnce()
    }

    private static func makeStartupResources(
        configuration: IrohaPeerNfcCoreNFCConfigurationV1,
        budget: IrohaPeerNfcDeadlineBudgetV1
    ) async throws -> IrohaPeerNfcCardStartupResourcesV1 {
        let assertion: NFCPresentmentIntentAssertion?
        let assertionRemaining = budget.remainingNanoseconds(
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        guard assertionRemaining > 0 else {
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        }
        do {
            let result = try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: assertionRemaining,
                operation: {
                    IrohaPeerNfcPresentmentIntentResultV1.acquired(
                        try await NFCPresentmentIntentAssertion.acquire()
                    )
                }
            )
            switch result {
            case .acquired(let acquired):
                assertion = acquired.isValid ? acquired : nil
            case .unavailable:
                assertion = nil
            }
        } catch let error as NFCPresentmentIntentAssertion.Error {
            switch error {
            case .systemNotAvailable:
                // The assertion is preferred, not required. This also covers
                // the system cooldown after a recently released assertion.
                assertion = nil
            case .systemEligibilityFailed:
                throw IrohaPeerNfcCoreNFCErrorV1.presentmentIntentFailed
            @unknown default:
                throw IrohaPeerNfcCoreNFCErrorV1.presentmentIntentFailed
            }
        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
            throw IrohaPeerNfcCoreNFCErrorV1.presentmentIntentFailed
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IrohaPeerNfcCoreNFCErrorV1.presentmentIntentFailed
        }

        try Task.checkCancellation()
        let sessionRemaining = budget.remainingNanoseconds(
            nowNanoseconds: DispatchTime.now().uptimeNanoseconds
        )
        guard sessionRemaining > 0 else {
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        }
        do {
            let sessionBox = try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: sessionRemaining,
                operation: {
                    IrohaPeerNfcCardSessionBoxV1(try await CardSession())
                },
                onDiscardedSuccess: { lateSession in
                    lateSession.session.invalidate()
                }
            )
            return IrohaPeerNfcCardStartupResourcesV1(
                cardSession: sessionBox,
                presentmentIntentAssertion: assertion
            )
        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
            throw IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw mapCardStartupError(error)
        }
    }

    private static func mapCardStartupError(_ error: Error) -> Error {
        if let coreError = error as? IrohaPeerNfcCoreNFCErrorV1 {
            return coreError
        }
        guard let cardError = error as? CardSession.Error else { return error }
        switch cardError {
        case .userInvalidated, .invalidated:
            return IrohaPeerNfcCoreNFCErrorV1.cancelled
        case .maxSessionDurationReached:
            return IrohaPeerNfcCoreNFCErrorV1.cardSessionTimedOut
        case .systemEligibilityFailed:
            return IrohaPeerNfcCoreNFCErrorV1.cardEmulationIneligible
        case .systemNotAvailable, .emulationStopped, .transmissionError:
            return IrohaPeerNfcCoreNFCErrorV1.cardSessionSystemUnavailable
        case .accessNotAccepted:
            return IrohaPeerNfcCoreNFCErrorV1.cardSessionAccessNotAccepted
        case .radioDisabled:
            return IrohaPeerNfcCoreNFCErrorV1.cardSessionRadioDisabled
        @unknown default:
            return IrohaPeerNfcCoreNFCErrorV1.cardEmulationUnavailable
        }
    }

    private static func mapCardFailure(_ error: Error) -> IrohaPeerNfcCardFailureV1 {
        if let coreError = error as? IrohaPeerNfcCoreNFCErrorV1,
           coreError == .platformCallTimedOut {
            return .platformCallTimedOut
        }
        if error is IrohaPeerNfcOperationDeadlineErrorV1 {
            return .platformCallTimedOut
        }
        return .transportFailure
    }

    private static func isConfirmation(_ command: IrohaPeerNfcCommandV1) -> Bool {
        if case .confirmAcknowledgement = command { return true }
        return false
    }

    private static func exposesRequest(_ command: IrohaPeerNfcCommandV1) -> Bool {
        switch command {
        case .getInfo, .readRequest:
            return true
        default:
            return false
        }
    }
}

@available(iOS 15.0, *)
public final class IrohaPeerNfcReaderServiceV1: NSObject, @unchecked Sendable,
    NFCTagReaderSessionDelegate {
    public static var isAvailable: Bool {
#if targetEnvironment(simulator)
        false
#else
        NFCReaderSession.readingAvailable
#endif
    }

    private let configuration: IrohaPeerNfcCoreNFCConfigurationV1
    private let lock = NSLock()
    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<IrohaPeerNfcReaderExchangeResultV1, Error>?
    private var exchange: (@Sendable (
        NFCISO7816Tag,
        UInt64,
        NFCTagReaderSession
    ) async throws -> IrohaPeerNfcReaderExchangeResultV1)?
    private var exchangeTask: Task<Void, Never>?
    private var progressReporter: IrohaPeerNfcReaderProgressReporterV1?
    private var platformCallGate: IrohaPeerNfcReaderPlatformCallGateV1?
    private var retryLimitsBox: IrohaPeerNfcRetryLimitsBoxV1?
    private var retryGate: IrohaPeerNfcRetryGateV1?
    private var retryTimeoutTask: Task<Void, Never>?
    private var operationTimeoutTask: Task<Void, Never>?
    private var operationGate = IrohaPeerNfcReaderOperationGateV1()
    private var completed = false

    public init(configuration: IrohaPeerNfcCoreNFCConfigurationV1) {
        self.configuration = configuration
        super.init()
    }

    public func run(
        restoredCheckpoint: Data? = nil,
        profilePolicy: IrohaPeerNfcProfilePolicyV1,
        limits: IrohaPeerNfcLimitsV1 = .default,
        retryPolicy: IrohaPeerNfcReaderRetryPolicyV1 = .default,
        onTypedProgress: ((IrohaPeerNfcProgressEventV1) -> Void)? = nil,
        loadOrCreateDurableCheckpoint: @escaping
            IrohaPeerNfcReaderExchangeV1.LoadOrCreateDurableCheckpoint,
        updateDurableCheckpoint: @escaping
            IrohaPeerNfcReaderExchangeV1.UpdateDurableCheckpoint
    ) async throws -> IrohaPeerNfcReaderExchangeResultV1 {
        guard Self.isAvailable else { throw IrohaPeerNfcCoreNFCErrorV1.unavailable }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
            guard !Task.isCancelled else {
                continuation.resume(throwing: CancellationError())
                return
            }
            lock.lock()
            guard self.continuation == nil else {
                lock.unlock()
                continuation.resume(
                    throwing: IrohaPeerNfcCoreNFCErrorV1.operationInProgress
                )
                return
            }
            self.completed = false
            let operationEpoch = self.operationGate.beginOperation()
            self.continuation = continuation
            let progressReporter = IrohaPeerNfcReaderProgressReporterV1(
                handler: onTypedProgress
            )
            self.progressReporter = progressReporter
            let platformCallGate = IrohaPeerNfcReaderPlatformCallGateV1()
            self.platformCallGate = platformCallGate
            let checkpointBox = IrohaPeerNfcCheckpointBoxV1(restoredCheckpoint)
            let retryLimitsBox = IrohaPeerNfcRetryLimitsBoxV1(limits)
            self.retryLimitsBox = retryLimitsBox
            self.retryGate = IrohaPeerNfcRetryGateV1(retryPolicy)
            self.exchange = { [weak self] tag, capturedEpoch, capturedSession in
                guard let self else { throw CancellationError() }
                let tagBox = IrohaPeerNfcISO7816TagBoxV1(tag)
                let platformCallTimeout = self.configuration
                    .platformCallTimeoutNanoseconds
                let validate = { [weak self] in
                    guard let self else { throw CancellationError() }
                    try self.validateCurrentOperation(
                        capturedEpoch: capturedEpoch,
                        expectedSession: capturedSession
                    )
                }
                try validate()
                let exchangeLimits = retryLimitsBox.load()
                let result = try await IrohaPeerNfcReaderExchangeV1.run(
                    restoredCheckpoint: checkpointBox.load(),
                    profilePolicy: profilePolicy,
                    limits: exchangeLimits,
                    transceive: { command in
                        do {
                            let response = try await irohaPeerNfcGuardedAwaitV1(
                                validate: validate,
                                operation: {
                                    try await irohaPeerNfcWithDeadlineV1(
                                        timeoutNanoseconds: platformCallTimeout,
                                        operation: {
                                            try await IrohaPeerNfcCoreNFCAdapterV1
                                                .transceive(
                                                    command,
                                                    using: tagBox.tag
                                                )
                                        }
                                    )
                                }
                            )
                            if IrohaPeerNfcStartupResponseRetryPolicyV1
                                .shouldRetry(response, for: command) {
                                // The peer was discovered while its CardSession
                                // was still installing the selected application.
                                // Re-enter through SELECT/INFO and the exact
                                // durable checkpoint, if one already exists.
                                throw IrohaPeerNfcRetryableTransportErrorV1()
                            }
                            return response
                        } catch is CancellationError {
                            throw CancellationError()
                        } catch is IrohaPeerNfcOperationDeadlineErrorV1 {
                            try validate()
                            throw IrohaPeerNfcCoreNFCErrorV1.platformCallTimedOut
                        } catch let error as IrohaPeerNfcCoreNFCErrorV1 {
                            try validate()
                            if case .invalidCommandAPDU = error,
                               retryLimitsBox.downgradeForRetry() {
                                throw IrohaPeerNfcRetryableTransportErrorV1()
                            }
                            throw error
                        } catch let error as NFCReaderError
                            where Self.isRetryableContactError(error) {
                            try validate()
                            throw IrohaPeerNfcRetryableTransportErrorV1()
                        } catch {
                            try validate()
                            throw error
                        }
                    },
                    loadOrCreateDurableCheckpoint: { info, request in
                        try validate()
                        progressReporter.emit(
                            .requestRead,
                            bytes: request.encoded.count
                        )
                        let checkpoint = try await irohaPeerNfcGuardedAwaitV1(
                            validate: validate,
                            operation: {
                                try await loadOrCreateDurableCheckpoint(info, request)
                            }
                        )
                        // The application contract guarantees this value is
                        // already durable. Cache it only after the boundary
                        // returns so a CoreNFC reconnect can resume without
                        // invoking value creation again.
                        checkpointBox.store(checkpoint.encoded)
                        return checkpoint
                    },
                    updateDurableCheckpoint: { encoded in
                        try validate()
                        let checkpoint = try IrohaPeerNfcSenderCheckpointV1.decode(
                            encoded,
                            profilePolicy: profilePolicy,
                            limits: exchangeLimits
                        )
                        guard checkpoint.durableAcknowledgement != nil else {
                            throw IrohaPeerNfcErrorV1.continuityMismatch
                        }
                        // A validated acknowledgement can only be read after
                        // the receiver durably commits the payment. Publish
                        // this before the app persists that ACK so the two
                        // durability boundaries retain their order.
                        progressReporter.emit(
                            .paymentCommitted,
                            bytes: checkpoint.payment.encoded.count
                        )
                        _ = try await irohaPeerNfcGuardedAwaitV1(
                            validate: validate,
                            operation: {
                                try await updateDurableCheckpoint(encoded)
                            }
                        )
                        checkpointBox.store(encoded)
                    }
                )
                try validate()
                return result
            }
            guard let readerSession = NFCTagReaderSession(
                pollingOption: [.iso14443],
                delegate: self,
                queue: nil
            ) else {
                self.continuation = nil
                self.exchange = nil
                self.progressReporter = nil
                self.platformCallGate = nil
                self.retryLimitsBox = nil
                self.retryGate = nil
                self.completed = true
                _ = self.operationGate.finishOperation(
                    capturedEpoch: operationEpoch
                )
                lock.unlock()
                platformCallGate.invalidate()
                progressReporter.invalidate()
                continuation.resume(throwing: IrohaPeerNfcCoreNFCErrorV1.unavailable)
                return
            }
            readerSession.alertMessage = configuration.readerAlertMessage
            self.session = readerSession
            let operationTimeout = configuration.readerOperationTimeoutNanoseconds
            let timeoutTask = Task { [weak self, weak readerSession] in
                do {
                    try await Task.sleep(nanoseconds: operationTimeout)
                } catch {
                    return
                }
                guard let self, let readerSession else { return }
                self.finish(
                    .failure(IrohaPeerNfcCoreNFCErrorV1.readerOperationTimedOut),
                    invalidating: true,
                    expectedEpoch: operationEpoch,
                    expectedSession: readerSession
                )
            }
            self.operationTimeoutTask = timeoutTask
            lock.unlock()
            platformCallGate.performIfActive {
                readerSession.begin()
            }
            }
        } onCancel: { [weak self] in
            self?.cancel()
        }
    }

    public func cancel() {
        finish(.failure(IrohaPeerNfcCoreNFCErrorV1.cancelled), invalidating: true)
    }

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        lock.lock()
        let reporter = !completed && self.session === session
            ? progressReporter
            : nil
        lock.unlock()
        reporter?.emit(.phase1SessionActive)
    }

    public func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error: Error
    ) {
        lock.lock()
        let operationEpoch = operationGate.activeEpoch
        let shouldFinish = !completed
            && self.session === session
            && operationGate.mayMutate(capturedEpoch: operationEpoch)
        lock.unlock()
        if shouldFinish {
            finish(
                .failure(Self.mapInvalidation(error)),
                invalidating: false,
                expectedEpoch: operationEpoch,
                expectedSession: session
            )
        }
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1, let tag = tags.first,
              case .iso7816(let isoTag) = tag else {
            lock.lock()
            let operationEpoch = operationGate.activeEpoch
            guard !completed,
                  self.session === session,
                  operationGate.mayMutate(capturedEpoch: operationEpoch) else {
                lock.unlock()
                return
            }
            let disposition = retryGate?.recordInvalidDetection()
            let platformCallGate = self.platformCallGate
            let retryTimeoutTask = self.retryTimeoutTask
            self.retryTimeoutTask = nil
            let reporter = progressReporter
            lock.unlock()
            retryTimeoutTask?.cancel()
            reporter?.emit(.tagDetected)
            switch disposition {
            case .retry:
                platformCallGate?.performIfActive {
                    session.alertMessage = IrohaPeerNfcCoreNFCErrorV1
                        .invalidTag.localizedDescription
                }
                restartPollingWithDeadline(
                    session,
                    operationEpoch: operationEpoch
                )
            case .exhausted:
                finish(
                    .failure(IrohaPeerNfcCoreNFCErrorV1.retryExhausted),
                    invalidating: true,
                    expectedEpoch: operationEpoch,
                    expectedSession: session
                )
            case nil:
                break
            }
            return
        }
        lock.lock()
        let operationEpoch = operationGate.activeEpoch
        guard !completed,
              self.session === session,
              exchangeTask == nil,
              let exchange,
              let platformCallGate = self.platformCallGate,
              let retryGate,
              retryGate.claimContactAttempt(
                operationGate: &operationGate,
                capturedEpoch: operationEpoch
              ) else {
            lock.unlock()
            return
        }
        let retryTimeoutTask = self.retryTimeoutTask
        self.retryTimeoutTask = nil
        let reporter = progressReporter
        lock.unlock()
        retryTimeoutTask?.cancel()
        reporter?.emit(.tagDetected)
        let connectTimeout = configuration.platformCallTimeoutNanoseconds
        let connectTimeoutTask = Task { [weak self, weak session] in
            do {
                try await Task.sleep(nanoseconds: connectTimeout)
            } catch {
                return
            }
            guard let self, let session else { return }
            self.finish(
                .failure(IrohaPeerNfcCoreNFCErrorV1.platformCallTimedOut),
                invalidating: true,
                expectedEpoch: operationEpoch,
                expectedSession: session
            )
        }
        let didStartConnect = platformCallGate.performIfActive {
            session.connect(to: tag) { [weak self] error in
                connectTimeoutTask.cancel()
                guard let self else { return }
                self.lock.lock()
                guard self.operationGate.finishConnect(
                    capturedEpoch: operationEpoch
                ), !self.completed, self.session === session else {
                    self.lock.unlock()
                    return
                }
                if let error {
                    let mayRetry = Self.isRetryableContactError(error)
                        && (self.retryGate?.mayRedetect() == true)
                    self.lock.unlock()
                    if mayRetry {
                        self.restartPollingWithDeadline(
                            session,
                            operationEpoch: operationEpoch
                        )
                    } else {
                        self.finish(
                            .failure(
                                Self.isRetryableContactError(error)
                                    ? IrohaPeerNfcCoreNFCErrorV1.retryExhausted
                                    : error
                            ),
                            invalidating: true,
                            expectedEpoch: operationEpoch,
                            expectedSession: session
                        )
                    }
                    return
                }
                let task = Task { [weak self] in
                    guard let self else { return }
                    do {
                        let result = try await exchange(isoTag, operationEpoch, session)
                        platformCallGate.performIfActive {
                            session.alertMessage = self.configuration.completionAlertMessage
                        }
                        self.finish(
                            .success(result),
                            invalidating: true,
                            expectedEpoch: operationEpoch,
                            expectedSession: session
                        )
                    } catch is CancellationError {
                        // cancel()/finish() already owns terminal publication.
                        // A stale durable callback returning after cancellation
                        // must not finish or restart a later operation.
                        return
                    } catch let error as IrohaPeerNfcErrorV1 {
                        self.finish(
                            .failure(error),
                            invalidating: true,
                            expectedEpoch: operationEpoch,
                            expectedSession: session
                        )
                    } catch let error as IrohaPeerNfcCoreNFCErrorV1 {
                        self.finish(
                            .failure(error),
                            invalidating: true,
                            expectedEpoch: operationEpoch,
                            expectedSession: session
                        )
                    } catch is IrohaPeerNfcRetryableTransportErrorV1 {
                        // RF loss keeps the persisted checkpoint authoritative.
                        // A fresh detection reruns GET_INFO/GET_STATUS and resumes.
                        self.lock.lock()
                        let mayRetry = !self.completed
                            && self.session === session
                            && self.operationGate.mayMutate(
                                capturedEpoch: operationEpoch
                            )
                            && self.retryGate?.mayRedetect() == true
                        if mayRetry { self.exchangeTask = nil }
                        self.lock.unlock()
                        if mayRetry {
                            self.restartPollingWithDeadline(
                                session,
                                operationEpoch: operationEpoch
                            )
                        } else {
                            self.finish(
                                .failure(IrohaPeerNfcCoreNFCErrorV1.retryExhausted),
                                invalidating: true,
                                expectedEpoch: operationEpoch,
                                expectedSession: session
                            )
                        }
                    } catch {
                        // Application preparation and checkpoint persistence
                        // failures are not RF failures and must not retry forever.
                        self.finish(
                            .failure(error),
                            invalidating: true,
                            expectedEpoch: operationEpoch,
                            expectedSession: session
                        )
                    }
                }
                self.exchangeTask = task
                self.lock.unlock()
            }
        }
        if !didStartConnect { connectTimeoutTask.cancel() }
    }

    private func finish(
        _ result: Result<IrohaPeerNfcReaderExchangeResultV1, Error>,
        invalidating: Bool,
        expectedEpoch: UInt64? = nil,
        expectedSession: NFCTagReaderSession? = nil
    ) {
        lock.lock()
        let operationEpoch = expectedEpoch ?? operationGate.activeEpoch
        guard !completed,
              operationGate.mayMutate(capturedEpoch: operationEpoch),
              expectedSession.map({ self.session === $0 }) ?? true else {
            lock.unlock()
            return
        }
        completed = true
        _ = operationGate.finishOperation(capturedEpoch: operationEpoch)
        let continuation = continuation
        self.continuation = nil
        exchange = nil
        let progressReporter = self.progressReporter
        self.progressReporter = nil
        let platformCallGate = self.platformCallGate
        self.platformCallGate = nil
        retryLimitsBox = nil
        retryGate = nil
        let retryTimeoutTask = self.retryTimeoutTask
        self.retryTimeoutTask = nil
        let operationTimeoutTask = self.operationTimeoutTask
        self.operationTimeoutTask = nil
        let task = exchangeTask
        exchangeTask = nil
        let session = session
        self.session = nil
        lock.unlock()
        retryTimeoutTask?.cancel()
        operationTimeoutTask?.cancel()
        platformCallGate?.invalidate()
        progressReporter?.invalidate()
        task?.cancel()
        if invalidating { session?.invalidate() }
        continuation?.resume(with: result)
    }

    private func restartPollingWithDeadline(
        _ session: NFCTagReaderSession,
        operationEpoch: UInt64
    ) {
        lock.lock()
        guard !completed,
              self.session === session,
              let gate = retryGate,
              let platformCallGate else {
            lock.unlock()
            return
        }
        retryTimeoutTask?.cancel()
        let timeout = gate.redetectionTimeoutNanoseconds
        let task = Task { [weak self, weak session] in
            try? await Task.sleep(nanoseconds: timeout)
            guard !Task.isCancelled, let self, let session else { return }
            self.finish(
                .failure(IrohaPeerNfcCoreNFCErrorV1.retryExhausted),
                invalidating: true,
                expectedEpoch: operationEpoch,
                expectedSession: session
            )
        }
        retryTimeoutTask = task
        lock.unlock()
        platformCallGate.performIfActive { session.restartPolling() }
    }

    private func validateCurrentOperation(
        capturedEpoch: UInt64,
        expectedSession: NFCTagReaderSession
    ) throws {
        try Task.checkCancellation()
        lock.lock()
        let isCurrent = !completed
            && session === expectedSession
            && operationGate.mayMutate(capturedEpoch: capturedEpoch)
        lock.unlock()
        guard isCurrent else { throw CancellationError() }
    }

    private static func mapInvalidation(_ error: Error) -> Error {
        guard let readerError = error as? NFCReaderError else { return error }
        switch readerError.code {
        case .readerSessionInvalidationErrorUserCanceled:
            return IrohaPeerNfcCoreNFCErrorV1.cancelled
        default:
            return error
        }
    }

    private static func isRetryableContactError(_ error: Error) -> Bool {
        guard let readerError = error as? NFCReaderError else { return false }
        switch readerError.code {
        case .readerTransceiveErrorTagConnectionLost,
             .readerTransceiveErrorRetryExceeded,
             .readerTransceiveErrorTagResponseError,
             .readerTransceiveErrorTagNotConnected:
            return true
        default:
            return false
        }
    }
}
#endif
