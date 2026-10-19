import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

final class IrohaPeerNfcPersistenceReplayV1Tests: XCTestCase {
    func testDurabilityTimeoutsKeepOneContextBoundWorkerWithoutWaiterBuildup() async throws {
        let gate = IrohaPeerNfcDurabilityLeaseGateV1()
        let latch = PersistenceLatch()
        let invocations = ReplayCounter()
        let pending = try IrohaPeerNfcPendingDurabilityV1(context: 7, leaseGate: gate) {
            invocations.increment()
            await latch.wait()
            return 42
        }
        defer { pending.invalidate() }
        for _ in 0..<4 {
            do {
                _ = try await pending.value(for: 7, timeoutNanoseconds: 10_000_000)
                XCTFail("the callback is still pending")
            } catch IrohaPeerNfcDurabilityDeadlineErrorV1.timedOut {}
            XCTAssertEqual(pending.pendingWaiterCount, 0)
            XCTAssertTrue(gate.isOccupied)
        }
        do {
            _ = try await pending.value(for: 8, timeoutNanoseconds: 10_000_000)
            XCTFail("a pending worker cannot be retargeted")
        } catch IrohaPeerNfcErrorV1.continuityMismatch {}
        XCTAssertEqual(invocations.value, 1)
        await latch.signal()
        let first = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
        let replay = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
        XCTAssertEqual(first, 42)
        XCTAssertEqual(replay, 42)
        XCTAssertEqual(invocations.value, 1)
        XCTAssertEqual(pending.pendingWaiterCount, 0)
        XCTAssertFalse(gate.isOccupied)
    }

    func testCancelledAndRetiredWaitCannotInstallLateDurabilityResult() async throws {
        let gate = IrohaPeerNfcDurabilityLeaseGateV1()
        let latch = PersistenceLatch()
        let entered = expectation(description: "durability entered")
        let pending = try IrohaPeerNfcPendingDurabilityV1(context: 7, leaseGate: gate) {
            entered.fulfill()
            await latch.wait()
            return 42
        }
        let wait = Task { try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000) }
        await fulfillment(of: [entered], timeout: 1)
        wait.cancel()
        do {
            _ = try await wait.value
            XCTFail("a cancelled APDU cannot install")
        } catch is CancellationError {}
        pending.invalidate()
        XCTAssertEqual(pending.pendingWaiterCount, 0)
        XCTAssertTrue(gate.isOccupied)
        XCTAssertThrowsError(try IrohaPeerNfcPendingDurabilityV1(context: 8, leaseGate: gate) { 8 }) {
            XCTAssertEqual($0 as? IrohaPeerNfcDurabilityDeadlineErrorV1, .saturated)
        }
        await latch.signal()
        for _ in 0..<1_000 {
            if !gate.isOccupied { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertFalse(gate.isOccupied)
        do {
            _ = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
            XCTFail("a retired runtime cannot collect a late result")
        } catch is CancellationError {}
    }

    func testDurableFailureIsCachedWithoutRepeatingApplicationWork() async throws {
        let invocations = ReplayCounter()
        let pending = try IrohaPeerNfcPendingDurabilityV1<Int, Int>(
            context: 7, leaseGate: IrohaPeerNfcDurabilityLeaseGateV1()) {
                invocations.increment()
                throw IrohaPeerNfcErrorV1.acknowledgementNotDurable
            }
        defer { pending.invalidate() }
        for _ in 0..<3 {
            do {
                _ = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
                XCTFail("application failure must remain a failure")
            } catch IrohaPeerNfcErrorV1.acknowledgementNotDurable {}
        }
        XCTAssertEqual(invocations.value, 1)
        XCTAssertEqual(pending.pendingWaiterCount, 0)
    }

    func testCompletionAndTimeoutRaceAlwaysRetainsExactResultForReplay() async throws {
        for _ in 0..<20 {
            let pending = try IrohaPeerNfcPendingDurabilityV1(
                context: 7, leaseGate: IrohaPeerNfcDurabilityLeaseGateV1()) {
                    try await Task.sleep(nanoseconds: 1_000_000)
                    return 42
                }
            do {
                let value = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000)
                XCTAssertEqual(value, 42)
            } catch IrohaPeerNfcDurabilityDeadlineErrorV1.timedOut {}
            let value = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
            XCTAssertEqual(value, 42)
            XCTAssertEqual(pending.pendingWaiterCount, 0)
            pending.invalidate()
        }
    }

    func testSlowAdmissionAndCommitResumeSamePeerWithoutAnotherApproval() async throws {
        let card = try PersistenceReplayCard(beginFailures: 2, commitFailures: 1)
        let checkpoint = IrohaPeerNfcCheckpointBoxV1(nil)
        let payment = try irohaPeerWalletExchangeMessageV1(kind: .payment, payload: Data([3]))
        let approvals = ReplayCounter()
        let sleeps = ReplayCounter()
        let result = try await irohaPeerNfcWithPersistenceReplayV1(
            hasDurableCheckpoint: { checkpoint.load() != nil },
            sleep: { nanoseconds in
                XCTAssertEqual(nanoseconds, 300_000_000)
                sleeps.increment()
            },
            operation: {
                try await IrohaPeerNfcReaderExchangeV1.run(
                    restoredCheckpoint: checkpoint.load(),
                    profilePolicy: .init(profile: .kagemushaWalletV1),
                    transceive: { try await card.transceive($0) },
                    loadOrCreateDurableCheckpoint: { info, request in
                        approvals.increment()
                        let created = try IrohaPeerNfcSenderCheckpointV1(
                            sessionID: info.identity.sessionID,
                            receiveRequest: request.encoded, payment: payment.encoded)
                        checkpoint.store(created.encoded)
                        return created
                    },
                    updateDurableCheckpoint: { checkpoint.store($0) }
                )
            }
        )
        XCTAssertEqual(approvals.value, 1)
        XCTAssertEqual(sleeps.value, 3)
        XCTAssertEqual(result.checkpoint.payment, payment)
        XCTAssertNotNil(result.checkpoint.durableAcknowledgement)
        let commands = await card.commands
        XCTAssertEqual(commands.filter { $0.operation == .readRequest }.count, 1)
        XCTAssertEqual(commands.filter { $0.operation == .beginPayment }.count, 3)
        XCTAssertEqual(commands.filter { $0.operation == .commit }.count, 2)
        let commits = await card.commits
        XCTAssertEqual(commits, 1)
    }

    func testPermanentPersistenceFailureStopsAfterTwelveAttempts() async {
        let attempts = ReplayCounter()
        do {
            let _: Int = try await irohaPeerNfcWithPersistenceReplayV1(
                hasDurableCheckpoint: { true }, sleep: { _ in }, operation: {
                    attempts.increment()
                    throw IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: .commit)
                })
            XCTFail("a permanent failure must terminate")
        } catch IrohaPeerNfcErrorV1.peerPersistenceFailure(let operation) {
            XCTAssertEqual(operation, .commit)
        } catch { XCTFail("unexpected error: \(error)") }
        XCTAssertEqual(attempts.value, 12)
    }

    func testUncheckpointedAndNonDurabilityFailuresAreNeverReplayed() async {
        for (durable, error) in [
            (false, IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: .commit)),
            (true, IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: .readRequest)),
            (true, IrohaPeerNfcErrorV1.continuityMismatch),
        ] {
            let attempts = ReplayCounter()
            do {
                let _: Int = try await irohaPeerNfcWithPersistenceReplayV1(
                    hasDurableCheckpoint: { durable },
                    sleep: { _ in XCTFail("must not delay an unrecoverable error") },
                    operation: { attempts.increment(); throw error })
                XCTFail("the original error must terminate")
            } catch let observed as IrohaPeerNfcErrorV1 {
                XCTAssertEqual(observed, error)
            } catch { XCTFail("unexpected error: \(error)") }
            XCTAssertEqual(attempts.value, 1)
        }
    }

    func testCancellationDuringReplayDelayCannotIssueAnotherCommand() async {
        let attempts = ReplayCounter()
        let task = Task {
            let _: Int = try await irohaPeerNfcWithPersistenceReplayV1(
                hasDurableCheckpoint: { true },
                sleep: { _ in withUnsafeCurrentTask { $0?.cancel() } },
                operation: {
                    attempts.increment()
                    throw IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: .commit)
                })
        }
        do {
            try await task.value
            XCTFail("cancelled replay must terminate")
        } catch is CancellationError {} catch { XCTFail("unexpected error: \(error)") }
        XCTAssertEqual(attempts.value, 1)
    }
}

/// One-shot test facade keeps the existing lease regression cases pointed at
/// the same pending-worker implementation used by the live card runtime.
func irohaPeerNfcWithDurabilityDeadlineV1<Value: Sendable>(
    timeoutNanoseconds: UInt64,
    leaseGate: IrohaPeerNfcDurabilityLeaseGateV1 = .shared,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value {
    try Task.checkCancellation()
    let pending = try IrohaPeerNfcPendingDurabilityV1(
        context: UInt8(0), leaseGate: leaseGate, operation: operation)
    defer { pending.invalidate() }
    return try await pending.value(for: 0, timeoutNanoseconds: timeoutNanoseconds)
}

private actor PersistenceLatch {
    private var signalled = false
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async {
        if signalled { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func signal() {
        signalled = true
        continuation?.resume()
        continuation = nil
    }
}

private final class ReplayCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    func increment() { lock.lock(); count += 1; lock.unlock() }
}

/// A single, continuously connected endpoint. Storage-failure replies delay
/// admission/commit without replacing its Request or committed Payment.
private actor PersistenceReplayCard {
    private var endpoint: IrohaPeerNfcCardEndpointV1
    private let request: IrohaPeerWireMessageV1
    private let credited: IrohaPeerWireMessageV1
    private var beginFailures: Int
    private var commitFailures: Int
    private(set) var commands: [IrohaPeerNfcCommandV1] = []
    private(set) var commits = 0

    init(beginFailures: Int, commitFailures: Int) throws {
        request = try irohaPeerWalletExchangeMessageV1(kind: .request, payload: Data([2]))
        endpoint = IrohaPeerNfcCardEndpointV1(receiver: try IrohaPeerNfcReceiverSessionV1(
            sessionID: Data(repeating: 7, count: 16), receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1)))
        credited = try irohaPeerWalletExchangeMessageV1(kind: .credited, payload: Data([4]))
        self.beginFailures = beginFailures
        self.commitFailures = commitFailures
    }

    func transceive(_ command: IrohaPeerNfcCommandV1) throws -> IrohaPeerNfcAPDUResponseV1 {
        commands.append(command)
        if case .beginPayment = command, beginFailures > 0 {
            beginFailures -= 1
            return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
        }
        if case .commit = command, commitFailures > 0 {
            commitFailures -= 1
            return IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure)
        }
        let credited = self.credited
        let step = endpoint.process(
            apdu: try IrohaPeerNfcAPDUCodecV1.encode(command),
            admitPayment: { try IrohaPeerNfcDurablePaymentAdmissionV1(context: $0) },
            durableCommit: {
                try IrohaPeerNfcDurableAcknowledgementV1(context: $0, acknowledgement: credited.encoded)
            })
        if case .commit = command, step.statusWord == .success { commits += 1 }
        return step
    }
}
