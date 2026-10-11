import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

private final class IrohaPeerNfcReaderGateTestStateV1: @unchecked Sendable {
    private let lock = NSLock()
    private var gate = IrohaPeerNfcReaderOperationGateV1()
    private var staleInstalls = 0

    func begin() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return gate.beginOperation()
    }

    func restart(after epoch: UInt64) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        _ = gate.finishOperation(capturedEpoch: epoch)
        return gate.beginOperation()
    }

    func validate(_ epoch: UInt64) throws {
        try Task.checkCancellation()
        lock.lock()
        let current = gate.mayMutate(capturedEpoch: epoch)
        lock.unlock()
        guard current else { throw CancellationError() }
    }

    func recordInstall() {
        lock.lock(); staleInstalls += 1; lock.unlock()
    }

    var installCount: Int {
        lock.lock(); defer { lock.unlock() }
        return staleInstalls
    }
}

private actor IrohaPeerNfcReaderGateAsyncLatchV1 {
    private var continuation: CheckedContinuation<Void, Never>?
    private var signalled = false

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

private final class IrohaPeerNfcDurabilityProbeV1: @unchecked Sendable {
    private let lock = NSLock()
    private var invocations = 0
    private var installs = 0

    func recordInvocation() {
        lock.lock(); invocations += 1; lock.unlock()
    }

    func recordInstall() {
        lock.lock(); installs += 1; lock.unlock()
    }

    var snapshot: (invocations: Int, installs: Int) {
        lock.lock(); defer { lock.unlock() }
        return (invocations, installs)
    }
}

final class IrohaPeerNfcProgressPublicationPolicyV1Tests: XCTestCase {
    func testRedetectionsIncrementAttemptWhileValueStagesRemainSingleShot() {
        var policy = IrohaPeerNfcProgressPublicationPolicyV1()

        XCTAssertEqual(policy.attempt(for: .phase1SessionActive), 1)
        XCTAssertEqual(policy.attempt(for: .tagDetected), 1)
        XCTAssertEqual(policy.attempt(for: .tagDetected), 2)
        XCTAssertEqual(policy.attempt(for: .requestRead), 2)
        XCTAssertNil(policy.attempt(for: .requestRead))
        XCTAssertEqual(policy.attempt(for: .paymentCommitted), 2)
        XCTAssertNil(policy.attempt(for: .paymentCommitted))
        XCTAssertEqual(policy.attempt(for: .tagDetected), 3)
    }

    func testInvalidationDrainsOldProgressAndSuppressesItAfterRestart() {
        let eventsLock = NSLock()
        var oldStages: [IrohaPeerNfcProgressStageV1] = []
        var newStages: [IrohaPeerNfcProgressStageV1] = []
        let oldHandlerEntered = DispatchSemaphore(value: 0)
        let releaseOldHandler = DispatchSemaphore(value: 0)
        let oldEmissionFinished = DispatchSemaphore(value: 0)
        let invalidationStarted = DispatchSemaphore(value: 0)
        let invalidationFinished = DispatchSemaphore(value: 0)
        let oldReporter = IrohaPeerNfcReaderProgressReporterV1 { event in
            eventsLock.lock()
            oldStages.append(event.stage)
            eventsLock.unlock()
            oldHandlerEntered.signal()
            releaseOldHandler.wait()
        }

        DispatchQueue.global().async {
            oldReporter.emit(.requestRead)
            oldEmissionFinished.signal()
        }
        XCTAssertEqual(oldHandlerEntered.wait(timeout: .now() + 1), .success)
        DispatchQueue.global().async {
            invalidationStarted.signal()
            oldReporter.invalidate()
            invalidationFinished.signal()
        }
        XCTAssertEqual(invalidationStarted.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            invalidationFinished.wait(timeout: .now() + 0.05),
            .timedOut,
            "invalidation must drain a callback already admitted by the old operation"
        )

        releaseOldHandler.signal()
        XCTAssertEqual(oldEmissionFinished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(invalidationFinished.wait(timeout: .now() + 1), .success)

        let newReporter = IrohaPeerNfcReaderProgressReporterV1 { event in
            eventsLock.lock()
            newStages.append(event.stage)
            eventsLock.unlock()
        }
        oldReporter.emit(.paymentCommitted)
        newReporter.emit(.paymentCommitted)

        eventsLock.lock()
        let oldSnapshot = oldStages
        let newSnapshot = newStages
        eventsLock.unlock()
        XCTAssertEqual(oldSnapshot, [.requestRead])
        XCTAssertEqual(newSnapshot, [.paymentCommitted])
    }
}

final class IrohaPeerNfcRetryLimitsBoxV1Tests: XCTestCase {
    func testTransportRetryAtomicallyClampsChunksAndPreservesMessageLimit() {
        let box = IrohaPeerNfcRetryLimitsBoxV1(.default)

        XCTAssertEqual(box.load(), .default)
        XCTAssertTrue(box.downgradeForRetry())
        XCTAssertEqual(
            box.load(),
            IrohaPeerNfcLimitsV1(
                maximumMessageBytes: IrohaPeerNfcV1.maximumMessageBytes,
                maximumReadChunkBytes: 240,
                maximumWriteChunkBytes: 203
            )
        )
        XCTAssertFalse(box.downgradeForRetry())

        let asymmetric = IrohaPeerNfcRetryLimitsBoxV1(
            IrohaPeerNfcLimitsV1(
                maximumMessageBytes: 4_096,
                maximumReadChunkBytes: 128,
                maximumWriteChunkBytes: 512
            )
        )
        XCTAssertTrue(asymmetric.downgradeForRetry())
        XCTAssertEqual(
            asymmetric.load(),
            IrohaPeerNfcLimitsV1(
                maximumMessageBytes: 4_096,
                maximumReadChunkBytes: 128,
                maximumWriteChunkBytes: 203
            )
        )
    }

    func testInvalidCommandAPDURoutesThroughPortableSameSessionRetry() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot.appendingPathComponent(
            "Sources/IrohaSwiftMobileTransports/IrohaPeerNfcCoreNFCV1.swift"
        )
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let startupRetryStart = try XCTUnwrap(source.range(
            of: "if IrohaPeerNfcStartupResponseRetryPolicyV1"
        ))
        let catchStart = try XCTUnwrap(source.range(
            of: "catch let error as IrohaPeerNfcCoreNFCErrorV1",
            range: startupRetryStart.upperBound..<source.endIndex
        ))
        let genericCatch = try XCTUnwrap(source.range(
            of: "} catch {",
            range: catchStart.upperBound..<source.endIndex
        ))
        let typedCatch = source[catchStart.lowerBound..<genericCatch.lowerBound]

        XCTAssertTrue(typedCatch.contains("case .invalidCommandAPDU = error"))
        XCTAssertTrue(typedCatch.contains("retryLimitsBox.downgradeForRetry()"))
        XCTAssertTrue(typedCatch.contains("IrohaPeerNfcRetryableTransportErrorV1"))
        XCTAssertTrue(typedCatch.contains("throw error"))
        XCTAssertTrue(source.contains(
            "catch is IrohaPeerNfcRetryableTransportErrorV1"
        ))
        XCTAssertTrue(source.contains(
            ".readerTransceiveErrorTagResponseError"
        ))
        XCTAssertTrue(source.contains(
            "IrohaPeerNfcStartupResponseRetryPolicyV1"
        ))
        XCTAssertTrue(source.contains(
            "Application preparation and checkpoint persistence"
        ))
    }
}

final class IrohaPeerNfcReaderOperationGateV1Tests: XCTestCase {
    func testCancelDuringDurableCallbackCannotInstallIntoRestart() async throws {
        let state = IrohaPeerNfcReaderGateTestStateV1()
        let firstEpoch = state.begin()
        let durableEntered = expectation(description: "old durable callback entered")
        let releaseDurable = IrohaPeerNfcReaderGateAsyncLatchV1()

        let oldTask = Task { () throws -> String in
            let value = try await irohaPeerNfcGuardedAwaitV1(
                validate: { try state.validate(firstEpoch) },
                operation: {
                    durableEntered.fulfill()
                    await releaseDurable.wait()
                    return "old"
                }
            )
            state.recordInstall()
            return value
        }

        await fulfillment(of: [durableEntered], timeout: 1)
        oldTask.cancel()
        let secondEpoch = state.restart(after: firstEpoch)
        await releaseDurable.signal()
        do {
            _ = try await oldTask.value
            XCTFail("cancelled operation installed a stale durable value")
        } catch is CancellationError {
            // Expected terminal suppression.
        }
        XCTAssertEqual(state.installCount, 0)

        let restarted = try await irohaPeerNfcGuardedAwaitV1(
            validate: { try state.validate(secondEpoch) },
            operation: { "new" }
        )
        XCTAssertEqual(restarted, "new")
    }

    func testLatePriorOperationCallbackCannotReleaseNewConnect() {
        var gate = IrohaPeerNfcReaderOperationGateV1()
        let firstEpoch = gate.beginOperation()
        XCTAssertTrue(gate.beginConnect(capturedEpoch: firstEpoch))
        XCTAssertTrue(gate.finishOperation(capturedEpoch: firstEpoch))

        let secondEpoch = gate.beginOperation()
        XCTAssertTrue(gate.beginConnect(capturedEpoch: secondEpoch))

        XCTAssertFalse(gate.finishConnect(capturedEpoch: firstEpoch))
        XCTAssertTrue(gate.connectInFlight)
        XCTAssertTrue(gate.finishConnect(capturedEpoch: secondEpoch))
        XCTAssertFalse(gate.connectInFlight)
    }

    func testDuplicateDetectionCannotStartConcurrentConnect() {
        var gate = IrohaPeerNfcReaderOperationGateV1()
        let epoch = gate.beginOperation()

        XCTAssertTrue(gate.beginConnect(capturedEpoch: epoch))
        XCTAssertFalse(gate.beginConnect(capturedEpoch: epoch))
        XCTAssertTrue(gate.connectInFlight)

        XCTAssertTrue(gate.finishConnect(capturedEpoch: epoch))
        XCTAssertFalse(gate.connectInFlight)
        XCTAssertTrue(gate.beginConnect(capturedEpoch: epoch))
    }
}

final class IrohaPeerNfcReaderPlatformCallGateV1Tests: XCTestCase {
    func testCancelDrainsAdmittedPlatformCallAndSuppressesOldCallsAfterRestart() {
        let oldGate = IrohaPeerNfcReaderPlatformCallGateV1()
        let callEntered = DispatchSemaphore(value: 0)
        let releaseCall = DispatchSemaphore(value: 0)
        let callFinished = DispatchSemaphore(value: 0)
        let invalidationStarted = DispatchSemaphore(value: 0)
        let invalidationFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            XCTAssertTrue(oldGate.performIfActive {
                callEntered.signal()
                releaseCall.wait()
            })
            callFinished.signal()
        }
        XCTAssertEqual(callEntered.wait(timeout: .now() + 1), .success)
        DispatchQueue.global().async {
            invalidationStarted.signal()
            oldGate.invalidate()
            invalidationFinished.signal()
        }
        XCTAssertEqual(invalidationStarted.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            invalidationFinished.wait(timeout: .now() + 0.05),
            .timedOut,
            "cancel must drain a synchronous CoreNFC call already admitted"
        )

        releaseCall.signal()
        XCTAssertEqual(callFinished.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(invalidationFinished.wait(timeout: .now() + 1), .success)
        XCTAssertFalse(oldGate.performIfActive {
            XCTFail("the old operation performed a post-cancel platform call")
        })

        let restartedGate = IrohaPeerNfcReaderPlatformCallGateV1()
        var restartedCalls = 0
        XCTAssertTrue(restartedGate.performIfActive { restartedCalls += 1 })
        XCTAssertEqual(restartedCalls, 1)
    }

    func testPlatformCallbackMayReentrantlyInvalidateWithoutDeadlock() {
        let gate = IrohaPeerNfcReaderPlatformCallGateV1()

        XCTAssertTrue(gate.performIfActive { gate.invalidate() })
        XCTAssertFalse(gate.performIfActive {
            XCTFail("reentrant invalidation did not close the gate")
        })
    }

    func testReaderRoutesBeginConnectAndPollingThroughPlatformGate() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: packageRoot.appendingPathComponent(
                "Sources/IrohaSwiftMobileTransports/IrohaPeerNfcCoreNFCV1.swift"
            ),
            encoding: .utf8
        )

        func assertEveryCallIsGuarded(
            _ call: String,
            file: StaticString = #filePath,
            line: UInt = #line
        ) {
            var searchStart = source.startIndex
            var count = 0
            while let range = source.range(
                of: call,
                range: searchStart..<source.endIndex
            ) {
                count += 1
                let distance = source.distance(
                    from: source.startIndex,
                    to: range.lowerBound
                )
                let prefixStart = source.index(
                    range.lowerBound,
                    offsetBy: -min(distance, 240)
                )
                let prefix = source[prefixStart..<range.lowerBound]
                XCTAssertTrue(
                    prefix.contains("performIfActive"),
                    "unguarded CoreNFC call: \(call)",
                    file: file,
                    line: line
                )
                searchStart = range.upperBound
            }
            XCTAssertGreaterThan(count, 0, file: file, line: line)
        }

        assertEveryCallIsGuarded("readerSession.begin()")
        assertEveryCallIsGuarded("session.connect(to: tag)")
        assertEveryCallIsGuarded("session.restartPolling()")
        XCTAssertTrue(source.contains("platformCallGate?.invalidate()\n        progressReporter?.invalidate()"))
    }
}

final class IrohaPeerNfcTerminalEventGateV1Tests: XCTestCase {
    func testStopCancellationInvalidationAndConfirmationPublishEndedOnce() {
        var gate = IrohaPeerNfcTerminalEventGateV1()

        XCTAssertTrue(gate.claimEndedPublication(), "stop owns the terminal event")
        XCTAssertFalse(gate.claimEndedPublication(), "cancellation is deduplicated")
        XCTAssertFalse(gate.claimEndedPublication(), "invalidation is deduplicated")
        XCTAssertFalse(gate.claimEndedPublication(), "confirmation is deduplicated")
        XCTAssertTrue(gate.didPublish)
    }

    func testTypedFailurePrecedesAndDoesNotDuplicateEnded() {
        var gate = IrohaPeerNfcTerminalEventGateV1()

        XCTAssertTrue(gate.claimFailurePublication())
        XCTAssertFalse(gate.claimFailurePublication())
        XCTAssertTrue(gate.claimEndedPublication())
        XCTAssertFalse(gate.claimFailurePublication())
        XCTAssertFalse(gate.claimEndedPublication())
    }
}

final class IrohaPeerNfcRetryGateV1Tests: XCTestCase {
    func testOnlyInitialSelectNotReadyResponsesAreRetryable() {
        for status in [
            IrohaPeerNfcStatusWordV1.notFound,
            .conditionsNotSatisfied,
        ] {
            XCTAssertTrue(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
                IrohaPeerNfcAPDUResponseV1(statusWord: status),
                for: .selectApplication
            ))
            XCTAssertFalse(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
                IrohaPeerNfcAPDUResponseV1(statusWord: status),
                for: .getInfo
            ))
        }
        XCTAssertFalse(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
            IrohaPeerNfcAPDUResponseV1(statusWord: .success),
            for: .selectApplication
        ))
        XCTAssertFalse(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
            IrohaPeerNfcAPDUResponseV1(statusWord: .storageFailure),
            for: .selectApplication
        ))
    }

    func testPublicRetryPolicyBoundsAreFinite() {
        XCTAssertTrue(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 1,
            redetectionTimeoutMilliseconds: 1
        ))
        XCTAssertTrue(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 10,
            redetectionTimeoutMilliseconds: 30_000
        ))
        XCTAssertFalse(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 0,
            redetectionTimeoutMilliseconds: 1
        ))
        XCTAssertFalse(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 11,
            redetectionTimeoutMilliseconds: 1
        ))
        XCTAssertFalse(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 1,
            redetectionTimeoutMilliseconds: 0
        ))
        XCTAssertFalse(IrohaPeerNfcReaderRetryPolicyV1.areValid(
            maximumContactAttempts: 1,
            redetectionTimeoutMilliseconds: 30_001
        ))
    }

    func testDuplicateDetectionDoesNotConsumeAnotherAttempt() {
        let retryGate = IrohaPeerNfcRetryGateV1(.init(
            maximumContactAttempts: 2,
            redetectionTimeoutMilliseconds: 1_000
        ))
        var operationGate = IrohaPeerNfcReaderOperationGateV1()
        let epoch = operationGate.beginOperation()

        XCTAssertTrue(retryGate.claimContactAttempt(
            operationGate: &operationGate,
            capturedEpoch: epoch
        ))
        XCTAssertFalse(retryGate.claimContactAttempt(
            operationGate: &operationGate,
            capturedEpoch: epoch
        ))
        XCTAssertTrue(retryGate.mayRedetect())
        XCTAssertTrue(operationGate.finishConnect(capturedEpoch: epoch))
        XCTAssertTrue(retryGate.claimContactAttempt(
            operationGate: &operationGate,
            capturedEpoch: epoch
        ))
        XCTAssertFalse(retryGate.mayRedetect())
    }

    func testThreeAttemptsAreBoundedAndRedetectionClosesAfterThird() {
        let gate = IrohaPeerNfcRetryGateV1(.init(
            maximumContactAttempts: 3,
            redetectionTimeoutMilliseconds: 3_000
        ))

        XCTAssertTrue(gate.beginContactAttempt())
        XCTAssertTrue(gate.mayRedetect())
        XCTAssertTrue(gate.beginContactAttempt())
        XCTAssertTrue(gate.mayRedetect())
        XCTAssertTrue(gate.beginContactAttempt())
        XCTAssertFalse(gate.mayRedetect())
        XCTAssertFalse(gate.beginContactAttempt())
        XCTAssertEqual(gate.redetectionTimeoutNanoseconds, 3_000_000_000)
    }
}

final class IrohaPeerNfcStartupRecoveryV1Tests: XCTestCase {
    func testFirstSelectNotReadyThenOneOperationCompletesWithOneDurableDebit()
        async throws {
        for startupStatus in [
            IrohaPeerNfcStatusWordV1.notFound,
            .conditionsNotSatisfied,
        ] {
            let request = try irohaPeerWalletExchangeMessageV1(kind: .request, payload: Data(repeating: 0x31, count: 96))
            let payment = try irohaPeerWalletExchangeMessageV1(kind: .payment, payload: Data(repeating: 0x32, count: 192))
            let acknowledgement = try irohaPeerWalletExchangeMessageV1(kind: .credited, payload: Data(repeating: 0x33, count: 80))
            let limits = IrohaPeerNfcLimitsV1(
                maximumReadChunkBytes: 240,
                maximumWriteChunkBytes: 203
            )
            let harness = try IrohaPeerNfcStartupRecoveryHarnessV1(
                startupStatus: startupStatus,
                sessionID: Data((1...IrohaPeerNfcV1.sessionIDBytes).map(UInt8.init)),
                request: request,
                payment: payment,
                acknowledgement: acknowledgement,
                limits: limits
            )
            let retryGate = IrohaPeerNfcRetryGateV1(.init(
                maximumContactAttempts: 3,
                redetectionTimeoutMilliseconds: 3_000
            ))
            var result: IrohaPeerNfcReaderExchangeResultV1?

            while retryGate.beginContactAttempt() {
                do {
                    result = try await IrohaPeerNfcReaderExchangeV1.run(
                        restoredCheckpoint: await harness.durableCheckpoint(),
                        profilePolicy: .init(profile: .kagemushaWalletV1),
                        limits: limits,
                        transceive: { command in
                            let response = try await harness.transceive(command)
                            if IrohaPeerNfcStartupResponseRetryPolicyV1
                                .shouldRetry(response, for: command) {
                                throw IrohaPeerNfcStartupRecoveryFailureV1.retryContact
                            }
                            return response
                        },
                        loadOrCreateDurableCheckpoint: { info, receivedRequest in
                            try await harness.loadOrCreateCheckpoint(
                                info: info,
                                request: receivedRequest
                            )
                        },
                        updateDurableCheckpoint: { checkpoint in
                            await harness.updateCheckpoint(checkpoint)
                        }
                    )
                    break
                } catch IrohaPeerNfcStartupRecoveryFailureV1.retryContact {
                    XCTAssertTrue(retryGate.mayRedetect())
                }
            }

            let completed = try XCTUnwrap(result)
            let snapshot = await harness.snapshot()
            XCTAssertEqual(completed.acknowledgement, acknowledgement)
            XCTAssertEqual(completed.checkpoint.durableAcknowledgement, acknowledgement)
            XCTAssertEqual(snapshot.selectCount, 2)
            XCTAssertEqual(snapshot.checkpointCreationCount, 1)
            XCTAssertEqual(snapshot.durableDebitCount, 1)
            XCTAssertEqual(snapshot.receiverDurableCommitCount, 1)
            XCTAssertEqual(snapshot.phase, .complete)
        }
    }
}

private enum IrohaPeerNfcStartupRecoveryFailureV1: Error {
    case retryContact
}

private actor IrohaPeerNfcStartupRecoveryHarnessV1 {
    struct Snapshot: Sendable {
        let selectCount: Int
        let checkpointCreationCount: Int
        let durableDebitCount: Int
        let receiverDurableCommitCount: Int
        let phase: IrohaPeerNfcPhaseV1
    }

    private let startupStatus: IrohaPeerNfcStatusWordV1
    private var receiver: IrohaPeerNfcReceiverSessionV1
    private let payment: IrohaPeerWireMessageV1
    private let acknowledgement: IrohaPeerWireMessageV1
    private let limits: IrohaPeerNfcLimitsV1
    private var checkpoint: Data?
    private var selectCount = 0
    private var checkpointCreationCount = 0
    private var durableDebitCount = 0
    private var receiverDurableCommitCount = 0

    init(
        startupStatus: IrohaPeerNfcStatusWordV1,
        sessionID: Data,
        request: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1,
        acknowledgement: IrohaPeerWireMessageV1,
        limits: IrohaPeerNfcLimitsV1
    ) throws {
        self.startupStatus = startupStatus
        receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits
        )
        self.payment = payment
        self.acknowledgement = acknowledgement
        self.limits = limits
    }

    func transceive(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcAPDUResponseV1 {
        if case .selectApplication = command {
            selectCount += 1
            if selectCount == 1 {
                return IrohaPeerNfcAPDUResponseV1(statusWord: startupStatus)
            }
        }
        if case .beginPayment = command {
            switch try receiver.preparePaymentAdmission(command) {
            case .alreadyAdmitted:
                break
            case .requiresDurableAdmission(let context):
                try receiver.installPaymentAdmission(
                    IrohaPeerNfcDurablePaymentAdmissionV1(context: context)
                )
            }
            return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
        }
        if case .commit = command {
            switch try receiver.prepareCommit(command) {
            case .alreadyCommitted:
                break
            case .requiresDurableCommit(let context):
                receiverDurableCommitCount += 1
                try receiver.installDurableAcknowledgement(
                    IrohaPeerNfcDurableAcknowledgementV1(
                        context: context,
                        acknowledgement: acknowledgement.encoded,
                        limits: limits
                    )
                )
            }
            return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
        }
        return IrohaPeerNfcAPDUResponseV1(
            data: try receiver.handle(command),
            statusWord: .success
        )
    }

    func loadOrCreateCheckpoint(
        info: IrohaPeerNfcInfoV1,
        request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcSenderCheckpointV1 {
        if let checkpoint {
            return try IrohaPeerNfcSenderCheckpointV1.decode(
                checkpoint,
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits
            )
        }
        checkpointCreationCount += 1
        let created = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: info.identity.sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits
        )
        checkpoint = created.encoded
        durableDebitCount += 1
        return created
    }

    func updateCheckpoint(_ checkpoint: Data) {
        self.checkpoint = Data(checkpoint)
    }

    func durableCheckpoint() -> Data? {
        checkpoint.map { Data($0) }
    }

    func snapshot() -> Snapshot {
        Snapshot(
            selectCount: selectCount,
            checkpointCreationCount: checkpointCreationCount,
            durableDebitCount: durableDebitCount,
            receiverDurableCommitCount: receiverDurableCommitCount,
            phase: receiver.phase
        )
    }
}

final class IrohaPeerNfcDurabilityLeaseV1Tests: XCTestCase {
    func testRepeatedRetapsDuringHungTimedOutCallbackRunOneInvocation() async {
        let gate = IrohaPeerNfcDurabilityLeaseGateV1()
        let latch = IrohaPeerNfcReaderGateAsyncLatchV1()
        let probe = IrohaPeerNfcDurabilityProbeV1()
        let entered = expectation(description: "durability callback entered")
        let returned = expectation(description: "deadline returned")

        let first = Task { () throws -> String in
            defer { returned.fulfill() }
            let value = try await irohaPeerNfcWithDurabilityDeadlineV1(
                timeoutNanoseconds: 10_000_000,
                leaseGate: gate,
                operation: {
                    probe.recordInvocation()
                    entered.fulfill()
                    await latch.wait()
                    return "late"
                }
            )
            probe.recordInstall()
            return value
        }

        await fulfillment(of: [entered], timeout: 1)
        await fulfillment(of: [returned], timeout: 0.5)
        do {
            _ = try await first.value
            XCTFail("hung callback must return a deadline failure")
        } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
            XCTAssertEqual(failure, .timedOut)
        } catch {
            XCTFail("unexpected failure: \(error)")
        }
        XCTAssertTrue(gate.isOccupied)
        XCTAssertEqual(probe.snapshot.invocations, 1)
        XCTAssertEqual(probe.snapshot.installs, 0)

        for _ in 0..<32 {
            do {
                _ = try await irohaPeerNfcWithDurabilityDeadlineV1(
                    timeoutNanoseconds: 10_000_000,
                    leaseGate: gate,
                    operation: {
                        probe.recordInvocation()
                        return "must not start"
                    }
                )
                XCTFail("occupied worker must reject without queueing")
            } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
                XCTAssertEqual(failure, .saturated)
            } catch {
                XCTFail("unexpected failure: \(error)")
            }
        }
        XCTAssertEqual(probe.snapshot.invocations, 1)
        XCTAssertEqual(probe.snapshot.installs, 0)
        await latch.signal()
        let didReleaseAfterTimeout = await waitUntilReleased(gate)
        XCTAssertTrue(didReleaseAfterTimeout)
        XCTAssertEqual(probe.snapshot.installs, 0)
    }

    func testLateCompletionReleasesLeaseAndExactRetryCanInstall() async throws {
        let gate = IrohaPeerNfcDurabilityLeaseGateV1()
        let latch = IrohaPeerNfcReaderGateAsyncLatchV1()
        let probe = IrohaPeerNfcDurabilityProbeV1()
        let entered = expectation(description: "old callback entered")

        let old = Task { () throws -> String in
            let value = try await irohaPeerNfcWithDurabilityDeadlineV1(
                timeoutNanoseconds: 10_000_000,
                leaseGate: gate,
                operation: {
                    probe.recordInvocation()
                    entered.fulfill()
                    await latch.wait()
                    return "old"
                }
            )
            probe.recordInstall()
            return value
        }
        await fulfillment(of: [entered], timeout: 1)
        do {
            _ = try await old.value
            XCTFail("old operation must time out")
        } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
            XCTAssertEqual(failure, .timedOut)
        }
        XCTAssertTrue(gate.isOccupied)

        await latch.signal()
        let didReleaseForRetry = await waitUntilReleased(gate)
        XCTAssertTrue(didReleaseForRetry)
        XCTAssertEqual(probe.snapshot.installs, 0)

        let retried = try await irohaPeerNfcWithDurabilityDeadlineV1(
            timeoutNanoseconds: 1_000_000_000,
            leaseGate: gate,
            operation: {
                probe.recordInvocation()
                return "exact retry"
            }
        )
        probe.recordInstall()
        XCTAssertEqual(retried, "exact retry")
        XCTAssertEqual(probe.snapshot.invocations, 2)
        XCTAssertEqual(probe.snapshot.installs, 1)
        XCTAssertFalse(gate.isOccupied)
    }

    func testCancellationReturnsButKeepsLeaseUntilCallbackActuallyCompletes() async {
        let gate = IrohaPeerNfcDurabilityLeaseGateV1()
        let latch = IrohaPeerNfcReaderGateAsyncLatchV1()
        let entered = expectation(description: "callback entered")
        let returned = expectation(description: "cancel returned")

        let task = Task { () throws -> String in
            defer { returned.fulfill() }
            return try await irohaPeerNfcWithDurabilityDeadlineV1(
                timeoutNanoseconds: 5_000_000_000,
                leaseGate: gate,
                operation: {
                    entered.fulfill()
                    await latch.wait()
                    return "late"
                }
            )
        }
        await fulfillment(of: [entered], timeout: 1)
        task.cancel()
        await fulfillment(of: [returned], timeout: 0.5)
        do {
            _ = try await task.value
            XCTFail("cancelled helper returned a value")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("unexpected failure: \(error)")
        }
        XCTAssertTrue(gate.isOccupied)
        do {
            _ = try await irohaPeerNfcWithDurabilityDeadlineV1(
                timeoutNanoseconds: 10_000_000,
                leaseGate: gate,
                operation: { "must not start" }
            )
            XCTFail("cancelled but running callback must retain the lease")
        } catch let failure as IrohaPeerNfcDurabilityDeadlineErrorV1 {
            XCTAssertEqual(failure, .saturated)
        } catch {
            XCTFail("unexpected failure: \(error)")
        }
        await latch.signal()
        let didReleaseAfterCancellation = await waitUntilReleased(gate)
        XCTAssertTrue(didReleaseAfterCancellation)
    }

    func testCardDurabilityCapSaturationAndLateInstallGuardRemainWired() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: packageRoot.appendingPathComponent(
                "Sources/IrohaSwiftMobileTransports/IrohaPeerNfcCoreNFCV1.swift"
            ),
            encoding: .utf8
        )

        XCTAssertTrue(source.contains(
            "maximumDurabilityTimeoutMilliseconds: UInt64 = 5_000"
        ))
        XCTAssertTrue(source.contains("case paymentAdmissionTimedOut"))
        XCTAssertTrue(source.contains("case durableCommitTimedOut"))
        XCTAssertTrue(source.contains("case durabilityWorkerSaturated"))
        XCTAssertTrue(source.contains(
            "leaseGate: IrohaPeerNfcDurabilityLeaseGateV1 = .shared"
        ))
        XCTAssertEqual(
            source.components(separatedBy: "leaseGate.release(lease)").count - 1,
            1,
            "timeout and cancellation paths must never release a running callback's lease"
        )
        XCTAssertGreaterThanOrEqual(
            source.components(separatedBy: "guard mayContinue(session) else {").count - 1,
            3
        )
    }

    private func waitUntilReleased(
        _ gate: IrohaPeerNfcDurabilityLeaseGateV1
    ) async -> Bool {
        for _ in 0..<200 where gate.isOccupied {
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return !gate.isOccupied
    }
}

final class IrohaPeerNfcCardRuntimeStartGateV1Tests: XCTestCase {
    func testStopDuringDelayedSessionCreationRejectsOrphanSession() {
        var gate = IrohaPeerNfcCardRuntimeStartGateV1()

        XCTAssertTrue(gate.beginStart())
        XCTAssertFalse(gate.requestStop(hasActiveSessionOrTask: false))
        XCTAssertTrue(gate.stopRequested)
        XCTAssertFalse(gate.finishSessionCreation())
        XCTAssertFalse(gate.startInFlight)
    }

    func testActiveEventTaskOwnsTerminalPublicationAfterStop() {
        var gate = IrohaPeerNfcCardRuntimeStartGateV1()

        XCTAssertTrue(gate.beginStart())
        XCTAssertTrue(gate.finishSessionCreation())
        XCTAssertFalse(gate.requestStop(hasActiveSessionOrTask: true))
    }

    func testCardRuntimePublishesEndedOnlyAfterEventLoopSettles() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot.appendingPathComponent(
            "Sources/IrohaSwiftMobileTransports/IrohaPeerNfcCoreNFCV1.swift"
        )
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let taskStart = try XCTUnwrap(source.range(of: "eventTask = Task"))
        let taskEnd = try XCTUnwrap(source.range(
            of: "lock.unlock()",
            range: taskStart.upperBound..<source.endIndex
        ))
        let taskBody = source[taskStart.lowerBound..<taskEnd.lowerBound]
        XCTAssertTrue(taskBody.contains("Task { [self] in"))
        XCTAssertFalse(taskBody.contains("[weak self]"))
        let runCall = try XCTUnwrap(source.range(
            of: "await run(session)",
            range: taskStart.upperBound..<source.endIndex
        ))
        let endedCall = try XCTUnwrap(source.range(
            of: "finishEventLoop()",
            range: runCall.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(runCall.lowerBound, endedCall.lowerBound)

        let runStart = try XCTUnwrap(source.range(
            of: "private func run(_ session: CardSession) async"
        ))
        let terminalHelper = try XCTUnwrap(source.range(
            of: "private func publishEndedOnce()",
            range: runStart.upperBound..<source.endIndex
        ))
        let eventLoop = source[runStart.lowerBound..<terminalHelper.lowerBound]
        XCTAssertFalse(eventLoop.contains("publishEndedOnce()"))
        XCTAssertTrue(eventLoop.contains("onEvent(.acknowledgementReady)"))
        XCTAssertTrue(eventLoop.contains("case .alreadyAdmitted:"))
        XCTAssertTrue(eventLoop.contains("case .alreadyCommitted:"))
        let alreadyAdmitted = try XCTUnwrap(eventLoop.range(of: "case .alreadyAdmitted:"))
        let admissionEvent = try XCTUnwrap(eventLoop.range(
            of: "onEvent(.paymentAdmitted)",
            range: alreadyAdmitted.upperBound..<eventLoop.endIndex
        ))
        let requiresAdmission = try XCTUnwrap(eventLoop.range(
            of: "case .requiresDurableAdmission",
            range: alreadyAdmitted.upperBound..<eventLoop.endIndex
        ))
        XCTAssertLessThan(admissionEvent.lowerBound, requiresAdmission.lowerBound)
        let alreadyCommitted = try XCTUnwrap(eventLoop.range(of: "case .alreadyCommitted:"))
        let acknowledgementEvent = try XCTUnwrap(eventLoop.range(
            of: "onEvent(.acknowledgementReady)",
            range: alreadyCommitted.upperBound..<eventLoop.endIndex
        ))
        let requiresCommit = try XCTUnwrap(eventLoop.range(
            of: "case .requiresDurableCommit",
            range: alreadyCommitted.upperBound..<eventLoop.endIndex
        ))
        XCTAssertLessThan(acknowledgementEvent.lowerBound, requiresCommit.lowerBound)
        XCTAssertTrue(eventLoop.contains("catch let error as CardSession.Error"))
        XCTAssertTrue(eventLoop.contains("error == .transmissionError"))
        XCTAssertTrue(eventLoop.contains("readerDeselected re-arms"))
    }
}
