import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

private final class WeakReference<Value: AnyObject> {
    weak var value: Value?

    init(_ value: Value?) {
        self.value = value
    }
}

final class IrohaPeerNearbyDeliveryBarrierV1Tests: XCTestCase {
    func testDefaultNearbyAdapterUsesExactThirtyTwoKiBRecordCeiling() {
        let configuration = IrohaPeerNearbyConnectionsConfigurationV1()
        XCTAssertEqual(configuration.maximumRecordBytes, 32 * 1_024)
        XCTAssertEqual(
            configuration.maximumRecordBytes,
            IrohaPeerNearbyV1.maximumMessageBytes + 64
        )
        XCTAssertEqual(configuration.maximumPendingSends, 8)
        XCTAssertEqual(configuration.maximumPendingWorkerActions, 64)
        XCTAssertEqual(configuration.maximumPendingCallbacks, 16)
        XCTAssertEqual(configuration.maximumPendingReceiveCallbacks, 4)
        // Hello, authentication, the receiver's ask, the Request and the Credited.
        XCTAssertEqual(configuration.maximumReceiveRecordsPerConnection, 5)
        XCTAssertEqual(
            IrohaPeerNearbyConnectionsConfigurationV1(operationTimeout: 300).operationTimeout,
            300
        )
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsConfigurationV1.isValidOperationTimeout(300.001)
        )
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsConfigurationV1.isValidOperationTimeout(.infinity)
        )
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsConfigurationV1.isValidOperationTimeout(.nan)
        )
    }

    func testRepeatedAndConflictingStartsPreserveLiveOperation() throws {
        let receiver = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: Data(repeating: 1, count: 16),
            requestCanonicalHash: Data(repeating: 2, count: 32)
        )
        let otherReceiver = try IrohaPeerNearbyDiscoveryContextV1(
            profile: .kagemushaWalletV1,
            role: .receiver,
            sessionID: Data(repeating: 3, count: 16),
            requestCanonicalHash: Data(repeating: 4, count: 32)
        )
        let sender = try IrohaPeerNearbyDiscoveryContextV1.senderBootstrap(
            profile: .kagemushaWalletV1
        )

        XCTAssertEqual(
            IrohaPeerNearbyConnectionsReducerV1.decideStart(
                activeMode: nil,
                activeContext: nil,
                requestedMode: .advertising,
                requestedContext: receiver
            ),
            .start
        )
        XCTAssertEqual(
            IrohaPeerNearbyConnectionsReducerV1.decideStart(
                activeMode: .advertising,
                activeContext: receiver,
                requestedMode: .advertising,
                requestedContext: receiver
            ),
            .keepActiveReplay
        )
        XCTAssertEqual(
            IrohaPeerNearbyConnectionsReducerV1.decideStart(
                activeMode: .advertising,
                activeContext: receiver,
                requestedMode: .advertising,
                requestedContext: otherReceiver
            ),
            .keepActiveConflict
        )
        XCTAssertEqual(
            IrohaPeerNearbyConnectionsReducerV1.decideStart(
                activeMode: .advertising,
                activeContext: receiver,
                requestedMode: .discovering,
                requestedContext: sender
            ),
            .keepActiveConflict
        )
    }

    func testStaleManagerStreamCallbackCannotPoisonRestartedConnection() {
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: false,
                activePeerID: "peer-new",
                state: .connected(peerID: "peer-new"),
                endpointID: "peer-old"
            )
        )
        XCTAssertTrue(
            IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: true,
                activePeerID: "peer-new",
                state: .connected(peerID: "peer-new"),
                endpointID: "peer-new"
            )
        )
    }

    func testStaleManagerResourceCallbackCannotPoisonRestartedConnection() {
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: false,
                activePeerID: "same-id",
                state: .connected(peerID: "same-id"),
                endpointID: "same-id"
            )
        )
        XCTAssertFalse(
            IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                managerMatches: true,
                activePeerID: "same-id",
                state: .connecting(peerID: "same-id"),
                endpointID: "same-id"
            )
        )
    }

    func testCurrentConnectedPayloadSourceTruthTable() {
        struct Row {
            let managerMatches: Bool
            let activePeerID: String?
            let state: IrohaPeerNearbyConnectionsStateV1
            let endpointID: String
            let expected: Bool
        }
        let rows = [
            Row(
                managerMatches: true,
                activePeerID: "peer",
                state: .connected(peerID: "peer"),
                endpointID: "peer",
                expected: true
            ),
            Row(
                managerMatches: false,
                activePeerID: "peer",
                state: .connected(peerID: "peer"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: nil,
                state: .connected(peerID: "peer"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: "other",
                state: .connected(peerID: "peer"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: "peer",
                state: .connecting(peerID: "peer"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: "peer",
                state: .verificationRequired(peerID: "peer", code: "1234"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: "peer",
                state: .connected(peerID: "other"),
                endpointID: "peer",
                expected: false
            ),
            Row(
                managerMatches: true,
                activePeerID: "peer",
                state: .stopped,
                endpointID: "peer",
                expected: false
            ),
        ]

        for row in rows {
            XCTAssertEqual(
                IrohaPeerNearbyConnectionsReducerV1.isCurrentConnectedPayloadSource(
                    managerMatches: row.managerMatches,
                    activePeerID: row.activePeerID,
                    state: row.state,
                    endpointID: row.endpointID
                ),
                row.expected
            )
        }
    }

    func testCallbackEpochGateSuppressesStopRestartStaleDelivery() {
        let gate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 7)
        var delivered: [String] = []
        let delayedOldOperation = {
            gate.performIfCurrent(7) {
                delivered.append("old")
            }
        }

        gate.update(to: 8)
        XCTAssertFalse(delayedOldOperation())
        XCTAssertTrue(delivered.isEmpty)
        XCTAssertTrue(gate.performIfCurrent(8) { delivered.append("new") })
        XCTAssertEqual(delivered, ["new"])
    }

    func testCallbackEpochGateInvalidatesWithoutWaitingForApplicationCode() {
        let gate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 11)
        let callbackEntered = DispatchSemaphore(value: 0)
        let releaseCallback = DispatchSemaphore(value: 0)
        let callbackFinished = DispatchSemaphore(value: 0)
        let updateStarted = DispatchSemaphore(value: 0)
        let updateFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            gate.performIfCurrent(11) {
                callbackEntered.signal()
                releaseCallback.wait()
            }
            callbackFinished.signal()
        }
        XCTAssertEqual(callbackEntered.wait(timeout: .now() + 1), .success)

        DispatchQueue.global().async {
            updateStarted.signal()
            gate.update(to: 12)
            updateFinished.signal()
        }
        XCTAssertEqual(updateStarted.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(updateFinished.wait(timeout: .now() + 1), .success)
        XCTAssertFalse(gate.performIfCurrent(11) {})
        XCTAssertTrue(gate.performIfCurrent(12) {})

        releaseCallback.signal()
        XCTAssertEqual(callbackFinished.wait(timeout: .now() + 1), .success)
    }

    func testCallbackCanReentrantlyInvalidateItsOwnEpochWithoutDeadlock() {
        let gate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 31)
        var stopReturned = false

        XCTAssertTrue(gate.performIfCurrent(31) {
            // This is the lock ordering exercised when a delegate calls
            // transport.stop() from inside its configured callback queue.
            gate.update(to: .max)
            stopReturned = true
        })

        XCTAssertTrue(stopReturned)
        XCTAssertFalse(gate.performIfCurrent(31) {})
        XCTAssertTrue(gate.performIfCurrent(.max) {})
    }

    func testPublicActionFloodRetainsOnlyConfiguredRecordCapAndDropsOnStop() {
        let queue = DispatchQueue(label: "public-action-flood-test")
        queue.suspend()
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 8,
            queue: queue
        )
        let lock = NSLock()
        var performed = 0
        var dropped = 0
        var admissions: [IrohaPeerNearbyPublicActionAdmissionV1] = []

        for value in 0..<1_000 {
            let capturedRecord = Data(repeating: UInt8(truncatingIfNeeded: value), count: 32 * 1_024)
            admissions.append(pump.enqueue(onDropped: {
                lock.lock()
                dropped += 1
                lock.unlock()
            }) {
                _ = capturedRecord.count
                lock.lock()
                performed += 1
                lock.unlock()
            })
        }

        XCTAssertEqual(admissions.filter { $0 == .accepted }.count, 8)
        XCTAssertEqual(admissions.filter { $0 == .full }.count, 992)
        XCTAssertEqual(pump.pendingCount, 8)
        let stopped = expectation(description: "stop control")
        pump.invalidateAndEnqueueControl { stopped.fulfill() }
        queue.resume()
        wait(for: [stopped], timeout: 2)
        XCTAssertEqual(pump.pendingCount, 0)
        lock.lock()
        let result = (performed, dropped)
        lock.unlock()
        XCTAssertEqual(result.0, 0)
        XCTAssertEqual(result.1, 8)
    }

    func testSubmissionLockOrdersConcurrentRestartBehindStopControl() {
        let queue = DispatchQueue(label: "public-action-order-test")
        queue.suspend()
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 4,
            queue: queue
        )
        let invalidated = DispatchSemaphore(value: 0)
        let releaseInvalidation = DispatchSemaphore(value: 0)
        let restartReturned = DispatchSemaphore(value: 0)
        let stopReturned = DispatchSemaphore(value: 0)
        let finished = expectation(description: "restart action")
        let lock = NSLock()
        var sequence: [String] = []

        XCTAssertEqual(pump.enqueue(onDropped: {
            lock.lock(); sequence.append("drop-old"); lock.unlock()
        }) {
            XCTFail("invalidated action must not run")
        }, .accepted)

        DispatchQueue.global().async {
            pump.invalidateAndEnqueueControl(afterInvalidation: {
                invalidated.signal()
                releaseInvalidation.wait()
            }) {
                lock.lock(); sequence.append("stop"); lock.unlock()
            }
            stopReturned.signal()
        }
        XCTAssertEqual(invalidated.wait(timeout: .now() + 1), .success)

        DispatchQueue.global().async {
            XCTAssertEqual(pump.enqueue {
                lock.lock(); sequence.append("restart"); lock.unlock()
                finished.fulfill()
            }, .accepted)
            restartReturned.signal()
        }
        XCTAssertEqual(restartReturned.wait(timeout: .now() + 0.05), .timedOut)
        releaseInvalidation.signal()
        XCTAssertEqual(stopReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(restartReturned.wait(timeout: .now() + 1), .success)

        queue.resume()
        wait(for: [finished], timeout: 1)
        lock.lock()
        let delivered = sequence
        lock.unlock()
        XCTAssertEqual(delivered, ["drop-old", "stop", "restart"])
    }

    func testGenerationGateWaitsForCheckedActionBeforeStopReturns() {
        let queue = DispatchQueue(label: "public-action-generation-gate-test")
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 2,
            queue: queue
        )
        let checked = DispatchSemaphore(value: 0)
        let releaseAction = DispatchSemaphore(value: 0)
        let stopReturned = DispatchSemaphore(value: 0)
        let finished = expectation(description: "stop control")
        let lock = NSLock()
        var sequence: [String] = []

        XCTAssertEqual(pump.enqueue(afterCurrentCheck: {
            checked.signal()
            releaseAction.wait()
        }) {
            lock.lock(); sequence.append("action"); lock.unlock()
        }, .accepted)
        XCTAssertEqual(checked.wait(timeout: .now() + 1), .success)

        DispatchQueue.global().async {
            pump.invalidateAndEnqueueControl {
                lock.lock(); sequence.append("stop"); lock.unlock()
                finished.fulfill()
            }
            stopReturned.signal()
        }
        XCTAssertEqual(stopReturned.wait(timeout: .now() + 0.05), .timedOut)
        releaseAction.signal()
        XCTAssertEqual(stopReturned.wait(timeout: .now() + 1), .success)
        wait(for: [finished], timeout: 1)
        lock.lock()
        let delivered = sequence
        lock.unlock()
        XCTAssertEqual(delivered, ["action", "stop"])
    }

    func testConcurrentInvalidatorCannotDeadlockReentrantStopFromAction() {
        let queue = DispatchQueue(label: "public-action-reentrant-stop-test")
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 2,
            queue: queue
        )
        let actionEntered = DispatchSemaphore(value: 0)
        let externalStarted = DispatchSemaphore(value: 0)
        let externalReturned = DispatchSemaphore(value: 0)
        let actionReturned = expectation(description: "reentrant stop returned")
        let controlFinished = expectation(description: "coalesced control")

        XCTAssertEqual(pump.enqueue {
            actionEntered.signal()
            XCTAssertEqual(externalStarted.wait(timeout: .now() + 1), .success)
            pump.invalidateAndEnqueueControl { }
            actionReturned.fulfill()
        }, .accepted)
        XCTAssertEqual(actionEntered.wait(timeout: .now() + 1), .success)

        DispatchQueue.global().async {
            externalStarted.signal()
            pump.invalidateAndEnqueueControl { controlFinished.fulfill() }
            externalReturned.signal()
        }

        wait(for: [actionReturned, controlFinished], timeout: 1)
        XCTAssertEqual(externalReturned.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(pump.pendingCount, 0)
    }

    func testPublicStartEpochTransitionCannotDeadlockCallbackStop() {
        let queue = DispatchQueue(label: "public-start-callback-stop-test")
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 2,
            queue: queue
        )
        let callbackGate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 1)
        let callbackEntered = DispatchSemaphore(value: 0)
        let updateAttempted = DispatchSemaphore(value: 0)
        let stopReturned = DispatchSemaphore(value: 0)
        let actionFinished = expectation(description: "stale start action")
        let controlFinished = expectation(description: "stop control")

        DispatchQueue.global().async {
            callbackGate.performIfCurrent(1) {
                callbackEntered.signal()
                XCTAssertEqual(updateAttempted.wait(timeout: .now() + 1), .success)
                pump.invalidateAndEnqueueControl { controlFinished.fulfill() }
                stopReturned.signal()
            }
        }
        XCTAssertEqual(callbackEntered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(pump.enqueue {
            _ = pump.performUnlockedIfCurrent {
                updateAttempted.signal()
                callbackGate.update(to: 2)
            }
            actionFinished.fulfill()
        }, .accepted)

        XCTAssertEqual(stopReturned.wait(timeout: .now() + 1), .success)
        wait(for: [actionFinished, controlFinished], timeout: 1)
    }

    func testInternalFailureCannotDeadlockCallbackThatCallsStop() {
        let queue = DispatchQueue(label: "internal-failure-callback-stop-test")
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 3,
            queue: queue
        )
        let callbackGate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 1)
        let callbackEntered = DispatchSemaphore(value: 0)
        let failureEntered = DispatchSemaphore(value: 0)
        let callbackStopReturned = DispatchSemaphore(value: 0)
        let failureFinished = expectation(description: "failure action")
        let stopFinished = expectation(description: "stop control")

        DispatchQueue.global().async {
            callbackGate.performIfCurrent(1) {
                callbackEntered.signal()
                XCTAssertEqual(failureEntered.wait(timeout: .now() + 1), .success)
                pump.invalidateAndEnqueueControl { stopFinished.fulfill() }
                callbackStopReturned.signal()
            }
        }
        XCTAssertEqual(callbackEntered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(pump.enqueue {
            failureEntered.signal()
            pump.invalidateOrdinaryActions()
            callbackGate.update(to: 2)
            failureFinished.fulfill()
        }, .accepted)

        XCTAssertEqual(callbackStopReturned.wait(timeout: .now() + 1), .success)
        wait(for: [failureFinished, stopFinished], timeout: 1)
    }

    func testInternalFailureDropsQueuedRestartAndSendExactlyOnce() {
        let queue = DispatchQueue(label: "internal-failure-queued-work-test")
        queue.suspend()
        let pump = IrohaPeerNearbyPublicActionPumpV1(
            maximumPendingCount: 4,
            queue: queue
        )
        let lock = NSLock()
        var restarted = 0
        var sendDropCount = 0
        let failureFinished = expectation(description: "failure")
        let sendDropped = expectation(description: "send dropped")

        XCTAssertEqual(pump.enqueue {
            pump.invalidateOrdinaryActions()
            failureFinished.fulfill()
        }, .accepted)
        XCTAssertEqual(pump.enqueue {
            lock.lock(); restarted += 1; lock.unlock()
        }, .accepted)
        XCTAssertEqual(pump.enqueue(onDropped: {
            lock.lock(); sendDropCount += 1; lock.unlock()
            sendDropped.fulfill()
        }) {
            XCTFail("queued send from the failed generation must not run")
        }, .accepted)

        queue.resume()
        wait(for: [failureFinished, sendDropped], timeout: 1)
        lock.lock()
        let result = (restarted, sendDropCount)
        lock.unlock()
        XCTAssertEqual(result.0, 0)
        XCTAssertEqual(result.1, 1)
        XCTAssertEqual(pump.pendingCount, 0)
    }

    func testQueueAcceptanceDoesNotCompleteBeforeTerminalDeliveryUpdate() {
        var barrier = IrohaPeerNearbyDeliveryBarrierV1()
        var results: [Bool] = []

        XCTAssertTrue(
            barrier.register(
                payloadID: 41,
                epoch: 7,
                peerID: "receiver"
            ) { result in
                results.append((try? result.get()) != nil)
            }
        )

        // The adapter's immediate Google send callback deliberately has no
        // corresponding barrier operation.
        XCTAssertEqual(barrier.pendingCount, 1)
        XCTAssertTrue(results.isEmpty)

        let action = barrier.resolve(
            payloadID: 41,
            epoch: 7,
            peerID: "receiver",
            result: .success(())
        )
        XCTAssertNotNil(action)
        XCTAssertTrue(results.isEmpty)
        action?.perform()
        XCTAssertEqual(results, [true])
        XCTAssertEqual(barrier.pendingCount, 0)
    }

    func testPayloadEpochAndPeerPinOrderedDeliveryBarriers() {
        var barrier = IrohaPeerNearbyDeliveryBarrierV1()
        var completed: [Int] = []
        XCTAssertTrue(barrier.register(payloadID: 1, epoch: 9, peerID: "peer") { _ in
            completed.append(1)
        })
        XCTAssertTrue(barrier.register(payloadID: 2, epoch: 9, peerID: "peer") { _ in
            completed.append(2)
        })

        XCTAssertNil(
            barrier.resolve(
                payloadID: 1,
                epoch: 8,
                peerID: "peer",
                result: .success(())
            )
        )
        XCTAssertNil(
            barrier.resolve(
                payloadID: 1,
                epoch: 9,
                peerID: "other",
                result: .success(())
            )
        )
        XCTAssertEqual(barrier.pendingCount, 2)

        barrier.resolve(
            payloadID: 1,
            epoch: 9,
            peerID: "peer",
            result: .success(())
        )?.perform()
        XCTAssertEqual(completed, [1])
        XCTAssertEqual(barrier.pendingCount, 1)
        barrier.resolve(
            payloadID: 2,
            epoch: 9,
            peerID: "peer",
            result: .success(())
        )?.perform()
        XCTAssertEqual(completed, [1, 2])
    }

    func testStopDuringSendCancelsAndFailsEveryPendingCompletionExactlyOnce() {
        var barrier = IrohaPeerNearbyDeliveryBarrierV1()
        var cancellationCount = 0
        var timeoutCancellationCount = 0
        var failureCount = 0
        XCTAssertTrue(barrier.register(payloadID: 11, epoch: 2, peerID: "peer") { result in
            if case .failure = result { failureCount += 1 }
        })
        XCTAssertTrue(
            barrier.attachCancellation(payloadID: 11) {
                cancellationCount += 1
            }
        )
        XCTAssertTrue(
            barrier.attachTimeoutCancellation(payloadID: 11) {
                timeoutCancellationCount += 1
            }
        )

        let actions = barrier.drain(
            result: .failure(IrohaPeerNearbyConnectionsErrorV1.cancelled)
        )
        XCTAssertEqual(barrier.pendingCount, 0)
        XCTAssertEqual(actions.count, 1)
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertEqual(timeoutCancellationCount, 1)
        XCTAssertEqual(failureCount, 0)
        actions.forEach { $0.perform() }
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertEqual(timeoutCancellationCount, 1)
        XCTAssertEqual(failureCount, 1)

        XCTAssertNil(
            barrier.resolve(
                payloadID: 11,
                epoch: 2,
                peerID: "peer",
                result: .success(())
            )
        )
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertEqual(timeoutCancellationCount, 1)
        XCTAssertEqual(failureCount, 1)
    }

    func testSendTimeoutFailsAndCancelsTheInFlightPayload() {
        var barrier = IrohaPeerNearbyDeliveryBarrierV1()
        var cancellationCount = 0
        var didTimeOut = false
        XCTAssertTrue(barrier.register(payloadID: 51, epoch: 3, peerID: "peer") { result in
            guard case .failure(let error) = result else { return }
            didTimeOut = (error as? IrohaPeerNearbyConnectionsErrorV1) == .timedOut
        })
        XCTAssertTrue(barrier.attachCancellation(payloadID: 51) {
            cancellationCount += 1
        })

        let timeoutAction = barrier.resolve(
            payloadID: 51,
            epoch: 3,
            peerID: "peer",
            result: .failure(IrohaPeerNearbyConnectionsErrorV1.timedOut)
        )
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertFalse(didTimeOut)
        timeoutAction?.perform()
        XCTAssertTrue(didTimeOut)
        XCTAssertEqual(cancellationCount, 1)
        XCTAssertEqual(barrier.pendingCount, 0)
    }

    func testPendingDeliverySetIsBounded() {
        var barrier = IrohaPeerNearbyDeliveryBarrierV1(maximumPendingCount: 1)
        XCTAssertTrue(barrier.register(payloadID: 1, epoch: 1, peerID: "peer") { _ in })
        XCTAssertFalse(barrier.register(payloadID: 2, epoch: 1, peerID: "peer") { _ in })
        XCTAssertEqual(barrier.pendingCount, 1)
    }

    func testReceiveFloodUsesOneBoundedGenerationScopedDrain() {
        var scheduled: [() -> Void] = []
        var delivered: [Int] = []
        let pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: 2,
            maximumRecordsPerPhase: 4,
            schedule: {
                scheduled.append($0)
                return true
            }
        )
        pump.activate(epoch: 7, peerID: "old")

        let admissions = (0..<100).map { value in
            pump.enqueue(epoch: 7, peerID: "old") { delivered.append(value) }
        }
        XCTAssertEqual(admissions.filter { $0 == .accepted }.count, 2)
        XCTAssertEqual(admissions.filter { $0 == .full }.count, 98)
        XCTAssertEqual(pump.pendingCount, 2)
        XCTAssertEqual(scheduled.count, 1)

        pump.deactivate()
        pump.activate(epoch: 8, peerID: "new")
        XCTAssertEqual(
            pump.enqueue(epoch: 7, peerID: "old") { delivered.append(-1) },
            .inactive
        )
        XCTAssertEqual(
            pump.enqueue(epoch: 8, peerID: "new") { delivered.append(8) },
            .accepted
        )
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()

        XCTAssertEqual(delivered, [8])
        XCTAssertEqual(pump.pendingCount, 0)
    }

    func testReceivePhaseAdmitsFourSequentialRecordsAndRejectsFifth() {
        var scheduled: [() -> Void] = []
        var delivered: [Int] = []
        let pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: 2,
            maximumRecordsPerPhase: 4,
            schedule: {
                scheduled.append($0)
                return true
            }
        )
        pump.activate(epoch: 4, peerID: "peer")

        XCTAssertEqual(pump.enqueue(epoch: 4, peerID: "peer") { delivered.append(1) }, .accepted)
        XCTAssertEqual(pump.enqueue(epoch: 4, peerID: "peer") { delivered.append(2) }, .accepted)
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()
        XCTAssertEqual(pump.enqueue(epoch: 4, peerID: "peer") { delivered.append(3) }, .accepted)
        XCTAssertEqual(pump.enqueue(epoch: 4, peerID: "peer") { delivered.append(4) }, .accepted)
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()
        XCTAssertEqual(
            pump.enqueue(epoch: 4, peerID: "peer") { delivered.append(5) },
            .budgetExceeded
        )
        XCTAssertEqual(delivered, [1, 2, 3, 4])
    }

    func testSuspendedReceiveExecutorAdmitsFullFourRecordTranscriptOnly() {
        var scheduled: [() -> Void] = []
        var delivered: [Int] = []
        let pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: 4,
            maximumRecordsPerPhase: 4,
            schedule: {
                scheduled.append($0)
                return true
            }
        )
        pump.activate(epoch: 5, peerID: "peer")

        for value in 1...4 {
            XCTAssertEqual(
                pump.enqueue(epoch: 5, peerID: "peer") { delivered.append(value) },
                .accepted
            )
        }
        XCTAssertEqual(pump.pendingCount, 4)
        XCTAssertEqual(scheduled.count, 1)
        XCTAssertEqual(
            pump.enqueue(epoch: 5, peerID: "peer") { delivered.append(5) },
            .budgetExceeded
        )
        XCTAssertEqual(scheduled.count, 1)
        scheduled.removeFirst()()
        XCTAssertEqual(delivered, [1, 2, 3, 4])
    }

    func testDefaultConnectionAdmitsThePayersFiveRecordTranscriptOnly() {
        // The payer receives hello, authentication, the receiver's sealed ask, the Request and
        // the Credited acknowledgement; the transport moves each as opaque bytes of any kind.
        let configuration = IrohaPeerNearbyConnectionsConfigurationV1()
        var scheduled: [() -> Void] = []
        var delivered: [Int] = []
        let pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: configuration.maximumPendingReceiveCallbacks,
            maximumRecordsPerPhase: configuration.maximumReceiveRecordsPerConnection,
            schedule: {
                scheduled.append($0)
                return true
            }
        )
        pump.activate(epoch: 6, peerID: "receiver")
        for value in 1...5 {
            XCTAssertEqual(
                pump.enqueue(epoch: 6, peerID: "receiver") { delivered.append(value) },
                .accepted
            )
            XCTAssertEqual(scheduled.count, 1)
            scheduled.removeFirst()()
        }
        XCTAssertEqual(
            pump.enqueue(epoch: 6, peerID: "receiver") { delivered.append(6) },
            .budgetExceeded
        )
        XCTAssertEqual(delivered, [1, 2, 3, 4, 5])
        // The next connection starts with a fresh budget.
        pump.activate(epoch: 7, peerID: "receiver")
        XCTAssertEqual(pump.enqueue(epoch: 7, peerID: "receiver") { delivered.append(7) }, .accepted)
        scheduled.removeFirst()()
        XCTAssertEqual(delivered, [1, 2, 3, 4, 5, 7])
    }

    func testCallbackDispatcherPreservesConfiguredQueueAndRejectsListenerOverflow() {
        let callbackQueue = DispatchQueue(label: "callback-queue-test")
        let queueKey = DispatchSpecificKey<Bool>()
        callbackQueue.setSpecific(key: queueKey, value: true)
        let firstEntered = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let callbackFinished = expectation(description: "callback")
        let dispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: 1,
            maximumPendingCompletionCount: 2,
            callbackQueue: callbackQueue
        )

        XCTAssertTrue(dispatcher.execute {
            XCTAssertEqual(DispatchQueue.getSpecific(key: queueKey), true)
            firstEntered.signal()
            releaseFirst.wait()
            callbackFinished.fulfill()
        })
        XCTAssertEqual(firstEntered.wait(timeout: .now() + 1), .success)
        XCTAssertFalse(dispatcher.execute { XCTFail("overflow listener must be rejected") })
        XCTAssertEqual(dispatcher.pendingCount, 1)
        releaseFirst.signal()
        wait(for: [callbackFinished], timeout: 1)
        XCTAssertEqual(dispatcher.pendingCount, 0)
    }

    func testCriticalDrainRetainsDispatcherAndNeverRunsOnProducerQueue() {
        let callbackQueue = DispatchQueue(label: "critical-callback-queue-test")
        let queueKey = DispatchSpecificKey<Bool>()
        callbackQueue.setSpecific(key: queueKey, value: true)
        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        callbackQueue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)

        let callbackFinished = expectation(description: "critical callback")
        var dispatcher: IrohaPeerNearbyCallbackDispatcherV1? =
            IrohaPeerNearbyCallbackDispatcherV1(
                maximumPendingCount: 1,
                maximumPendingCompletionCount: 1,
                callbackQueue: callbackQueue
            )
        let retainedDispatcher = WeakReference(dispatcher)
        dispatcher?.executeCritical {
            XCTAssertEqual(DispatchQueue.getSpecific(key: queueKey), true)
            callbackFinished.fulfill()
        }
        dispatcher = nil
        XCTAssertNotNil(retainedDispatcher.value)

        releaseBlocker.signal()
        wait(for: [callbackFinished], timeout: 1)
    }

    func testSaturatedCriticalCompletionRunsInlineOnlyOnConfiguredQueue() {
        let callbackQueue = DispatchQueue(label: "critical-reentrant-test")
        let dispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: 1,
            maximumPendingCompletionCount: 1,
            callbackQueue: callbackQueue
        )
        let finished = expectation(description: "reentrant completion")
        let sequenceLock = NSLock()
        var sequence: [String] = []

        dispatcher.executeCritical {
            sequenceLock.lock()
            sequence.append("first-start")
            sequenceLock.unlock()
            dispatcher.executeCritical {
                sequenceLock.lock()
                sequence.append("deinit-batch")
                sequenceLock.unlock()
                finished.fulfill()
            }
            sequenceLock.lock()
            sequence.append("first-end")
            sequenceLock.unlock()
        }

        wait(for: [finished], timeout: 1)
        sequenceLock.lock()
        let delivered = sequence
        sequenceLock.unlock()
        XCTAssertEqual(delivered, ["first-start", "deinit-batch", "first-end"])
    }

    func testRecursiveCriticalCompletionFloodRetainsNoClosureChain() {
        let callbackQueue = DispatchQueue(label: "critical-recursive-flood-test")
        let queueKey = DispatchSpecificKey<Bool>()
        callbackQueue.setSpecific(key: queueKey, value: true)
        let dispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: 1,
            maximumPendingCompletionCount: 1,
            callbackQueue: callbackQueue
        )
        let finished = expectation(description: "recursive completion flood")
        var maximumObservedPending = 0
        var recurse: ((Int) -> Void)!
        recurse = { depth in
            XCTAssertEqual(DispatchQueue.getSpecific(key: queueKey), true)
            maximumObservedPending = max(maximumObservedPending, dispatcher.pendingCount)
            if depth == 250 {
                finished.fulfill()
                return
            }
            dispatcher.executeCritical { recurse(depth + 1) }
        }

        dispatcher.executeCritical { recurse(0) }
        wait(for: [finished], timeout: 1)
        XCTAssertEqual(maximumObservedPending, 1)
        XCTAssertEqual(dispatcher.pendingCount, 0)
    }

    func testStalledConfiguredAndSaturatedFallbackDeliverExactlyOnceWithLaneOrder() {
        let callbackQueue = DispatchQueue(label: "stalled-configured-callback-test")
        callbackQueue.suspend()
        let fallback = IrohaPeerNearbyCompletionFallbackV1(maximumPendingCount: 1)
        let dispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: 1,
            maximumPendingCompletionCount: 1,
            callbackQueue: callbackQueue,
            completionFallback: fallback
        )
        let fallbackEntered = DispatchSemaphore(value: 0)
        let releaseFallback = DispatchSemaphore(value: 0)
        let configuredFinished = expectation(description: "configured completion")
        let fallbackFinished = expectation(description: "fallback completion")
        let eventsLock = NSLock()
        var counts: [Int: Int] = [:]
        var order: [Int] = []
        let record: (Int) -> Void = { value in
            eventsLock.lock()
            counts[value, default: 0] += 1
            order.append(value)
            eventsLock.unlock()
        }

        dispatcher.executeCritical {
            record(0)
            configuredFinished.fulfill()
        }
        dispatcher.executeCritical {
            fallbackEntered.signal()
            releaseFallback.wait()
            record(1)
            fallbackFinished.fulfill()
        }
        XCTAssertEqual(fallbackEntered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(fallback.pendingCount, 1)
        for value in 2..<10 {
            dispatcher.executeCritical { record(value) }
        }
        eventsLock.lock()
        let overloadOrder = order
        eventsLock.unlock()
        XCTAssertEqual(overloadOrder, Array(2..<10))
        XCTAssertEqual(dispatcher.pendingCount, 1)
        XCTAssertEqual(fallback.pendingCount, 1)

        releaseFallback.signal()
        wait(for: [fallbackFinished], timeout: 1)
        callbackQueue.resume()
        wait(for: [configuredFinished], timeout: 1)
        XCTAssertEqual(dispatcher.pendingCount, 0)
        XCTAssertEqual(fallback.pendingCount, 0)
        eventsLock.lock()
        let deliveredCounts = counts
        let deliveredOrder = order
        eventsLock.unlock()
        XCTAssertEqual(deliveredCounts, Dictionary(uniqueKeysWithValues: (0..<10).map { ($0, 1) }))
        XCTAssertEqual(deliveredOrder, Array(2..<10) + [1, 0])
    }

    func testCallbackDrainYieldsToUnrelatedConfiguredQueueWork() {
        let callbackQueue = DispatchQueue(label: "callback-fairness-test")
        let dispatcher = IrohaPeerNearbyCallbackDispatcherV1(
            maximumPendingCount: 2,
            maximumPendingCompletionCount: 2,
            callbackQueue: callbackQueue
        )
        let firstEntered = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let marker = expectation(description: "unrelated queue marker")
        let floodFinished = expectation(description: "callback flood")
        var remaining = 100
        var enqueueNext: (() -> Void)!
        enqueueNext = {
            XCTAssertTrue(dispatcher.execute {
                if remaining == 100 {
                    firstEntered.signal()
                    releaseFirst.wait()
                }
                remaining -= 1
                if remaining > 0 { enqueueNext() } else { floodFinished.fulfill() }
            })
        }
        enqueueNext()
        XCTAssertEqual(firstEntered.wait(timeout: .now() + 1), .success)
        callbackQueue.async { marker.fulfill() }
        releaseFirst.signal()
        wait(for: [marker, floodFinished], timeout: 2)
    }

    func testTerminalGateSuppressesNewUpdatesButLetsAdmittedUpdateFinish() {
        let gate = IrohaPeerNearbyCallbackEpochGateV1(initialEpoch: 7)
        var barrier = IrohaPeerNearbyDeliveryBarrierV1(maximumPendingCount: 2)
        var successes = 0
        XCTAssertTrue(barrier.register(payloadID: 1, epoch: 7, peerID: "peer") { result in
            if case .success = result { successes += 1 }
        })
        XCTAssertTrue(barrier.register(payloadID: 2, epoch: 7, peerID: "peer") { result in
            if case .success = result { successes += 1 }
        })
        let updateEntered = DispatchSemaphore(value: 0)
        let releaseUpdate = DispatchSemaphore(value: 0)
        let stopReturned = DispatchSemaphore(value: 0)
        let updateFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            gate.performIfCurrent(7) {
                updateEntered.signal()
                releaseUpdate.wait()
                barrier.resolve(
                    payloadID: 1,
                    epoch: 7,
                    peerID: "peer",
                    result: .success(())
                )?.perform()
            }
            updateFinished.signal()
        }
        XCTAssertEqual(updateEntered.wait(timeout: .now() + 1), .success)
        DispatchQueue.global().async {
            gate.update(to: .max)
            stopReturned.signal()
        }
        XCTAssertEqual(stopReturned.wait(timeout: .now() + 1), .success)
        releaseUpdate.signal()
        XCTAssertEqual(updateFinished.wait(timeout: .now() + 1), .success)

        XCTAssertFalse(gate.performIfCurrent(7) {
            barrier.resolve(
                payloadID: 2,
                epoch: 7,
                peerID: "peer",
                result: .success(())
            )?.perform()
        })
        barrier.drain(result: .failure(IrohaPeerNearbyConnectionsErrorV1.cancelled))
            .forEach { $0.perform() }
        XCTAssertEqual(successes, 1)
    }

    func testConcurrentRejectingReceiveSchedulerNeverReturnsAcceptedThenDrops() {
        let schedulerEntered = DispatchSemaphore(value: 0)
        let releaseScheduler = DispatchSemaphore(value: 0)
        let resultLock = NSLock()
        var results: [IrohaPeerNearbyReceiveAdmissionV1] = []
        var scheduleCount = 0
        let pump = IrohaPeerNearbyReceiveCallbackPumpV1(
            maximumPendingCount: 2,
            maximumRecordsPerPhase: 4,
            schedule: { _ in
                resultLock.lock()
                scheduleCount += 1
                let count = scheduleCount
                resultLock.unlock()
                if count == 1 {
                    schedulerEntered.signal()
                    releaseScheduler.wait()
                }
                return false
            }
        )
        pump.activate(epoch: 9, peerID: "peer")

        let first = DispatchGroup()
        first.enter()
        DispatchQueue.global().async {
            let result = pump.enqueue(epoch: 9, peerID: "peer") { }
            resultLock.lock(); results.append(result); resultLock.unlock()
            first.leave()
        }
        XCTAssertEqual(schedulerEntered.wait(timeout: .now() + 1), .success)
        first.enter()
        DispatchQueue.global().async {
            let result = pump.enqueue(epoch: 9, peerID: "peer") { }
            resultLock.lock(); results.append(result); resultLock.unlock()
            first.leave()
        }
        releaseScheduler.signal()
        XCTAssertEqual(first.wait(timeout: .now() + 1), .success)

        resultLock.lock()
        let admissions = results
        let attempts = scheduleCount
        resultLock.unlock()
        XCTAssertEqual(admissions, [.full, .full])
        XCTAssertEqual(attempts, 2)
        XCTAssertEqual(pump.pendingCount, 0)
    }

    func testDeadlineReplacementAndCancellationRetainAtMostOneTimer() {
        let deadline = IrohaPeerNearbyDeadlineV1()
        let queue = DispatchQueue(label: "deadline-retention-test")
        for _ in 0..<1_000 {
            deadline.schedule(on: queue, after: 90) {
                XCTFail("cancelled deadline fired")
            }
            XCTAssertEqual(deadline.retainedTimerCount, 1)
        }
        deadline.cancel()
        XCTAssertEqual(deadline.retainedTimerCount, 0)
    }

    func testDeadlineConcurrentScheduleCancelNeverCancelsSuspendedSource() {
        let deadline = IrohaPeerNearbyDeadlineV1()
        let timerQueue = DispatchQueue(label: "deadline-race-timers")
        let workers = DispatchGroup()
        for worker in 0..<4 {
            workers.enter()
            DispatchQueue.global().async {
                for index in 0..<250 {
                    if (worker + index).isMultiple(of: 2) {
                        deadline.schedule(on: timerQueue, after: 90) { }
                    } else {
                        deadline.cancel()
                    }
                }
                workers.leave()
            }
        }
        XCTAssertEqual(workers.wait(timeout: .now() + 5), .success)
        deadline.cancel()
        XCTAssertEqual(deadline.retainedTimerCount, 0)
    }
}
