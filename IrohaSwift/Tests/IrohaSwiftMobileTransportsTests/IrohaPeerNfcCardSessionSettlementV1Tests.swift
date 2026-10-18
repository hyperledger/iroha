import XCTest
@testable import IrohaSwiftMobileTransports

final class IrohaPeerNfcCardSessionSettlementV1Tests: XCTestCase {
    func testIdleRadioMustFinishBeforeSettlement() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        XCTAssertFalse(settlement.isSettled)
        let waiting = Task { try await settlement.wait() }
        await waitForWaiters(1, in: settlement)
        settlement.seal()
        try await waiting.value
        XCTAssertTrue(settlement.isSettled)
        XCTAssertEqual(settlement.pendingWaiterCount, 0)
        try await settlement.wait()
    }

    func testReservedCallbackKeepsEndedRadioPendingBeforeDispatch() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        // Reservation precedes dispatch, including a queue on MainActor.
        let callback = try settlement.reserveCallback()
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        let waiting = Task { try await settlement.wait() }
        await waitForWaiters(1, in: settlement)
        let task = Task.detached { callback.finish() }
        await task.value
        try await waiting.value
        XCTAssertTrue(settlement.isSettled)
    }

    func testConcurrentWaitersResumeOnlyAfterEveryCallbackReturns() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let request = try settlement.reserveCallback()
        let commit = try settlement.reserveCallback()
        let first = Task { try await settlement.wait() }
        let second = Task { try await settlement.wait() }
        await waitForWaiters(2, in: settlement)
        settlement.seal()
        request.finish()
        XCTAssertFalse(settlement.isSettled)
        XCTAssertEqual(settlement.pendingWaiterCount, 2)
        commit.finish()
        try await first.value
        try await second.value
        XCTAssertTrue(settlement.isSettled)
    }

    func testCancellationBeforeRegistrationLeavesNoWaiterOrCallbackCancellation() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let callback = try settlement.reserveCallback()
        let gate = SettlementTestLatch()
        let waiting = Task {
            await gate.wait()
            try await settlement.wait()
        }
        waiting.cancel()
        await gate.open()
        do {
            try await waiting.value
            XCTFail("a previously cancelled waiter must throw")
        } catch is CancellationError {}
        XCTAssertEqual(settlement.pendingWaiterCount, 0)
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        callback.finish()
        try await settlement.wait()
    }

    func testCancellationAfterRegistrationRemovesOnlyThatWaiter() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let callback = try settlement.reserveCallback()
        let cancelled = Task { try await settlement.wait() }
        let remaining = Task { try await settlement.wait() }
        await waitForWaiters(2, in: settlement)
        cancelled.cancel()
        do {
            try await cancelled.value
            XCTFail("cancelled wait must throw")
        } catch is CancellationError {}
        XCTAssertEqual(settlement.pendingWaiterCount, 1)
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        callback.finish()
        try await remaining.value
        XCTAssertEqual(settlement.pendingWaiterCount, 0)
    }

    func testSealedHandleRejectsAnyNewCallback() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        settlement.seal()
        XCTAssertThrowsError(try settlement.reserveCallback()) { error in
            XCTAssertTrue(error is CancellationError)
        }
        try await settlement.wait()
    }

    func testRequestCallbackOutlivesAlreadyCancelledDeadlineWaiter() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let callbackGate = SettlementTestLatch()
        let waiterGate = SettlementTestLatch()
        let callback = try settlement.startCallback {
            await callbackGate.wait()
            return 42
        }
        let timedWait = Task {
            await waiterGate.wait()
            return try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: 1_000_000_000,
                operation: { try await callback.value }
            )
        }
        timedWait.cancel()
        await waiterGate.open()
        do {
            _ = try await timedWait.value
            XCTFail("the deadline wrapper was cancelled before entering")
        } catch is CancellationError {}
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        await callbackGate.open()
        try await settlement.wait()
        let actual = try await callback.value
        XCTAssertEqual(actual, 42)
    }

    func testRequestCallbackFailureSettlesAfterReturning() async throws {
        enum Expected: Error { case failure }
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let gate = SettlementTestLatch()
        let callback: Task<Int, Error> = try settlement.startCallback {
            await gate.wait()
            throw Expected.failure
        }
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        await gate.open()
        try await settlement.wait()
        do {
            _ = try await callback.value
            XCTFail("settlement must preserve callback failure")
        } catch Expected.failure {}
    }

    func testFinishedCallbackCannotSettleTwice() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let first = try settlement.reserveCallback()
        let second = try settlement.reserveCallback()
        settlement.seal()
        first.finish()
        first.finish()
        XCTAssertFalse(settlement.isSettled)
        second.finish()
        second.finish()
        try await settlement.wait()
    }

    func testCapturedOldHandleIsIndependentOfReplacement() async throws {
        let old = IrohaPeerNfcCardSessionSettlementV1()
        let oldCallback = try old.reserveCallback()
        old.seal()
        let replacement = IrohaPeerNfcCardSessionSettlementV1()
        let newCallback = try replacement.reserveCallback()
        replacement.seal()
        oldCallback.finish()
        try await old.wait()
        XCTAssertFalse(replacement.isSettled)
        newCallback.finish()
        try await replacement.wait()
    }

    func testRetiredDurabilityWorkerSettlesOnlyAfterReturnAndLeaseRelease() async throws {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let lease = IrohaPeerNfcDurabilityLeaseGateV1()
        let gate = SettlementTestLatch()
        let entered = expectation(description: "durable callback entered")
        let pending = try IrohaPeerNfcPendingDurabilityV1(
            context: 7, leaseGate: lease, settlement: settlement
        ) {
            entered.fulfill()
            await gate.wait()
            return 42
        }
        await fulfillment(of: [entered], timeout: 1)
        pending.invalidate()
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        XCTAssertTrue(lease.isOccupied)
        let waiting = Task {
            try await settlement.wait()
            // Settlement resumes after the lease is released, even when the
            // retired runtime has discarded the monetary callback's result.
            XCTAssertFalse(lease.isOccupied)
        }
        await waitForWaiters(1, in: settlement)
        await gate.open()
        try await waiting.value
        XCTAssertTrue(settlement.isSettled)
    }

    func testDurabilityErrorAlsoReleasesLeaseBeforeSettlement() async throws {
        enum Expected: Error { case failure }
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let lease = IrohaPeerNfcDurabilityLeaseGateV1()
        let gate = SettlementTestLatch()
        let pending = try IrohaPeerNfcPendingDurabilityV1<Int, Int>(
            context: 7, leaseGate: lease, settlement: settlement
        ) {
            await gate.wait()
            throw Expected.failure
        }
        settlement.seal()
        XCTAssertFalse(settlement.isSettled)
        await gate.open()
        try await settlement.wait()
        XCTAssertFalse(lease.isOccupied)
        do {
            _ = try await pending.value(for: 7, timeoutNanoseconds: 1_000_000_000)
            XCTFail("settlement cannot convert callback failure to success")
        } catch Expected.failure {}
    }

    func testSealedReservationReleasesPreviouslyAcquiredDurabilityLease() {
        let settlement = IrohaPeerNfcCardSessionSettlementV1()
        let lease = IrohaPeerNfcDurabilityLeaseGateV1()
        settlement.seal()
        XCTAssertThrowsError(try IrohaPeerNfcPendingDurabilityV1(
            context: 7, leaseGate: lease, settlement: settlement
        ) { 42 }) { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertFalse(lease.isOccupied)
    }

    private func waitForWaiters(
        _ count: Int,
        in settlement: IrohaPeerNfcCardSessionSettlementV1,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        for _ in 0..<10_000 {
            if settlement.pendingWaiterCount == count { return }
            await Task.yield()
        }
        XCTFail("waiters did not register", file: file, line: line)
    }
}

private actor SettlementTestLatch {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        isOpen = true
        let waiting = waiters
        waiters.removeAll()
        waiting.forEach { $0.resume() }
    }
}
