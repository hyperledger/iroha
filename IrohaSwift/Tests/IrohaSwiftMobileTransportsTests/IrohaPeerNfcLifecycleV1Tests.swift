import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

private actor IrohaPeerNfcLifecycleLatchV1 {
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

private final class IrohaPeerNfcLifecycleProbeV1: @unchecked Sendable {
    private let lock = NSLock()
    private var discardedValues: [Int] = []

    func appendDiscarded(_ value: Int) {
        lock.lock()
        discardedValues.append(value)
        lock.unlock()
    }

    var discarded: [Int] {
        lock.lock()
        defer { lock.unlock() }
        return discardedValues
    }
}

final class IrohaPeerNfcLifecycleV1Tests: XCTestCase {
    func testDeadlineReturnsCompletedValue() async throws {
        let value = try await irohaPeerNfcWithDeadlineV1(
            timeoutNanoseconds: 1_000_000_000,
            operation: { 42 }
        )

        XCTAssertEqual(value, 42)
    }

    func testDeadlineDiscardsLatePlatformValueExactlyOnce() async {
        let latch = IrohaPeerNfcLifecycleLatchV1()
        let probe = IrohaPeerNfcLifecycleProbeV1()
        let operationEntered = expectation(description: "platform operation entered")
        let cleanupObserved = expectation(description: "late cleanup observed")

        do {
            _ = try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: 20_000_000,
                operation: {
                    operationEntered.fulfill()
                    await latch.wait()
                    return 7
                },
                onDiscardedSuccess: { value in
                    probe.appendDiscarded(value)
                    cleanupObserved.fulfill()
                }
            )
            XCTFail("the deadline must win")
        } catch let error as IrohaPeerNfcOperationDeadlineErrorV1 {
            XCTAssertEqual(error, .timedOut)
        } catch {
            XCTFail("unexpected deadline error: \(error)")
        }

        await fulfillment(of: [operationEntered], timeout: 1)
        await latch.signal()
        await fulfillment(of: [cleanupObserved], timeout: 1)
        XCTAssertEqual(probe.discarded, [7])
    }

    func testParentCancellationWinsAndCleansUpLateValue() async {
        let latch = IrohaPeerNfcLifecycleLatchV1()
        let probe = IrohaPeerNfcLifecycleProbeV1()
        let operationEntered = expectation(description: "platform operation entered")
        let cleanupObserved = expectation(description: "cancel cleanup observed")
        let task = Task {
            try await irohaPeerNfcWithDeadlineV1(
                timeoutNanoseconds: 5_000_000_000,
                operation: {
                    operationEntered.fulfill()
                    await latch.wait()
                    return 9
                },
                onDiscardedSuccess: { value in
                    probe.appendDiscarded(value)
                    cleanupObserved.fulfill()
                }
            )
        }

        await fulfillment(of: [operationEntered], timeout: 1)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("cancelled deadline race returned a value")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("unexpected cancellation error: \(error)")
        }
        await latch.signal()
        await fulfillment(of: [cleanupObserved], timeout: 1)
        XCTAssertEqual(probe.discarded, [9])
    }

    func testStartupBudgetNeverExtendsAcrossCalls() {
        let budget = IrohaPeerNfcDeadlineBudgetV1(
            timeoutMilliseconds: 10_000,
            nowNanoseconds: 1_000
        )

        XCTAssertEqual(
            budget.remainingNanoseconds(nowNanoseconds: 2_000),
            9_999_999_000
        )
        XCTAssertEqual(
            budget.remainingNanoseconds(nowNanoseconds: 10_000_001_000),
            0
        )
        XCTAssertEqual(
            budget.remainingNanoseconds(nowNanoseconds: 20_000_000_000),
            0
        )
    }

    func testInvalidAndMultipleTagsConsumeTheSharedAttemptBudget() {
        let gate = IrohaPeerNfcRetryGateV1(.init(
            maximumContactAttempts: 3,
            redetectionTimeoutMilliseconds: 3_000
        ))

        XCTAssertEqual(gate.recordInvalidDetection(), .retry)
        XCTAssertEqual(gate.recordInvalidDetection(), .retry)
        XCTAssertEqual(gate.recordInvalidDetection(), .exhausted)
        XCTAssertEqual(gate.recordInvalidDetection(), .exhausted)
        XCTAssertFalse(gate.mayRedetect())
        XCTAssertFalse(gate.beginContactAttempt())
    }

    func testStartupSignalPublishesOnlyItsFirstTerminalResult() async throws {
        let signal = IrohaPeerNfcAsyncSignalV1()

        XCTAssertTrue(signal.resolve(.success(())))
        XCTAssertFalse(signal.resolve(.failure(CancellationError())))
        try await signal.wait()
        try await signal.wait()
    }

    func testOnlyInitialSelectNotReadyResponsesAreRetryable() {
        for status in [
            IrohaPeerNfcStatusWordV1.notFound,
            .conditionsNotSatisfied,
        ] {
            XCTAssertTrue(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
                IrohaPeerNfcAPDUResponseV1(statusWord: status),
                for: .selectApplication(.protocolDefault)
            ))
            XCTAssertFalse(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
                IrohaPeerNfcAPDUResponseV1(statusWord: status),
                for: .getInfo
            ))
        }
        XCTAssertFalse(IrohaPeerNfcStartupResponseRetryPolicyV1.shouldRetry(
            IrohaPeerNfcAPDUResponseV1(statusWord: .success),
            for: .selectApplication(.protocolDefault)
        ))
    }

    func testCoreNfcAdapterDeclaresFiniteLifecycleDefaults() throws {
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

        XCTAssertTrue(source.contains("readerOperationTimeoutMilliseconds: UInt64 = 30_000"))
        XCTAssertTrue(source.contains("platformCallTimeoutMilliseconds: UInt64 = 3_000"))
        XCTAssertTrue(source.contains("cardSessionStartupTimeoutMilliseconds: UInt64 = 10_000"))
        XCTAssertTrue(source.contains("maximumReaderOperationTimeoutMilliseconds: UInt64 = 60_000"))
        XCTAssertTrue(source.contains("NFCPresentmentIntentAssertion.acquire()"))
        XCTAssertTrue(source.contains("readerOperationTimedOut"))
        XCTAssertTrue(source.contains("platformCallTimedOut"))
        XCTAssertTrue(source.contains("withTaskCancellationHandler"))
    }

    func testCardSessionAvailabilityKeepsAppleReaderPreflight() throws {
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
        let start = try XCTUnwrap(source.range(
            of: "private static func requireAvailability("
        ))
        let end = try XCTUnwrap(source.range(
            of: "\n}\n\n@available(iOS 17.4, *)\nprivate final class IrohaPeerNfcCardRuntimeV1",
            range: start.upperBound..<source.endIndex
        ))
        let cardAvailability = source[start.lowerBound..<end.lowerBound]

        XCTAssertTrue(cardAvailability.contains("CardSession.isSupported"))
        XCTAssertTrue(cardAvailability.contains("CardSession.isEligible"))
        XCTAssertTrue(
            cardAvailability.contains("NFCReaderSession.readingAvailable"),
            "CardSession startup must preserve Apple's NFC reader availability preflight."
        )
    }

    func testCardSessionStartupFailuresRemainDistinct() throws {
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
        let start = try XCTUnwrap(source.range(
            of: "private static func mapCardStartupError("
        ))
        let end = try XCTUnwrap(source.range(
            of: "\n    private static func mapCardFailure(",
            range: start.upperBound..<source.endIndex
        ))
        let startupMapping = source[start.lowerBound..<end.lowerBound]

        XCTAssertTrue(source.contains("case cardSessionSystemUnavailable"))
        XCTAssertTrue(source.contains("case cardSessionAccessNotAccepted"))
        XCTAssertTrue(source.contains("case cardSessionRadioDisabled"))
        XCTAssertTrue(startupMapping.contains(
            "case .systemNotAvailable, .emulationStopped, .transmissionError:"
        ))
        XCTAssertTrue(startupMapping.contains(
            "return IrohaPeerNfcCoreNFCErrorV1.cardSessionSystemUnavailable"
        ))
        XCTAssertTrue(startupMapping.contains("case .accessNotAccepted:"))
        XCTAssertTrue(startupMapping.contains(
            "return IrohaPeerNfcCoreNFCErrorV1.cardSessionAccessNotAccepted"
        ))
        XCTAssertTrue(startupMapping.contains("case .radioDisabled:"))
        XCTAssertTrue(startupMapping.contains(
            "return IrohaPeerNfcCoreNFCErrorV1.cardSessionRadioDisabled"
        ))
    }

    func testCardSessionEventInvalidationPreservesStartupFailureReason() throws {
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
        let runStart = try XCTUnwrap(source.range(
            of: "private func run(_ session: CardSession) async {"
        ))
        let runEnd = try XCTUnwrap(source.range(
            of: "\n    private func ensureEmulation(",
            range: runStart.upperBound..<source.endIndex
        ))
        let run = source[runStart.lowerBound..<runEnd.lowerBound]
        let invalidationStart = try XCTUnwrap(run.range(
            of: "case .sessionInvalidated(let reason):"
        ))
        let invalidationEnd = try XCTUnwrap(run.range(
            of: "\n                @unknown default:",
            range: invalidationStart.upperBound..<run.endIndex
        ))
        let invalidation = run[
            invalidationStart.lowerBound..<invalidationEnd.lowerBound
        ]

        XCTAssertTrue(invalidation.contains("startupSignal.resolve("))
        XCTAssertTrue(invalidation.contains(
            ".failure(Self.mapCardStartupError(reason))"
        ))
        XCTAssertFalse(invalidation.contains(
            ".failure(IrohaPeerNfcCoreNFCErrorV1.cancelled)"
        ))
    }
}
