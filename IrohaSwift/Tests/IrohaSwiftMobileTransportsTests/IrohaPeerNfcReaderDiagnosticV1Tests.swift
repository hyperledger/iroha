import XCTest
import IrohaSwift
@testable import IrohaSwiftMobileTransports

private final class IrohaPeerNfcDiagnosticSinkV1: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [IrohaPeerNfcReaderTerminalDiagnosticV1] = []

    func append(_ record: IrohaPeerNfcReaderTerminalDiagnosticV1) {
        lock.lock(); defer { lock.unlock() }
        records.append(record)
    }

    var snapshot: [IrohaPeerNfcReaderTerminalDiagnosticV1] {
        lock.lock(); defer { lock.unlock() }
        return records
    }
}

final class IrohaPeerNfcReaderDiagnosticV1Tests: XCTestCase {
    func testPeerFailureKeepsTypedOperationAndClosedMetadataOnly() {
        let record = IrohaPeerNfcReaderTerminalDiagnosticV1(
            error: IrohaPeerNfcErrorV1.peerPersistenceFailure(operation: .commit),
            operation: .write,
            lastStage: .requestRead,
            elapsedMilliseconds: 250
        )
        XCTAssertEqual(record.logLine,
            "iroha_kagemusha_nfc_ios_reader_terminal error=peer.peerPersistenceFailure"
                + " operation=commit elapsed_ms=250 last_stage=request_read")
        XCTAssertNil(record.platformCode)
    }

    func testAssociatedValuesAndArbitraryErrorDetailsNeverEnterLog() {
        let errors: [Error] = [
            IrohaPeerNfcErrorV1.offerDeclined(reason: 65535),
            IrohaPeerNfcErrorV1.messageTooLarge(actual: 987654, maximum: 123456),
            NSError(domain: "PRIVATE_ACCOUNT_REQUEST_PAYMENT_ACK", code: 987654,
                userInfo: [NSLocalizedDescriptionKey: "PRIVATE_ORIGINALS"]),
        ]
        let expected: [IrohaPeerNfcReaderFailureCodeV1] = [
            .peerOfferDeclined, .peerMessageTooLarge, .unknown,
        ]
        for (error, code) in zip(errors, expected) {
            let record = IrohaPeerNfcReaderTerminalDiagnosticV1(
                error: error, operation: nil, lastStage: nil, elapsedMilliseconds: 0
            )
            XCTAssertEqual(record.failure, code)
            XCTAssertNil(record.platformCode)
            for forbidden in ["65535", "987654", "123456", "PRIVATE", "platform_domain"] {
                XCTAssertFalse(record.logLine.contains(forbidden))
            }
        }
    }

    func testReporterUsesLastPublishedStageAndMonotonicElapsedTime() {
        let sink = IrohaPeerNfcDiagnosticSinkV1()
        var instant: TimeInterval = 1
        let reporter = IrohaPeerNfcReaderProgressReporterV1(
            now: { instant }, terminalHandler: sink.append, handler: nil
        )
        reporter.emit(.requestRead)
        reporter.emit(.tagDetected)
        reporter.emit(.requestRead) // A suppressed duplicate is not the last publication.
        reporter.record(operation: .readAcknowledgement)
        instant = 1.25
        reporter.finish(error: IrohaPeerNfcErrorV1.invalidHash)
        XCTAssertEqual(sink.snapshot.count, 1)
        XCTAssertEqual(sink.snapshot.first?.lastStage, .tagDetected)
        XCTAssertEqual(sink.snapshot.first?.operation, .readAcknowledgement)
        XCTAssertEqual(sink.snapshot.first?.elapsedMilliseconds, 250)
    }

    func testConcurrentCancellationTimeoutAndFailurePublishExactlyOnce() {
        let sink = IrohaPeerNfcDiagnosticSinkV1()
        let reporter = IrohaPeerNfcReaderProgressReporterV1(
            terminalHandler: sink.append, handler: nil
        )
        DispatchQueue.concurrentPerform(iterations: 64) { index in
            let error: Error = index.isMultiple(of: 2)
                ? CancellationError() : IrohaPeerNfcOperationDeadlineErrorV1.timedOut
            reporter.finish(error: error)
        }
        reporter.record(operation: .commit)
        reporter.emit(.complete)
        reporter.finish(error: IrohaPeerNfcErrorV1.conflictingReplay)
        XCTAssertEqual(sink.snapshot.count, 1)
        XCTAssertTrue([.cancelled, .operationTimedOut].contains(sink.snapshot[0].failure))
        XCTAssertNil(sink.snapshot[0].operation)
        XCTAssertNil(sink.snapshot[0].lastStage)
    }

    func testSuccessIsSilentAndLateOldFailureCannotDescribeNewOperation() {
        let sink = IrohaPeerNfcDiagnosticSinkV1()
        let old = IrohaPeerNfcReaderProgressReporterV1(
            terminalHandler: sink.append, handler: nil
        )
        old.record(operation: .commit)
        old.emit(.complete)
        old.invalidate()
        let current = IrohaPeerNfcReaderProgressReporterV1(
            terminalHandler: sink.append, handler: nil
        )
        old.finish(error: IrohaPeerNfcErrorV1.peerRejected(operation: .commit))
        XCTAssertTrue(sink.snapshot.isEmpty)
        current.record(operation: .getIntake)
        current.finish(error: IrohaPeerNfcErrorV1.stateMismatch)
        XCTAssertEqual(sink.snapshot.count, 1)
        XCTAssertEqual(sink.snapshot[0].operation, .getIntake)
        XCTAssertNil(sink.snapshot[0].lastStage)
    }

    func testFailureBeforeAnyProgressHasNoInventedStageOrOperation() {
        let sink = IrohaPeerNfcDiagnosticSinkV1()
        let reporter = IrohaPeerNfcReaderProgressReporterV1(
            now: { 2 }, terminalHandler: sink.append, handler: nil
        )
        reporter.finish(error: CancellationError())
        XCTAssertEqual(sink.snapshot.first?.logLine,
            "iroha_kagemusha_nfc_ios_reader_terminal error=cancelled"
                + " operation=none elapsed_ms=0 last_stage=none")
    }
}
