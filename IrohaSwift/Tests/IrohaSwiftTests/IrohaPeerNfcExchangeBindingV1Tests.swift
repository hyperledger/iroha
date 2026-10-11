import XCTest
@testable import IrohaSwift

/// Hash-correct transport DATA must still quote the retained Request exactly.
final class IrohaPeerNfcExchangeBindingV1Tests: XCTestCase {
    private let sessionID = Data(repeating: 0x71, count: 16)

    func testSenderCheckpointRejectsDifferentQuotedBodyAndSignature() throws {
        let request = try message(.request)
        let wrongPayments = [
            try irohaPeerWalletExchangeMessageV1(kind: .payment, payload: Data([2]), requestBodyByte: 0x30),
            try irohaPeerWalletExchangeMessageV1(kind: .payment, payload: Data([2]), requestSignatureByte: 0x37),
        ]
        for payment in wrongPayments {
            XCTAssertThrowsError(try IrohaPeerNfcSenderCheckpointV1(sessionID: sessionID,
                receiveRequest: request.encoded, payment: payment.encoded)) {
                XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
            }
        }
    }

    func testRestoredSenderCheckpointRejectsHashCorrectDifferentRequest() throws {
        let request = try message(.request)
        let payment = try message(.payment)
        let replacement = try irohaPeerWalletExchangeMessageV1(
            kind: .payment, payload: Data([2]), requestSignatureByte: 0x37)
        XCTAssertEqual(payment.encoded.count, replacement.encoded.count)
        var bytes = try IrohaPeerNfcSenderCheckpointV1(sessionID: sessionID,
            receiveRequest: request.encoded, payment: payment.encoded).encoded
        let start = 36 + request.encoded.count
        bytes.replaceSubrange(start..<bytes.count, with: replacement.encoded)
        XCTAssertThrowsError(try IrohaPeerNfcSenderCheckpointV1.decode(bytes)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
    }

    func testMismatchedPaymentFailsBeforeDurableCommitHandlerAndOnReplay() throws {
        let request = try message(.request)
        let payment = try irohaPeerWalletExchangeMessageV1(
            kind: .payment, payload: Data([2]), requestBodyByte: 0x30)
        var receiver = try readyReceiver(request: request, payment: payment)
        let before = try receiver.status()
        let command = commit(request: request, payment: payment)
        var calls = 0
        for _ in 0..<2 {
            let response = receiver.process(apdu: try IrohaPeerNfcAPDUCodecV1.encode(command),
                durableCommit: { _ in
                    calls += 1
                    throw IrohaPeerNfcErrorV1.stateMismatch
                })
            XCTAssertEqual(response.statusWord, .securityStatusNotSatisfied)
            XCTAssertEqual(try receiver.status(), before)
        }
        XCTAssertEqual(calls, 0)
        XCTAssertEqual(receiver.phase, .paymentReceiving)
    }

    func testCommitRetainsRequestAndRejectsWrongCreditedScheme() throws {
        let request = try message(.request)
        let payment = try message(.payment)
        let receiver = try readyReceiver(request: request, payment: payment)
        guard case let .requiresDurableCommit(context) = try receiver.prepareCommit(
            commit(request: request, payment: payment)) else { return XCTFail("expected commit") }
        XCTAssertEqual(context.receiveRequest, request)
        let credited = try message(.credited, scheme: Data(repeating: 0x6d, count: 32))
        XCTAssertThrowsError(try IrohaPeerNfcDurableAcknowledgementV1(
            context: context, acknowledgement: credited.encoded)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        XCTAssertThrowsError(try IrohaPeerNfcSenderCheckpointV1(sessionID: sessionID,
            receiveRequest: request.encoded, payment: payment.encoded,
            durableAcknowledgement: credited.encoded)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
    }

    func testRestoredAckWithMatchingOuterIdentityStillRequiresRequestScheme() throws {
        let request = try message(.request)
        let payment = try message(.payment)
        var receiver = try readyReceiver(request: request, payment: payment)
        let foreignScheme = Data(repeating: 0x6d, count: 32)
        let foreignRequest = try message(.request, scheme: foreignScheme)
        let foreignPayment = try message(.payment, scheme: foreignScheme)
        let foreignReceiver = try readyReceiver(request: foreignRequest, payment: foreignPayment)
        guard case let .requiresDurableCommit(context) = try foreignReceiver.prepareCommit(
            commit(request: foreignRequest, payment: foreignPayment)) else { return XCTFail("expected commit") }
        var bytes = try IrohaPeerNfcDurableAcknowledgementV1(context: context,
            acknowledgement: message(.credited, scheme: foreignScheme).encoded).encoded
        // Persisted IDA1 has no retained Request; its consumer must check the credited scheme.
        bytes.replaceSubrange(24..<56, with: request.canonicalHash)
        bytes.replaceSubrange(56..<88, with: request.wireHash)
        XCTAssertEqual(payment.encoded.count, foreignPayment.encoded.count)
        bytes.replaceSubrange(94..<126, with: payment.wireHash)
        let restored = try IrohaPeerNfcDurableAcknowledgementV1.decode(bytes)
        XCTAssertEqual(restored.identity, receiver.identity)
        XCTAssertThrowsError(try IrohaPeerNfcReceiverSessionV1(sessionID: sessionID,
            receiveRequest: request.encoded, durableAcknowledgement: restored)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        let before = try receiver.status()
        XCTAssertThrowsError(try receiver.installDurableAcknowledgement(restored)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        XCTAssertEqual(try receiver.status(), before)
    }

    func testMatchingExchangeDurableRecordRestoresAndCommitReplayIsIdempotent() throws {
        let request = try message(.request)
        let payment = try message(.payment)
        var receiver = try readyReceiver(request: request, payment: payment)
        let command = commit(request: request, payment: payment)
        guard case let .requiresDurableCommit(context) = try receiver.prepareCommit(command)
        else { return XCTFail("expected commit") }
        let durable = try IrohaPeerNfcDurableAcknowledgementV1(
            context: context, acknowledgement: message(.credited).encoded)
        try receiver.installDurableAcknowledgement(durable)
        try receiver.installDurableAcknowledgement(durable)
        XCTAssertEqual(try receiver.prepareCommit(command), .alreadyCommitted)
        let restored = try IrohaPeerNfcReceiverSessionV1(sessionID: sessionID,
            receiveRequest: request.encoded,
            durableAcknowledgement: IrohaPeerNfcDurableAcknowledgementV1.decode(durable.encoded))
        XCTAssertEqual(try restored.status(), try receiver.status())
        XCTAssertEqual(try restored.prepareCommit(command), .alreadyCommitted)
    }

    func testSenderRejectsHashCorrectWrongSchemeBeforeAcknowledgementPersistence() throws {
        let request = try message(.request)
        let payment = try message(.payment)
        let credited = try message(.credited, scheme: Data(repeating: 0x6d, count: 32))
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(sessionID: sessionID,
            receiveRequest: request.encoded, payment: payment.encoded)
        var reducer = IrohaPeerNfcTwoTapReducerV1(checkpoint: checkpoint)
        let status = try IrohaPeerNfcStatusV1(phase: .acknowledgementReady,
            flags: [.idempotentWrites, .durableAcknowledgement], identity: checkpoint.identity,
            paymentProfile: payment.profile, paymentLength: payment.encoded.count,
            receivedPaymentBytes: payment.encoded.count, paymentWireHash: payment.wireHash,
            acknowledgementProfile: credited.profile, acknowledgementLength: credited.encoded.count,
            acknowledgementWireHash: credited.wireHash,
            maximumReadChunkBytes: 4_096, maximumWriteChunkBytes: 4_096)
        guard case .send(.readAcknowledgement) = try reducer.nextAction(observing: status)
        else { return XCTFail("expected acknowledgement read") }
        XCTAssertThrowsError(try reducer.consumeAcknowledgementChunk(credited.encoded)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        var calls = 0
        XCTAssertThrowsError(try reducer.persistAcknowledgement { _ in calls += 1 }) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
        XCTAssertEqual(calls, 0)
        XCTAssertEqual(reducer.checkpoint, checkpoint)
    }

    private func message(_ kind: IrohaPeerWireKindV1,
        scheme: Data = irohaPeerWalletStructuralSchemeV1) throws -> IrohaPeerWireMessageV1 {
        try irohaPeerWalletExchangeMessageV1(kind: kind, payload: Data([2]), schemeID: scheme)
    }

    private func commit(request: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1) -> IrohaPeerNfcCommandV1 {
        .commit(sessionID: sessionID, requestCanonicalHash: request.canonicalHash,
            paymentWireHash: payment.wireHash)
    }

    private func readyReceiver(request: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1) throws -> IrohaPeerNfcReceiverSessionV1 {
        var receiver = try IrohaPeerNfcReceiverSessionV1(sessionID: sessionID,
            receiveRequest: request.encoded)
        guard case let .requiresDurableAdmission(context) = try receiver.preparePaymentAdmission(
            .beginPayment(sessionID: sessionID, requestCanonicalHash: request.canonicalHash,
                paymentHeader: payment.header.bytes)) else { throw IrohaPeerNfcErrorV1.stateMismatch }
        try receiver.installPaymentAdmission(IrohaPeerNfcDurablePaymentAdmissionV1(context: context))
        _ = try receiver.handle(.write(sessionID: sessionID, paymentWireHash: payment.wireHash,
            offset: 0, bytes: payment.encoded))
        return receiver
    }
}
