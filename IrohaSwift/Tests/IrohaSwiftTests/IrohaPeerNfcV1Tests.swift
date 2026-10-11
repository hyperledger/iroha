import XCTest
@testable import IrohaSwift

final class IrohaPeerNfcV1Tests: XCTestCase {

    func testNfcMessageLimitCannotExceedPortableV1Maximum() {
        XCTAssertTrue(IrohaPeerNfcLimitsV1.areValid(
            maximumMessageBytes: IrohaPeerNfcV1.maximumMessageBytes,
            maximumReadChunkBytes: IrohaPeerNfcV1.maximumChunkBytes,
            maximumWriteChunkBytes: IrohaPeerNfcV1.maximumChunkBytes
        ))
        XCTAssertFalse(IrohaPeerNfcLimitsV1.areValid(
            maximumMessageBytes: IrohaPeerNfcV1.maximumMessageBytes + 1,
            maximumReadChunkBytes: IrohaPeerNfcV1.maximumChunkBytes,
            maximumWriteChunkBytes: IrohaPeerNfcV1.maximumChunkBytes
        ))
    }

    private let sessionID = Data((1...16).map(UInt8.init))
    func testExactAidInstructionsAndUInt32Offsets() throws {
        let expectedAid = Data([
            0xF0, 0x50, 0x4B, 0x45, 0x50, 0x4B, 0x52, 0x4E, 0x46, 0x43, 0x01,
        ])
        let expectedAidHex = "F0504B45504B524E464301"
        XCTAssertEqual(
            IrohaPeerNfcV1.applicationIdentifier,
            expectedAid
        )
        XCTAssertEqual(IrohaPeerNfcV1.applicationIdentifierHex, expectedAidHex)
        XCTAssertEqual(
            IrohaPeerNfcV1.buildProfileMarker,
            "IrohaPeerNfcV1.AID.\(expectedAidHex)"
        )
        XCTAssertEqual(IrohaPeerNfcInstructionV1.getInfo.rawValue, 0x10)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.readRequest.rawValue, 0x11)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.beginPayment.rawValue, 0x20)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.write.rawValue, 0x21)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.commit.rawValue, 0x22)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.readAcknowledgement.rawValue, 0x23)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.confirmAcknowledgement.rawValue, 0x24)
        XCTAssertEqual(IrohaPeerNfcInstructionV1.getStatus.rawValue, 0x25)

        let request = try message(kind: .request, byte: 0x31, count: 200)
        let payment = try message(kind: .payment, byte: 0x32, count: 700)
        let commands: [IrohaPeerNfcCommandV1] = [
            .selectApplication,
            .getInfo,
            .readRequest(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash,
                offset: 0x0102_0304,
                length: 240
            ),
            .beginPayment(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash,
                paymentHeader: payment.header.bytes
            ),
            .write(
                sessionID: sessionID,
                paymentWireHash: payment.wireHash,
                offset: 0x0102_0304,
                bytes: Data(repeating: 0x55, count: 300)
            ),
            .commit(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash,
                paymentWireHash: payment.wireHash
            ),
            .readAcknowledgement(
                sessionID: sessionID,
                paymentWireHash: payment.wireHash,
                offset: 0x0102_0304,
                length: 1_024
            ),
            .confirmAcknowledgement(
                sessionID: sessionID,
                paymentWireHash: payment.wireHash,
                acknowledgementWireHash: request.wireHash
            ),
            .getStatus(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash
            ),
        ]
        for command in commands {
            let encoded = try IrohaPeerNfcAPDUCodecV1.encode(command)
            XCTAssertEqual(try IrohaPeerNfcAPDUCodecV1.decode(encoded), command)
        }

        let read = try IrohaPeerNfcAPDUCodecV1.encode(commands[2])
        XCTAssertEqual(Array(read[53..<57]), [0x01, 0x02, 0x03, 0x04])

        let extendedWrite = try IrohaPeerNfcAPDUCodecV1.encode(commands[4])
        XCTAssertEqual(extendedWrite[4], 0, "large WRITE must use extended Lc")
        XCTAssertEqual(Array(extendedWrite[55..<59]), [0x01, 0x02, 0x03, 0x04])

        var legacyStyleOffset = read
        legacyStyleOffset[2] = 0x01
        XCTAssertThrowsError(try IrohaPeerNfcAPDUCodecV1.decode(legacyStyleOffset)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidAPDU)
        }
    }

    func testInfoAndStatusRoundTripRejectUnknownFlags() throws {
        let request = try message(kind: .request, byte: 0x41, count: 80)
        let identity = try identity(for: request)
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: identity,
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        XCTAssertEqual(info.encode().count, IrohaPeerNfcV1.infoBytes)
        XCTAssertEqual(try IrohaPeerNfcInfoV1.decode(info.encode()), info)

        let status = try IrohaPeerNfcStatusV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: identity,
            paymentProfile: nil,
            paymentLength: 0,
            receivedPaymentBytes: 0,
            paymentWireHash: zeroHash,
            acknowledgementProfile: nil,
            acknowledgementLength: 0,
            acknowledgementWireHash: zeroHash,
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        XCTAssertEqual(status.encode().count, IrohaPeerNfcV1.statusBytes)
        XCTAssertEqual(try IrohaPeerNfcStatusV1.decode(status.encode()), status)

        var changed = status.encode()
        changed[8] |= 0x80
        XCTAssertThrowsError(try IrohaPeerNfcStatusV1.decode(changed)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidFlags)
        }
    }

    func testReceiverCommitIsDurableIdempotentAndRestorable() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 128,
            maximumWriteChunkBytes: 128
        )
        let request = try message(kind: .request, byte: 0x51, count: 260)
        let payment = try message(kind: .payment, byte: 0x52, count: 530)
        let acknowledgement = try message(kind: .credited, byte: 0x53, count: 200)
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: limits
        )
        XCTAssertEqual(receiver.phase, .requestReady)

        let info = try receiver.info()
        XCTAssertEqual(
            try IrohaPeerNfcReaderPlanningV1.validateReceiveRequest(
                request.encoded,
                against: info,
                limits: limits
            ),
            request
        )

        let begin = IrohaPeerNfcCommandV1.beginPayment(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentHeader: payment.header.bytes
        )
        XCTAssertThrowsError(try receiver.handle(begin)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .durableAdmissionRequired)
        }
        XCTAssertEqual(receiver.phase, .requestReady)
        XCTAssertNoThrow(try admit(begin, to: &receiver))
        XCTAssertEqual(receiver.phase, .paymentReceiving)
        guard case .alreadyAdmitted = try receiver.preparePaymentAdmission(begin) else {
            return XCTFail("exact BEGIN_PAYMENT replay must be idempotent")
        }

        let first = payment.encoded.subdata(in: 0..<100)
        XCTAssertNoThrow(try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 0,
            bytes: first
        )))
        let overlap = payment.encoded.subdata(in: 50..<150)
        XCTAssertNoThrow(try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 50,
            bytes: overlap
        )))
        XCTAssertEqual(try receiver.status().receivedPaymentBytes, 150)

        var conflicting = overlap
        conflicting[0] ^= 0x01
        XCTAssertThrowsError(try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 50,
            bytes: conflicting
        ))) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .conflictingReplay)
        }
        try writeRemaining(payment.encoded, to: &receiver, paymentHash: payment.wireHash, offset: 150)

        let commit = IrohaPeerNfcCommandV1.commit(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentWireHash: payment.wireHash
        )
        let commitAPDU = try IrohaPeerNfcAPDUCodecV1.encode(commit)
        var commitCount = 0
        var durableRecord: IrohaPeerNfcDurableAcknowledgementV1?
        let response = receiver.process(
            apdu: commitAPDU,
            durableCommit: { context in
                commitCount += 1
                XCTAssertEqual(context.payment, payment)
                let record = try IrohaPeerNfcDurableAcknowledgementV1(
                    context: context,
                    acknowledgement: acknowledgement.encoded,
                    limits: limits
                )
                durableRecord = record
                _ = record.encoded // the application persists these bytes here
                return record
            }
        )
        XCTAssertEqual(response.statusWord, .success)
        XCTAssertEqual(receiver.phase, .acknowledgementReady)
        XCTAssertEqual(commitCount, 1)

        let replay = receiver.process(
            apdu: commitAPDU,
            durableCommit: { _ in
                XCTFail("an exact durable COMMIT replay must not ingest twice")
                throw TestFailure.expected
            }
        )
        XCTAssertEqual(replay.statusWord, .success)
        XCTAssertEqual(commitCount, 1)

        let ackRead = try receiver.handle(.readAcknowledgement(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 0,
            length: 128
        ))
        XCTAssertEqual(ackRead, acknowledgement.encoded.prefix(128))
        XCTAssertNoThrow(try receiver.handle(.confirmAcknowledgement(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            acknowledgementWireHash: acknowledgement.wireHash
        )))
        XCTAssertEqual(receiver.phase, .complete)
        XCTAssertNoThrow(try receiver.handle(.confirmAcknowledgement(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            acknowledgementWireHash: acknowledgement.wireHash
        )))

        let persisted = try XCTUnwrap(durableRecord)
        let decodedRecord = try IrohaPeerNfcDurableAcknowledgementV1.decode(
            persisted.encoded,
            limits: limits
        )
        XCTAssertEqual(decodedRecord, persisted)
        var restored = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            durableAcknowledgement: decodedRecord,
            limits: limits
        )
        XCTAssertEqual(restored.phase, .acknowledgementReady)
        XCTAssertNoThrow(try restored.handle(.confirmAcknowledgement(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            acknowledgementWireHash: acknowledgement.wireHash
        )))
        XCTAssertEqual(restored.phase, .complete)
    }

    func testDurableAdmissionRestoresAtZeroAndIdaIsAuthoritative() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 128,
            maximumWriteChunkBytes: 128
        )
        let policy = IrohaPeerNfcProfilePolicyV1(profile: .kagemushaWalletV1)
        let request = try message(kind: .request, byte: 0x51, count: 260)
        let payment = try message(kind: .payment, byte: 0x52, count: 530)
        let acknowledgement = try message(kind: .credited, byte: 0x53, count: 200)
        let begin = IrohaPeerNfcCommandV1.beginPayment(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentHeader: payment.header.bytes
        )
        var fresh = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            profilePolicy: policy,
            limits: limits
        )
        guard case .requiresDurableAdmission(let context) =
            try fresh.preparePaymentAdmission(begin) else {
            return XCTFail("fresh BEGIN must require IPA1")
        }
        let admission = try IrohaPeerNfcDurablePaymentAdmissionV1(
            context: context,
            limits: limits
        )
        try fresh.installPaymentAdmission(admission)
        _ = try fresh.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 0,
            bytes: Data(payment.encoded.prefix(128))
        ))
        XCTAssertEqual(try fresh.status().receivedPaymentBytes, 128)

        var restored = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            restoredPaymentAdmission: admission,
            profilePolicy: policy,
            limits: limits
        )
        XCTAssertEqual(restored.phase, .paymentReceiving)
        XCTAssertEqual(
            try restored.status().receivedPaymentBytes,
            0,
            "IPA1 never claims streamed payment bytes survived process death"
        )
        guard case .alreadyAdmitted = try restored.preparePaymentAdmission(begin) else {
            return XCTFail("restored exact BEGIN must be idempotent")
        }
        try writeRemaining(
            payment.encoded,
            to: &restored,
            paymentHash: payment.wireHash,
            offset: 0
        )
        let commit = IrohaPeerNfcCommandV1.commit(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentWireHash: payment.wireHash
        )
        guard case .requiresDurableCommit(let commitContext) =
            try restored.prepareCommit(commit) else {
            return XCTFail("complete restored payment must require durable COMMIT")
        }
        let durable = try IrohaPeerNfcDurableAcknowledgementV1(
            context: commitContext,
            acknowledgement: acknowledgement.encoded,
            limits: limits
        )
        try restored.installDurableAcknowledgement(durable)

        var withBoth = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            durableAcknowledgement: durable,
            restoredPaymentAdmission: admission,
            profilePolicy: policy,
            limits: limits
        )
        XCTAssertEqual(withBoth.phase, .acknowledgementReady)
        XCTAssertThrowsError(try withBoth.preparePaymentAdmission(begin)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .stateMismatch)
        }
        _ = try withBoth.handle(.confirmAcknowledgement(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            acknowledgementWireHash: acknowledgement.wireHash
        ))
        XCTAssertEqual(withBoth.phase, .complete)
        XCTAssertThrowsError(try withBoth.preparePaymentAdmission(begin)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .stateMismatch)
        }

        let conflictingPayment = try message(kind: .payment, byte: 0x54, count: 530)
        let conflictingContext = try IrohaPeerNfcPaymentAdmissionContextV1(
            identity: context.identity,
            profilePolicy: policy,
            paymentHeader: conflictingPayment.header.bytes,
            limits: limits
        )
        let conflictingAdmission = try IrohaPeerNfcDurablePaymentAdmissionV1(
            context: conflictingContext,
            limits: limits
        )
        XCTAssertThrowsError(try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            durableAcknowledgement: durable,
            restoredPaymentAdmission: conflictingAdmission,
            profilePolicy: policy,
            limits: limits
        )) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
    }

    func testDurableAdmissionDecodeRejectsRedundantFieldMutation() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 128,
            maximumWriteChunkBytes: 128
        )
        let request = try message(kind: .request, byte: 0x55, count: 260)
        let payment = try message(kind: .payment, byte: 0x56, count: 530)
        let receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits
        )
        guard case .requiresDurableAdmission(let context) =
            try receiver.preparePaymentAdmission(.beginPayment(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash,
                paymentHeader: payment.header.bytes
            )) else {
            return XCTFail("current wallet BEGIN must require durable admission")
        }
        let encoded = try IrohaPeerNfcDurablePaymentAdmissionV1(
            context: context,
            limits: limits
        ).encoded
        var mutated = encoded
        mutated[96] ^= 1
        XCTAssertThrowsError(try IrohaPeerNfcDurablePaymentAdmissionV1.decode(mutated)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .continuityMismatch)
        }
    }

    func testCommitFailureCannotExposeAcknowledgement() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 200,
            maximumWriteChunkBytes: 200
        )
        let request = try message(kind: .request, byte: 0x61, count: 100)
        let payment = try message(kind: .payment, byte: 0x62, count: 300)
        let acknowledgement = try message(kind: .credited, byte: 0x63, count: 100)
        var receiver = try readyReceiver(
            request: request,
            payment: payment,
            limits: limits
        )
        let commit = try IrohaPeerNfcAPDUCodecV1.encode(.commit(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentWireHash: payment.wireHash
        ))
        let failed = receiver.process(
            apdu: commit,
            durableCommit: { _ in
                throw TestFailure.expected
            }
        )
        XCTAssertEqual(failed.statusWord, .storageFailure)
        XCTAssertEqual(receiver.phase, .paymentReceiving)
        XCTAssertFalse(try receiver.status().flags.contains(.durableAcknowledgement))

        let succeeded = receiver.process(
            apdu: commit,
            durableCommit: { context in
                try IrohaPeerNfcDurableAcknowledgementV1(
                    context: context,
                    acknowledgement: acknowledgement.encoded,
                    limits: limits
                )
            }
        )
        XCTAssertEqual(succeeded.statusWord, .success)
        XCTAssertEqual(receiver.phase, .acknowledgementReady)
        XCTAssertTrue(try receiver.status().flags.contains(.durableAcknowledgement))
    }

    func testTwoTapReducerResumesExactPaymentAndPersistsAckBeforeConfirm() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 97,
            maximumWriteChunkBytes: 113
        )
        let request = try message(kind: .request, byte: 0x71, count: 140)
        let payment = try message(kind: .payment, byte: 0x72, count: 490)
        let acknowledgement = try message(kind: .credited, byte: 0x73, count: 200)
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            limits: limits
        )
        XCTAssertEqual(
            try IrohaPeerNfcSenderCheckpointV1.decode(checkpoint.encoded, limits: limits),
            checkpoint
        )
        var reducer = IrohaPeerNfcTwoTapReducerV1(checkpoint: checkpoint, limits: limits)
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: limits
        )
        try reducer.requireSamePeer(receiver.info())

        try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        XCTAssertEqual(receiver.phase, .paymentReceiving)

        // First contact transfers only one chunk, then RF is lost.
        try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        let firstTapProgress = try receiver.status().receivedPaymentBytes
        XCTAssertGreaterThan(firstTapProgress, 0)
        XCTAssertLessThan(firstTapProgress, payment.encoded.count)

        // Second contact starts from receiver-authoritative progress and reuses
        // the exact checkpointed payment rather than creating a replacement.
        while try receiver.status().receivedPaymentBytes < payment.encoded.count {
            try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        }
        let commitAction = try reducer.nextAction(observing: receiver.status())
        guard case .send(let commitCommand) = commitAction else {
            return XCTFail("expected COMMIT")
        }
        let commitContext: IrohaPeerNfcCommitContextV1
        switch try receiver.prepareCommit(commitCommand) {
        case .alreadyCommitted:
            return XCTFail("payment was not previously committed")
        case .requiresDurableCommit(let context):
            commitContext = context
        }
        let record = try IrohaPeerNfcDurableAcknowledgementV1(
            context: commitContext,
            acknowledgement: acknowledgement.encoded,
            limits: limits
        )
        _ = record.encoded // receiver store fsync/transaction boundary
        try receiver.installDurableAcknowledgement(record)

        while true {
            let action = try reducer.nextAction(observing: receiver.status())
            switch action {
            case .send(let command):
                guard case .readAcknowledgement = command else {
                    return XCTFail("CONFIRM_ACK cannot precede durable sender persistence")
                }
                let chunk = try receiver.handle(command)
                try reducer.consumeAcknowledgementChunk(chunk)
            case .persistAcknowledgement(let bytes):
                XCTAssertEqual(bytes, acknowledgement.encoded)
                var persistedCheckpoint = Data()
                try reducer.persistAcknowledgement { persistedCheckpoint = $0 }
                XCTAssertEqual(
                    try IrohaPeerNfcSenderCheckpointV1.decode(
                        persistedCheckpoint,
                        limits: limits
                    ).durableAcknowledgement,
                    acknowledgement
                )
                break
            case .complete:
                return XCTFail("receiver is not complete yet")
            }
            if reducer.checkpoint.durableAcknowledgement != nil { break }
        }

        let confirm = try reducer.nextAction(observing: receiver.status())
        try executeSendAction(confirm, on: &receiver)
        XCTAssertEqual(receiver.phase, .complete)
        XCTAssertEqual(
            try reducer.nextAction(observing: receiver.status()),
            .complete(acknowledgement.encoded)
        )

        // A lost CONFIRM_ACK response remains complete after reconstructing
        // the reducer from the durable sender checkpoint on another tap.
        let restoredCheckpoint = try IrohaPeerNfcSenderCheckpointV1.decode(
            reducer.checkpoint.encoded,
            limits: limits
        )
        var restoredReducer = IrohaPeerNfcTwoTapReducerV1(
            checkpoint: restoredCheckpoint,
            limits: limits
        )
        XCTAssertEqual(
            try restoredReducer.nextAction(observing: receiver.status()),
            .complete(acknowledgement.encoded)
        )
    }

    func testEveryInstructionResponseCanBeLostWithAndroidSafeChunks() throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let request = try message(kind: .request, byte: 0x81, count: 420)
        let payment = try message(kind: .payment, byte: 0x82, count: 820)
        let acknowledgement = try message(kind: .credited, byte: 0x83, count: 200)
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: limits
        )

        // SELECT and GET_INFO are read-only and byte-identical on retry.
        let select = IrohaPeerNfcCommandV1.selectApplication
        _ = try receiver.handle(select) // response lost
        XCTAssertEqual(try receiver.handle(select), Data())
        _ = try receiver.handle(.getInfo) // response lost
        let info = try IrohaPeerNfcInfoV1.decode(try receiver.handle(.getInfo))
        XCTAssertEqual(info.maximumReadChunkBytes, 240)
        XCTAssertEqual(info.maximumWriteChunkBytes, 240)

        // READ_REQUEST has no receiver mutation. Losing the first response and
        // retrying the same u32 offset yields the same bytes.
        let firstRequestRead = try IrohaPeerNfcReaderPlanningV1.readRequestCommand(
            for: info,
            offset: 0
        )
        let lostRequestChunk = try receiver.handle(firstRequestRead)
        XCTAssertEqual(try receiver.handle(firstRequestRead), lostRequestChunk)
        var assembledRequest = lostRequestChunk
        while assembledRequest.count < info.requestLength {
            let command = try IrohaPeerNfcReaderPlanningV1.readRequestCommand(
                for: info,
                offset: assembledRequest.count
            )
            assembledRequest.append(try receiver.handle(command))
        }
        XCTAssertEqual(assembledRequest, request.encoded)

        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: assembledRequest,
            payment: payment.encoded,
            limits: limits
        )
        var reducer = IrohaPeerNfcTwoTapReducerV1(checkpoint: checkpoint, limits: limits)

        // GET_STATUS is also retryable after a lost response.
        let getStatus = IrohaPeerNfcReaderPlanningV1.getStatusCommand(for: info)
        _ = try receiver.handle(getStatus) // response lost
        var status = try IrohaPeerNfcStatusV1.decode(try receiver.handle(getStatus))

        // BEGIN_PAYMENT response loss: replaying the exact header is a no-op.
        let beginAction = try reducer.nextAction(observing: status)
        guard case .send(let begin) = beginAction else { return XCTFail("expected BEGIN_PAYMENT") }
        try admit(begin, to: &receiver) // response lost
        XCTAssertNoThrow(try admit(begin, to: &receiver))

        // WRITE response loss: replay the same range; receiver progress must
        // remain contiguous with no duplicated bytes.
        status = try receiver.status()
        let writeAction = try reducer.nextAction(observing: status)
        guard case .send(let firstWrite) = writeAction else { return XCTFail("expected WRITE") }
        _ = try receiver.handle(firstWrite) // response lost
        let progressAfterLostWrite = try receiver.status().receivedPaymentBytes
        XCTAssertNoThrow(try receiver.handle(firstWrite))
        XCTAssertEqual(try receiver.status().receivedPaymentBytes, progressAfterLostWrite)
        while try receiver.status().receivedPaymentBytes < payment.encoded.count {
            try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        }

        // COMMIT response loss occurs after the durable record is installed.
        guard case .send(let commit) = try reducer.nextAction(observing: receiver.status()),
              case .requiresDurableCommit(let context) = try receiver.prepareCommit(commit) else {
            return XCTFail("expected durable COMMIT")
        }
        let durableRecord = try IrohaPeerNfcDurableAcknowledgementV1(
            context: context,
            acknowledgement: acknowledgement.encoded,
            limits: limits
        )
        _ = durableRecord.encoded // durable receiver journal write
        try receiver.installDurableAcknowledgement(durableRecord)
        XCTAssertEqual(try receiver.prepareCommit(commit), .alreadyCommitted)

        // READ_ACK response loss leaves the sender offset unchanged, so the
        // same read is issued and returns the same bytes.
        status = try receiver.status()
        guard case .send(let firstAckRead) = try reducer.nextAction(observing: status) else {
            return XCTFail("expected READ_ACK")
        }
        let lostAckChunk = try receiver.handle(firstAckRead)
        guard case .send(let retriedAckRead) = try reducer.nextAction(observing: status) else {
            return XCTFail("expected retried READ_ACK")
        }
        XCTAssertEqual(retriedAckRead, firstAckRead)
        XCTAssertEqual(try receiver.handle(retriedAckRead), lostAckChunk)
        try reducer.consumeAcknowledgementChunk(lostAckChunk)
        while reducer.checkpoint.durableAcknowledgement == nil {
            switch try reducer.nextAction(observing: receiver.status()) {
            case .send(let command):
                try reducer.consumeAcknowledgementChunk(try receiver.handle(command))
            case .persistAcknowledgement:
                try reducer.persistAcknowledgement { _ in }
            case .complete:
                return XCTFail("cannot complete before CONFIRM_ACK")
            }
        }

        // CONFIRM_ACK response loss is resolved by COMPLETE status. An exact
        // replay is idempotent if a platform retries before observing status.
        guard case .send(let confirm) = try reducer.nextAction(observing: receiver.status()) else {
            return XCTFail("expected CONFIRM_ACK")
        }
        _ = try receiver.handle(confirm) // response lost
        XCTAssertNoThrow(try receiver.handle(confirm))
        XCTAssertEqual(
            try reducer.nextAction(observing: receiver.status()),
            .complete(acknowledgement.encoded)
        )
    }

    func testWalletSessionStaysSingleProfile() throws {
        let walletPayment = try message(
            profile: .kagemushaWalletV1,
            kind: .payment,
            byte: 0x92,
            count: 360
        )

        let request = try message(
            profile: .kagemushaWalletV1,
            kind: .request,
            byte: 0x94,
            count: 120
        )
        let payment = walletPayment
        let acknowledgement = try message(
            profile: .kagemushaWalletV1,
            kind: .credited,
            byte: 0x93,
            count: 140
        )
        let policy = IrohaPeerNfcProfilePolicyV1(profile: .kagemushaWalletV1)
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            profilePolicy: policy,
            limits: limits
        )
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            profilePolicy: policy,
            limits: limits
        )
        var reducer = IrohaPeerNfcTwoTapReducerV1(checkpoint: checkpoint, limits: limits)
        try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        while try receiver.status().receivedPaymentBytes < payment.encoded.count {
            try executeSendAction(try reducer.nextAction(observing: receiver.status()), on: &receiver)
        }
        guard case .send(let commit) = try reducer.nextAction(observing: receiver.status()),
              case .requiresDurableCommit(let context) = try receiver.prepareCommit(commit) else {
            return XCTFail("expected wallet COMMIT")
        }
        XCTAssertEqual(context.identity.profile, .kagemushaWalletV1)
        XCTAssertEqual(context.payment.profile, .kagemushaWalletV1)
        let record = try IrohaPeerNfcDurableAcknowledgementV1(
            context: context,
            acknowledgement: acknowledgement.encoded,
            limits: limits
        )
        XCTAssertEqual(record.paymentProfile, .kagemushaWalletV1)
        XCTAssertEqual(record.acknowledgement.profile, .kagemushaWalletV1)
        XCTAssertEqual(
            try IrohaPeerNfcDurableAcknowledgementV1.decode(record.encoded, limits: limits),
            record
        )
        XCTAssertEqual(
            try IrohaPeerNfcDurableAcknowledgementV1.decode(
                record.encoded,
                profilePolicy: policy,
                limits: limits
            ),
            record
        )
        try receiver.installDurableAcknowledgement(record)
        let status = try receiver.status()
        XCTAssertEqual(status.identity.profile, .kagemushaWalletV1)
        XCTAssertEqual(status.paymentProfile, .kagemushaWalletV1)
        XCTAssertEqual(status.acknowledgementProfile, .kagemushaWalletV1)
        XCTAssertEqual(try IrohaPeerNfcStatusV1.decode(status.encode()), status)
    }

    func testPortableReaderIntersectsLocal240WithReceiver4096() throws {
        let portable = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let receiverLimits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 4_096,
            maximumWriteChunkBytes: 4_096
        )
        let request = try message(kind: .request, byte: 0xA1, count: 880)
        let payment = try message(kind: .payment, byte: 0xA2, count: 1_100)
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xA3,
            count: 200
        )
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: receiverLimits
        )
        let info = try receiver.info()
        guard case .readRequest(_, _, _, let requestLength) =
            try IrohaPeerNfcReaderPlanningV1.readRequestCommand(
                for: info,
                offset: 0,
                localLimits: portable
            ) else {
            return XCTFail("expected READ_REQUEST")
        }
        XCTAssertEqual(requestLength, 240)

        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            limits: receiverLimits
        )
        var reducer = IrohaPeerNfcTwoTapReducerV1(
            checkpoint: checkpoint,
            limits: portable
        )
        try executeSendAction(
            try reducer.nextAction(observing: receiver.status()),
            on: &receiver
        )
        guard case .send(.write(_, _, _, let writeBytes)) =
            try reducer.nextAction(observing: receiver.status()) else {
            return XCTFail("expected WRITE")
        }
        XCTAssertEqual(writeBytes.count, 240)

        while try receiver.status().receivedPaymentBytes < payment.encoded.count {
            try executeSendAction(
                try reducer.nextAction(observing: receiver.status()),
                on: &receiver
            )
        }
        guard case .send(let commit) = try reducer.nextAction(observing: receiver.status()),
              case .requiresDurableCommit(let context) = try receiver.prepareCommit(commit) else {
            return XCTFail("expected COMMIT")
        }
        try receiver.installDurableAcknowledgement(
            IrohaPeerNfcDurableAcknowledgementV1(
                context: context,
                acknowledgement: acknowledgement.encoded,
                limits: receiverLimits
            )
        )
        guard case .send(.readAcknowledgement(_, _, _, let acknowledgementLength)) =
            try reducer.nextAction(observing: receiver.status()) else {
            return XCTFail("expected READ_ACK")
        }
        XCTAssertEqual(acknowledgementLength, 240)
    }

    func testReaderExchangeStreamsOneContactWithBoundedStatusSyncs() async throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let request = try message(
            kind: .request,
            byte: 0xB1,
            count: 730
        )
        let payment = try message(
            kind: .payment,
            byte: 0xB2,
            count: 1_330
        )
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xB3,
            count: 200
        )
        let loopback = try IrohaPeerNfcAsyncLoopbackV1(
            sessionID: sessionID,
            request: request,
            payment: payment,
            acknowledgement: acknowledgement,
            limits: limits
        )

        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits,
            transceive: { command in
                try await loopback.transceive(command)
            },
            loadOrCreateDurableCheckpoint: { info, receivedRequest in
                let checkpoint = try await loopback.makeCheckpoint(
                    info: info,
                    request: receivedRequest
                )
                await loopback.persist(checkpoint.encoded)
                return checkpoint
            },
            updateDurableCheckpoint: { checkpoint in
                await loopback.persist(checkpoint)
            }
        )

        let snapshot = await loopback.snapshot()
        XCTAssertEqual(result.acknowledgement, acknowledgement)
        XCTAssertEqual(result.checkpoint.durableAcknowledgement, acknowledgement)
        XCTAssertEqual(result.confirmationState, .confirmed)
        XCTAssertEqual(snapshot.checkpointCreationCount, 1)
        XCTAssertEqual(snapshot.receiverDurableCommitCount, 1)
        XCTAssertEqual(snapshot.persistedCheckpoints.count, 2)
        XCTAssertEqual(snapshot.commandCount(.selectApplication), 1)
        XCTAssertEqual(snapshot.commandCount(.getInfo), 1)
        XCTAssertEqual(
            snapshot.commandCount(.readRequest),
            request.encoded.count.roundedUpChunkCount(chunkBytes: 240)
        )
        XCTAssertEqual(
            snapshot.commandCount(.write),
            payment.encoded.count.roundedUpChunkCount(chunkBytes: 240)
        )
        XCTAssertEqual(
            snapshot.commandCount(.readAcknowledgement),
            acknowledgement.encoded.count.roundedUpChunkCount(chunkBytes: 240)
        )
        XCTAssertEqual(snapshot.commandCount(.beginPayment), 1)
        XCTAssertEqual(snapshot.commandCount(.commit), 1)
        XCTAssertEqual(snapshot.commandCount(.confirmAcknowledgement), 1)
        XCTAssertEqual(
            snapshot.commandCount(.getStatus),
            3,
            "one contact should status-sync only at entry and phase transitions"
        )
    }

    func testReaderExchangeNeverCreatesValueForNonRequestReadyPeer() async throws {
        let request = try message(
            kind: .request,
            byte: 0xBD,
            count: 320
        )
        let identity = try identity(for: request)

        for phase in [
            IrohaPeerNfcPhaseV1.paymentReceiving,
            .acknowledgementReady,
            .complete,
        ] {
            var flags: IrohaPeerNfcFlagsV1 = [.idempotentWrites]
            if phase == .acknowledgementReady || phase == .complete {
                flags.insert(.durableAcknowledgement)
            }
            let info = try IrohaPeerNfcInfoV1(
                phase: phase,
                flags: flags,
                identity: identity,
                requestLength: request.encoded.count,
                maximumReadChunkBytes: 240,
                maximumWriteChunkBytes: 240
            )
            let probe = IrohaPeerNfcNonReadyInfoProbeV1(info: info)

            do {
                _ = try await IrohaPeerNfcReaderExchangeV1.run(
                    profilePolicy: .init(profile: .kagemushaWalletV1),
                    limits: IrohaPeerNfcLimitsV1(
                        maximumReadChunkBytes: 240,
                        maximumWriteChunkBytes: 240
                    ),
                    transceive: { command in
                        try await probe.transceive(command)
                    },
                    loadOrCreateDurableCheckpoint: { info, request in
                        try await probe.makeCheckpoint(
                            info: info,
                            request: request
                        )
                    },
                    updateDurableCheckpoint: { checkpoint in
                        await probe.persist(checkpoint)
                    }
                )
                XCTFail("expected non-request-ready phase \(phase) to fail")
            } catch let error as IrohaPeerNfcErrorV1 {
                XCTAssertEqual(error, .stateMismatch)
            }

            let snapshot = await probe.snapshot()
            XCTAssertEqual(snapshot.makeCheckpointCount, 0)
            XCTAssertEqual(snapshot.persistCheckpointCount, 0)
            XCTAssertEqual(snapshot.commandCount, 2)
        }
    }

    func testReaderExchangeDefaultActionBudgetCoversWorstCaseOneByteChunks() {
        XCTAssertEqual(
            IrohaPeerNfcReaderExchangeV1.defaultMaximumActions,
            3 * IrohaPeerNfcV1.maximumMessageBytes + 16
        )
    }

    func testDefaultNfcLimitCarriesExactMaximumWalletIPM() throws {
        // Bounds DATA only: the maximum-size companion does not establish AccountId authority.
        let request = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            irohaPeerWalletExchangeEnvelopeV1(kind: .request, frameBytes: 10_000),
            destinationAccountOriginal: Data(repeating: 0xbc, count: 4_096))
        let payment = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            irohaPeerWalletExchangeEnvelopeV1(kind: .payment, frameBytes: 10_000))
        XCTAssertEqual(request.encoded.count, IrohaPeerNfcV1.maximumMessageBytes)
        XCTAssertEqual(IrohaPeerNfcV1.maximumMessageBytes, 14_196)
        XCTAssertEqual(payment.encoded.count, 10_084)

        let receiver = try readyReceiver(
            request: request,
            payment: payment,
            limits: .default
        )
        let commit = IrohaPeerNfcCommandV1.commit(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentWireHash: payment.wireHash
        )
        guard case .requiresDurableCommit(let context) = try receiver.prepareCommit(commit) else {
            return XCTFail("expected durable commit at exact IPM ceiling")
        }
        XCTAssertEqual(context.payment, payment)

        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: KagemushaWalletWireV1.messageMaximumBytes + 1
            )
        )) {
            XCTAssertEqual(
                $0 as? IrohaPeerWireMessageErrorV1,
                .canonicalLengthOutOfRange(actual: 10_001, maximum: 10_000)
            )
        }
    }

    func testOneBytePeerCannotEscapeWholeReaderExchangeActionBudget() async throws {
        let request = try message(
            kind: .request,
            byte: 0xBE,
            count: 300
        )
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: try identity(for: request),
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 1,
            maximumWriteChunkBytes: 1
        )
        let probe = IrohaPeerNfcOneByteRequestProbeV1(
            info: info,
            request: request.encoded
        )

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .init(profile: .kagemushaWalletV1),
                maximumActions: 6,
                transceive: { command in
                    try await probe.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { info, receivedRequest in
                    try await probe.makeCheckpoint(
                        info: info,
                        request: receivedRequest
                    )
                },
                updateDurableCheckpoint: { checkpoint in
                    await probe.persist(checkpoint)
                }
            )
            XCTFail("expected the whole-exchange action budget to fail closed")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .stateMismatch)
        }

        let snapshot = await probe.snapshot()
        XCTAssertEqual(snapshot.commands.count, 6)
        XCTAssertEqual(
            snapshot.commands.filter { command in
                if case .readRequest(_, _, _, 1) = command { return true }
                return false
            }.count,
            4
        )
        XCTAssertEqual(snapshot.makeCheckpointCount, 0)
        XCTAssertEqual(snapshot.persistCheckpointCount, 0)
    }

    func testReaderExchangeChargesFreshDurableCheckpointBeforeValueCreation() async throws {
        let request = try message(
            kind: .request,
            byte: 0xBF,
            count: 24
        )
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: try identity(for: request),
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 1,
            maximumWriteChunkBytes: 1
        )
        let probe = IrohaPeerNfcOneByteRequestProbeV1(
            info: info,
            request: request.encoded
        )

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .init(profile: .kagemushaWalletV1),
                maximumActions: 2 + request.encoded.count,
                transceive: { command in
                    try await probe.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { info, receivedRequest in
                    try await probe.makeCheckpoint(
                        info: info,
                        request: receivedRequest
                    )
                },
                updateDurableCheckpoint: { checkpoint in
                    await probe.persist(checkpoint)
                }
            )
            XCTFail("expected budget exhaustion before value creation")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .stateMismatch)
        }

        let snapshot = await probe.snapshot()
        XCTAssertEqual(snapshot.commands.count, 2 + request.encoded.count)
        XCTAssertEqual(snapshot.makeCheckpointCount, 0)
        XCTAssertEqual(snapshot.persistCheckpointCount, 0)
    }

    func testRestoredReaderExchangeChargesStatusProbeAfterSelectionAndInfo() async throws {
        let request = try message(
            kind: .request,
            byte: 0xC0,
            count: 40
        )
        let payment = try message(kind: .payment, byte: 0xC1, count: 40)
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xC2,
            count: 40
        )
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            limits: limits
        )
        let loopback = try IrohaPeerNfcAsyncLoopbackV1(
            sessionID: sessionID,
            request: request,
            payment: payment,
            acknowledgement: acknowledgement,
            limits: limits
        )

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                restoredCheckpoint: checkpoint.encoded,
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits,
                maximumActions: 2,
                transceive: { command in
                    try await loopback.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { _, _ in
                    throw IrohaPeerNfcErrorV1.stateMismatch
                },
                updateDurableCheckpoint: { checkpoint in
                    await loopback.persist(checkpoint)
                }
            )
            XCTFail("expected budget exhaustion before GET_STATUS")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .stateMismatch)
        }

        let snapshot = await loopback.snapshot()
        XCTAssertEqual(snapshot.commands.count, 2)
        XCTAssertEqual(snapshot.commandCount(.selectApplication), 1)
        XCTAssertEqual(snapshot.commandCount(.getInfo), 1)
        XCTAssertEqual(snapshot.commandCount(.getStatus), 0)
        XCTAssertTrue(snapshot.persistedCheckpoints.isEmpty)
    }

    func testReaderExchangeChargesDurableAcknowledgementTransition() async throws {
        let request = try message(
            kind: .request,
            byte: 0xC3,
            count: 40
        )
        let payment = try message(kind: .payment, byte: 0xC4, count: 40)
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xC5,
            count: 40
        )
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let loopback = try IrohaPeerNfcAsyncLoopbackV1(
            sessionID: sessionID,
            request: request,
            payment: payment,
            acknowledgement: acknowledgement,
            limits: limits
        )
        let actionsBeforeAcknowledgementPersistence = 8
            + request.encoded.count.roundedUpChunkCount(chunkBytes: 240)
            + payment.encoded.count.roundedUpChunkCount(chunkBytes: 240)
            + acknowledgement.encoded.count.roundedUpChunkCount(chunkBytes: 240)

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits,
                maximumActions: actionsBeforeAcknowledgementPersistence,
                transceive: { command in
                    try await loopback.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { info, receivedRequest in
                    let checkpoint = try await loopback.makeCheckpoint(
                        info: info,
                        request: receivedRequest
                    )
                    await loopback.persist(checkpoint.encoded)
                    return checkpoint
                },
                updateDurableCheckpoint: { checkpoint in
                    await loopback.persist(checkpoint)
                }
            )
            XCTFail("expected budget exhaustion before ACK persistence")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .stateMismatch)
        }

        let snapshot = await loopback.snapshot()
        XCTAssertEqual(snapshot.commands.count, actionsBeforeAcknowledgementPersistence - 1)
        XCTAssertEqual(snapshot.persistedCheckpoints.count, 1)
        XCTAssertEqual(snapshot.commandCount(.getStatus), 3)
        XCTAssertEqual(snapshot.commandCount(.confirmAcknowledgement), 0)
    }

    func testAtomicCheckpointStoreFailureAndRequestReadyRestartCommitOneDebit() async throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let request = try message(
            kind: .request,
            byte: 0xD1,
            count: 300
        )
        let payment = try message(kind: .payment, byte: 0xD2, count: 400)
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xD3,
            count: 200
        )
        let loopback = try IrohaPeerNfcAsyncLoopbackV1(
            sessionID: sessionID,
            request: request,
            payment: payment,
            acknowledgement: acknowledgement,
            limits: limits
        )
        let store = IrohaPeerNfcTransactionalCheckpointStoreV1(
            payment: payment,
            limits: limits,
            failFirstLoadOrCreate: true
        )

        func run(
            maximumActions: Int = IrohaPeerNfcReaderExchangeV1.defaultMaximumActions
        ) async throws -> IrohaPeerNfcReaderExchangeResultV1 {
            try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits,
                maximumActions: maximumActions,
                transceive: { command in
                    try await loopback.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { info, receivedRequest in
                    try await store.loadOrCreate(
                        info: info,
                        request: receivedRequest
                    )
                },
                updateDurableCheckpoint: { encoded in
                    try await store.update(encoded)
                }
            )
        }

        do {
            _ = try await run()
            XCTFail("expected the transactional store failure")
        } catch IrohaPeerNfcTransactionalCheckpointStoreFailureV1.injected {
            // The transaction failed before either the debit or ISC1 committed.
        }
        var storeSnapshot = await store.snapshot()
        var loopbackSnapshot = await loopback.snapshot()
        XCTAssertEqual(storeSnapshot.durableDebitCount, 0)
        XCTAssertEqual(loopbackSnapshot.commandCount(.beginPayment), 0)

        let actionsThroughDurableStore =
            3 + request.encoded.count.roundedUpChunkCount(chunkBytes: 240)
        do {
            _ = try await run(maximumActions: actionsThroughDurableStore)
            XCTFail("expected exhaustion immediately after the durable store")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .stateMismatch)
        }
        storeSnapshot = await store.snapshot()
        loopbackSnapshot = await loopback.snapshot()
        XCTAssertEqual(storeSnapshot.durableDebitCount, 1)
        XCTAssertEqual(loopbackSnapshot.commandCount(.beginPayment), 0)

        let result = try await run()
        storeSnapshot = await store.snapshot()
        XCTAssertEqual(storeSnapshot.loadOrCreateCount, 3)
        XCTAssertEqual(storeSnapshot.creationAttemptCount, 2)
        XCTAssertEqual(storeSnapshot.durableDebitCount, 1)
        XCTAssertEqual(result.acknowledgement, acknowledgement)
    }

    func testAcknowledgementCheckpointStoreFailureNeverConfirmsAndResumes() async throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let request = try message(
            kind: .request,
            byte: 0xD4,
            count: 300
        )
        let payment = try message(kind: .payment, byte: 0xD5, count: 400)
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xD6,
            count: 200
        )
        let loopback = try IrohaPeerNfcAsyncLoopbackV1(
            sessionID: sessionID,
            request: request,
            payment: payment,
            acknowledgement: acknowledgement,
            limits: limits
        )
        let store = IrohaPeerNfcTransactionalCheckpointStoreV1(
            payment: payment,
            limits: limits,
            failFirstUpdate: true
        )

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits,
                transceive: { command in
                    try await loopback.transceive(command)
                },
                loadOrCreateDurableCheckpoint: { info, receivedRequest in
                    try await store.loadOrCreate(
                        info: info,
                        request: receivedRequest
                    )
                },
                updateDurableCheckpoint: { encoded in
                    try await store.update(encoded)
                }
            )
            XCTFail("expected the ACK checkpoint store failure")
        } catch IrohaPeerNfcTransactionalCheckpointStoreFailureV1.injected {
            // No CONFIRM_ACK may be emitted for a non-durable ACK.
        }

        let durableCheckpoint = await store.durableCheckpoint()
        let paymentOnlyCheckpoint = try XCTUnwrap(durableCheckpoint)
        XCTAssertNil(
            try IrohaPeerNfcSenderCheckpointV1.decode(
                paymentOnlyCheckpoint,
                profilePolicy: .init(profile: .kagemushaWalletV1),
                limits: limits
            ).durableAcknowledgement
        )
        var loopbackSnapshot = await loopback.snapshot()
        XCTAssertEqual(loopbackSnapshot.commandCount(.confirmAcknowledgement), 0)

        let result = try await IrohaPeerNfcReaderExchangeV1.run(
            restoredCheckpoint: paymentOnlyCheckpoint,
            profilePolicy: .init(profile: .kagemushaWalletV1),
            limits: limits,
            transceive: { command in
                try await loopback.transceive(command)
            },
            loadOrCreateDurableCheckpoint: { _, _ in
                throw IrohaPeerNfcErrorV1.stateMismatch
            },
            updateDurableCheckpoint: { encoded in
                try await store.update(encoded)
            }
        )
        let storeSnapshot = await store.snapshot()
        loopbackSnapshot = await loopback.snapshot()
        XCTAssertEqual(storeSnapshot.updateCount, 2)
        XCTAssertEqual(loopbackSnapshot.commandCount(.confirmAcknowledgement), 1)
        XCTAssertEqual(result.acknowledgement, acknowledgement)
    }

    func testStreamedReaderExchangeResumesEveryValuePhaseAfterLostResponse() async throws {
        let limits = IrohaPeerNfcLimitsV1(
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let request = try message(
            kind: .request,
            byte: 0xC1,
            count: 520
        )
        let payment = try message(
            kind: .payment,
            byte: 0xC2,
            count: 780
        )
        let acknowledgement = try message(
            kind: .credited,
            byte: 0xC3,
            count: 200
        )

        for lostResponse in [
            IrohaPeerNfcLoopbackCommandKindV1.write,
            .commit,
            .readAcknowledgement,
            .confirmAcknowledgement,
        ] {
            let loopback = try IrohaPeerNfcAsyncLoopbackV1(
                sessionID: sessionID,
                request: request,
                payment: payment,
                acknowledgement: acknowledgement,
                limits: limits,
                loseResponseFor: lostResponse
            )

            func run(
                restoredCheckpoint: Data? = nil
            ) async throws -> IrohaPeerNfcReaderExchangeResultV1 {
                try await IrohaPeerNfcReaderExchangeV1.run(
                    restoredCheckpoint: restoredCheckpoint,
                    profilePolicy: .init(profile: .kagemushaWalletV1),
                    limits: limits,
                    transceive: { command in
                        try await loopback.transceive(command)
                    },
                    loadOrCreateDurableCheckpoint: { info, receivedRequest in
                        let checkpoint = try await loopback.makeCheckpoint(
                            info: info,
                            request: receivedRequest
                        )
                        await loopback.persist(checkpoint.encoded)
                        return checkpoint
                    },
                    updateDurableCheckpoint: { checkpoint in
                        await loopback.persist(checkpoint)
                    }
                )
            }

            if case .confirmAcknowledgement = lostResponse {
                let result = try await run()
                let snapshot = await loopback.snapshot()
                XCTAssertEqual(result.acknowledgement, acknowledgement)
                XCTAssertEqual(result.checkpoint.durableAcknowledgement, acknowledgement)
                XCTAssertEqual(result.confirmationState, .responseUnknown)
                XCTAssertEqual(snapshot.checkpointCreationCount, 1)
                XCTAssertEqual(snapshot.receiverDurableCommitCount, 1)
                XCTAssertEqual(snapshot.persistedCheckpoints.count, 2)
                XCTAssertEqual(snapshot.commandCount(.selectApplication), 1)
                XCTAssertEqual(snapshot.commandCount(.confirmAcknowledgement), 1)
                continue
            } else {
                do {
                    _ = try await run()
                    XCTFail("expected one simulated \(lostResponse) response loss")
                } catch IrohaPeerNfcAsyncLoopbackFailureV1.responseLost {
                    // The receiver may have applied the APDU. Resume
                    // exclusively from status and the durable checkpoint.
                }
            }

            let interruptedSnapshot = await loopback.snapshot()
            let retryCheckpoint = try XCTUnwrap(
                interruptedSnapshot.persistedCheckpoints.last
            )
            let result = try await run(restoredCheckpoint: retryCheckpoint)
            let snapshot = await loopback.snapshot()
            XCTAssertEqual(result.acknowledgement, acknowledgement)
            XCTAssertEqual(snapshot.checkpointCreationCount, 1)
            XCTAssertEqual(snapshot.receiverDurableCommitCount, 1)
            XCTAssertEqual(snapshot.persistedCheckpoints.count, 2)
            XCTAssertEqual(snapshot.commandCount(.selectApplication), 2)
        }
    }

    func testUnknownProfileKindSessionAndHashSubstitutionFailClosed() throws {
        let request = try message(kind: .request, byte: 0x11, count: 90)
        let payment = try message(kind: .payment, byte: 0x12, count: 90)
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded
        )
        for rawProfile: UInt16 in [0, UInt16.max] {
            var forgedHeader = payment.header.bytes
            forgedHeader[6] = UInt8(rawProfile >> 8)
            forgedHeader[7] = UInt8(rawProfile & 0xFF)
            XCTAssertThrowsError(try receiver.preparePaymentAdmission(.beginPayment(
                sessionID: sessionID,
                requestCanonicalHash: request.canonicalHash,
                paymentHeader: forgedHeader
            ))) {
                XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidIPM1)
            }
        }

        var wrongSession = sessionID
        wrongSession[0] ^= 0x80
        let requestRead = try IrohaPeerNfcAPDUCodecV1.encode(.readRequest(
            sessionID: wrongSession,
            requestCanonicalHash: request.canonicalHash,
            offset: 0,
            length: 16
        ))
        XCTAssertEqual(
            receiver.process(apdu: requestRead).statusWord,
            .securityStatusNotSatisfied
        )

        var tamperedRequest = request.encoded
        tamperedRequest[tamperedRequest.count - 1] ^= 0x01
        XCTAssertThrowsError(try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: tamperedRequest
        )) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidHash)
        }

        XCTAssertThrowsError(try IrohaPeerNfcDurableAcknowledgementV1(
            context: IrohaPeerNfcCommitContextV1(
                identity: try identity(for: request),
                profilePolicy: .init(profile: .kagemushaWalletV1),
                receiveRequest: request,
                payment: payment
            ),
            acknowledgement: payment.encoded
        )) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidKind)
        }
    }

    private var zeroHash: Data {
        Data(repeating: 0, count: IrohaPeerNfcV1.hashBytes)
    }

    private func message(
        profile: IrohaPeerPayloadProfile = .kagemushaWalletV1,
        kind: IrohaPeerPayloadKind,
        byte: UInt8,
        count: Int
    ) throws -> IrohaPeerWireMessageV1 {
        let payload = Data(repeating: byte, count: count)
        if profile == .kagemushaWalletV1 {
            return try irohaPeerWalletExchangeMessageV1(kind: kind, payload: payload)
        }
        let canonicalPayload = payload
        return try IrohaPeerWireMessageV1(
            profile: profile,
            kind: kind,
            schemaVersion: profile.requiredSchemaVersion,
            canonicalPayload: canonicalPayload
        )
    }

    private func identity(
        for request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcRequestIdentityV1 {
        try IrohaPeerNfcRequestIdentityV1(
            profile: request.profile,
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            requestWireHash: request.wireHash
        )
    }

    private func writeRemaining(
        _ payment: Data,
        to receiver: inout IrohaPeerNfcReceiverSessionV1,
        paymentHash: Data,
        offset initialOffset: Int
    ) throws {
        var offset = initialOffset
        while offset < payment.count {
            let end = min(offset + receiver.limits.maximumWriteChunkBytes, payment.count)
            _ = try receiver.handle(.write(
                sessionID: sessionID,
                paymentWireHash: paymentHash,
                offset: UInt32(offset),
                bytes: payment.subdata(in: offset..<end)
            ))
            offset = end
        }
    }

    private func readyReceiver(
        request: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1,
        limits: IrohaPeerNfcLimitsV1
    ) throws -> IrohaPeerNfcReceiverSessionV1 {
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: limits
        )
        try admit(.beginPayment(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentHeader: payment.header.bytes
        ), to: &receiver)
        try writeRemaining(
            payment.encoded,
            to: &receiver,
            paymentHash: payment.wireHash,
            offset: 0
        )
        return receiver
    }

    private func executeSendAction(
        _ action: IrohaPeerNfcSenderActionV1,
        on receiver: inout IrohaPeerNfcReceiverSessionV1
    ) throws {
        guard case .send(let command) = action else {
            throw TestFailure.expected
        }
        if case .beginPayment = command {
            try admit(command, to: &receiver)
        } else {
            _ = try receiver.handle(command)
        }
    }

    private func admit(
        _ command: IrohaPeerNfcCommandV1,
        to receiver: inout IrohaPeerNfcReceiverSessionV1
    ) throws {
        switch try receiver.preparePaymentAdmission(command) {
        case .alreadyAdmitted:
            return
        case .requiresDurableAdmission(let context):
            try receiver.installPaymentAdmission(
                IrohaPeerNfcDurablePaymentAdmissionV1(context: context)
            )
        }
    }

    private enum TestFailure: Error {
        case expected
    }
}

private enum IrohaPeerNfcAsyncLoopbackFailureV1:
    IrohaPeerNfcAmbiguousResponseErrorV1 {
    case responseLost
    case commandLimitExceeded(Int)
    case commandAfterConfirmation
}

private actor IrohaPeerNfcNonReadyInfoProbeV1 {
    struct Snapshot: Sendable {
        let commandCount: Int
        let makeCheckpointCount: Int
        let persistCheckpointCount: Int
    }

    private let info: IrohaPeerNfcInfoV1
    private var commandCount = 0
    private var makeCheckpointCount = 0
    private var persistCheckpointCount = 0

    init(info: IrohaPeerNfcInfoV1) {
        self.info = info
    }

    func transceive(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcAPDUResponseV1 {
        commandCount += 1
        switch command {
        case .selectApplication:
            return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
        case .getInfo:
            return IrohaPeerNfcAPDUResponseV1(
                data: info.encode(),
                statusWord: .success
            )
        default:
            throw IrohaPeerNfcAsyncLoopbackFailureV1.commandLimitExceeded(
                commandCount
            )
        }
    }

    func makeCheckpoint(
        info: IrohaPeerNfcInfoV1,
        request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcSenderCheckpointV1 {
        makeCheckpointCount += 1
        throw IrohaPeerNfcAsyncLoopbackFailureV1.commandLimitExceeded(
            commandCount
        )
    }

    func persist(_ checkpoint: Data) {
        persistCheckpointCount += 1
    }

    func snapshot() -> Snapshot {
        Snapshot(
            commandCount: commandCount,
            makeCheckpointCount: makeCheckpointCount,
            persistCheckpointCount: persistCheckpointCount
        )
    }
}

private actor IrohaPeerNfcOneByteRequestProbeV1 {
    struct Snapshot: Sendable {
        let commands: [IrohaPeerNfcCommandV1]
        let makeCheckpointCount: Int
        let persistCheckpointCount: Int
    }

    private let info: IrohaPeerNfcInfoV1
    private let request: Data
    private var commands: [IrohaPeerNfcCommandV1] = []
    private var makeCheckpointCount = 0
    private var persistCheckpointCount = 0

    init(info: IrohaPeerNfcInfoV1, request: Data) {
        self.info = info
        self.request = request
    }

    func transceive(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcAPDUResponseV1 {
        commands.append(command)
        switch command {
        case .selectApplication:
            return IrohaPeerNfcAPDUResponseV1(statusWord: .success)

        case .getInfo:
            return IrohaPeerNfcAPDUResponseV1(
                data: info.encode(),
                statusWord: .success
            )

        case .readRequest(
            let sessionID,
            let requestCanonicalHash,
            let rawOffset,
            let length
        ):
            let offset = Int(rawOffset)
            guard sessionID == info.identity.sessionID,
                  requestCanonicalHash == info.identity.requestCanonicalHash,
                  length == 1,
                  offset < request.count else {
                throw IrohaPeerNfcErrorV1.stateMismatch
            }
            return IrohaPeerNfcAPDUResponseV1(
                data: request.subdata(in: offset..<(offset + 1)),
                statusWord: .success
            )

        default:
            throw IrohaPeerNfcErrorV1.stateMismatch
        }
    }

    func makeCheckpoint(
        info: IrohaPeerNfcInfoV1,
        request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcSenderCheckpointV1 {
        _ = info
        _ = request
        makeCheckpointCount += 1
        throw IrohaPeerNfcErrorV1.stateMismatch
    }

    func persist(_ checkpoint: Data) {
        _ = checkpoint
        persistCheckpointCount += 1
    }

    func snapshot() -> Snapshot {
        Snapshot(
            commands: commands,
            makeCheckpointCount: makeCheckpointCount,
            persistCheckpointCount: persistCheckpointCount
        )
    }
}


private enum IrohaPeerNfcTransactionalCheckpointStoreFailureV1: Error {
    case injected
}

private struct IrohaPeerNfcTransactionalCheckpointStoreSnapshotV1: Sendable {
    let loadOrCreateCount: Int
    let creationAttemptCount: Int
    let durableDebitCount: Int
    let updateCount: Int
}

private actor IrohaPeerNfcTransactionalCheckpointStoreV1 {
    private let payment: IrohaPeerWireMessageV1
    private let limits: IrohaPeerNfcLimitsV1
    private let profilePolicy = IrohaPeerNfcProfilePolicyV1(profile: .kagemushaWalletV1)
    private var encodedCheckpoint: Data?
    private var failNextLoadOrCreate: Bool
    private var failNextUpdate: Bool
    private var loadOrCreateCount = 0
    private var creationAttemptCount = 0
    private var durableDebitCount = 0
    private var updateCount = 0

    init(
        payment: IrohaPeerWireMessageV1,
        limits: IrohaPeerNfcLimitsV1,
        failFirstLoadOrCreate: Bool = false,
        failFirstUpdate: Bool = false
    ) {
        self.payment = payment
        self.limits = limits
        failNextLoadOrCreate = failFirstLoadOrCreate
        failNextUpdate = failFirstUpdate
    }

    func loadOrCreate(
        info: IrohaPeerNfcInfoV1,
        request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcSenderCheckpointV1 {
        loadOrCreateCount += 1
        if let encodedCheckpoint {
            return try IrohaPeerNfcSenderCheckpointV1.decode(
                encodedCheckpoint,
                profilePolicy: profilePolicy,
                limits: limits
            )
        }

        creationAttemptCount += 1
        let created = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: info.identity.sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            profilePolicy: profilePolicy,
            limits: limits
        )
        if failNextLoadOrCreate {
            failNextLoadOrCreate = false
            throw IrohaPeerNfcTransactionalCheckpointStoreFailureV1.injected
        }
        // The debit and exact ISC1 become visible in the same transaction.
        encodedCheckpoint = created.encoded
        durableDebitCount += 1
        return created
    }

    func update(_ candidateData: Data) throws {
        updateCount += 1
        if failNextUpdate {
            failNextUpdate = false
            throw IrohaPeerNfcTransactionalCheckpointStoreFailureV1.injected
        }
        guard let encodedCheckpoint else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        let existing = try IrohaPeerNfcSenderCheckpointV1.decode(
            encodedCheckpoint,
            profilePolicy: profilePolicy,
            limits: limits
        )
        let candidate = try IrohaPeerNfcSenderCheckpointV1.decode(
            candidateData,
            profilePolicy: profilePolicy,
            limits: limits
        )
        guard existing.identity == candidate.identity,
              existing.profilePolicy == candidate.profilePolicy,
              existing.receiveRequest == candidate.receiveRequest,
              existing.payment == candidate.payment,
              existing.durableAcknowledgement == nil,
              candidate.durableAcknowledgement != nil else {
            throw IrohaPeerNfcErrorV1.continuityMismatch
        }
        self.encodedCheckpoint = Data(candidateData)
    }

    func durableCheckpoint() -> Data? {
        encodedCheckpoint.map { Data($0) }
    }

    func snapshot() -> IrohaPeerNfcTransactionalCheckpointStoreSnapshotV1 {
        IrohaPeerNfcTransactionalCheckpointStoreSnapshotV1(
            loadOrCreateCount: loadOrCreateCount,
            creationAttemptCount: creationAttemptCount,
            durableDebitCount: durableDebitCount,
            updateCount: updateCount
        )
    }
}

private actor IrohaPeerNfcAsyncLoopbackV1 {
    private var receiver: IrohaPeerNfcReceiverSessionV1
    private let payment: IrohaPeerWireMessageV1
    private let acknowledgement: IrohaPeerWireMessageV1
    private let limits: IrohaPeerNfcLimitsV1
    private var commands: [IrohaPeerNfcCommandV1] = []
    private var checkpointCreationCount = 0
    private var receiverDurableCommitCount = 0
    private var persistedCheckpoints: [Data] = []
    private let responseLossKind: IrohaPeerNfcLoopbackCommandKindV1?
    private var didLosePlannedResponse = false
    private var didConfirmInCurrentContact = false

    init(
        sessionID: Data,
        request: IrohaPeerWireMessageV1,
        payment: IrohaPeerWireMessageV1,
        acknowledgement: IrohaPeerWireMessageV1,
        limits: IrohaPeerNfcLimitsV1,
        loseResponseFor responseLossKind:
            IrohaPeerNfcLoopbackCommandKindV1? = nil
    ) throws {
        receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: limits
        )
        self.payment = payment
        self.acknowledgement = acknowledgement
        self.limits = limits
        self.responseLossKind = responseLossKind
    }

    func transceive(
        _ command: IrohaPeerNfcCommandV1
    ) throws -> IrohaPeerNfcAPDUResponseV1 {
        if didConfirmInCurrentContact {
            guard case .selectApplication = command else {
                throw IrohaPeerNfcAsyncLoopbackFailureV1
                    .commandAfterConfirmation
            }
            didConfirmInCurrentContact = false
        }
        commands.append(command)
        guard commands.count <= 100 else {
            throw IrohaPeerNfcAsyncLoopbackFailureV1.commandLimitExceeded(
                commands.count
            )
        }
        let response: IrohaPeerNfcAPDUResponseV1
        if case .beginPayment = command {
            switch try receiver.preparePaymentAdmission(command) {
            case .alreadyAdmitted:
                break
            case .requiresDurableAdmission(let context):
                try receiver.installPaymentAdmission(
                    IrohaPeerNfcDurablePaymentAdmissionV1(context: context)
                )
            }
            response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
        } else if case .commit = command {
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
            response = IrohaPeerNfcAPDUResponseV1(statusWord: .success)
        } else {
            response = IrohaPeerNfcAPDUResponseV1(
                data: try receiver.handle(command),
                statusWord: .success
            )
        }
        if case .confirmAcknowledgement = command {
            didConfirmInCurrentContact = true
        }
        if !didLosePlannedResponse,
           let responseLossKind,
           command.matches(responseLossKind) {
            didLosePlannedResponse = true
            throw IrohaPeerNfcAsyncLoopbackFailureV1.responseLost
        }
        return response
    }

    func makeCheckpoint(
        info: IrohaPeerNfcInfoV1,
        request: IrohaPeerWireMessageV1
    ) throws -> IrohaPeerNfcSenderCheckpointV1 {
        checkpointCreationCount += 1
        return try IrohaPeerNfcSenderCheckpointV1(
            sessionID: info.identity.sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded,
            limits: limits
        )
    }

    func persist(_ checkpoint: Data) {
        persistedCheckpoints.append(checkpoint)
    }

    func snapshot() -> IrohaPeerNfcAsyncLoopbackSnapshotV1 {
        IrohaPeerNfcAsyncLoopbackSnapshotV1(
            commands: commands,
            checkpointCreationCount: checkpointCreationCount,
            receiverDurableCommitCount: receiverDurableCommitCount,
            persistedCheckpoints: persistedCheckpoints
        )
    }
}

private enum IrohaPeerNfcLoopbackCommandKindV1: Sendable {
    case selectApplication
    case getInfo
    case readRequest
    case beginPayment
    case write
    case commit
    case readAcknowledgement
    case confirmAcknowledgement
    case getStatus
}

private struct IrohaPeerNfcAsyncLoopbackSnapshotV1: Sendable {
    let commands: [IrohaPeerNfcCommandV1]
    let checkpointCreationCount: Int
    let receiverDurableCommitCount: Int
    let persistedCheckpoints: [Data]

    func commandCount(_ kind: IrohaPeerNfcLoopbackCommandKindV1) -> Int {
        commands.reduce(into: 0) { count, command in
            if command.matches(kind) { count += 1 }
        }
    }
}

private extension IrohaPeerNfcCommandV1 {
    func matches(_ kind: IrohaPeerNfcLoopbackCommandKindV1) -> Bool {
        switch (kind, self) {
        case (.selectApplication, .selectApplication),
             (.getInfo, .getInfo),
             (.readRequest, .readRequest),
             (.beginPayment, .beginPayment),
             (.write, .write),
             (.commit, .commit),
             (.readAcknowledgement, .readAcknowledgement),
             (.confirmAcknowledgement, .confirmAcknowledgement),
             (.getStatus, .getStatus):
            return true
        default:
            return false
        }
    }
}

private extension Int {
    func roundedUpChunkCount(chunkBytes: Int) -> Int {
        (self + chunkBytes - 1) / chunkBytes
    }
}
