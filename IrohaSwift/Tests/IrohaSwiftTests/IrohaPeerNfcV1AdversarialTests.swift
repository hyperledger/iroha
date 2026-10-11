import XCTest
@testable import IrohaSwift

final class IrohaPeerNfcV1AdversarialTests: XCTestCase {
    private let sessionID = Data((1...16).map(UInt8.init))

    func testAPDUDecoderRejectsNonCanonicalExtendedLengthAliases() throws {
        let getInfoCase2E = Data([0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x62])
        assertInvalidAPDU(getInfoCase2E)

        let hash = Data(repeating: 0x31, count: 32)
        let write = try IrohaPeerNfcAPDUCodecV1.encode(.write(
            sessionID: sessionID,
            paymentWireHash: hash,
            offset: 0,
            bytes: Data([0x55])
        ))
        XCTAssertNotEqual(write[4], 0)
        let writeBody = write.subdata(in: 5..<write.count)
        var nonCanonicalWrite = Data([0x80, 0x21, 0x00, 0x00, 0x00])
        nonCanonicalWrite.append(0)
        nonCanonicalWrite.append(UInt8(writeBody.count))
        nonCanonicalWrite.append(writeBody)
        assertInvalidAPDU(nonCanonicalWrite)

        let status = try IrohaPeerNfcAPDUCodecV1.encode(.getStatus(
            sessionID: sessionID,
            requestCanonicalHash: hash
        ))
        let statusBody = status.subdata(in: 5..<(status.count - 1))
        var nonCanonicalStatus = Data([0x80, 0x25, 0x00, 0x00, 0x00])
        nonCanonicalStatus.append(0)
        nonCanonicalStatus.append(UInt8(statusBody.count))
        nonCanonicalStatus.append(statusBody)
        nonCanonicalStatus.append(contentsOf: [0, UInt8(IrohaPeerNfcV1.statusBytes)])
        assertInvalidAPDU(nonCanonicalStatus)
    }

    func testHashCorrectWrongPhaseHeaderAndExtremeOffsetsLeaveReceiverUnchanged() throws {
        let request = try message(kind: .request, byte: 0x41, count: 180)
        let payment = try message(kind: .payment, byte: 0x42, count: 300)
        let acknowledgement = try message(kind: .credited, byte: 0x43, count: 120)
        var receiver = try IrohaPeerNfcReceiverSessionV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            limits: IrohaPeerNfcLimitsV1(
                maximumReadChunkBytes: 128,
                maximumWriteChunkBytes: 128
            )
        )

        XCTAssertThrowsError(try receiver.preparePaymentAdmission(.beginPayment(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentHeader: acknowledgement.header.bytes
        ))) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidIPM1)
        }
        XCTAssertEqual(receiver.phase, .requestReady)

        XCTAssertThrowsError(try receiver.handle(.readRequest(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            offset: UInt32.max,
            length: 1
        ))) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidOffset)
        }

        let beginPayment = IrohaPeerNfcCommandV1.beginPayment(
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            paymentHeader: payment.header.bytes
        )
        guard case let .requiresDurableAdmission(context) = try receiver.preparePaymentAdmission(
            beginPayment
        ) else {
            return XCTFail("fresh payment must require a durable admission record")
        }
        try receiver.installPaymentAdmission(
            IrohaPeerNfcDurablePaymentAdmissionV1(context: context)
        )
        _ = try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 0,
            bytes: payment.encoded.prefix(100)
        ))
        XCTAssertThrowsError(try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: UInt32.max,
            bytes: Data([0x01])
        ))) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidOffset)
        }

        var conflictingExtension = payment.encoded.subdata(in: 50..<150)
        conflictingExtension[0] ^= 0x80
        XCTAssertThrowsError(try receiver.handle(.write(
            sessionID: sessionID,
            paymentWireHash: payment.wireHash,
            offset: 50,
            bytes: conflictingExtension
        ))) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .conflictingReplay)
        }
        XCTAssertEqual(try receiver.status().receivedPaymentBytes, 100)
    }

    func testPeerAdvertisementsAndPersistedU32LengthsRespectLocalBounds() throws {
        let request = try message(kind: .request, byte: 0x51, count: 300)
        let payment = try message(kind: .payment, byte: 0x52, count: 300)
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: request.profile,
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            requestWireHash: request.wireHash
        )
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: identity,
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let local = IrohaPeerNfcLimitsV1(
            maximumMessageBytes: 128,
            maximumReadChunkBytes: 128,
            maximumWriteChunkBytes: 128
        )
        XCTAssertThrowsError(try IrohaPeerNfcReaderPlanningV1.readRequestCommand(
            for: info,
            offset: 0,
            localLimits: local
        )) {
            XCTAssertEqual(
                $0 as? IrohaPeerNfcErrorV1,
                .messageTooLarge(actual: request.encoded.count, maximum: 128)
            )
        }

        var hostileInfo = info.encode()
        hostileInfo[94] = 0xff
        hostileInfo[95] = 0xff
        XCTAssertThrowsError(try IrohaPeerNfcInfoV1.decode(hostileInfo)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidLength)
        }

        var checkpoint = try IrohaPeerNfcSenderCheckpointV1(
            sessionID: sessionID,
            receiveRequest: request.encoded,
            payment: payment.encoded
        ).encoded
        checkpoint.replaceSubrange(24..<28, with: repeatElement(UInt8.max, count: 4))
        XCTAssertThrowsError(try IrohaPeerNfcSenderCheckpointV1.decode(checkpoint)) {
            XCTAssertEqual($0 as? IrohaPeerNfcErrorV1, .invalidLength)
        }
    }

    func testReaderRejectsOversizeRequestBeforeReadOrValueCreation() async throws {
        let request = try message(kind: .request, byte: 0x61, count: 300)
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: request.profile,
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            requestWireHash: request.wireHash
        )
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: identity,
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 240,
            maximumWriteChunkBytes: 240
        )
        let local = IrohaPeerNfcLimitsV1(
            maximumMessageBytes: 128,
            maximumReadChunkBytes: 128,
            maximumWriteChunkBytes: 128
        )
        let observed = LockedCommands()

        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .sameProfile(.kagemushaWalletV1),
                limits: local,
                transceive: { command in
                    observed.append(command)
                    switch command {
                    case .selectApplication:
                        return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                    case .getInfo:
                        return IrohaPeerNfcAPDUResponseV1(
                            data: info.encode(),
                            statusWord: .success
                        )
                    default:
                        XCTFail("oversize INF1 must fail before a request read")
                        return IrohaPeerNfcAPDUResponseV1(statusWord: .wrongData)
                    }
                },
                loadOrCreateDurableCheckpoint: { _, _ in
                    XCTFail("oversize INF1 must fail before value creation")
                    throw TestFailure.unexpected
                },
                updateDurableCheckpoint: { _ in
                    XCTFail("oversize INF1 must not update a checkpoint")
                }
            )
            XCTFail("expected local message-bound rejection")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(
                error,
                .messageTooLarge(actual: request.encoded.count, maximum: 128)
            )
        }
        XCTAssertEqual(observed.types, ["select", "info"])
    }

    func testReaderRejectsUnexpectedControlResponseData() async throws {
        let observed = LockedCommands()
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .sameProfile(.kagemushaWalletV1),
                transceive: { command in
                    observed.append(command)
                    return IrohaPeerNfcAPDUResponseV1(
                        data: Data([0x00]),
                        statusWord: .success
                    )
                },
                loadOrCreateDurableCheckpoint: { _, _ in throw TestFailure.unexpected },
                updateDurableCheckpoint: { _ in }
            )
            XCTFail("expected non-empty SELECT response rejection")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .invalidLength)
        }
        XCTAssertEqual(observed.types, ["select"])
    }

    func testReaderRejectsResponseLongerThanRequestedRead() async throws {
        let request = try message(kind: .request, byte: 0x71, count: 120)
        let identity = try IrohaPeerNfcRequestIdentityV1(
            profile: request.profile,
            sessionID: sessionID,
            requestCanonicalHash: request.canonicalHash,
            requestWireHash: request.wireHash
        )
        let info = try IrohaPeerNfcInfoV1(
            phase: .requestReady,
            flags: [.idempotentWrites],
            identity: identity,
            requestLength: request.encoded.count,
            maximumReadChunkBytes: 1,
            maximumWriteChunkBytes: 1
        )
        let observed = LockedCommands()
        do {
            _ = try await IrohaPeerNfcReaderExchangeV1.run(
                profilePolicy: .sameProfile(.kagemushaWalletV1),
                transceive: { command in
                    observed.append(command)
                    switch command {
                    case .selectApplication:
                        return IrohaPeerNfcAPDUResponseV1(statusWord: .success)
                    case .getInfo:
                        return IrohaPeerNfcAPDUResponseV1(
                            data: info.encode(),
                            statusWord: .success
                        )
                    case .readRequest:
                        return IrohaPeerNfcAPDUResponseV1(
                            data: Data([0x71, 0x71]),
                            statusWord: .success
                        )
                    default:
                        throw TestFailure.unexpected
                    }
                },
                loadOrCreateDurableCheckpoint: { _, _ in throw TestFailure.unexpected },
                updateDurableCheckpoint: { _ in }
            )
            XCTFail("expected overlong READ response rejection")
        } catch let error as IrohaPeerNfcErrorV1 {
            XCTAssertEqual(error, .invalidLength)
        }
        XCTAssertEqual(observed.types, ["select", "info", "read"])
    }

    private func message(
        kind: IrohaPeerPayloadKind,
        byte: UInt8,
        count: Int
    ) throws -> IrohaPeerWireMessageV1 {
        try irohaPeerWalletExchangeMessageV1(kind: kind, payload: Data(repeating: byte, count: count))
    }

    private func assertInvalidAPDU(
        _ apdu: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try IrohaPeerNfcAPDUCodecV1.decode(apdu),
            file: file,
            line: line
        ) {
            XCTAssertEqual(
                $0 as? IrohaPeerNfcErrorV1,
                .invalidAPDU,
                file: file,
                line: line
            )
        }
    }
}

private final class LockedCommands: @unchecked Sendable {
    private let lock = NSLock()
    private var commands: [IrohaPeerNfcCommandV1] = []

    func append(_ command: IrohaPeerNfcCommandV1) {
        lock.lock()
        commands.append(command)
        lock.unlock()
    }

    var types: [String] {
        lock.lock()
        defer { lock.unlock() }
        return commands.map {
            switch $0 {
            case .selectApplication: return "select"
            case .getInfo: return "info"
            case .readRequest: return "read"
            default: return "other"
            }
        }
    }
}

private enum TestFailure: Error {
    case unexpected
}
