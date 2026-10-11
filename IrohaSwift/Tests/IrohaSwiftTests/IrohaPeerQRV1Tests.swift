import XCTest
@testable import IrohaSwift

private final class IrohaPeerQRClockProbeV1: @unchecked Sendable {
    private let lock = NSLock()
    private var active = 0
    private var maximum = 0
    private var nextTime: TimeInterval = 1
    private var errors = 0

    func now() -> TimeInterval {
        lock.lock()
        active += 1
        maximum = max(maximum, active)
        let value = nextTime
        nextTime += 1
        lock.unlock()
        Thread.sleep(forTimeInterval: 0.005)
        lock.lock(); active -= 1; lock.unlock()
        return value
    }

    func recordError() { lock.lock(); errors += 1; lock.unlock() }
    var result: (maximum: Int, errors: Int) {
        lock.lock(); defer { lock.unlock() }
        return (maximum, errors)
    }
}

final class IrohaPeerQRV1Tests: XCTestCase {

    func testStaticRequestPreservesMandatoryAccountCompanion() throws {
        let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: .request, payload: Data([0x31]))
        let account = try irohaPeerWalletRequestAccountOriginalV1()
        let request = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            envelope, destinationAccountOriginal: account)
        let text = try XCTUnwrap(IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: request))
        let session = IrohaPeerQRScanSessionV1(expectedProfile: .kagemushaWalletV1,
            expectedKind: .request, expectedSchemaVersion: 1)
        guard case let .completed(decoded) = try session.ingest(text)
        else { return XCTFail("expected complete Request carrier") }
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded), account)
    }

    func testAnimatedRequestPreservesMandatoryAccountCompanion() throws {
        let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: .request,
            payload: deterministicBytes(count: 2_048, seed: 0x32))
        let account = try irohaPeerWalletRequestAccountOriginalV1()
        let request = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            envelope, destinationAccountOriginal: account)
        let session = IrohaPeerQRScanSessionV1(expectedProfile: .kagemushaWalletV1,
            expectedKind: .request, expectedSchemaVersion: 1)
        var completed: IrohaPeerWireMessageV1?
        for text in try IrohaPeerQRCodecV1.animatedFrameTexts(for: request) {
            if case let .completed(decoded) = try session.ingest(text) {
                completed = decoded
                break
            }
        }
        let decoded = try XCTUnwrap(completed)
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded), account)
    }

    func testScanLimitHardCeilingsRejectConfigurationEscapeHatches() {
        XCTAssertTrue(IrohaPeerQRScanLimitsV1.areValid(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 30,
            absoluteTimeout: 180
        ))
        XCTAssertFalse(IrohaPeerQRScanLimitsV1.areValid(
            maximumActiveStreams: 4,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 30,
            absoluteTimeout: 180
        ))
        XCTAssertFalse(IrohaPeerQRScanLimitsV1.areValid(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 13,
            maximumPreheaderPayloadBytesPerStream: 3_073,
            idleTimeout: 31,
            absoluteTimeout: 181
        ))
        XCTAssertFalse(IrohaPeerQRScanLimitsV1.areValid(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: .infinity,
            absoluteTimeout: .infinity
        ))
    }

    func testImplicitClockIsSampledInsideSessionSerialization() {
        let probe = IrohaPeerQRClockProbeV1()
        let session = IrohaPeerQRScanSessionV1(clock: { probe.now() })
        let group = DispatchGroup()
        for _ in 0..<16 {
            group.enter()
            DispatchQueue.global().async {
                do { _ = try session.expire() } catch { probe.recordError() }
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(probe.result.errors, 0)
        XCTAssertEqual(probe.result.maximum, 1)
    }

    func testRFC9285Base45AndCRC32CGoldenVectors() {
        XCTAssertEqual(IrohaBase45V1.encode(Data("AB".utf8)), "BB8")
        XCTAssertEqual(IrohaBase45V1.encode(Data("Hello!!".utf8)), "%69 VD92EX0")
        XCTAssertEqual(IrohaBase45V1.encode(Data("base-45".utf8)), "UJCLQE7W581")
        XCTAssertEqual(IrohaBase45V1.decode("BB8"), Data("AB".utf8))
        XCTAssertNil(IrohaBase45V1.decode("a"))
        XCTAssertEqual(
            IrohaPeerCRC32CV1.checksum(Data("123456789".utf8)),
            0xE306_9283
        )
    }

    func testFrameLayoutIsBigEndianAndTextIsStrict() throws {
        let message = try makeMessage(count: 600, seed: 9)
        let texts = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
        let dataText = try XCTUnwrap(texts.first(where: {
            (try? IrohaPeerQRCodecV1.decodeFrame($0).frameKind) == .data
        }))
        let frame = try IrohaPeerQRCodecV1.decodeFrame(dataText)
        let encoded = frame.encoded
        XCTAssertEqual(Data(encoded[0..<4]), Data("IRQR".utf8))
        XCTAssertEqual(encoded[4], 1)
        XCTAssertEqual(encoded[5], 2)
        XCTAssertEqual(readUInt16BE(encoded, 6), 1)
        XCTAssertEqual(encoded[8], IrohaPeerWireKindV1.payment.rawValue)
        XCTAssertEqual(encoded[9], 0)
        XCTAssertEqual(Data(encoded[10..<26]), message.streamID)
        XCTAssertEqual(readUInt16BE(encoded, 28), 3)
        XCTAssertEqual(readUInt16BE(encoded, 30), 256)
        XCTAssertEqual(readUInt32BE(encoded, encoded.count - 4), IrohaPeerCRC32CV1.checksum(encoded.dropLast(4)))
        XCTAssertTrue(dataText.hasPrefix("IQR1:"))
        XCTAssertTrue(dataText.hasSuffix(":"))
        XCTAssertThrowsError(try IrohaPeerQRCodecV1.decodeFrame(" \(dataText)")) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .malformedText)
        }

        var badCRC = encoded
        badCRC[badCRC.count - 1] ^= 1
        let corruptedText = "IQR1:\(IrohaBase45V1.encode(badCRC)):"
        XCTAssertThrowsError(try IrohaPeerQRCodecV1.decodeFrame(corruptedText)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .checksumMismatch)
        }

        let oversizedText = "IQR1:" + String(repeating: "0", count: 700) + ":"
        XCTAssertThrowsError(try IrohaPeerQRCodecV1.decodeFrame(oversizedText)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .frameTextTooLarge(
                    actual: oversizedText.utf8.count,
                    maximum: IrohaPeerQRCodecV1.maximumStaticTextBytes
                )
            )
        }

        XCTAssertThrowsError(
            try IrohaPeerQRFrameV1(
                frameKind: .complete,
                profile: message.profile,
                payloadKind: message.kind,
                streamID: message.streamID,
                index: 0,
                total: 1,
                payload: Data(message.encoded.prefix(IrohaPeerWireMessageV1.headerBytes))
            )
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidFrameShape)
        }
    }

    func testStaticCandidateAndFixedPairParitySequence() throws {
        let small = try makeMessage(count: 80, seed: 1)
        let staticText = try XCTUnwrap(
            IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: small)
        )
        for nonCanonical in [" \(staticText)", "\(staticText)\t", "\n\(staticText)"] {
            XCTAssertThrowsError(try IrohaPeerQRScanSessionV1().ingest(nonCanonical)) {
                XCTAssertEqual($0 as? IrohaPeerQRErrorV1, .malformedText)
            }
        }
        XCTAssertLessThanOrEqual(
            staticText.utf8.count,
            IrohaPeerQRCodecV1.maximumStaticTextBytes
        )
        let staticEvent = try IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment,
            expectedSchemaVersion: 1
        ).ingest(staticText)
        guard case .completed(let staticDecoded) = staticEvent else {
            return XCTFail("Expected complete-frame decoding")
        }
        XCTAssertEqual(staticDecoded, small)

        let message = try makeMessage(count: 600, seed: 2)
        XCTAssertNil(try IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: message))
        let frames = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
            .map { try IrohaPeerQRCodecV1.decodeFrame($0) }
        XCTAssertEqual(frames.map(\.frameKind), [.header, .data, .data, .parity, .data, .parity])
        XCTAssertTrue(frames.allSatisfy { $0.total == 3 })
        XCTAssertTrue(frames.filter { $0.frameKind == .data || $0.frameKind == .parity }
            .allSatisfy { $0.payload.count == 256 })

        let d0 = try XCTUnwrap(frames.first { $0.frameKind == .data && $0.index == 0 })
        let d1 = try XCTUnwrap(frames.first { $0.frameKind == .data && $0.index == 1 })
        let p0 = try XCTUnwrap(frames.first { $0.frameKind == .parity && $0.index == 0 })
        for index in 0..<256 { XCTAssertEqual(p0.payload[index], d0.payload[index] ^ d1.payload[index]) }
        let d2 = try XCTUnwrap(frames.first { $0.frameKind == .data && $0.index == 2 })
        let p1 = try XCTUnwrap(frames.first { $0.frameKind == .parity && $0.index == 1 })
        XCTAssertEqual(p1.payload, d2.payload)
        XCTAssertTrue(d2.payload[136..<256].allSatisfy { $0 == 0 })
    }

    func testStaticCandidatePreflightsExactBase45Boundary() throws {
        let largestStaticMessage = try makeMessage(count: 294, seed: 3)
        let staticText = try XCTUnwrap(
            IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: largestStaticMessage)
        )
        XCTAssertEqual(staticText.utf8.count, 699)

        let firstAnimatedMessage = try makeMessage(count: 295, seed: 4)
        XCTAssertNil(
            try IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: firstAnimatedMessage)
        )
    }

    func testHeaderRepeatsAfterTwelveNonHeaderShards() throws {
        let message = try makeMessage(count: 2_048, seed: 5)
        let frames = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
            .map { try IrohaPeerQRCodecV1.decodeFrame($0) }
        XCTAssertEqual(frames.count, 16)
        XCTAssertEqual(frames.first?.frameKind, .header)
        XCTAssertEqual(frames[13].frameKind, .header)
        XCTAssertEqual(frames.filter { $0.frameKind == .header }.count, 2)
        XCTAssertEqual(frames.filter { $0.frameKind != .header }.count, 14)
    }

    func testMaximumStreamFrameCountsAndRepeatedHeaderText() throws {
        let message = try makeMessage(
            count: IrohaPeerWireKindV1.payment.maximumWalletFrameBytes - 48,
            seed: 6
        )
        XCTAssertEqual(message.encodedBody.count, 10_000)
        let texts = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
        let frames = try texts.map { try IrohaPeerQRCodecV1.decodeFrame($0) }

        XCTAssertEqual(texts.count, 66)
        XCTAssertEqual(frames.filter { $0.frameKind == .header }.count, 6)
        XCTAssertEqual(frames.filter { $0.frameKind == .data }.count, 40)
        XCTAssertEqual(frames.filter { $0.frameKind == .parity }.count, 20)
        let headerTexts = zip(texts, frames).compactMap { text, frame in
            frame.frameKind == .header ? text : nil
        }
        XCTAssertEqual(Set(headerTexts).count, 1)
    }

    func testMaximumRequestCompanionRecoversLostShardAndPreservesBothOriginals() throws {
        let envelope = irohaPeerWalletStructuralEnvelopeV1(
            kind: .request,
            frameBytes: KagemushaWalletWireV1.messageMaximumBytes
        )
        // Bounded transport DATA; account authentication belongs to Native.
        let account = deterministicBytes(count: IrohaPeerWalletRequestV1.maximumAccountBytes, seed: 7)
        let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(
            envelope, destinationAccountOriginal: account)
        XCTAssertEqual(message.encodedBody.count, 14_112)
        XCTAssertNil(try IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: message))
        let texts = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
        let frames = try texts.map { try IrohaPeerQRCodecV1.decodeFrame($0) }
        XCTAssertEqual(texts.count, 92)
        XCTAssertEqual(frames.filter { $0.frameKind == .header }.count, 8)
        XCTAssertEqual(frames.filter { $0.frameKind == .data }.count, 56)
        XCTAssertEqual(frames.filter { $0.frameKind == .parity }.count, 28)
        XCTAssertTrue(frames.allSatisfy { $0.total == 56 })
        let lost = try XCTUnwrap(frames.firstIndex { $0.frameKind == .data && $0.index == 53 })
        let session = IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .request,
            expectedSchemaVersion: 1
        )
        var completed: IrohaPeerWireMessageV1?
        var recoveredDataShards = 0
        for (index, text) in texts.enumerated() where index != lost {
            switch try session.ingest(text, atUptime: 0) {
            case let .accepted(progress), let .duplicate(progress):
                recoveredDataShards = max(recoveredDataShards, progress.recoveredDataShards)
            case let .completed(decoded):
                completed = decoded
            }
            if completed != nil { break }
        }
        XCTAssertEqual(recoveredDataShards, 1)
        let decoded = try XCTUnwrap(completed)
        XCTAssertEqual(decoded, message)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), envelope)
        XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.destinationAccountOriginal(decoded), account)
    }

    func testRequestCompanionBoundDoesNotPermitOversizedCompressedPayments() throws {
        let envelope = irohaPeerWalletStructuralEnvelopeV1(kind: .payment, frameBytes: 10_001)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: envelope,
            compressionPolicy: .peerOptimized
        )) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1,
                           .canonicalLengthOutOfRange(actual: 10_001, maximum: 10_000))
        }
    }

    func testOutOfOrderPreheaderFramesAndPairParityRecoverMessage() throws {
        let message = try makeMessage(count: 600, seed: 12)
        let frames = try indexedFrames(message)
        let session = IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment,
            expectedSchemaVersion: 1
        )
        _ = try session.ingest(try text(frames[.data, 0]))
        _ = try session.ingest(try text(frames[.parity, 0]))
        _ = try session.ingest(try text(frames[.data, 2]))
        let event = try session.ingest(try text(frames[.header, 0]))
        guard case .completed(let decoded) = event else {
            return XCTFail("Expected parity-assisted completion")
        }
        XCTAssertEqual(decoded, message)
        XCTAssertEqual(decoded.canonicalPayload, message.canonicalPayload)
    }

    func testConflictingDuplicateQuarantinesOnlyThatStream() throws {
        let message = try makeMessage(count: 600, seed: 21)
        let frames = try indexedFrames(message)
        let original = try XCTUnwrap(frames[FrameLookup(kind: .data, index: 0)])
        var changedPayload = original.payload
        changedPayload[0] ^= 1
        let conflict = try IrohaPeerQRFrameV1(
            frameKind: .data,
            profile: original.profile,
            payloadKind: original.payloadKind,
            streamID: original.streamID,
            index: original.index,
            total: original.total,
            payload: changedPayload
        )
        let session = IrohaPeerQRScanSessionV1()
        _ = try session.ingest(IrohaPeerQRCodecV1.encodeFrame(original))
        XCTAssertThrowsError(try session.ingest(IrohaPeerQRCodecV1.encodeFrame(conflict))) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .conflictingDuplicate)
        }
        XCTAssertEqual(session.activeStreamCount, 0)
        XCTAssertThrowsError(try session.ingest(IrohaPeerQRCodecV1.encodeFrame(original))) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
    }

    func testDecoderBoundsThreeStreams() throws {
        let session = IrohaPeerQRScanSessionV1(expectedProfile: .kagemushaWalletV1)
        var firstTexts: [String] = []
        for seed in 1...4 {
            let message = try makeMessage(count: 600, seed: UInt8(seed))
            let frames = try indexedFrames(message)
            firstTexts.append(try text(frames[.data, 0]))
        }
        for text in firstTexts.prefix(3) { _ = try session.ingest(text) }
        XCTAssertEqual(session.activeStreamCount, 3)
        XCTAssertThrowsError(try session.ingest(firstTexts[3])) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .tooManyActiveStreams(maximum: 3))
        }
        XCTAssertEqual(session.activeStreamCount, 3)

        let kindSession = IrohaPeerQRScanSessionV1(expectedKind: .credited)
        let paymentText = try XCTUnwrap(
            IrohaPeerQRCodecV1.staticCompleteTextCandidate(
                for: try makeMessage(count: 80, seed: 89)
            )
        )
        XCTAssertThrowsError(try kindSession.ingest(paymentText)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .unexpectedKind(expected: .credited, actual: .payment)
            )
        }
        XCTAssertThrowsError(try kindSession.ingest(paymentText)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
    }

    func testApplicationCanBoundAndExpireCompletedStreamQuarantine() throws {
        let limits = IrohaPeerQRScanLimitsV1(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 1,
            absoluteTimeout: 3
        )
        let message = try makeMessage(count: 80, seed: 91)
        let text = try XCTUnwrap(IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: message))
        let session = IrohaPeerQRScanSessionV1(scanLimits: limits)
        guard case .completed(let completed) = try session.ingest(text, atUptime: 100) else {
            return XCTFail("Expected structural IPM1 completion")
        }
        XCTAssertEqual(completed, message)
        XCTAssertEqual(session.activeStreamCount, 0)

        try session.quarantine(streamID: completed.streamID, atUptime: 100)
        XCTAssertThrowsError(try session.ingest(text, atUptime: 102.999)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
        guard case .completed(let retried) = try session.ingest(text, atUptime: 103) else {
            return XCTFail("Expected reuse at the quarantine deadline")
        }
        XCTAssertEqual(retried, message)
        XCTAssertThrowsError(
            try session.quarantine(streamID: Data(repeating: 0, count: 15), atUptime: 104)
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidFrameShape)
        }

        let saturated = IrohaPeerQRScanSessionV1(scanLimits: limits)
        try saturated.quarantine(
            streamID: message.streamID,
            atUptime: .greatestFiniteMagnitude
        )
        XCTAssertThrowsError(
            try saturated.ingest(text, atUptime: .greatestFiniteMagnitude)
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
        _ = try saturated.expire(atUptime: .greatestFiniteMagnitude)
        XCTAssertThrowsError(
            try saturated.ingest(text, atUptime: .greatestFiniteMagnitude)
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }

        var bounded: [(message: IrohaPeerWireMessageV1, text: String)] = []
        for seed in 100..<113 {
            let item = try makeMessage(count: 80, seed: UInt8(seed))
            bounded.append((
                item,
                try XCTUnwrap(IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: item))
            ))
        }
        for (index, item) in bounded.enumerated() {
            try session.quarantine(
                streamID: item.message.streamID,
                atUptime: 200 + Double(index) / 100
            )
        }
        // The quarantine table is capped at twelve, so the oldest of thirteen
        // application-rejected streams is reusable without affecting the rest.
        guard case .completed = try session.ingest(bounded[0].text, atUptime: 201) else {
            return XCTFail("Expected bounded quarantine eviction")
        }
        XCTAssertThrowsError(try session.ingest(bounded[1].text, atUptime: 201)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
    }

    func testInjectedUptimeMustBeFiniteNonnegativeAndMonotonicUntilReset() throws {
        let message = try makeMessage(count: 80, seed: 92)
        let text = try XCTUnwrap(IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: message))
        for invalid in [-1.0, Double.nan, Double.infinity, -Double.infinity] {
            let session = IrohaPeerQRScanSessionV1()
            XCTAssertThrowsError(try session.ingest(text, atUptime: invalid)) { error in
                XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
            }
            XCTAssertThrowsError(
                try session.quarantine(streamID: message.streamID, atUptime: invalid)
            ) { error in
                XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
            }
            XCTAssertThrowsError(try session.expire(atUptime: invalid)) { error in
                XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
            }
            XCTAssertEqual(session.activeStreamCount, 0)
        }

        let poisonedClock = IrohaPeerQRScanSessionV1(clock: { .nan })
        XCTAssertThrowsError(try poisonedClock.ingest(text)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
        }
        XCTAssertThrowsError(try poisonedClock.quarantine(streamID: message.streamID)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
        }
        XCTAssertThrowsError(try poisonedClock.expire()) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
        }

        let monotonic = IrohaPeerQRScanSessionV1()
        XCTAssertEqual(try monotonic.expire(atUptime: 100), [])
        for operation in [
            { try monotonic.ingest(text, atUptime: 99) as Any },
            { try monotonic.quarantine(streamID: message.streamID, atUptime: 99) as Any },
            { try monotonic.expire(atUptime: 99) as Any }
        ] {
            XCTAssertThrowsError(try operation()) { error in
                XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidUptime)
            }
        }
        monotonic.reset()
        guard case .completed = try monotonic.ingest(text, atUptime: 99) else {
            return XCTFail("Reset must establish a new monotonic clock epoch")
        }
    }

    func testPreheaderIdleAndAbsoluteBounds() throws {
        let message = try makeMessage(count: 2_560, seed: 44)
        let allFrames = try IrohaPeerQRCodecV1.animatedFrameTexts(for: message)
            .map { try IrohaPeerQRCodecV1.decodeFrame($0) }
        let nonHeaders = allFrames.filter { $0.frameKind != .header }
        XCTAssertGreaterThanOrEqual(nonHeaders.count, 13)
        let bounded = IrohaPeerQRScanSessionV1()
        for frame in nonHeaders.prefix(12) {
            _ = try bounded.ingest(IrohaPeerQRCodecV1.encodeFrame(frame))
        }
        XCTAssertThrowsError(try bounded.ingest(IrohaPeerQRCodecV1.encodeFrame(nonHeaders[12]))) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .preheaderLimitExceeded)
        }

        let timeLimits = IrohaPeerQRScanLimitsV1(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 2,
            absoluteTimeout: 3
        )
        let timed = IrohaPeerQRScanSessionV1(scanLimits: timeLimits)
        let start: TimeInterval = 1_000
        _ = try timed.ingest(IrohaPeerQRCodecV1.encodeFrame(nonHeaders[0]), atUptime: start)
        _ = try timed.ingest(IrohaPeerQRCodecV1.encodeFrame(nonHeaders[1]), atUptime: start + 1.5)
        XCTAssertEqual(try timed.expire(atUptime: start + 2.9), [])
        XCTAssertEqual(timed.activeStreamCount, 1)
        XCTAssertEqual(try timed.expire(atUptime: start + 3), [message.streamID])
        XCTAssertEqual(timed.activeStreamCount, 0)

        let idle = IrohaPeerQRScanSessionV1(scanLimits: timeLimits)
        _ = try idle.ingest(IrohaPeerQRCodecV1.encodeFrame(nonHeaders[0]), atUptime: start)
        XCTAssertEqual(try idle.expire(atUptime: start + 2), [message.streamID])
    }

    func testChecksumCorrectHostileHeaderIsQuarantinedUntilExactExpiry() throws {
        let message = try makeMessage(count: 600, seed: 61)
        let frames = try indexedFrames(message)
        let validHeader = try XCTUnwrap(frames[.header, 0])
        var hostileHeaderPayload = validHeader.payload
        hostileHeaderPayload[9] = 1 // Reserved IPM1 flags, protected by a fresh IRQR CRC below.
        let hostileHeader = try IrohaPeerQRFrameV1(
            frameKind: .header,
            profile: validHeader.profile,
            payloadKind: validHeader.payloadKind,
            streamID: validHeader.streamID,
            index: validHeader.index,
            total: validHeader.total,
            payload: hostileHeaderPayload
        )
        XCTAssertEqual(
            try IrohaPeerQRCodecV1.decodeFrame(
                IrohaPeerQRCodecV1.encodeFrame(hostileHeader)
            ),
            hostileHeader
        )

        let limits = IrohaPeerQRScanLimitsV1(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 1,
            absoluteTimeout: 3
        )
        let session = IrohaPeerQRScanSessionV1(scanLimits: limits)
        let start: TimeInterval = 5_000
        XCTAssertThrowsError(
            try session.ingest(
                IrohaPeerQRCodecV1.encodeFrame(hostileHeader),
                atUptime: start
            )
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidHeader)
        }
        XCTAssertEqual(session.activeStreamCount, 0)
        XCTAssertThrowsError(
            try session.ingest(
                IrohaPeerQRCodecV1.encodeFrame(validHeader),
                atUptime: start + 2.999
            )
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }

        let accepted = try session.ingest(
            IrohaPeerQRCodecV1.encodeFrame(validHeader),
            atUptime: start + 3
        )
        guard case .accepted(let progress) = accepted else {
            return XCTFail("Expected clean stream reuse at the quarantine deadline")
        }
        XCTAssertEqual(progress.streamID, message.streamID)
        XCTAssertEqual(session.activeStreamCount, 1)
    }

    func testChecksumCorrectHostileCompleteBodyAndPaddingFailClosed() throws {
        let small = try makeMessage(count: 80, seed: 62)
        var corruptMessage = small.encoded
        corruptMessage[corruptMessage.count - 1] ^= 1
        let hostileComplete = try IrohaPeerQRFrameV1(
            frameKind: .complete,
            profile: small.profile,
            payloadKind: small.kind,
            streamID: small.streamID,
            index: 0,
            total: 1,
            payload: corruptMessage
        )
        let completeSession = IrohaPeerQRScanSessionV1()
        XCTAssertThrowsError(
            try completeSession.ingest(IrohaPeerQRCodecV1.encodeFrame(hostileComplete))
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidMessage)
        }
        XCTAssertEqual(completeSession.activeStreamCount, 0)

        let animated = try makeMessage(count: 300, seed: 63)
        let frames = try indexedFrames(animated)
        let header = try XCTUnwrap(frames[.header, 0])
        let first = try XCTUnwrap(frames[.data, 0])
        let final = try XCTUnwrap(frames[.data, 1])
        var nonzeroPaddedPayload = final.payload
        nonzeroPaddedPayload[nonzeroPaddedPayload.count - 1] = 1
        let hostileFinal = try IrohaPeerQRFrameV1(
            frameKind: .data,
            profile: final.profile,
            payloadKind: final.payloadKind,
            streamID: final.streamID,
            index: final.index,
            total: final.total,
            payload: nonzeroPaddedPayload
        )
        let animatedSession = IrohaPeerQRScanSessionV1()
        _ = try animatedSession.ingest(IrohaPeerQRCodecV1.encodeFrame(header))
        _ = try animatedSession.ingest(IrohaPeerQRCodecV1.encodeFrame(first))
        XCTAssertThrowsError(
            try animatedSession.ingest(IrohaPeerQRCodecV1.encodeFrame(hostileFinal))
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .invalidMessage)
        }
        XCTAssertEqual(animatedSession.activeStreamCount, 0)
        XCTAssertThrowsError(
            try animatedSession.ingest(IrohaPeerQRCodecV1.encodeFrame(header))
        ) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
    }

    func testExpectedSchemaQuarantinesCompleteAndAnimatedStreamUntilExpiry() throws {
        let limits = IrohaPeerQRScanLimitsV1(
            maximumActiveStreams: 3,
            maximumPreheaderFramesPerStream: 12,
            maximumPreheaderPayloadBytesPerStream: 3_072,
            idleTimeout: 1,
            absoluteTimeout: 3
        )
        let staticMessage = try makeMessage(count: 80, seed: 71)
        let staticText = try XCTUnwrap(
            IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: staticMessage)
        )
        let staticSession = IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment,
            expectedSchemaVersion: 2,
            scanLimits: limits
        )
        XCTAssertThrowsError(try staticSession.ingest(staticText, atUptime: 100)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .unexpectedSchemaVersion(expected: 2, actual: 1)
            )
        }
        XCTAssertThrowsError(try staticSession.ingest(staticText, atUptime: 102.999)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
        XCTAssertThrowsError(try staticSession.ingest(staticText, atUptime: 103)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .unexpectedSchemaVersion(expected: 2, actual: 1)
            )
        }

        let animatedMessage = try makeMessage(count: 2_048, seed: 72)
        let animated = try IrohaPeerQRCodecV1.animatedFrameTexts(for: animatedMessage)
        let headerTexts = try animated.filter {
            try IrohaPeerQRCodecV1.decodeFrame($0).frameKind == .header
        }
        let parityText = try XCTUnwrap(animated.first {
            (try? IrohaPeerQRCodecV1.decodeFrame($0).frameKind) == .parity
        })
        XCTAssertGreaterThanOrEqual(headerTexts.count, 2)
        let animatedSession = IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment,
            expectedSchemaVersion: 2,
            scanLimits: limits
        )
        XCTAssertThrowsError(try animatedSession.ingest(headerTexts[0], atUptime: 200)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .unexpectedSchemaVersion(expected: 2, actual: 1)
            )
        }
        XCTAssertThrowsError(try animatedSession.ingest(parityText, atUptime: 201)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
        XCTAssertThrowsError(try animatedSession.ingest(headerTexts[1], atUptime: 202.999)) { error in
            XCTAssertEqual(error as? IrohaPeerQRErrorV1, .streamQuarantined)
        }
        XCTAssertThrowsError(try animatedSession.ingest(headerTexts[1], atUptime: 203)) { error in
            XCTAssertEqual(
                error as? IrohaPeerQRErrorV1,
                .unexpectedSchemaVersion(expected: 2, actual: 1)
            )
        }

        let walletMessage = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                payload: deterministicBytes(count: 20, seed: 73)
            )
        )
        let walletText = try XCTUnwrap(
            IrohaPeerQRCodecV1.staticCompleteTextCandidate(for: walletMessage)
        )
        let accepted = try IrohaPeerQRScanSessionV1(
            expectedProfile: .kagemushaWalletV1,
            expectedKind: .payment,
            expectedSchemaVersion: 1
        ).ingest(walletText)
        guard case .completed(let decoded) = accepted else {
            return XCTFail("Expected configurable wallet schema completion")
        }
        XCTAssertEqual(decoded, walletMessage)
    }

    fileprivate struct FrameLookup: Hashable {
        let kind: IrohaPeerQRFrameKindV1
        let index: Int
    }

    private func indexedFrames(_ message: IrohaPeerWireMessageV1) throws
        -> [FrameLookup: IrohaPeerQRFrameV1]
    {
        var result: [FrameLookup: IrohaPeerQRFrameV1] = [:]
        for text in try IrohaPeerQRCodecV1.animatedFrameTexts(for: message) {
            let frame = try IrohaPeerQRCodecV1.decodeFrame(text)
            result[FrameLookup(kind: frame.frameKind, index: frame.index)] = frame
        }
        return result
    }

    private func text(_ frame: IrohaPeerQRFrameV1?) throws -> String {
        IrohaPeerQRCodecV1.encodeFrame(try XCTUnwrap(frame))
    }

    /// Structural Payment whose canonical wallet envelope is exactly `48 + count` bytes, so each
    /// count fixes the shard layout; the opaque field is seeded by `seed`.
    private func makeMessage(
        count: Int,
        seed: UInt8,
        schemaVersion: UInt16 = 1
    ) throws -> IrohaPeerWireMessageV1 {
        try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: schemaVersion,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: 48 + count,
                filler: { self.deterministicBytes(count: $0, seed: seed) }
            )
        )
    }

    private func deterministicBytes(count: Int, seed: UInt8) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: Int(seed) + $0 * 73) })
    }

    private func readUInt16BE(_ data: Data, _ offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private func readUInt32BE(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24
            | UInt32(data[offset + 1]) << 16
            | UInt32(data[offset + 2]) << 8
            | UInt32(data[offset + 3])
    }
}

private extension Dictionary where Key == IrohaPeerQRV1Tests.FrameLookup,
                                   Value == IrohaPeerQRFrameV1 {
    subscript(_ kind: IrohaPeerQRFrameKindV1, _ index: Int) -> IrohaPeerQRFrameV1? {
        self[IrohaPeerQRV1Tests.FrameLookup(kind: kind, index: index)]
    }
}
