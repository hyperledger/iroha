import XCTest
@testable import IrohaSwift

final class IrohaPeerWireMessageV1Tests: XCTestCase {

    func testWalletMessageKindsAreTheEnvelopeTagsAndBounds() {
        XCTAssertEqual(IrohaPeerWireKindV1.allCases.map(\.rawValue), [1, 2, 3, 4, 5, 6, 7])
        XCTAssertEqual(
            IrohaPeerWireKindV1.allCases.map(\.walletMessageKind),
            KagemushaWalletMessageKindV1.allCases
        )
        XCTAssertEqual(
            IrohaPeerWireKindV1.allCases.map { UInt32($0.rawValue) },
            KagemushaWalletMessageKindV1.allCases.map(\.rawValue)
        )
        XCTAssertEqual(
            IrohaPeerWireKindV1.allCases.map(\.maximumWalletFrameBytes),
            [2_048, 14_112, 10_000, 10_000, 2_048, 10_000, 10_000]
        )
        XCTAssertEqual(IrohaPeerWireProfileV1.kagemushaWalletV1.requiredSchemaVersion, 1)
        XCTAssertNil(IrohaPeerWireKindV1(rawValue: 0))
        XCTAssertNil(IrohaPeerWireKindV1(rawValue: 8))
    }

    func testWireLimitHardCeilingsRejectLargerAllocationPolicies() {
        XCTAssertEqual(IrohaPeerWireLimitsV1.maximumWalletProfileBytes, 14_112)
        XCTAssertTrue(IrohaPeerWireLimitsV1.areValid(
            maximumCanonicalBytes: 14_112,
            maximumWalletEncodedBytes: 14_112
        ))
        XCTAssertFalse(IrohaPeerWireLimitsV1.areValid(
            maximumCanonicalBytes: 14_113,
            maximumWalletEncodedBytes: 14_112
        ))
        XCTAssertFalse(IrohaPeerWireLimitsV1.areValid(
            maximumCanonicalBytes: 14_112,
            maximumWalletEncodedBytes: 14_113
        ))
    }

    func testWalletVectorEnvelopesTravelOnlyUnderTheirOwnKind() throws {
        let vectors = try irohaPeerWalletVectorEnvelopesV1()
        XCTAssertEqual(Set(vectors.map(\.kind)), Set(IrohaPeerWireKindV1.allCases))
        for vector in vectors {
            for compressionPolicy in [IrohaPeerWireCompressionPolicyV1.disabled, .peerOptimized] {
                let message = try IrohaPeerKagemushaWalletAdapterV1.wrap(vector.frame,
                    destinationAccountOriginal: vector.kind == .request ? irohaPeerWalletRequestAccountOriginalV1() : nil,
                    compressionPolicy: compressionPolicy)
                let decoded = try IrohaPeerWireMessageV1.decode(
                    message.encoded,
                    expectedProfile: .kagemushaWalletV1,
                    expectedKind: vector.kind
                )
                XCTAssertEqual(try IrohaPeerKagemushaWalletAdapterV1.decode(decoded), vector.frame, vector.variant)
            }
            for other in IrohaPeerWireKindV1.allCases where other != vector.kind {
                XCTAssertThrowsError(try IrohaPeerWireMessageV1(
                    profile: .kagemushaWalletV1,
                    kind: other,
                    schemaVersion: 1,
                    canonicalPayload: vector.frame
                ), vector.variant) {
                    XCTAssertEqual(
                        $0 as? IrohaPeerWireMessageErrorV1,
                        vector.frame.count > other.maximumWalletFrameBytes
                            ? .canonicalLengthOutOfRange(actual: vector.frame.count, maximum: other.maximumWalletFrameBytes)
                            : .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: other)
                    )
                }
            }
        }
    }

    func testEmptyCanonicalPayloadIsRejectedByProducerAndHeaderParser() throws {
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .request,
            schemaVersion: 1,
            canonicalPayload: Data()
        )) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .emptyCanonicalPayload)
        }

        let valid = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .credited,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .credited,
                payload: Data([0x01])
            )
        )
        var emptyHeader = valid.header.bytes
        writeUInt32BE(&emptyHeader, at: 12, 0)
        writeUInt32BE(&emptyHeader, at: 16, 0)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(emptyHeader)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .emptyCanonicalPayload)
        }
    }

    func testIPM1HeaderLayoutAndDomainSeparatedHashes() throws {
        let canonical = irohaPeerWalletStructuralEnvelopeV1(
            kind: .payment,
            payload: Data("canonical-wallet-payload".utf8)
        )
        let message = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: canonical
        )
        let encoded = message.encoded

        XCTAssertEqual(encoded.count, 84 + canonical.count)
        XCTAssertEqual(Data(encoded[0..<4]), Data("IPM1".utf8))
        XCTAssertEqual(encoded[4], 1)
        XCTAssertEqual(encoded[5], 0)
        XCTAssertEqual(readUInt16BE(encoded, 6), 1)
        XCTAssertEqual(encoded[8], IrohaPeerWireKindV1.payment.rawValue)
        XCTAssertEqual(encoded[9], 0)
        XCTAssertEqual(readUInt16BE(encoded, 10), 1)
        XCTAssertEqual(readUInt32BE(encoded, 12), UInt32(canonical.count))
        XCTAssertEqual(readUInt32BE(encoded, 16), UInt32(canonical.count))

        var canonicalPreimage = Data("IROHA-PEER-PAYLOAD-V1\0".utf8)
        canonicalPreimage.append(contentsOf: [0, 1, IrohaPeerWireKindV1.payment.rawValue, 0, 1])
        canonicalPreimage.append(canonical)
        let canonicalHash = Blake2b.hash256(canonicalPreimage)
        XCTAssertEqual(Data(encoded[20..<52]), canonicalHash)

        var wirePreimage = Data("IROHA-PEER-MESSAGE-V1\0".utf8)
        wirePreimage.append(encoded[0..<52])
        wirePreimage.append(canonical)
        let wireHash = Blake2b.hash256(wirePreimage)
        XCTAssertEqual(Data(encoded[52..<84]), wireHash)
        XCTAssertEqual(message.streamID, Data(wireHash.prefix(16)))

        let decoded = try IrohaPeerWireMessageV1.decode(encoded)
        XCTAssertEqual(decoded, message)
        XCTAssertEqual(decoded.canonicalPayload, canonical)
    }

    func testPeerCompressionPolicyRequiresSavingsAndFewerShards() throws {
        let compressible = irohaPeerWalletStructuralEnvelopeV1(
            kind: .payment,
            frameBytes: 1_072,
            filler: { Data(repeating: 0x41, count: $0) }
        )
        let compressed = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: compressible,
            compressionPolicy: .peerOptimized
        )
        XCTAssertEqual(compressed.encoding, .zlib)
        XCTAssertGreaterThanOrEqual(compressible.count - compressed.encodedBody.count, 32)
        XCTAssertLessThan(
            shardCount(compressed.encodedBody.count),
            shardCount(compressible.count)
        )
        XCTAssertEqual(
            try IrohaPeerWireMessageV1.decode(compressed.encoded).canonicalPayload,
            compressible
        )

        // Compression saves bytes here, but both forms still occupy one 256-byte shard.
        let oneShard = irohaPeerWalletStructuralEnvelopeV1(
            kind: .payment,
            frameBytes: 248,
            filler: { Data(repeating: 0x41, count: $0) }
        )
        let unchanged = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: oneShard,
            compressionPolicy: .peerOptimized
        )
        XCTAssertEqual(unchanged.encoding, .none)
        XCTAssertEqual(unchanged.encodedBody, oneShard)

        let disabled = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: compressible,
            compressionPolicy: .disabled
        )
        XCTAssertEqual(disabled.encoding, .none)
    }

    func testDecoderRejectsNonCanonicalZlibAndTrailingInput() throws {
        let canonical = irohaPeerWalletStructuralEnvelopeV1(
            kind: .payment,
            frameBytes: 1_072,
            filler: { Data(repeating: 0x41, count: $0) }
        )
        let message = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: canonical,
            compressionPolicy: .peerOptimized
        )
        XCTAssertEqual(message.encoding, .zlib)

        var insufficientSavings = message.header.bytes
        writeUInt32BE(
            &insufficientSavings,
            at: 12,
            UInt32(message.encodedBody.count + 31)
        )
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(insufficientSavings)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .compressionPolicyNotSatisfied
            )
        }

        var sameShardCount = message.header.bytes
        writeUInt32BE(&sameShardCount, at: 12, 200)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(sameShardCount)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .compressionPolicyNotSatisfied
            )
        }

        var emptyEncodedBody = message.header.bytes
        writeUInt32BE(&emptyEncodedBody, at: 16, 0)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(emptyEncodedBody)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .emptyEncodedBody
            )
        }

        var trailingInput = message.encoded
        trailingInput.append(0)
        writeUInt32BE(&trailingInput, at: 16, UInt32(message.encodedBody.count + 1))
        refreshWireHash(&trailingInput)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(trailingInput)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .decompressionFailed)
        }

        var nonCanonicalWrapper = message.encoded
        nonCanonicalWrapper[84] = 0x79
        refreshWireHash(&nonCanonicalWrapper)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(nonCanonicalWrapper)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .decompressionFailed)
        }

        var invalidAdler32 = message.encoded
        invalidAdler32[invalidAdler32.count - 1] ^= 1
        refreshWireHash(&invalidAdler32)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(invalidAdler32)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .decompressionFailed)
        }
    }

    func testProfileAndCanonicalLimitsAreEnforcedBeforeAllocation() throws {
        XCTAssertEqual(IrohaPeerWireLimitsV1.peerV1.maximumWalletEncodedBytes, 14_112)
        let boundaryCanonical = irohaPeerWalletStructuralEnvelopeV1(
            kind: .payment,
            frameBytes: 10_000
        )
        let boundary = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: boundaryCanonical
        )
        XCTAssertEqual(boundary.encodedBody.count, 10_000)
        XCTAssertEqual(try IrohaPeerWireMessageV1.decode(boundary.encoded), boundary)
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: 10_001
            )
        )) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .canonicalLengthOutOfRange(actual: 10_001, maximum: 10_000)
            )
        }

        // Offer and SessionControl envelopes keep their 2,048-byte frame bound inside IPM1.
        for kind in [IrohaPeerWireKindV1.offer, .sessionControl] {
            XCTAssertNoThrow(try IrohaPeerWireMessageV1(
                profile: .kagemushaWalletV1,
                kind: kind,
                schemaVersion: 1,
                canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(kind: kind, frameBytes: 2_048)
            ))
            XCTAssertThrowsError(try IrohaPeerWireMessageV1(
                profile: .kagemushaWalletV1,
                kind: kind,
                schemaVersion: 1,
                canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(kind: kind, frameBytes: 2_049)
            )) { error in
                XCTAssertEqual(
                    error as? IrohaPeerWireMessageErrorV1,
                    .canonicalLengthOutOfRange(actual: 2_049, maximum: 2_048)
                )
            }
        }

        let tight = IrohaPeerWireLimitsV1(
            maximumCanonicalBytes: 1_024,
            maximumWalletEncodedBytes: 700
        )
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: 701,
                filler: { Data(repeating: 1, count: $0) }
            ),
            limits: tight
        )) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .encodedLengthOutOfRange(actual: 701, maximum: 700)
            )
        }
        XCTAssertNoThrow(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: 700,
                filler: { Data(repeating: 1, count: $0) }
            ),
            limits: tight
        ))
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                frameBytes: 1_025,
                filler: { Data(repeating: 1, count: $0) }
            ),
            limits: tight
        )) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .canonicalLengthOutOfRange(actual: 1_025, maximum: 1_024)
            )
        }
    }

    func testWireAndCanonicalCorruptionAreRejected() throws {
        let message = try makeMessage(bytes: Data("bound-by-both-hashes".utf8))

        var bodyCorruption = message.encoded
        bodyCorruption[bodyCorruption.count - 1] ^= 1
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(bodyCorruption)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .wireHashMismatch)
        }

        var canonicalHashCorruption = message.encoded
        canonicalHashCorruption[20] ^= 1
        let body = Data(canonicalHashCorruption[84...])
        var wireInput = Data("IROHA-PEER-MESSAGE-V1\0".utf8)
        wireInput.append(canonicalHashCorruption[0..<52])
        wireInput.append(body)
        canonicalHashCorruption.replaceSubrange(52..<84, with: Blake2b.hash256(wireInput))
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(canonicalHashCorruption)) { error in
            XCTAssertEqual(error as? IrohaPeerWireMessageErrorV1, .canonicalHashMismatch)
        }
    }

    func testExpectedKindProducesTypedRejection() throws {
        let message = try makeMessage(bytes: Data("typed-routing".utf8))
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(
            message.encoded,
            expectedKind: .credited
        )) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .unexpectedKind(expected: .credited, actual: .payment)
            )
        }
    }

    func testWalletProfileRequiresExactEnvelopeOfItsKind() throws {
        let canonical = irohaPeerWalletStructuralEnvelopeV1(
            kind: .request,
            payload: Data([0x51])
        )
        XCTAssertEqual(canonical.subdata(in: 40..<48), Data(repeating: 0, count: 8))
        XCTAssertEqual(
            try KagemushaWalletWireV1.inspectEnvelope(canonical).kind,
            KagemushaWalletMessageKindV1.request
        )
        let account = try irohaPeerWalletRequestAccountOriginalV1()
        func carrier(_ envelope: Data) -> Data {
            var bytes = Data("KWRQAC1\0".utf8)
            for length in [envelope.count, account.count] {
                for shift in stride(from: 24, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: length >> shift)) }
            }
            bytes.append(envelope); bytes.append(account); return bytes
        }
        let message = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .request,
            schemaVersion: 1,
            canonicalPayload: carrier(canonical)
        )
        XCTAssertEqual(try IrohaPeerWireMessageV1.decode(message.encoded), message)

        var wrongSchema = canonical
        wrongSchema[6] ^= 1
        var shortPadding = canonical
        shortPadding.remove(at: 40)
        var longPadding = canonical
        longPadding.insert(0, at: 40)
        var wrongChecksum = canonical
        wrongChecksum[31] ^= 1
        var wrongFlags = canonical
        wrongFlags[39] = 0
        var wrongCompression = canonical
        wrongCompression[22] = 1
        var trailing = canonical
        trailing.append(0)
        let bareSchema = noritoEncode(
            typeName: "UnknownPeerPayload",
            payload: Data([0x51]),
            flags: NoritoHeader.compactLen,
            payloadAlignment: 16
        )
        // A valid envelope of another message kind cannot travel as a Request.
        let offerEnvelope = irohaPeerWalletStructuralEnvelopeV1(
            kind: .offer,
            payload: Data([0x51])
        )

        for invalid in [
            wrongSchema,
            shortPadding,
            longPadding,
            wrongChecksum,
            wrongFlags,
            wrongCompression,
            trailing,
            bareSchema,
            offerEnvelope
        ] {
            XCTAssertThrowsError(try IrohaPeerWireMessageV1(
                profile: .kagemushaWalletV1,
                kind: .request,
                schemaVersion: 1,
                canonicalPayload: carrier(invalid)
            )) {
                XCTAssertEqual(
                    $0 as? IrohaPeerWireMessageErrorV1,
                    .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .request)
                )
            }
        }
        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: canonical
        ))

        let forged = rehashWalletRequestMessage(message.encoded, canonical: carrier(wrongSchema))
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.decode(forged)) {
            XCTAssertEqual(
                $0 as? IrohaPeerWireMessageErrorV1,
                .invalidCanonicalPayload(profile: .kagemushaWalletV1, kind: .request)
            )
        }
    }

    func testFirstReleaseProfileSchemaPairsAreEnforcedAtConstructionAndInspection() throws {
        XCTAssertEqual(IrohaPeerWireProfileV1(rawValue: 1), .kagemushaWalletV1)
        XCTAssertNil(IrohaPeerWireProfileV1(rawValue: 2))
        XCTAssertNil(IrohaPeerWireProfileV1(rawValue: UInt16.max))

        XCTAssertThrowsError(try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 2,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                payload: Data([1])
            )
        )) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .schemaVersionMismatch(profile: .kagemushaWalletV1, expected: 1, actual: 2)
            )
        }

        let current = try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                payload: Data([1])
            )
        )
        var retiredHeader = current.header.bytes
        retiredHeader[6] = 0
        retiredHeader[7] = 2
        retiredHeader[10] = 0
        retiredHeader[11] = 1
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(retiredHeader)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .invalidProfile(2)
            )
        }

        var unknownHeader = current.header.bytes
        unknownHeader[6] = 0xFF
        unknownHeader[7] = 0xFF
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(unknownHeader)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .invalidProfile(UInt16.max)
            )
        }

        var wrongSchemaHeader = current.header.bytes
        wrongSchemaHeader[10] = 0
        wrongSchemaHeader[11] = 2
        XCTAssertThrowsError(try IrohaPeerWireMessageV1.inspectHeader(wrongSchemaHeader)) { error in
            XCTAssertEqual(
                error as? IrohaPeerWireMessageErrorV1,
                .schemaVersionMismatch(profile: .kagemushaWalletV1, expected: 1, actual: 2)
            )
        }
    }

    private func makeMessage(bytes: Data) throws -> IrohaPeerWireMessageV1 {
        try IrohaPeerWireMessageV1(
            profile: .kagemushaWalletV1,
            kind: .payment,
            schemaVersion: 1,
            canonicalPayload: irohaPeerWalletStructuralEnvelopeV1(
                kind: .payment,
                payload: bytes
            )
        )
    }

    private func shardCount(_ count: Int) -> Int { (count + 255) / 256 }

    private func readUInt16BE(_ data: Data, _ offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }

    private func readUInt32BE(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24
            | UInt32(data[offset + 1]) << 16
            | UInt32(data[offset + 2]) << 8
            | UInt32(data[offset + 3])
    }

    private func writeUInt32BE(
        _ data: inout Data,
        at offset: Int,
        _ value: UInt32
    ) {
        data[offset] = UInt8(truncatingIfNeeded: value >> 24)
        data[offset + 1] = UInt8(truncatingIfNeeded: value >> 16)
        data[offset + 2] = UInt8(truncatingIfNeeded: value >> 8)
        data[offset + 3] = UInt8(truncatingIfNeeded: value)
    }

    private func refreshWireHash(_ message: inout Data) {
        var preimage = Data("IROHA-PEER-MESSAGE-V1\0".utf8)
        preimage.append(message[0..<52])
        preimage.append(message[84...])
        message.replaceSubrange(52..<84, with: Blake2b.hash256(preimage))
    }

    private func rehashWalletRequestMessage(
        _ encoded: Data,
        canonical: Data
    ) -> Data {
        precondition(encoded.count == 84 + canonical.count)
        var result = encoded
        result.replaceSubrange(84..<result.count, with: canonical)
        var canonicalPreimage = Data("IROHA-PEER-PAYLOAD-V1\0".utf8)
        canonicalPreimage.append(contentsOf: [0, 1, IrohaPeerWireKindV1.request.rawValue, 0, 1])
        canonicalPreimage.append(canonical)
        result.replaceSubrange(20..<52, with: Blake2b.hash256(canonicalPreimage))
        refreshWireHash(&result)
        return result
    }
}
