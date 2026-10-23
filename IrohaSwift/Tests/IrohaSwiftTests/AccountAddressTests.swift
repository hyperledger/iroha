import XCTest
@testable import IrohaSwift

private struct Fixture: Decodable {
    let formatVersion: Int
    let defaultNetworkPrefix: UInt16
    let cases: FixtureCaseSets
}

private struct FixtureCaseSets: Decodable {
    let positive: [PositiveCase]
    let negative: [NegativeCase]
}

private struct PositiveCase: Decodable {
    let caseId: String
    let category: String
    let encodings: Encodings
    let controller: Controller?
}

private struct Encodings: Decodable {
    let canonicalHex: String
    let i105: I105Encoding

    private enum CodingKeys: String, CodingKey {
        case canonicalHex
        case i105
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        canonicalHex = try container.decode(String.self, forKey: .canonicalHex)
        i105 = try container.decode(I105Encoding.self, forKey: .i105)
    }
}

private struct Controller: Decodable {
    let kind: String
    let version: UInt8?
    let threshold: UInt16?
    let totalWeight: UInt32?
    let members: [ControllerMember]?
    let ctap2CborHex: String?
    let digestBlake2b256Hex: String?

    private enum CodingKeys: String, CodingKey {
        case kind
        case version
        case threshold
        case totalWeight
        case members
        case ctap2CborHex
        case digestBlake2B256Hex
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        kind = try container.decode(String.self, forKey: .kind)
        version = try container.decodeIfPresent(UInt8.self, forKey: .version)
        threshold = try container.decodeIfPresent(UInt16.self, forKey: .threshold)
        totalWeight = try container.decodeIfPresent(UInt32.self, forKey: .totalWeight)
        members = try container.decodeIfPresent([ControllerMember].self, forKey: .members)
        ctap2CborHex = try container.decodeIfPresent(String.self, forKey: .ctap2CborHex)
        digestBlake2b256Hex = try container.decodeIfPresent(String.self, forKey: .digestBlake2B256Hex)
    }
}

private struct ControllerMember: Decodable {
    let algorithm: String?
    let curve: String?
    let weight: UInt16
    let publicKeyHex: String

    var normalizedAlgorithm: String {
        (algorithm ?? curve ?? "unknown").lowercased()
    }
}

private struct I105Encoding: Decodable {
    let prefix: UInt16
    let string: String
}

private struct NegativeCase: Decodable {
    let caseId: String
    let format: String
    let input: String
    let expectedPrefix: UInt16?
    let expectedError: ExpectedError
}

private struct ExpectedError: Decodable {
    let kind: String
    let expected: UInt16?
    let found: UInt16?
    let char: String?
    let policyError: String?
}

final class AccountAddressTests: XCTestCase {
    private static let canonicalEd25519PublicKey = Data([
        0x3B, 0x6A, 0x27, 0xBC, 0xCE, 0xB6, 0xA4, 0x2D,
        0x62, 0xA3, 0xA8, 0xD0, 0x2A, 0x6F, 0x0D, 0x73,
        0x65, 0x32, 0x15, 0x77, 0x1D, 0xE2, 0x43, 0xA6,
        0x3A, 0xC0, 0x48, 0xA1, 0x8B, 0x59, 0xDA, 0x29,
    ])

    private func validEd25519PublicKey(seed: UInt8) throws -> Data {
        try Keypair(privateKeyBytes: Data(repeating: seed, count: 32)).publicKey
    }

    func testGoldenRoundTrip() throws {
        let address = try AccountAddress.fromAccount(publicKey: Self.canonicalEd25519PublicKey)

        let canonical = try address.canonicalHex()
        let i105 = try address.toI105(networkPrefix: 753)

        XCTAssertEqual(
            canonical,
            "0x020001203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        )
        XCTAssertTrue(i105.hasPrefix("sora"))
        let payload = String(i105.dropFirst(4))
        XCTAssertTrue(
            payload.unicodeScalars.contains(where: {
                $0.isASCII && CharacterSet.alphanumerics.contains($0)
            })
        )
        XCTAssertTrue(
            payload.contains(where: {
                "ｲﾛﾊﾆﾎﾍﾄﾁﾘﾇﾙｦﾜｶﾖﾀﾚｿﾂﾈﾅﾗﾑｳヰﾉｵｸﾔﾏｹﾌｺｴﾃｱｻｷﾕﾒﾐｼヱﾋﾓｾｽ".contains($0)
            })
        )

        let parsedI105 = try AccountAddress.parseEncoded(i105, expectedPrefix: 753)
        XCTAssertEqual(try parsedI105.canonicalBytes(), try address.canonicalBytes())
    }

    func testSm2ExtendedSingleKeyPayloadUsesCanonicalTag() throws {
        let distid = String(repeating: "d", count: 189)
        let publicKey = try XCTUnwrap(Data(hexString:
            "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7" +
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        ))
        let address = try AccountAddress.fromAccount(
            publicKey: publicKey,
            algorithm: "sm2",
            distid: distid
        )

        let canonical = try address.canonicalBytes()
        XCTAssertEqual(canonical[0], 0x02)
        XCTAssertEqual(canonical[1], 0x02)
        XCTAssertEqual(canonical[2], 0x0F)
        XCTAssertEqual(Int((UInt16(canonical[3]) << 8) | UInt16(canonical[4])), 0x0100)

        let payload = Data(canonical.dropFirst(5))
        XCTAssertEqual(payload.count, 0x0100)
        XCTAssertEqual(Data(payload.prefix(2)), Data([0x00, 0xBD]))
        XCTAssertEqual(Data(payload.dropFirst(2).prefix(distid.utf8.count)), Data(distid.utf8))
        XCTAssertEqual(Data(payload.suffix(publicKey.count)), publicKey)
    }

    func testSm2ExtendedSingleKeyRoundTripsThroughCanonicalAndI105() throws {
        let distid = String(repeating: "d", count: 189)
        let publicKey = try XCTUnwrap(Data(hexString:
            "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7" +
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        ))
        let address = try AccountAddress.fromAccount(
            publicKey: publicKey,
            algorithm: "sm2",
            distid: distid
        )
        let canonical = try address.canonicalBytes()

        let decodedCanonical = try AccountAddress.fromCanonicalBytes(canonical)
        XCTAssertEqual(try decodedCanonical.canonicalBytes(), canonical)

        let i105 = try address.toI105(networkPrefix: 0x02F1)
        let decodedI105 = try AccountAddress.fromI105(i105, expectedPrefix: 0x02F1)
        XCTAssertEqual(try decodedI105.canonicalBytes(), canonical)
    }

    func testRejectsExtendedSingleKeyEncodingForShortPayload() {
        var canonical = Data([0x02, 0x02, 0x01, 0x00, 0x20])
        canonical.append(Data(repeating: 0x11, count: 32))

        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(canonical)) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidLength)
        }
    }

    func testRejectsNonV1AndControllerClassInconsistentHeaders() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0x01))
        let canonical = try address.canonicalBytes()

        var nonV1Header = canonical
        nonV1Header[0] = 0x22
        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(nonV1Header)) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidHeaderVersion(1))
        }

        var nonV1Normalization = canonical
        nonV1Normalization[0] = 0x04
        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(nonV1Normalization)) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidNormVersion(2))
        }

        var mismatchedClass = canonical
        mismatchedClass[0] = 0x0A
        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(mismatchedClass)) { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
        }
    }

    func testParseEncodedRejectsCanonicalHex() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0x42))
        let canonical = try address.canonicalHex()
        XCTAssertThrowsError(try AccountAddress.parseEncoded(canonical)) { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
        }
    }

    func testCanonicalBytesRejectRetiredDomainSelectorPrefix() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0x01))
        let canonical = try address.canonicalBytes()
        var selectorPrefixed = Data([canonical[0], 0x01])
        selectorPrefixed.append(contentsOf: (1...12).map(UInt8.init))
        selectorPrefixed.append(canonical.dropFirst())

        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(selectorPrefixed))
    }

    func testParseEncodedRejectsFullwidthSentinelI105() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0x31))
        let canonical = try address.toI105(networkPrefix: 753)
        var noncanonical = canonical
        if let range = noncanonical.range(of: "sora") {
            noncanonical.replaceSubrange(range, with: "ｓｏｒａ")
        }

        // Native admission uses Rust parse_encoded for both public entry points.
        XCTAssertThrowsError(try AccountAddress.fromI105(noncanonical, expectedPrefix: 753)) { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
        }
        // Keep the missing-sentinel diagnostic on the syntax inspection owner.
        XCTAssertThrowsError(try AccountAddress.inspectI105NetworkPrefix(noncanonical, expectedPrefix: 753)) { error in
            XCTAssertEqual(error as? AccountAddressError, .missingI105Sentinel)
        }
        XCTAssertThrowsError(try AccountAddress.parseEncoded(noncanonical, expectedPrefix: 753)) { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
        }
    }

    func testAccountAddressConstructorIsDomainless() throws {
        XCTAssertNoThrow(
            try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0x22))
        )
    }

    func testAccountAddressRejectsEmptyPublicKey() {
        XCTAssertThrowsError(
            try AccountAddress.fromAccount(publicKey: Data())
        ) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey)
        }
    }

    func testAccountAddressRejectsInvalidEd25519KeyLength() {
        XCTAssertThrowsError(
            try AccountAddress.fromAccount(publicKey: Data(repeating: 0x01, count: 31))
        ) { error in
            XCTAssertEqual(error as? AccountAddressError, .invalidPublicKey)
        }
    }

    func testI105PrefixMismatch() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 1))
        let i105 = try address.toI105(networkPrefix: 5)
        XCTAssertThrowsError(try AccountAddress.parseEncoded(i105, expectedPrefix: 9)) { error in
            guard case let AccountAddressError.unexpectedNetworkPrefix(expected, found) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, 9)
            XCTAssertEqual(found, 5)
        }
    }

    func testInspectI105NetworkPrefixReportsProfileWithoutRewriting() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 1))
        let minamoto = try address.toI105(networkPrefix: 0x02F1)
        let prefix = try AccountAddress.inspectI105NetworkPrefix(minamoto, expectedPrefix: 0x02F1)
        XCTAssertEqual(prefix.sentinel, "sora")
        XCTAssertEqual(prefix.chainDiscriminant, 0x02F1)
        XCTAssertEqual(prefix.profileName, "minamoto")

        let custom = try address.toI105(networkPrefix: 42)
        let customPrefix = try AccountAddress.inspectI105NetworkPrefix(custom)
        XCTAssertEqual(customPrefix.sentinel, "n42")
        XCTAssertEqual(customPrefix.chainDiscriminant, 42)
        XCTAssertNil(customPrefix.profileName)

        XCTAssertThrowsError(try AccountAddress.inspectI105NetworkPrefix(minamoto, expectedPrefix: 0x0171)) { error in
            guard case let AccountAddressError.unexpectedNetworkPrefix(expected, found) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, 0x0171)
            XCTAssertEqual(found, 0x02F1)
        }
    }

    func testI105RequiresSentinel() {
        XCTAssertThrowsError(try AccountAddress.fromI105("invalid"))
    }

    func testBridgePayloadRejectsFractionalField() {
        let payload = AccountAddressError.BridgePayload(code: "ERR_INVALID_I105_CHAR",
                                                        message: "ERR_INVALID_I105_CHAR",
                                                        fields: ["char": NSNumber(value: 1.5)])
        XCTAssertNil(AccountAddressError.fromBridgePayload(payload))
    }

    func testBridgePayloadRejectsOutOfRangeUInt16() {
        let payload = AccountAddressError.BridgePayload(code: "ERR_INVALID_i105_PREFIX",
                                                        message: "ERR_INVALID_i105_PREFIX",
                                                        fields: ["prefix": 70000])
        XCTAssertNil(AccountAddressError.fromBridgePayload(payload))
    }

    func testI105TooShort() {
        XCTAssertThrowsError(try AccountAddress.fromI105("soraｱ")) { error in
            guard let addressError = error as? AccountAddressError else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(addressError.code, "ERR_I105_TOO_SHORT")
        }
    }

    func testParseLiveLinkedBankReserveLiteral() throws {
        let fixture = try loadAddressFixture()
        let liveReserveLiteral = try XCTUnwrap(
            fixture.cases.positive.first(where: { $0.category == "multisig" })?.encodings.i105.string
        )

        let parsed = try AccountAddress.parseEncoded(liveReserveLiteral, expectedPrefix: nil)
        XCTAssertEqual(try parsed.toI105(networkPrefix: fixture.defaultNetworkPrefix), liveReserveLiteral)
        XCTAssertNotNil(try parsed.multisigPolicyInfo())
    }

    func testMixedCanonicalI105LiteralRoundTrips() throws {
        let literal = "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7"
        let address = try AccountAddress.fromI105(literal, expectedPrefix: 753)
        XCTAssertEqual(
            try address.canonicalHex().lowercased(),
            "0x02000120bc717326224e4b4119298e7b1db8133cb27d6cdf6b3e04d75a6d27b29a34c1cf"
        )
        XCTAssertEqual(try address.toI105(networkPrefix: 753), literal)
    }

    func testRejectsNonCanonicalFullwidthKanaPayload() throws {
        let literal = "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7"
        let nonCanonical = literal.replacingOccurrences(of: "ﾛ", with: "ロ")

        XCTAssertThrowsError(try AccountAddress.fromI105(nonCanonical, expectedPrefix: 753)) { error in
            guard let addressError = error as? AccountAddressError else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(addressError.code, "ERR_INVALID_I105_CHAR")
        }
    }

    func testCanonicalIdentityRecognitionDoesNotDependOnSwiftFeatureFlags() {
        for algorithm in ["ed25519", "secp256k1", "bls_normal", "bls_small", "ml-dsa",
            "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b",
            "gost3410-2012-256-paramset-c", "gost3410-2012-512-paramset-a",
            "gost3410-2012-512-paramset-b", "sm2"] {
            XCTAssertThrowsError(try AccountAddress.fromAccount(publicKey: Data(), algorithm: algorithm)) {
                XCTAssertEqual($0 as? AccountAddressError, .invalidPublicKey, algorithm)
            }
        }
    }

    func testKnownMissingImplementationBridgeCategoryDoesNotDependOnMessageText() {
        for message in ["unavailable", "invalid key", "unknown curve"] {
            let payload = AccountAddressError.BridgePayload(code: "ERR_UNSUPPORTED_IMPLEMENTATION",
                message: message, fields: ["algorithm": "bls_normal", "operation": "public-key parsing"])
            let error = AccountAddressError.fromBridgePayload(payload)
            XCTAssertEqual(error, .unsupportedImplementation(algorithm: "bls_normal", operation: "public-key parsing"))
            XCTAssertEqual(error?.code, "ERR_UNSUPPORTED_IMPLEMENTATION")
        }
        XCTAssertEqual(AccountAddressError.unknownAlgorithm("future").code, "ERR_UNKNOWN_ALGORITHM")
        XCTAssertEqual(AccountAddressError.unknownCurve(255).code, "ERR_UNKNOWN_CURVE")
        XCTAssertNil(AccountAddressError.fromBridgePayload(.init(code: "ERR_UNSUPPORTED_ALGORITHM", message: "retired", fields: [:])))
    }

    func testNativeResourceCategoryDoesNotBecomeBridgeAbsence() {
        for diagnostic in ["arbitrary diagnostic", "implementation unavailable is only text"] {
            let payload = AccountAddressError.BridgePayload(code: "ERR_DECODE_RESOURCE_LIMIT",
                message: diagnostic, fields: [:])
            let error = AccountAddressError.fromBridgePayload(payload)
            XCTAssertEqual(error, .decodeResourceLimit)
            XCTAssertEqual(error?.code, "ERR_DECODE_RESOURCE_LIMIT")
            XCTAssertNotEqual(error, .nativeBridgeUnavailable)
        }
    }

    func testUnknownAlgorithmRejected() {
        XCTAssertThrowsError(
            try AccountAddress.fromAccount(publicKey: Data(repeating: 0xAA, count: 32),
                algorithm: "future-curve"
            )
        ) { error in
            guard case let AccountAddressError.unknownAlgorithm(name) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(name.lowercased(), "future-curve")
        }
    }

    func testConfusableAlgorithmAliasesRejected() {
        let publicKey = Data(repeating: 0xAA, count: 32)
        let algorithms = [
            "",
            "   ",
            " ed25519",
            "ed25519 ",
            "\u{00A0}ML-DSA-65\u{00A0}",
            "\u{2003}ML-DSA-65\u{2003}",
            "future-curve", "ed", "ED25519", "secp", "SECP256K1",
            "mldsa", "ML-DSA-65", "ML_DSA_65", "ML_DSA-65",
            "bls-normal", "bls-small", "gost256a", "gost512b", "sm-2", "SM2",
            "ed\t25519",
            "ed 25519",
            "ed.25519",
            "ed/25519",
            "ed@25519",
            "ed#25519",
            "ed\u{200B}25519",
            "\u{0435}d25519",
            "secp256\u{212A}1",
            "ml\u{FF0D}dsa",
            "ML-DSA-44",
            "ML_DSA_87",
            "gost256\u{0430}",
        ]

        for algorithm in algorithms {
            XCTAssertThrowsError(
                try AccountAddress.fromAccount(publicKey: publicKey, algorithm: algorithm)
            ) { error in
                guard case let AccountAddressError.unknownAlgorithm(name) = error else {
                    return XCTFail("unexpected error for \(algorithm): \(error)")
                }
                XCTAssertEqual(name, algorithm)
            }
        }
    }

    func testMlDsaCanonicalIdentityRequiresProtocolSuite65KeyMaterial() throws {
        let publicKey = Data(repeating: 0xA5, count: 1_952)
        for algorithm in ["ml-dsa"] {
            let address = try AccountAddress.fromAccount(
                publicKey: publicKey,
                algorithm: algorithm
            )
            let canonical = try address.canonicalBytes()
            XCTAssertEqual(
                Data(canonical.prefix(5)),
                Data([0x02, 0x02, 0x02, 0x07, 0xA0]),
                algorithm
            )
            XCTAssertEqual(Data(canonical.suffix(publicKey.count)), publicKey, algorithm)
            XCTAssertEqual(
                try AccountAddress.fromCanonicalBytes(canonical).canonicalBytes(),
                canonical,
                algorithm
            )
            let i105 = try address.toI105(networkPrefix: 753)
            XCTAssertEqual(
                try AccountAddress.fromI105(i105, expectedPrefix: 753).canonicalBytes(),
                canonical,
                algorithm
            )
            let compact = try address.compactNoritoAccountControllerPayload()
            XCTAssertTrue(
                AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(compact),
                algorithm
            )
        }

        for malformedKey in [
            Data(repeating: 0x44, count: 1_312),
            Data(repeating: 0x65, count: 1_951),
            Data(repeating: 0x65, count: 1_953),
            Data(repeating: 0x87, count: 2_592),
            Data(repeating: 0, count: 1_952),
        ] {
            XCTAssertThrowsError(
                try AccountAddress.fromAccount(
                    publicKey: malformedKey,
                    algorithm: "ml-dsa"
                )
            ) { error in
                guard case AccountAddressError.invalidPublicKey = error else {
                    return XCTFail("unexpected error: \(error)")
                }
            }
        }

        var suite44Canonical = Data([0x02, 0x02, 0x02, 0x05, 0x20])
        suite44Canonical.append(Data(repeating: 0x44, count: 1_312))
        XCTAssertThrowsError(try AccountAddress.fromCanonicalBytes(suite44Canonical)) { error in
            guard case AccountAddressError.invalidPublicKey = error else {
                return XCTFail("unexpected wire-decoding error: \(error)")
            }
        }

        for malformedKey in [
            Data(repeating: 0x44, count: 1_312),
            Data(repeating: 0x87, count: 2_592),
            Data(repeating: 0, count: 1_952),
        ] {
            var algorithmAndPayload = Data([SigningAlgorithm.mlDsa.noritoDiscriminant])
            algorithmAndPayload.append(malformedKey)
            var compactPublicKey = CompactNoritoWriter()
            compactPublicKey.writeUInt64LE(UInt64(algorithmAndPayload.count))
            for byte in algorithmAndPayload {
                compactPublicKey.writeLength(1)
                compactPublicKey.writeUInt8(byte)
            }
            var controller = CompactNoritoWriter()
            controller.writeUInt32LE(0)
            controller.writeField(compactPublicKey.data)
            XCTAssertFalse(
                AccountAddress.isCanonicalCompactNoritoAccountControllerPayload(controller.data)
            )
        }
    }

    func testAccountControllerNoritoUsesAlgorithmTaggedPublicKeyBytes() throws {
        let publicKey = try validEd25519PublicKey(seed: 0x42)
        let address = try AccountAddress.fromAccount(publicKey: publicKey)
        var algorithmAndPayload = Data([SigningAlgorithm.ed25519.noritoDiscriminant])
        algorithmAndPayload.append(publicKey)

        var expected = CanonicalNoritoWriter()
        expected.writeUInt32LE(0)
        expected.writeField(CanonicalNorito.encodeConstVec(algorithmAndPayload))
        XCTAssertEqual(try address.noritoAccountControllerPayload(), expected.data)

        var compactPublicKey = CompactNoritoWriter()
        compactPublicKey.writeUInt64LE(UInt64(algorithmAndPayload.count))
        for byte in algorithmAndPayload {
            compactPublicKey.writeLength(1)
            compactPublicKey.writeUInt8(byte)
        }
        var expectedCompact = CompactNoritoWriter()
        expectedCompact.writeUInt32LE(0)
        expectedCompact.writeField(compactPublicKey.data)
        XCTAssertEqual(try address.compactNoritoAccountControllerPayload(), expectedCompact.data)
    }

    func testMultisigCompactNoritoControllerUsesFixedVectorCount() throws {
        let fixture = try loadAddressFixture()
        let vector = try XCTUnwrap(fixture.cases.positive.first { $0.category == "multisig" })
        let address = try AccountAddress.parseEncoded(
            vector.encodings.i105.string,
            expectedPrefix: vector.encodings.i105.prefix
        )
        let memberCount = try XCTUnwrap(vector.controller?.members?.count)

        var controllerReader = CanonicalNoritoReader(data: try address.compactNoritoAccountControllerPayload())
        XCTAssertEqual(try controllerReader.readUInt32LE(), 1)
        var policyReader = CanonicalNoritoReader(data: try controllerReader.readCompactField())
        XCTAssertEqual(controllerReader.remaining(), 0)

        var versionReader = CanonicalNoritoReader(data: try policyReader.readCompactField())
        XCTAssertEqual(try versionReader.readUInt8(), vector.controller?.version)
        XCTAssertEqual(versionReader.remaining(), 0)

        var thresholdReader = CanonicalNoritoReader(data: try policyReader.readCompactField())
        XCTAssertEqual(try thresholdReader.readUInt16LE(), vector.controller?.threshold)
        XCTAssertEqual(thresholdReader.remaining(), 0)

        var membersReader = CanonicalNoritoReader(data: try policyReader.readCompactField())
        XCTAssertEqual(try membersReader.readUInt64LE(), UInt64(memberCount))
        for _ in 0..<memberCount {
            var memberReader = CanonicalNoritoReader(data: try membersReader.readCompactField())
            _ = try memberReader.readCompactField()
            _ = try memberReader.readCompactField()
            XCTAssertEqual(memberReader.remaining(), 0)
        }
        XCTAssertEqual(membersReader.remaining(), 0)
        XCTAssertEqual(policyReader.remaining(), 0)
    }

    func testComplianceVectorsFixture() throws {
        let fixture = try loadAddressFixture()
        XCTAssertEqual(fixture.formatVersion, 1)

        for vector in fixture.cases.positive {
            try assertPositiveCase(vector)
        }

        for vector in fixture.cases.negative {
            assertNegativeCase(vector, defaultPrefix: fixture.defaultNetworkPrefix)
        }
    }

    func testDisplayFormats() throws {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: 0xAB))
        let formats = try address.displayFormats()

        XCTAssertEqual(formats.networkPrefix, 753)
        XCTAssertEqual(formats.i105, try address.toI105(networkPrefix: 753))
        XCTAssertTrue(formats.i105Warning.contains("canonical I105 alphabet"))
        XCTAssertTrue(formats.i105Warning.contains("Base58 plus the 47 half-width katakana"))
    }

    private func loadAddressFixture() throws -> Fixture {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/account/address_vectors.json")
        let data = try Data(contentsOf: fixtureURL)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Fixture.self, from: data)
    }

    private func captureBridgeError(for vector: NegativeCase, defaultPrefix: UInt16) throws -> AccountAddressError? {
        guard NoritoNativeBridge.shared.isAccountAddressCodecAvailable else { return nil }
        do {
            switch vector.format {
            case "i105":
                _ = try NoritoNativeBridge.shared.parseAccountAddress(
                    literal: vector.input,
                    expectedPrefix: vector.expectedPrefix ?? defaultPrefix
                )
            case "canonical_hex":
                _ = try NoritoNativeBridge.shared.parseAccountAddress(
                    literal: vector.input,
                    expectedPrefix: nil
                )
            default:
                return nil
            }
        } catch let error as AccountAddressError {
            return error
        }
        return nil
    }

    func testBridgeCodecMatchesFixtures() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.isAccountAddressCodecAvailable,
            "NoritoBridge not available"
        )
        let fixture = try loadAddressFixture()
        let defaultPrefix = fixture.defaultNetworkPrefix
        try NoritoNativeBridge.shared.withChainDiscriminant(defaultPrefix) {
            for vector in fixture.cases.positive {
                let parseResult = try XCTUnwrap(
                    try NoritoNativeBridge.shared.parseAccountAddress(
                        literal: vector.encodings.i105.string,
                        expectedPrefix: vector.encodings.i105.prefix
                    )
                )
                XCTAssertEqual(parseResult.networkPrefix, vector.encodings.i105.prefix, "\(vector.caseId): bridge i105 prefix mismatch")
                let render = try XCTUnwrap(
                    try NoritoNativeBridge.shared.renderAccountAddress(
                        canonicalBytes: parseResult.canonicalBytes,
                        networkPrefix: vector.encodings.i105.prefix
                    ),
                    "\(vector.caseId): bridge render missing"
                )
                XCTAssertEqual(render.i105, vector.encodings.i105.string, "\(vector.caseId): bridge i105 encode mismatch")
                XCTAssertEqual(render.canonicalHex.lowercased(), vector.encodings.canonicalHex.lowercased(), "\(vector.caseId): bridge canonical hex mismatch")
            }

            for vector in fixture.cases.negative {
                guard let error = try captureBridgeError(for: vector, defaultPrefix: defaultPrefix) else {
                    return XCTFail("\(vector.caseId): expected bridge error")
                }
                if vector.format == "canonical_hex",
                   case .unsupportedAddressFormat = error {
                    continue
                }
                verify(error: error, matches: vector.expectedError, caseId: vector.caseId)
            }
        }
    }

    private func assertPositiveCase(_ vector: PositiveCase) throws {
        let address = try AccountAddress.fromI105(vector.encodings.i105.string,
                                                  expectedPrefix: vector.encodings.i105.prefix)
        let canonicalBytes = try address.canonicalBytes()

        let i105 = try AccountAddress.fromI105(vector.encodings.i105.string, expectedPrefix: vector.encodings.i105.prefix)
        XCTAssertEqual(try i105.canonicalBytes(), canonicalBytes, "\(vector.caseId): i105 canonical mismatch")

        let parsedI105 = try AccountAddress.parseEncoded(vector.encodings.i105.string, expectedPrefix: vector.encodings.i105.prefix)
        XCTAssertEqual(try parsedI105.canonicalBytes(), canonicalBytes, "\(vector.caseId): parseEncoded i105 canonical mismatch")

        XCTAssertThrowsError(try AccountAddress.parseEncoded(vector.encodings.canonicalHex),
                             "\(vector.caseId): canonical hex parse should be rejected") { error in
            XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat)
        }

        XCTAssertEqual(try address.toI105(networkPrefix: vector.encodings.i105.prefix), vector.encodings.i105.string, "\(vector.caseId): i105 re-encode mismatch")
        XCTAssertEqual(try address.canonicalHex().lowercased(), vector.encodings.canonicalHex.lowercased(), "\(vector.caseId): canonical hex re-encode mismatch")

        if let controller = vector.controller, controller.kind == "multisig" {
            guard let info = try address.multisigPolicyInfo() else {
                return XCTFail("\(vector.caseId): expected multisig policy info")
            }
            if let version = controller.version {
                XCTAssertEqual(info.version, version, "\(vector.caseId): controller version mismatch")
            }
            if let threshold = controller.threshold {
                XCTAssertEqual(info.threshold, threshold, "\(vector.caseId): controller threshold mismatch")
            }
            if let totalWeight = controller.totalWeight {
                XCTAssertEqual(info.totalWeight, totalWeight, "\(vector.caseId): controller total weight mismatch")
            }
            if let members = controller.members {
                XCTAssertEqual(info.members.count, members.count, "\(vector.caseId): controller member count mismatch")
                for (actual, expected) in zip(info.members, members) {
                    XCTAssertEqual(actual.algorithm, expected.normalizedAlgorithm, "\(vector.caseId): controller member algorithm mismatch")
                    XCTAssertEqual(actual.weight, expected.weight, "\(vector.caseId): controller member weight mismatch")
                    let actualKey = stripHexPrefix(actual.publicKeyHex).uppercased()
                    let expectedKey = stripHexPrefix(expected.publicKeyHex).uppercased()
                    XCTAssertEqual(actualKey, expectedKey, "\(vector.caseId): controller member key mismatch")
                }
            }
            if let ctap2Hex = controller.ctap2CborHex {
                XCTAssertEqual(info.ctap2CborHex.uppercased(), ctap2Hex.uppercased(), "\(vector.caseId): controller CTAP2 hex mismatch")
            }
            if let digestHex = controller.digestBlake2b256Hex {
                XCTAssertEqual(info.digestBlake2b256Hex.uppercased(), digestHex.uppercased(), "\(vector.caseId): controller digest mismatch")
            }
        }
    }

    private func stripHexPrefix(_ value: String) -> String {
        if value.hasPrefix("0x") || value.hasPrefix("0X") {
            return String(value.dropFirst(2))
        }
        return value
    }

    private func assertNegativeCase(_ vector: NegativeCase, defaultPrefix: UInt16) {
        switch vector.format {
        case "i105":
            XCTAssertThrowsError(
                try AccountAddress.fromI105(vector.input, expectedPrefix: vector.expectedPrefix ?? defaultPrefix),
                "\(vector.caseId): i105 negative should fail"
            ) { error in
                self.verify(error: error, matches: vector.expectedError, caseId: vector.caseId)
            }
        case "canonical_hex":
            XCTAssertThrowsError(
                try AccountAddress.parseEncoded(vector.input),
                "\(vector.caseId): canonical negative should fail"
            ) { error in
                XCTAssertEqual(error as? AccountAddressError, .unsupportedAddressFormat, "\(vector.caseId): canonical hex parser must reject non-canonical format")
            }
        default:
            XCTFail("\(vector.caseId): unsupported negative format \(vector.format)")
        }
    }

    private func verify(error: Error, matches expected: ExpectedError, caseId: String) {
        guard let addressError = error as? AccountAddressError else {
            return XCTFail("\(caseId): unexpected error type \(error)")
        }
        let expectedCode = AccountAddressTests.expectedErrorCode(for: expected.kind)
        XCTAssertEqual(addressError.code, expectedCode, "\(caseId): error code mismatch")
        switch expected.kind {
        case "ChecksumMismatch":
            XCTAssertEqual(addressError, .checksumMismatch, "\(caseId): expected checksum mismatch")
        case "UnexpectedNetworkPrefix":
            if case let .unexpectedNetworkPrefix(expectedPrefix, foundPrefix) = addressError {
                XCTAssertEqual(expectedPrefix, expected.expected, "\(caseId): expected prefix mismatch")
                XCTAssertEqual(foundPrefix, expected.found, "\(caseId): found prefix mismatch")
            } else {
                XCTFail("\(caseId): expected unexpected network prefix, got \(addressError)")
            }
        case "InvalidI105Char":
            if case let .invalidI105Char(symbol) = addressError {
                XCTAssertEqual(String(symbol), expected.char, "\(caseId): invalid symbol mismatch")
            } else {
                XCTFail("\(caseId): expected invalid I105 symbol, got \(addressError)")
            }
        case "UnexpectedTrailingBytes":
            XCTAssertEqual(addressError, .unexpectedTrailingBytes, "\(caseId): expected unexpected trailing bytes")
        case "InvalidMultisigPolicy":
            if case let .invalidMultisigPolicy(reason) = addressError {
                XCTAssertEqual(reason, expected.policyError, "\(caseId): multisig policy mismatch")
            } else {
                XCTFail("\(caseId): expected invalid multisig policy, got \(addressError)")
            }
        case "InvalidI105Prefix":
            if case let .invalidI105Prefix(prefix) = addressError {
                if let expectedPrefix = expected.expected {
                    XCTAssertEqual(prefix, expectedPrefix, "\(caseId): i105 prefix mismatch")
                }
            } else {
                XCTFail("\(caseId): expected invalid i105 prefix, got \(addressError)")
            }
        case "UnknownAlgorithm":
            if case let .unknownAlgorithm(name) = addressError {
                if let expectedName = expected.policyError {
                    XCTAssertEqual(name.lowercased(), expectedName.lowercased(), "\(caseId): unsupported algorithm mismatch")
                }
            } else {
                XCTFail("\(caseId): expected unsupported algorithm, got \(addressError)")
            }
        default:
            XCTAssertEqual(addressError.identifier, expected.kind, "\(caseId): unexpected error kind")
        }
    }
}

private extension AccountAddressError {
    var identifier: String {
        switch self {
        case .nativeBridgeUnavailable:
            return "NativeBridgeUnavailable"
        case .unknownAlgorithm:
            return "UnknownAlgorithm"
        case .unsupportedImplementation:
            return "UnsupportedImplementation"
        case .decodeResourceLimit:
            return "DecodeResourceLimit"
        case .keyPayloadTooLong:
            return "KeyPayloadTooLong"
        case .invalidHeaderVersion:
            return "InvalidHeaderVersion"
        case .invalidNormVersion:
            return "InvalidNormVersion"
        case .invalidI105Prefix:
            return "InvalidI105Prefix"
        case .invalidI105Encoding:
            return "InvalidI105Encoding"
        case .invalidLength:
            return "InvalidLength"
        case .checksumMismatch:
            return "ChecksumMismatch"
        case .unexpectedNetworkPrefix:
            return "UnexpectedNetworkPrefix"
        case .unknownAddressClass:
            return "UnknownAddressClass"
        case .unexpectedExtensionFlag:
            return "UnexpectedExtensionFlag"
        case .unknownControllerTag:
            return "UnknownControllerTag"
        case .invalidPublicKey:
            return "InvalidPublicKey"
        case .unknownCurve:
            return "UnknownCurve"
        case .unexpectedTrailingBytes:
            return "UnexpectedTrailingBytes"
        case .invalidI105PrefixEncoding:
            return "InvalidI105PrefixEncoding"
        case .missingI105Sentinel:
            return "MissingI105Sentinel"
        case .invalidI105Base:
            return "InvalidI105Base"
        case .invalidI105Digit:
            return "InvalidI105Digit"
        case .i105TooShort:
            return "I105TooShort"
        case .invalidI105Char:
            return "InvalidI105Char"
        case .unsupportedAddressFormat:
            return "UnsupportedAddressFormat"
        case .multisigMemberOverflow:
            return "MultisigMemberOverflow"
        case .invalidMultisigPolicy:
            return "InvalidMultisigPolicy"
        }
    }
}

private extension AccountAddressTests {
    static func expectedErrorCode(for kind: String) -> String {
        return "ERR_" + camelToScreamingSnake(kind)
    }

    static func camelToScreamingSnake(_ value: String) -> String {
        var result = ""
        for (index, character) in value.enumerated() {
            if character.isUppercase, index > 0 {
                result.append("_")
            }
            result.append(contentsOf: character.uppercased())
        }
        return result
    }
}
