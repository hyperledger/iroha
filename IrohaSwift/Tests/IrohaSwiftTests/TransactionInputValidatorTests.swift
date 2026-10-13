import XCTest
@testable import IrohaSwift

final class TransactionInputValidatorTests: XCTestCase {
    private let sampleAid = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"

    private func validEd25519PublicKey(seed: UInt8) throws -> Data {
        try Keypair(privateKeyBytes: Data(repeating: seed, count: 32)).publicKey
    }

    private func i105(seed: UInt8 = 1) throws -> String {
        let address = try AccountAddress.fromAccount(publicKey: validEd25519PublicKey(seed: seed))
        return try address.toI105(networkPrefix: AccountId.defaultNetworkPrefix)
    }

    func testValidateCarriesExactNetworkId() throws {
        let authority = try i105(seed: 3)
        let ids = try TransactionInputValidator.validate(
            networkId: TestNetworkIds.canonical,
            authorityId: authority,
            assetDefinitionId: sampleAid
        )
        XCTAssertEqual(ids.networkId, TestNetworkIds.canonical)
    }

    func testValidateRejectsMalformedAuthority() {
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: "alice",
                                                   assetDefinitionId: sampleAid)
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "authority", value: "alice"))
        }
    }

    func testValidateRejectsAuthorityWithReservedCharacters() {
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: "alice#bad@banka.dataspace",
                                                   assetDefinitionId: sampleAid)
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "authority", value: "alice#bad@banka.dataspace"))
        }
    }

    func testValidateRejectsMalformedAssetDefinition() throws {
        let authority = try i105(seed: 2)
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: authority,
                                                   assetDefinitionId: "cbdc#banka")
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetDefinitionId("cbdc#banka"))
        }
    }

    func testValidateRejectsBase58AssetDefinitionWithInvalidChecksum() throws {
        let authority = try i105(seed: 2)
        let invalidDefinition = "66owaQmAQMuHxPzxUN3bqZ6FJfDb"

        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: authority,
                                                   assetDefinitionId: invalidDefinition)
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetDefinitionId(invalidDefinition))
        }
    }

    func testValidateRequiresCanonicalDataspaceScopeSuffix() throws {
        let authority = try i105(seed: 2)
        XCTAssertNoThrow(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: authority,
                                                   assetDefinitionId: "\(sampleAid)#dataspace:0")
        )
        XCTAssertNoThrow(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: authority,
                                                   assetDefinitionId: "\(sampleAid)#dataspace:42")
        )

        for suffix in [
            "dataspace:",
            "dataspace:+1",
            "dataspace:01",
            "dataspace:-1",
            "dataspace:1.0",
            "DATASPACE:1",
            "dataspace:18446744073709551616",
        ] {
            let value = "\(sampleAid)#\(suffix)"
            XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                       authorityId: authority,
                                                       assetDefinitionId: value),
                "Expected non-canonical dataspace scope to fail: \(suffix)"
            ) { error in
                XCTAssertEqual(error as? TransactionInputError,
                               .malformedAssetDefinitionId(value))
            }
        }
    }

    func testAssetDefinitionAddressCodecRejectsInvalidChecksum() {
        XCTAssertEqual(
            AssetDefinitionAddressCodec.canonicalDefinitionLiteral(" \(sampleAid) "),
            sampleAid
        )
        let uuidBytes = Data([
            0x6e, 0x15, 0x6b, 0x50, 0x10, 0xe6, 0x45, 0xf8,
            0x83, 0xeb, 0x83, 0x19, 0x46, 0xb8, 0x8d, 0xb8
        ])
        XCTAssertEqual(AssetDefinitionAddressCodec.uuidBytes(sampleAid), uuidBytes)
        XCTAssertEqual(AssetDefinitionAddressCodec.definitionLiteral(uuidBytes: uuidBytes), sampleAid)
        XCTAssertNil(AssetDefinitionAddressCodec.definitionLiteral(uuidBytes: Data(repeating: 0x01, count: 15)))
        XCTAssertNil(
            AssetDefinitionAddressCodec.canonicalDefinitionLiteral("66owaQmAQMuHxPzxUN3bqZ6FJfDb")
        )
        XCTAssertNil(
            AssetDefinitionAddressCodec.uuidBytes("66owaQmAQMuHxPzxUN3bqZ6FJfDb")
        )
    }

    func testValidateRejectsAssetDefinitionWithReservedCharacters() throws {
        let authority = try i105(seed: 3)
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: authority,
                                                   assetDefinitionId: "rose$#wonderland")
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetDefinitionId("rose$#wonderland"))
        }
    }

    func testValidateRejectsSurroundingWhitespace() throws {
        let authority = try i105(seed: 4)
        let destination = try i105(seed: 5)

        XCTAssertThrowsError(
            try TransactionInputValidator.validate(
                networkId: TestNetworkIds.canonical,
                authorityId: " \(authority) ",
                assetDefinitionId: sampleAid,
                accountIds: [.init(field: "destination", value: destination)]
            )
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "authority", value: " \(authority) "))
        }
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(
                networkId: TestNetworkIds.canonical,
                authorityId: authority,
                assetDefinitionId: " \(sampleAid) ",
                accountIds: [.init(field: "destination", value: destination)]
            )
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetDefinitionId(" \(sampleAid) "))
        }
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(
                networkId: TestNetworkIds.canonical,
                authorityId: authority,
                assetDefinitionId: sampleAid,
                accountIds: [.init(field: "destination", value: " \(destination) ")]
            )
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "destination", value: " \(destination) "))
        }
    }

    func testSanitizeMetadataTargetRejectsMalformedAssetId() {
        let malformed = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        XCTAssertThrowsError(try TransactionInputValidator.sanitizeMetadataTarget(.asset(malformed))) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetId(malformed))
        }
    }

    func testSanitizeMetadataTargetRejectsTextualAssetId() {
        XCTAssertThrowsError(try TransactionInputValidator.sanitizeMetadataTarget(.asset("ro$se#wonderland#alice@banka.dataspace"))) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetId("ro$se#wonderland#alice@banka.dataspace"))
        }
    }

    func testSanitizeMetadataTargetRejectsMalformedRwaId() {
        XCTAssertThrowsError(try TransactionInputValidator.sanitizeMetadataTarget(.rwa("lot-001"))) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedRwaId(field: "target", value: "lot-001"))
        }
    }

    func testSanitizeMetadataTargetRejectsSurroundingWhitespace() throws {
        let authority = try i105(seed: 6)
        XCTAssertThrowsError(
            try TransactionInputValidator.sanitizeMetadataTarget(.account("  \(authority)  "))
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "target", value: "  \(authority)  "))
        }
        XCTAssertThrowsError(
            try TransactionInputValidator.sanitizeMetadataTarget(.domain("  wonderland.universal  "))
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedDomainId(field: "target", value: "  wonderland.universal  "))
        }
        XCTAssertThrowsError(
            try TransactionInputValidator.sanitizeMetadataTarget(.asset("  \(sampleAid)  "))
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAssetId("  \(sampleAid)  "))
        }
        XCTAssertThrowsError(
            try TransactionInputValidator.sanitizeLabel(" alias ", field: "alias")
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedLabel(field: "alias", value: " alias "))
        }
    }

    func testSanitizeMetadataTargetRejectsBareDomainId() {
        XCTAssertThrowsError(try TransactionInputValidator.sanitizeMetadataTarget(.domain("wonderland"))) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedDomainId(field: "target", value: "wonderland"))
        }
    }

    func testSanitizeDomainIdUsesExplicitDomainNormalization() throws {
        XCTAssertEqual(
            try TransactionInputValidator.sanitizeDomainId(
                "Wonderland.UNIVERSAL",
                field: "target"
            ),
            "wonderland.universal"
        )
        for invalid in ["wondérland.universal", "wonderland.uni@versal", "wonderland.uni versal"] {
            XCTAssertThrowsError(
                try TransactionInputValidator.sanitizeDomainId(invalid, field: "target")
            ) { error in
                XCTAssertEqual(
                    error as? TransactionInputError,
                    .malformedDomainId(field: "target", value: invalid)
                )
            }
        }
    }

    func testSanitizeAssetIdAcceptsCanonicalPublicLiteral() throws {
        let literal =
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        let target = try TransactionInputValidator.sanitizeMetadataTarget(.asset(literal))
        XCTAssertEqual(target.objectId, literal)
    }

    func testSanitizeRwaIdAcceptsCanonicalPublicLiteral() throws {
        let literal =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities.universal"
        let uppercaseHashLiteral =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF$commodities.universal"
        let target = try TransactionInputValidator.sanitizeMetadataTarget(.rwa(uppercaseHashLiteral))
        XCTAssertEqual(target.objectId, literal)
    }

    func testValidateAcceptsI105Authority() throws {
        let publicKey = try validEd25519PublicKey(seed: 0xAB)
        let i105 = try AccountId.makeI105(publicKey: publicKey)
        let ids = try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                         authorityId: i105)
        XCTAssertEqual(ids.authorityId, i105)
    }

    func testValidateAcceptsSoraSentinelAuthority() throws {
        let address = try AccountAddress.fromAccount(
            publicKey: validEd25519PublicKey(seed: 0xAD)
        )
        let i105 = try address.toI105(networkPrefix: AccountId.defaultNetworkPrefix)
        let ids = try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                         authorityId: i105)
        XCTAssertEqual(ids.authorityId, i105)
    }

    func testValidatePreservesTairaAuthorityAndDestinationDiscriminants() throws {
        let authority = try AccountAddress
            .fromAccount(publicKey: validEd25519PublicKey(seed: 0xB1))
            .toI105(networkPrefix: TairaTestnetProfile.i105Discriminant)
        let destination = try AccountAddress
            .fromAccount(publicKey: validEd25519PublicKey(seed: 0xB2))
            .toI105(networkPrefix: TairaTestnetProfile.i105Discriminant)

        let ids = try TransactionInputValidator.validate(
            networkId: TestNetworkIds.canonical,
            authorityId: authority,
            assetDefinitionId: sampleAid,
            accountIds: [.init(field: "destination", value: destination)]
        )

        XCTAssertEqual(ids.authorityId, authority)
        XCTAssertEqual(ids.accountIds["destination"], destination)
        XCTAssertEqual(
            try AccountAddress.inspectI105NetworkPrefix(ids.authorityId).chainDiscriminant,
            TairaTestnetProfile.i105Discriminant
        )
    }

    func testTransferRejectsCrossChainAuthorityAndDestination() throws {
        let authority = try AccountAddress
            .fromAccount(publicKey: validEd25519PublicKey(seed: 0xC1))
            .toI105(networkPrefix: AccountId.defaultNetworkPrefix)
        let destination = try AccountAddress
            .fromAccount(publicKey: validEd25519PublicKey(seed: 0xC2))
            .toI105(networkPrefix: TairaTestnetProfile.i105Discriminant)

        XCTAssertThrowsError(
            try TransactionInputValidator.validateSameChainDiscriminant(
                authority: authority, account: destination, field: "destination"
            )
        ) { error in
            XCTAssertEqual(
                error as? TransactionInputError,
                .accountChainDiscriminantMismatch(
                    field: "destination",
                    expected: AccountId.defaultNetworkPrefix,
                    actual: TairaTestnetProfile.i105Discriminant
                )
            )
        }
    }

    func testCanonicalNoritoAccountEncodersPreserveTairaLiteral() throws {
        let address = try AccountAddress.fromAccount(
            publicKey: validEd25519PublicKey(seed: 0xB3)
        )
        let taira = try address.toI105(
            networkPrefix: TairaTestnetProfile.i105Discriminant
        )
        let defaultNetwork = try address.toI105(
            networkPrefix: AccountId.defaultNetworkPrefix
        )

        XCTAssertEqual(
            try CanonicalNorito.encodeCompactAccountId(taira),
            try CanonicalNorito.encodeCompactAccountId(defaultNetwork)
        )
        XCTAssertEqual(
            try CanonicalNorito.encodeAccountId(taira),
            try CanonicalNorito.encodeAccountId(defaultNetwork)
        )
        XCTAssertThrowsError(
            try CanonicalNorito.encodeCompactAccountId(" \(taira)")
        )
        XCTAssertThrowsError(
            try CanonicalNorito.encodeAccountId("\(taira) ")
        )
    }

    func testValidateRejectsI105WithDomainSuffix() throws {
        let publicKey = try validEd25519PublicKey(seed: 0xAC)
        let i105 = try AccountId.makeI105(publicKey: publicKey)
        let literal = "\(i105)@banka.dataspace"
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: literal)
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "authority", value: literal))
        }
    }

    func testValidateRejectsUaidAuthority() throws {
        let uaidHex = String(repeating: "0", count: 63) + "f"
        let literal = "uaid:\(uaidHex)"
        XCTAssertThrowsError(
            try TransactionInputValidator.validate(networkId: TestNetworkIds.canonical,
                                                   authorityId: literal)
        ) { error in
            XCTAssertEqual(error as? TransactionInputError,
                           .malformedAccountId(field: "authority", value: literal))
        }
    }
}
