import XCTest
@testable import IrohaSwift

final class TransactionParityFixturesTests: XCTestCase {
    private static var cachedFixtures: TransactionFixtureLoader?
    private static var cachedKeypair: Keypair?

    func testExpectedSignedTransactionSchemaHashMatchesRustManifest() throws {
        let loader = try Self.fixtures()
        XCTAssertEqual(
            ToriiNodeCapabilities.expectedSignedTransactionSchemaHashHex,
            loader.signedSchemaHashHex
        )
    }

    func testFixtureExecutableDecoderPreservesMixedBatchOrder() throws {
        let data = Data(#"""
        {
          "Batch": [
            {"Instruction": {"kind": "Grant", "arguments": {"action": "GrantPermission"}}},
            {"ContractCall": {
              "contract_address": "irohac1example",
              "expected_code_hash": "hash:0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A9#6A22",
              "entrypoint": "run",
              "arguments": [1, 2, 3, 4]
            }},
            {"Instruction": {"kind": "Revoke", "arguments": {"action": "RevokePermission"}}}
          ]
        }
        """#.utf8)
        let decoder = JSONDecoder()
        let executable = try decoder.decode(TransactionExecutable.self, from: data)

        guard case let .batch(items) = executable else {
            return XCTFail("expected mixed executable batch")
        }
        XCTAssertEqual(items.count, 3)
        guard case let .instruction(first) = items[0] else {
            return XCTFail("expected leading instruction")
        }
        XCTAssertEqual(first.kind, "Grant")
        guard case let .contractCall(invocation) = items[1] else {
            return XCTFail("expected middle contract call")
        }
        XCTAssertEqual(invocation.entrypoint, "run")
        XCTAssertEqual(invocation.arguments, [1, 2, 3, 4])
        guard case let .instruction(last) = items[2] else {
            return XCTFail("expected trailing instruction")
        }
        XCTAssertEqual(last.kind, "Revoke")
    }

    func testSwiftParityManifestSignedHashesUseCompactExternalEntrypoint() throws {
        let loader = try Self.fixtures()
        XCTAssertEqual(loader.manifests.count, 3)
        for (name, entry) in loader.manifests {
            let signedBytes = try XCTUnwrap(
                Data(base64Encoded: entry.signedBase64),
                "invalid signed_base64 for \(name)"
            )
            let payloadBytes = try canonicalSignedTransactionPayload(signedBytes)
            var compact = CompactNoritoWriter()
            compact.writeUInt32LE(0)
            compact.writeField(payloadBytes)
            XCTAssertEqual(
                IrohaHash.hash(compact.data).hexEncodedString(),
                entry.signedHash,
                "compact External hash mismatch for \(name)"
            )
            XCTAssertNotEqual(
                IrohaHash.hash(signedBytes).hexEncodedString(),
                entry.signedHash,
                "raw signed bytes must not alias compact External hash for \(name)"
            )
        }
    }

    func testSwiftParityFixturesUseOnlyTheTairaAddressDiscriminant() throws {
        let loader = try Self.fixtures()
        XCTAssertEqual(FixtureConstants.networkPrefix, TairaTestnetProfile.i105Discriminant)
        for (name, payload) in loader.payloads {
            let authorityPrefix = try AccountAddress.inspectI105NetworkPrefix(
                payload.authority,
                expectedPrefix: TairaTestnetProfile.i105Discriminant
            )
            XCTAssertEqual(authorityPrefix.sentinel, "test", "\(name): authority sentinel")
            XCTAssertEqual(
                authorityPrefix.chainDiscriminant,
                TairaTestnetProfile.i105Discriminant,
                "\(name): authority discriminant"
            )
            let instructions: [TransactionInstruction]
            switch payload.executable {
            case let .instructions(items):
                instructions = items
            case let .batch(entries):
                instructions = entries.compactMap { entry in
                    guard case let .instruction(instruction) = entry else { return nil }
                    return instruction
                }
            case .ivm, .contractCall:
                instructions = []
            }
            for instruction in instructions {
                guard let destination = instruction.arguments["destination"] else { continue }
                let destinationPrefix = try AccountAddress.inspectI105NetworkPrefix(
                    destination,
                    expectedPrefix: TairaTestnetProfile.i105Discriminant
                )
                XCTAssertEqual(destinationPrefix.sentinel, "test", "\(name): destination sentinel")
                XCTAssertEqual(
                    destinationPrefix.chainDiscriminant,
                    TairaTestnetProfile.i105Discriminant,
                    "\(name): destination discriminant"
                )
            }
        }
        let legacyMinamotoLiteral =
            "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53"
        XCTAssertThrowsError(
            try AccountAddress.parseEncoded(
                legacyMinamotoLiteral,
                expectedPrefix: TairaTestnetProfile.i105Discriminant
            )
        )
    }

    func testSwiftTransferAssetFixtureMatchesRustEncoder() throws {
        try ensureBridgeAvailable()
        try assertFixture(named: "swift_transfer_asset_basic") { fixture, keypair in
            let instruction = try fixture.payload.instruction(kind: "Transfer", action: "TransferAsset")
            let assetDefinitionId = try instruction.argument(named: "asset_definition_id")
            let destination = try instruction.argument(named: "destination")
            let quantity = try instruction.argument(named: "quantity")
            let authority = try TransactionParityFixturesTests.canonicalAccountId(
                fixture.payload.authority,
                field: "payload.authority"
            )
            let canonicalDestination = try TransactionParityFixturesTests.canonicalAccountId(
                destination,
                field: "Transfer.TransferAsset.destination"
            )
            let request = TransferRequest(networkId: fixture.payload.networkId,
                                          authority: authority,
                                          assetDefinitionId: assetDefinitionId,
                                          quantity: quantity,
                                          destination: canonicalDestination,
                                          description: fixture.payload.stringMetadata(named: "memo"),
                                          feePayment: fixture.payload.feePayment,
                                          ttlMs: fixture.payload.timeToLiveMs,
                                          nonce: fixture.payload.nonce)
            return try SwiftTransactionEncoder.encodeTransfer(transfer: request,
                                                              keypair: keypair,
                                                              creationTimeMs: fixture.payload.creationTimeMs)
        }
    }

    func testReferenceSignatureParityRejectsInvalidSignaturesFramingAndDifferentPayloads() throws {
        let loader = try Self.fixtures()
        let transfer = try loader.fixture(named: "swift_transfer_asset_basic")
        let transferSigned = try XCTUnwrap(Data(base64Encoded: transfer.manifest.signedBase64))
        let transferWire = Data([1]) + transferSigned
        let transferHash = try XCTUnwrap(Data(hexString: transfer.manifest.signedHash))
        func envelope(_ wire: Data, signed: Data? = nil) -> SignedTransactionEnvelope {
            SignedTransactionEnvelope(
                norito: wire, signedTransaction: signed ?? Data(wire.dropFirst()),
                payload: nil, transactionHash: transferHash
            )
        }
        XCTAssertEqual(
            try canonicalSignedTransactionUsingReferenceSignature(
                envelope(transferWire), referenceWire: transferWire
            ),
            transferWire
        )

        let mint = try loader.fixture(named: "swift_mint_asset_basic")
        let mintWire = Data([1]) + (try XCTUnwrap(Data(base64Encoded: mint.manifest.signedBase64)))
        let verifiedMint = try ToriiCanonicalTransactionDraft.inspectVersionedSignedTransaction(
            mintWire, context: "valid different signing-parity payload"
        )
        XCTAssertNotEqual(verifiedMint.transactionPayload, try canonicalSignedTransactionPayload(transferSigned))
        // Both are independently valid, but the reference signs a different payload.
        XCTAssertThrowsError(try canonicalSignedTransactionUsingReferenceSignature(
            envelope(transferWire), referenceWire: mintWire
        ))

        var transferReader = CanonicalNoritoReader(data: transferSigned)
        _ = try transferReader.readCompactField()
        var mintReader = CanonicalNoritoReader(data: Data(mintWire.dropFirst()))
        _ = try mintReader.readCompactField()
        // A well-formed signature for Mint must not authenticate the Transfer payload,
        // even if replacing it with the valid reference would conceal that failure.
        let forgedWire = Data(mintWire.prefix(1 + mintReader.offset))
            + Data(transferWire.dropFirst(1 + transferReader.offset))
        for invalidWire in [forgedWire, transferWire + Data([0])] {
            XCTAssertThrowsError(try canonicalSignedTransactionUsingReferenceSignature(
                envelope(invalidWire), referenceWire: transferWire
            ))
            XCTAssertThrowsError(try canonicalSignedTransactionUsingReferenceSignature(
                envelope(transferWire), referenceWire: invalidWire
            ))
        }
        XCTAssertThrowsError(try canonicalSignedTransactionUsingReferenceSignature(
            envelope(transferWire, signed: transferSigned + Data([0])), referenceWire: transferWire
        ))
    }

    func testSwiftMintAssetFixtureMatchesRustEncoder() throws {
        try ensureBridgeAvailable()
        try assertFixture(named: "swift_mint_asset_basic") { fixture, keypair in
            let instruction = try fixture.payload.instruction(kind: "Mint", action: "MintAsset")
            let assetDefinitionId = try instruction.argument(named: "asset_definition_id")
            let destination = try instruction.argument(named: "destination")
            let quantity = try instruction.argument(named: "quantity")
            let authority = try TransactionParityFixturesTests.canonicalAccountId(
                fixture.payload.authority,
                field: "payload.authority"
            )
            let canonicalDestination = try TransactionParityFixturesTests.canonicalAccountId(
                destination,
                field: "Mint.MintAsset.destination"
            )
            let request = MintRequest(networkId: fixture.payload.networkId,
                                      authority: authority,
                                      assetDefinitionId: assetDefinitionId,
                                      quantity: quantity,
                                      destination: canonicalDestination,
                                      feePayment: fixture.payload.feePayment,
                                      ttlMs: fixture.payload.timeToLiveMs,
                                      nonce: fixture.payload.nonce)
            return try SwiftTransactionEncoder.encodeMint(request: request,
                                                          keypair: keypair,
                                                          creationTimeMs: fixture.payload.creationTimeMs)
        }
    }

    func testSwiftBurnAssetFixtureMatchesRustEncoder() throws {
        try ensureBridgeAvailable()
        try assertFixture(named: "swift_burn_asset_basic") { fixture, keypair in
            let instruction = try fixture.payload.instruction(kind: "Burn", action: "BurnAsset")
            let assetDefinitionId = try instruction.argument(named: "asset_definition_id")
            let destination = try instruction.argument(named: "destination")
            let quantity = try instruction.argument(named: "quantity")
            let authority = try TransactionParityFixturesTests.canonicalAccountId(
                fixture.payload.authority,
                field: "payload.authority"
            )
            let canonicalDestination = try TransactionParityFixturesTests.canonicalAccountId(
                destination,
                field: "Burn.BurnAsset.destination"
            )
            let request = BurnRequest(networkId: fixture.payload.networkId,
                                      authority: authority,
                                      assetDefinitionId: assetDefinitionId,
                                      quantity: quantity,
                                      destination: canonicalDestination,
                                      feePayment: fixture.payload.feePayment,
                                      ttlMs: fixture.payload.timeToLiveMs,
                                      nonce: fixture.payload.nonce)
            return try SwiftTransactionEncoder.encodeBurn(request: request,
                                                          keypair: keypair,
                                                          creationTimeMs: fixture.payload.creationTimeMs)
        }
    }

    func testFixtureSeedKeypairMatchesBridge() throws {
        try ensureBridgeAvailable()
        guard let seed = Data(hexString: FixtureConstants.signingSeedHex) else {
            throw FixtureError.invalidSigningSeed
        }
        guard let derived = NoritoNativeBridge.shared.keypairFromSeed(algorithm: .ed25519, seed: seed) else {
            throw FixtureError.bridgeKeypairUnavailable
        }
        let keypair = try Keypair(privateKeyBytes: derived.privateKey)
        XCTAssertEqual(keypair.privateKeyBytes, derived.privateKey)
        XCTAssertEqual(keypair.publicKey, derived.publicKey)
    }

    func testCompactAndroidGoldenMatchesSwiftEntrypointHasher() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/norito_rpc/iroha_compact_hash_vector.properties")
        let fixtureText = try String(contentsOf: fixtureURL, encoding: .utf8)
        let fixture = try Self.properties(fixtureText)
        XCTAssertEqual(fixture["schema.version"], "2")
        XCTAssertEqual(fixture["source.fixture"], "transfer_asset")
        let versioned = try TransactionFixtureLoader.decodeCanonicalBase64(
            try XCTUnwrap(fixture["versioned.base64"]),
            context: "versioned.base64"
        )
        XCTAssertEqual(versioned.count, Int(try XCTUnwrap(fixture["versioned.bytes"])))
        XCTAssertEqual(versioned.first, 1)

        let bare = Data(versioned.dropFirst())
        XCTAssertEqual(bare.count, Int(try XCTUnwrap(fixture["bare.bytes"])))
        let payload = try canonicalSignedTransactionPayload(bare)
        var compact = CompactNoritoWriter()
        compact.writeUInt32LE(0)
        compact.writeField(payload)
        XCTAssertEqual(
            Data(compact.data.prefix(6)).hexEncodedString(),
            fixture["canonical.prefix.hex"]
        )
        XCTAssertEqual(
            IrohaHash.hash(compact.data).hexEncodedString(),
            fixture["canonical.hash"]
        )

        var fixedWidth = CanonicalNoritoWriter()
        fixedWidth.writeUInt32LE(0)
        fixedWidth.writeField(payload)
        XCTAssertNotEqual(
            IrohaHash.hash(fixedWidth.data).hexEncodedString(),
            fixture["canonical.hash"],
            "fixed-u64 field lengths must not alias canonical COMPACT_LEN framing"
        )
    }

    func testParityFixtureLoadersRejectDuplicateIdentitiesAndBase64Aliases() throws {
        let first = TransactionFixtureLoader.ManifestEntry(
            name: "first",
            payloadBase64: "AA==",
            payloadHash: "payload-hash",
            signedBase64: "AQ==",
            signedHash: "signed-hash"
        )
        let renamedClone = TransactionFixtureLoader.ManifestEntry(
            name: "renamed-clone",
            payloadBase64: first.payloadBase64,
            payloadHash: first.payloadHash,
            signedBase64: first.signedBase64,
            signedHash: first.signedHash
        )
        XCTAssertThrowsError(
            try TransactionFixtureLoader.validatedManifests([first, renamedClone])
        ) { error in
            guard case FixtureError.duplicatePayloadHash("payload-hash") = error else {
                return XCTFail("unexpected renamed-clone error: \(error)")
            }
        }

        let duplicateKeyData = Data(
            #"[{"name":"first","name":"second"}]"#.utf8
        )
        XCTAssertThrowsError(
            try StrictFixtureJSON.decode(
                [TransactionFixtureLoader.PayloadEntry].self,
                from: duplicateKeyData,
                using: JSONDecoder(),
                context: "duplicate-key-test"
            )
        ) { error in
            guard case StrictFixtureJSONError.duplicateKey("name", "duplicate-key-test") = error else {
                return XCTFail("unexpected duplicate-key error: \(error)")
            }
        }

        for malformed in ["YQ!!", "Y Q==", "YQ=", "YQ===", "YR=="] {
            XCTAssertThrowsError(
                try TransactionFixtureLoader.decodeCanonicalBase64(
                    malformed,
                    context: "adversarial.fixture"
                )
            ) { error in
                guard case FixtureError.invalidBase64("adversarial.fixture") = error else {
                    return XCTFail("unexpected base64 error for \(malformed): \(error)")
                }
            }
        }
    }

    func testPayloadFixtureLoaderRequiresPositiveIntegerTtl() throws {
        let payloadURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/swift_parity_payloads.json")
        let source = try Data(contentsOf: payloadURL)

        func loadFixture(ttl: Any?) throws -> TransactionFixtureLoader.PayloadEntry {
            guard var entries =
                    try JSONSerialization.jsonObject(with: source) as? [[String: Any]],
                  var payload = entries.first?["payload"] as? [String: Any] else {
                throw FixtureError.missingFixture("swift parity payload")
            }
            if let ttl {
                payload["time_to_live_ms"] = ttl
            } else {
                payload.removeValue(forKey: "time_to_live_ms")
            }
            entries[0]["payload"] = payload
            let data = try JSONSerialization.data(withJSONObject: entries)
            let decoder = JSONDecoder()
            return try StrictFixtureJSON.decode(
                [TransactionFixtureLoader.PayloadEntry].self,
                from: data,
                using: decoder,
                context: "ttl-test"
            )[0]
        }

        XCTAssertEqual(try loadFixture(ttl: 1).payload.timeToLiveMs, 1)
        XCTAssertEqual(try loadFixture(ttl: 100_000).payload.timeToLiveMs, 100_000)

        let invalidValues: [(String, Any?)] = [
            ("missing", nil),
            ("null", NSNull()),
            ("zero", 0),
            ("negative", -1),
            ("true", true),
            ("false", false),
            ("fractional", 1.5),
            ("string", "100000"),
        ]
        for (label, value) in invalidValues {
            XCTAssertThrowsError(try loadFixture(ttl: value), label)
        }
    }

    func testSwiftPayloadRequiresAuthorityFeePayer() throws {
        let invalidPayers: [Any] = ["owner", "Authority", "", true]
        for payer in invalidPayers {
            XCTAssertThrowsError(
                try decodeFirstSwiftPayload { payload in
                    guard var feePayment = payload["fee_payment"] as? [String: Any] else {
                        throw FixtureError.missingFixture("Swift parity fee payment")
                    }
                    feePayment["payer"] = payer
                    payload["fee_payment"] = feePayment
                },
                "payer \(String(describing: payer))"
            )
        }
    }

    func testSwiftPayloadRejectsNonEmptyChargeLimits() throws {
        XCTAssertThrowsError(
            try decodeFirstSwiftPayload { payload in
                guard var feePayment = payload["fee_payment"] as? [String: Any],
                      var feeValue = feePayment["value"] as? [String: Any] else {
                    throw FixtureError.missingFixture("Swift parity fee value")
                }
                feeValue["charge_limits"] = [["limit": 1]]
                feePayment["value"] = feeValue
                payload["fee_payment"] = feePayment
            }
        )
    }

    func testSwiftPayloadMetadataAcceptsNestedJsonValues() throws {
        let entry = try decodeFirstSwiftPayload { payload in
            let nested: [String: Any] = [
                "enabled": true,
                "values": [1, NSNull(), ["ratio": 1.5]] as [Any],
            ]
            payload["metadata"] = [
                "memo": "fixture memo",
                "nested": nested,
            ] as [String: Any]
        }

        XCTAssertEqual(entry.payload.metadata["memo"], .string("fixture memo"))
        XCTAssertEqual(
            entry.payload.metadata["nested"],
            .object([
                "enabled": .bool(true),
                "values": .array([
                    .number(1),
                    .null,
                    .object(["ratio": .number(1.5)]),
                ]),
            ])
        )
        XCTAssertEqual(entry.payload.stringMetadata(named: "memo"), "fixture memo")
        XCTAssertNil(entry.payload.stringMetadata(named: "nested"))
    }

    func testSwiftManifestRejectsLegacyRootAndEntryFields() throws {
        let decoder = JSONDecoder()
        let legacyRoot = Data(
            #"{"fixtures":[],"generated_at":"legacy","schema":{},"signing_key":{}}"#.utf8
        )
        XCTAssertThrowsError(
            try StrictFixtureJSON.decode(
                TransactionFixtureLoader.ManifestFile.self,
                from: legacyRoot,
                using: decoder,
                context: "legacy-root"
            )
        )

        let legacyEntry = Data(
            #"{"fixtures":[{"name":"swift_transfer_asset_basic","payload_base64":"AA==","payload_hash":"00","signed_base64":"AQ==","signed_hash":"00","encoded_file":"legacy.norito"}]}"#.utf8
        )
        XCTAssertThrowsError(
            try StrictFixtureJSON.decode(
                TransactionFixtureLoader.ManifestFile.self,
                from: legacyEntry,
                using: decoder,
                context: "legacy-entry"
            )
        )
    }

    func testCompactPropertiesRejectDuplicateKeys() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/norito_rpc/iroha_compact_hash_vector.properties")
        let fixtureText = try String(contentsOf: fixtureURL, encoding: .utf8)
        XCTAssertThrowsError(
            try Self.properties(fixtureText + "\ncanonical.hash=duplicate\n")
        ) { error in
            guard case FixtureError.duplicateManifestProperty("canonical.hash") = error else {
                return XCTFail("unexpected duplicate-property error: \(error)")
            }
        }
    }

    // MARK: - Helpers

    private func decodeFirstSwiftPayload(
        mutating mutation: (inout [String: Any]) throws -> Void
    ) throws -> TransactionFixtureLoader.PayloadEntry {
        let payloadURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/swift_parity_payloads.json")
        let source = try Data(contentsOf: payloadURL)
        guard var entries = try JSONSerialization.jsonObject(with: source) as? [[String: Any]],
              var payload = entries.first?["payload"] as? [String: Any] else {
            throw FixtureError.missingFixture("Swift parity payload")
        }
        try mutation(&payload)
        entries[0]["payload"] = payload
        let data = try JSONSerialization.data(withJSONObject: entries)
        return try StrictFixtureJSON.decode(
            [TransactionFixtureLoader.PayloadEntry].self,
            from: data,
            using: JSONDecoder(),
            context: "Swift parity payload mutation test"
        )[0]
    }

    private func assertFixture(
        named name: String,
        encoder: (CombinedTransactionFixture, Keypair) throws -> SignedTransactionEnvelope
    ) throws {
        let loader = try Self.fixtures()
        let fixture = try loader.fixture(named: name)
        let keypair = try Self.fixtureKeypair()
        do {
            let envelope = try NoritoNativeBridge.shared.withChainDiscriminant(FixtureConstants.networkPrefix) {
                try encoder(fixture, keypair)
            }
            let actual: String
            if name == "swift_transfer_asset_basic" {
                // CryptoKit may hedge Ed25519 signatures. Verify both signatures, then
                // retain exact Rust framing parity with the reference signature field.
                let reference = try XCTUnwrap(Data(base64Encoded: fixture.manifest.signedBase64))
                let wire = try canonicalSignedTransactionUsingReferenceSignature(
                    envelope, referenceWire: Data([1]) + reference
                )
                XCTAssertEqual(wire, Data([1]) + reference, "versioned Rust framing parity for \(name)")
                actual = Data(wire.dropFirst()).base64EncodedString()
            } else {
                actual = envelope.signedTransaction.base64EncodedString()
            }
            XCTAssertEqual(
                actual,
                fixture.manifest.signedBase64,
                "encoded transaction for \(name) did not match Rust fixture"
            )
            XCTAssertEqual(
                envelope.transactionHash.hexEncodedString(),
                fixture.manifest.signedHash,
                "entrypoint hash for \(name) did not match compact Rust framing"
            )
        } catch let SwiftTransactionEncoderError.nativeBridgeError(error) {
            throw error
        }
    }

    private func ensureBridgeAvailable() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.supportsTransactions(using: .ed25519),
            "NoritoBridge ed25519 transaction encoder unavailable"
        )
        guard let seed = Data(hexString: FixtureConstants.signingSeedHex) else {
            throw FixtureError.invalidSigningSeed
        }
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.keypairFromSeed(algorithm: .ed25519, seed: seed) != nil,
            "NoritoBridge ed25519 seed derivation unavailable"
        )
    }

    private static func fixtures() throws -> TransactionFixtureLoader {
        if let cached = cachedFixtures { return cached }
        let loader = try TransactionFixtureLoader()
        cachedFixtures = loader
        return loader
    }

    private static func fixtureKeypair() throws -> Keypair {
        if let cached = cachedKeypair { return cached }
        guard let bytes = Data(hexString: FixtureConstants.signingSeedHex) else {
            throw FixtureError.invalidSigningSeed
        }
        guard let derived = NoritoNativeBridge.shared.keypairFromSeed(algorithm: .ed25519, seed: bytes) else {
            throw FixtureError.bridgeKeypairUnavailable
        }
        let keypair = try Keypair(privateKeyBytes: derived.privateKey)
        cachedKeypair = keypair
        return keypair
    }

    private static func canonicalAccountId(_ value: String, field: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw FixtureError.invalidAccountId(field: field, value: value)
        }
        do {
            _ = try AccountAddress.parseEncoded(trimmed)
            return trimmed
        } catch {
            throw FixtureError.invalidAccountId(field: field, value: value)
        }
    }

    private static func properties(_ contents: String) throws -> [String: String] {
        let expectedKeys: Set<String> = [
            "schema.version",
            "source.fixture",
            "versioned.bytes",
            "versioned.sha256",
            "bare.bytes",
            "compact.length.hex",
            "canonical.prefix.hex",
            "canonical.hash",
            "payload.prehash",
            "versioned.base64",
        ]
        var result: [String: String] = [:]
        for line in contents.split(whereSeparator: { $0.isNewline }) {
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let separator = line.firstIndex(of: "=") else {
                throw FixtureError.invalidManifestProperty(String(line))
            }
            let key = String(line[..<separator])
            let value = String(line[line.index(after: separator)...])
            guard !key.isEmpty, !value.isEmpty else {
                throw FixtureError.invalidManifestProperty(String(line))
            }
            guard result[key] == nil else {
                throw FixtureError.duplicateManifestProperty(key)
            }
            result[key] = value
        }
        guard Set(result.keys) == expectedKeys else {
            throw FixtureError.unexpectedManifestProperties(Set(result.keys))
        }
        return result
    }
}

// MARK: - Strict Native JSON

struct FixtureJSONCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

func requireExactFixtureKeys(
    _ decoder: Decoder,
    _ expected: Set<String>,
    context: String
) throws {
    let container = try decoder.container(keyedBy: FixtureJSONCodingKey.self)
    let actual = Set(container.allKeys.map(\.stringValue))
    guard actual == expected else {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath,
                debugDescription: "\(context) fields must be exactly \(expected.sorted()); got \(actual.sorted())"
            )
        )
    }
}

enum StrictFixtureJSON {
    static func decode<T: Decodable>(
        _ type: T.Type,
        from data: Data,
        using decoder: JSONDecoder,
        context: String
    ) throws -> T {
        var scanner = FixtureJSONDuplicateKeyScanner(data: data, context: context)
        try scanner.validate()
        return try decoder.decode(type, from: data)
    }
}

enum StrictFixtureJSONError: Error, Equatable {
    case duplicateKey(String, String)
    case malformed(String)
}

private struct FixtureJSONDuplicateKeyScanner {
    private let bytes: [UInt8]
    private let context: String
    private var offset = 0

    init(data: Data, context: String) {
        bytes = Array(data)
        self.context = context
    }

    mutating func validate() throws {
        skipWhitespace()
        try parseValue()
        skipWhitespace()
        guard offset == bytes.count else {
            throw malformed("trailing content")
        }
    }

    private mutating func parseValue() throws {
        skipWhitespace()
        guard let byte = current else { throw malformed("unexpected end of input") }
        switch byte {
        case 0x7B: try parseObject() // {
        case 0x5B: try parseArray() // [
        case 0x22: _ = try parseString() // "
        case 0x74: try parseLiteral("true")
        case 0x66: try parseLiteral("false")
        case 0x6E: try parseLiteral("null")
        case 0x2D, 0x30 ... 0x39: try parseNumber()
        default: throw malformed("unexpected byte \(byte)")
        }
    }

    private mutating func parseObject() throws {
        try consume(0x7B)
        skipWhitespace()
        if current == 0x7D {
            offset += 1
            return
        }
        var keys = Set<String>()
        while true {
            skipWhitespace()
            let key = try parseString()
            guard keys.insert(key).inserted else {
                throw StrictFixtureJSONError.duplicateKey(key, context)
            }
            skipWhitespace()
            try consume(0x3A)
            try parseValue()
            skipWhitespace()
            if current == 0x7D {
                offset += 1
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseArray() throws {
        try consume(0x5B)
        skipWhitespace()
        if current == 0x5D {
            offset += 1
            return
        }
        while true {
            try parseValue()
            skipWhitespace()
            if current == 0x5D {
                offset += 1
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseString() throws -> String {
        let start = offset
        try consume(0x22)
        while let byte = current {
            if byte == 0x22 {
                offset += 1
                let token = Data(bytes[start ..< offset])
                do {
                    return try JSONDecoder().decode(String.self, from: token)
                } catch {
                    throw malformed("invalid string")
                }
            }
            if byte < 0x20 { throw malformed("unescaped control byte in string") }
            offset += 1
            if byte == 0x5C {
                guard let escaped = current else { throw malformed("truncated escape") }
                offset += 1
                if escaped == 0x75 {
                    for _ in 0 ..< 4 {
                        guard let hex = current, isHex(hex) else {
                            throw malformed("invalid unicode escape")
                        }
                        offset += 1
                    }
                } else if ![0x22, 0x2F, 0x5C, 0x62, 0x66, 0x6E, 0x72, 0x74].contains(escaped) {
                    throw malformed("invalid string escape")
                }
            }
        }
        throw malformed("unterminated string")
    }

    private mutating func parseLiteral(_ literal: StaticString) throws {
        for byte in String(describing: literal).utf8 {
            try consume(byte)
        }
    }

    private mutating func parseNumber() throws {
        if current == 0x2D { offset += 1 }
        guard let first = current else { throw malformed("truncated number") }
        if first == 0x30 {
            offset += 1
        } else {
            guard (0x31 ... 0x39).contains(first) else { throw malformed("invalid number") }
            offset += 1
            while let byte = current, (0x30 ... 0x39).contains(byte) { offset += 1 }
        }
        if current == 0x2E {
            offset += 1
            try consumeDigits()
        }
        if current == 0x65 || current == 0x45 {
            offset += 1
            if current == 0x2B || current == 0x2D { offset += 1 }
            try consumeDigits()
        }
    }

    private mutating func consumeDigits() throws {
        guard let first = current, (0x30 ... 0x39).contains(first) else {
            throw malformed("number requires a digit")
        }
        while let byte = current, (0x30 ... 0x39).contains(byte) { offset += 1 }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard current == expected else { throw malformed("expected byte \(expected)") }
        offset += 1
    }

    private mutating func skipWhitespace() {
        while let byte = current, [0x20, 0x09, 0x0A, 0x0D].contains(byte) {
            offset += 1
        }
    }

    private var current: UInt8? {
        offset < bytes.count ? bytes[offset] : nil
    }

    private func malformed(_ detail: String) -> StrictFixtureJSONError {
        .malformed("\(context): \(detail) at byte \(offset)")
    }

    private func isHex(_ byte: UInt8) -> Bool {
        (0x30 ... 0x39).contains(byte)
            || (0x41 ... 0x46).contains(byte)
            || (0x61 ... 0x66).contains(byte)
    }
}

// MARK: - Fixture Loading

private struct TransactionFixtureLoader {
    struct PayloadEntry: Decodable {
        let name: String
        let payload: TransactionPayloadSpec

        private enum CodingKeys: String, CodingKey {
            case name
            case payload
        }

        init(from decoder: Decoder) throws {
            try requireExactFixtureKeys(
                decoder,
                ["name", "payload"],
                context: "Swift parity payload entry"
            )
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.decode(String.self, forKey: .name)
            payload = try container.decode(TransactionPayloadSpec.self, forKey: .payload)
        }
    }

    struct ManifestEntry: Decodable {
        let name: String
        let payloadBase64: String
        let payloadHash: String
        let signedBase64: String
        let signedHash: String

        private enum CodingKeys: String, CodingKey {
            case name
            case payloadBase64 = "payload_base64"
            case payloadHash = "payload_hash"
            case signedBase64 = "signed_base64"
            case signedHash = "signed_hash"
        }

        init(
            name: String,
            payloadBase64: String,
            payloadHash: String,
            signedBase64: String,
            signedHash: String
        ) {
            self.name = name
            self.payloadBase64 = payloadBase64
            self.payloadHash = payloadHash
            self.signedBase64 = signedBase64
            self.signedHash = signedHash
        }

        init(from decoder: Decoder) throws {
            try requireExactFixtureKeys(
                decoder,
                [
                    "name", "payload_base64", "payload_hash", "signed_base64", "signed_hash",
                ],
                context: "Swift parity manifest fixture"
            )
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.decode(String.self, forKey: .name)
            payloadBase64 = try container.decode(String.self, forKey: .payloadBase64)
            payloadHash = try container.decode(String.self, forKey: .payloadHash)
            signedBase64 = try container.decode(String.self, forKey: .signedBase64)
            signedHash = try container.decode(String.self, forKey: .signedHash)
        }
    }

    struct ManifestFile: Decodable {
        let fixtures: [ManifestEntry]

        private enum CodingKeys: String, CodingKey {
            case fixtures
        }

        init(from decoder: Decoder) throws {
            try requireExactFixtureKeys(
                decoder,
                ["fixtures"],
                context: "Swift parity manifest"
            )
            let container = try decoder.container(keyedBy: CodingKeys.self)
            fixtures = try container.decode([ManifestEntry].self, forKey: .fixtures)
        }
    }

    private struct SchemaHashFile: Decodable {
        let version: UInt64
        let entries: [SchemaHashEntry]

        private enum CodingKeys: String, CodingKey {
            case version
            case entries
        }

        init(from decoder: Decoder) throws {
            try requireExactFixtureKeys(
                decoder,
                ["entries", "version"],
                context: "canonical schema hash file"
            )
            let container = try decoder.container(keyedBy: CodingKeys.self)
            version = try container.decode(UInt64.self, forKey: .version)
            entries = try container.decode([SchemaHashEntry].self, forKey: .entries)
        }
    }

    private struct SchemaHashEntry: Decodable {
        let typeName: String
        let alias: String
        let schemaHash: String

        private enum CodingKeys: String, CodingKey {
            case typeName = "type_name"
            case alias
            case schemaHash = "schema_hash"
        }

        init(from decoder: Decoder) throws {
            try requireExactFixtureKeys(
                decoder,
                ["alias", "schema_hash", "type_name"],
                context: "canonical schema hash entry"
            )
            let container = try decoder.container(keyedBy: CodingKeys.self)
            typeName = try container.decode(String.self, forKey: .typeName)
            alias = try container.decode(String.self, forKey: .alias)
            schemaHash = try container.decode(String.self, forKey: .schemaHash)
        }
    }

    private static let expectedFixtureNames: Set<String> = [
        "swift_transfer_asset_basic",
        "swift_mint_asset_basic",
        "swift_burn_asset_basic",
    ]
    private static let maximumFixtureLength = 16 * 1024 * 1024

    let signedSchemaHashHex: String
    let payloads: [String: TransactionPayloadSpec]
    let manifests: [String: ManifestEntry]

    init() throws {
        let decoder = JSONDecoder()

        let payloadURL = TransactionFixtureLoader.fixturesRoot()
            .appendingPathComponent("swift_parity_payloads.json")
        let payloadData = try Data(contentsOf: payloadURL)
        let payloadEntries = try StrictFixtureJSON.decode(
            [PayloadEntry].self,
            from: payloadData,
            using: decoder,
            context: payloadURL.path
        )
        payloads = try Self.validatedPayloads(payloadEntries)

        let manifestURL = TransactionFixtureLoader.fixturesRoot()
            .appendingPathComponent("swift_parity_manifest.json")
        let manifestData = try Data(contentsOf: manifestURL)
        let manifest = try StrictFixtureJSON.decode(
            ManifestFile.self,
            from: manifestData,
            using: decoder,
            context: manifestURL.path
        )
        manifests = try Self.validatedManifests(manifest.fixtures)
        guard Set(payloads.keys) == Set(manifests.keys) else {
            throw FixtureError.fixtureNameSetMismatch(
                payloads: Set(payloads.keys),
                manifests: Set(manifests.keys)
            )
        }
        guard Set(payloads.keys) == Self.expectedFixtureNames else {
            throw FixtureError.unexpectedSwiftFixtureNames(Set(payloads.keys))
        }
        signedSchemaHashHex = try Self.loadSignedSchemaHash(using: decoder)
        let root = Self.fixturesRoot()
        for name in Self.expectedFixtureNames {
            guard payloads[name] != nil, let entry = manifests[name] else {
                throw FixtureError.missingFixture(name)
            }
            try Self.validateParity(manifest: entry, root: root)
        }
    }

    static func validatedPayloads(_ entries: [PayloadEntry]) throws -> [String: TransactionPayloadSpec] {
        var names = Set<String>()
        for entry in entries {
            guard !entry.name.isEmpty else {
                throw FixtureError.invalidFixtureName(entry.name)
            }
            guard names.insert(entry.name).inserted else {
                throw FixtureError.duplicateFixtureName(entry.name)
            }
            let expected: (kind: String, action: String)
            switch entry.name {
            case "swift_burn_asset_basic": expected = ("Burn", "BurnAsset")
            case "swift_mint_asset_basic": expected = ("Mint", "MintAsset")
            case "swift_transfer_asset_basic": expected = ("Transfer", "TransferAsset")
            default: throw FixtureError.invalidSwiftPayload(entry.name)
            }
            guard case let .instructions(instructions) = entry.payload.executable,
                  instructions.count == 1,
                  let instruction = instructions.first,
                  instruction.kind == expected.kind,
                  instruction.arguments["action"] == expected.action,
                  Set(instruction.arguments.keys) == [
                      "action", "asset_definition_id", "destination", "quantity",
                  ] else {
                throw FixtureError.invalidSwiftPayload(entry.name)
            }
        }
        return Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0.payload) })
    }

    static func validatedManifests(_ entries: [ManifestEntry]) throws -> [String: ManifestEntry] {
        var names = Set<String>()
        var payloadHashes = Set<String>()
        var payloadBytes = Set<Data>()
        var signedHashes = Set<String>()
        var signedBytes = Set<Data>()
        for entry in entries {
            guard !entry.name.isEmpty,
                  !entry.name.contains("/"),
                  !entry.name.contains("\\") else {
                throw FixtureError.invalidFixtureName(entry.name)
            }
            guard names.insert(entry.name).inserted else {
                throw FixtureError.duplicateFixtureName(entry.name)
            }
            guard payloadHashes.insert(entry.payloadHash).inserted else {
                throw FixtureError.duplicatePayloadHash(entry.payloadHash)
            }
            let decodedPayload = try decodeCanonicalBase64(
                entry.payloadBase64,
                context: "\(entry.name).payload_base64"
            )
            guard payloadBytes.insert(decodedPayload).inserted else {
                throw FixtureError.duplicatePayloadBytes(entry.name)
            }
            guard signedHashes.insert(entry.signedHash).inserted else {
                throw FixtureError.duplicateSignedHash(entry.signedHash)
            }
            let decodedSigned = try decodeCanonicalBase64(
                entry.signedBase64,
                context: "\(entry.name).signed_base64"
            )
            guard signedBytes.insert(decodedSigned).inserted else {
                throw FixtureError.duplicateSignedBytes(entry.name)
            }
        }
        return Dictionary(uniqueKeysWithValues: entries.map { ($0.name, $0) })
    }

    static func decodeCanonicalBase64(_ value: String, context: String) throws -> Data {
        guard let decoded = Data(base64Encoded: value),
              decoded.base64EncodedString() == value else {
            throw FixtureError.invalidBase64(context)
        }
        return decoded
    }

    private static func validateParity(manifest: ManifestEntry, root: URL) throws {
        guard isLowerHex(manifest.payloadHash, count: 64),
              isLowerHex(manifest.signedHash, count: 64) else {
            throw FixtureError.invalidFixtureHash(manifest.name)
        }
        let payloadBytes = try decodeCanonicalBase64(
            manifest.payloadBase64,
            context: "\(manifest.name).payload_base64"
        )
        let signedBytes = try decodeCanonicalBase64(
            manifest.signedBase64,
            context: "\(manifest.name).signed_base64"
        )
        guard !payloadBytes.isEmpty,
              payloadBytes.count <= maximumFixtureLength,
              !signedBytes.isEmpty,
              signedBytes.count <= maximumFixtureLength,
              IrohaHash.hash(payloadBytes).hexEncodedString() == manifest.payloadHash,
              try canonicalSignedTransactionPayload(signedBytes) == payloadBytes else {
            throw FixtureError.invalidFixtureIdentity(manifest.name)
        }
        var compact = CompactNoritoWriter()
        compact.writeUInt32LE(0)
        compact.writeField(payloadBytes)
        guard IrohaHash.hash(compact.data).hexEncodedString() == manifest.signedHash else {
            throw FixtureError.invalidFixtureIdentity(manifest.name)
        }
        let fixtureURL = root.appendingPathComponent("\(manifest.name).norito")
        guard try Data(contentsOf: fixtureURL) == payloadBytes else {
            throw FixtureError.invalidFixtureIdentity(manifest.name)
        }
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.count == count && value.allSatisfy { "0123456789abcdef".contains($0) }
    }

    private static func loadSignedSchemaHash(using decoder: JSONDecoder) throws -> String {
        let schemaURL = fixturesRoot()
            .deletingLastPathComponent() // IrohaSwift
            .deletingLastPathComponent() // repository root
            .appendingPathComponent("fixtures/norito_rpc/schema_hashes.json")
        let file = try StrictFixtureJSON.decode(
            SchemaHashFile.self,
            from: Data(contentsOf: schemaURL),
            using: decoder,
            context: schemaURL.path
        )
        guard file.version == 1,
              let entry = file.entries.first(where: { $0.alias == "SignedTransaction" }),
              entry.typeName == "iroha_data_model::transaction::signed::model::SignedTransaction",
              entry.schemaHash.hasPrefix("0x") else {
            throw FixtureError.invalidManifestMetadata
        }
        let hash = String(entry.schemaHash.dropFirst(2))
        guard isLowerHex(hash, count: 32) else {
            throw FixtureError.invalidManifestMetadata
        }
        return hash
    }

    func fixture(named name: String) throws -> CombinedTransactionFixture {
        guard let payload = payloads[name] else {
            throw FixtureError.missingFixture(name)
        }
        guard let manifest = manifests[name] else {
            throw FixtureError.missingFixture(name)
        }
        return CombinedTransactionFixture(payload: payload, manifest: manifest)
    }

    private static func fixturesRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // TransactionParityFixturesTests.swift
            .deletingLastPathComponent() // IrohaSwiftTests
            .deletingLastPathComponent() // Tests
            .appendingPathComponent("Fixtures", isDirectory: true)
    }
}

private struct CombinedTransactionFixture {
    let payload: TransactionPayloadSpec
    let manifest: TransactionFixtureLoader.ManifestEntry
}

private struct TransactionPayloadSpec: Decodable {
    let networkId: NetworkId
    let authority: String
    let creationTimeMs: UInt64
    let executable: TransactionExecutable
    let timeToLiveMs: UInt64
    let nonce: UInt32?
    let feePayment: FeePaymentIntent
    let metadata: [String: ToriiJSONValue]

    private enum CodingKeys: String, CodingKey {
        case networkId = "network_id"
        case authority
        case creationTimeMs = "creation_time_ms"
        case executable
        case timeToLiveMs = "time_to_live_ms"
        case nonce
        case feePayment = "fee_payment"

        case metadata
    }

    init(from decoder: Decoder) throws {
        try requireExactFixtureKeys(
            decoder,
            [
                "authority", "network_id", "creation_time_ms", "executable", "fee_payment",
                "metadata", "nonce", "time_to_live_ms",
            ],
            context: "Swift parity transaction payload"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        networkId = try container.decode(NetworkId.self, forKey: .networkId)
        authority = try container.decode(String.self, forKey: .authority)
        creationTimeMs = try container.decode(UInt64.self, forKey: .creationTimeMs)
        executable = try container.decode(TransactionExecutable.self, forKey: .executable)
        timeToLiveMs = try container.decode(UInt64.self, forKey: .timeToLiveMs)
        guard timeToLiveMs > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .timeToLiveMs,
                in: container,
                debugDescription: "time_to_live_ms must be positive"
            )
        }
        let decodedNonce = try container.decode(UInt32.self, forKey: .nonce)
        guard decodedNonce > 0 else {
            throw DecodingError.dataCorruptedError(
                forKey: .nonce,
                in: container,
                debugDescription: "nonce must be positive"
            )
        }
        nonce = decodedNonce
        // Decode the fee object as JSON after the closed-schema preflight so
        // its exact wire keys reach FeePaymentIntent unchanged.
        _ = try container.decode(SwiftFixtureFeePayment.self, forKey: .feePayment)
        let feeValue = try container.decode(ToriiJSONValue.self, forKey: .feePayment)
        feePayment = try feeValue.decode(as: FeePaymentIntent.self)
        metadata = try container.decode([String: ToriiJSONValue].self, forKey: .metadata)
    }

    func stringMetadata(named name: String) -> String? {
        guard case let .string(value)? = metadata[name] else { return nil }
        return value
    }

    func instruction(kind: String, action: String) throws -> TransactionInstruction {
        let items: [TransactionInstruction]
        switch executable {
        case let .instructions(instructions):
            items = instructions
        case let .batch(entries):
            items = entries.compactMap { entry in
                guard case let .instruction(instruction) = entry else { return nil }
                return instruction
            }
        case .ivm, .contractCall:
            throw FixtureError.unsupportedExecutable(kind)
        }
        guard let instruction = items.first(where: { instruction in
            instruction.kind == kind && instruction.arguments["action"] == action
        }) else {
            throw FixtureError.missingInstruction("\(kind)::\(action)")
        }
        return instruction
    }
}


private struct SwiftFixtureFeePayment: Decodable {
    private enum CodingKeys: String, CodingKey {
        case payer
        case value
    }

    init(from decoder: Decoder) throws {
        try requireExactFixtureKeys(
            decoder,
            ["payer", "value"],
            context: "Swift parity fee payment"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let payer = try container.decode(String.self, forKey: .payer)
        guard payer == "authority" else {
            throw DecodingError.dataCorruptedError(
                forKey: .payer,
                in: container,
                debugDescription: "payer must be the literal 'authority'"
            )
        }
        _ = try container.decode(SwiftFixtureFeeValue.self, forKey: .value)
    }
}

private struct SwiftFixtureFeeValue: Decodable {
    private enum CodingKeys: String, CodingKey {
        case chargeLimits = "charge_limits"
        case gasLimit = "gas_limit"
    }

    init(from decoder: Decoder) throws {
        try requireExactFixtureKeys(
            decoder,
            ["charge_limits", "gas_limit"],
            context: "Swift parity fee value"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let chargeLimits = try container.decode([ToriiJSONValue].self, forKey: .chargeLimits)
        guard chargeLimits.isEmpty else {
            throw DecodingError.dataCorruptedError(
                forKey: .chargeLimits,
                in: container,
                debugDescription: "charge_limits must be an empty array"
            )
        }
        guard try container.decodeNil(forKey: .gasLimit) else {
            throw DecodingError.dataCorruptedError(
                forKey: .gasLimit,
                in: container,
                debugDescription: "gas_limit must be null"
            )
        }
    }
}

private enum TransactionExecutable: Decodable {
    case instructions([TransactionInstruction])
    case ivm(Data)
    case batch([TransactionExecutableBatchItem])
    case contractCall(TransactionContractInvocationSpec)

    private enum CodingKeys: String, CodingKey {
        case instructions = "Instructions"
        case ivm = "Ivm"
        case batch = "Batch"
        case contractCall = "ContractCall"
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: FixtureJSONCodingKey.self)
        let variants = Set(dynamic.allKeys.map(\.stringValue))
        guard variants.count == 1,
              let variant = variants.first,
              ["Batch", "ContractCall", "Instructions", "Ivm"].contains(variant) else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "executable must contain exactly one known variant"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if variant == "Instructions" {
            let instructions = try container.decode([TransactionInstruction].self, forKey: .instructions)
            self = .instructions(instructions)
        } else if variant == "Ivm" {
            let ivmBase64 = try container.decode(String.self, forKey: .ivm)
            guard let decoded = Data(base64Encoded: ivmBase64),
                  !decoded.isEmpty,
                  decoded.base64EncodedString() == ivmBase64 else {
                throw DecodingError.dataCorruptedError(forKey: .ivm,
                                                       in: container,
                                                       debugDescription: "invalid or non-canonical base64 payload")
            }
            self = .ivm(decoded)
        } else if variant == "Batch" {
            let batch = try container.decode([TransactionExecutableBatchItem].self, forKey: .batch)
            self = .batch(batch)
        } else if variant == "ContractCall" {
            self = try .contractCall(
                container.decode(TransactionContractInvocationSpec.self, forKey: .contractCall)
            )
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: decoder.codingPath,
                                      debugDescription: "unsupported executable variant")
            )
        }
    }
}

private enum TransactionExecutableBatchItem: Decodable {
    case instruction(TransactionInstruction)
    case contractCall(TransactionContractInvocationSpec)

    private enum CodingKeys: String, CodingKey {
        case instruction = "Instruction"
        case contractCall = "ContractCall"
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: FixtureJSONCodingKey.self)
        let variants = Set(dynamic.allKeys.map(\.stringValue))
        guard variants.count == 1,
              let variant = variants.first,
              ["ContractCall", "Instruction"].contains(variant) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "executable batch item must contain exactly one variant"
                )
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if variant == "Instruction" {
            self = try .instruction(
                container.decode(TransactionInstruction.self, forKey: .instruction)
            )
        } else if variant == "ContractCall" {
            self = try .contractCall(
                container.decode(TransactionContractInvocationSpec.self, forKey: .contractCall)
            )
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "unsupported executable batch item"
                )
            )
        }
    }
}

private struct TransactionContractInvocationSpec: Decodable {
    let contractAddress: String
    let expectedCodeHash: String
    let entrypoint: String
    let arguments: [UInt8]?

    private enum CodingKeys: String, CodingKey {
        case contractAddress = "contract_address"
        case expectedCodeHash = "expected_code_hash"
        case entrypoint
        case arguments
    }

    init(from decoder: Decoder) throws {
        try requireExactFixtureKeys(
            decoder,
            ["arguments", "contract_address", "entrypoint", "expected_code_hash"],
            context: "contract call"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        contractAddress = try container.decode(String.self, forKey: .contractAddress)
        expectedCodeHash = try container.decode(String.self, forKey: .expectedCodeHash)
        entrypoint = try container.decode(String.self, forKey: .entrypoint)
        arguments = try container.decodeIfPresent([UInt8].self, forKey: .arguments)
    }
}

private struct TransactionInstruction: Decodable {
    let kind: String
    let arguments: [String: String]

    private enum CodingKeys: String, CodingKey {
        case kind
        case arguments
    }

    init(from decoder: Decoder) throws {
        try requireExactFixtureKeys(
            decoder,
            ["arguments", "kind"],
            context: "Swift parity instruction"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        kind = try container.decode(String.self, forKey: .kind)
        arguments = try container.decode([String: String].self, forKey: .arguments)
    }

    func argument(named name: String) throws -> String {
        guard let value = arguments[name], !value.isEmpty else {
            throw FixtureError.missingArgument(name, instruction: kind)
        }
        return value
    }
}

private enum FixtureError: Error, LocalizedError {
    case missingFixture(String)
    case unsupportedExecutable(String)
    case missingInstruction(String)
    case missingArgument(String, instruction: String)
    case invalidAccountId(field: String, value: String)
    case invalidManifestProperty(String)
    case duplicateManifestProperty(String)
    case unexpectedManifestProperties(Set<String>)
    case duplicateFixtureName(String)
    case duplicateEncodedFile(String)
    case duplicatePayloadHash(String)
    case duplicatePayloadBytes(String)
    case duplicateSignedHash(String)
    case duplicateSignedBytes(String)
    case invalidBase64(String)
    case invalidFixtureName(String)
    case invalidEncodedFile(String)
    case unexpectedSwiftFixtureNames(Set<String>)
    case invalidManifestMetadata
    case manifestPayloadMismatch(String)
    case invalidFixtureLength(String)
    case invalidFixtureHash(String)
    case invalidFixtureIdentity(String)
    case invalidSwiftPayload(String)
    case fixtureNameSetMismatch(payloads: Set<String>, manifests: Set<String>)
    case invalidSigningSeed
    case bridgeKeypairUnavailable

    var errorDescription: String? {
        switch self {
        case let .missingFixture(name):
            return "fixture '\(name)' is not available"
        case let .unsupportedExecutable(kind):
            return "executable for '\(kind)' fixture is not instruction-based"
        case let .missingInstruction(label):
            return "instruction \(label) not found in fixture"
        case let .missingArgument(arg, instruction):
            return "instruction \(instruction) missing argument '\(arg)'"
        case let .invalidAccountId(field, value):
            return "account id for \(field) must be encoded-only (received '\(value)')"
        case let .invalidManifestProperty(line):
            return "fixture property is missing '=': \(line)"
        case let .duplicateManifestProperty(key):
            return "fixture property '\(key)' is duplicated"
        case let .unexpectedManifestProperties(keys):
            return "fixture properties did not match the required key set: \(keys.sorted())"
        case let .duplicateFixtureName(name):
            return "fixture name '\(name)' is duplicated"
        case let .duplicateEncodedFile(file):
            return "fixture encoded file '\(file)' is duplicated"
        case let .duplicatePayloadHash(hash):
            return "fixture payload hash '\(hash)' is duplicated"
        case let .duplicatePayloadBytes(name):
            return "fixture payload bytes are duplicated by '\(name)'"
        case let .duplicateSignedHash(hash):
            return "fixture signed hash '\(hash)' is duplicated"
        case let .duplicateSignedBytes(name):
            return "fixture signed bytes are duplicated by '\(name)'"
        case let .invalidBase64(context):
            return "fixture base64 is invalid or non-canonical: \(context)"
        case let .invalidFixtureName(name):
            return "fixture name is empty or invalid: '\(name)'"
        case let .invalidEncodedFile(file):
            return "fixture encoded_file is not the canonical local filename: '\(file)'"
        case let .unexpectedSwiftFixtureNames(names):
            return "Swift fixture names are not the exact first-release set: \(names.sorted())"
        case .invalidManifestMetadata:
            return "Swift fixture manifest metadata is missing or malformed"
        case let .manifestPayloadMismatch(name):
            return "Swift fixture manifest and payload metadata differ for '\(name)'"
        case let .invalidFixtureLength(name):
            return "Swift fixture lengths are outside the accepted bounds for '\(name)'"
        case let .invalidFixtureHash(name):
            return "Swift fixture hashes are malformed for '\(name)'"
        case let .invalidFixtureIdentity(name):
            return "Swift fixture bytes, lengths, or hashes do not agree for '\(name)'"
        case let .invalidSwiftPayload(name):
            return "Swift fixture payload is outside the exact first-release schema for '\(name)'"
        case let .fixtureNameSetMismatch(payloads, manifests):
            return "payload/manifest fixture names differ: payloads=\(payloads.sorted()) manifests=\(manifests.sorted())"
        case .invalidSigningSeed:
            return "fixture signing seed could not be decoded"
        case .bridgeKeypairUnavailable:
            return "fixture signing seed could not be derived using the native bridge"
        }
    }
}

private enum FixtureConstants {
    static let signingSeedHex = "616e64726f69642d666978747572652d7369676e696e672d6b65792d30313032"
    static let networkPrefix = TairaTestnetProfile.i105Discriminant
}
