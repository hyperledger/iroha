import XCTest
import CryptoKit
@testable import IrohaSwift

final class ToriiAccountAndNodeBoundaryTests: XCTestCase {
    private static let operatorSigningContext: ToriiOperatorSigningContext = {
        let signingKey = try! SigningKey.ed25519(
            privateKey: Data(repeating: 0x5A, count: 32)
        )
        return try! ToriiOperatorSigningContext(
            networkId: TestNetworkIds.canonical,
            signingKey: signingKey
        )
    }()

    private static let pipelineHash = String(repeating: "d", count: 64)
    private let canonicalSigningSeed = Data(repeating: 0x41, count: 32)
    private let onboardingToken = String(repeating: "T", count: 32)

    private var authority: String {
        try! Keypair(privateKeyBytes: canonicalSigningSeed)
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
    }

    private var canonicalReadAuth: ToriiCanonicalRequestAuth {
        ToriiCanonicalRequestAuth(
            accountId: authority,
            privateKey: canonicalSigningSeed
        )
    }

    private func canonicalOwnerLiteral(
        domain: String = "wonderland",
        chainDiscriminant: UInt16 = AccountId.defaultNetworkPrefix
    ) throws -> String {
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 1, count: 32))
        let address = try AccountAddress.fromAccount(publicKey: keypair.publicKey)
        return try address.toI105(networkPrefix: chainDiscriminant)
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func bodyData(from request: URLRequest) -> Data? {
        toriiClientTestBodyData(from: request)
    }

    private func bodyJSON(from request: URLRequest) -> [String: Any] {
        toriiClientTestBodyJSON(from: request)
    }

    private func makeClient(
        baseURL: URL = URL(string: "https://example.test")!,
        defaultHeaders: [String: String] = [:],
        operatorSigningContext: ToriiOperatorSigningContext? =
            ToriiAccountAndNodeBoundaryTests.operatorSigningContext
    ) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        return ToriiClient(
            baseURL: baseURL,
            session: session,
            defaultHeaders: defaultHeaders,
            localSigningContext: ToriiLocalSigningContext(networkId: TestNetworkIds.canonical),
            canonicalRequestAuth: canonicalReadAuth,
            canonicalRequestFreshness: ToriiCanonicalRequestFreshness(
                timestampMs: { 4_102_444_801_000 },
                nonce: { "canonical-read-test" }
            ),
            operatorSigningContext: operatorSigningContext
        )
    }

    private func assertOperatorAuthentication(
        _ request: URLRequest,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for header in [
            "X-Iroha-Operator-Public-Key",
            "X-Iroha-Operator-Timestamp-Ms",
            "X-Iroha-Operator-Nonce",
            "X-Iroha-Operator-Signature",
        ] {
            XCTAssertNotNil(
                request.value(forHTTPHeaderField: header),
                "missing \(header)",
                file: file,
                line: line
            )
        }
        XCTAssertTrue(request.httpBody?.isEmpty ?? true, file: file, line: line)
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"), file: file, line: line)
        XCTAssertNil(request.value(forHTTPHeaderField: "X-API-Token"), file: file, line: line)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidPortfolioPreservesExactLiteral() async throws {
        let uaidHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let assetId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#\(accountId)#dataspace:0"
        let payload = """
        {
          "uaid":"uaid:\(uaidHex)",
          "totals":{"accounts":1,"positions":1},
          "dataspaces":[
            {
              "dataspace_id":0,
              "dataspace_alias":"universal",
              "accounts":[
                {
                  "account_id":"\(accountId)",
                  "label":null,
                  "assets":[{"asset_id":"\(assetId)","asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","quantity":"500"}]
                }
              ]
            }
          ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/accounts/uaid%3A\(uaidHex)/portfolio"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let response = try await makeClient().getUaidPortfolio(uaid: "uaid:\(uaidHex)")
        XCTAssertEqual(response.uaid, "uaid:\(uaidHex)")
        XCTAssertEqual(response.totals.accounts, 1)
        XCTAssertEqual(response.dataspaces.first?.accounts.first?.assets.first?.assetId,
                       assetId)
        XCTAssertEqual(response.dataspaces.first?.accounts.first?.assets.first?.assetDefinitionId,
                       "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(response.dataspaces.first?.accounts.first?.assets.first?.quantity, "500")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidPortfolioRejectsNoncanonicalLiteralBeforeNetwork() async {
        StubURLProtocol.handler = { _ in
            XCTFail("getUaidPortfolio should validate UAID before dispatch")
            throw URLError(.badURL)
        }
        let uaidHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        for literal in [
            uaidHex,
            "UAID:\(uaidHex)",
            "uaid:\(uaidHex.uppercased())",
            " uaid:\(uaidHex)",
            "uaid:\(uaidHex) ",
            "uaid: \(uaidHex)"
        ] {
            await XCTAssertThrowsErrorAsync(try await makeClient().getUaidPortfolio(uaid: literal)) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertTrue(
                    reason.contains("exact canonical uaid")
                        || reason.contains("surrounding whitespace")
                )
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidPortfolioIncludesAssetIdQuery() async throws {
        let uaidHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543211"
        let assetId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV#dataspace:0"
        let payload = """
        {
          "uaid":"uaid:\(uaidHex)",
          "totals":{"accounts":0,"positions":0},
          "dataspaces":[]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/accounts/uaid%3A\(uaidHex)/portfolio"))
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            let queryItems = components?.queryItems ?? []
            let query = Dictionary(uniqueKeysWithValues: queryItems.map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(query["asset_id"], assetId)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        _ = try await makeClient().getUaidPortfolio(uaid: "uaid:\(uaidHex)",
                                                    query: ToriiUaidPortfolioQuery(assetId: assetId))
    }

    @available(iOS 15.0, macOS 12.0, *)
    private func onboardingPlanReceipt(
        request: ToriiAccountOnboardingPlanRequest,
        disposition: AliasPlanDispositionV1 = .create,
        chainDiscriminant: UInt16 = AccountId.defaultNetworkPrefix
    ) throws -> ToriiAccountOnboardingPlanReceipt {
        let authorityKey = try SigningKey.ed25519(privateKey: Data(repeating: 0x51, count: 32))
        let authority = try AccountId.makeI105(
            publicKey: authorityKey.publicKey(),
            networkPrefix: chainDiscriminant
        )
        let alias = try ResolvedAccountAliasV1(
            canonicalName: request.alias,
            dataspaceId: 0
        )
        let intent = AliasIntentV1.accountAlias(
            try AliasAccountIntentV1(
                alias: alias,
                targetAccount: request.accountId,
                provision: .create,
                role: .primary
            )
        )
        let acquisition = try AliasLeaseAcquisitionV1(termYears: 1)
        let quoteGuard = try AliasQuoteGuardV1(
            expectedPolicyVersion: 1,
            expectedPaymentAsset: "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            maxAmount: "0",
            validUntilMs: UInt64.max
        )
        let instructions = disposition == .noOp
            ? []
            : [try AliasFramedInstructionV1(
                wireId: EnsureAlias.wireId,
                framedPayload: Data([1, 2, 3])
            )]
        let body = ToriiAccountOnboardingPlanBody(
            version: ToriiAccountOnboardingPlanBody.version,
            request: request,
            authority: authority,
            networkId: TestNetworkIds.canonical,
            anchor: try AliasPlanAnchorV1(
                blockHeight: 1,
                blockHash: NetworkId(bytes: Data(repeating: 0x11, count: 32)).literal
            ),
            resource: AliasPlanResourceV1(
                intent: intent,
                disposition: disposition,
                quote: nil,
                instructionIndex: instructions.isEmpty ? nil : 0
            ),
            acquisition: acquisition,
            quoteGuard: quoteGuard,
            instructions: instructions,
            ownerAutoRenewInstruction: nil,
            validUntilMs: UInt64.max
        )
        let bodyBytes = try encodeTestCanonicalOnboardingBody(body)
        let planHash = try ToriiAccountOnboardingReceiptVerifier.canonicalHash(
            canonicalBodyNorito: bodyBytes
        )
        return ToriiAccountOnboardingPlanReceipt(
            body: body,
            planHash: try ToriiAccountOnboardingReceiptVerifier.canonicalHashLiteral(
                canonicalBodyNorito: bodyBytes
            ),
            signature: .string(try authorityKey.sign(planHash).hexUppercased())
        )
    }

    private func preparedAccountBinding(
        receipt: ToriiAccountOnboardingPlanReceipt,
        requestByte: String
    ) throws -> ToriiPreparedOperationBindingV1 {
        try ToriiPreparedOperationBindingV1(
            semanticHashHex: XCTUnwrap(ToriiCanonicalHashLiteral.normalizedHex(from: receipt.planHash)),
            kind: .onboarding,
            requestId: String(repeating: requestByte, count: 32),
            executionExpiresAtUnixMs: 4_102_444_800_000
        )
    }

    private func preparedAccountBinding(
        claim: ToriiAccountFaucetClaimV1,
        requestByte: String
    ) throws -> ToriiPreparedOperationBindingV1 {
        try ToriiPreparedOperationBindingV1(
            semanticHashHex: ToriiPreparedAccountProtocolV1.faucetSemanticHash(claim),
            kind: .faucet,
            requestId: String(repeating: requestByte, count: 32),
            executionExpiresAtUnixMs: 4_102_444_800_000
        )
    }

    private func preparedTransactionPayload(
        authority: String,
        networkId: NetworkId,
        feePayment: FeePaymentIntent,
        binding: ToriiPreparedOperationBindingV1,
        operation: ToriiPreparedAccountOperationV1,
        semanticHashHex: String,
        instructionPayloads: [Data] = [Data([0])],
        faucetMarker: ToriiJSONValue? = .number(1)
    ) throws -> Data {
        var instructions = CompactNoritoWriter()
        instructions.writeUInt64LE(UInt64(instructionPayloads.count))
        for instruction in instructionPayloads {
            instructions.writeField(instruction)
        }
        var executable = CompactNoritoWriter()
        executable.writeUInt32LE(0)
        executable.writeField(instructions.data)
        let bindingJSON = ToriiJSONValue.object([
            "schema": .string(binding.schema),
            "semantic_hash_hex": .string(binding.semanticHashHex),
            "kind": .string(binding.kind.rawValue),
            "request_id": .string(binding.requestId),
            "execution_expires_at_unix_ms": .number(Double(binding.executionExpiresAtUnixMs)),
        ])
        var metadata: [String: ToriiJSONValue] = [
            "prepared_operation_binding": bindingJSON,
            "prepared_operation": .string(operation.rawValue),
            "prepared_semantic_hash": .string(semanticHashHex),
        ]
        if operation == .faucet, let faucetMarker {
            metadata["taira_faucet_claim_marker_version"] = faucetMarker
        }
        let creationTimeMs = min(4_000_000_000_000, binding.executionExpiresAtUnixMs - 1)
        return try CanonicalUnsignedTransactionTestSupport.transactionPayload(
            networkId: networkId,
            authority: authority,
            creationTimeMs: creationTimeMs,
            executable: executable.data,
            timeToLiveMs: min(3_600_000, binding.executionExpiresAtUnixMs - creationTimeMs),
            nonce: operation == .onboarding ? 1 : 2,
            feePayment: feePayment,

            metadata: metadata
        )
    }

    private func preparedOnboardingTransaction(
        receipt: ToriiAccountOnboardingPlanReceipt,
        binding: ToriiPreparedOperationBindingV1
    ) throws -> ToriiAccountOnboardingPreparedTransactionV1 {
        let canonicalBody = try encodeTestCanonicalOnboardingBody(receipt.body)
        let semanticHash = try ToriiAccountOnboardingReceiptVerifier.canonicalHash(
            canonicalBodyNorito: canonicalBody
        ).hexEncodedString()
        let feePayment = testFeePayment()
        let signer = try SigningKey.ed25519(privateKey: Data(repeating: 0x51, count: 32))
        let payload = try preparedTransactionPayload(
            authority: receipt.body.authority,
            networkId: receipt.body.networkId,
            feePayment: feePayment,
            binding: binding,
            operation: .onboarding,
            semanticHashHex: semanticHash
        )
        let (wire, transactionHash) = try preparedTransactionWire(
            payload: payload,
            signer: signer
        )
        let unsignedEnvelope = try ToriiAccountOnboardingPreparedTransactionV1(
            binding: binding,
            receipt: receipt,
            semanticHashHex: semanticHash,
            accountId: receipt.body.request.accountId,
            alias: receipt.body.request.alias,
            disposition: receipt.body.resource.disposition,
            transactionHashHex: transactionHash,
            signedTransactionWireHex: wire.hexEncodedString(),
            signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString(),
            feePayment: feePayment,
            serverSignature: try signer.sign(Data("placeholder".utf8)).hexUppercased()
        )
        return try ToriiAccountOnboardingPreparedTransactionV1(
            binding: binding,
            receipt: receipt,
            semanticHashHex: semanticHash,
            accountId: receipt.body.request.accountId,
            alias: receipt.body.request.alias,
            disposition: receipt.body.resource.disposition,
            transactionHashHex: transactionHash,
            signedTransactionWireHex: wire.hexEncodedString(),
            signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString(),
            feePayment: feePayment,
            serverSignature: try signer.sign(
                IrohaHash.hash(unsignedEnvelope.signatureTranscript())
            ).hexUppercased()
        )
    }

    private func proofRequiredOnboardingResponse(
        receipt: ToriiAccountOnboardingPlanReceipt,
        binding: ToriiPreparedOperationBindingV1
    ) throws -> ToriiAccountOnboardingProofRequiredPrepareResponseV1 {
        let canonicalBody = try encodeTestCanonicalOnboardingBody(receipt.body)
        let semanticHash = try ToriiAccountOnboardingReceiptVerifier.canonicalHash(
            canonicalBodyNorito: canonicalBody
        ).hexEncodedString()
        let signer = try SigningKey.ed25519(privateKey: Data(repeating: 0x51, count: 32))
        let unsigned = try ToriiAccountOnboardingProofRequiredPrepareResponseV1(
            binding: binding,
            semanticHashHex: semanticHash,
            accountId: receipt.body.request.accountId,
            alias: receipt.body.request.alias,
            disposition: .noOp,
            serverSignature: try signer.sign(Data("placeholder".utf8)).hexUppercased()
        )
        return try ToriiAccountOnboardingProofRequiredPrepareResponseV1(
            binding: binding,
            semanticHashHex: semanticHash,
            accountId: receipt.body.request.accountId,
            alias: receipt.body.request.alias,
            disposition: .noOp,
            serverSignature: try signer.sign(
                IrohaHash.hash(unsigned.signatureTranscript())
            ).hexUppercased()
        )
    }

    private func preparedFaucetTransaction(
        claim: ToriiAccountFaucetClaimV1,
        binding: ToriiPreparedOperationBindingV1
    ) throws -> ToriiAccountFaucetPreparedTransactionV1 {
        let signer = try SigningKey.ed25519(privateKey: Data(repeating: 0x61, count: 32))
        let authority = try AccountId.makeI105(publicKey: signer.publicKey())
        let semanticHash = try ToriiPreparedAccountProtocolV1.faucetSemanticHash(claim)
        let feePayment = testFeePayment()
        let payload = try preparedTransactionPayload(
            authority: authority,
            networkId: TestNetworkIds.canonical,
            feePayment: feePayment,
            binding: binding,
            operation: .faucet,
            semanticHashHex: semanticHash
        )
        let (wire, transactionHash) = try preparedTransactionWire(
            payload: payload,
            signer: signer
        )
        let unsignedEnvelope = try ToriiAccountFaucetPreparedTransactionV1(
            binding: binding,
            claim: claim,
            semanticHashHex: semanticHash,
            accountId: claim.accountId,
            assetDefinitionId: "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            assetId: "4rPeAP6jAjiLVZThZYwwPRBuQagt#\(claim.accountId)",
            amount: "25",
            transactionHashHex: transactionHash,
            signedTransactionWireHex: wire.hexEncodedString(),
            signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString(),
            feePayment: feePayment,
            serverSignature: try signer.sign(Data("placeholder".utf8)).hexUppercased()
        )
        return try ToriiAccountFaucetPreparedTransactionV1(
            binding: binding,
            claim: claim,
            semanticHashHex: semanticHash,
            accountId: claim.accountId,
            assetDefinitionId: "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            assetId: "4rPeAP6jAjiLVZThZYwwPRBuQagt#\(claim.accountId)",
            amount: "25",
            transactionHashHex: transactionHash,
            signedTransactionWireHex: wire.hexEncodedString(),
            signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString(),
            feePayment: feePayment,
            serverSignature: try signer.sign(
                IrohaHash.hash(unsignedEnvelope.signatureTranscript())
            ).hexUppercased()
        )
    }

    private func faucetPolicy(
        for prepared: ToriiAccountFaucetPreparedTransactionV1
    ) throws -> ToriiAccountFaucetPolicyV1 {
        let signer = try SigningKey.ed25519(
            privateKey: Data(repeating: 0x61, count: 32)
        )
        return try ToriiAccountFaucetPolicyV1(
            faucetAuthority: AccountId.makeI105(publicKey: signer.publicKey()),
            assetDefinitionId: prepared.assetDefinitionId,
            amount: KotodamaQuantity(prepared.amount)
        )
    }

    private func preparedTransactionWire(
        payload: Data,
        signer: SigningKey
    ) throws -> (wire: Data, hash: String) {
        let signature = try signer.sign(IrohaHash.hash(payload))
        let finalized = try ToriiCanonicalTransactionDraft.finalize(
            transactionPayload: payload,
            publicKey: signer.publicKey(),
            signature: signature
        )
        return (
            finalized.signedTransaction,
            finalized.finalization.transactionHash.hexEncodedString()
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingReceiptVerifiesDomainHashAndAuthoritySignature() throws {
        let request = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral(
                chainDiscriminant: TairaTestnetProfile.i105Discriminant
            )
        )
        let receipt = try onboardingPlanReceipt(
            request: request,
            chainDiscriminant: TairaTestnetProfile.i105Discriminant
        )
        let canonicalBody = try encodeTestCanonicalOnboardingBody(receipt.body)

        XCTAssertNoThrow(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: request,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId
            )
        )

        var expectedHash = Blake2b.hash256(
            Data("iroha:account-onboarding-plan-receipt:v1\0".utf8) + canonicalBody
        )
        expectedHash[expectedHash.index(before: expectedHash.endIndex)] |= 1
        XCTAssertEqual(
            receipt.planHash,
            try ToriiAccountOnboardingReceiptVerifier.canonicalHashLiteral(
                canonicalBodyNorito: canonicalBody
            )
        )

        var tamperedBody = canonicalBody
        tamperedBody.append(0)
        XCTAssertThrowsError(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: request,
                canonicalBodyNorito: tamperedBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId
            )
        ) { error in
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .planHashMismatch
            )
        }

        guard case let .string(signatureHex) = receipt.signature,
              var signature = Data(hexString: signatureHex) else {
            return XCTFail("expected canonical signature hex")
        }
        signature[signature.startIndex] ^= 1
        let badSignature = ToriiAccountOnboardingPlanReceipt(
            body: receipt.body,
            planHash: receipt.planHash,
            signature: .string(signature.hexUppercased())
        )
        XCTAssertThrowsError(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                badSignature,
                for: request,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId
            )
        ) { error in
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .signatureMismatch
            )
        }

        let wrongAuthority = try AccountId.makeI105(
            publicKey: SigningKey.ed25519(privateKey: Data(repeating: 0x52, count: 32)).publicKey()
        )
        XCTAssertThrowsError(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: request,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: wrongAuthority,
                expectedNetworkId: receipt.body.networkId
            )
        ) { error in
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .authorityMismatch
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingReceiptRequiresExactPinnedNetworkId() throws {
        let request = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: request)
        let canonicalBody = try encodeTestCanonicalOnboardingBody(receipt.body)

        XCTAssertThrowsError(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: request,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: TestNetworkIds.other
            )
        ) { error in
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .networkIdMismatch
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testProductionOnboardingBodyEncoderUsesNoritoOrFailsClosed() throws {
        let request = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: request)
        let transportJSON = try encodeTestCanonicalOnboardingBody(receipt.body)
        do {
            let encoded = try ToriiAccountOnboardingPlanBodyNorito.encode(receipt.body)
            XCTAssertFalse(encoded.isEmpty)
            XCTAssertNotEqual(encoded, transportJSON)
        } catch {
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .canonicalBodyEncodingUnavailable
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingPermissionsAreExactCanonicalAndReceiptPinned() async throws {
        let accountId = try canonicalOwnerLiteral()
        for permissions in [
            [" CanFoo"],
            ["CanFoo", "CanFoo"],
            ["CanFoo", "CanBar"],
        ] {
            XCTAssertThrowsError(
                try ToriiAccountOnboardingPlanRequest(
                    alias: "alice@universal",
                    accountId: accountId,
                    permissions: permissions
                )
            )
        }

        let requested = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId,
            permissions: ["CanBar", "CanFoo"]
        )
        let receipt = try onboardingPlanReceipt(request: requested)
        let canonicalBody = try encodeTestCanonicalOnboardingBody(receipt.body)
        XCTAssertNoThrow(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: requested,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId
            )
        )

        let substitutedRequest = try ToriiAccountOnboardingPlanRequest(
            alias: requested.alias,
            accountId: requested.accountId,
            permissions: ["CanBar"]
        )
        XCTAssertThrowsError(
            try ToriiAccountOnboardingReceiptVerifier.verify(
                receipt,
                for: substitutedRequest,
                canonicalBodyNorito: canonicalBody,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId
            )
        )

        let binding = try preparedAccountBinding(
            receipt: receipt,
            requestByte: "22"
        )
        let prepared = try preparedOnboardingTransaction(receipt: receipt, binding: binding)
        let proofRequired = try proofRequiredOnboardingResponse(
            receipt: receipt,
            binding: binding
        )
        var requestCount = 0
        StubURLProtocol.handler = { _ in
            requestCount += 1
            XCTFail("a substituted original onboarding request reached HTTP dispatch")
            throw URLError(.badServerResponse)
        }
        let client = makeClient()

        do {
            _ = try await client.prepareAccountOnboarding(
                receipt,
                request: substitutedRequest,
                binding: binding,
                feePayment: prepared.feePayment,
                onboardingToken: onboardingToken,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("prepare accepted a permission-substituted original request")
        } catch {
            guard case ToriiClientError.invalidResponse = error else {
                return XCTFail("prepare failed for the wrong reason: \(error)")
            }
        }
        do {
            _ = try await client.verifyAccountOnboardingCurrentState(
                proofRequired,
                request: substitutedRequest,
                receipt: receipt,
                binding: binding,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                canonicalAuth: canonicalReadAuth,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("current-state verification accepted a substituted original request")
        } catch {
            guard case ToriiClientError.invalidResponse = error else {
                return XCTFail("current-state verification failed for the wrong reason: \(error)")
            }
        }
        do {
            _ = try await client.submitPreparedAccountOnboarding(
                prepared,
                expectedFeePayment: prepared.feePayment,
                request: substitutedRequest,
                onboardingToken: onboardingToken,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("submit accepted a permission-substituted original request")
        } catch {
            guard case ToriiClientError.invalidResponse = error else {
                return XCTFail("submit failed for the wrong reason: \(error)")
            }
        }
        XCTAssertEqual(requestCount, 0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingPlansPreparesPersistsAndSubmitsExactEnvelope() async throws {
        let accountId = try canonicalOwnerLiteral()
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId,
            permissions: ["CanBar", "CanFoo"]
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        let prepared = try preparedOnboardingTransaction(receipt: receipt, binding: binding)
        let receiptBody = try JSONEncoder().encode(receipt)
        let preparedBody = try JSONEncoder().encode(prepared)
        let submitResult = try ToriiPreparedTransactionSubmitResponseV1(
            binding: binding,
            operation: .onboarding,
            transactionHashHex: prepared.transactionHashHex,
            outcome: .pending
        )
        let submitBody = try JSONEncoder().encode(submitResult)
        var requestCount = 0

        StubURLProtocol.handler = { request in
            requestCount += 1
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiAccountOnboardingTokenHeader),
                self.onboardingToken
            )
            XCTAssertEqual(
                request.allHTTPHeaderFields?.keys.filter {
                    $0.caseInsensitiveCompare(ToriiAccountOnboardingTokenHeader) == .orderedSame
                }.count,
                1
            )
            let rawBody = try XCTUnwrap(self.bodyData(from: request))
            let rawText = String(decoding: rawBody, as: UTF8.self)
            XCTAssertFalse(rawText.contains(self.onboardingToken))
            XCTAssertFalse(rawText.contains("private_key"))
            XCTAssertFalse(rawText.contains("public_key_hex"))
            XCTAssertFalse(rawText.contains("uaid"))

            if request.url?.path == "/v1/accounts/onboard/plan" {
                let decoded = try JSONDecoder().decode(
                    ToriiAccountOnboardingPlanRequest.self,
                    from: rawBody
                )
                XCTAssertEqual(decoded, intent)
                let payload = self.bodyJSON(from: request)
                XCTAssertEqual(
                    Set(payload.keys),
                    Set(["version", "alias", "account_id", "permissions"])
                )
                XCTAssertEqual(payload["permissions"] as? [String], ["CanBar", "CanFoo"])
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, receiptBody)
            }

            if request.url?.path == "/v1/accounts/onboard/prepare" {
                let decoded = try JSONDecoder().decode(
                    ToriiAccountOnboardingPrepareRequestV1.self,
                    from: rawBody
                )
                XCTAssertEqual(decoded.binding, binding)
                XCTAssertEqual(decoded.receipt, receipt)
                XCTAssertEqual(decoded.feePayment, prepared.feePayment)
                XCTAssertEqual(
                    Set(self.bodyJSON(from: request).keys),
                    Set(["schema", "binding", "receipt", "fee_payment"])
                )
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, preparedBody)
            }

            XCTAssertEqual(request.url?.path, "/v1/accounts/onboard")
            XCTAssertEqual(
                try JSONDecoder().decode(
                    ToriiAccountOnboardingPreparedTransactionV1.self,
                    from: rawBody
                ),
                prepared
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 202,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, submitBody)
        }

        let client = makeClient(defaultHeaders: [
            ToriiAPITokenHeader: "global-api-token",
            ToriiAccountOnboardingTokenHeader.lowercased(): "retired-default-token-must-not-be-used"
        ])
        let planned = try await client.planAccountOnboarding(
            intent,
            onboardingToken: onboardingToken,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        XCTAssertEqual(planned, receipt)
        let preparedResult = try await client.prepareAccountOnboarding(
            planned,
            request: intent,
            binding: binding,
            feePayment: prepared.feePayment,
            onboardingToken: onboardingToken,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        guard case let .prepared(receivedPrepared) = preparedResult else {
            return XCTFail("expected one exact prepared onboarding transaction")
        }

        let persisted = try JSONEncoder().encode(receivedPrepared)
        let reopened = try JSONDecoder().decode(
            ToriiAccountOnboardingPreparedTransactionV1.self,
            from: persisted
        )
        XCTAssertEqual(reopened, prepared)
        let submitted = try await client.submitPreparedAccountOnboarding(
            reopened,
            expectedFeePayment: prepared.feePayment,
            request: intent,
            onboardingToken: onboardingToken,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        XCTAssertEqual(submitted, submitResult)
        XCTAssertEqual(requestCount, 3)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingProofRequiredUsesOneAtomicStatePost() async throws {
        let accountId = try canonicalOwnerLiteral()
        let alternateAccountId = try AccountAddress.parseEncoded(accountId)
            .toI105(networkPrefix: TairaTestnetProfile.i105Discriminant)
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId
        )
        let receipt = try onboardingPlanReceipt(request: intent, disposition: .noOp)
        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        let proofRequired = try proofRequiredOnboardingResponse(
            receipt: receipt,
            binding: binding
        )
        let blockHash = try ToriiAccountOnboardingBlockHashV1(
            literal: TestNetworkIds.canonical.literal
        )
        let currentState = try ToriiAccountOnboardingCurrentStateResponseV1(
            networkId: receipt.body.networkId,
            accountId: accountId,
            alias: intent.alias,
            accountExists: true,
            aliasTargetAccountId: alternateAccountId,
            observedBlockHeight: 41,
            observedBlockHash: blockHash
        )
        var requestCount = 0

        StubURLProtocol.handler = { request in
            requestCount += 1
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            switch requestCount {
            case 1:
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.url?.path, "/v1/accounts/onboard/prepare")
                return (response, try JSONEncoder().encode(proofRequired))
            default:
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(
                    request.url?.path,
                    "/v1/accounts/onboarding/current-state"
                )
                XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-cache")
                XCTAssertNotNil(
                    request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount)
                )
                XCTAssertNotNil(
                    request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
                )
                XCTAssertNotNil(
                    request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs)
                )
                XCTAssertNotNil(
                    request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce)
                )
                XCTAssertEqual(
                    try JSONDecoder().decode(
                        ToriiAccountOnboardingCurrentStateRequestV1.self,
                        from: try XCTUnwrap(self.bodyData(from: request))
                    ),
                    try ToriiAccountOnboardingCurrentStateRequestV1(
                        accountId: accountId,
                        alias: intent.alias
                    )
                )
                return (response, try JSONEncoder().encode(currentState))
            }
        }

        let result = try await makeClient().prepareAccountOnboarding(
            receipt,
            request: intent,
            binding: binding,
            feePayment: testFeePayment(),
            onboardingToken: onboardingToken,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        guard case let .proofRequired(receivedProofRequired) = result else {
            return XCTFail("proof-required onboarding must not synthesize a transaction")
        }
        XCTAssertEqual(receivedProofRequired, proofRequired)
        let persisted = try JSONEncoder().encode(result)
        let reopened = try JSONDecoder().decode(
            ToriiAccountOnboardingPrepareResponseV1.self,
            from: persisted
        )
        guard case let .proofRequired(reopenedProofRequired) = reopened else {
            return XCTFail("reopened proof-required result changed variant")
        }
        let verification = try await makeClient().verifyAccountOnboardingCurrentState(
            reopenedProofRequired,
            request: intent,
            receipt: receipt,
            binding: binding,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            canonicalAuth: canonicalReadAuth,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        XCTAssertEqual(
            verification,
            .applied(blockHeight: 41, blockHash: blockHash)
        )
        XCTAssertEqual(requestCount, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingCurrentStateClassifiesAbsentAndConflictingAliases() async throws {
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: intent, disposition: .noOp)
        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        let proofRequired = try proofRequiredOnboardingResponse(
            receipt: receipt,
            binding: binding
        )
        let wrongAccountId = try Keypair(privateKeyBytes: Data(repeating: 2, count: 32))
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
        let blockHash = try ToriiAccountOnboardingBlockHashV1(
            literal: TestNetworkIds.canonical.literal
        )
        for (target, expected) in [
            (
                Optional<String>.none,
                ToriiAccountOnboardingCurrentStateVerificationV1.aliasAbsent(
                    blockHeight: 51,
                    blockHash: blockHash
                )
            ),
            (
                Optional(wrongAccountId),
                ToriiAccountOnboardingCurrentStateVerificationV1.aliasConflict(
                    blockHeight: 51,
                    blockHash: blockHash
                )
            ),
        ] {
            var requestCount = 0
            let observation = try ToriiAccountOnboardingCurrentStateResponseV1(
                networkId: receipt.body.networkId,
                accountId: intent.accountId,
                alias: intent.alias,
                accountExists: true,
                aliasTargetAccountId: target,
                observedBlockHeight: 51,
                observedBlockHash: blockHash
            )
            StubURLProtocol.handler = { request in
                requestCount += 1
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(
                    request.url?.path,
                    "/v1/accounts/onboarding/current-state"
                )
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, try JSONEncoder().encode(observation))
            }

            let result = try await makeClient().verifyAccountOnboardingCurrentState(
                proofRequired,
                request: intent,
                receipt: receipt,
                binding: binding,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                canonicalAuth: canonicalReadAuth,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTAssertEqual(result, expected)
            XCTAssertEqual(requestCount, 1)
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingCurrentStateRejectsOpenSubstitutedAndInvalidResponses() async throws {
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: intent, disposition: .noOp)
        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        let proofRequired = try proofRequiredOnboardingResponse(
            receipt: receipt,
            binding: binding
        )
        let blockHash = TestNetworkIds.canonical.literal
        let alternateNetwork = try NetworkId(bytes: Data(repeating: 0x25, count: 32))
        let otherAccount = try Keypair(privateKeyBytes: Data(repeating: 3, count: 32))
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
        let base: [String: Any] = [
            "version": 1,
            "network_id": receipt.body.networkId.literal,
            "account_id": intent.accountId,
            "alias": intent.alias,
            "account_exists": true,
            "alias_target_account_id": intent.accountId,
            "observed_block_height": 61,
            "observed_block_hash": blockHash,
        ]
        var cases: [(String, [String: Any])] = []
        func changed(_ key: String, _ value: Any) -> [String: Any] {
            var body = base
            body[key] = value
            return body
        }
        cases.append(("version", changed("version", 2)))
        cases.append(("network", changed("network_id", alternateNetwork.literal)))
        cases.append(("account", changed("account_id", otherAccount)))
        cases.append(("alias", changed("alias", "other@universal")))
        cases.append(("height", changed("observed_block_height", 0)))
        cases.append(("hash", changed("observed_block_hash", blockHash.lowercased())))
        cases.append(("target", changed("alias_target_account_id", " \(intent.accountId)")))
        var absent = changed("account_exists", false)
        absent["alias_target_account_id"] = NSNull()
        cases.append(("absent account", absent))
        var open = base
        open["legacy_account_state"] = "Applied"
        cases.append(("unknown field", open))
        var missingTarget = base
        missingTarget.removeValue(forKey: "alias_target_account_id")
        cases.append(("missing optional target key", missingTarget))

        for (label, body) in cases {
            var requestCount = 0
            StubURLProtocol.handler = { request in
                requestCount += 1
                XCTAssertEqual(request.httpMethod, "POST", label)
                XCTAssertEqual(
                    request.url?.path,
                    "/v1/accounts/onboarding/current-state",
                    label
                )
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, try JSONSerialization.data(withJSONObject: body))
            }
            do {
                _ = try await makeClient().verifyAccountOnboardingCurrentState(
                    proofRequired,
                    request: intent,
                    receipt: receipt,
                    binding: binding,
                    expectedAuthority: receipt.body.authority,
                    expectedNetworkId: receipt.body.networkId,
                    canonicalAuth: canonicalReadAuth,
                    bodyEncoder: encodeTestCanonicalOnboardingBody
                )
                XCTFail("\(label) must be rejected")
            } catch {}
            XCTAssertEqual(requestCount, 1, label)
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountFaucetClaimAndPolicyRejectInvalidFirstReleaseValues() throws {
        let accountId = try canonicalOwnerLiteral()
        XCTAssertThrowsError(
            try ToriiAccountFaucetClaimV1(
                accountId: accountId,
                powAnchorHeight: 0,
                powNonceHex: "00"
            )
        )
        for nonce in ["", "0", "AA", "gg"] {
            XCTAssertThrowsError(
                try ToriiAccountFaucetClaimV1(
                    accountId: accountId,
                    powAnchorHeight: 1,
                    powNonceHex: nonce
                )
            )
        }
        let validClaim = try ToriiAccountFaucetClaimV1(
            accountId: accountId,
            powAnchorHeight: 1,
            powNonceHex: "00"
        )
        let claimObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(validClaim))
                as? [String: Any]
        )
        for field in ["pow_anchor_height", "pow_nonce_hex"] {
            var missing = claimObject
            missing.removeValue(forKey: field)
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiAccountFaucetClaimV1.self,
                    from: JSONSerialization.data(withJSONObject: missing)
                )
            )
            var null = claimObject
            null[field] = NSNull()
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiAccountFaucetClaimV1.self,
                    from: JSONSerialization.data(withJSONObject: null)
                )
            )
        }

        let signer = try SigningKey.ed25519(
            privateKey: Data(repeating: 0x61, count: 32)
        )
        let authority = try AccountId.makeI105(publicKey: signer.publicKey())
        let assetDefinitionId = "4rPeAP6jAjiLVZThZYwwPRBuQagt"
        XCTAssertThrowsError(
            try ToriiAccountFaucetPolicyV1(
                faucetAuthority: authority,
                assetDefinitionId: assetDefinitionId,
                amount: KotodamaQuantity("0")
            )
        )
        XCTAssertThrowsError(
            try ToriiAccountFaucetPolicyV1(
                faucetAuthority: authority,
                assetDefinitionId: "not-an-asset-definition",
                amount: KotodamaQuantity("1")
            )
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountFaucetPreparesPersistsAndSubmitsExactEnvelope() async throws {
        let claim = try ToriiAccountFaucetClaimV1(
            accountId: canonicalOwnerLiteral(),
            powAnchorHeight: 42,
            powNonceHex: "0a"
        )
        let binding = try preparedAccountBinding(claim: claim, requestByte: "33")
        let prepared = try preparedFaucetTransaction(claim: claim, binding: binding)
        let submitResult = try ToriiPreparedTransactionSubmitResponseV1(
            binding: binding,
            operation: .faucet,
            transactionHashHex: prepared.transactionHashHex,
            outcome: .applied
        )
        var requestCount = 0

        StubURLProtocol.handler = { request in
            requestCount += 1
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertNil(request.value(forHTTPHeaderField: ToriiAccountOnboardingTokenHeader))
            let body = try XCTUnwrap(self.bodyData(from: request))
            if request.url?.path == "/v1/accounts/faucet/prepare" {
                XCTAssertEqual(
                    try JSONDecoder().decode(
                        ToriiAccountFaucetPrepareRequestV1.self,
                        from: body
                    ),
                    try ToriiAccountFaucetPrepareRequestV1(
                        binding: binding,
                        claim: claim,
                        feePayment: prepared.feePayment
                    )
                )
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, try JSONEncoder().encode(prepared))
            }

            XCTAssertEqual(request.url?.path, "/v1/accounts/faucet")
            XCTAssertEqual(
                try JSONDecoder().decode(
                    ToriiAccountFaucetPreparedTransactionV1.self,
                    from: body
                ),
                prepared
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, try JSONEncoder().encode(submitResult))
        }

        let client = makeClient()
        let policy = try faucetPolicy(for: prepared)
        let preparedResult = try await client.prepareAccountFaucet(
            claim,
            binding: binding,
            feePayment: prepared.feePayment,
            policy: policy,
            expectedNetworkId: TestNetworkIds.canonical
        )
        XCTAssertEqual(preparedResult, prepared)
        let persisted = try JSONEncoder().encode(preparedResult)
        let reopened = try JSONDecoder().decode(
            ToriiAccountFaucetPreparedTransactionV1.self,
            from: persisted
        )
        let submitted = try await client.submitPreparedAccountFaucet(
            reopened,
            expectedFeePayment: prepared.feePayment,
            policy: policy,
            expectedNetworkId: TestNetworkIds.canonical
        )
        XCTAssertEqual(submitted, submitResult)
        XCTAssertEqual(requestCount, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testPreparedAccountSubmitsRejectCallerFeeAndFaucetPolicySubstitutionBeforeDispatch() async throws {
        let accountId = try canonicalOwnerLiteral()
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let onboardingBinding = try preparedAccountBinding(
            receipt: receipt,
            requestByte: "22"
        )
        let onboarding = try preparedOnboardingTransaction(
            receipt: receipt,
            binding: onboardingBinding
        )
        let claim = try ToriiAccountFaucetClaimV1(
            accountId: accountId,
            powAnchorHeight: 42,
            powNonceHex: "0a"
        )
        let faucetBinding = try preparedAccountBinding(
            claim: claim,
            requestByte: "33"
        )
        let faucet = try preparedFaucetTransaction(claim: claim, binding: faucetBinding)
        let policy = try faucetPolicy(for: faucet)
        var requestCount = 0
        StubURLProtocol.handler = { _ in
            requestCount += 1
            XCTFail("fee-substituted prepared envelope reached HTTP dispatch")
            throw URLError(.badServerResponse)
        }
        let substitutedFee = testFeePayment(gasLimit: 1)

        do {
            _ = try await makeClient().submitPreparedAccountOnboarding(
                onboarding,
                expectedFeePayment: substitutedFee,
                request: intent,
                onboardingToken: onboardingToken,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("onboarding submit accepted a substituted fee intent")
        } catch {
            guard case ToriiClientError.invalidResponse = error else {
                return XCTFail("unexpected onboarding fee error: \(error)")
            }
        }

        do {
            _ = try await makeClient().submitPreparedAccountFaucet(
                faucet,
                expectedFeePayment: substitutedFee,
                policy: policy,
                expectedNetworkId: TestNetworkIds.canonical
            )
            XCTFail("faucet submit accepted a substituted fee intent")
        } catch {
            guard case ToriiClientError.invalidResponse = error else {
                return XCTFail("unexpected faucet fee error: \(error)")
            }
        }

        let substitutedAuthoritySigner = try SigningKey.ed25519(
            privateKey: Data(repeating: 0x51, count: 32)
        )
        let substitutedAuthority = try ToriiAccountFaucetPolicyV1(
            faucetAuthority: AccountId.makeI105(
                publicKey: substitutedAuthoritySigner.publicKey()
            ),
            assetDefinitionId: faucet.assetDefinitionId,
            amount: KotodamaQuantity(faucet.amount)
        )
        var substitutedAssetUUID = Data(repeating: 0xa5, count: 16)
        substitutedAssetUUID[6] = 0x45
        substitutedAssetUUID[8] = 0xa5
        let substitutedAssetId = try XCTUnwrap(
            AssetDefinitionAddressCodec.definitionLiteral(
                uuidBytes: substitutedAssetUUID
            )
        )
        let substitutedAsset = try ToriiAccountFaucetPolicyV1(
            faucetAuthority: policy.faucetAuthority,
            assetDefinitionId: substitutedAssetId,
            amount: policy.amount
        )
        let substitutedAmount = try ToriiAccountFaucetPolicyV1(
            faucetAuthority: policy.faucetAuthority,
            assetDefinitionId: policy.assetDefinitionId,
            amount: KotodamaQuantity("26")
        )
        for (label, substitutedPolicy) in [
            ("authority", substitutedAuthority),
            ("asset definition", substitutedAsset),
            ("amount", substitutedAmount),
        ] {
            do {
                _ = try await makeClient().submitPreparedAccountFaucet(
                    faucet,
                    expectedFeePayment: faucet.feePayment,
                    policy: substitutedPolicy,
                    expectedNetworkId: TestNetworkIds.canonical
                )
                XCTFail("faucet submit accepted a substituted \(label) policy")
            } catch {}
        }
        XCTAssertEqual(requestCount, 0)
    }

    func testPreparedAccountProtocolRejectsEmptyInstructionExecutable() throws {
        let accountId = try canonicalOwnerLiteral()
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let binding = try preparedAccountBinding(
            receipt: receipt,
            requestByte: "22"
        )
        let semanticHash = try ToriiAccountOnboardingReceiptVerifier.canonicalHash(
            canonicalBodyNorito: encodeTestCanonicalOnboardingBody(receipt.body)
        ).hexEncodedString()
        let feePayment = testFeePayment()
        let signer = try SigningKey.ed25519(privateKey: Data(repeating: 0x51, count: 32))
        let payload = try preparedTransactionPayload(
            authority: receipt.body.authority,
            networkId: receipt.body.networkId,
            feePayment: feePayment,
            binding: binding,
            operation: .onboarding,
            semanticHashHex: semanticHash,
            instructionPayloads: []
        )
        let (wire, transactionHash) = try preparedTransactionWire(
            payload: payload,
            signer: signer
        )

        XCTAssertThrowsError(
            try ToriiAccountOnboardingPreparedTransactionV1(
                binding: binding,
                receipt: receipt,
                semanticHashHex: semanticHash,
                accountId: receipt.body.request.accountId,
                alias: receipt.body.request.alias,
                disposition: receipt.body.resource.disposition,
                transactionHashHex: transactionHash,
                signedTransactionWireHex: wire.hexEncodedString(),
                signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString(),
                feePayment: feePayment,
                serverSignature: try signer.sign(Data("placeholder".utf8)).hexUppercased()
            )
        )
    }

    func testPreparedFaucetRequiresExactConsumeOnceMarker() throws {
        let claim = try ToriiAccountFaucetClaimV1(
            accountId: canonicalOwnerLiteral(), powAnchorHeight: 42, powNonceHex: "0a"
        )
        let binding = try preparedAccountBinding(claim: claim, requestByte: "33")
        let signer = try SigningKey.ed25519(privateKey: Data(repeating: 0x61, count: 32))
        let authority = try AccountId.makeI105(publicKey: signer.publicKey())
        let feePayment = testFeePayment()
        for marker: ToriiJSONValue? in [.number(1), nil, .number(2), .string("1"), .bool(true)] {
            let payload = try preparedTransactionPayload(
                authority: authority, networkId: TestNetworkIds.canonical,
                feePayment: feePayment, binding: binding, operation: .faucet,
                semanticHashHex: binding.semanticHashHex, faucetMarker: marker
            )
            let (wire, transactionHash) = try preparedTransactionWire(payload: payload, signer: signer)
            let inspected = try ToriiPreparedAccountProtocolV1.inspectWire(
                transactionHashHex: transactionHash,
                signedTransactionWireHex: wire.hexEncodedString(),
                signedTransactionWireSHA256: Data(SHA256.hash(data: wire)).hexEncodedString()
            )
            let validate = {
                try ToriiPreparedAccountProtocolV1.validatePreparedTransaction(
                    inspected, feePayment: feePayment, binding: binding, operation: .faucet,
                    semanticHashHex: binding.semanticHashHex, expectedAuthority: authority,
                    expectedNetworkId: TestNetworkIds.canonical
                )
            }
            if marker == .number(1) {
                XCTAssertNoThrow(try validate())
            } else {
                XCTAssertThrowsError(try validate())
            }
        }
    }

    func testPreparedExecutionLifetimeIsBoundedByOperationDeadline() throws {
        try ToriiPreparedAccountProtocolV1.validateExecutionLifetime(
            creationTimeMs: 10, timeToLiveMs: 5, deadline: 15
        )
        for ttl: UInt64? in [nil, 0, 6, UInt64.max] {
            XCTAssertThrowsError(try ToriiPreparedAccountProtocolV1.validateExecutionLifetime(
                creationTimeMs: 10, timeToLiveMs: ttl, deadline: 15
            ))
        }
    }

    func testPreparedOperationBindingRejectsPrivateCustodyAndSemanticSubstitution() throws {
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal", accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        XCTAssertThrowsError(try ToriiPreparedOperationBindingV1(
            semanticHashHex: binding.semanticHashHex, kind: .onboarding,
            requestId: binding.requestId, executionExpiresAtUnixMs: (1 << 53) + 1
        ))
        let encoded = try JSONEncoder().encode(binding)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(Set(object.keys), Set([
            "schema", "kind", "semantic_hash_hex", "request_id", "execution_expires_at_unix_ms"
        ]))
        for field in ["authorization_sha256", "authorization_nonce", "phase", "idempotency_key"] {
            var contaminated = object
            contaminated[field] = "private-custody-is-not-public"
            XCTAssertThrowsError(try JSONDecoder().decode(
                ToriiPreparedOperationBindingV1.self,
                from: JSONSerialization.data(withJSONObject: contaminated)
            ))
        }
        let substituted = try ToriiPreparedOperationBindingV1(
            semanticHashHex: String(repeating: "11", count: 32), kind: .onboarding,
            requestId: binding.requestId, executionExpiresAtUnixMs: binding.executionExpiresAtUnixMs
        )
        XCTAssertThrowsError(try ToriiAccountOnboardingPrepareRequestV1(
            binding: substituted, receipt: receipt, feePayment: testFeePayment()
        ))
        var shortReceiptObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any]
        )
        var body = try XCTUnwrap(shortReceiptObject["body"] as? [String: Any])
        body["valid_until_ms"] = 1
        shortReceiptObject["body"] = body
        let shortReceipt = try JSONDecoder().decode(
            ToriiAccountOnboardingPlanReceipt.self,
            from: JSONSerialization.data(withJSONObject: shortReceiptObject)
        )
        XCTAssertThrowsError(try binding.validate(receipt: shortReceipt))
        let transcript = ToriiPreparedAccountProtocolV1.baseSignatureTranscript(
            envelopeSchema: ToriiPreparedAccountProtocolV1.preparedTransactionSchema,
            operation: .onboarding, binding: binding
        )
        XCTAssertFalse(String(decoding: transcript, as: UTF8.self).contains("authorization_nonce"))
        XCTAssertTrue(String(decoding: transcript, as: UTF8.self).contains("binding.request_id"))
    }

    func testPreparedAccountProtocolRejectsLegacyApplyAndOpenEnvelopes() throws {
        XCTAssertThrowsError(
            try ToriiPreparedOperationBindingV1(
                semanticHashHex: String(repeating: "11", count: 32),
                kind: .onboarding,
                requestId: String(repeating: "22", count: 32),
                executionExpiresAtUnixMs: 0
            )
        )
        let accountId = try canonicalOwnerLiteral()
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: accountId
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let receiptObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt))
                as? [String: Any]
        )
        let retiredApplyBody = try JSONSerialization.data(
            withJSONObject: ["receipt": receiptObject]
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareRequestV1.self,
                from: retiredApplyBody
            )
        )

        let binding = try preparedAccountBinding(receipt: receipt, requestByte: "22")
        var openPrepare = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: JSONEncoder().encode(
                    ToriiAccountOnboardingPrepareRequestV1(
                        binding: binding,
                        receipt: receipt,
                        feePayment: testFeePayment()
                    )
                )
            ) as? [String: Any]
        )
        var missingOnboardingFee = openPrepare
        missingOnboardingFee.removeValue(forKey: "fee_payment")
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareRequestV1.self,
                from: JSONSerialization.data(withJSONObject: missingOnboardingFee)
            )
        )
        let faucetClaim = try ToriiAccountFaucetClaimV1(
            accountId: accountId,
            powAnchorHeight: 42,
            powNonceHex: "0a"
        )
        let faucetBinding = try preparedAccountBinding(
            claim: faucetClaim,
            requestByte: "33"
        )
        var missingFaucetFee = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: JSONEncoder().encode(
                    ToriiAccountFaucetPrepareRequestV1(
                        binding: faucetBinding,
                        claim: faucetClaim,
                        feePayment: testFeePayment()
                    )
                )
            ) as? [String: Any]
        )
        missingFaucetFee.removeValue(forKey: "fee_payment")
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountFaucetPrepareRequestV1.self,
                from: JSONSerialization.data(withJSONObject: missingFaucetFee)
            )
        )
        openPrepare["legacy_apply"] = true
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareRequestV1.self,
                from: JSONSerialization.data(withJSONObject: openPrepare)
            )
        )

        let validBinding = try XCTUnwrap(openPrepare["binding"] as? [String: Any])
        var uppercaseBinding = validBinding
        uppercaseBinding["request_id"] = String(repeating: "AA", count: 32)
        openPrepare.removeValue(forKey: "legacy_apply")
        openPrepare["binding"] = uppercaseBinding
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareRequestV1.self,
                from: JSONSerialization.data(withJSONObject: openPrepare)
            )
        )

        openPrepare["binding"] = validBinding
        var openReceipt = receiptObject
        openReceipt["legacy_signature"] = "AB"
        openPrepare["receipt"] = openReceipt
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareRequestV1.self,
                from: JSONSerialization.data(withJSONObject: openPrepare)
            )
        )

        let prepared = try preparedOnboardingTransaction(receipt: receipt, binding: binding)
        var aggregateEnvelope = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(prepared))
                as? [String: Any]
        )
        aggregateEnvelope["operations"] = []
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPreparedTransactionV1.self,
                from: JSONSerialization.data(withJSONObject: aggregateEnvelope)
            )
        )
        aggregateEnvelope.removeValue(forKey: "operations")
        aggregateEnvelope["transaction_hash_hex"] = String(repeating: "00", count: 32)
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPreparedTransactionV1.self,
                from: JSONSerialization.data(withJSONObject: aggregateEnvelope)
            )
        )

        let proofRequired = try proofRequiredOnboardingResponse(
            receipt: receipt,
            binding: binding
        )
        var retiredUnchanged = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(proofRequired))
                as? [String: Any]
        )
        retiredUnchanged["schema"] = "iroha.accounts.onboard.prepare-unchanged.v1"
        retiredUnchanged["outcome"] = "Unchanged"
        retiredUnchanged.removeValue(forKey: "proof_kind")
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareResponseV1.self,
                from: JSONSerialization.data(withJSONObject: retiredUnchanged)
            )
        )

        retiredUnchanged["schema"] =
            ToriiAccountOnboardingProofRequiredPrepareResponseV1.schemaV1
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAccountOnboardingPrepareResponseV1.self,
                from: JSONSerialization.data(withJSONObject: retiredUnchanged)
            )
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExpiredRetainedOnboardingEnvelopeCanReconcileButCannotPrepareAgain() async throws {
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let receipt = try onboardingPlanReceipt(request: intent)
        let expiredBinding = try ToriiPreparedOperationBindingV1(
            semanticHashHex: XCTUnwrap(ToriiCanonicalHashLiteral.normalizedHex(from: receipt.planHash)),
            kind: .onboarding,
            requestId: String(repeating: "22", count: 32),
            executionExpiresAtUnixMs: 100
        )
        let prepared = try preparedOnboardingTransaction(
            receipt: receipt,
            binding: expiredBinding
        )
        let applied = try ToriiPreparedTransactionSubmitResponseV1(
            binding: expiredBinding,
            operation: .onboarding,
            transactionHashHex: prepared.transactionHashHex,
            outcome: .applied
        )
        var requestCount = 0
        StubURLProtocol.handler = { request in
            requestCount += 1
            XCTAssertEqual(request.url?.path, "/v1/accounts/onboard")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, try JSONEncoder().encode(applied))
        }

        do {
            _ = try await makeClient().prepareAccountOnboarding(
                receipt,
                request: intent,
                binding: expiredBinding,
                feePayment: prepared.feePayment,
                onboardingToken: onboardingToken,
                expectedAuthority: receipt.body.authority,
                expectedNetworkId: receipt.body.networkId,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("expired binding must not start a new prepare")
        } catch {
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("expected expired binding failure, got \(error)")
            }
        }
        XCTAssertEqual(requestCount, 0)

        let result = try await makeClient().submitPreparedAccountOnboarding(
            prepared,
            expectedFeePayment: prepared.feePayment,
            request: intent,
            onboardingToken: onboardingToken,
            expectedAuthority: receipt.body.authority,
            expectedNetworkId: receipt.body.networkId,
            bodyEncoder: encodeTestCanonicalOnboardingBody
        )
        XCTAssertEqual(result, applied)
        XCTAssertEqual(requestCount, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingRejectsMalformedTokenBeforeNetwork() async throws {
        StubURLProtocol.handler = { _ in
            XCTFail("malformed onboarding token reached HTTP dispatch")
            throw URLError(.badURL)
        }
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let expectedAuthority = try canonicalOwnerLiteral()
        let expectedNetworkId = TestNetworkIds.canonical
        for token in [
            "",
            String(repeating: "T", count: 31),
            String(repeating: "T", count: 257),
            String(repeating: "T", count: 31) + " ",
            String(repeating: "T", count: 31) + "é"
        ] {
            do {
                _ = try await makeClient().planAccountOnboarding(
                    intent,
                    onboardingToken: token,
                    expectedAuthority: expectedAuthority,
                    expectedNetworkId: expectedNetworkId,
                    bodyEncoder: encodeTestCanonicalOnboardingBody
                )
                XCTFail("Expected malformed onboarding token to fail")
            } catch {
                guard case let ToriiClientError.invalidPayload(message) = error else {
                    return XCTFail("Expected invalidPayload error, got \(error)")
                }
                if !token.isEmpty {
                    XCTAssertFalse(message.contains(token))
                }
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingRejectsInvalidTrustPinsBeforeNetwork() async throws {
        StubURLProtocol.handler = { _ in
            XCTFail("invalid onboarding trust pin reached HTTP dispatch")
            throw URLError(.badURL)
        }
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        do {
            _ = try await makeClient().planAccountOnboarding(
                intent,
                onboardingToken: onboardingToken,
                expectedAuthority: "not-an-account-id",
                expectedNetworkId: TestNetworkIds.canonical,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("Expected invalid authority pin to fail")
        } catch {
            XCTAssertEqual(
                error as? ToriiAccountOnboardingReceiptVerificationError,
                .invalidAuthority
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountOnboardingPlanDoesNotFollowRedirectsAndRedactsToken() async throws {
        var requestCount = 0
        StubURLProtocol.handler = { request in
            requestCount += 1
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 307,
                httpVersion: nil,
                headerFields: [
                    "Location": "https://redirect.example/v1/accounts/onboard/plan",
                    "x-iroha-reject-code": self.onboardingToken
                ]
            )!
            return (
                response,
                Data("{\"message\":\"server echoed \(self.onboardingToken)\"}".utf8)
            )
        }
        let intent = try ToriiAccountOnboardingPlanRequest(
            alias: "alice@universal",
            accountId: canonicalOwnerLiteral()
        )
        let expectedAuthority = try canonicalOwnerLiteral()
        let expectedNetworkId = TestNetworkIds.canonical

        do {
            _ = try await makeClient().planAccountOnboarding(
                intent,
                onboardingToken: onboardingToken,
                expectedAuthority: expectedAuthority,
                expectedNetworkId: expectedNetworkId,
                bodyEncoder: encodeTestCanonicalOnboardingBody
            )
            XCTFail("Expected redirect response to fail closed")
        } catch {
            guard case let ToriiClientError.api(apiError) = error else {
                return XCTFail("Expected HTTP status error, got \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 307)
            XCTAssertEqual(message, "server echoed <redacted>")
            XCTAssertEqual(rejectCode, "<redacted>")
            XCTAssertFalse(error.localizedDescription.contains(onboardingToken))
        }
        XCTAssertEqual(requestCount, 1)
    }
    func testGetUaidBindingsReturnsDataspaces() async throws {
        let uaidHex = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        let payload = """
        {
          "uaid":"uaid:\(uaidHex)",
          "dataspaces":[
            {"dataspace_id":0,"dataspace_alias":"universal","accounts":["sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"]},
            {"dataspace_id":11,"dataspace_alias":"cbdc","accounts":[]}
          ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/space-directory/uaids/uaid%3A\(uaidHex)"))
            XCTAssertNil(request.url?.query)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let response = try await makeClient().getUaidBindings(
            uaid: "uaid:\(uaidHex)",
            query: ToriiUaidBindingsQuery()
        )
        XCTAssertEqual(response.dataspaces.count, 2)
        XCTAssertEqual(response.dataspaces.first?.accounts.first, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidManifestsAppliesQueryItems() async throws {
        let uaidHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543211"
        let payload = """
        {
          "total":1,
          "next_cursor":null,
          "items":[
            {
              "dataspace_id":11,
              "dataspace_alias":"cbdc",
              "manifest_hash":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
              "status":"Active",
              "lifecycle":{"activated_epoch":4096,"expired_epoch":null,"revocation":null},
              "accounts":["sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"],
              "manifest":{
                "version":1,
                "uaid":"uaid:\(uaidHex)",
                "dataspace":11,
                "issued_ms":100,
                "activation_epoch":200,
                "entries":[{"scope":{"program":"cbdc.transfer"},"effect":{"Allow":{"max_amount":"500","window":"PerDay"}}}]
              }
            }
          ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/space-directory/uaids/uaid%3A\(uaidHex)/manifests"))
            XCTAssertEqual(request.httpMethod, "POST")
            let query = try JSONSerialization.jsonObject(with: XCTUnwrap(self.bodyData(from: request))) as! [String: Any]
            XCTAssertEqual(query["limit"] as? Int, 2)
            XCTAssertEqual(query["include_total"] as? Bool, true)
            XCTAssertNotNil(query["filter"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let query = ToriiListQuery(filterText: #"dataspace_id = 11 and status = "Active""#, limit: 2, includeTotal: true)
        let response = try await makeClient().uaidManifests(of: "uaid:\(uaidHex)").page(query)
        XCTAssertEqual(response.total, 1)
        XCTAssertFalse(response.hasMore)
        XCTAssertEqual(response.items.first?.status, .active)
        XCTAssertEqual(response.items.first?.manifest.version, 1)
        XCTAssertEqual(response.items.first?.manifest.issuedMs, 100)
        XCTAssertEqual(response.items.first?.accounts.first, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
    }

    func testUaidManifestModelsRequireExactFirstReleaseWireShape() throws {
        let uaid = "uaid:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543211"
        let valid = """
        {
          "total":1,
          "next_cursor":null,
          "items":[{
            "dataspace_id":11,
            "dataspace_alias":null,
            "manifest_hash":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "status":"Active",
            "lifecycle":{"activated_epoch":4096,"expired_epoch":null,"revocation":null},
            "accounts":[],
            "manifest":{
              "version":1,
              "uaid":"\(uaid)",
              "dataspace":11,
              "issued_ms":100,
              "activation_epoch":200,
              "entries":[]
            }
          }]
        }
        """
        let decoder = JSONDecoder()
        XCTAssertNoThrow(
            try decoder.decode(ToriiPage<ToriiUaidManifestRecord>.self, from: Data(valid.utf8))
        )

        let invalidPayloads = [
            valid.replacingOccurrences(of: "\"next_cursor\":null,", with: ""),
            valid.replacingOccurrences(of: "\"next_cursor\":null,", with: "\"next_cursor\":\"\","),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":\"V1\""),
            valid.replacingOccurrences(of: "\"entries\":[]", with: "\"expiry_epoch\":null,\"entries\":[]"),
            valid.replacingOccurrences(of: "\"status\":\"Active\"", with: "\"status\":\"active\""),
            valid.replacingOccurrences(of: "\"status\":\"Active\"", with: "\"status\":\"Pending\""),
            valid.replacingOccurrences(of: "\"total\":1", with: "\"total\":0"),
            valid.replacingOccurrences(of: "\"next_cursor\":null", with: "\"has_more\":false,\"next_cursor\":null"),
        ]
        for payload in invalidPayloads {
            XCTAssertThrowsError(
                try decoder.decode(ToriiPage<ToriiUaidManifestRecord>.self, from: Data(payload.utf8))
            )
        }
    }

    func testUaidPortfolioAndBindingsEnforceUniversalAccountInvariantsWithoutTrimmingLabels() throws {
        let uaid = "uaid:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let otherAccount = "sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"
        let portfolio = """
        {
          "uaid":"\(uaid)",
          "totals":{"accounts":1,"positions":0},
          "dataspaces":[{
            "dataspace_id":0,
            "dataspace_alias":" universal ",
            "accounts":[{"account_id":"\(account)","label":" holder ","assets":[]}]
          }]
        }
        """
        let decoded = try JSONDecoder().decode(
            ToriiUaidPortfolioResponse.self,
            from: Data(portfolio.utf8)
        )
        XCTAssertEqual(decoded.dataspaces[0].dataspaceAlias, " universal ")
        XCTAssertEqual(decoded.dataspaces[0].accounts[0].label, " holder ")

        let badTotals = portfolio.replacingOccurrences(
            of: "\"accounts\":1,\"positions\":0",
            with: "\"accounts\":2,\"positions\":0"
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiUaidPortfolioResponse.self, from: Data(badTotals.utf8))
        )

        let bindings = """
        {
          "uaid":"\(uaid)",
          "dataspaces":[{
            "dataspace_id":0,
            "dataspace_alias":null,
            "accounts":["\(account)","\(otherAccount)"]
          }]
        }
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiUaidBindingsResponse.self, from: Data(bindings.utf8))
        )
    }

    func testUaidPortfolioRejectsLegacyOrMismatchedAssetIdentifiers() throws {
        let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let otherAccount = "sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"
        let definition = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        let assetId = "\(definition)#\(account)#dataspace:7"
        let valid = """
        {
          "uaid":"uaid:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "totals":{"accounts":1,"positions":1},
          "dataspaces":[{
            "dataspace_id":7,
            "dataspace_alias":null,
            "accounts":[{
              "account_id":"\(account)",
              "label":null,
              "assets":[{
                "asset_id":"\(assetId)",
                "asset_definition_id":"\(definition)",
                "quantity":"1"
              }]
            }]
          }]
        }
        """
        XCTAssertNoThrow(
            try JSONDecoder().decode(ToriiUaidPortfolioResponse.self, from: Data(valid.utf8))
        )

        for invalid in [
            valid.replacingOccurrences(of: assetId, with: definition),
            valid.replacingOccurrences(of: assetId, with: "\(definition)#\(otherAccount)#dataspace:7"),
            valid.replacingOccurrences(of: "#dataspace:7", with: "#dataspace:8"),
            valid.replacingOccurrences(
                of: "\"asset_definition_id\":\"\(definition)\"",
                with: "\"asset_definition_id\":\"61CtjvNd9T3THAR65GsMVHr82Bjc\""
            ),
        ] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiUaidPortfolioResponse.self, from: Data(invalid.utf8))
            )
        }

        XCTAssertThrowsError(try ToriiUaidPortfolioQuery(assetId: definition).queryItems())
    }

    func testUaidBindingsQueryHasNoItems() throws {
        XCTAssertNil(try ToriiUaidBindingsQuery().queryItems())
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidPortfolioRejectsInvalidLiteral() async {
        do {
            _ = try await makeClient().getUaidPortfolio(uaid: "bad")
            XCTFail("Expected invalid UAID error")
        } catch {
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetUaidPortfolioRejectsInvalidLsb() async {
        let uaidHex = String(repeating: "10", count: 32)
        do {
            _ = try await makeClient().getUaidPortfolio(uaid: "uaid:\(uaidHex)")
            XCTFail("Expected invalid UAID error")
        } catch {
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIrohaSDKGetTransactionStatusAsyncUsesREST() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertEqual(components?.queryItems?.first(where: { $0.name == "hash" })?.value, Self.pipelineHash)
            XCTAssertEqual(components?.queryItems?.first(where: { $0.name == "scope" })?.value, "global")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"hash":"\(Self.pipelineHash)","status":{"kind":"Rejected","block_height":12},"scope":"global","resolved_from":"state"}
            """.data(using: .utf8)!
            return (response, body)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let sdk = IrohaSDK(baseURL: URL(string: "https://example.test")!, session: session)

        let status = try await sdk.getTransactionStatus(hashHex: Self.pipelineHash)
        XCTAssertEqual(status?.hash, Self.pipelineHash)
        XCTAssertEqual(status?.status.kind, "Rejected")
        XCTAssertEqual(status?.status.blockHeight, 12)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetPipelineRecoveryAsync() async throws {
        let payload = """
        {"format":"pipeline.recovery.v1","height":42,"dag":{"fingerprint":"abcdef","key_count":1},"txs":[{"hash":"0x01","reads":["account/sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"],"writes":["asset/62Fk4FPcMuLvW5QjDGNF2a4jAmjM"]}]}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/recovery/42")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let recovery = try await makeClient().getPipelineRecovery(height: 42)
        XCTAssertEqual(recovery?.format, "pipeline.recovery.v1")
        XCTAssertEqual(recovery?.height, 42)
        XCTAssertEqual(recovery?.dag.fingerprint, "abcdef")
        XCTAssertEqual(recovery?.txs.first?.hash, "0x01")
    }

    func testGetPipelineRecoveryReturnsNilOn404() {
        let expectation = expectation(description: "recovery")
        StubURLProtocol.handler = { request in
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
            return (response, nil)
        }

        makeClient().getPipelineRecovery(height: 99) { result in
            switch result {
            case .success(let recovery):
                XCTAssertNil(recovery)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetPipelinePreflightAsync() async throws {
        // The exact body Torii serves, generated from its Rust DTO.
        let payload = try PipelinePreflightFixture.data()
        let served = try PipelinePreflightFixture.object()
        let servedFees = try XCTUnwrap(served["fees"] as? [String: Any])

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/preflight")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let preflight = try await makeClient().getPipelinePreflight()
        let status = try ToriiStatusPayload(raw: [
            "peers": .number(1),
            "queue_size": .number(2),
            "time_since_last_non_empty_block_ms": .number(20_001),
            "commit_time_ms": .number(30),
            "txs_approved": .number(0),
            "txs_rejected": .number(0),
            "view_changes": .number(0)
        ])
        XCTAssertEqual(preflight.schemaVersion, 1)
        XCTAssertEqual(preflight.chainHeight, 42)
        XCTAssertEqual(preflight.sumeragi.blockCadenceMs, 1_000)
        XCTAssertEqual(preflight.stallThresholdMs, 20_000)
        XCTAssertEqual(preflight.admission.maxTxBytes, 1_048_576)
        XCTAssertEqual(preflight.pipeline.signatureBatchMaxEd25519, 64)
        XCTAssertEqual(preflight.pipeline.ivmMaxCyclesUpperBound, 2_000_000)
        XCTAssertEqual(preflight.pipeline.ivmAdmissionCycleLimit, 1_000_000)
        XCTAssertEqual(preflight.queue.queued, 2)
        XCTAssertEqual(preflight.fees.baseFee, "0.1")
        XCTAssertEqual(
            preflight.fees.sponsorVaultCustodyAccountId,
            servedFees["sponsor_vault_custody_account_id"] as? String
        )
        XCTAssertEqual(
            preflight.fees.successfulClaimFeeExemptAuthorities,
            servedFees["successful_claim_fee_exempt_authorities"] as? [String]
        )
        XCTAssertTrue(preflight.isStatusStalled(status))
    }

    func testPipelinePreflightFeesRejectAliasShapedAccountIds() throws {
        let canonicalAccountId = "sorauﾛ1NｲﾘｳdPBeｼRoｸQ2ﾔgｼQqeｶﾍｽﾁhRW2ｺｿZ9ﾕｦUﾅRX5NJYH53"
        let cases: [(String, Any)] = [
            ("fee_sink_account_id", "fees@system"),
            ("sponsor_vault_custody_account_id", "vault@system"),
            ("successful_claim_fee_exempt_authorities", ["authority@system"]),
        ]

        for (field, value) in cases {
            var payload: [String: Any] = [
                "fee_asset_id": "xor#sora",
                "fee_sink_account_id": canonicalAccountId,
                "base_fee": "0",
                "per_byte_fee": "0",
                "per_instruction_fee": "0",
                "per_gas_unit_fee": "0",
                "sponsor_vault_custody_account_id": canonicalAccountId,
                "successful_claim_fee_exempt_authorities": [canonicalAccountId],
            ]
            payload[field] = value
            let data = try JSONSerialization.data(withJSONObject: payload)
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiPipelinePreflightFees.self, from: data),
                field
            )
        }
    }

    func testPipelinePreflightRejectsRetiredSignatureBatchAlias() throws {
        let payload = """
        {"signature_batch_max":0,"signature_batch_max_ed25519":64,"signature_batch_max_secp256k1":16,"signature_batch_max_pqc":8,"signature_batch_max_bls":16,"overlay_max_instructions":0,"ivm_max_decoded_instructions":1048576}
        """.data(using: .utf8)!

        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelinePreflightPipeline.self, from: payload)
        ) { error in
            XCTAssertTrue(String(describing: error).contains("unknown or retired field"))
        }
    }

    func testPipelinePreflightRequiresPositiveCurrentCycleLimits() throws {
        let cases = [
            """
            {"signature_batch_max_ed25519":64,"signature_batch_max_secp256k1":16,"signature_batch_max_pqc":8,"signature_batch_max_bls":16,"overlay_max_instructions":0,"ivm_max_cycles_upper_bound":0,"ivm_admission_cycle_limit":1000000,"ivm_max_decoded_instructions":1048576}
            """,
            """
            {"signature_batch_max_ed25519":64,"signature_batch_max_secp256k1":16,"signature_batch_max_pqc":8,"signature_batch_max_bls":16,"overlay_max_instructions":0,"ivm_max_cycles_upper_bound":2000000,"ivm_admission_cycle_limit":0,"ivm_max_decoded_instructions":1048576}
            """,
        ]

        for payload in cases {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiPipelinePreflightPipeline.self,
                    from: Data(payload.utf8)
                )
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIrohaSDKGetPipelineRecoveryAsyncUsesREST() async throws {
        let payload = """
        {"format":"pipeline.recovery.v1","height":7,"dag":{"fingerprint":"cafebabe","key_count":2},"txs":[]}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/recovery/7")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let sdk = IrohaSDK(
            baseURL: URL(string: "https://example.test")!,
            session: session,
            operatorSigningContext: Self.operatorSigningContext
        )

        let recovery = try await sdk.getPipelineRecovery(height: 7)
        XCTAssertEqual(recovery?.dag.fingerprint, "cafebabe")
        XCTAssertEqual(recovery?.height, 7)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIrohaSDKGetTimeNowAsync() async throws {
        let payload = """
        {"now":42,"offset_ms":0,"confidence_ms":1,"sample_count":6,"peer_count":3,"enforcement_mode":"reject","fallback":false,"health":{"healthy":true,"min_samples_ok":true,"offset_ok":true,"confidence_ok":true}}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/time/now")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let sdk = IrohaSDK(baseURL: URL(string: "https://example.test")!, session: session)

        let snapshot = try await sdk.getTimeNow()
        XCTAssertEqual(snapshot.now, 42)
        XCTAssertEqual(snapshot.confidence_ms, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTimeNowAsync() async throws {
        let payload = """
        {"now":1700000000123,"offset_ms":5,"confidence_ms":2,"sample_count":6,"peer_count":3,"enforcement_mode":"reject","fallback":false,"health":{"healthy":true,"min_samples_ok":true,"offset_ok":true,"confidence_ok":true}}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/time/now")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let snapshot = try await makeClient().getTimeNow()
        XCTAssertEqual(snapshot.now, 1_700_000_000_123)
        XCTAssertEqual(snapshot.offset_ms, 5)
        XCTAssertEqual(snapshot.confidence_ms, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTimeNowRejectsFallbackAndUnhealthyClock() async throws {
        for field in ["fallback", "sample_count", "health"] {
            var body: [String: Any] = ["now": 1_700_000_000_000, "offset_ms": 0,
                "confidence_ms": 1, "sample_count": 6, "peer_count": 3,
                "enforcement_mode": "reject", "fallback": false,
                "health": ["healthy": true, "min_samples_ok": true, "offset_ok": true, "confidence_ok": true]]
            switch field {
            case "fallback": body[field] = true
            case "sample_count": body[field] = 0
            default: body[field] = ["healthy": false, "min_samples_ok": true, "offset_ok": true, "confidence_ok": false]
            }
            let payload = try JSONSerialization.data(withJSONObject: body)
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
                return (response, payload)
            }
            do {
                _ = try await makeClient().getTimeNow()
                XCTFail("\(field) must not supply authoritative transaction time")
            } catch ToriiClientError.invalidPayload {
                // The time endpoint cannot promote this snapshot to the SDK clock.
            }
        }
    }

    func testGetTimeNowCompletion() {
        let expectation = expectation(description: "time-now")
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"now":10,"offset_ms":-1,"confidence_ms":0,"sample_count":6,"peer_count":3,"enforcement_mode":"reject","fallback":false,"health":{"healthy":true,"min_samples_ok":true,"offset_ok":true,"confidence_ok":true}}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().getTimeNow { result in
            switch result {
            case .success(let snapshot):
                XCTAssertEqual(snapshot.now, 10)
                XCTAssertEqual(snapshot.offset_ms, -1)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetNodeCapabilitiesAsync() async throws {
        let payload = """
        {"abi_version":1}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/node/capabilities")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let capabilities = try await makeClient().getNodeCapabilities(canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(capabilities.abiVersion, 1)
    }
}
