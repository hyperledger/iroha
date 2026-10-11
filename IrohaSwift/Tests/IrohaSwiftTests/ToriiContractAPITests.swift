import CryptoKit
import XCTest
@testable import IrohaSwift

@available(iOS 15.0, macOS 12.0, *)
final class ToriiContractAPITests: XCTestCase {
    private let detachedCreationTimeMs: UInt64 = 4_102_444_800_000
    private let signingSeed = Data(repeating: 0x41, count: 32)
    private var signingKeypair: Keypair { try! Keypair(privateKeyBytes: signingSeed) }
    private var authority: String {
        try! signingKeypair.accountId(networkPrefix: AccountId.defaultNetworkPrefix)
    }
    private var signingPublicKeyHex: String {
        signingKeypair.publicKey.map { String(format: "%02x", $0) }.joined()
    }
    private func detachedSignatureB64() throws -> String {
        try signingKeypair.sign(IrohaHash.hash(contractTransactionPayload)).base64EncodedString()
    }
    private let merchantAccount = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
    private let contractAlias = "bisp::hbl.sbp"
    private let contractAddress = "irohac1qyqqqqqqqqqqqqz6putm9wv6wkf4r22v02ktg4af7n3n7egd607g2"
    private let assetId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
    private let codeHash = String(repeating: "a", count: 63) + "b"
    private let abiHash = String(repeating: "b", count: 64)
    private let payloadDigest = "180cfc3bcd8ac21e73becfc0ce45618853171b0a20d4db52fac65c6cdd262ddc"
    private var contractTransactionPayload: Data {
        try! CanonicalUnsignedTransactionTestSupport.contractPayload(
            request: detachedRequest(),
            contractAddress: contractAddress,
            codeHashHex: codeHash,
            networkId: TestNetworkIds.canonical
        )
    }
    private var txHash: String {
        CanonicalUnsignedTransactionTestSupport.transactionHash(
            for: contractTransactionPayload
        ).map { String(format: "%02x", $0) }.joined()
    }
    private var entrypointHash: String { txHash }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func makeClient(includeCanonicalAuth: Bool = true) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return ToriiClient(
            baseURL: URL(string: "https://contracts.example")!,
            session: URLSession(configuration: configuration),
            localSigningContext: ToriiLocalSigningContext(
                networkId: TestNetworkIds.canonical
            ),
            canonicalRequestAuth: includeCanonicalAuth ? canonicalReadAuth : nil,
            canonicalRequestFreshness: ToriiCanonicalRequestFreshness(
                timestampMs: { 4_102_444_801_000 },
                nonce: { "canonical-read-test" }
            ),
            currentTimeMilliseconds: { 4_102_444_801_000 }
        )
    }

    private var canonicalReadAuth: ToriiCanonicalRequestAuth {
        ToriiCanonicalRequestAuth(
            accountId: authority,
            privateKey: signingSeed
        )
    }

    private func requestBodyData(_ request: URLRequest) throws -> Data {
        let data: Data
        if let body = request.httpBody {
            data = body
        } else if let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var result = Data()
            var buffer = [UInt8](repeating: 0, count: 4_096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                guard count > 0 else { break }
                result.append(buffer, count: count)
            }
            data = result
        } else {
            throw NSError(domain: "ToriiContractAPITests", code: 1)
        }
        return data
    }

    private func jsonBody(_ request: URLRequest) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: requestBodyData(request)) as? [String: Any])
    }

    private func response(
        for request: URLRequest,
        status: Int = 200,
        contentType: String = "application/json",
        json: Any
    ) throws -> (HTTPURLResponse, Data?) {
        let response = try XCTUnwrap(HTTPURLResponse(
            url: try XCTUnwrap(request.url),
            statusCode: status,
            httpVersion: nil,
            headerFields: ["Content-Type": contentType]
        ))
        return (response, try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]))
    }

    private func contractCallResponse(
        submitted: Bool,
        mutate: (inout [String: Any]) -> Void = { _ in }
    ) -> [String: Any] {
        var receipt: [String: Any] = [
            "operation_kind": "contract_call",
            "status": submitted ? "submitted" : "pending_signature",
            "transport": "torii",
            "dataspace": "hbl.sbp",
            "contract_alias": contractAlias,
            "contract_address": contractAddress,
            "code_hash_hex": codeHash,
            "abi_hash_hex": abiHash,
            "entrypoint": "spend_to_merchant",
            "gas_limit": 500_000,
            "fee_payment": testFeePaymentObject(testFeePayment(gasLimit: 500_000)),
            "payload_digest_hex": payloadDigest,
            "gas_used": NSNull(),
            "tx_hash_hex": NSNull(),
            "entrypoint_hash_hex": NSNull(),
        ]
        if submitted {
            receipt["tx_hash_hex"] = txHash
            receipt["entrypoint_hash_hex"] = entrypointHash
        }
        var value: [String: Any] = [
            "ok": true,
            "submitted": submitted,
            "dataspace": "hbl.sbp",
            "contract_address": contractAddress,
            "code_hash_hex": codeHash,
            "abi_hash_hex": abiHash,
            "creation_time_ms": detachedCreationTimeMs,
            "transaction_ttl_ms": 120_000,
            "entrypoint": "spend_to_merchant",
            "operation_receipt": receipt,
            "pipeline_status": NSNull(),
            "tx_hash_hex": NSNull(),
            "entrypoint_hash_hex": NSNull(),
            "transaction_payload_b64": NSNull(),
            "signing_message_b64": NSNull(),
        ]
        if submitted {
            value["tx_hash_hex"] = txHash
            value["entrypoint_hash_hex"] = entrypointHash
        } else {
            value["transaction_payload_b64"] = contractTransactionPayload.base64EncodedString()
            value["signing_message_b64"] = IrohaHash.hash(contractTransactionPayload).base64EncodedString()
        }
        mutate(&value)
        return value
    }

    private func detachedRequest() -> ToriiContractCallRequest {
        let payload = ToriiJSONValue.object([
            "merchant_account_id": .string(merchantAccount),
            "amount": .string("750"),
        ])
        let argumentRecord = try! CanonicalUnsignedTransactionTestSupport
            .contractArgumentRecord(for: payload)
        let invocation = try! TransactionContractInvocation(
            contractAddress: contractAddress,
            expectedCodeHash: Data(hexString: codeHash)!,
            entrypoint: "spend_to_merchant",
            arguments: argumentRecord
        )
        let callerMetadata = ["client_reference": ToriiJSONValue.string("invoice-7")]
        var exactMetadata = callerMetadata
        exactMetadata["contract_address"] = .string(contractAddress)
        exactMetadata["contract_code_hash"] = .string(codeHash)
        exactMetadata["contract_alias"] = .string(contractAlias)
        exactMetadata["contract_entrypoint"] = .string("spend_to_merchant")
        exactMetadata["contract_payload"] = payload
        return ToriiContractCallRequest(
            authority: authority,
            contractAlias: contractAlias,
            entrypoint: "spend_to_merchant",
            payload: payload,
            metadata: callerMetadata,
            draftIntent: try! ToriiContractCallDraftIntent(
                invocation: invocation,
                metadata: exactMetadata
            ),
            creationTimeMs: detachedCreationTimeMs,
            transactionTtlMs: 120_000,
            feePayment: testFeePayment(gasLimit: 500_000)
        )
    }

    func testResolveContractAliasUsesCanonicalRouteAndBindsResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/aliases/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(try self.jsonBody(request)["contract_alias"] as? String, self.contractAlias)
            return try self.response(for: request, json: [
                "contract_alias": self.contractAlias,
                "contract_address": self.contractAddress,
                "dataspace": "hbl.sbp",
                "contract_alias_binding": [
                    "alias": self.contractAlias,
                    "status": "permanent",
                    "bound_at_ms": 123,
                ],
                "source": "world_state",
            ])
        }

        let result = try await makeClient().resolveContractAlias(contractAlias, canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(result.contractAddress, contractAddress)
        XCTAssertEqual(result.binding?.status, .permanent)
    }

    func testResolveContractAliasRejectsUnboundDuplicateAndUnknownResponses() async {
        let payloads = [
            "{\"contract_alias\":\"other::hbl.sbp\",\"contract_address\":\"\(contractAddress)\",\"dataspace\":\"hbl.sbp\"}",
            "{\"contract_alias\":\"\(contractAlias)\",\"contract_alias\":\"\(contractAlias)\",\"contract_address\":\"\(contractAddress)\",\"dataspace\":\"hbl.sbp\"}",
            "{\"contract_alias\":\"\(contractAlias)\",\"contract_address\":\"\(contractAddress)\",\"dataspace\":\"hbl.sbp\",\"legacy\":true}",
        ]
        for payload in payloads {
            StubURLProtocol.handler = { request in
                let http = HTTPURLResponse(
                    url: request.url!, statusCode: 200, httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (http, Data(payload.utf8))
            }
            do {
                _ = try await makeClient().resolveContractAlias(contractAlias, canonicalAuth: canonicalReadAuth)
                XCTFail("adversarial alias response was accepted: \(payload)")
            } catch {}
        }
    }

    func testContractStatePathQueryIsStrictlyBound() async throws {
        let query = try ToriiContractStateQuery(
            target: .alias(contractAlias),
            selector: .path("TrancheCount"),
            decodeJSON: true
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/state")
            let items = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems
            XCTAssertEqual(items?.first(where: { $0.name == "contract_alias" })?.value, self.contractAlias)
            XCTAssertEqual(items?.first(where: { $0.name == "path" })?.value, "TrancheCount")
            XCTAssertEqual(items?.first(where: { $0.name == "decode" })?.value, "json")
            return try self.response(for: request, json: [
                "contract_address": self.contractAddress,
                "contract_alias": self.contractAlias,
                "path": "TrancheCount",
                "entries": [[
                    "path": "TrancheCount",
                    "found": true,
                    "value_b64": Data([0, 0, 0, 2]).base64EncodedString(),
                    "value_len": 4,
                    "value_json": "2",
                ]],
                "offset": 0,
                "limit": 1,
            ])
        }

        let page = try await makeClient().queryContractState(query)
        XCTAssertEqual(page.entries.first?.valueJSON, .string("2"))
        XCTAssertFalse(page.hasMore)
    }

    func testContractStateQueryRejectsAmbiguousAndNonCanonicalSelectors() throws {
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .paths([])
        ))
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .paths(["Tranches/a", "Tranches/a"])
        ))
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .path("Tranches,a")
        ))
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .path(" TrancheCount")
        ))
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .path("TrancheCount"), offset: 1
        ))
        XCTAssertThrowsError(try ToriiContractStateQuery(
            target: .alias(contractAlias), selector: .prefix("Tranches"), limit: 10_001
        ))
    }

    func testContractStateModelsRejectLegacyDecodeErrorsAndCorruptValues() throws {
        let base: [String: Any] = [
            "contract_address": contractAddress,
            "contract_alias": contractAlias,
            "path": "TrancheCount",
            "entries": [[
                "path": "TrancheCount", "found": true,
                "value_b64": "AQ==", "value_len": 1,
            ]],
            "offset": 0,
            "limit": 1,
        ]
        var legacy = base
        legacy["entries"] = [[
            "path": "TrancheCount", "found": true,
            "decode_error": "legacy entry error",
        ]]
        var badLength = base
        badLength["entries"] = [[
            "path": "TrancheCount", "found": true,
            "value_b64": "AQ==", "value_len": 2,
        ]]
        var missingWithValue = base
        missingWithValue["entries"] = [[
            "path": "TrancheCount", "found": false,
            "value_json": "2",
        ]]
        for object in [legacy, badLength, missingWithValue] {
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiContractStateResponse.self, from: data)
            )
        }
    }

    func testContractCallRequiresBoundCanonicalAuthBeforeNetworkRequest() async throws {
        var calls = 0
        StubURLProtocol.handler = { request in
            calls += 1
            return try self.response(for: request, json: self.contractCallResponse(submitted: false))
        }
        let unsignedClient = makeClient(includeCanonicalAuth: false)
        do {
            _ = try await unsignedClient.callContract(detachedRequest())
            XCTFail("missing canonical auth was accepted")
        } catch {}
        let otherKey = try Keypair(privateKeyBytes: Data(repeating: 0x42, count: 32))
        let otherAuth = ToriiCanonicalRequestAuth(
            accountId: try otherKey.accountId(networkPrefix: AccountId.defaultNetworkPrefix),
            privateKey: Data(repeating: 0x42, count: 32)
        )
        do {
            _ = try await makeClient().callContract(detachedRequest(), canonicalAuth: otherAuth)
            XCTFail("foreign canonical authority was accepted")
        } catch {}
        XCTAssertEqual(calls, 0)
        _ = try await unsignedClient.prepareDetachedContractCall(detachedRequest(), canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(calls, 1)
    }

    func testContractCallRequiresCompleteRetainedPayloadEnvelope() throws {
        let encoder = JSONEncoder()
        for bits in 1..<7 {
            var request = detachedRequest()
            if bits & 1 != 0 { request.publicKeyHex = signingPublicKeyHex }
            if bits & 2 != 0 { request.signatureB64 = try detachedSignatureB64() }
            if bits & 4 != 0 { request.transactionPayloadB64 = contractTransactionPayload.base64EncodedString() }
            XCTAssertThrowsError(try encoder.encode(request), "partial detached envelope \(bits)")
        }
        var request = detachedRequest()
        request.publicKeyHex = signingPublicKeyHex
        request.signatureB64 = try detachedSignatureB64()
        request.transactionPayloadB64 = contractTransactionPayload.base64EncodedString()
        XCTAssertNoThrow(try encoder.encode(request))
        request.creationTimeMs = nil
        XCTAssertThrowsError(try encoder.encode(request))
        request.creationTimeMs = detachedCreationTimeMs
        request.transactionPayloadB64! += "\n"
        XCTAssertThrowsError(try encoder.encode(request))
    }

    func testPrepareAndSubmitDetachedContractCallPreservesEveryBinding() async throws {
        var requestIndex = 0
        let detachedSignature = try detachedSignatureB64()
        StubURLProtocol.handler = { request in
            requestIndex += 1
            XCTAssertEqual(request.url?.path, "/v1/contracts/call")
            let bodyData = try self.requestBodyData(request)
            let body = try XCTUnwrap(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
            let expectedHeaders = try ToriiCanonicalRequest.buildHeaders(
                method: "POST",
                url: try XCTUnwrap(request.url),
                body: bodyData,
                accountId: self.authority,
                privateKey: self.signingSeed,
                networkId: TestNetworkIds.canonical,
                timestampMs: 4_102_444_801_000,
                nonce: "canonical-read-test"
            )
            for (name, value) in expectedHeaders
                where name != ToriiCanonicalRequest.headerSignature {
                XCTAssertEqual(request.value(forHTTPHeaderField: name), value)
            }
            let encodedSignature = try XCTUnwrap(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let signature = try XCTUnwrap(Data(base64Encoded: encodedSignature))
            XCTAssertEqual(signature.base64EncodedString(), encodedSignature)
            let signedMessage = try ToriiCanonicalRequest.signatureMessage(
                networkId: TestNetworkIds.canonical,
                method: "POST",
                url: try XCTUnwrap(request.url),
                body: bodyData,
                timestampMs: 4_102_444_801_000,
                nonce: "canonical-read-test"
            )
            let signer = try Curve25519.Signing.PrivateKey(rawRepresentation: self.signingSeed)
            XCTAssertTrue(signer.publicKey.isValidSignature(signature, for: signedMessage))
            XCTAssertNil(body["private_key"])
            XCTAssertNil(body["draft_intent"])
            XCTAssertEqual(
                body["metadata"] as? NSDictionary,
                ["client_reference": "invoice-7"] as NSDictionary
            )
            XCTAssertEqual(body["transaction_ttl_ms"] as? Int, 120_000)
            if requestIndex == 1 {
                XCTAssertNil(body["public_key_hex"])
                XCTAssertNil(body["signature_b64"])
                XCTAssertNil(body["transaction_payload_b64"])
                return try self.response(
                    for: request,
                    json: self.contractCallResponse(submitted: false)
                )
            }
            XCTAssertEqual(
                body["creation_time_ms"] as? NSNumber,
                self.detachedCreationTimeMs as NSNumber
            )
            XCTAssertEqual(body["public_key_hex"] as? String, self.signingPublicKeyHex)
            XCTAssertEqual(body["signature_b64"] as? String, detachedSignature)
            XCTAssertEqual(body["transaction_payload_b64"] as? String, self.contractTransactionPayload.base64EncodedString())
            return try self.response(
                for: request,
                json: self.contractCallResponse(submitted: true)
            )
        }

        let client = makeClient()
        let draft = try await client.prepareDetachedContractCall(detachedRequest())
        XCTAssertEqual(draft.transactionPayload, contractTransactionPayload)
        XCTAssertEqual(draft.signingMessage, IrohaHash.hash(contractTransactionPayload))
        XCTAssertEqual(draft.networkId, TestNetworkIds.canonical)
        XCTAssertEqual(draft.resolvedContractAddress, contractAddress)
        let submitted = try await client.submitDetachedContractCall(
            draft,
            publicKeyHex: signingPublicKeyHex,
            signatureB64: detachedSignature
        )
        XCTAssertEqual(submitted.transactionHashHex, txHash)
        XCTAssertEqual(requestIndex, 2)
    }

    func testDetachedPreparationAcceptsOnlyToriiEnrichedFeeMaxima() async throws {
        let enrichedFee = FeePaymentIntent.authority(
            chargeLimits: [
                try FeeChargeLimit(
                    kind: .pipelineGas,
                    assetDefinitionId: assetId,
                    maxAmount: "10"
                )
            ],
            gasLimit: 500_000
        )
        let enrichedPayload = try CanonicalUnsignedTransactionTestSupport.contractPayload(
            request: detachedRequest(),
            contractAddress: contractAddress,
            codeHashHex: codeHash,
            networkId: TestNetworkIds.canonical,
            feePayment: enrichedFee
        )
        var calls = 0
        let expectedHash = CanonicalUnsignedTransactionTestSupport.transactionHash(for: enrichedPayload)
            .map { String(format: "%02x", $0) }.joined()
        StubURLProtocol.handler = { request in
            calls += 1
            let submitted = calls == 2
            let body = try self.jsonBody(request)
            if submitted {
                XCTAssertEqual(body["transaction_payload_b64"] as? String, enrichedPayload.base64EncodedString())
                XCTAssertEqual(body["fee_payment"] as? NSDictionary, testFeePaymentObject(enrichedFee) as NSDictionary)
                XCTAssertEqual(body["creation_time_ms"] as? NSNumber, self.detachedCreationTimeMs as NSNumber)
                XCTAssertEqual(body["transaction_ttl_ms"] as? Int, 120_000)
                XCTAssertEqual(body["contract_alias"] as? String, self.contractAlias)
            }
            var json = self.contractCallResponse(submitted: submitted)
            var receipt = json["operation_receipt"] as! [String: Any]
            receipt["fee_payment"] = testFeePaymentObject(enrichedFee)
            if submitted {
                receipt["tx_hash_hex"] = expectedHash
                receipt["entrypoint_hash_hex"] = expectedHash
                json["tx_hash_hex"] = expectedHash
                json["entrypoint_hash_hex"] = expectedHash
                XCTAssertTrue(json["pipeline_status"] is NSNull)
            } else {
                json["transaction_payload_b64"] = enrichedPayload.base64EncodedString()
                json["signing_message_b64"] = IrohaHash.hash(enrichedPayload).base64EncodedString()
            }
            json["operation_receipt"] = receipt
            return try self.response(for: request, json: json)
        }

        let client = makeClient()
        let draft = try await client.prepareDetachedContractCall(detachedRequest())
        XCTAssertEqual(draft.transactionPayload, enrichedPayload)
        XCTAssertEqual(draft.request.feePayment, enrichedFee)
        let submitted = try await client.submitDetachedContractCall(
            draft,
            publicKeyHex: signingPublicKeyHex,
            signatureB64: try signingKeypair.sign(draft.signingMessage).base64EncodedString()
        )
        XCTAssertEqual(submitted.transactionHashHex, expectedHash)
        XCTAssertEqual(calls, 2)
    }

    /// Torii binds only the consensus-checked call keys into contract-call
    /// metadata; the contract-events feed derives kind, payload and
    /// provenance from the call itself. A draft intent that also claims
    /// `contract_module`/`contract_event_*` entries (such as a self-asserted
    /// `"emitted"` provenance) therefore never matches Torii's prepared bytes.
    func testDetachedPreparationRejectsDraftIntentClaimingEventMetadata() async throws {
        var request = detachedRequest()
        let eventClaims: [String: ToriiJSONValue] = [
            "contract_module": .string("intents"),
            "contract_event_kind": .string("intent_opened"),
            "contract_event_schema_version": .number(1),
            "contract_event_provenance": .string("emitted"),
        ]
        var claimedMetadata = try XCTUnwrap(request.draftIntent).metadata
        claimedMetadata.merge(eventClaims) { _, claimed in claimed }
        request.draftIntent = try ToriiContractCallDraftIntent(
            invocation: try XCTUnwrap(request.draftIntent).invocation,
            metadata: claimedMetadata
        )
        let toriiPayload = try CanonicalUnsignedTransactionTestSupport.contractPayload(
            request: request,
            contractAddress: contractAddress,
            codeHashHex: codeHash,
            networkId: TestNetworkIds.canonical
        )
        StubURLProtocol.handler = { urlRequest in
            var json = self.contractCallResponse(submitted: false)
            json["transaction_payload_b64"] = toriiPayload.base64EncodedString()
            json["signing_message_b64"] = IrohaHash.hash(toriiPayload).base64EncodedString()
            return try self.response(for: urlRequest, json: json)
        }

        do {
            _ = try await makeClient().prepareDetachedContractCall(request)
            XCTFail("a draft intent claiming event metadata matched Torii's prepared bytes")
        } catch let ToriiClientError.invalidPayload(message) {
            XCTAssertTrue(message.contains("canonical transaction payload"), message)
        }
    }

    func testDetachedContractCallPayloadDigestMatchesToriiCanonicalJSON() throws {
        XCTAssertEqual(
            try detachedRequest().canonicalContractPayloadDigestHex(),
            payloadDigest
        )
    }

    func testDetachedPreparationRejectsUnboundedOrMissingGasLimitBeforeNetwork() async {
        var calls = 0
        StubURLProtocol.handler = { request in
            calls += 1
            return try self.response(
                for: request,
                json: self.contractCallResponse(submitted: false)
            )
        }
        let mutations: [(inout ToriiContractCallRequest) -> Void] = [
            { $0.transactionTtlMs = nil },
            { $0.transactionTtlMs = ToriiContractCallRequest.maximumDetachedTransactionTtlMs + 1 },
            { $0.creationTimeMs = nil },
            { $0.creationTimeMs = 1 },
            { $0.creationTimeMs = UInt64.max },
            { $0.feePayment = testFeePayment() },
            { $0.draftIntent = nil },
            { $0.transactionPayloadB64 = "AQ==" },
        ]
        for mutation in mutations {
            var request = detachedRequest()
            mutation(&request)
            do {
                _ = try await makeClient().prepareDetachedContractCall(request)
                XCTFail("unbounded detached request was accepted")
            } catch {}
        }
        XCTAssertEqual(calls, 0)
    }

    func testDetachedContractCallFinalityRequiresGlobalStateAppliedStatus() async throws {
        var requestIndex = 0
        StubURLProtocol.handler = { request in
            requestIndex += 1
            switch requestIndex {
            case 1:
                return try self.response(
                    for: request,
                    json: self.contractCallResponse(submitted: false)
                )
            case 2:
                return try self.response(
                    for: request,
                    json: self.contractCallResponse(submitted: true)
                )
            default:
                XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
                let items = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems
                XCTAssertEqual(items?.first(where: { $0.name == "hash" })?.value, self.txHash)
                XCTAssertEqual(items?.first(where: { $0.name == "scope" })?.value, "global")
                return try self.response(for: request, json: [
                    "hash": self.txHash,
                    "status": ["kind": "Applied", "block_height": 44],
                    "scope": "global",
                    "resolved_from": "state",
                ])
            }
        }

        let client = makeClient()
        let draft = try await client.prepareDetachedContractCall(detachedRequest())
        let submitted = try await client.submitDetachedContractCall(
            draft,
            publicKeyHex: signingPublicKeyHex,
            signatureB64: try detachedSignatureB64()
        )
        let finality = try await client.waitForDetachedContractCallFinality(
            draft,
            submission: submitted,
            pollOptions: PipelineStatusPollOptions(
                pollInterval: 0,
                timeout: 1,
                maxAttempts: 1
            )
        )
        XCTAssertEqual(finality.state, .applied)
        XCTAssertEqual(finality.status.blockHeight, 44)
        XCTAssertEqual(requestIndex, 3)
    }

    func testDetachedPreparationRejectsAdversarialDraftResponses() async {
        let mutations: [(inout [String: Any]) -> Void] = [
            { $0["submitted"] = true },
            { $0["signing_message_b64"] = Data(repeating: 1, count: 31).base64EncodedString() },
            { $0["signed_transaction_b64"] = Data([9]).base64EncodedString() },
            { $0["code_hash_hex"] = "0x" + self.codeHash },
            { $0["abi_hash_hex"] = self.abiHash.uppercased() },
            { $0["transaction_ttl_ms"] = 0 },
            {
                let payload = try! CanonicalUnsignedTransactionTestSupport.contractPayload(
                    request: self.detachedRequest(),
                    contractAddress: self.contractAddress,
                    codeHashHex: self.codeHash,
                    networkId: TestNetworkIds.other
                )
                $0["transaction_payload_b64"] = payload.base64EncodedString()
                $0["signing_message_b64"] = IrohaHash.hash(payload).base64EncodedString()
            },
            {
                let payload = try! CanonicalUnsignedTransactionTestSupport.contractPayload(
                    request: self.detachedRequest(),
                    contractAddress: self.contractAddress,
                    codeHashHex: self.codeHash,
                    networkId: TestNetworkIds.canonical,
                    retiredAdmissionTag: 0
                )
                $0["transaction_payload_b64"] = payload.base64EncodedString()
                $0["signing_message_b64"] = IrohaHash.hash(payload).base64EncodedString()
            },
            {
                var tamperedRequest = self.detachedRequest()
                let originalIntent = tamperedRequest.draftIntent!
                let invocation = try! TransactionContractInvocation(
                    contractAddress: originalIntent.invocation.contractAddress,
                    expectedCodeHash: originalIntent.invocation.expectedCodeHash,
                    entrypoint: originalIntent.invocation.entrypoint,
                    arguments: Data("different arguments".utf8)
                )
                tamperedRequest.draftIntent = try! ToriiContractCallDraftIntent(
                    invocation: invocation,
                    metadata: originalIntent.metadata
                )
                let payload = try! CanonicalUnsignedTransactionTestSupport.contractPayload(
                    request: tamperedRequest,
                    contractAddress: self.contractAddress,
                    codeHashHex: self.codeHash,
                    networkId: TestNetworkIds.canonical
                )
                $0["transaction_payload_b64"] = payload.base64EncodedString()
                $0["signing_message_b64"] = IrohaHash.hash(payload).base64EncodedString()
            },
            {
                let payload = try! CanonicalUnsignedTransactionTestSupport.contractPayload(
                    request: self.detachedRequest(),
                    contractAddress: self.contractAddress,
                    codeHashHex: self.codeHash,
                    networkId: TestNetworkIds.canonical,
                    additionalMetadata: ["server_added_intent": .bool(true)]
                )
                $0["transaction_payload_b64"] = payload.base64EncodedString()
                $0["signing_message_b64"] = IrohaHash.hash(payload).base64EncodedString()
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["transport"] = "legacy"
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["payload_digest_hex"] = " " + self.payloadDigest
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["payload_digest_hex"] = String(repeating: "0", count: 64)
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["payload_digest_hex"] = String(repeating: "f", count: 64)
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["fee_payment"] = testFeePaymentObject(testFeePayment(gasLimit: 500_001))
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["unexpected_fee_field"] = "legacy"
                $0["operation_receipt"] = receipt
            },
        ]
        for mutation in mutations {
            StubURLProtocol.handler = { request in
                try self.response(
                    for: request,
                    json: self.contractCallResponse(submitted: false, mutate: mutation)
                )
            }
            do {
                _ = try await makeClient().prepareDetachedContractCall(detachedRequest())
                XCTFail("adversarial detached draft was accepted")
            } catch {}
        }
    }

    func testDetachedPreparationRejectsRetiredAdmissionBeforeSigning() async throws {
        let payload = try CanonicalUnsignedTransactionTestSupport.contractPayload(
            request: detachedRequest(),
            contractAddress: contractAddress,
            codeHashHex: codeHash,
            networkId: TestNetworkIds.canonical,
            retiredAdmissionTag: 1
        )
        let signingMessage = IrohaHash.hash(payload)
        XCTAssertThrowsError(try ToriiCanonicalTransactionDraft.decode(
            transactionPayloadB64: payload.base64EncodedString(),
            signingMessageB64: signingMessage.base64EncodedString(),
            context: "retired admission fixture"
        ))
        var requests = 0
        StubURLProtocol.handler = { request in
            requests += 1
            var json = self.contractCallResponse(submitted: false)
            json["transaction_payload_b64"] = payload.base64EncodedString()
            json["signing_message_b64"] = signingMessage.base64EncodedString()
            return try self.response(for: request, json: json)
        }
        do {
            _ = try await makeClient().prepareDetachedContractCall(detachedRequest())
            XCTFail("retired contract draft was accepted")
        } catch {
            XCTAssertFalse(String(describing: error).isEmpty)
        }
        XCTAssertEqual(requests, 1)
    }

    func testDetachedSubmitRejectsInvalidSignatureWithoutNetworkRequest() async throws {
        var calls = 0
        StubURLProtocol.handler = { request in
            calls += 1
            return try self.response(
                for: request,
                json: self.contractCallResponse(submitted: false)
            )
        }
        let client = makeClient()
        let draft = try await client.prepareDetachedContractCall(detachedRequest())
        let invalidInputs = [
            (String(repeating: "A", count: 64), Data(repeating: 1, count: 64).base64EncodedString()),
            (String(repeating: "0", count: 64), Data(repeating: 1, count: 64).base64EncodedString()),
            (signingPublicKeyHex, "AQ=="),
            (signingPublicKeyHex, Data(repeating: 1, count: 64).base64EncodedString()),
            (String(repeating: "1", count: 64), Data(repeating: 0, count: 64).base64EncodedString()),
            (String(repeating: "1", count: 64), Data(repeating: 1, count: 64).base64EncodedString() + "\n"),
        ]
        for input in invalidInputs {
            do {
                _ = try await client.submitDetachedContractCall(
                    draft,
                    publicKeyHex: input.0,
                    signatureB64: input.1
                )
                XCTFail("invalid detached signature input was accepted")
            } catch {}
        }
        XCTAssertEqual(calls, 1)
    }

    func testDetachedSubmitRejectsTamperedReceiptAndPipelineBindings() async throws {
        let mutations: [(inout [String: Any]) -> Void] = [
            {
                $0["pipeline_status"] = [
                    "hash": self.txHash, "status": ["kind": "Queued"],
                    "scope": "local", "resolved_from": "queue",
                ]
            },
            {
                $0["pipeline_status"] = [
                    "hash": self.txHash, "status": ["kind": "Committed", "block_height": 12],
                    "scope": "global", "resolved_from": "state",
                ]
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["payload_digest_hex"] = String(repeating: "f", count: 64)
                $0["operation_receipt"] = receipt
            },
            {
                var receipt = $0["operation_receipt"] as! [String: Any]
                receipt["gas_used"] = 1
                $0["operation_receipt"] = receipt
            },
            { $0["signing_message_b64"] = Data(repeating: 1, count: 32).base64EncodedString() },
            { $0["entrypoint_hash_hex"] = String(repeating: "f", count: 64) },
        ]
        for mutation in mutations {
            var call = 0
            StubURLProtocol.handler = { request in
                call += 1
                let json = call == 1
                    ? self.contractCallResponse(submitted: false)
                    : self.contractCallResponse(submitted: true, mutate: mutation)
                return try self.response(for: request, json: json)
            }
            let client = makeClient()
            let draft = try await client.prepareDetachedContractCall(detachedRequest())
            do {
                _ = try await client.submitDetachedContractCall(
                    draft,
                    publicKeyHex: signingPublicKeyHex,
                    signatureB64: try detachedSignatureB64()
                )
                XCTFail("tampered detached submit response was accepted")
            } catch {}
        }
    }
}
