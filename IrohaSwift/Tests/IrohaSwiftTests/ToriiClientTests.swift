import XCTest
import CryptoKit
import Foundation
#if canImport(Combine)
import Combine
#endif
@testable import IrohaSwift

func testFeePayment(gasLimit: UInt64? = nil) -> FeePaymentIntent {
    .authority(chargeLimits: [], gasLimit: gasLimit)
}

func testFeePaymentObject(_ intent: FeePaymentIntent) -> [String: Any] {
    let data = try! intent.canonicalJSONData()
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
}

/// Deterministic stand-in for the exact Norito body encoder supplied by an app.
/// Receipt-verifier tests separately pin the protocol domain and hash marker.
func encodeTestCanonicalOnboardingBody(
    _ body: ToriiAccountOnboardingPlanBody
) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(body)
}


final class StubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data?))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "Stub", code: -1))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if let data { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private func canonicalVerifierRecordArchive(
    seed: UInt8,
    verifierKeyLength: Int = 96
) throws -> Data {
    guard verifierKeyLength > 0 else {
        throw NSError(
            domain: "ToriiClientTests",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: "verifierKeyLength must be positive"]
        )
    }
    return noritoEncode(
        typeName: "iroha_data_model::proof::VerifyingKeyRecord",
        payload: Data(repeating: seed, count: verifierKeyLength),
        flags: NoritoHeader.compactLen
    )
}

final class StubGatewayFetcher: SorafsGatewayFetching, @unchecked Sendable {
    var capturedPlan: ToriiJSONValue?
    var capturedProviders: [SorafsGatewayProvider]?
    var capturedOptions: SorafsGatewayFetchOptions?
    var fetchCount = 0
    var result: SorafsGatewayFetchResult

    init(result: SorafsGatewayFetchResult) {
        self.result = result
    }

    func fetchGatewayPayload(
        plan: ToriiJSONValue,
        providers: [SorafsGatewayProvider],
        options: SorafsGatewayFetchOptions?,
        cancellationHandler: (() -> Void)?
    ) async throws -> SorafsGatewayFetchResult {
        fetchCount += 1
        capturedPlan = plan
        capturedProviders = providers
        capturedOptions = options
        return result
    }
}

private struct StubProofSummaryGenerator: DaProofSummaryGenerating, @unchecked Sendable {
    let summary: ToriiDaProofSummary

    func makeProofSummary(manifest: Data,
                          payload: Data,
                          options: ToriiDaProofSummaryOptions) throws -> ToriiDaProofSummary {
        summary
    }
}

private enum DaTestFixtures {
    static let manifestBytes = Data("swift-da-manifest".utf8)
    static let manifestHandle = "chunking.demo@1.0.0"
    static let storageTicketHex = String(repeating: "AB", count: 32)
    static let clientBlobHex = String(repeating: "CD", count: 32)
    static let blobHashHex = String(repeating: "EF", count: 32)
    static let chunkRootHex = String(repeating: "12", count: 32)
    static let manifestHashHex = String(repeating: "34", count: 32)

    private static let manifestDictionary: [String: Any] = [
        "chunker_handle": manifestHandle,
        "metadata": ["note": "swift-da-fixture"]
    ]

    private static let chunkPlanDictionary: [String: Any] = [
        "schema": "sorafs.chunk_fetch_plan.v1",
        "payload_digest_blake3_hex": String(repeating: "ef", count: 32),
        "chunk_fetch_specs": [[
            "chunk_index": 0,
            "offset": 0,
            "length": 4,
            "digest_blake3": String(repeating: "22", count: 32)
        ]]
    ]

    static var storageTicketInput: String { "0x\(storageTicketHex.uppercased())" }

    static func manifestJSONValue() throws -> ToriiJSONValue {
        try jsonValue(from: manifestDictionary)
    }

    static func chunkPlanJSONValue() throws -> ToriiJSONValue {
        try jsonValue(from: chunkPlanDictionary)
    }

    static func responseBody() throws -> Data {
        let payload: [String: Any] = [
            "storage_ticket": storageTicketInput,
            "client_blob_id": "0x\(clientBlobHex.uppercased())",
            "blob_hash": "0x\(blobHashHex)",
            "manifest_hash": "0x\(manifestHashHex)",
            "chunk_root": "0x\(chunkRootHex)",
            "lane_id": 2,
            "epoch": 7,
            "manifest_len": manifestBytes.count,
            "manifest_norito": manifestBytes.base64EncodedString(),
            "manifest": manifestDictionary,
            "chunk_plan": chunkPlanDictionary
        ]
        return try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }

    static func manifestBundle() throws -> ToriiDaManifestBundle {
        try JSONDecoder().decode(ToriiDaManifestBundle.self, from: responseBody())
    }

    private static func jsonValue(from dictionary: [String: Any]) throws -> ToriiJSONValue {
        let data = try JSONSerialization.data(withJSONObject: dictionary, options: [.sortedKeys])
        return try JSONDecoder().decode(ToriiJSONValue.self, from: data)
    }
}

// Shared test helpers to keep Torii client DA fixtures deterministic across suites.
func tcMakeClient() -> ToriiClient {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [StubURLProtocol.self]
    let session = URLSession(configuration: configuration)
    let seed = Data(repeating: 0x41, count: 32)
    let auth = ToriiCanonicalRequestAuth(
        accountId: try! Keypair(privateKeyBytes: seed)
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix),
        privateKey: seed
    )
    return ToriiClient(
        baseURL: URL(string: "https://example.test")!,
        session: session,
        canonicalRequestAuth: auth
    )
}

func tcBodyJSON(from request: URLRequest) -> [String: Any] {
    var data: Data?
    if let direct = request.httpBody {
        data = direct
    } else if let stream = request.httpBodyStream {
        stream.open()
        defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 1024)
        var collected = Data()
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            collected.append(buffer, count: read)
        }
        data = collected.isEmpty ? nil : collected
    }
    guard
        let raw = data,
        let object = try? JSONSerialization.jsonObject(with: raw),
        let dictionary = object as? [String: Any]
    else { return [:] }
    return dictionary
}

final class ToriiClientTests: XCTestCase {
    func testOrdinaryEnumsAndEventsBindExactNominalSchemas() throws {
        let text = #"{"permissions":[],"enum_types":[{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}],"events":[{"name":"Changed","payload_type":{"nodes":[{"kind":"Struct","value":{"name":"Demo::Changed","fields":["status"]}},{"kind":"Enum","value":{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}}]}}],"states":[{"name":"status","type_name":"Demo::Status"}]}"#
        let parsed = try JSONDecoder().decode(ToriiContractManifest.self, from: Data(text.utf8))
        XCTAssertEqual(parsed.enumTypes.first?.variants.last?.code, 7)
        guard case .enumType(let descriptor) = parsed.events[0].payloadType.nodes[1] else { return XCTFail("distinct Enum node expected") }
        XCTAssertEqual(descriptor, parsed.enumTypes[0])
        let encoded = try JSONEncoder().encode(parsed)
        XCTAssertEqual(try JSONDecoder().decode(ToriiContractManifest.self, from: encoded), parsed)
        let invalid = [
            text.replacingOccurrences(of: #""enum_types":"#, with: #""retired_enum_types":"#),
            text.replacingOccurrences(of: #""events":"#, with: #""retired_events":"#),
            text.replacingOccurrences(of: #""code":1"#, with: #""code":0"#),
            text.replacingOccurrences(of: #""kind":"Enum""#, with: #""kind":"Error""#),
            text.replacingOccurrences(of: #""name":"Changed","payload_type""#, with: #""name":"Other","payload_type""#),
            text.replacingOccurrences(of: #""kind":"Enum","value":{"identity":"Demo::Status","variants":[{"name":"Pending","code":1},{"name":"Done","code":7}]}"#, with: #""kind":"Leaf","value":{"kind":"Json","value":null}"#),
        ]
        for value in invalid { XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractManifest.self, from: Data(value.utf8))) }
        var forged = parsed
        forged.enumTypes[0].variants[1].code = 8
        XCTAssertThrowsError(try JSONEncoder().encode(forged))
        forged = parsed
        forged.errorTypes = [ToriiContractErrorTypeDescriptor(identity: "Demo::Status", variants: [ToriiContractErrorVariantDescriptor(name: "Pending", code: 1)])]
        XCTAssertThrowsError(try JSONEncoder().encode(forged))
    }

    func testRamLfeEncryptionRefusalDoesNotImplyUncertainAssetTransferSubmission() {
        XCTAssertNil(ToriiClient.uncertainDetachedAssetTransferPostCause(
            ToriiClientError.ramLfeEncryptionUnavailable
        ))
    }

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
    private let encodedRoseAssetID = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
    private let roseAssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
    private let vpnRelayIdHex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    private let vpnRelayMldsa65PublicKeyHex = String(repeating: "ab", count: 1_952)

    private func validEd25519PublicKey(seed: UInt8) throws -> Data {
        try Keypair(privateKeyBytes: Data(repeating: seed, count: 32)).publicKey
    }

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

    private func canonicalReadAuth(accountId: String,
                                   privateKeyByte: UInt8) -> ToriiCanonicalRequestAuth {
        ToriiCanonicalRequestAuth(
            accountId: accountId,
            privateKey: Data(repeating: privateKeyByte, count: 32)
        )
    }

    private func noncanonicalStandardBase64PadBitAlias(_ encoded: String) -> String {
        toriiClientTestNoncanonicalBase64PadBitAlias(encoded)
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    /// Inspect shared collection JSON while preserving the individual selector assertions.
    private func explorerQueryValues(_ request: URLRequest) throws -> [String: String] {
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertNil(request.url?.query)
        let body = try JSONSerialization.jsonObject(with: XCTUnwrap(bodyData(from: request))) as! [String: Any]
        var values: [String: String] = [:]
        for key in ["limit", "cursor"] {
            if let value = body[key] { values[key] = String(describing: value) }
        }
        func equalityValues(_ node: Any) {
            guard let node = node as? [String: Any], let args = node["args"] as? [Any] else { return }
            if node["op"] as? String == "and" { args.forEach(equalityValues) }
            else if node["op"] as? String == "eq", args.count == 2, let field = args[0] as? String {
                values[field] = String(describing: args[1])
            }
        }
        if let filter = body["filter"] { equalityValues(filter) }
        return values
    }

    private func bodyData(from request: URLRequest) -> Data? {
        toriiClientTestBodyData(from: request)
    }

    private func bodyJSON(from request: URLRequest) -> [String: Any] {
        toriiClientTestBodyJSON(from: request)
    }

    private func assertDecodedPath(_ request: URLRequest, contains expected: String, line: UInt = #line) {
        XCTAssertTrue(
            request.url?.path.contains(expected) == true,
            "expected decoded path to contain \(expected), got \(request.url?.path ?? "<nil>")",
            line: line
        )
    }

    private func assertCanonicalEventRequest(
        _ request: URLRequest,
        queryItems: [URLQueryItem],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var expectedComponents = try XCTUnwrap(
            URLComponents(string: "https://example.test/v1/events/sse"),
            file: file,
            line: line
        )
        if !queryItems.isEmpty {
            expectedComponents.queryItems = queryItems
        }
        let expectedURL = try XCTUnwrap(expectedComponents.url, file: file, line: line)
        XCTAssertEqual(request.httpMethod, "GET", file: file, line: line)
        XCTAssertEqual(request.url, expectedURL, file: file, line: line)
        XCTAssertEqual(
            request.value(forHTTPHeaderField: "Accept"),
            "text/event-stream",
            file: file,
            line: line
        )

        try assertCanonicalReadAuth(
            request,
            url: expectedURL,
            context: "event",
            file: file,
            line: line
        )
    }

    private func assertCanonicalReadAuth(
        _ request: URLRequest,
        url: URL,
        context: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let expectedHeaders = try ToriiCanonicalRequest.buildHeaders(
            method: "GET",
            url: url,
            accountId: authority,
            privateKey: canonicalSigningSeed,
            networkId: TestNetworkIds.canonical,
            timestampMs: 4_102_444_801_000,
            nonce: "canonical-read-test"
        )
        for header in [
            ToriiCanonicalRequest.headerAccount,
            ToriiCanonicalRequest.headerTimestampMs,
            ToriiCanonicalRequest.headerNonce,
        ] {
            XCTAssertEqual(
                request.value(forHTTPHeaderField: header),
                expectedHeaders[header],
                "canonical header \(header) must bind the final \(context) URL",
                file: file,
                line: line
            )
        }
        let encodedSignature = try XCTUnwrap(
            request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature),
            file: file,
            line: line
        )
        let signature = try XCTUnwrap(Data(base64Encoded: encodedSignature), file: file, line: line)
        XCTAssertEqual(signature.base64EncodedString(), encodedSignature, file: file, line: line)
        let message = try ToriiCanonicalRequest.signatureMessage(
            networkId: TestNetworkIds.canonical,
            method: "GET",
            url: url,
            timestampMs: 4_102_444_801_000,
            nonce: "canonical-read-test"
        )
        let publicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: canonicalSigningSeed
        ).publicKey
        XCTAssertTrue(
            publicKey.isValidSignature(signature, for: message),
            "canonical signature must bind the final \(context) URL",
            file: file,
            line: line
        )
    }

    private func assertCanonicalDataspaceReadRequest(
        _ request: URLRequest,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let url = try XCTUnwrap(request.url, file: file, line: line)
        XCTAssertEqual(request.httpMethod, "GET", file: file, line: line)
        try assertCanonicalReadAuth(
            request,
            url: url,
            context: "account-read",
            file: file,
            line: line
        )
    }

    private func expectCanonicalEventRequest(queryItems: [URLQueryItem]) {
        StubURLProtocol.handler = { request in
            try self.assertCanonicalEventRequest(request, queryItems: queryItems)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, Data())
        }
    }

    private func irohaSwiftPackageRootURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ToriiClientTests.swift
            .deletingLastPathComponent() // IrohaSwiftTests
            .deletingLastPathComponent() // Tests
    }

    private func repositoryRootURL() -> URL {
        irohaSwiftPackageRootURL().deletingLastPathComponent()
    }

    /// Fixed canonical-request freshness so tests can recompute exact signatures.
    private static let canonicalReadFreshness = ToriiCanonicalRequestFreshness(
        timestampMs: { 4_102_444_801_000 },
        nonce: { "canonical-read-test" }
    )

    private func makeClient(
        baseURL: URL = URL(string: "https://example.test")!,
        defaultHeaders: [String: String] = [:],
        operatorSigningContext: ToriiOperatorSigningContext? = ToriiClientTests.operatorSigningContext,
        includeCanonicalReadAuth: Bool = true,
        canonicalRequestFreshness: ToriiCanonicalRequestFreshness = ToriiClientTests.canonicalReadFreshness
    ) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        return ToriiClient(
            baseURL: baseURL,
            session: session,
            defaultHeaders: defaultHeaders,
            localSigningContext: ToriiLocalSigningContext(networkId: TestNetworkIds.canonical),
            canonicalRequestAuth: includeCanonicalReadAuth ? canonicalReadAuth : nil,
            canonicalRequestFreshness: canonicalRequestFreshness,
            operatorSigningContext: operatorSigningContext
        )
    }

    private func canonicalSignedPipelineTransaction() throws -> Data {
        let signer = try SigningKey.ed25519(privateKey: canonicalSigningSeed)
        let payload = try CanonicalUnsignedTransactionTestSupport.genericPayload(
            authority: authority
        )
        let signature = try signer.sign(IrohaHash.hash(payload))
        return try ToriiCanonicalTransactionDraft.finalize(
            transactionPayload: payload,
            publicKey: signer.publicKey(),
            signature: signature
        ).signedTransaction
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

    private func canonicalUnsignedFeePayload(
        domain: ToriiJSONValue = .object([
            "kind": .string("network"),
            "value": .string(TestNetworkIds.canonical.literal),
        ])
    ) throws -> [String: ToriiJSONValue] {
        let feePayment = try JSONDecoder().decode(
            ToriiJSONValue.self,
            from: FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
                .canonicalJSONData()
        )
        return [
            "domain": domain,
            "authority": .string(authority),
            "creation_time_ms": .number(1),
            "instructions": .object([:]),
            "time_to_live_ms": .number(100_000),
            "fee_payment": feePayment,
            "metadata": .object([:]),
            "attachments": .null,
        ]
    }

    private func assertToriiInvalidPayload(
        contains expected: String,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("expected bounded Torii response failure")
        } catch ToriiClientError.invalidPayload(let message) {
            XCTAssertTrue(
                message.contains(expected),
                "expected \(expected), got \(message)"
            )
        } catch {
            XCTFail("unexpected bounded Torii response failure: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAuthenticationContextAddsWalletHeadersToEveryRequest() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: session,
            authentication: try ToriiClientAuthentication.bearerToken(
                " wallet-token ",
                accountId: " sora-account-1 ",
                dataspaceId: " mibank.paynet ",
                additionalHeaders: ["X-Trace-Id": "trace-123"]
            )
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/health")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer wallet-token")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Account-Id"), "sora-account-1")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Dataspace-Id"), "mibank.paynet")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Trace-Id"), "trace-123")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/plain")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/plain"])!
            return (response, Data("ok".utf8))
        }

        let health = try await client.getHealth()
        XCTAssertEqual(health, "ok")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAuthenticationContextPreservesJsonRequestHeaders() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: session,
            authentication: try ToriiClientAuthentication.authorizationHeader(
                "Bearer wallet-token",
                accountId: "sora-account-1",
                dataspaceId: "mibank.paynet"
            )
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer wallet-token")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Account-Id"), "sora-account-1")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Dataspace-Id"), "mibank.paynet")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, Data())
        }

        let resolved = try await client.resolveAccountAlias("missing@universal")
        XCTAssertNil(resolved)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAuthenticationContextRejectsInsecureTransport() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let client = ToriiClient(
            baseURL: URL(string: "http://example.test")!,
            session: session,
            authentication: try ToriiClientAuthentication.bearerToken(
                "wallet-token",
                accountId: "sora-account-1",
                dataspaceId: "mibank.paynet"
            )
        )

        await XCTAssertThrowsErrorAsync(try await client.getHealth()) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("Expected invalidPayload, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("refuses insecure transport"))
        }
    }

    func testAuthenticationContextRequiresNonEmptyTokenAndAccount() throws {
        XCTAssertThrowsError(
            try ToriiClientAuthentication.bearerToken(" ", accountId: "sora-account-1")
        )
        XCTAssertThrowsError(
            try ToriiClientAuthentication.bearerToken("wallet-token", accountId: " ")
        )
    }

    private func nodeCapabilitiesBody(
        dataModelVersion: Int = ToriiNodeCapabilities.expectedDataModelVersion,
        signedTransactionSchemaHashHex: String? = ToriiNodeCapabilities.expectedSignedTransactionSchemaHashHex
    ) -> Data {
        var payload: [String: Any] = [
            "abi_version": 1,
            "data_model_version": dataModelVersion
        ]
        if let signedTransactionSchemaHashHex {
            payload["signed_transaction_schema_hash_hex"] = signedTransactionSchemaHashHex
        }
        return (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
    }

    private func canonicalOwnerLiteral(
        domain: String = "wonderland",
        chainDiscriminant: UInt16 = AccountId.defaultNetworkPrefix
    ) throws -> String {
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 1, count: 32))
        let address = try AccountAddress.fromAccount(publicKey: keypair.publicKey)
        let i105 = try address.toI105(networkPrefix: chainDiscriminant)
        return i105
    }

    private func noncanonicalOwnerLiteral(domain: String = "wonderland") throws -> String {
        let keypair = try Keypair(privateKeyBytes: Data(repeating: 2, count: 32))
        let address = try AccountAddress.fromAccount(publicKey: keypair.publicKey)
        let canonicalHex = try address.canonicalHex()
        return canonicalHex
    }

    private func makeSignedIdentifierReceiptPayload(policyId: String = "phone#retail",
                                                    accountId: String,
                                                    opaqueId: String,
                                                    receiptHash: String,
                                                    uaid: String,
                                                    backend: String,
                                                    verificationMode: String = "signed",
                                                    programId: String = "identifier_lookup_retail",
                                                    openingProgramId: String? = nil,
                                                    programDigestHex: String = String(repeating: "11", count: 32),
                                                    inputCiphertextHashHex: String = String(repeating: "ab", count: 32),
                                                    outputCiphertextHashHex: String = String(repeating: "bb", count: 32),
                                                    parameterDigestHex: String = String(repeating: "cd", count: 32),
                                                    evaluationKeyDigestHex: String = String(repeating: "dd", count: 32),
                                                    outputHashHex: String = String(repeating: "22", count: 31) + "23",
                                                    associatedDataHashHex: String = String(repeating: "33", count: 32),
                                                    resolvedAtMs: UInt64 = 42,
                                                    expiresAtMs: UInt64? = 142,
                                                    openingSignatureHex: String = String(repeating: "ff", count: 64))
                                                    -> ToriiIdentifierResolutionPayload {
        ToriiIdentifierResolutionPayload(
            networkId: TestNetworkIds.canonical,
            policyId: policyId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            accountId: accountId,
            execution: ToriiIdentifierResolutionExecutionPayload(
                programId: programId,
                programDigest: programDigestHex,
                backend: backend,
                verificationMode: verificationMode,
                inputCiphertextHash: inputCiphertextHashHex,
                outputCiphertextHash: outputCiphertextHashHex,
                parameterDigest: parameterDigestHex,
                evaluationKeyDigest: evaluationKeyDigestHex,
                outputHash: outputHashHex,
                associatedDataHash: associatedDataHashHex,
                executedAtMs: resolvedAtMs,
                expiresAtMs: expiresAtMs
            ),
            opening: sampleOpening(
                programId: openingProgramId ?? programId,
                inputCiphertextHash: inputCiphertextHashHex,
                outputCiphertextHash: outputCiphertextHashHex,
                parameterDigest: parameterDigestHex,
                evaluationKeyDigest: evaluationKeyDigestHex,
                openedOutputHash: outputHashHex,
                openedAtMs: resolvedAtMs,
                expiresAtMs: expiresAtMs,
                signatureHex: openingSignatureHex.lowercased()
            )
        )
    }

    private func sampleOpening(
        programId: String = "identifier_lookup_retail",
        inputCiphertextHash: String = String(repeating: "ab", count: 32),
        outputCiphertextHash: String = String(repeating: "bb", count: 32),
        parameterDigest: String = String(repeating: "cd", count: 32),
        evaluationKeyDigest: String = String(repeating: "dd", count: 32),
        openedOutputHash: String = String(repeating: "ee", count: 31) + "ef",
        openedAtMs: UInt64 = 42,
        expiresAtMs: UInt64? = 142,
        signatureHex: String = String(repeating: "ff", count: 64)
    ) -> ToriiRamLfeOutputOpening {
        ToriiRamLfeOutputOpening(
            payload: ToriiRamLfeOutputOpeningPayload(
                programId: programId,
                inputCiphertextHash: inputCiphertextHash,
                outputCiphertextHash: outputCiphertextHash,
                parameterDigest: parameterDigest,
                evaluationKeyDigest: evaluationKeyDigest,
                openedOutputHash: openedOutputHash,
                openedAtMs: openedAtMs,
                expiresAtMs: expiresAtMs
            ),
            signature: signatureHex
        )
    }

    private func ramLfeProgramPoliciesJSON(
        programId: String = "identifier_lookup_retail",
        owner: String = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
        resolverPublicKey: String = "ed25519:resolver-key",
        backend: String = "bfv-programmed-v1",
        verificationMode: String = "signed",
        inputEncryption: String = "bfv-v1",
        inputEncryptionPublicParameters: String = "ABCD",
        proofBackend: String = "halo2-ipa",
        circuitId: String = "ram-lfe-v1",
        publicInputsSchemaHash: String = String(repeating: "44", count: 32),
        verifyingKeyBytesB64: String = "AQID"
    ) -> Data {
        """
        {
          "total":1,
          "items":[{
            "program_id":"\(programId)",
            "owner":"\(owner)",
            "active":true,
            "resolver_public_key":"\(resolverPublicKey)",
            "backend":"\(backend)",
            "verification_mode":"\(verificationMode)",
            "input_encryption":"\(inputEncryption)",
            "input_encryption_public_parameters":"\(inputEncryptionPublicParameters)",
            "input_encryption_public_parameters_decoded":{
              "parameters":{
                "polynomial_degree":64,
                "plaintext_modulus":257,
                "ciphertext_modulus":1099511627776,
                "decomposition_base_log":12
              },
              "public_key":{
                "b":[1,2,3],
                "a":[4,5,6]
              },
              "max_input_bytes":32
            },
            "ram_fhe_profile":{
              "profile_version":1,
              "register_count":4,
              "memory_lane_count":32,
              "ciphertext_mul_per_step":1,
              "encrypted_input_mode":"encrypted_envelope_v1",
              "initializer_descriptor_hash":"ababababababababababababababababababababababababababababababab01",
              "min_ciphertext_modulus":1099511627776
            },
            "proof_verifier":{
              "proof_backend":"\(proofBackend)",
              "circuit_id":"\(circuitId)",
              "public_inputs_schema_hash":"\(publicInputsSchemaHash)",
              "verifying_key_bytes_b64":"\(verifyingKeyBytesB64)"
            },
            "note":"retail programmed policy"
          }]
        }
        """.data(using: .utf8)!
    }

    private func signedIdentifierReceiptFixture(
        payload: ToriiIdentifierResolutionPayload,
        canonicalPayloadBytes: Data? = nil
    ) throws -> (resolverPublicKey: String, signatureHex: String) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let multihash = CanonicalNorito.publicKeyMultihash(
            algorithm: .ed25519,
            payload: privateKey.publicKey.rawRepresentation
        )
        let payloadBytes: Data
        if let canonicalPayloadBytes {
            payloadBytes = canonicalPayloadBytes
        } else {
            payloadBytes = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)
        }
        var digest = Blake2b.hash256(payloadBytes)
        digest[digest.count - 1] |= 0x01
        let signature = try privateKey.signature(for: digest)
        return (
            resolverPublicKey: "ed25519:\(multihash)",
            signatureHex: signature.hexUppercased()
        )
    }

    private func noritoField(_ payload: Data) -> Data {
        var writer = CompactNoritoWriter()
        writer.writeField(payload)
        return writer.data
    }

    private func legacyFlatBytesVec(_ bytes: Data) -> Data {
        var writer = CompactNoritoWriter()
        writer.writeUInt64LE(UInt64(bytes.count))
        writer.writeBytes(bytes)
        return writer.data
    }

    private func constVecBytes(_ bytes: Data) -> Data {
        var writer = CompactNoritoWriter()
        writer.writeUInt64LE(UInt64(bytes.count))
        for byte in bytes {
            writer.writeLength(1)
            writer.writeUInt8(byte)
        }
        return writer.data
    }

    private func readCompactLength(_ data: Data, offset: inout Int) throws -> Int {
        var shift = 0
        var result: UInt64 = 0
        while true {
            guard offset < data.count, shift < 64 else {
                throw TcHelperError.invalidPayloadEncoding
            }
            let byte = data[offset]
            offset += 1
            result |= UInt64(byte & 0x7F) << UInt64(shift)
            if byte & 0x80 == 0 {
                break
            }
            shift += 7
        }
        guard result <= UInt64(Int.max) else {
            throw TcHelperError.invalidPayloadEncoding
        }
        return Int(result)
    }

    private func noritoFieldRange(in data: Data, fieldIndex: Int) throws -> Range<Data.Index> {
        var offset = 0
        for index in 0...fieldIndex {
            let fieldStart = offset
            let fieldLength = try readCompactLength(data, offset: &offset)
            let fieldEnd = offset + fieldLength
            guard fieldEnd <= data.count else {
                throw TcHelperError.invalidPayloadEncoding
            }
            if index == fieldIndex {
                return fieldStart..<fieldEnd
            }
            offset = fieldEnd
        }
        throw TcHelperError.invalidPayloadEncoding
    }

    private func noritoFieldPayload(_ field: Data) throws -> Data {
        var offset = 0
        let fieldLength = try readCompactLength(field, offset: &offset)
        let fieldEnd = offset + fieldLength
        guard fieldEnd == field.count else {
            throw TcHelperError.invalidPayloadEncoding
        }
        return Data(field[offset..<fieldEnd])
    }

    private func payloadBytesWithLegacyFlatOpeningSignature(
        _ payload: ToriiIdentifierResolutionPayload
    ) throws -> Data {
        let signatureHex = payload.opening.signature.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedSignatureHex: String
        if signatureHex.hasPrefix("0x") || signatureHex.hasPrefix("0X") {
            normalizedSignatureHex = String(signatureHex.dropFirst(2))
        } else {
            normalizedSignatureHex = signatureHex
        }
        guard let signatureBytes = Data(hexString: normalizedSignatureHex) else {
            throw TcHelperError.invalidHashEncoding
        }

        var canonicalPayload = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)
        let openingFieldRange = try noritoFieldRange(in: canonicalPayload, fieldIndex: 3)
        let openingField = Data(canonicalPayload[openingFieldRange])
        var openingPayload = try noritoFieldPayload(openingField)
        let signatureFieldRange = try noritoFieldRange(in: openingPayload, fieldIndex: 1)
        openingPayload.replaceSubrange(
            signatureFieldRange,
            with: noritoField(legacyFlatBytesVec(signatureBytes))
        )

        canonicalPayload.replaceSubrange(openingFieldRange, with: noritoField(openingPayload))
        return canonicalPayload
    }

    private func openingSignaturePayload(in encodedPayload: Data) throws -> Data {
        let openingFieldRange = try noritoFieldRange(in: encodedPayload, fieldIndex: 3)
        let openingField = Data(encodedPayload[openingFieldRange])
        let openingPayload = try noritoFieldPayload(openingField)
        let signatureFieldRange = try noritoFieldRange(in: openingPayload, fieldIndex: 1)
        let signatureField = Data(openingPayload[signatureFieldRange])
        return try noritoFieldPayload(signatureField)
    }

    private func identifierReceiptJSON(
        payload: ToriiIdentifierResolutionPayload,
        signatureHex: String
    ) throws -> String {
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        return """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"signed",
            "signature":"\(signatureHex)"
          }
        }
        """
    }

    private func identifierReceipt(
        payload: ToriiIdentifierResolutionPayload,
        signatureHex: String
    ) throws -> ToriiIdentifierResolutionReceipt {
        try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(try identifierReceiptJSON(payload: payload, signatureHex: signatureHex).utf8)
        )
    }

    private func identifierPolicy(
        policyId: String = "phone#retail",
        owner: String,
        resolverPublicKey: String,
        active: Bool = true,
        backend: String = "bfv-affine-v1"
    ) -> ToriiIdentifierPolicySummary {
        ToriiIdentifierPolicySummary(
            policyId: policyId,
            programId: "identifier_lookup_retail",
            owner: owner,
            active: active,
            normalization: .phoneE164,
            resolverPublicKey: resolverPublicKey,
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: backend,
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAssetAliasAsync() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/assets/aliases/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["alias"] as? String, "usd#issuer.main")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "alias":"usd#issuer.main",
              "asset_definition_id":"66owaQmAQMuHxPzxUN3bqZ6FJfDa",
              "asset_name":"USD",
              "description":"United States Dollar",
              "logo":"sorafs://logos/usd.png",
              "source":"world_state",
              "alias_binding":{"alias":"usd#issuer.main","status":"permanent","bound_at_ms":1}
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let resolved = try await makeClient().resolveAssetAlias("usd#issuer.main")
        XCTAssertEqual(resolved?.alias, "usd#issuer.main")
        XCTAssertEqual(resolved?.assetDefinitionId, "66owaQmAQMuHxPzxUN3bqZ6FJfDa")
        XCTAssertEqual(resolved?.assetName, "USD")
        XCTAssertEqual(resolved?.description, "United States Dollar")
        XCTAssertEqual(resolved?.logo, "sorafs://logos/usd.png")
        XCTAssertEqual(resolved?.source, "world_state")
        XCTAssertEqual(resolved?.aliasBinding?.status, "permanent")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAssetAliasReturnsNilOnNotFound() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/assets/aliases/resolve")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = Data()
            return (response, body)
        }

        let resolved = try await makeClient().resolveAssetAlias("missing#issuer.main")
        XCTAssertNil(resolved)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAccountAliasAsync() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["alias"] as? String, "alice@universal")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "alias":"alice@universal",
              "account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
              "index":7,
              "source":"world_state"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let resolved = try await makeClient().resolveAccountAlias("alice@universal")
        XCTAssertEqual(resolved?.alias, "alice@universal")
        XCTAssertEqual(resolved?.accountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(resolved?.index, 7)
        XCTAssertEqual(resolved?.source, "world_state")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveRestrictedAccountAliasUsesCanonicalAuthentication() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs),
                "4102444801000"
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce),
                "canonical-read-test"
            )
            XCTAssertNotNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
            XCTAssertEqual(self.bodyJSON(from: request)["alias"] as? String, "merchant@private")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {
              "alias":"merchant@private",
              "account_id":"\(self.authority)",
              "source":"world_state"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let resolved = try await makeClient().resolveAccountAlias(
            "merchant@private",
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(resolved?.accountId, authority)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testPlanAliasSetupUsesCanonicalAuthenticationWithoutMutation() async throws {
        let resolved = try ResolvedAccountAliasV1(
            canonicalName: "merchant@private",
            dataspaceId: 7
        )
        let guardValue = try AliasQuoteGuardV1(
            expectedPolicyVersion: 1,
            expectedPaymentAsset: "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            maxAmount: "5",
            validUntilMs: 4_102_444_802_000
        )
        let setup = try AliasSetupPlanRequestV1(
            intents: [
                EnsureAlias(
                    intent: .accountAlias(
                        try AliasAccountIntentV1(
                            alias: resolved,
                            targetAccount: authority,
                            provision: .existing,
                            role: .primary
                        )
                    ),
                    acquisition: try AliasLeaseAcquisitionV1(termYears: 1),
                    quoteGuard: guardValue
                )
            ]
        )
        let responsePlan = try AliasTransactionPlanV1(
            body: try AliasTransactionPlanBodyV1(
                authority: authority,
                networkId: TestNetworkIds.canonical,
                anchor: try AliasPlanAnchorV1(
                    blockHeight: 9,
                    blockHash: NetworkId(bytes: Data(repeating: 0x01, count: 32)).literal
                ),
                resources: [],
                instructions: [],
                totalsByAsset: [],
                warnings: [],
                blockers: [],
                validUntilMs: 4_102_444_802_000
            ),
            planHash: String(repeating: "02", count: 32)
        )
        let responseBody = try JSONEncoder().encode(responsePlan)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/setup/plan")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            XCTAssertNotNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
            XCTAssertEqual(self.bodyJSON(from: request)["schema_version"] as? Int, 1)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, responseBody)
        }

        let plan = try await makeClient().planAliasSetup(setup, canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(plan, responsePlan)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAliasLifecyclePlannersUseCanonicalAuthenticationAndExactOperation() async throws {
        let resolved = try ResolvedAccountAliasV1(
            canonicalName: "merchant@private",
            dataspaceId: 7
        )
        let guardValue = try AliasQuoteGuardV1(
            expectedPolicyVersion: 1,
            expectedPaymentAsset: "4rPeAP6jAjiLVZThZYwwPRBuQagt",
            maxAmount: "5",
            validUntilMs: 4_102_444_802_000
        )
        let renewal = try RenewAliasLease(
            target: .accountAlias(resolved),
            expectedCurrentExpiryMs: 1_000,
            targetExpiryMs: 2_000,
            quoteGuard: guardValue
        )
        let renewalRequest = AliasLeaseRenewPlanRequestV1(renewal: renewal)
        let quote = try AliasLeaseQuoteV1(
            target: renewal.target,
            pricingClass: 1,
            exactAmount: "1",
            quoteGuard: guardValue,
            expiresAtMs: renewal.targetExpiryMs,
            graceExpiresAtMs: 3_000,
            redemptionExpiresAtMs: 4_000
        )
        let renewalPlan = try AliasLifecycleTransactionPlanV1(
            body: try AliasLifecycleTransactionPlanBodyV1(
                authority: authority,
                networkId: TestNetworkIds.canonical,
                anchor: try AliasPlanAnchorV1(
                    blockHeight: 9,
                    blockHash: NetworkId(bytes: Data(repeating: 0x01, count: 32)).literal
                ),
                operation: .renewLease(renewal),
                disposition: .apply,
                instruction: try AliasFramedInstructionV1(
                    wireId: RenewAliasLease.wireId,
                    framedPayload: Data([1, 2, 3])
                ),
                quote: quote,
                totalsByAsset: [try AliasAssetTotalV1(
                    paymentAsset: guardValue.expectedPaymentAsset,
                    amount: quote.exactAmount
                )],
                warnings: [],
                blockers: [],
                validUntilMs: guardValue.validUntilMs
            ),
            planHash: String(repeating: "02", count: 32)
        )
        let renewalResponse = try JSONEncoder().encode(renewalPlan)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/lease/renew/plan")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            XCTAssertEqual(self.bodyJSON(from: request)["schema_version"] as? Int, 1)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, renewalResponse)
        }
        let returnedRenewalPlan = try await makeClient().planAliasLeaseRenewal(
            renewalRequest,
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(returnedRenewalPlan, renewalPlan)

        let configuration = ConfigureAliasAutoRenew(
            target: .accountAlias(resolved),
            expectedRevision: 4,
            config: nil
        )
        let autoRequest = AliasAutoRenewPlanRequestV1(configuration: configuration)
        let autoPlan = try AliasLifecycleTransactionPlanV1(
            body: try AliasLifecycleTransactionPlanBodyV1(
                authority: authority,
                networkId: TestNetworkIds.canonical,
                anchor: renewalPlan.body.anchor,
                operation: .configureAutoRenew(configuration),
                disposition: .noOp,
                instruction: nil,
                quote: nil,
                totalsByAsset: [],
                warnings: [],
                blockers: [],
                validUntilMs: 4_102_444_802_000
            ),
            planHash: String(repeating: "03", count: 32)
        )
        let autoResponse = try JSONEncoder().encode(autoPlan)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/auto-renew/plan")
            XCTAssertNotNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, autoResponse)
        }
        let returnedAutoRenewPlan = try await makeClient().planAliasAutoRenew(
            autoRequest,
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(returnedAutoRenewPlan, autoPlan)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testTypedAliasIndexAndByAccountReadsUseVisibilityAwareRoutes() async throws {
        XCTAssertThrowsError(
            try ToriiAliasesByAccountRequest(
                accountId: authority,
                domain: "banka"
            )
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/resolve-index")
            XCTAssertNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data("""
                {"index":7,"alias":"merchant@paynet","account_id":"\(self.authority)","source":"active_sns"}
                """.utf8)
            )
        }
        let indexed = try await makeClient().resolveAccountAliasIndex(7)
        XCTAssertEqual(indexed?.alias, "merchant@paynet")
        XCTAssertEqual(indexed?.accountId, authority)

        let lookup = try ToriiAliasesByAccountRequest(
            accountId: authority,
            dataspace: "paynet"
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/by-account")
            XCTAssertNotNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let requestBody = self.bodyJSON(from: request)
            XCTAssertEqual(requestBody["account_id"] as? String, self.authority)
            XCTAssertEqual(requestBody["dataspace"] as? String, "paynet")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data("""
                {"account_id":"\(self.authority)","total":1,"items":[{"alias":"merchant@paynet","dataspace":"paynet","is_primary":true}],"source":"fanout"}
                """.utf8)
            )
        }
        let aliases = try await makeClient().aliasesByAccount(
            lookup,
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(aliases?.total, 1)
        XCTAssertEqual(aliases?.items.first?.alias, "merchant@paynet")

        let unsorted = Data("""
        {"account_id":"\(authority)","total":2,"items":[{"alias":"z@paynet","dataspace":"paynet","is_primary":false},{"alias":"a@paynet","dataspace":"paynet","is_primary":true}]}
        """.utf8)
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiAliasesByAccountResponse.self, from: unsorted)
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testTypedAliasReadsRejectSubstitutedResponseSelectors() async throws {
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data("""
                {"alias":"other@paynet","account_id":"\(self.authority)","source":"active_sns"}
                """.utf8)
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await makeClient().resolveAccountAlias("merchant@paynet")
        ) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(reason.contains("exact request"))
        }

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data("""
                {"index":8,"alias":"merchant@paynet","account_id":"\(self.authority)","source":"active_sns"}
                """.utf8)
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await makeClient().resolveAccountAliasIndex(7)
        ) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(reason.contains("exact request"))
        }

        let lookup = try ToriiAliasesByAccountRequest(
            accountId: authority,
            dataspace: "paynet",
            domain: "banka"
        )
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data("""
                {"account_id":"\(self.authority)","total":1,"items":[{"alias":"merchant@other.paynet","dataspace":"paynet","domain":"other","is_primary":true}],"source":"fanout"}
                """.utf8)
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await makeClient().aliasesByAccount(
                lookup,
                canonicalAuth: canonicalReadAuth
            )
        ) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(reason.contains("exact account and scope"))
        }
    }

    func testTypedAliasReadsRejectUnknownResponseFields() {
        let accountId = authority
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAliasIndexResolution.self,
                from: Data("""
                {"index":7,"alias":"merchant@paynet","account_id":"\(accountId)","legacy":true}
                """.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAliasesByAccountResponse.self,
                from: Data("""
                {"account_id":"\(accountId)","total":0,"items":[],"legacy":true}
                """.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiAliasesByAccountResponse.self,
                from: Data("""
                {"account_id":"\(accountId)","total":1,"items":[{"alias":"merchant@paynet","dataspace":"paynet","is_primary":true,"legacy":true}]}
                """.utf8)
            )
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAccountAliasRejectsRetiredAndUnknownResponseFields() async throws {
        let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        for retiredField in [
            "\"accountId\":\"\(accountId)\"",
            "\"account_ids\":[\"\(accountId)\"]",
            "\"accountIds\":[\"\(accountId)\"]",
            "\"unexpected\":true",
        ] {
            StubURLProtocol.handler = { request in
                XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                let body = """
                {"alias":"alice@universal","account_id":"\(accountId)",\(retiredField)}
                """.data(using: .utf8)!
                return (response, body)
            }

            await XCTAssertThrowsErrorAsync(
                try await makeClient().resolveAccountAlias("alice@universal")
            ) { _ in }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAccountAliasRejectsNonExactResponseFields() async throws {
        let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let canonical = """
        {
          "alias":"alice@universal",
          "account_id":"\(accountId)",
          "index":7,
          "source":"world_state"
        }
        """
        let cases = [
            (
                "account alias resolution.alias",
                "\"alias\":\"alice@universal\"",
                "\"alias\":\" alice@universal\""
            ),
            (
                "account alias resolution.account_id",
                "\"account_id\":\"\(accountId)\"",
                "\"account_id\":\" \(accountId)\""
            ),
            (
                "account alias resolution.source",
                "\"source\":\"world_state\"",
                "\"source\":\"world_state \""
            )
        ]

        for (field, needle, replacement) in cases {
            StubURLProtocol.handler = { request in
                XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                let body = canonical.replacingOccurrences(of: needle, with: replacement)
                    .data(using: .utf8)!
                return (response, body)
            }

            do {
                _ = try await makeClient().resolveAccountAlias("alice@universal")
                XCTFail("expected \(field) exactness failure")
            } catch let ToriiClientError.decoding(underlying) {
                guard case let DecodingError.dataCorrupted(context) = underlying else {
                    return XCTFail("expected dataCorrupted decode error for \(field), got \(underlying)")
                }
                XCTAssertTrue(
                    context.debugDescription.contains(field),
                    "expected \(field) failure, got \(context.debugDescription)"
                )
            } catch {
                XCTFail("expected dataCorrupted decode error for \(field), got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveAccountAliasReturnsNilOnNotFound() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/aliases/resolve")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, Data())
        }

        let resolved = try await makeClient().resolveAccountAlias("missing-alias@universal")
        XCTAssertNil(resolved)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListIdentifierPoliciesAsync() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifier-policies")
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "total": 1,
              "items": [{
                "policy_id":"phone#retail",
                "program_id":"identifier_lookup_retail",
                "output_opening_public_key":"ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
                "owner":"\(owner)",
                "active":true,
                "normalization":"phone_e164",
                "resolver_public_key":"ed25519:resolver-key",
                "backend":"bfv-affine-v1",
                "input_encryption":"bfv-v1",
                "input_encryption_public_parameters":"ABCD",
                "input_encryption_public_parameters_decoded":{
                  "parameters":{
                    "polynomial_degree":64,
                    "plaintext_modulus":257,
                    "ciphertext_modulus":1099511627776,
                    "decomposition_base_log":12
                  },
                  "public_key":{
                    "b":[1,2,3],
                    "a":[4,5,6]
                  },
                  "max_input_bytes":32,
                  "norito_length_encoding":"u64-v1"
                },
                "ram_fhe_profile":{
                  "profile_version":1,
                  "register_count":4,
                  "memory_lane_count":32,
                  "ciphertext_mul_per_step":1,
                  "encrypted_input_mode":"encrypted_envelope_v1",
                  "initializer_descriptor_hash":"ababababababababababababababababababababababababababababababab01",
                  "min_ciphertext_modulus":1099511627776
                },
                "proof_verifier":{
                  "proof_backend":"halo2-ipa",
                  "circuit_id":"identifier-ram-lfe-v1",
                  "public_inputs_schema_hash":"\(String(repeating: "66", count: 32))",
                  "verifying_key_bytes_b64":"AQID"
                },
                "note":"retail phone policy"
              }]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let response = try await makeClient().listIdentifierPolicies()
        XCTAssertEqual(response.total, 1)
        XCTAssertEqual(response.items.count, 1)
        XCTAssertEqual(response.items.first?.policyId, "phone#retail")
        XCTAssertEqual(response.items.first?.programId, "identifier_lookup_retail")
        XCTAssertEqual(response.items.first?.outputOpeningPublicKey, "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE")
        XCTAssertEqual(response.items.first?.owner, owner)
        XCTAssertEqual(response.items.first?.normalization, .phoneE164)
        XCTAssertEqual(response.items.first?.inputEncryption, "bfv-v1")
        XCTAssertEqual(response.items.first?.inputEncryptionPublicParameters, "ABCD")
        XCTAssertEqual(
            response.items.first?.inputEncryptionPublicParametersDecoded?.parameters.polynomialDegree,
            64
        )
        XCTAssertEqual(
            response.items.first?.inputEncryptionPublicParametersDecoded?.parameters.decompositionBaseLog,
            12
        )
        XCTAssertEqual(
            response.items.first?.inputEncryptionPublicParametersDecoded?.noritoLengthEncoding,
            "u64-v1"
        )
        XCTAssertEqual(response.items.first?.ramFheProfile?.profileVersion, 1)
        XCTAssertEqual(response.items.first?.ramFheProfile?.registerCount, 4)
        XCTAssertEqual(response.items.first?.ramFheProfile?.memoryLaneCount, 32)
        XCTAssertEqual(
            response.items.first?.ramFheProfile?.encryptedInputMode,
            .encryptedEnvelopeV1
        )
        XCTAssertEqual(response.items.first?.proofVerifier?.proofBackend, "halo2-ipa")
        XCTAssertEqual(response.items.first?.proofVerifier?.publicInputsSchemaHash, String(repeating: "66", count: 32))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListIdentifierPoliciesRejectsNonExactMetadata() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let canonical = """
        {
          "total": 1,
          "items": [{
            "policy_id":"phone#retail",
            "program_id":"identifier_lookup_retail",
            "output_opening_public_key":"ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            "owner":"\(owner)",
            "active":true,
            "normalization":"phone_e164",
            "resolver_public_key":"ed25519:resolver-key",
            "backend":"bfv-affine-v1",
            "input_encryption":"bfv-v1",
            "input_encryption_public_parameters":"ABCD",
            "input_encryption_public_parameters_decoded":{
              "parameters":{
                "polynomial_degree":64,
                "plaintext_modulus":257,
                "ciphertext_modulus":1099511627776,
                "decomposition_base_log":12
              },
              "public_key":{
                "b":[1,2,3],
                "a":[4,5,6]
              },
              "max_input_bytes":32,
              "norito_length_encoding":"u64-v1"
            },
            "note":"retail phone policy"
          }]
        }
        """
        let cases = [
            (
                "identifier policy.owner",
                "\"owner\":\"\(owner)\"",
                "\"owner\":\" \(owner)\""
            ),
            (
                "identifier policy.normalization",
                "\"normalization\":\"phone_e164\"",
                "\"normalization\":\"Phone_E164\""
            ),
            (
                "identifier policy.backend",
                "\"backend\":\"bfv-affine-v1\"",
                "\"backend\":\"bfv-affine-v1 \""
            ),
            (
                "identifier policy.input_encryption",
                "\"input_encryption\":\"bfv-v1\"",
                "\"input_encryption\":\"BFV-v1\""
            ),
            (
                "identifier policy.input_encryption_public_parameters",
                "\"input_encryption_public_parameters\":\"ABCD\"",
                "\"input_encryption_public_parameters\":\" ABCD\""
            ),
            (
                "identifier policy.input_encryption_public_parameters_decoded.norito_length_encoding",
                "\"norito_length_encoding\":\"u64-v1\"",
                "\"norito_length_encoding\":\" u64-v1\""
            ),
            (
                "identifier policy.note",
                "\"note\":\"retail phone policy\"",
                "\"note\":\"retail phone policy \""
            )
        ]

        for (field, needle, replacement) in cases {
            StubURLProtocol.handler = { request in
                XCTAssertEqual(request.url?.path, "/v1/identifier-policies")
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                let body = canonical.replacingOccurrences(of: needle, with: replacement)
                    .data(using: .utf8)!
                return (response, body)
            }

            do {
                _ = try await makeClient().listIdentifierPolicies()
                XCTFail("expected \(field) exactness failure")
            } catch let ToriiClientError.decoding(underlying) {
                guard case let DecodingError.dataCorrupted(context) = underlying else {
                    return XCTFail("expected dataCorrupted decode error for \(field), got \(underlying)")
                }
                XCTAssertTrue(
                    context.debugDescription.contains(field),
                    "expected \(field) failure, got \(context.debugDescription)"
                )
            } catch {
                XCTFail("expected dataCorrupted decode error for \(field), got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListIdentifierPoliciesRejectsTaggedEncryptedInputMode() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifier-policies")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {
              "total": 1,
              "items": [{
                "policy_id":"email#retail",
                "program_id":"identifier_lookup_retail",
                "output_opening_public_key":"ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
                "owner":"\(owner)",
                "active":true,
                "normalization":"email_address",
                "resolver_public_key":"ed25519:resolver-key",
                "backend":"bfv-programmed-v1",
                "input_encryption":"bfv-v1",
                "input_encryption_public_parameters":"ABCD",
                "input_encryption_public_parameters_decoded":{
                  "parameters":{
                    "polynomial_degree":64,
                    "plaintext_modulus":256,
                    "ciphertext_modulus":4503599627370496,
                    "decomposition_base_log":12
                  },
                  "public_key":{
                    "b":[1,2,3],
                    "a":[4,5,6]
                  },
                  "max_input_bytes":63
                },
                "ram_fhe_profile":{
                  "profile_version":1,
                  "register_count":4,
                  "memory_lane_count":32,
                  "ciphertext_mul_per_step":1,
                  "encrypted_input_mode":{
                    "mode":"EncryptedEnvelopeV1",
                    "value":null
                  },
                  "initializer_descriptor_hash":"ababababababababababababababababababababababababababababababab01",
                  "min_ciphertext_modulus":4503599627370496
                },
                "note":"retail email policy"
              }]
            }
            """.data(using: .utf8)!
            // Prove that the retired mode is the only malformed field.
            var canonical = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            var items = try XCTUnwrap(canonical["items"] as? [[String: Any]])
            var profile = try XCTUnwrap(items[0]["ram_fhe_profile"] as? [String: Any])
            profile["encrypted_input_mode"] = "encrypted_envelope_v1"
            items[0]["ram_fhe_profile"] = profile
            canonical["items"] = items
            XCTAssertNoThrow(try JSONDecoder().decode(ToriiIdentifierPolicyListResponse.self,
                from: JSONSerialization.data(withJSONObject: canonical)))
            return (response, body)
        }

        do {
            _ = try await makeClient().listIdentifierPolicies()
            XCTFail("expected retired encrypted input mode rejection")
        } catch let ToriiClientError.decoding(error) {
            XCTAssertTrue(String(describing: error).contains("encrypted_input_mode"))
        } catch {
            XCTFail("expected encrypted input mode decoding error, got \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListIdentifierPoliciesRejectsRetiredResolverCanonicalizedInputMode() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifier-policies")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {
              "total": 1,
              "items": [{
                "policy_id":"email#retail",
                "program_id":"identifier_lookup_retail",
                "output_opening_public_key":"ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
                "owner":"\(owner)",
                "active":true,
                "normalization":"email_address",
                "resolver_public_key":"ed25519:resolver-key",
                "backend":"bfv-programmed-v1",
                "input_encryption":"bfv-v1",
                "input_encryption_public_parameters_decoded":{
                  "parameters":{
                    "polynomial_degree":64,
                    "plaintext_modulus":256,
                    "ciphertext_modulus":4503599627370496,
                    "decomposition_base_log":12
                  },
                  "public_key":{
                    "b":[1,2,3],
                    "a":[4,5,6]
                  },
                  "max_input_bytes":63
                },
                "ram_fhe_profile":{
                  "profile_version":1,
                  "register_count":4,
                  "memory_lane_count":32,
                  "ciphertext_mul_per_step":1,
                  "encrypted_input_mode":{
                    "mode":"ResolverCanonicalizedEnvelopeV1",
                    "value":null
                  },
                  "initializer_descriptor_hash":"ababababababababababababababababababababababababababababababab01",
                  "min_ciphertext_modulus":4503599627370496
                },
                "note":"Retail identifier policy email#retail"
              }]
            }
            """.data(using: .utf8)!
            // Prove that the retired mode is the only malformed field.
            var canonical = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            var items = try XCTUnwrap(canonical["items"] as? [[String: Any]])
            var profile = try XCTUnwrap(items[0]["ram_fhe_profile"] as? [String: Any])
            profile["encrypted_input_mode"] = "encrypted_envelope_v1"
            items[0]["ram_fhe_profile"] = profile
            canonical["items"] = items
            XCTAssertNoThrow(try JSONDecoder().decode(ToriiIdentifierPolicyListResponse.self,
                from: JSONSerialization.data(withJSONObject: canonical)))
            return (response, body)
        }

        do {
            _ = try await makeClient().listIdentifierPolicies()
            XCTFail("expected retired encrypted input mode rejection")
        } catch let ToriiClientError.decoding(error) {
            XCTAssertTrue(String(describing: error).contains("encrypted_input_mode"))
        } catch {
            XCTFail("expected encrypted input mode decoding error, got \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListRamLfeProgramPoliciesAsync() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/ram-lfe/program-policies")
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = self.ramLfeProgramPoliciesJSON(owner: owner)
            return (response, body)
        }

        let response = try await makeClient().listRamLfeProgramPolicies()
        XCTAssertEqual(response.total, 1)
        XCTAssertEqual(response.items.count, 1)
        XCTAssertEqual(response.items.first?.programId, "identifier_lookup_retail")
        XCTAssertEqual(response.items.first?.owner, owner)
        XCTAssertEqual(response.items.first?.verificationMode, "signed")
        XCTAssertEqual(response.items.first?.inputEncryption, "bfv-v1")
        XCTAssertEqual(
            response.items.first?.inputEncryptionPublicParametersDecoded?.parameters.polynomialDegree,
            64
        )
        XCTAssertEqual(response.items.first?.ramFheProfile?.profileVersion, 1)
        XCTAssertEqual(response.items.first?.proofVerifier?.proofBackend, "halo2-ipa")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRamLfeProgramPolicyParserRejectsNonExactFieldsAsync() async throws {
        let owner = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let cases: [(field: String, body: Data)] = [
            ("ram-lfe program policy.program_id", ramLfeProgramPoliciesJSON(programId: " identifier_lookup_retail")),
            ("ram-lfe program policy.owner", ramLfeProgramPoliciesJSON(owner: "\(owner) ")),
            ("ram-lfe program policy.resolver_public_key", ramLfeProgramPoliciesJSON(resolverPublicKey: " ed25519:resolver-key")),
            ("ram-lfe program policy.backend", ramLfeProgramPoliciesJSON(backend: "BFV-programmed-sha3-256-v1")),
            ("ram-lfe program policy.verification_mode", ramLfeProgramPoliciesJSON(verificationMode: " signed")),
            ("ram-lfe program policy.input_encryption", ramLfeProgramPoliciesJSON(inputEncryption: "bfv-v1 ")),
            (
                "ram-lfe program policy.input_encryption_public_parameters",
                ramLfeProgramPoliciesJSON(inputEncryptionPublicParameters: " ABCD")
            ),
            ("ram-lfe proof verifier.proof_backend", ramLfeProgramPoliciesJSON(proofBackend: " halo2-ipa")),
            ("ram-lfe proof verifier.circuit_id", ramLfeProgramPoliciesJSON(circuitId: "ram-lfe-v1 ")),
            (
                "ram-lfe proof verifier.public_inputs_schema_hash",
                ramLfeProgramPoliciesJSON(publicInputsSchemaHash: " \(String(repeating: "44", count: 32))")
            ),
            ("ram-lfe proof verifier.verifying_key_bytes_b64", ramLfeProgramPoliciesJSON(verifyingKeyBytesB64: "AQID "))
        ]
        for testCase in cases {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiRamLfeProgramPolicyListResponse.self, from: testCase.body)
            ) { error in
                XCTAssertTrue(
                    String(describing: error).contains(testCase.field),
                    "\(testCase.field): \(error)"
                )
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExecuteRamLfeProgramAsync() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/ram-lfe/programs/identifier_lookup_retail/execute")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            XCTAssertNotNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
            let payload = self.bodyJSON(from: request)
            XCTAssertNil(payload["input_hex"])
            XCTAssertNil(payload["encrypted_input"])
            XCTAssertEqual(payload["normalized_input"] as? String, "private@example.org")
            XCTAssertEqual(payload["input_nonce"] as? String, String(repeating: "12", count: 32))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, try ramLfeExecuteResponseJSON())
        }

        let response = try await makeClient().executeRamLfeProgram(
            programId: "identifier_lookup_retail",
            requestBody: try .ownerInput(normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32)),
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(response?.programId, "identifier_lookup_retail")
        XCTAssertEqual(response?.opaqueOutputHex, try currentOwnerExecuteResponseField("opaque_output"))
        XCTAssertEqual(response?.outputHash, try currentOwnerExecuteResponseField("output_hash"))
        XCTAssertEqual(response?.verificationMode, "signed")
        if case let .object(receipt)? = response?.receipt["payload"] {
            XCTAssertNotNil(receipt["program_id"])
        } else {
            XCTFail("missing raw receipt payload")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExecuteRamLfeProgramReturnsNilOnNotFound() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/ram-lfe/programs/identifier_lookup_retail/execute")
            let payload = self.bodyJSON(from: request)
            XCTAssertNil(payload["encrypted_input"])
            XCTAssertEqual(payload["normalized_input"] as? String, "private@example.org")
            XCTAssertEqual(payload["input_nonce"] as? String, String(repeating: "12", count: 32))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, Data())
        }

        let response = try await makeClient().executeRamLfeProgram(
            programId: "identifier_lookup_retail",
            requestBody: try .ownerInput(normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32)),
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertNil(response)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyRamLfeReceiptAsync() async throws {
        let receipt: ToriiRamLfeExecutionReceipt = [
            "payload": .object([
                "program_id": .string("identifier_lookup_retail"),
                "program_digest": .string(String(repeating: "11", count: 32)),
                "backend": .string("bfv-programmed-v1"),
                "verification_mode": .string("signed"),
                "output_hash": .string(String(repeating: "22", count: 32)),
                "associated_data_hash": .string(String(repeating: "33", count: 32)),
                "executed_at_ms": .number(42),
                "expires_at_ms": .number(142)
            ]),
            "attestation": .object([
                "kind": .string("signed"),
                "signature": .string(String(repeating: "aa", count: 64))
            ])
        ]
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/ram-lfe/receipts/verify")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["output_hex"] as? String, "c0ffee")
            let receiptObject = payload["receipt"] as? [String: Any]
            let payloadObject = receiptObject?["payload"] as? [String: Any]
            XCTAssertNotNil(payloadObject?["program_id"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, ramLfeReceiptVerifyResponseJSON())
        }

        let response = try await makeClient().verifyRamLfeReceipt(
            receipt: receipt,
            outputHex: "C0FFEE",
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertTrue(response.valid)
        XCTAssertEqual(response.programId, "identifier_lookup_retail")
        XCTAssertEqual(response.outputHashMatches, true)
    }

    func testIdentifierPolicyRequiresProgramAndOpeningKey() throws {
        let policy: [String: Any] = [
            "policy_id": "email#retail",
            "program_id": "identifier_lookup_retail",
            "owner": try canonicalOwnerLiteral(),
            "active": true,
            "normalization": "email_address",
            "resolver_public_key": "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            "output_opening_public_key": "ed01208FC2E4882B20ABCCBFADB4E44268206E187AEB235A51252F159B3B24D5BB6661",
            "backend": "bfv-programmed-v1"
        ]
        func decode(_ value: [String: Any]) throws -> ToriiIdentifierPolicySummary {
            try JSONDecoder().decode(
                ToriiIdentifierPolicySummary.self,
                from: JSONSerialization.data(withJSONObject: value)
            )
        }
        let decoded = try decode(policy)
        XCTAssertEqual(decoded.programId, "identifier_lookup_retail")
        XCTAssertNotEqual(decoded.outputOpeningPublicKey, decoded.resolverPublicKey)
        for field in ["program_id", "output_opening_public_key"] {
            var missing = policy
            missing.removeValue(forKey: field)
            XCTAssertThrowsError(try decode(missing), "missing \(field) must fail")
            for invalid in [NSNull(), "", " ", " padded", "padded ", "embedded space", "control\u{01}", 1] as [Any] {
                var malformed = policy
                malformed[field] = invalid
                XCTAssertThrowsError(try decode(malformed), "invalid \(field) must fail")
            }
        }
    }

    func testRamLfeResponseParsersAcceptOnlyCurrentBackendAndModeTags() throws {
        let decoder = JSONDecoder()
        func object(_ data: Data) throws -> [String: Any] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        }
        let execute = try object(try ramLfeExecuteResponseJSON())
        // Generic and identifier receipts use the same program-only execution payload.
        let identifierPayload = makeSignedIdentifierReceiptPayload(
            accountId: try canonicalOwnerLiteral(),
            opaqueId: String(repeating: "11", count: 32),
            receiptHash: String(repeating: "22", count: 32),
            uaid: String(repeating: "33", count: 32),
            backend: "bfv-programmed-v1"
        )
        let execution = try object(JSONEncoder().encode(identifierPayload.execution))
        let programList = try object(ramLfeProgramPoliciesJSON())
        let policies = try XCTUnwrap(programList["items"] as? [[String: Any]])
        let identifierPolicy: [String: Any] = [
            "policy_id": "email#retail",
            "program_id": "identifier_lookup_retail",
            "output_opening_public_key": "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            "owner": try canonicalOwnerLiteral(),
            "active": true,
            "normalization": "email_address",
            "resolver_public_key": "ed25519:resolver-key",
            "backend": "bfv-programmed-v1",
        ]
        let surfaces: [(name: String, body: [String: Any], decode: (Data) throws -> Void)] = [
            ("identifier policy", identifierPolicy, { _ = try decoder.decode(ToriiIdentifierPolicySummary.self, from: $0) }),
            ("ram-lfe program policy", try XCTUnwrap(policies.first), { _ = try decoder.decode(ToriiRamLfeProgramPolicySummary.self, from: $0) }),
            ("ram-lfe execute response", execute, { _ = try decoder.decode(ToriiRamLfeExecuteResponse.self, from: $0) }),
            ("ram-lfe receipt verify response", try object(ramLfeReceiptVerifyResponseJSON()), { _ = try decoder.decode(ToriiRamLfeReceiptVerifyResponse.self, from: $0) }),
            ("payload.execution", execution, { _ = try decoder.decode(ToriiIdentifierResolutionExecutionPayload.self, from: $0) }),
        ]
        func setting(_ fields: [String: String], in body: [String: Any]) -> [String: Any] {
            var result = body
            for (field, value) in fields where result[field] != nil {
                result[field] = value
            }
            // Keep execution-response duplication consistent so it cannot mask tag validation.
            if var receipt = result["receipt"] as? [String: Any],
               var payload = receipt["payload"] as? [String: Any] {
                for (field, value) in fields { payload[field] = value }
                receipt["payload"] = payload
                result["receipt"] = receipt
            }
            return result
        }
        for surface in surfaces {
            for backend in ["hkdf-sha3-512-prf-v1", "bfv-affine-v1", "bfv-programmed-v1"] {
                for mode in ["signed", "proof"] {
                    let body = setting(["backend": backend, "verification_mode": mode], in: surface.body)
                    if surface.name == "ram-lfe execute response", backend != "hkdf-sha3-512-prf-v1" || mode != "signed" {
                        XCTAssertThrowsError(try surface.decode(JSONSerialization.data(withJSONObject: body)), surface.name)
                    } else {
                        XCTAssertNoThrow(try surface.decode(JSONSerialization.data(withJSONObject: body)), surface.name)
                    }
                }
            }
            for (field, value) in [
                ("backend", "bfv-affine-sha3-256-v1"),
                ("backend", "bfv-programmed-sha3-256-v1"),
                ("backend", "unknown"),
                ("verification_mode", "signed-v1"),
                ("verification_mode", "unknown"),
            ] where surface.body[field] != nil {
                let body = setting([field: value], in: surface.body)
                XCTAssertThrowsError(try surface.decode(JSONSerialization.data(withJSONObject: body))) { error in
                    guard case let DecodingError.dataCorrupted(context) = error else {
                        return XCTFail("expected dataCorrupted for \(surface.name).\(field), got \(error)")
                    }
                    XCTAssertTrue(context.debugDescription.contains("\(surface.name).\(field) must be one of:"))
                }
            }
        }
    }

    func testRamLfeExecuteResponseRejectsRetiredOutputOpening() throws {
        let valid = try ramLfeExecuteResponseJSON()
        _ = try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: valid)
        for retiredValue in [NSNull(), ["payload": [:], "signature": "ab"]] as [Any] {
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: valid) as? [String: Any])
            object["output_opening"] = retiredValue
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: data)) { error in
                XCTAssertTrue(String(describing: error).contains("unknown or retired field"))
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRamLfeResponseParsersRejectNonExactFieldsAsync() async throws {
        let executeCases: [(field: String, body: Data)] = [
            ("program_id", try ramLfeExecuteResponseJSON(programId: " identifier_lookup_retail")),
            ("opaque_hash", try ramLfeExecuteResponseJSON(opaqueHash: "\(String(repeating: "11", count: 32)) ")),
            ("receipt_hash", try ramLfeExecuteResponseJSON(receiptHash: " \(String(repeating: "22", count: 32))")),
            ("opaque_output", try ramLfeExecuteResponseJSON(opaqueOutputHex: " C0FFEE")),
            ("output_hash", try ramLfeExecuteResponseJSON(outputHash: "\(String(repeating: "44", count: 32)) ")),
            ("associated_data_hash", try ramLfeExecuteResponseJSON(associatedDataHash: " \(String(repeating: "55", count: 32))")),
            ("backend", try ramLfeExecuteResponseJSON(backend: "BFV-programmed-sha3-256-v1")),
            ("verification_mode", try ramLfeExecuteResponseJSON(verificationMode: " signed"))
        ]
        for testCase in executeCases {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiRamLfeExecuteResponse.self, from: testCase.body)
            ) { error in
                XCTAssertTrue(
                    String(describing: error).contains("ram-lfe execute response.\(testCase.field)"),
                    "\(testCase.field): \(error)"
                )
            }
        }

        let verifyCases: [(field: String, body: Data)] = [
            ("program_id", ramLfeReceiptVerifyResponseJSON(programId: "identifier_lookup_retail ")),
            ("backend", ramLfeReceiptVerifyResponseJSON(backend: " bfv-programmed-v1")),
            ("verification_mode", ramLfeReceiptVerifyResponseJSON(verificationMode: "Signed")),
            ("output_hash", ramLfeReceiptVerifyResponseJSON(outputHash: " \(String(repeating: "44", count: 32))")),
            (
                "associated_data_hash",
                ramLfeReceiptVerifyResponseJSON(associatedDataHash: "\(String(repeating: "55", count: 32)) ")
            )
        ]
        for testCase in verifyCases {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiRamLfeReceiptVerifyResponse.self, from: testCase.body)
            ) { error in
                XCTAssertTrue(
                    String(describing: error).contains("ram-lfe receipt verify response.\(testCase.field)"),
                    "\(testCase.field): \(error)"
                )
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveIdentifierAsync() async throws {
        let accountId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let opaqueId = "opaque:\(String(repeating: "11", count: 32))"
        let receiptHash = String(repeating: "22", count: 31) + "23"
        let uaid = "uaid:\(String(repeating: "33", count: 31))35"
        let signedPayload = makeSignedIdentifierReceiptPayload(
            policyId: "email#retail",
            accountId: accountId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            backend: "hkdf-sha3-512-prf-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: signedPayload)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifiers/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                try AccountAddress.parseEncoded(self.authority).canonicalHex()
            )
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["policy_id"] as? String, "email#retail")
            XCTAssertNil(payload["encrypted_input"])
            XCTAssertEqual(payload["normalized_input"] as? String, "private@example.org")
            XCTAssertEqual(payload["input_nonce"] as? String, String(repeating: "12", count: 32))
            XCTAssertNotNil(payload["output_opening"])
            XCTAssertNil(payload["input"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = try self.identifierReceiptJSON(
                payload: signedPayload,
                signatureHex: signed.signatureHex
            ).data(using: .utf8)!
            return (response, body)
        }

        let receipt = try await makeClient().resolveIdentifier(
            try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: signedPayload.opening),
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(receipt?.policyId, "email#retail")
        XCTAssertEqual(receipt?.opaqueId, opaqueId)
        XCTAssertEqual(receipt?.receiptHash, receiptHash)
        XCTAssertEqual(receipt?.uaid, uaid)
        XCTAssertEqual(receipt?.accountId, accountId)
        XCTAssertEqual(receipt?.resolvedAtMs, 42)
        XCTAssertEqual(receipt?.expiresAtMs, 142)
        XCTAssertEqual(receipt?.backend, "hkdf-sha3-512-prf-v1")
        let policy = ToriiIdentifierPolicySummary(
            policyId: "email#retail",
            programId: "identifier_lookup_retail",
            owner: accountId,
            active: true,
            normalization: .phoneE164,
            resolverPublicKey: signed.resolverPublicKey,
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "hkdf-sha3-512-prf-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        XCTAssertEqual(try receipt?.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)
    }

    func testIdentifierReceiptDecodeRejectsPaddedAccountIdBeforeSignatureVerification() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        var receiptObject = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(try identifierReceiptJSON(payload: payload, signatureHex: signed.signatureHex).utf8)
            ) as? [String: Any]
        )
        var payloadObject = try XCTUnwrap(receiptObject["payload"] as? [String: Any])
        payloadObject["account_id"] = " \(accountId) "
        receiptObject["payload"] = payloadObject

        let receiptData = try JSONSerialization.data(withJSONObject: receiptObject, options: [])
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiIdentifierResolutionReceipt.self, from: receiptData)
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertTrue(context.debugDescription.contains("payload.account_id"))
            XCTAssertTrue(context.debugDescription.contains("surrounding whitespace"))
        }
    }

    func testIdentifierReceiptPreservesTairaAccountRoundTrip() throws {
        let accountId = try canonicalOwnerLiteral(
            chainDiscriminant: TairaTestnetProfile.i105Discriminant
        )
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let json = try JSONEncoder().encode(payload)
        let decoded = try JSONDecoder().decode(
            ToriiIdentifierResolutionPayload.self,
            from: json
        )

        XCTAssertEqual(decoded.accountId, accountId)
        XCTAssertEqual(
            try AccountAddress.inspectI105NetworkPrefix(decoded.accountId)
                .chainDiscriminant,
            TairaTestnetProfile.i105Discriminant
        )
        XCTAssertFalse(
            try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(decoded)
                .isEmpty
        )
    }

    func testIdentifierReceiptOpeningSignatureUsesConstVecEncoding() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: "fafbfc"
        )

        let encoded = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)

        XCTAssertNotNil(
            encoded.range(of: Data([0x0E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFA, 0x01, 0xFB, 0x01, 0xFC]))
        )
        XCTAssertNil(
            encoded.range(of: Data([0x0B, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0xFB, 0xFC]))
        )
    }

    func testIdentifierReceiptOpeningSignatureConstVecEncodingUsesFixedU64LengthFraming() throws {
        let accountId = try canonicalOwnerLiteral()
        let longSignature = Data((0..<128).map { UInt8($0) })
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: longSignature.hexUppercased().lowercased()
        )

        let signaturePayload = try openingSignaturePayload(
            in: ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)
        )

        XCTAssertEqual(signaturePayload, constVecBytes(longSignature))
        XCTAssertNotEqual(signaturePayload, legacyFlatBytesVec(longSignature))
        XCTAssertEqual(
            Data(signaturePayload.prefix(6)),
            Data([0x80, 0x00, 0x00, 0x00, 0x00, 0x00])
        )
    }

    func testIdentifierReceiptRejectsMalformedOpeningSignatureHex() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: "0xGG"
        )

        XCTAssertThrowsError(try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("expected invalid payload error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("payload.opening.signature"))
        }
    }

    func testIdentifierReceiptRejectsLegacyFlatOpeningSignatureAttestation() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: "fafbfc"
        )
        let currentSigned = try signedIdentifierReceiptFixture(payload: payload)
        let legacySigned = try signedIdentifierReceiptFixture(
            payload: payload,
            canonicalPayloadBytes: payloadBytesWithLegacyFlatOpeningSignature(payload)
        )
        let policy = ToriiIdentifierPolicySummary(
            policyId: "phone#retail",
            programId: "identifier_lookup_retail",
            owner: accountId,
            active: true,
            normalization: .phoneE164,
            resolverPublicKey: currentSigned.resolverPublicKey,
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-affine-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        let currentReceipt = try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(try identifierReceiptJSON(
                payload: payload,
                signatureHex: currentSigned.signatureHex
            ).utf8)
        )
        let legacyReceipt = try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(try identifierReceiptJSON(
                payload: payload,
                signatureHex: legacySigned.signatureHex
            ).utf8)
        )

        XCTAssertEqual(try currentReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertEqual(try legacyReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false)
    }

    func testIdentifierReceiptRejectsOpeningSignatureMutationAfterSigning() throws {
        let accountId = try canonicalOwnerLiteral()
        let originalPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: String(repeating: "fa", count: 64)
        )
        let mutatedPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1",
            openingSignatureHex: String(repeating: "fb", count: 64)
        )
        let signed = try signedIdentifierReceiptFixture(payload: originalPayload)
        let policy = ToriiIdentifierPolicySummary(
            policyId: "phone#retail",
            programId: "identifier_lookup_retail",
            owner: accountId,
            active: true,
            normalization: .phoneE164,
            resolverPublicKey: signed.resolverPublicKey,
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-affine-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        let originalReceipt = try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(try identifierReceiptJSON(
                payload: originalPayload,
                signatureHex: signed.signatureHex
            ).utf8)
        )
        let mutatedReceipt = try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(try identifierReceiptJSON(
                payload: mutatedPayload,
                signatureHex: signed.signatureHex
            ).utf8)
        )

        XCTAssertEqual(try originalReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertEqual(try mutatedReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false)
    }

    func testIdentifierReceiptRejectsReceiptHashMutationAfterSigning() throws {
        let accountId = try canonicalOwnerLiteral()
        let originalPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let mutatedPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "25",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: originalPayload)
        let policy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let originalReceipt = try identifierReceipt(
            payload: originalPayload,
            signatureHex: signed.signatureHex
        )
        let mutatedReceipt = try identifierReceipt(
            payload: mutatedPayload,
            signatureHex: signed.signatureHex
        )

        XCTAssertEqual(try originalReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertEqual(try mutatedReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false)
    }

    func testIdentifierReceiptRejectsMalformedMlDsaAttestationLengthsBeforeBridge() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let params = MlDsaSuite.mlDsa65.parameters()
        let publicKey = Data(repeating: 0xA5, count: params.publicKeyLength)
        let publicKeyMultihash = CanonicalNorito.publicKeyMultihash(
            algorithm: .mlDsa,
            payload: publicKey
        )
        let shortSignature = Data(repeating: 0x11, count: params.signatureLength - 1)
        let overlongSignature = Data(repeating: 0x22, count: params.signatureLength + 1)
        let shortReceipt = try identifierReceipt(
            payload: payload,
            signatureHex: shortSignature.hexUppercased()
        )
        for signature in [
            overlongSignature,
            Data(repeating: 0x33, count: MlDsaSuite.mlDsa87.parameters().signatureLength),
        ] {
            XCTAssertThrowsError(try identifierReceipt(
                payload: payload,
                signatureHex: signature.hexUppercased()
            )) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    return XCTFail("Expected signature-bound decode refusal, got \(error)")
                }
                XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "signature"])
                XCTAssertTrue(context.debugDescription.contains("exceeds the canonical signature bound"))
            }
        }

        for prefix in ["ml-dsa", "mldsa", "mldsa65", "ML-DSA-65", "ML_DSA_65", "ML_DSA-65"] {
            let policy = identifierPolicy(
                owner: accountId,
                resolverPublicKey: "\(prefix):\(publicKeyMultihash)"
            )
            XCTAssertEqual(try shortReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false, prefix)

            for suite in [MlDsaSuite.mlDsa44, .mlDsa87] {
                let signature = Data(
                    repeating: 0x33,
                    count: min(suite.parameters().signatureLength, params.signatureLength)
                )
                let receipt = try identifierReceipt(
                    payload: payload,
                    signatureHex: signature.hexUppercased()
                )
                XCTAssertEqual(
                    try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical),
                    false,
                    "protocol ML-DSA verification must reject the in-bound \(suite) signature for \(prefix)"
                )
            }
        }
    }

    func testIdentifierReceiptVerifierPinsMlDsa65ProtocolSuite() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.mldsaSupported,
            "ML-DSA bridge is unavailable in this environment."
        )
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadBytes = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)
        var message = Blake2b.hash256(payloadBytes)
        message[message.count - 1] |= 0x01

        for suite in MlDsaSuite.allCases {
            let keypair = try MlDsaKeypair.generate(suite: suite)
            let signature = try keypair.sign(message: message)
            let multihash = CanonicalNorito.publicKeyMultihash(
                algorithm: .mlDsa,
                payload: keypair.publicKey
            )
            if signature.count > MlDsaSuite.mlDsa65.parameters().signatureLength {
                XCTAssertThrowsError(try identifierReceipt(
                    payload: payload,
                    signatureHex: signature.hexUppercased()
                )) { error in
                    guard case let DecodingError.dataCorrupted(context) = error else {
                        return XCTFail("Expected signature-bound decode refusal, got \(error)")
                    }
                    XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "signature"])
                    XCTAssertTrue(context.debugDescription.contains("exceeds the canonical signature bound"))
                }
            }
            // Keep wrong-suite key rejection reachable within the DTO's wire bound.
            // The actual ML-DSA-65 signature remains unchanged and must verify.
            let boundedSignature = Data(signature.prefix(MlDsaSuite.mlDsa65.parameters().signatureLength))
            let receipt = try identifierReceipt(
                payload: payload,
                signatureHex: boundedSignature.hexUppercased()
            )

            for resolverPublicKey in ["ml-dsa:\(multihash)", multihash] {
                let policy = identifierPolicy(
                    owner: accountId,
                    resolverPublicKey: resolverPublicKey
                )
                XCTAssertEqual(
                    try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical),
                    suite == .mlDsa65,
                    "protocol verification must accept only ML-DSA-65 for \(resolverPublicKey)"
                )
            }
        }
    }

    func testIdentifierReceiptRejectsMalformedEd25519AttestationRBeforeCryptoKit() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let policy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let validReceipt = try identifierReceipt(
            payload: payload,
            signatureHex: signed.signatureHex
        )
        XCTAssertEqual(try validReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)

        let smallOrderR = Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let noncanonicalR = Data([
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ])

        for (label, replacementR) in [
            ("small-order", smallOrderR),
            ("noncanonical", noncanonicalR),
        ] {
            var signature = try XCTUnwrap(Data(hexString: signed.signatureHex))
            signature.replaceSubrange(0..<replacementR.count, with: replacementR)
            let receipt = try identifierReceipt(
                payload: payload,
                signatureHex: signature.hexUppercased()
            )

            XCTAssertEqual(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false, label)
        }
    }

    func testIdentifierReceiptRejectsUaidMutationAfterSigning() throws {
        let accountId = try canonicalOwnerLiteral()
        let originalPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let mutatedPayload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))37",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: originalPayload)
        let policy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let originalReceipt = try identifierReceipt(
            payload: originalPayload,
            signatureHex: signed.signatureHex
        )
        let mutatedReceipt = try identifierReceipt(
            payload: mutatedPayload,
            signatureHex: signed.signatureHex
        )

        XCTAssertEqual(try originalReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertEqual(try mutatedReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), false)
    }

    func testIdentifierReceiptRejectsMismatchedPolicySummaryBeforeSignatureVerification() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)
        let policy = identifierPolicy(
            policyId: "email#retail",
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )

        XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("expected invalid payload error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("does not match policy summary"))
        }
    }

    func testIdentifierReceiptRejectsWrongResolverPublicKey() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let otherSigned = try signedIdentifierReceiptFixture(payload: payload)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)
        let validPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let wrongKeyPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: otherSigned.resolverPublicKey
        )

        XCTAssertNotEqual(signed.resolverPublicKey, otherSigned.resolverPublicKey)
        XCTAssertEqual(try receipt.verifyResolverAttestation(using: validPolicy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertEqual(try receipt.verifyResolverAttestation(using: wrongKeyPolicy, intendedNetworkId: TestNetworkIds.canonical), false)
    }

    func testIdentifierReceiptRejectsMalformedResolverPublicKey() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)
        let validPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let malformedPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: "ed25519:not-hex"
        )

        XCTAssertEqual(try receipt.verifyResolverAttestation(using: validPolicy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: malformedPolicy, intendedNetworkId: TestNetworkIds.canonical)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("expected invalid payload error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("resolverPublicKey"))
        }
    }

    func testIdentifierReceiptRejectsConfusableResolverPublicKeyPrefixes() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let multihash = try XCTUnwrap(signed.resolverPublicKey.split(separator: ":").last)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)

        for prefix in [
            "ed 25519",
            "ed.25519",
            "ed/25519",
            "ed@25519",
            "ed#25519",
            "secp256\u{212A}1",
            "ml\u{FF0D}dsa",
        ] {
            let policy = identifierPolicy(
                owner: accountId,
                resolverPublicKey: "\(prefix):\(multihash)"
            )
            XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical), prefix) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("unexpected error for \(prefix): \(error)")
                }
                XCTAssertTrue(reason.contains("Unsupported resolver public-key prefix"), prefix)
            }
        }
    }

    func testIdentifierReceiptRejectsMalformedEd25519ResolverPublicKeyBeforeCryptoKit() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)
        let validPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        XCTAssertEqual(try receipt.verifyResolverAttestation(using: validPolicy, intendedNetworkId: TestNetworkIds.canonical), true)

        let smallOrderKey = Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let noncanonicalKey = Data([
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ])

        for (label, rawPublicKey) in [
            ("all-zero", Data(repeating: 0, count: 32)),
            ("small-order", smallOrderKey),
            ("noncanonical", noncanonicalKey),
        ] {
            let multihash = CanonicalNorito.publicKeyMultihash(
                algorithm: .ed25519,
                payload: rawPublicKey
            )
            let malformedPolicy = identifierPolicy(
                owner: accountId,
                resolverPublicKey: "ed25519:\(multihash)"
            )
            XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: malformedPolicy, intendedNetworkId: TestNetworkIds.canonical), label) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    XCTFail("expected invalid payload error, got \(error)")
                    return
                }
                XCTAssertTrue(reason.contains("valid Ed25519 public key"), label)
            }
        }
    }

    func testIdentifierReceiptRejectsResolverPublicKeyPrefixMismatch() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let multihash = try XCTUnwrap(signed.resolverPublicKey.split(separator: ":").last)
        let receipt = try identifierReceipt(payload: payload, signatureHex: signed.signatureHex)
        let validPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )
        let mismatchedPrefixPolicy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: "secp256k1:\(multihash)"
        )

        XCTAssertEqual(try receipt.verifyResolverAttestation(using: validPolicy, intendedNetworkId: TestNetworkIds.canonical), true)
        XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: mismatchedPrefixPolicy, intendedNetworkId: TestNetworkIds.canonical)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("expected invalid payload error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("prefix does not match"))
        }
    }

    func testIdentifierReceiptRejectsMalformedAttestationSignatureHex() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )

        XCTAssertThrowsError(try identifierReceipt(payload: payload, signatureHex: "GG")) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "signature"])
            XCTAssertTrue(context.debugDescription.contains("requires exact lowercase raw hex"))
            XCTAssertTrue(context.underlyingError is ToriiClientError)
        }
    }

    func testIdentifierReceiptPreservesSignatureTypeMismatchDuringDecode() throws {
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: try canonicalOwnerLiteral(),
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "hkdf-sha3-512-prf-v1"
        )
        let json = try identifierReceiptJSON(payload: payload, signatureHex: "01")
            .replacingOccurrences(of: "\"signature\":\"01\"", with: "\"signature\":17")
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiIdentifierResolutionReceipt.self, from: Data(json.utf8))) { error in
            guard case let DecodingError.typeMismatch(type, context) = error else {
                return XCTFail("expected signature typeMismatch, got \(error)")
            }
            XCTAssertTrue(type == String.self)
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "signature"])
        }
    }

    func testIdentifierReceiptCanonicalPayloadRejectsNonExactExecutionTags() throws {
        let accountId = try canonicalOwnerLiteral()
        for (payload, expectedReason) in [
            (
                makeSignedIdentifierReceiptPayload(
                    policyId: " phone#retail",
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "policyId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    policyId: "phone#retail ",
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "policyId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    policyId: "phone #retail",
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "policyId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    policyId: "phone# retail",
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "policyId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    programId: " identifier_lookup_retail"
                ),
                "programId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: " \(accountId)",
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "accountId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: "\(accountId) ",
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "accountId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: " opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "opaque_id"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: "\(String(repeating: "22", count: 31))23 ",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "receipt_hash"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: " uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1"
                ),
                "uaid"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    programDigestHex: " \(String(repeating: "11", count: 32))"
                ),
                "program_digest"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    inputCiphertextHashHex: "\(String(repeating: "ab", count: 32)) "
                ),
                "input_ciphertext_hash"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    programId: "identifier_lookup_retail "
                ),
                "programId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    openingProgramId: " identifier_lookup_retail"
                ),
                "programId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    openingProgramId: "identifier_lookup_retail "
                ),
                "programId"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: " bfv-affine-v1"
                ),
                "backend"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "BFV-AFFINE-SHA3-256-V1"
                ),
                "backend"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    verificationMode: "signed "
                ),
                "verificationMode"
            ),
            (
                makeSignedIdentifierReceiptPayload(
                    accountId: accountId,
                    opaqueId: "opaque:\(String(repeating: "11", count: 32))",
                    receiptHash: String(repeating: "22", count: 31) + "23",
                    uaid: "uaid:\(String(repeating: "33", count: 31))35",
                    backend: "bfv-affine-v1",
                    verificationMode: "Signed"
                ),
                "verificationMode"
            ),
        ] {
            XCTAssertThrowsError(try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(payload)) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    XCTFail("expected invalid payload error, got \(error)")
                    return
                }
                let normalizedReason = reason.replacingOccurrences(of: "_", with: "").lowercased()
                let normalizedExpectedReason = expectedReason.replacingOccurrences(of: "_", with: "").lowercased()
                XCTAssertTrue(normalizedReason.contains(normalizedExpectedReason), reason)
            }
        }
    }

    func testIdentifierReceiptDecodeRejectsNonExactExecutionTags() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadData = try JSONEncoder().encode(payload)
        let payloadObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
        )

        for policyId in [" phone#retail", "phone#retail ", "phone #retail", "phone# retail"] {
            var mutatedPayload = payloadObject
            mutatedPayload["policy_id"] = policyId
            let mutatedData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedData
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("policy_id"))
            }
        }

        for programId in [" identifier_lookup_retail", "identifier_lookup_retail "] {
            var mutatedPayload = payloadObject
            var execution = try XCTUnwrap(mutatedPayload["execution"] as? [String: Any])
            execution["program_id"] = programId
            mutatedPayload["execution"] = execution
            let mutatedData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedData
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("program_id"))
            }

            mutatedPayload = payloadObject
            var opening = try XCTUnwrap(mutatedPayload["opening"] as? [String: Any])
            var openingPayload = try XCTUnwrap(opening["payload"] as? [String: Any])
            openingPayload["program_id"] = programId
            opening["payload"] = openingPayload
            mutatedPayload["opening"] = opening
            let mutatedOpeningData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedOpeningData
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("program_id"))
            }
        }

        for paddedAccountId in [" \(accountId)", "\(accountId) "] {
            var mutatedPayload = payloadObject
            mutatedPayload["account_id"] = paddedAccountId
            let mutatedData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedData
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("payload.account_id"))
                XCTAssertTrue(context.debugDescription.contains("surrounding whitespace"))
            }
        }

        let hashExactnessCases: [(path: [String], value: String, reason: String)] = [
            (["opaque_id"], " \(try XCTUnwrap(payloadObject["opaque_id"] as? String))", "opaque_id"),
            (["receipt_hash"], "\(try XCTUnwrap(payloadObject["receipt_hash"] as? String)) ", "receipt_hash"),
            (["uaid"], " \(try XCTUnwrap(payloadObject["uaid"] as? String))", "uaid"),
            (
                ["execution", "program_digest"],
                " \(try XCTUnwrap(try XCTUnwrap(payloadObject["execution"] as? [String: Any])["program_digest"] as? String))",
                "program_digest"
            ),
            (
                ["opening", "payload", "input_ciphertext_hash"],
                "\(try XCTUnwrap(try XCTUnwrap(try XCTUnwrap(payloadObject["opening"] as? [String: Any])["payload"] as? [String: Any])["input_ciphertext_hash"] as? String)) ",
                "input_ciphertext_hash"
            ),
        ]
        for testCase in hashExactnessCases {
            var mutatedPayload = payloadObject
            if testCase.path.count == 1 {
                mutatedPayload[testCase.path[0]] = testCase.value
            } else if testCase.path == ["execution", "program_digest"] {
                var execution = try XCTUnwrap(mutatedPayload["execution"] as? [String: Any])
                execution["program_digest"] = testCase.value
                mutatedPayload["execution"] = execution
            } else {
                var opening = try XCTUnwrap(mutatedPayload["opening"] as? [String: Any])
                var openingPayload = try XCTUnwrap(opening["payload"] as? [String: Any])
                openingPayload["input_ciphertext_hash"] = testCase.value
                opening["payload"] = openingPayload
                mutatedPayload["opening"] = opening
            }
            let mutatedData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedData
                )
            ) { error in
                if case let DecodingError.dataCorrupted(context) = error {
                    XCTAssertTrue(context.debugDescription.contains(testCase.reason))
                } else if case let ToriiClientError.invalidPayload(reason) = error {
                    XCTAssertTrue(reason.contains(testCase.reason))
                } else {
                    XCTFail("expected exactness decode error, got \(error)")
                }
            }
        }

        var emptyAccountPayload = payloadObject
        emptyAccountPayload["account_id"] = " \n\t "
        let emptyAccountData = try JSONSerialization.data(
            withJSONObject: emptyAccountPayload,
            options: []
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionPayload.self,
                from: emptyAccountData
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertTrue(context.debugDescription.contains("account_id"))
        }

        for (field, value) in [
            ("backend", " bfv-affine-v1"),
            ("backend", "BFV-AFFINE-SHA3-256-V1"),
            ("verification_mode", "signed "),
            ("verification_mode", "Signed"),
        ] {
            var mutatedPayload = payloadObject
            var execution = try XCTUnwrap(mutatedPayload["execution"] as? [String: Any])
            execution[field] = value
            mutatedPayload["execution"] = execution
            let mutatedData = try JSONSerialization.data(
                withJSONObject: mutatedPayload,
                options: []
            )

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionPayload.self,
                    from: mutatedData
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains(field))
            }
        }
    }

    func testIdentifierReceiptRejectsProofAttestationVerificationWithResolverKey() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"proof",
            "proof_backend":"ram-lfe-v1",
            "proof_b64":"AAAA"
          }
        }
        """
        let receipt = try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self,
            from: Data(receiptJSON.utf8)
        )
        let policy = identifierPolicy(
            owner: accountId,
            resolverPublicKey: signed.resolverPublicKey
        )

        XCTAssertThrowsError(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: TestNetworkIds.canonical)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                XCTFail("expected invalid payload error, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("Only signed identifier receipt attestations"))
        }
    }

    func testIdentifierReceiptRejectsPaddedProofAttestationBackendDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )

        for proofBackend in [" ram-lfe-v1", "ram-lfe-v1 "] {
            let receiptJSON = """
            {
              "payload":\(payloadJSON),
              "attestation":{
                "kind":"proof",
                "proof_backend":"\(proofBackend)",
                "proof_b64":"AAAA"
              }
            }
            """

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionReceipt.self,
                    from: Data(receiptJSON.utf8)
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("proof_backend"))
            }
        }
    }

    func testIdentifierReceiptRejectsNonExactAttestationKindDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )

        for kind in [" signed", "signed ", "Signed"] {
            let receiptJSON = """
            {
              "payload":\(payloadJSON),
              "attestation":{
                "kind":"\(kind)",
                "signature":"A1B2C3D4"
              }
            }
            """

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionReceipt.self,
                    from: Data(receiptJSON.utf8)
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("kind"))
            }
        }
    }

    func testIdentifierReceiptRejectsPaddedPayloadAccountIdDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )

        for paddedAccountId in [" \(accountId)", "\(accountId) "] {
            let paddedPayloadJSON = payloadJSON.replacingOccurrences(
                of: "\"account_id\":\"\(accountId)\"",
                with: "\"account_id\":\"\(paddedAccountId)\""
            )
            let receiptJSON = """
            {
              "payload":\(paddedPayloadJSON),
              "attestation":{
                "kind":"signed",
                "signature":"\(signed.signatureHex)"
              }
            }
            """

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionReceipt.self,
                    from: Data(receiptJSON.utf8)
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("payload.account_id"))
                XCTAssertTrue(context.debugDescription.contains("surrounding whitespace"))
            }
        }
    }

    func testIdentifierReceiptRejectsMalformedProofAttestationBase64DuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"proof",
            "proof_backend":"ram-lfe-v1",
            "proof_b64":"@@@"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertTrue(context.debugDescription.contains("proof_b64"))
        }
    }

    func testIdentifierReceiptRejectsPaddedProofAttestationBase64DuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )

        for proofB64 in [" AAAA", "AAAA "] {
            let receiptJSON = """
            {
              "payload":\(payloadJSON),
              "attestation":{
                "kind":"proof",
                "proof_backend":"ram-lfe-v1",
                "proof_b64":"\(proofB64)"
              }
            }
            """

            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiIdentifierResolutionReceipt.self,
                    from: Data(receiptJSON.utf8)
                )
            ) { error in
                guard case let DecodingError.dataCorrupted(context) = error else {
                    XCTFail("expected dataCorrupted decode error, got \(error)")
                    return
                }
                XCTAssertTrue(context.debugDescription.contains("proof_b64"))
            }
        }
    }

    func testIdentifierReceiptVerifierMatchesSharedReceiptVectors() throws {
        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/soracloud/identifier_receipt_vectors_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
        )
        XCTAssertEqual(try string(fixture, "vector_set"), "identifier-receipt-attestation-v1")
        let intendedNetworkId = try ToriiIdentifierOwnerContract.network("5e60c5da42509f0077c6adf39b7dd708611eb4d6a9f1cbb71769092c26d20bf1")
        let receiptObject = try object(fixture, "receipt")
        let policyObject = try object(fixture, "policy")
        let receipt = try identifierReceipt(fromFixture: receiptObject)
        let policy = try identifierReceiptPolicy(fromFixture: policyObject)

        let payloadBytes = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(receipt.payload)
        XCTAssertEqual(sha256Hex(payloadBytes), try string(fixture, "canonical_payload_sha256"))
        XCTAssertEqual(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: intendedNetworkId), true)

        for vector in try objectArray(fixture, "attestation_vectors") {
            let name = try string(vector, "name")
            let attestationObject = try object(vector, "attestation")
            let attestation = try identifierReceiptAttestation(fromFixture: attestationObject)
            let encoded = try ToriiIdentifierReceiptCanonicalEncoder.encodeAttestation(attestation)
            XCTAssertEqual(
                encoded.count,
                try int(vector, "expected_attestation_bytes"),
                "\(name) attestation byte length"
            )
            XCTAssertEqual(
                sha256Hex(encoded),
                try string(vector, "expected_attestation_sha256"),
                "\(name) attestation digest"
            )
            if attestation.kind == "proof" {
                var proofReceiptObject = receiptObject
                proofReceiptObject["attestation"] = attestationObject
                let proofReceipt = try identifierReceipt(fromFixture: proofReceiptObject)
                XCTAssertThrowsError(
                    try proofReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: intendedNetworkId),
                    "\(name) proof verifier gate"
                ) { error in
                    guard case let ToriiClientError.invalidPayload(reason) = error else {
                        XCTFail("expected invalid payload error, got \(error)")
                        return
                    }
                    XCTAssertTrue(reason.contains("Only signed identifier receipt attestations"))
                }
            }
        }

        for negative in try objectArray(fixture, "negative_cases") {
            let negativeName = try string(negative, "name")
            let mutation = try string(negative, "mutation")
            var mutatedReceiptObject = receiptObject
            var mutatedPolicyObject = policyObject
            let independentlySelectedNetwork = mutation == "receipt.payload.network_id" ? try ToriiIdentifierOwnerContract.network(string(negative, "value")) : intendedNetworkId
            switch mutation {
            case "receipt.payload.network_id":
                var payload = try object(mutatedReceiptObject, "payload")
                payload["network_id"] = try string(negative, "value")
                mutatedReceiptObject["payload"] = payload
            case "receipt.payload.execution.output_ciphertext_hash":
                var payload = try object(mutatedReceiptObject, "payload")
                var execution = try object(payload, "execution")
                execution["output_ciphertext_hash"] = try string(negative, "value")
                payload["execution"] = execution
                mutatedReceiptObject["payload"] = payload
            case "policy.resolver_public_key":
                mutatedPolicyObject["resolver_public_key"] = try string(negative, "value")
            case "policy.policy_id":
                mutatedPolicyObject["policy_id"] = try string(negative, "value")
            case "receipt.attestation.signature":
                var attestation = try object(mutatedReceiptObject, "attestation")
                attestation["signature"] = try string(negative, "value")
                mutatedReceiptObject["attestation"] = attestation
            case "receipt.attestation":
                mutatedReceiptObject["attestation"] = try object(negative, "value")
            default:
                XCTFail("Unhandled receipt vector mutation \(mutation)")
                continue
            }

            if let expectedError = negative["expected_error_contains"] as? String {
                do {
                    let mutatedReceipt = try identifierReceipt(fromFixture: mutatedReceiptObject)
                    let mutatedPolicy = try identifierReceiptPolicy(fromFixture: mutatedPolicyObject)
                    XCTAssertThrowsError(
                        try mutatedReceipt.verifyResolverAttestation(using: mutatedPolicy, intendedNetworkId: independentlySelectedNetwork),
                        negativeName
                    )
                } catch let DecodingError.dataCorrupted(context) {
                    XCTAssertTrue(
                        context.debugDescription.localizedCaseInsensitiveContains(expectedError),
                        negativeName
                    )
                }
            } else {
                let mutatedReceipt = try identifierReceipt(fromFixture: mutatedReceiptObject)
                let mutatedPolicy = try identifierReceiptPolicy(fromFixture: mutatedPolicyObject)
                XCTAssertEqual(
                    try mutatedReceipt.verifyResolverAttestation(using: mutatedPolicy, intendedNetworkId: independentlySelectedNetwork),
                    try bool(negative, "expected_result"),
                    negativeName
                )
            }
        }
    }

    func testIdentifierReceiptRejectsSignedAttestationMissingSignatureDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"signed"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation"])
            XCTAssertTrue(context.debugDescription.contains("requires its exact current fields"))
        }
    }

    func testIdentifierReceiptRejectsPaddedSignedAttestationSignatureDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"signed",
            "signature":" \(signed.signatureHex)"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "signature"])
            XCTAssertTrue(context.debugDescription.contains("surrounding whitespace"))
        }
    }

    func testIdentifierReceiptRejectsPaddedOpeningSignatureDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        ).replacingOccurrences(
            of: "\"signature\":\"\(payload.opening.signature)\"",
            with: "\"signature\":\"\(payload.opening.signature) \""
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"signed",
            "signature":"\(signed.signatureHex)"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["payload", "opening", "signature"])
            XCTAssertTrue(context.debugDescription.contains("requires exact lowercase raw hex"))
        }
    }

    func testIdentifierReceiptRejectsSignedAttestationWithProofFieldsDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"signed",
            "signature":"\(signed.signatureHex)",
            "proof_backend":"ram-lfe-v1",
            "proof_b64":"AAAA"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation"])
            XCTAssertTrue(context.debugDescription.contains("requires its exact current fields"))
        }
    }

    func testIdentifierReceiptRejectsUnknownAttestationKindDuringDecode() throws {
        let accountId = try canonicalOwnerLiteral()
        let payload = makeSignedIdentifierReceiptPayload(
            accountId: accountId,
            opaqueId: "opaque:\(String(repeating: "11", count: 32))",
            receiptHash: String(repeating: "22", count: 31) + "23",
            uaid: "uaid:\(String(repeating: "33", count: 31))35",
            backend: "bfv-affine-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: payload)
        let payloadJSON = try XCTUnwrap(
            String(data: JSONEncoder().encode(payload), encoding: .utf8)
        )
        let receiptJSON = """
        {
          "payload":\(payloadJSON),
          "attestation":{
            "kind":"unsigned",
            "signature":"\(signed.signatureHex)"
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(
                ToriiIdentifierResolutionReceipt.self,
                from: Data(receiptJSON.utf8)
            )
        ) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                XCTFail("expected dataCorrupted decode error, got \(error)")
                return
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["attestation", "kind"])
            XCTAssertTrue(context.debugDescription.contains("must be signed or proof"))
        }
    }

    func testIdentifierReceiptCanonicalPayloadRejectsLegacyReceiptAndSignature() throws {
        let accountId = "sorauﾛ1NiGｸﾛﾋRuﾎQtﾐpヱﾈｻHﾍﾐ3RZﾕYdvbｺhcｽG8A8ｿRﾗeP1E463"
        let receiptJSON = """
        {
          "payload":{
            "policy_id":"email#retail",
            "execution":{
              "program_id":"email_retail",
              "program_digest":"fe36ceb3996d101200b895fd2a377cce4426426a473da9fe08b2dbd2bd8b9375",
              "backend":"bfv-programmed-v1",
              "verification_mode":"signed",
              "input_ciphertext_hash":"abababababababababababababababababababababababababababababababab",
              "output_ciphertext_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "parameter_digest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "evaluation_key_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
              "output_hash":"72dcdee1435552e943d5e2e1c978d3f728c6a1ce7e6870b50c63568d4876eea5",
              "associated_data_hash":"35b8bc8a30685e7cc5679b6e6a45675539548f5a24326bbee1d8c20e55918f55",
              "executed_at_ms":1776812470694,
              "expires_at_ms":1776812500694
            },
            "opening":{
              "payload":{
                "program_id":"email_retail",
                "input_ciphertext_hash":"abababababababababababababababababababababababababababababababab",
                "output_ciphertext_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "parameter_digest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "evaluation_key_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "opened_output_hash":"72dcdee1435552e943d5e2e1c978d3f728c6a1ce7e6870b50c63568d4876eea5",
                "opened_at_ms":1776812470694,
                "expires_at_ms":1776812500694
              },
              "signature":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            },
            "opaque_id":"opaque:fd14cb369e853352d4b9c578745627d154471ce5fd3462c4db542c104766e983",
            "receipt_hash":"51bbe55b70e09d4c2bb75d9c31b2cde46a7bdd5414134f6786255c679a68ac53",
            "uaid":"uaid:471b620a99c608af1c7a47199f27b3368ae0ea889a497dd774b52a8287a58393",
            "account_id":"\(accountId)"
          },
          "attestation":{
            "kind":"signed",
            "signature":"4B26BF33F721C551C13F102D4D7F483CB8DD8A13FD6BF4ED26C845E2B69D5D0124B8CFA05493772F6748A42408EEE4542C470B284AB87F686B423F9DF87C8D00"
          }
        }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(
            ToriiIdentifierResolutionReceipt.self, from: Data(receiptJSON.utf8)
        )) { error in
            guard case let DecodingError.dataCorrupted(context) = error else {
                return XCTFail("expected legacy payload decode rejection, got \(error)")
            }
            XCTAssertEqual(context.codingPath.map(\.stringValue), ["payload"])
            XCTAssertTrue(context.debugDescription.contains("requires its exact current fields"))
        }

        // The same historical signature is also refused after projecting the fixture into
        // the current network-bound layout with the original lowercase opening signature.
        var currentObject = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(receiptJSON.utf8)) as? [String: Any])
        var currentPayload = try object(currentObject, "payload")
        currentPayload["network_id"] = ToriiIdentifierOwnerContract.rawNetwork(TestNetworkIds.canonical)
        var currentOpening = try object(currentPayload, "opening")
        currentOpening["signature"] = String(repeating: "ff", count: 64)
        currentPayload["opening"] = currentOpening
        currentObject["payload"] = currentPayload
        let currentReceipt = try identifierReceipt(fromFixture: currentObject)
        XCTAssertFalse(try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(currentReceipt.payload).isEmpty)
        let historicalPolicy = ToriiIdentifierPolicySummary(
            policyId: "email#retail",
            programId: "identifier_lookup_retail",
            owner: accountId,
            active: true,
            normalization: .emailAddress,
            resolverPublicKey: "ed01200376E59E9078B647F55003896B59758B7BE99908535EC24BAF80A6D52C8B3EB8",
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-programmed-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        XCTAssertFalse(try currentReceipt.verifyResolverAttestation(
            using: historicalPolicy, intendedNetworkId: TestNetworkIds.canonical))

        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/soracloud/identifier_receipt_vectors_v1.json")
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any])
        let receipt = try identifierReceipt(fromFixture: object(fixture, "receipt"))
        let policy = try identifierReceiptPolicy(fromFixture: object(fixture, "policy"))
        let intendedNetworkId = try ToriiIdentifierOwnerContract.network("5e60c5da42509f0077c6adf39b7dd708611eb4d6a9f1cbb71769092c26d20bf1")
        let payloadBytes = try ToriiIdentifierReceiptCanonicalEncoder.encodePayload(receipt.payload)
        XCTAssertFalse(payloadBytes.isEmpty)
        XCTAssertEqual(sha256Hex(payloadBytes), try string(fixture, "canonical_payload_sha256"))
        XCTAssertTrue(try receipt.verifyResolverAttestation(using: policy, intendedNetworkId: intendedNetworkId))
        let legacySignatureReceipt = try identifierReceipt(
            payload: receipt.payload,
            signatureHex: "4B26BF33F721C551C13F102D4D7F483CB8DD8A13FD6BF4ED26C845E2B69D5D0124B8CFA05493772F6748A42408EEE4542C470B284AB87F686B423F9DF87C8D00"
        )
        XCTAssertFalse(try legacySignatureReceipt.verifyResolverAttestation(using: policy, intendedNetworkId: intendedNetworkId))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveIdentifierRejectsInvalidAttestationPayload() async throws {
        let accountId = try canonicalOwnerLiteral()
        let opaqueId = "opaque:\(String(repeating: "41", count: 32))"
        let receiptHash = String(repeating: "51", count: 32)
        let uaid = "uaid:\(String(repeating: "61", count: 31))63"
        let signedPayload = makeSignedIdentifierReceiptPayload(
            policyId: "email#retail",
            accountId: accountId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            backend: "hkdf-sha3-512-prf-v1"
        )
        let signed = try signedIdentifierReceiptFixture(payload: signedPayload)

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifiers/resolve")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "policy_id":"email#retail",
              "opaque_id":"\(opaqueId)",
              "receipt_hash":"\(receiptHash)",
              "uaid":"\(uaid)",
              "account_id":"\(accountId)",
              "resolved_at_ms":42,
              "expires_at_ms":142,
              "backend":"hkdf-sha3-512-prf-v1",
              "signature":"\(signed.signatureHex)",
              "signature_payload_hex":"01020304A0"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().resolveIdentifier(
            try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: signedPayload.opening),
            canonicalAuth: canonicalReadAuth
            )
            XCTFail("Expected invalidPayload error")
        } catch let ToriiClientError.invalidPayload(reason) {
            XCTAssertTrue(reason.contains("claim-receipt decode failed"))
            XCTAssertTrue(reason.contains("body_len="))
            XCTAssertTrue(reason.contains("body_sha256="))
            XCTAssertFalse(reason.contains(accountId))
            XCTAssertFalse(reason.contains(opaqueId))
            XCTAssertFalse(reason.contains("signature_payload_hex"))
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveIdentifierReturnsNilOnNotFound() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifiers/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["policy_id"] as? String, "email#retail")
            XCTAssertNil(payload["encrypted_input"])
            XCTAssertEqual(payload["normalized_input"] as? String, "private@example.org")
            XCTAssertEqual(payload["input_nonce"] as? String, String(repeating: "12", count: 32))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, Data())
        }

        let receipt = try await makeClient().resolveIdentifier(
            try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: sampleOpening()),
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertNil(receipt)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testResolveIdentifierDecodesNestedExecutionPayload() async throws {
        let accountId = try canonicalOwnerLiteral()
        let opaqueId = "opaque:\(String(repeating: "77", count: 32))"
        let receiptHash = String(repeating: "88", count: 31) + "89"
        let outputHash = String(repeating: "22", count: 31) + "23"
        let uaid = "uaid:\(String(repeating: "99", count: 31))9b"
        let signedPayload = makeSignedIdentifierReceiptPayload(
            policyId: "email#retail",
            accountId: accountId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            backend: "hkdf-sha3-512-prf-v1",
            outputHashHex: outputHash,
            resolvedAtMs: 42,
            expiresAtMs: 142
        )
        let signed = try signedIdentifierReceiptFixture(payload: signedPayload)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/identifiers/resolve")
            XCTAssertEqual(request.httpMethod, "POST")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = try self.identifierReceiptJSON(
                payload: signedPayload,
                signatureHex: signed.signatureHex
            ).data(using: .utf8)!
            return (response, body)
        }

        let receipt = try await makeClient().resolveIdentifier(
            try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: signedPayload.opening),
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(receipt?.resolvedAtMs, 42)
        XCTAssertEqual(receipt?.expiresAtMs, 142)
        XCTAssertEqual(receipt?.payload.policyId, "email#retail")
        XCTAssertEqual(receipt?.payload.opaqueId, opaqueId)
        XCTAssertEqual(receipt?.payload.receiptHash, receiptHash)
        XCTAssertEqual(receipt?.payload.uaid, uaid)
        XCTAssertEqual(receipt?.payload.execution.programId, "identifier_lookup_retail")
        XCTAssertEqual(receipt?.payload.execution.programDigest, String(repeating: "11", count: 32))
        XCTAssertEqual(receipt?.payload.execution.verificationMode, "signed")
        XCTAssertEqual(receipt?.payload.execution.inputCiphertextHash, String(repeating: "ab", count: 32))
        XCTAssertEqual(receipt?.payload.execution.outputCiphertextHash, String(repeating: "bb", count: 32))
        XCTAssertEqual(receipt?.payload.execution.parameterDigest, String(repeating: "cd", count: 32))
        XCTAssertEqual(receipt?.payload.execution.evaluationKeyDigest, String(repeating: "dd", count: 32))
        XCTAssertEqual(receipt?.payload.execution.outputHash, outputHash)
        XCTAssertEqual(receipt?.payload.execution.associatedDataHash, String(repeating: "33", count: 32))
        XCTAssertEqual(receipt?.payload.execution.executedAtMs, 42)
        XCTAssertEqual(receipt?.payload.execution.expiresAtMs, 142)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIssueIdentifierClaimReceiptAsync() async throws {
        let accountId = try canonicalOwnerLiteral()
        let opaqueId = "opaque:\(String(repeating: "44", count: 31))45"
        let receiptHash = String(repeating: "55", count: 32)
        let uaid = "uaid:\(String(repeating: "66", count: 31))67"
        let signedPayload = makeSignedIdentifierReceiptPayload(
            policyId: "email#retail",
            accountId: accountId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            backend: "hkdf-sha3-512-prf-v1",
            resolvedAtMs: 7,
            expiresAtMs: 77
        )
        let signed = try signedIdentifierReceiptFixture(payload: signedPayload)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(
                request.url?.path,
                "/v1/accounts/\(accountId)/identifiers/claim-receipt"
            )
            XCTAssertEqual(request.httpMethod, "POST")
            let payload = self.bodyJSON(from: request)
            XCTAssertEqual(payload["policy_id"] as? String, "email#retail")
            XCTAssertNil(payload["encrypted_input"])
            XCTAssertEqual(payload["normalized_input"] as? String, "private@example.org")
            XCTAssertEqual(payload["input_nonce"] as? String, String(repeating: "12", count: 32))
            XCTAssertNotNil(payload["output_opening"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = try self.identifierReceiptJSON(
                payload: signedPayload,
                signatureHex: signed.signatureHex
            ).data(using: .utf8)!
            return (response, body)
        }

        let receipt = try await makeClient().issueIdentifierClaimReceipt(
            accountId: accountId,
            requestBody: try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: signedPayload.opening),
            canonicalAuth: canonicalReadAuth(accountId: accountId, privateKeyByte: 1)
        )
        XCTAssertEqual(receipt?.opaqueId, opaqueId)
        XCTAssertEqual(receipt?.receiptHash, receiptHash)
        XCTAssertEqual(receipt?.uaid, uaid)
        XCTAssertEqual(receipt?.accountId, accountId)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIssueIdentifierClaimReceiptDecodesNestedExecutionPayload() async throws {
        let accountId = try canonicalOwnerLiteral()
        let opaqueId = "opaque:\(String(repeating: "aa", count: 31))ab"
        let receiptHash = String(repeating: "bb", count: 32)
        let programDigest = String(repeating: "12", count: 31) + "13"
        let outputHash = String(repeating: "23", count: 32)
        let associatedDataHash = String(repeating: "34", count: 31) + "35"
        let uaid = "uaid:\(String(repeating: "cc", count: 31))cd"
        let signedPayload = makeSignedIdentifierReceiptPayload(
            policyId: "email#retail",
            accountId: accountId,
            opaqueId: opaqueId,
            receiptHash: receiptHash,
            uaid: uaid,
            backend: "hkdf-sha3-512-prf-v1",
            programDigestHex: programDigest,
            outputHashHex: outputHash,
            associatedDataHashHex: associatedDataHash,
            resolvedAtMs: 7,
            expiresAtMs: 77
        )
        let signed = try signedIdentifierReceiptFixture(payload: signedPayload)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(
                request.url?.path,
                "/v1/accounts/\(accountId)/identifiers/claim-receipt"
            )
            XCTAssertEqual(request.httpMethod, "POST")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = try self.identifierReceiptJSON(
                payload: signedPayload,
                signatureHex: signed.signatureHex
            ).data(using: .utf8)!
            return (response, body)
        }

        let receipt = try await makeClient().issueIdentifierClaimReceipt(
            accountId: accountId,
            requestBody: try .claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: signedPayload.opening),
            canonicalAuth: canonicalReadAuth(accountId: accountId, privateKeyByte: 1)
        )
        XCTAssertEqual(receipt?.resolvedAtMs, 7)
        XCTAssertEqual(receipt?.expiresAtMs, 77)
        XCTAssertEqual(receipt?.payload.policyId, "email#retail")
        XCTAssertEqual(receipt?.payload.opaqueId, opaqueId)
        XCTAssertEqual(receipt?.payload.receiptHash, receiptHash)
        XCTAssertEqual(receipt?.payload.uaid, uaid)
        XCTAssertEqual(receipt?.payload.execution.programId, "identifier_lookup_retail")
        XCTAssertEqual(receipt?.payload.execution.programDigest, programDigest)
        XCTAssertEqual(receipt?.payload.execution.verificationMode, "signed")
        XCTAssertEqual(receipt?.payload.execution.outputHash, outputHash)
        XCTAssertEqual(receipt?.payload.execution.associatedDataHash, associatedDataHash)
        XCTAssertEqual(receipt?.payload.execution.executedAtMs, 7)
        XCTAssertEqual(receipt?.payload.execution.expiresAtMs, 77)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIssueIdentifierClaimReceiptAllowsIndependentBeneficiary() async throws {
        let beneficiary = try canonicalOwnerLiteral()
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/accounts/\(beneficiary)/identifiers/claim-receipt")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount), try AccountAddress.parseEncoded(self.authority).canonicalHex())
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let request = try ToriiIdentifierLookupRequest.claim(policyId: "email#retail", normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32), outputOpening: sampleOpening())
        XCTAssertNotEqual(beneficiary, canonicalReadAuth.accountId)
        let receipt = try await makeClient().issueIdentifierClaimReceipt(accountId: beneficiary, requestBody: request, canonicalAuth: canonicalReadAuth)
        XCTAssertNil(receipt)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetIdentifierClaimByReceiptHashAsync() async throws {
        let accountId = try canonicalOwnerLiteral()
        StubURLProtocol.handler = { request in
            XCTAssertEqual(
                request.url?.path,
                "/v1/identifiers/receipts/\(String(repeating: "55", count: 32))"
            )
            XCTAssertEqual(request.httpMethod, "GET")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "policy_id":"phone#retail",
              "opaque_id":"opaque:\(String(repeating: "44", count: 31))45",
              "receipt_hash":"\(String(repeating: "55", count: 32))",
              "uaid":"uaid:\(String(repeating: "66", count: 31))67",
              "account_id":"\(accountId)",
              "verified_at_ms":7
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let claim = try await makeClient().getIdentifierClaimByReceiptHash(String(repeating: "55", count: 32))
        XCTAssertEqual(claim?.policyId, "phone#retail")
        XCTAssertEqual(claim?.accountId, accountId)
        XCTAssertEqual(claim?.verifiedAtMs, 7)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetIdentifierClaimByReceiptHashRejectsNonExactClaimFieldsAsync() async throws {
        let accountId = try canonicalOwnerLiteral()
        let receiptHash = String(repeating: "55", count: 32)
        let opaqueId = "opaque:\(String(repeating: "44", count: 31))45"
        let uaid = "uaid:\(String(repeating: "66", count: 31))67"

        func claimRecordJSON(policyId: String = "phone#retail",
                             opaqueId: String = opaqueId,
                             receiptHash: String = receiptHash,
                             uaid: String = uaid,
                             accountId: String = accountId) -> Data {
            """
            {
              "policy_id":"\(policyId)",
              "opaque_id":"\(opaqueId)",
              "receipt_hash":"\(receiptHash)",
              "uaid":"\(uaid)",
              "account_id":"\(accountId)",
              "verified_at_ms":7
            }
            """.data(using: .utf8)!
        }

        let cases: [(field: String, body: Data)] = [
            ("policy_id", claimRecordJSON(policyId: " phone#retail")),
            ("opaque_id", claimRecordJSON(opaqueId: "\(opaqueId) ")),
            ("receipt_hash", claimRecordJSON(receiptHash: " \(receiptHash)")),
            ("uaid", claimRecordJSON(uaid: "\(uaid) ")),
            ("account_id", claimRecordJSON(accountId: " \(accountId)")),
        ]

        for testCase in cases {
            StubURLProtocol.handler = { request in
                XCTAssertEqual(
                    request.url?.path,
                    "/v1/identifiers/receipts/\(receiptHash)"
                )
                XCTAssertEqual(request.httpMethod, "GET")
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, testCase.body)
            }

            do {
                _ = try await makeClient().getIdentifierClaimByReceiptHash(receiptHash)
                XCTFail("expected non-exact claim record \(testCase.field) to fail")
            } catch {
                XCTAssertTrue(
                    String(describing: error).contains("identifier claim record.\(testCase.field)"),
                    "\(testCase.field): \(error)"
                )
            }
        }
    }

    func testIdentifierNormalizationCanonicalizesPhoneAndEmail() throws {
        XCTAssertEqual(
            try ToriiIdentifierNormalization.phoneE164.normalize(" +1 (555) 123-4567 ", field: "phone"),
            "+15551234567"
        )
        XCTAssertEqual(
            try ToriiIdentifierNormalization.emailAddress.normalize(" Alice.Example@Example.COM ", field: "email"),
            "alice.example@example.com"
        )
        XCTAssertEqual(
            try ToriiIdentifierNormalization.accountNumber.normalize(" gb82-west-1234 ", field: "account"),
            "GB82WEST1234"
        )
    }

    func testIdentifierBfvEnvelopeBuilderProducesDeterministicCiphertext() throws {
        let policy = ToriiIdentifierPolicySummary(
            policyId: "string#retail",
            programId: "identifier_lookup_retail",
            owner: try canonicalOwnerLiteral(),
            active: true,
            normalization: .exact,
            resolverPublicKey: "ed25519:ed0120" + String(repeating: "11", count: 32),
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-affine-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: ToriiIdentifierBfvPublicParameters(
                parameters: ToriiIdentifierBfvParameters(
                    polynomialDegree: 8,
                    plaintextModulus: 257,
                    ciphertextModulus: 16_842_752,
                    decompositionBaseLog: 12
                ),
                publicKey: ToriiIdentifierBfvPublicKey(
                    b: [11_472_226, 15_791_131, 10_301_391, 6_321_610, 502_045, 1_948_157, 5_332_249, 12_641_494],
                    a: [3_503_246, 2_379_264, 12_091_019, 30_169, 15_804_162, 8_155_629, 2_418_997, 3_003_107]
                ),
                maxInputBytes: 3
            ),
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        let seedHex = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        let expected =
            "4e52543000001042e5b988077612440e4cd45673596b00b004000000000000dd479e32bf99dbd000a804000000000000040000000000000020010000000000008800000000000000080000000000000008000000000000002dac6c00000000000800000000000000440e92000000000008000000000000005b2600000000000008000000000000004a681100000000000800000000000000bc3d2300000000000800000000000000413e85000000000008000000000000005619f900000000000800000000000000bd73fc0000000000880000000000000008000000000000000800000000000000ee894300000000000800000000000000dd22b000000000000800000000000000fe7c50000000000008000000000000001639a3000000000008000000000000006a969b00000000000800000000000000ddd4410000000000080000000000000051076600000000000800000000000000ef14ae00000000002001000000000000880000000000000008000000000000000800000000000000d86c690000000000080000000000000093070e0000000000080000000000000033067500000000000800000000000000ddc5190000000000080000000000000062ea230000000000080000000000000056f00a00000000000800000000000000ab51d400000000000800000000000000e945790000000000880000000000000008000000000000000800000000000000f2204400000000000800000000000000c9ecd2000000000008000000000000001dfc5b00000000000800000000000000d16d660000000000080000000000000016ec0e000000000008000000000000003def83000000000008000000000000006e7ff900000000000800000000000000c1fabb00000000002001000000000000880000000000000008000000000000000800000000000000c8c6eb00000000000800000000000000c9c14800000000000800000000000000f01f8700000000000800000000000000aed22c000000000008000000000000006122990000000000080000000000000036ad8c00000000000800000000000000d1429300000000000800000000000000891f6d0000000000880000000000000008000000000000000800000000000000417eed00000000000800000000000000d79c34000000000008000000000000009f322c0000000000080000000000000091fe5700000000000800000000000000533ce8000000000008000000000000005db8df00000000000800000000000000a8c313000000000008000000000000006e03c20000000000200100000000000088000000000000000800000000000000080000000000000003d654000000000008000000000000005d884400000000000800000000000000567ab50000000000080000000000000007273100000000000800000000000000ff6d0a00000000000800000000000000077466000000000008000000000000006d1d1a000000000008000000000000007050c200000000008800000000000000080000000000000008000000000000002f884f0000000000080000000000000041b0a100000000000800000000000000cbfa290000000000080000000000000057477300000000000800000000000000608f9200000000000800000000000000f5f5dd00000000000800000000000000445b3b00000000000800000000000000999e690000000000"

        XCTAssertEqual(try DiagnosticIdentifierBfvEnvelopeBuilder.encrypt(policy: policy, input: "ab", seedHex: seedHex), expected)
        XCTAssertThrowsError(try policy.prepareRequest(normalizedInput: "ab", inputNonceHex: String(repeating: "12", count: 32)))

    }

    func testCurrentOwnerFactoriesRejectRetiredBfvPolicy() throws {
        let policy = ToriiIdentifierPolicySummary(
            policyId: "malformed",
            programId: "identifier_lookup_retail",
            owner: "not-an-account",
            active: true,
            normalization: .exact,
            resolverPublicKey: "invalid",
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-programmed-v1",
            inputEncryption: nil,
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        XCTAssertThrowsError(try policy.prepareRequest(normalizedInput: "invalid\0plaintext", inputNonceHex: String(repeating: "12", count: 32)))
        XCTAssertThrowsError(try policy.claimRequest(normalizedInput: "invalid\0plaintext", inputNonceHex: String(repeating: "12", count: 32), outputOpening: sampleOpening()))
    }

    func testIdentifierBfvEnvelopeBuilderRejectsOverwideInputProfile() throws {
        let policy = ToriiIdentifierPolicySummary(
            policyId: "string#retail",
            programId: "identifier_lookup_retail",
            owner: try canonicalOwnerLiteral(),
            active: true,
            normalization: .exact,
            resolverPublicKey: "ed25519:ed0120" + String(repeating: "11", count: 32),
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-affine-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: ToriiIdentifierBfvPublicParameters(
                parameters: ToriiIdentifierBfvParameters(
                    polynomialDegree: 8,
                    plaintextModulus: 257,
                    ciphertextModulus: 16_842_752,
                    decompositionBaseLog: 12
                ),
                publicKey: ToriiIdentifierBfvPublicKey(
                    b: [11_472_226, 15_791_131, 10_301_391, 6_321_610, 502_045, 1_948_157, 5_332_249, 12_641_494],
                    a: [3_503_246, 2_379_264, 12_091_019, 30_169, 15_804_162, 8_155_629, 2_418_997, 3_003_107]
                ),
                maxInputBytes: 64
            ),
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )

        XCTAssertThrowsError(
            try DiagnosticIdentifierBfvEnvelopeBuilder.encrypt(policy: policy, input:
                "ab",
                seedHex: "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            )
        ) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(reason.contains("registered RAM-LFE"))
        }
    }

    func testIdentifierBfvEnvelopeBuilderMatchesSharedSoracloudVectors() throws {
        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/soracloud/bfv_identifier_vectors_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
        )
        XCTAssertEqual(try string(fixture, "vector_set"), "soracloud-bfv-identifier-envelope-v1")
        try assertBfvOperationKeyComponentVectors(try object(fixture, "operation_vectors"))
        let policy = try bfvPolicy(fromFixture: object(fixture, "policy"))
        let vectors = try objectArray(fixture, "vectors")
        var observedDigests = Set<String>()

        for vector in vectors {
            let vectorName = try string(vector, "name")
            let ciphertextHex = try DiagnosticIdentifierBfvEnvelopeBuilder.encrypt(policy: policy, input:
                string(vector, "input_utf8"),
                seedHex: string(vector, "seed_hex")
            )
            XCTAssertEqual(
                ciphertextHex.count / 2,
                try int(vector, "expected_ciphertext_bytes"),
                "\(vectorName) ciphertext byte length"
            )
            let ciphertext = try XCTUnwrap(Data(hexString: ciphertextHex))
            let digest = sha256Hex(ciphertext)
            XCTAssertEqual(
                digest,
                try string(vector, "expected_ciphertext_sha256"),
                "\(vectorName) ciphertext digest"
            )
            XCTAssertTrue(
                observedDigests.insert(digest).inserted,
                "fixture ciphertext digest must be unique: \(digest)"
            )
        }
    }

    func testIdentifierBfvEnvelopeBuilderMatchesSharedSoracloudOperationInputVectors() throws {
        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/soracloud/bfv_identifier_vectors_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
        )
        let operationVectors = try object(fixture, "operation_vectors")
        XCTAssertEqual(try string(operationVectors, "vector_set"), "soracloud-bfv-operation-v1")
        let policy = ToriiIdentifierPolicySummary(
            policyId: "soracloud-operation#fixture",
            programId: "identifier_lookup_retail",
            owner: try canonicalOwnerLiteral(),
            active: true,
            normalization: .exact,
            resolverPublicKey: "ed25519:ed0120" + String(repeating: "11", count: 32),
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-programmed-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: try bfvParameters(
                fromFixture: object(operationVectors, "public_parameters_decoded")
            ),
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        var checkedInputs = 0
        var observedDigests = Set<String>()
        for vector in try objectArray(operationVectors, "vectors") {
            let vectorName = try string(vector, "name")
            for input in try objectArray(vector, "inputs") {
                if input["packed_slots"] != nil {
                    continue
                }
                let seedUtf8 = try string(input, "seed_utf8")
                let inputBytes = try XCTUnwrap(Data(hexString: try string(input, "input_hex")))
                let inputString = String(decoding: inputBytes, as: UTF8.self)
                let seed = Data(seedUtf8.utf8).hexEncodedString()
                let ciphertextHex = try DiagnosticIdentifierBfvEnvelopeBuilder.encrypt(policy: policy, input: inputString, seedHex: seed)
                XCTAssertEqual(
                    ciphertextHex.count / 2,
                    try int(input, "expected_ciphertext_bytes"),
                    "\(vectorName)/\(seedUtf8) ciphertext byte length"
                )
                let ciphertext = try XCTUnwrap(Data(hexString: ciphertextHex))
                let digest = sha256Hex(ciphertext)
                XCTAssertEqual(
                    digest,
                    try string(input, "expected_ciphertext_sha256"),
                    "\(vectorName)/\(seedUtf8) ciphertext digest"
                )
                XCTAssertTrue(
                    observedDigests.insert(digest).inserted,
                    "operation input digest must be unique: \(digest)"
                )
                checkedInputs += 1
            }
        }
        XCTAssertEqual(checkedInputs, 8)
    }

    func testSharedSoracloudBfvKeyBundleComponentVectorsAreComplete() throws {
        let fixture = try loadSharedBfvFixture()

        try assertBfvOperationKeyComponentVectors(try object(fixture, "operation_vectors"))
    }

    func testSharedSoracloudBfvKeyBundleComponentVectorsRejectAdversarialDrift() throws {
        var missingComponent = try object(loadSharedBfvFixture(), "operation_vectors")
        var missingEvaluationKey = try object(missingComponent, "evaluation_key_bundle")
        var missingEntries = try objectArray(missingEvaluationKey, "relinearization_entries")
        missingEntries[0].removeValue(forKey: "b_sha256")
        missingEvaluationKey["relinearization_entries"] = missingEntries
        missingComponent["evaluation_key_bundle"] = missingEvaluationKey
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(missingComponent))

        var duplicateComponent = try object(loadSharedBfvFixture(), "operation_vectors")
        var duplicateEvaluationKey = try object(duplicateComponent, "evaluation_key_bundle")
        var duplicateEntries = try objectArray(duplicateEvaluationKey, "relinearization_entries")
        duplicateEntries[1]["a_sha256"] = try string(duplicateEntries[0], "b_sha256")
        duplicateEvaluationKey["relinearization_entries"] = duplicateEntries
        duplicateComponent["evaluation_key_bundle"] = duplicateEvaluationKey
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(duplicateComponent))

        var lowercaseComponent = try object(loadSharedBfvFixture(), "operation_vectors")
        var lowercaseEvaluationKey = try object(lowercaseComponent, "evaluation_key_bundle")
        var lowercaseEntries = try objectArray(lowercaseEvaluationKey, "relinearization_entries")
        lowercaseEntries[0]["b_sha256"] = try string(lowercaseEntries[0], "b_sha256").lowercased()
        lowercaseEvaluationKey["relinearization_entries"] = lowercaseEntries
        lowercaseComponent["evaluation_key_bundle"] = lowercaseEvaluationKey
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(lowercaseComponent))

        var zeroRefresh = try object(loadSharedBfvFixture(), "operation_vectors")
        var rotationKeys = try objectArray(zeroRefresh, "rotation_keys")
        var firstRotation = rotationKeys[0]
        var refreshComponents = try object(firstRotation, "zero_refresh_components")
        refreshComponents["c1_sha256"] = String(repeating: "0", count: 64)
        firstRotation["zero_refresh_components"] = refreshComponents
        rotationKeys[0] = firstRotation
        zeroRefresh["rotation_keys"] = rotationKeys
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(zeroRefresh))

        var countDrift = try object(loadSharedBfvFixture(), "operation_vectors")
        var bootstrap = try object(countDrift, "bootstrap_key")
        var bootstrapComponents = try object(bootstrap, "zero_refresh_components")
        bootstrapComponents["coefficient_count"] = 63
        bootstrap["zero_refresh_components"] = bootstrapComponents
        countDrift["bootstrap_key"] = bootstrap
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(countDrift))

        var rotationCountDrift = try object(loadSharedBfvFixture(), "operation_vectors")
        var rotationEvaluationKey = try object(rotationCountDrift, "evaluation_key_bundle")
        rotationEvaluationKey["rotation_key_count"] = 99
        rotationCountDrift["evaluation_key_bundle"] = rotationEvaluationKey
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(rotationCountDrift))

        var missingFullBootstrapMaterial = try object(loadSharedBfvFixture(), "operation_vectors")
        missingFullBootstrapMaterial.removeValue(forKey: "full_bootstrap_material")
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(missingFullBootstrapMaterial))

        var verifierCommitmentDrift = try object(loadSharedBfvFixture(), "operation_vectors")
        var driftedMaterial = try object(verifierCommitmentDrift, "full_bootstrap_material")
        driftedMaterial["vk_commitment_hex"] = try string(driftedMaterial, "expected_material_digest_hex")
        verifierCommitmentDrift["full_bootstrap_material"] = driftedMaterial
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(verifierCommitmentDrift))

        var noncanonicalMaterialDigest = try object(loadSharedBfvFixture(), "operation_vectors")
        var noncanonicalMaterial = try object(noncanonicalMaterialDigest, "full_bootstrap_material")
        noncanonicalMaterial["expected_material_digest_hex"] = try string(noncanonicalMaterial, "expected_material_digest_hex").uppercased()
        noncanonicalMaterialDigest["full_bootstrap_material"] = noncanonicalMaterial
        XCTAssertThrowsError(try assertBfvOperationKeyComponentVectors(noncanonicalMaterialDigest))
    }

    func testIdentifierBfvEnvelopeBuilderMatchesLiveJsVector() throws {
        let fixtureURL = irohaSwiftPackageRootURL()
            .appendingPathComponent("Fixtures/js_email_identifier_request.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        let fixture = try JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
        let expected = try XCTUnwrap(fixture?["encryptedInput"] as? String)

        let policy = ToriiIdentifierPolicySummary(
            policyId: "email#retail",
            programId: "identifier_lookup_retail",
            owner: try canonicalOwnerLiteral(),
            active: true,
            normalization: .emailAddress,
            resolverPublicKey: "ed01208FC2E4882B20ABCCBFADB4E44268206E187AEB235A51252F159B3B24D5BB6661",
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: "bfv-programmed-v1",
            inputEncryption: "bfv-v1",
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: ToriiIdentifierBfvPublicParameters(
                parameters: ToriiIdentifierBfvParameters(
                    polynomialDegree: 64,
                    plaintextModulus: 256,
                    ciphertextModulus: 4_503_599_627_370_496,
                    decompositionBaseLog: 12
                ),
                publicKey: ToriiIdentifierBfvPublicKey(
                    b: [
                        121937970585568, 2077422026028227, 500805327165639, 2424373013208231,
                        1243826623687677, 3764723070138803, 2777853678689092, 4148792190743456,
                        832919354056448, 1078220173904611, 1449102004009053, 2553195729187374,
                        4121823210086138, 1314721746498746, 2081320919861598, 1293550100235769,
                        752052855416432, 2560964795529688, 4373758947250140, 302739621553461,
                        2576363806012840, 3992909986948675, 468471023959674, 403186621067672,
                        2412531771816291, 1151008441392236, 4235659218269462, 3632712073230975,
                        1570131697783046, 2686064869757573, 868982827285377, 4024361324590714,
                        2720840185948756, 4035919674038070, 1768439826701200, 1795998257831299,
                        3146057215641308, 4427306182373160, 431902047897329, 4103953196264316,
                        252052014793937, 4481957945412857, 313876785458221, 502488979381506,
                        2254533341218653, 378630418191746, 3949757926731121, 3205345961759607,
                        4403697458699262, 1051260385144426, 3165025408388444, 2971268616428220,
                        1438933110049424, 221886932655998, 760759893336199, 2366379419062310,
                        3808463564396841, 3404172544660443, 3109880358158474, 977074504388190,
                        3693464878032463, 4157741571468524, 4422156359690334, 3136084645017157
                    ],
                    a: [
                        1757685446086860, 3389246144977851, 568120110213016, 3749195222357958,
                        505425731783661, 1653917459200990, 3991392281498110, 2498385903989296,
                        2202458345522039, 665774489520137, 3431324343332235, 2757156726851470,
                        3945284631206095, 4260357308916675, 3556193440561259, 528988422073873,
                        3556053776248327, 231714661150035, 4000422747863537, 4440124990980577,
                        1151102360936999, 1203423089979213, 3714754289019569, 365230193721200,
                        4121105395019879, 906275922098612, 2167568203585419, 902141125979404,
                        1847406449459084, 1974477488630907, 3986975207909980, 2303086024281801,
                        1799110714207632, 1984353349506261, 3868774043831877, 3439432886790299,
                        2603619075693252, 2329149836785785, 3805700285192206, 4000022950860341,
                        2467812426805913, 491688654005352, 3108228703212131, 3552150340822500,
                        3495862320984036, 2457966307381587, 654204939969134, 3247840319357347,
                        1494057235954141, 4259088215794420, 3588894761760921, 2147790385334894,
                        2062768833373357, 3953764458945290, 1442228637461419, 3551539910829634,
                        3571737697974589, 3660975499942543, 1729481054172766, 4367395767819851,
                        43579440603412, 3935477944038421, 4132857811135436, 903532232777036
                    ]
                ),
                maxInputBytes: 63
            ),
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
        let seedHex = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        let actual = try DiagnosticIdentifierBfvEnvelopeBuilder.encrypt(policy: policy, input: "ios.bankb.live@example.com", seedHex: seedHex)

        if actual != expected {
            let mismatchIndex = {
                var index = 0
                for (lhs, rhs) in zip(actual, expected) {
                    if lhs != rhs { return index }
                    index += 1
                }
                return min(actual.count, expected.count)
            }()
            XCTFail("mismatch at offset \(mismatchIndex) actual=\(actual.dropFirst(mismatchIndex).prefix(64)) expected=\(expected.dropFirst(mismatchIndex).prefix(64))")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionAsync() async throws {
        let transaction = try canonicalSignedPipelineTransaction()
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody())
            case "/v1/pipeline/transactions":
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), ToriiWireFormatPreference.noritoPreferred.acceptHeader)
                XCTAssertEqual(self.bodyData(from: request), transaction)
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 202,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let body = """
                {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":1,"submitted_at_height":2,"signer":"signer"},"signature":"deadbeef"}
                """.data(using: .utf8)!
                return (response, body)
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        let payload = try await makeClient().submitTransaction(data: transaction)
        XCTAssertEqual(payload?.hash, Self.pipelineHash)
        XCTAssertEqual(payload?.payload.submittedAtMs, 1)
        XCTAssertEqual(payload?.payload.submittedAtHeight, 2)
        XCTAssertEqual(payload?.payload.signer, "signer")
        XCTAssertEqual(payload?.signature, "deadbeef")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsNoncanonicalWireBeforeAnyRequest() async throws {
        let canonical = try canonicalSignedPipelineTransaction()
        StubURLProtocol.handler = { request in
            XCTFail("noncanonical transaction reached HTTP dispatch: \(request.url?.path ?? "")")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data())
        }

        let invalidWires = [
            Data(),
            Data([0x00]) + Data(canonical.dropFirst()),
            Data(canonical.dropFirst()),
            canonical + Data([0x00]),
        ]
        for invalidWire in invalidWires {
            do {
                _ = try await makeClient().submitTransaction(data: invalidWire)
                XCTFail("expected canonical V1 transaction rejection")
            } catch let error as ToriiClientError {
                guard case let .invalidPayload(reason) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertTrue(reason.contains("canonical V1 versioned signed transaction"))
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsRetiredSuccessStatusCodes() async throws {
        let transaction = try canonicalSignedPipelineTransaction()
        for statusCode in [200, 201, 204] {
            StubURLProtocol.handler = { request in
                switch request.url?.path {
                case "/v1/node/capabilities":
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: ["Content-Type": "application/json"]
                    )!
                    return (response, self.nodeCapabilitiesBody())
                case "/v1/pipeline/transactions":
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: statusCode,
                        httpVersion: nil,
                        headerFields: ["Content-Type": "application/json"]
                    )!
                    return (response, Data())
                default:
                    XCTFail("unexpected request: \(request.url?.path ?? "")")
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 404,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                    return (response, Data())
                }
            }

            do {
                _ = try await makeClient().submitTransaction(data: transaction)
                XCTFail("expected HTTP \(statusCode) rejection")
            } catch let error as ToriiClientError {
                guard case let .api(apiError) = error else {
                    return XCTFail("unexpected error for HTTP \(statusCode): \(error)")
                }
                let code = apiError.status
                XCTAssertEqual(code, statusCode)
            }
        }
    }

    func testSubmitTransactionResponseDecodesCanonicalJsonReceiptFields() throws {
        let body = """
        {
          "payload": {
            "entrypoint_hash": "\(Self.pipelineHash)",
            "signed_transaction_hash": "\(String(repeating: "b", count: 64))",
            "submitted_at_ms": 1,
            "submitted_at_height": 2,
            "signer": {
              "algorithm": "ed25519",
              "payload": "node-key"
            }
          },
          "signature": {
            "algorithm": "ed25519",
            "payload": "receipt-signature"
          }
        }
        """.data(using: .utf8)!

        let receipt = try JSONDecoder().decode(ToriiSubmitTransactionResponse.self, from: body)

        XCTAssertEqual(receipt.hash, Self.pipelineHash)
        XCTAssertEqual(receipt.payload.entrypointHash, Self.pipelineHash)
        XCTAssertEqual(receipt.payload.signedTransactionHash, String(repeating: "b", count: 64))
        XCTAssertEqual(receipt.payload.signerValue["algorithm"], .string("ed25519"))
        XCTAssertEqual(receipt.payload.signerValue["payload"], .string("node-key"))
        XCTAssertEqual(receipt.signatureValue["algorithm"], .string("ed25519"))
        XCTAssertEqual(receipt.signatureValue["payload"], .string("receipt-signature"))
        XCTAssertEqual(receipt.payload.signer, #"{"algorithm":"ed25519","payload":"node-key"}"#)
        XCTAssertEqual(receipt.signature, #"{"algorithm":"ed25519","payload":"receipt-signature"}"#)

        let missingNullableHash = """
        {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","submitted_at_ms":1,"submitted_at_height":2,"signer":"node"},"signature":"sig"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiSubmitTransactionResponse.self, from: missingNullableHash)
        )

        let unknownPayloadField = """
        {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":1,"submitted_at_height":2,"signer":"node","legacy":null},"signature":"sig"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiSubmitTransactionResponse.self, from: unknownPayloadField)
        )

        let retiredStringNumber = """
        {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":"1","submitted_at_height":2,"signer":"node"},"signature":"sig"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiSubmitTransactionResponse.self, from: retiredStringNumber)
        )

        let evenHashMarker = String(Self.pipelineHash.dropLast()) + "c"
        let retiredUntypedHash = """
        {"payload":{"entrypoint_hash":"\(evenHashMarker)","signed_transaction_hash":null,"submitted_at_ms":1,"submitted_at_height":2,"signer":"node"},"signature":"sig"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiSubmitTransactionResponse.self, from: retiredUntypedHash)
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionJsonUsesConfiguredWirePreference() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody())
            case "/v1/pipeline/transactions":
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), ToriiWireFormatPreference.jsonOnly.acceptHeader)
                XCTAssertEqual(self.bodyData(from: request), Data("{\"version\":1,\"content\":{}}".utf8))
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 202,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let body = """
                {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":1,"submitted_at_height":2,"signer":"json-signer"},"signature":"cafe"}
                """.data(using: .utf8)!
                return (response, body)
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let client = ToriiClient(baseURL: URL(string: "https://example.test")!,
                                 session: session,
                                 localSigningContext: ToriiLocalSigningContext(
                                     networkId: TestNetworkIds.canonical
                                 ),
                                 canonicalRequestAuth: canonicalReadAuth,
                                 wireFormatPreference: .jsonOnly)

        let payload = try await client.submitTransaction(jsonData: Data("{\"version\":1,\"content\":{}}".utf8))
        XCTAssertEqual(payload?.hash, Self.pipelineHash)
        XCTAssertEqual(payload?.payload.signer, "json-signer")
        XCTAssertEqual(payload?.signature, "cafe")
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }

    private func matchingVerifyingKeyCommitmentHex(backend: String, bytes: Data) -> String {
        let backendBytes = Data(backend.utf8)
        var preimage = Data("iroha:zk:v1:vk".utf8)
        preimage.append(u64BigEndianData(UInt64(backendBytes.count)))
        preimage.append(backendBytes)
        preimage.append(u64BigEndianData(UInt64(bytes.count)))
        preimage.append(bytes)
        return Data(SHA256.hash(data: preimage)).hexEncodedString()
    }

    private func expectedVerifierRegistryBackendRejection(_ backend: String) -> String {
        backend.trimmingCharacters(in: .whitespacesAndNewlines) == backend
            ? "backend is not an exact supported verifier-registry label: \(backend)."
            : "backend must not contain surrounding whitespace."
    }

    private func u64BigEndianData(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    private func loadSharedBfvFixture() throws -> [String: Any] {
        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/soracloud/bfv_identifier_vectors_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: fixtureData) as? [String: Any]
        )
    }

    private func identifierReceiptPolicy(
        fromFixture policy: [String: Any]
    ) throws -> ToriiIdentifierPolicySummary {
        ToriiIdentifierPolicySummary(
            policyId: try string(policy, "policy_id"),
            programId: "identifier_lookup_retail",
            owner: try string(policy, "owner"),
            active: try bool(policy, "active"),
            normalization: .phoneE164,
            resolverPublicKey: try string(policy, "resolver_public_key"),
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: try string(policy, "backend"),
            inputEncryption: policy["input_encryption"] as? String,
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: nil,
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
    }

    private func identifierReceipt(
        fromFixture receipt: [String: Any]
    ) throws -> ToriiIdentifierResolutionReceipt {
        let data = try JSONSerialization.data(withJSONObject: receipt)
        return try JSONDecoder().decode(ToriiIdentifierResolutionReceipt.self, from: data)
    }

    private func identifierReceiptAttestation(
        fromFixture attestation: [String: Any]
    ) throws -> ToriiIdentifierReceiptAttestation {
        let data = try JSONSerialization.data(withJSONObject: attestation)
        return try JSONDecoder().decode(ToriiIdentifierReceiptAttestation.self, from: data)
    }

    private func bfvPolicy(fromFixture policy: [String: Any]) throws -> ToriiIdentifierPolicySummary {
        ToriiIdentifierPolicySummary(
            policyId: try string(policy, "policy_id"),
            programId: "identifier_lookup_retail",
            owner: try string(policy, "owner"),
            active: try bool(policy, "active"),
            normalization: .exact,
            resolverPublicKey: try string(policy, "resolver_public_key"),
            outputOpeningPublicKey: "ed012043046BFE4092B3E94994EADA15DCC20D8AAA07B658FD3954EB8E0EFB8BDCA5DE",
            backend: try string(policy, "backend"),
            inputEncryption: try string(policy, "input_encryption"),
            inputEncryptionPublicParameters: nil,
            inputEncryptionPublicParametersDecoded: try bfvParameters(
                fromFixture: object(policy, "input_encryption_public_parameters_decoded")
            ),
            ramFheProfile: nil,
            proofVerifier: nil,
            note: nil
        )
    }

    private func bfvParameters(fromFixture params: [String: Any]) throws -> ToriiIdentifierBfvPublicParameters {
        let rawParameters = try object(params, "parameters")
        let rawPublicKey = try object(params, "public_key")
        return ToriiIdentifierBfvPublicParameters(
            parameters: ToriiIdentifierBfvParameters(
                polynomialDegree: UInt32(try int(rawParameters, "polynomial_degree")),
                plaintextModulus: try uint64(rawParameters, "plaintext_modulus"),
                ciphertextModulus: try uint64(rawParameters, "ciphertext_modulus"),
                decompositionBaseLog: UInt8(try int(rawParameters, "decomposition_base_log"))
            ),
            publicKey: ToriiIdentifierBfvPublicKey(
                b: try uint64Array(rawPublicKey, "b"),
                a: try uint64Array(rawPublicKey, "a")
            ),
            maxInputBytes: UInt16(try int(params, "max_input_bytes")),
            noritoLengthEncoding: params["norito_length_encoding"] as? String
        )
    }

    private func object(_ root: [String: Any], _ key: String) throws -> [String: Any] {
        guard let value = root[key] as? [String: Any] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be an object"])
        }
        return value
    }

    private func objectArray(_ root: [String: Any], _ key: String) throws -> [[String: Any]] {
        guard let value = root[key] as? [[String: Any]] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be an object array"])
        }
        return value
    }

    private func string(_ root: [String: Any], _ key: String) throws -> String {
        guard let value = root[key] as? String else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be a string"])
        }
        return value
    }

    private func assertBfvOperationKeyComponentVectors(_ operationVectors: [String: Any]) throws {
        try assertBfvEqual(try string(operationVectors, "vector_set"), "soracloud-bfv-operation-v1", "operation vector set")
        let publicParameters = try object(operationVectors, "public_parameters")
        let publicDegree = try int(publicParameters, "polynomial_degree")
        try assertBfvRnsModulusChainFixture(operationVectors, publicDegree: publicDegree)
        let evaluationKey = try object(operationVectors, "evaluation_key_bundle")
        try assertBfvEqual(
            try int(evaluationKey, "decomposition_base_log"),
            try int(publicParameters, "decomposition_base_log"),
            "evaluation-key decomposition base log"
        )
        try assertBfvEqual(
            try int(evaluationKey, "decomposition_digit_count"),
            try int(evaluationKey, "relinearization_entry_count"),
            "evaluation-key decomposition digit count"
        )
        let entries = try objectArray(evaluationKey, "relinearization_entries")
        try assertBfvEqual(entries.count, try int(evaluationKey, "relinearization_entry_count"), "relinearization entry count")
        var componentDigests = Set<String>()
        for (index, entry) in entries.enumerated() {
            try assertBfvEqual(try int(entry, "index"), index, "relinearization entry \(index) index")
            try assertBfvEqual(try int(entry, "coefficient_count"), publicDegree, "relinearization entry \(index) coefficient count")
            try assertBfvComponentDigest("relinearization entry \(index) b", try string(entry, "b_sha256"), seen: &componentDigests)
            try assertBfvComponentDigest("relinearization entry \(index) a", try string(entry, "a_sha256"), seen: &componentDigests)
        }
        let galoisKeys = try objectArray(operationVectors, "galois_keys")
        XCTAssertEqual(galoisKeys.count, try int(evaluationKey, "galois_key_count"))
        for key in galoisKeys {
            let power = try int(key, "automorphism_power")
            let keyEntries = try objectArray(key, "entries")
            XCTAssertEqual(keyEntries.count, try int(key, "entry_count"))
            for (index, entry) in keyEntries.enumerated() {
                XCTAssertEqual(try int(entry, "index"), index)
                XCTAssertEqual(try int(entry, "coefficient_count"), publicDegree)
                try assertBfvComponentDigest("Galois key \(power) entry \(index) b", try string(entry, "b_sha256"), seen: &componentDigests)
                try assertBfvComponentDigest("Galois key \(power) entry \(index) a", try string(entry, "a_sha256"), seen: &componentDigests)
            }
        }
        let galoisSwitchVectors = try objectArray(operationVectors, "galois_switch_vectors")
        XCTAssertFalse(galoisSwitchVectors.isEmpty)
        for vector in galoisSwitchVectors {
            let name = try string(vector, "name")
            let power = try int(vector, "automorphism_power")
            XCTAssertTrue(try galoisKeys.contains { try int($0, "automorphism_power") == power })
            guard let plaintextSlots = vector["input_plaintext_slots"] as? [Int] else {
                throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "input_plaintext_slots must be an integer array"])
            }
            XCTAssertFalse(plaintextSlots.isEmpty)
            XCTAssertTrue(plaintextSlots.allSatisfy { $0 >= 0 })
            XCTAssertGreaterThan(try int(vector, "expected_input_ciphertext_bytes"), 0)
            XCTAssertGreaterThan(try int(vector, "expected_output_ciphertext_bytes"), 0)
            assertBfvUpperSha256("Galois switch vector \(name) input", try string(vector, "expected_input_ciphertext_sha256"))
            assertBfvUpperSha256("Galois switch vector \(name) output", try string(vector, "expected_output_ciphertext_sha256"))
            assertBfvUpperSha256("Galois switch vector \(name) plaintext", try string(vector, "expected_plaintext_sha256"))
            let components = try object(vector, "output_components")
            XCTAssertEqual(try int(components, "coefficient_count"), publicDegree)
            try assertBfvComponentDigest("Galois switch vector \(name) c0", try string(components, "c0_sha256"), seen: &componentDigests)
            try assertBfvComponentDigest("Galois switch vector \(name) c1", try string(components, "c1_sha256"), seen: &componentDigests)
        }
        let packedGaloisSwitchVectors = try objectArray(operationVectors, "packed_galois_switch_vectors")
        XCTAssertFalse(packedGaloisSwitchVectors.isEmpty)
        for vector in packedGaloisSwitchVectors {
            let name = try string(vector, "name")
            let power = try int(vector, "automorphism_power")
            XCTAssertTrue(try galoisKeys.contains { try int($0, "automorphism_power") == power })
            guard let inputSlots = vector["input_packed_slots"] as? [Int] else {
                throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "input_packed_slots must be an integer array"])
            }
            guard let permutation = vector["expected_slot_permutation"] as? [Int] else {
                throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "expected_slot_permutation must be an integer array"])
            }
            guard let outputSlots = vector["expected_packed_slots"] as? [Int] else {
                throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "expected_packed_slots must be an integer array"])
            }
            XCTAssertEqual(inputSlots.count, publicDegree)
            XCTAssertEqual(permutation.count, publicDegree)
            XCTAssertEqual(outputSlots.count, publicDegree)
            XCTAssertTrue(inputSlots.allSatisfy { $0 >= 0 })
            XCTAssertTrue(permutation.allSatisfy { $0 >= 0 })
            XCTAssertTrue(outputSlots.allSatisfy { $0 >= 0 })
            assertBfvUpperSha256("packed Galois switch vector \(name) packed plaintext", try string(vector, "expected_packed_plaintext_sha256"))
            assertBfvUpperSha256("packed Galois switch vector \(name) input", try string(vector, "expected_input_ciphertext_sha256"))
            assertBfvUpperSha256("packed Galois switch vector \(name) output", try string(vector, "expected_output_ciphertext_sha256"))
            assertBfvUpperSha256("packed Galois switch vector \(name) plaintext", try string(vector, "expected_plaintext_coefficients_sha256"))
            let components = try object(vector, "output_components")
            XCTAssertEqual(try int(components, "coefficient_count"), publicDegree)
            try assertBfvComponentDigest("packed Galois switch vector \(name) c0", try string(components, "c0_sha256"), seen: &componentDigests)
            try assertBfvComponentDigest("packed Galois switch vector \(name) c1", try string(components, "c1_sha256"), seen: &componentDigests)
        }
        let rotationKeys = try objectArray(operationVectors, "rotation_keys")
        try assertBfvEqual(rotationKeys.count, try int(evaluationKey, "rotation_key_count"), "rotation key count")
        for key in rotationKeys {
            let components = try object(key, "zero_refresh_components")
            let steps = try int(key, "rotation_steps")
            try assertBfvEqual(try int(components, "coefficient_count"), publicDegree, "rotation key \(steps) coefficient count")
            try assertBfvComponentDigest("rotation key \(steps) c0", try string(components, "c0_sha256"), seen: &componentDigests)
            try assertBfvComponentDigest("rotation key \(steps) c1", try string(components, "c1_sha256"), seen: &componentDigests)
        }
        let bootstrap = try object(operationVectors, "bootstrap_key")
        try assertBfvEqual(try string(bootstrap, "key_id"), try string(evaluationKey, "bootstrap_key_id"), "bootstrap key id")
        try assertBfvEqual(try int(bootstrap, "max_refresh_rounds"), try int(evaluationKey, "bootstrap_max_refresh_rounds"), "bootstrap max refresh rounds")
        XCTAssertGreaterThan(try int(bootstrap, "max_refresh_rounds"), 0)
        let bootstrapComponents = try object(bootstrap, "zero_refresh_components")
        try assertBfvEqual(try int(bootstrapComponents, "coefficient_count"), publicDegree, "bootstrap coefficient count")
        try assertBfvComponentDigest("bootstrap c0", try string(bootstrapComponents, "c0_sha256"), seen: &componentDigests)
        try assertBfvComponentDigest("bootstrap c1", try string(bootstrapComponents, "c1_sha256"), seen: &componentDigests)
        let roundRefreshes = try objectArray(bootstrap, "round_refreshes")
        XCTAssertEqual(roundRefreshes.count, try int(bootstrap, "max_refresh_rounds"))
        for (index, refresh) in roundRefreshes.enumerated() {
            XCTAssertEqual(try int(refresh, "round_index"), index)
            XCTAssertGreaterThan(try int(refresh, "expected_refresh_bytes"), 0)
            assertBfvUpperSha256("bootstrap round \(index) refresh", try string(refresh, "expected_refresh_sha256"))
            let components = try object(refresh, "components")
            XCTAssertEqual(try int(components, "coefficient_count"), publicDegree)
            if index == 0 {
                XCTAssertEqual(try string(components, "c0_sha256"), try string(bootstrapComponents, "c0_sha256"))
                XCTAssertEqual(try string(components, "c1_sha256"), try string(bootstrapComponents, "c1_sha256"))
                assertBfvUpperSha256("bootstrap round 0 c0", try string(components, "c0_sha256"))
                assertBfvUpperSha256("bootstrap round 0 c1", try string(components, "c1_sha256"))
            } else {
                try assertBfvComponentDigest("bootstrap round \(index) c0", try string(components, "c0_sha256"), seen: &componentDigests)
                try assertBfvComponentDigest("bootstrap round \(index) c1", try string(components, "c1_sha256"), seen: &componentDigests)
            }
        }
        XCTAssertEqual(try string(roundRefreshes[0], "expected_refresh_sha256"), try string(bootstrap, "expected_zero_refresh_sha256"))
        if roundRefreshes.count > 1 {
            XCTAssertNotEqual(try string(roundRefreshes[0], "expected_refresh_sha256"), try string(roundRefreshes[1], "expected_refresh_sha256"))
        }
        try assertBfvFullBootstrapMaterialFixture(operationVectors)
        let bootstrapRefreshVectors = try objectArray(operationVectors, "bootstrap_refresh_vectors")
        XCTAssertFalse(bootstrapRefreshVectors.isEmpty)
        for vector in bootstrapRefreshVectors {
            let name = try string(vector, "name")
            XCTAssertEqual(try string(vector, "key_id"), try string(bootstrap, "key_id"))
            let refreshRounds = try int(vector, "refresh_rounds")
            XCTAssertGreaterThan(refreshRounds, 0)
            guard let plaintextSlots = vector["input_plaintext_slots"] as? [Int] else {
                throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "input_plaintext_slots must be an integer array"])
            }
            XCTAssertFalse(plaintextSlots.isEmpty)
            XCTAssertTrue(plaintextSlots.allSatisfy { $0 >= 0 })
            XCTAssertGreaterThan(try int(vector, "expected_input_ciphertext_bytes"), 0)
            assertBfvUpperSha256("bootstrap refresh vector \(name) input", try string(vector, "expected_input_ciphertext_sha256"))
            if let expectedError = vector["expected_error"] as? String {
                XCTAssertGreaterThan(refreshRounds, try int(bootstrap, "max_refresh_rounds"))
                XCTAssertEqual(expectedError, "invalid BFV parameters: BFV bootstrap refresh rounds 2 exceeds bootstrap key max_refresh_rounds 1")
                XCTAssertNil(vector["expected_output_ciphertext_sha256"])
                continue
            }
            XCTAssertLessThanOrEqual(refreshRounds, try int(bootstrap, "max_refresh_rounds"))
            XCTAssertGreaterThan(try int(vector, "expected_output_ciphertext_bytes"), 0)
            assertBfvUpperSha256("bootstrap refresh vector \(name) output", try string(vector, "expected_output_ciphertext_sha256"))
            assertBfvUpperSha256("bootstrap refresh vector \(name) plaintext", try string(vector, "expected_plaintext_sha256"))
            let components = try object(vector, "output_components")
            XCTAssertEqual(try int(components, "coefficient_count"), publicDegree)
            try assertBfvComponentDigest("bootstrap refresh vector \(name) c0", try string(components, "c0_sha256"), seen: &componentDigests)
            try assertBfvComponentDigest("bootstrap refresh vector \(name) c1", try string(components, "c1_sha256"), seen: &componentDigests)
        }
        let runtimeVectors = try objectArray(operationVectors, "vectors")
        for vector in runtimeVectors {
            let vectorName = try string(vector, "name")
            let expectedDepth = try string(vector, "operation") == "Multiply"
                ? balancedBfvMultiplicationDepth(try objectArray(vector, "inputs").count)
                : 0
            XCTAssertEqual(
                try int(vector, "requested_multiplication_depth"),
                expectedDepth,
                "\(vectorName) requested multiplication depth"
            )
        }
        guard let packedRotate = runtimeVectors.first(where: { ($0["name"] as? String) == "soracloud-packed-rotate-left-output" }) else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft operation vector must be present"])
        }
        XCTAssertEqual(try string(packedRotate, "operation"), "RotateLeft")
        XCTAssertEqual(try int(packedRotate, "rotation_steps"), publicDegree / 2)
        let packedRotatePower = try int(packedRotate, "automorphism_power")
        XCTAssertEqual(packedRotatePower, publicDegree + 1)
        XCTAssertTrue(try galoisKeys.contains { try int($0, "automorphism_power") == packedRotatePower })
        let packedRotateInputs = try objectArray(packedRotate, "inputs")
        XCTAssertEqual(packedRotateInputs.count, 1)
        let packedRotateInput = packedRotateInputs[0]
        guard let inputSlots = packedRotateInput["packed_slots"] as? [Int] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft packed_slots must be an integer array"])
        }
        guard let outputSlots = packedRotate["expected_packed_slots"] as? [Int] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft expected_packed_slots must be an integer array"])
        }
        XCTAssertEqual(inputSlots.count, publicDegree)
        XCTAssertEqual(outputSlots.count, publicDegree)
        XCTAssertTrue(inputSlots.allSatisfy { $0 >= 0 })
        XCTAssertTrue(outputSlots.allSatisfy { $0 >= 0 })
        XCTAssertGreaterThan(try int(packedRotateInput, "expected_ciphertext_bytes"), 0)
        XCTAssertGreaterThan(try int(packedRotate, "expected_output_ciphertext_bytes"), 0)
        assertBfvUpperSha256("packed RotateLeft input plaintext", try string(packedRotateInput, "expected_packed_plaintext_sha256"))
        assertBfvUpperSha256("packed RotateLeft input", try string(packedRotateInput, "expected_ciphertext_sha256"))
        assertBfvUpperSha256("packed RotateLeft output", try string(packedRotate, "expected_output_ciphertext_sha256"))
        assertBfvUpperSha256("packed RotateLeft plaintext", try string(packedRotate, "expected_plaintext_coefficients_sha256"))
        let packedRotateComponents = try object(packedRotate, "output_components")
        XCTAssertEqual(try int(packedRotateComponents, "coefficient_count"), publicDegree)
        try assertBfvComponentDigest("packed RotateLeft c0", try string(packedRotateComponents, "c0_sha256"), seen: &componentDigests)
        try assertBfvComponentDigest("packed RotateLeft c1", try string(packedRotateComponents, "c1_sha256"), seen: &componentDigests)

        guard let packedRotateSchedule = runtimeVectors.first(where: { ($0["name"] as? String) == "soracloud-packed-rotate-left-schedule-output" }) else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft schedule vector must be present"])
        }
        XCTAssertEqual(try string(packedRotateSchedule, "operation"), "RotateLeft")
        XCTAssertEqual(try int(packedRotateSchedule, "rotation_steps"), 1)
        guard let schedulePowers = packedRotateSchedule["automorphism_powers"] as? [Int] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft automorphism_powers must be an integer array"])
        }
        XCTAssertGreaterThan(schedulePowers.count, 1)
        for power in schedulePowers {
            XCTAssertGreaterThan(power, 0)
            XCTAssertTrue(try galoisKeys.contains { try int($0, "automorphism_power") == power })
        }
        let packedRotateScheduleInputs = try objectArray(packedRotateSchedule, "inputs")
        XCTAssertEqual(packedRotateScheduleInputs.count, 1)
        let packedRotateScheduleInput = packedRotateScheduleInputs[0]
        guard let scheduleInputSlots = packedRotateScheduleInput["packed_slots"] as? [Int] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft schedule packed_slots must be an integer array"])
        }
        guard let scheduleOutputSlots = packedRotateSchedule["expected_packed_slots"] as? [Int] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "packed RotateLeft schedule expected_packed_slots must be an integer array"])
        }
        XCTAssertEqual(scheduleInputSlots.count, publicDegree)
        XCTAssertEqual(scheduleOutputSlots.count, publicDegree)
        XCTAssertEqual(Array(scheduleInputSlots.dropFirst()) + [scheduleInputSlots[0]], scheduleOutputSlots)
        XCTAssertTrue(scheduleInputSlots.allSatisfy { $0 >= 0 })
        XCTAssertTrue(scheduleOutputSlots.allSatisfy { $0 >= 0 })
        XCTAssertGreaterThan(try int(packedRotateScheduleInput, "expected_ciphertext_bytes"), 0)
        XCTAssertGreaterThan(try int(packedRotateSchedule, "expected_output_ciphertext_bytes"), 0)
        assertBfvUpperSha256("packed RotateLeft schedule input plaintext", try string(packedRotateScheduleInput, "expected_packed_plaintext_sha256"))
        assertBfvUpperSha256("packed RotateLeft schedule input", try string(packedRotateScheduleInput, "expected_ciphertext_sha256"))
        assertBfvUpperSha256("packed RotateLeft schedule output", try string(packedRotateSchedule, "expected_output_ciphertext_sha256"))
        assertBfvUpperSha256("packed RotateLeft schedule plaintext", try string(packedRotateSchedule, "expected_plaintext_coefficients_sha256"))
        let packedRotateScheduleComponents = try object(packedRotateSchedule, "output_components")
        XCTAssertEqual(try int(packedRotateScheduleComponents, "coefficient_count"), publicDegree)
        try assertBfvComponentDigest("packed RotateLeft schedule c0", try string(packedRotateScheduleComponents, "c0_sha256"), seen: &componentDigests)
        try assertBfvComponentDigest("packed RotateLeft schedule c1", try string(packedRotateScheduleComponents, "c1_sha256"), seen: &componentDigests)
    }

    private func assertBfvFullBootstrapMaterialFixture(_ operationVectors: [String: Any]) throws {
        let material = try object(operationVectors, "full_bootstrap_material")
        try assertBfvEqual(try string(material, "circuit_id"), "iroha_bfv_full_bootstrap_v1", "full-bootstrap circuit id")
        try assertBfvEqual(try int(material, "max_bootstrap_depth"), 1, "full-bootstrap max depth")

        let digestFields = [
            "parameter_digest_hex",
            "rns_modulus_chain_digest_hex",
            "key_switch_decomposition_chain_digest_hex",
            "coefficient_to_slot_key_digest_hex",
            "slot_to_coefficient_key_digest_hex",
            "blind_rotation_key_digest_hex",
            "sample_extraction_key_digest_hex",
            "accumulator_digest_hex",
            "proof_public_input_schema_digest_hex",
            "prover_key_digest_hex",
            "prover_key_material_commitment_hex",
            "verifier_key_digest_hex",
            "verifier_key_material_commitment_hex",
            "vk_commitment_hex",
            "expected_material_digest_hex",
        ]
        let digestValues = try digestFields.map { field -> String in
            let value = try string(material, field)
            try requireBfvLowerDigest("full-bootstrap material \(field)", value)
            return value
        }
        try assertBfvEqual(
            try string(try object(operationVectors, "rns_modulus_chain"), "expected_digest_hex"),
            try string(material, "rns_modulus_chain_digest_hex"),
            "full-bootstrap RNS digest"
        )
        try assertBfvEqual(
            try string(material, "verifier_key_material_commitment_hex"),
            try string(material, "vk_commitment_hex"),
            "full-bootstrap verifier-key commitment"
        )
        XCTAssertNotEqual(
            try string(material, "verifier_key_digest_hex"),
            try string(material, "vk_commitment_hex"),
            "full-bootstrap verifier-key commitment must be distinct from the artifact digest"
        )
        var uniqueDigestValues: [String] = []
        for (field, value) in zip(digestFields, digestValues) where field != "vk_commitment_hex" {
            uniqueDigestValues.append(value)
        }
        try assertBfvEqual(Set(uniqueDigestValues).count, uniqueDigestValues.count, "full-bootstrap material digest roles")
    }

    private func assertBfvEqual<T: Equatable>(_ actual: T, _ expected: T, _ label: String) throws {
        guard actual == expected else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) mismatch"])
        }
    }

    private func assertBfvRnsModulusChainFixture(_ operationVectors: [String: Any], publicDegree: Int) throws {
        let rns = try object(operationVectors, "rns_modulus_chain")
        let moduli = try uint64Array(rns, "moduli")
        XCTAssertFalse(moduli.isEmpty)
        XCTAssertEqual(moduli, moduli.sorted())
        XCTAssertTrue(moduli.allSatisfy { $0 > 2 && $0 % 2 == 1 })
        XCTAssertTrue(try string(rns, "product").allSatisfy(\.isNumber))
        assertBfvLowerDigest("RNS modulus-chain digest", try string(rns, "expected_digest_hex"))

        let samples = try object(rns, "sample_polynomials")
        XCTAssertEqual(try uint64Array(samples, "lhs_coefficients").count, publicDegree)
        XCTAssertEqual(try uint64Array(samples, "rhs_coefficients").count, publicDegree)
        for label in ["lhs", "rhs", "sum", "negacyclic_product"] {
            try assertBfvRnsPolynomialFixture(
                label,
                try object(samples, label),
                publicDegree: publicDegree,
                limbCount: moduli.count
            )
        }
    }

    private func assertBfvRnsPolynomialFixture(
        _ label: String,
        _ polynomial: [String: Any],
        publicDegree: Int,
        limbCount: Int
    ) throws {
        XCTAssertEqual(try int(polynomial, "coefficient_count"), publicDegree)
        let limbHashes = try stringArray(polynomial, "residue_limb_sha256")
        XCTAssertEqual(limbHashes.count, limbCount)
        assertBfvUpperSha256("\(label) RNS reconstructed coefficients", try string(polynomial, "reconstructed_sha256"))
        for (index, digest) in limbHashes.enumerated() {
            assertBfvUpperSha256("\(label) RNS residue limb \(index)", digest)
        }
    }

    private func assertBfvComponentDigest(_ label: String, _ value: String, seen: inout Set<String>) throws {
        guard value.count == 64 else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must be 32-byte hex"])
        }
        let nonHex = value.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789ABCDEF").inverted)
        guard nonHex == nil else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must be uppercase hex"])
        }
        guard value != String(repeating: "0", count: 64) else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must not be zero"])
        }
        let inserted = seen.insert(value).inserted
        guard inserted else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must be unique"])
        }
    }

    private func assertBfvUpperSha256(_ label: String, _ value: String) {
        XCTAssertEqual(value.count, 64, "\(label) must be 32-byte hex")
        XCTAssertNil(value.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789ABCDEF").inverted), "\(label) must be uppercase hex")
        XCTAssertNotEqual(value, String(repeating: "0", count: 64), "\(label) must not be zero")
    }

    private func balancedBfvMultiplicationDepth(_ inputCount: Int) -> Int {
        XCTAssertGreaterThan(inputCount, 0, "BFV multiplication depth requires at least one input")
        var covered = 1
        var depth = 0
        while covered < inputCount {
            covered *= 2
            depth += 1
        }
        return depth
    }

    private func assertBfvLowerDigest(_ label: String, _ value: String) {
        XCTAssertEqual(value.count, 64, "\(label) must be 32-byte hex")
        XCTAssertNil(value.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789abcdef").inverted), "\(label) must be lowercase hex")
        XCTAssertNotEqual(value, String(repeating: "0", count: 64), "\(label) must not be zero")
    }

    private func requireBfvLowerDigest(_ label: String, _ value: String) throws {
        guard value.count == 64 else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must be 32-byte hex"])
        }
        guard value.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789abcdef").inverted) == nil else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must be lowercase hex"])
        }
        guard value != String(repeating: "0", count: 64) else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(label) must not be zero"])
        }
    }

    private func bool(_ root: [String: Any], _ key: String) throws -> Bool {
        guard let value = root[key] as? Bool else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be a bool"])
        }
        return value
    }

    private func int(_ root: [String: Any], _ key: String) throws -> Int {
        guard let value = root[key] as? NSNumber else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be a number"])
        }
        return value.intValue
    }

    private func uint64(_ root: [String: Any], _ key: String) throws -> UInt64 {
        if let value = root[key] as? NSNumber {
            return UInt64(truncating: value)
        }
        if let value = root[key] as? String, let parsed = UInt64(value) {
            return parsed
        }
        throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be an unsigned integer"])
    }

    private func uint64Array(_ root: [String: Any], _ key: String) throws -> [UInt64] {
        guard let values = root[key] as? [Any] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be a number array"])
        }
        return try values.map { value in
            if let number = value as? NSNumber {
                return UInt64(truncating: number)
            }
            if let string = value as? String, let parsed = UInt64(string) {
                return parsed
            }
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must contain unsigned integers"])
        }
    }

    private func stringArray(_ root: [String: Any], _ key: String) throws -> [String] {
        guard let values = root[key] as? [String] else {
            throw NSError(domain: "ToriiClientTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(key) must be a string array"])
        }
        return values
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionEntrypointAsync() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody())
            case "/v1/pipeline/transaction-entrypoints":
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), ToriiWireFormatPreference.noritoPreferred.acceptHeader)
                XCTAssertEqual(self.bodyData(from: request), Data([0xAA, 0xBB]))
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 202,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let body = """
                {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":3,"submitted_at_height":4,"signer":"entry-signer"},"signature":"feedface"}
                """.data(using: .utf8)!
                return (response, body)
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        let payload = try await makeClient().submitTransactionEntrypoint(data: Data([0xAA, 0xBB]))
        XCTAssertEqual(payload?.hash, Self.pipelineHash)
        XCTAssertEqual(payload?.payload.submittedAtMs, 3)
        XCTAssertEqual(payload?.payload.submittedAtHeight, 4)
        XCTAssertEqual(payload?.payload.signer, "entry-signer")
        XCTAssertEqual(payload?.signature, "feedface")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCurrentV1TransactionIngressSurfacesRequireExact202() async throws {
        enum Surface: String, CaseIterable {
            case transactionJson
            case entrypointNorito
            case entrypointJson

            var path: String {
                switch self {
                case .transactionJson:
                    "/v1/pipeline/transactions"
                case .entrypointNorito, .entrypointJson:
                    "/v1/pipeline/transaction-entrypoints"
                }
            }
        }

        for surface in Surface.allCases {
            for statusCode in [200, 201, 204] {
                var submissionCount = 0
                StubURLProtocol.handler = { request in
                    switch request.url?.path {
                    case "/v1/node/capabilities":
                        let response = HTTPURLResponse(
                            url: request.url!,
                            statusCode: 200,
                            httpVersion: nil,
                            headerFields: ["Content-Type": "application/json"]
                        )!
                        return (response, self.nodeCapabilitiesBody())
                    case surface.path:
                        submissionCount += 1
                        let response = HTTPURLResponse(
                            url: request.url!,
                            statusCode: statusCode,
                            httpVersion: nil,
                            headerFields: ["Content-Type": "application/json"]
                        )!
                        return (response, Data())
                    default:
                        XCTFail("unexpected request: \(request.url?.path ?? "")")
                        let response = HTTPURLResponse(
                            url: request.url!,
                            statusCode: 404,
                            httpVersion: nil,
                            headerFields: nil
                        )!
                        return (response, Data())
                    }
                }

                let client = makeClient()
                do {
                    switch surface {
                    case .transactionJson:
                        _ = try await client.submitTransaction(
                            jsonData: Data("{\"version\":1,\"content\":{}}".utf8)
                        )
                    case .entrypointNorito:
                        _ = try await client.submitTransactionEntrypoint(data: Data([1]))
                    case .entrypointJson:
                        _ = try await client.submitTransactionEntrypoint(
                            jsonData: Data("{\"version\":1,\"content\":{}}".utf8)
                        )
                    }
                    XCTFail("\(surface.rawValue) must reject HTTP \(statusCode)")
                } catch let error as ToriiClientError {
                    guard case let .api(apiError) = error else {
                        return XCTFail("unexpected \(surface.rawValue) error: \(error)")
                    }
                    let code = apiError.status
                    XCTAssertEqual(code, statusCode)
                }
                XCTAssertEqual(
                    submissionCount,
                    1,
                    "\(surface.rawValue) HTTP \(statusCode) must remain one-shot"
                )
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectCodeHeaderSurfaced() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody())
            case "/v1/pipeline/transactions":
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), ToriiWireFormatPreference.noritoPreferred.acceptHeader)
                let headers = [
                    "Content-Type": "application/json",
                    "x-iroha-reject-code": "PRTRY:TX_SIGNATURE_MISSING"
                ]
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 400,
                                               httpVersion: nil,
                                               headerFields: headers)!
                let body = """
                {"message":"failed to accept transaction"}
                """.data(using: .utf8)!
                return (response, body)
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected rejection")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 400)
            XCTAssertEqual(rejectCode, "PRTRY:TX_SIGNATURE_MISSING")
            XCTAssertEqual(message, "failed to accept transaction")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsMismatchedDataModelVersion() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody(dataModelVersion: 9))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted with data model mismatch")
                let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected data model mismatch")
        } catch let error as ToriiClientError {
            guard case let .dataModelMismatch(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, ToriiNodeCapabilities.expectedDataModelVersion)
            XCTAssertEqual(actual, 9)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsMissingSignedTransactionSchemaHash() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody(signedTransactionSchemaHashHex: nil))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted with missing schema hash")
                let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected schema mismatch")
        } catch let error as ToriiClientError {
            guard case let .transactionSchemaMismatch(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, ToriiNodeCapabilities.expectedSignedTransactionSchemaHashHex)
            XCTAssertNil(actual)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsInvalidSignedTransactionSchemaHash() async throws {
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody(signedTransactionSchemaHashHex: "ABC123"))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted with invalid schema hash")
                let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected schema mismatch")
        } catch let error as ToriiClientError {
            guard case let .transactionSchemaMismatch(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, ToriiNodeCapabilities.expectedSignedTransactionSchemaHashHex)
            XCTAssertEqual(actual, "ABC123")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsMismatchedSignedTransactionSchemaHash() async throws {
        let mismatchedHash = "00000000000000000000000000000000"
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody(signedTransactionSchemaHashHex: mismatchedHash))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted with schema hash mismatch")
                let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected schema mismatch")
        } catch let error as ToriiClientError {
            guard case let .transactionSchemaMismatch(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, ToriiNodeCapabilities.expectedSignedTransactionSchemaHashHex)
            XCTAssertEqual(actual, mismatchedHash)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsMissingCapabilitiesProbe() async throws {
        let lock = NSLock()
        var paths: [String] = []
        StubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            lock.lock()
            paths.append(path)
            lock.unlock()
            switch path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 404,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/plain"])!
                return (response, Data("missing".utf8))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted after missing capabilities")
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 500,
                                               httpVersion: nil,
                                               headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(path)")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected missing capabilities to reject submission")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            XCTAssertEqual(code, 404)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(paths, ["/v1/node/capabilities"])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsRateLimitedCapabilitiesProbe() async throws {
        let lock = NSLock()
        var paths: [String] = []
        StubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            lock.lock()
            paths.append(path)
            lock.unlock()
            switch path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 429,
                                               httpVersion: nil,
                                               headerFields: ["Retry-After": "1"])!
                return (response, Data("rate limited".utf8))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted after rate-limited capabilities")
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 500,
                                               httpVersion: nil,
                                               headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(path)")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected rate-limited capabilities to reject submission")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            XCTAssertEqual(code, 429)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(paths, ["/v1/node/capabilities"])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitTransactionRejectsServerErrorCapabilitiesProbe() async throws {
        let lock = NSLock()
        var paths: [String] = []
        StubURLProtocol.handler = { request in
            let path = request.url?.path ?? ""
            lock.lock()
            paths.append(path)
            lock.unlock()
            switch path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 502,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/plain"])!
                return (response, Data("bad gateway".utf8))
            case "/v1/pipeline/transactions":
                XCTFail("transaction submitted after failed capabilities")
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 500,
                                               httpVersion: nil,
                                               headerFields: nil)!
                return (response, Data())
            default:
                XCTFail("unexpected request: \(path)")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        do {
            _ = try await makeClient().submitTransaction(
                data: try canonicalSignedPipelineTransaction()
            )
            XCTFail("expected failed capabilities to reject submission")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            XCTAssertEqual(code, 502)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(paths, ["/v1/node/capabilities"])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConnectStatusParsesSnapshot() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/status/aggregate")
            self.assertOperatorAuthentication(request)
            let payload: [String: Any] = [
                "enabled": true,
                "sessions_total": 10,
                "sessions_active": 7,
                "per_ip_sessions": [
                    ["ip": "1.1.1.1", "sessions": 3]
                ],
                "buffered_sessions": 2,
                "total_buffer_bytes": 128,
                "dedupe_size": 4,
                "policy": [
                    "ws_max_sessions": 50,
                    "session_ttl_ms": 60000,
                    "relay_enabled": true,
                    "relay_strategy": "broadcast",
                    "relay_effective_strategy": "local_only",
                    "relay_p2p_attached": false,
                    "p2p_ttl_hops": 2
                ],
                "frames_in_total": 11,
                "frames_out_total": 12,
                "ciphertext_total": 13,
                "dedupe_drops_total": 1,
                "buffer_drops_total": 2,
                "plaintext_control_drops_total": 3,
                "monotonic_drops_total": 4,
                "sequence_violation_closes_total": 5,
                "role_direction_mismatch_total": 6,
                "ping_miss_total": 7,
                "p2p_rebroadcasts_total": 8,
                "p2p_rebroadcast_skipped_total": 9,
                "p2p_auth_failures_total": 10,
                "p2p_ttl_drops_total": 11,
                "p2p_unknown_session_drops_total": 12,
                "p2p_session_claims_in_total": 13,
                "p2p_session_claims_installed_total": 14,
                "p2p_session_claim_conflicts_total": 15,
                "p2p_role_consumed_total": 16,
                "p2p_session_terminated_total": 17
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }
        let snapshot = try await makeClient().getConnectStatus()
        let status = try XCTUnwrap(snapshot)
        XCTAssertTrue(status.enabled)
        XCTAssertEqual(status.sessionsTotal, 10)
        XCTAssertEqual(status.perIpSessions.first?.ip, "1.1.1.1")
        XCTAssertEqual(status.policy?.wsMaxSessions, 50)
        XCTAssertEqual(status.policy?.relayStrategy, "broadcast")
        XCTAssertEqual(status.policy?.p2pTtlHops, 2)
        XCTAssertEqual(status.sequenceViolationClosesTotal, 5)
        XCTAssertEqual(status.p2pAuthFailuresTotal, 10)
        XCTAssertEqual(status.p2pSessionClaimsInstalledTotal, 14)
        XCTAssertEqual(status.p2pSessionTerminatedTotal, 17)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConnectStatusReturnsNilFor404() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/status/aggregate")
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let snapshot = try await makeClient().getConnectStatus()
        XCTAssertNil(snapshot)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCreateConnectSessionPostsPayload() async throws {
        let networkID = TestNetworkIds.canonical
        let appPublicKey = Data(repeating: 0x31, count: 32)
        let nonce = Data(repeating: 0x32, count: 16)
        let sid = try ConnectCrypto.deriveSessionID(
            networkID: networkID,
            appPublicKey: appPublicKey,
            nonce: nonce
        )
        let sidLiteral = toriiClientTestBase64URL(sid)
        let appPublicKeyLiteral = toriiClientTestBase64URL(appPublicKey)
        let nonceLiteral = toriiClientTestBase64URL(nonce)
        let connectResponse = toriiClientTestConnectSessionResponse(
            sid: sidLiteral,
            networkID: networkID.literal,
            appPublicKey: appPublicKeyLiteral,
            nonce: nonceLiteral,
            node: "node-1"
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/session")
            XCTAssertEqual(request.httpMethod, "POST")
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["sid"] as? String, sidLiteral)
            XCTAssertEqual(body["network_id"] as? String, networkID.literal)
            XCTAssertEqual(body["app_pk"] as? String, appPublicKeyLiteral)
            XCTAssertEqual(body["nonce"] as? String, nonceLiteral)
            XCTAssertEqual(body["node"] as? String, "node-1")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: connectResponse.payload)
            return (response, data)
        }
        let response = try await makeClient().createConnectSession(
            networkID: networkID,
            appPublicKey: appPublicKey,
            nonce: nonce,
            node: "node-1"
        )
        XCTAssertEqual(response.sid, sidLiteral)
        XCTAssertEqual(response.tokenWallet, connectResponse.tokenWallet)
        XCTAssertEqual(response.tokenManagement, connectResponse.tokenManagement)
        XCTAssertEqual(response.tokenRelay, connectResponse.tokenRelay)
        XCTAssertTrue(response.extra.isEmpty)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testDeleteConnectSessionHandles404() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/session/sid-1")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer token-management")
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let deleted = try await makeClient().deleteConnectSession(sid: "sid-1", tokenManagement: "token-management")
        XCTAssertFalse(deleted)
    }

    private func vpnProfileResponsePayload() -> [String: Any] {
        [
            "available": true,
            "supported_exit_classes": ["standard", "low-latency", "high-security"],
            "default_exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
            "lease_secs": 900,
            "dns_push_interval_secs": 60,
            "route_pushes": ["0.0.0.0/0"],
            "excluded_routes": ["10.0.0.0/8"],
            "dns_servers": ["1.1.1.1"],
            "tunnel_addresses": ["10.208.0.2/32"],
            "mtu_bytes": 1280,
            "meter_family": "vpn-standard",
            "display_billing_label": "standard vpn",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "settlement_grace_secs": 60,
            "flow_label_bits": 24,
            "padding_budget_ms": 15,
            "relay_id_hex": vpnRelayIdHex,
            "relay_mldsa65_public_key_hex": vpnRelayMldsa65PublicKeyHex,
            "descriptor_commit_hex": String(repeating: "cd", count: 32),
            "tls_server_name": "vpn.sora.org",
            "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
            "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
            "directory_snapshot_digest_hex": String(repeating: "42", count: 32)
        ]
    }

    private func vpnQuoteResponsePayload() -> [String: Any] {
        let quoteId = String(repeating: "11", count: 32)
        let instruction: [String: Any] = ["wire_id": "OpenVpnLeaseEscrow", "payload_hex": "abcd"]
        return [
            "quote_id": quoteId,
            "lease_id_hex": quoteId,
            "session_id_hex": String(repeating: "22", count: 16),
            "payment_reference": quoteId,
            "account_id": "alice",
            "exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
            "lease_secs": 900,
            "quote_expires_at_ms": 1_700_000_900_000,
            "fee_asset_id": "xor#universal.universal",
            "escrow_account_id": "vpn_escrow",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "route_pushes": [],
            "excluded_routes": [],
            "dns_servers": ["1.1.1.1"],
            "tunnel_addresses": ["10.208.0.2/32"],
            "mtu_bytes": 1280,
            "meter_family": "vpn-standard",
            "flow_label_bits": 24,
            "padding_budget_ms": 15,
            "relay_id_hex": vpnRelayIdHex,
            "relay_mldsa65_public_key_hex": vpnRelayMldsa65PublicKeyHex,
            "descriptor_commit_hex": String(repeating: "cd", count: 32),
            "tls_server_name": "vpn.sora.org",
            "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
            "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
            "directory_snapshot_digest_hex": String(repeating: "42", count: 32),
            "metering_public_key_hex": String(repeating: "44", count: 32),
            "open_lease_instruction": instruction
        ]
    }

    private func vpnSessionResponsePayload() -> [String: Any] {
        let sessionId = String(repeating: "55", count: 16)
        let quoteId = String(repeating: "56", count: 32)
        return [
            "session_id": sessionId,
            "account_id": "alice",
            "exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
            "lease_secs": 900,
            "expires_at_ms": 1_700_000_900_000,
            "connected_at_ms": 1_700_000_000_000,
            "meter_family": "vpn-standard",
            "quote_id": quoteId,
            "payment_reference": quoteId,
            "payment_tx_hash": String(repeating: "66", count: 32),
            "fee_asset_id": "xor#universal.universal",
            "escrow_account_id": "vpn_escrow",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "flow_label_bits": 24,
            "padding_budget_ms": 15,
            "relay_id_hex": vpnRelayIdHex,
            "relay_mldsa65_public_key_hex": vpnRelayMldsa65PublicKeyHex,
            "descriptor_commit_hex": String(repeating: "cd", count: 32),
            "tls_server_name": "vpn.sora.org",
            "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
            "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
            "directory_snapshot_digest_hex": String(repeating: "42", count: 32),
            "route_pushes": [],
            "excluded_routes": [],
            "dns_servers": [],
            "tunnel_addresses": ["10.208.0.2/32"],
            "mtu_bytes": 1280,
            "helper_ticket_hex": "5356504e48543100" + String(repeating: "00", count: 780),
            "bytes_in": 0,
            "bytes_out": 0,
            "status": "active"
        ]
    }

    private func vpnReceiptResponsePayload() -> [String: Any] {
        let sessionId = String(repeating: "77", count: 16)
        let quoteId = String(repeating: "78", count: 32)
        let leaseId = String(repeating: "79", count: 32)
        return [
            "session_id": sessionId,
            "account_id": "alice",
            "exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/tcp/443/wss",
            "meter_family": "vpn-standard",
            "connected_at_ms": 1,
            "disconnected_at_ms": 2,
            "duration_ms": 1,
            "bytes_in": 10,
            "bytes_out": 20,
            "status": "settled",
            "receipt_source": "relay",
            "quote_id": quoteId,
            "payment_tx_hash": String(repeating: "88", count: 32),
            "fee_asset_id": "xor#universal.universal",
            "escrow_account_id": "vpn_escrow",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "earned_fee": "700000.125",
            "refunded_fee": "300000.125",
            "lease_id_hex": leaseId,
            "settle_lease_instruction": NSNull()
        ]
    }

    func testVpnReceiptStatusValidatorRetainsExactLifecycleValues() throws {
        let decoder = JSONDecoder()
        let statuses = [
            "disconnected",
            "expired",
            "replaced",
            "settlement_pending",
            "settled"
        ]
        for status in statuses {
            var payload = vpnReceiptResponsePayload()
            payload["status"] = status
            let receipt = try decoder.decode(
                ToriiVpnReceipt.self,
                from: JSONSerialization.data(withJSONObject: payload)
            )
            XCTAssertEqual(receipt.status, status)
        }

        var padded = vpnReceiptResponsePayload()
        padded["status"] = "settlement_pending "
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceipt.self,
                from: JSONSerialization.data(withJSONObject: padded)
            )
        )
    }

    func testVpnResponseModelsRejectUnknownFields() throws {
        let decoder = JSONDecoder()
        let fixtures: [(String, [String: Any], (Data) throws -> Void)] = [
            ("profile", vpnProfileResponsePayload(), { _ = try decoder.decode(ToriiVpnProfile.self, from: $0) }),
            ("quote", vpnQuoteResponsePayload(), { _ = try decoder.decode(ToriiVpnQuote.self, from: $0) }),
            ("session", vpnSessionResponsePayload(), { _ = try decoder.decode(ToriiVpnSession.self, from: $0) }),
            ("receipt", vpnReceiptResponsePayload(), { _ = try decoder.decode(ToriiVpnReceipt.self, from: $0) }),
            ("receipt list", ["items": [vpnReceiptResponsePayload()], "total": 1], {
                _ = try decoder.decode(ToriiVpnReceiptListResponse.self, from: $0)
            })
        ]

        for (label, original, decode) in fixtures {
            var payload = original
            payload["unexpected"] = true
            let data = try JSONSerialization.data(withJSONObject: payload)
            XCTAssertThrowsError(try decode(data), label)
        }

        var quote = vpnQuoteResponsePayload()
        var instruction = try XCTUnwrap(quote["open_lease_instruction"] as? [String: Any])
        instruction["unexpected"] = true
        quote["open_lease_instruction"] = instruction
        let nestedData = try JSONSerialization.data(withJSONObject: quote)
        XCTAssertThrowsError(try decoder.decode(ToriiVpnQuote.self, from: nestedData))
    }

    func testVpnResponseModelsRejectNonCanonicalIdentifiersAndHashes() throws {
        let decoder = JSONDecoder()

        var profile = vpnProfileResponsePayload()
        profile["relay_tls_spki_sha256_hex"] = String(repeating: "AB", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["relay_id_hex"] = String(repeating: "00", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["relay_mldsa65_public_key_hex"] = String(repeating: "AB", count: 1_952)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["relay_mldsa65_public_key_hex"] = String(repeating: "00", count: 1_952)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["relay_mldsa65_public_key_hex"] = String(repeating: "ab", count: 1_951)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["directory_snapshot_digest_hex"] = String(repeating: "00", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )
        profile = vpnProfileResponsePayload()
        profile["tls_server_name"] = "VPN.sora.org"
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnProfile.self,
                from: JSONSerialization.data(withJSONObject: profile)
            )
        )

        var quote = vpnQuoteResponsePayload()
        quote["quote_id"] = "0x" + String(repeating: "11", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnQuote.self,
                from: JSONSerialization.data(withJSONObject: quote)
            )
        )
        quote = vpnQuoteResponsePayload()
        quote["session_id_hex"] = String(repeating: "AA", count: 16)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnQuote.self,
                from: JSONSerialization.data(withJSONObject: quote)
            )
        )
        quote = vpnQuoteResponsePayload()
        quote["payment_reference"] = String(repeating: "11", count: 16)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnQuote.self,
                from: JSONSerialization.data(withJSONObject: quote)
            )
        )
        for (label, malformedKey) in [
            ("uppercase", String(repeating: "AB", count: 1_952)),
            ("all-zero", String(repeating: "00", count: 1_952)),
            ("wrong-length", String(repeating: "ab", count: 1_951))
        ] {
            quote = vpnQuoteResponsePayload()
            quote["relay_mldsa65_public_key_hex"] = malformedKey
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnQuote.self,
                    from: JSONSerialization.data(withJSONObject: quote)
                ),
                "quote should reject \(label) relay ML-DSA public keys"
            )
        }

        var session = vpnSessionResponsePayload()
        session["session_id"] = String(repeating: "AA", count: 16)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnSession.self,
                from: JSONSerialization.data(withJSONObject: session)
            )
        )
        session = vpnSessionResponsePayload()
        session["payment_reference"] = "0x" + String(repeating: "56", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnSession.self,
                from: JSONSerialization.data(withJSONObject: session)
            )
        )
        session = vpnSessionResponsePayload()
        session["session_id"] = String(repeating: "aa", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnSession.self,
                from: JSONSerialization.data(withJSONObject: session)
            )
        )
        session = vpnSessionResponsePayload()
        session["payment_tx_hash"] = "0x" + String(repeating: "66", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnSession.self,
                from: JSONSerialization.data(withJSONObject: session)
            )
        )
        for (label, malformedKey) in [
            ("uppercase", String(repeating: "AB", count: 1_952)),
            ("all-zero", String(repeating: "00", count: 1_952)),
            ("wrong-length", String(repeating: "ab", count: 1_951))
        ] {
            session = vpnSessionResponsePayload()
            session["relay_mldsa65_public_key_hex"] = malformedKey
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnSession.self,
                    from: JSONSerialization.data(withJSONObject: session)
                ),
                "session should reject \(label) relay ML-DSA public keys"
            )
        }

        var receipt = vpnReceiptResponsePayload()
        receipt["lease_id_hex"] = "0x" + String(repeating: "77", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceipt.self,
                from: JSONSerialization.data(withJSONObject: receipt)
            )
        )
        receipt = vpnReceiptResponsePayload()
        receipt["payment_tx_hash"] = String(repeating: "AA", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceipt.self,
                from: JSONSerialization.data(withJSONObject: receipt)
            )
        )
        receipt = vpnReceiptResponsePayload()
        receipt["session_id"] = String(repeating: "aa", count: 32)
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceipt.self,
                from: JSONSerialization.data(withJSONObject: receipt)
            )
        )
    }

    func testVpnSessionIdNormalizerAccepts16BytesAndRejects32Bytes() throws {
        let sessionId = String(repeating: "ab", count: 16)
        XCTAssertEqual(
            try ToriiRequestValidation.normalized16ByteHex("0X\(sessionId.uppercased())", field: "sessionId"),
            sessionId
        )
        XCTAssertThrowsError(
            try ToriiRequestValidation.normalized16ByteHex(
                String(repeating: "ab", count: 32),
                field: "sessionId"
            )
        )
    }

    func testVpnResponseModelsRejectMissingRequiredFields() throws {
        let decoder = JSONDecoder()
        let fixtures: [(String, [String: Any], String, (Data) throws -> Void)] = [
            ("required profile TLS pin", vpnProfileResponsePayload(), "relay_tls_spki_sha256_hex", {
                _ = try decoder.decode(ToriiVpnProfile.self, from: $0)
            }),
            ("required quote instruction", vpnQuoteResponsePayload(), "open_lease_instruction", {
                _ = try decoder.decode(ToriiVpnQuote.self, from: $0)
            }),
            ("required session route list", vpnSessionResponsePayload(), "route_pushes", {
                _ = try decoder.decode(ToriiVpnSession.self, from: $0)
            }),
            ("required nullable receipt instruction", vpnReceiptResponsePayload(), "settle_lease_instruction", {
                _ = try decoder.decode(ToriiVpnReceipt.self, from: $0)
            }),
            ("required receipt-list items", ["items": [vpnReceiptResponsePayload()], "total": 1], "items", {
                _ = try decoder.decode(ToriiVpnReceiptListResponse.self, from: $0)
            })
        ]

        for (label, original, missingKey, decode) in fixtures {
            var payload = original
            payload.removeValue(forKey: missingKey)
            let data = try JSONSerialization.data(withJSONObject: payload)
            XCTAssertThrowsError(try decode(data), label)
        }

        var quote = vpnQuoteResponsePayload()
        var instruction = try XCTUnwrap(quote["open_lease_instruction"] as? [String: Any])
        instruction.removeValue(forKey: "payload_hex")
        quote["open_lease_instruction"] = instruction
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnQuote.self,
                from: JSONSerialization.data(withJSONObject: quote)
            )
        )
    }

    func testVpnResponseModelsRequireCompleteTrustTuple() throws {
        let decoder = JSONDecoder()
        let trustKeys = [
            "relay_id_hex",
            "relay_mldsa65_public_key_hex",
            "descriptor_commit_hex",
            "tls_server_name",
            "relay_tls_spki_sha256_hex",
            "relay_certificate_sha256_hex",
            "directory_snapshot_digest_hex"
        ]
        let fixtures: [(String, [String: Any], (Data) throws -> Void)] = [
            ("profile", vpnProfileResponsePayload(), {
                _ = try decoder.decode(ToriiVpnProfile.self, from: $0)
            }),
            ("quote", vpnQuoteResponsePayload(), {
                _ = try decoder.decode(ToriiVpnQuote.self, from: $0)
            }),
            ("session", vpnSessionResponsePayload(), {
                _ = try decoder.decode(ToriiVpnSession.self, from: $0)
            })
        ]

        for (label, original, decode) in fixtures {
            for key in trustKeys {
                var payload = original
                payload.removeValue(forKey: key)
                XCTAssertThrowsError(
                    try decode(JSONSerialization.data(withJSONObject: payload)),
                    "\(label) missing \(key)"
                )
            }
        }
    }

    func testUnavailableVpnProfileAcceptsExplicitEmptyTrustTuple() throws {
        var payload = vpnProfileResponsePayload()
        payload["available"] = false
        payload["relay_endpoint"] = ""
        for key in [
            "relay_id_hex",
            "relay_mldsa65_public_key_hex",
            "descriptor_commit_hex",
            "tls_server_name",
            "relay_tls_spki_sha256_hex",
            "relay_certificate_sha256_hex",
            "directory_snapshot_digest_hex"
        ] {
            payload[key] = ""
        }

        let profile = try JSONDecoder().decode(
            ToriiVpnProfile.self,
            from: JSONSerialization.data(withJSONObject: payload)
        )
        XCTAssertFalse(profile.available)
        XCTAssertEqual(profile.relayEndpoint, "")
        XCTAssertEqual(profile.relayIdHex, "")
        XCTAssertEqual(profile.relayMldsa65PublicKeyHex, "")
        XCTAssertEqual(profile.descriptorCommitHex, "")
        XCTAssertEqual(profile.tlsServerName, "")
        XCTAssertEqual(profile.relayTlsSpkiSha256Hex, "")
        XCTAssertEqual(profile.relayCertificateSha256Hex, "")
        XCTAssertEqual(profile.directorySnapshotDigestHex, "")
    }

    func testVpnResponseModelsRejectOpenApiConstraintViolations() throws {
        let decoder = JSONDecoder()
        let invalidProfileFields: [(String, Any)] = [
            ("supported_exit_classes", ["standard", "low-latency"]),
            ("supported_exit_classes", ["standard", "standard", "high-security"]),
            ("default_exit_class", "unsupported"),
            ("lease_secs", 0),
            ("lease_secs", 4_294_967_296 as UInt64),
            ("mtu_bytes", 1_279),
            ("settlement_grace_secs", 0),
            ("flow_label_bits", 23),
            ("padding_budget_ms", 0),
            ("route_pushes", NSNull())
        ]
        for (field, value) in invalidProfileFields {
            var profile = vpnProfileResponsePayload()
            profile[field] = value
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnProfile.self,
                    from: JSONSerialization.data(withJSONObject: profile)
                ),
                field
            )
        }

        for retiredField in ["fee_asset_id", "escrow_account_id"] {
            var profile = vpnProfileResponsePayload()
            profile[retiredField] = "retired"
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnProfile.self,
                    from: JSONSerialization.data(withJSONObject: profile)
                ),
                retiredField
            )
        }

        var quoteWithRetiredInstructions = vpnQuoteResponsePayload()
        quoteWithRetiredInstructions["tx_instructions"] = []
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnQuote.self,
                from: JSONSerialization.data(withJSONObject: quoteWithRetiredInstructions)
            )
        )

        for (field, value) in [("exit_class", "unsupported"), ("status", "settled")] {
            var session = vpnSessionResponsePayload()
            session[field] = value
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnSession.self,
                    from: JSONSerialization.data(withJSONObject: session)
                ),
                field
            )
        }

        let invalidReceipts: [(String, Any)] = [
            ("status", "active"),
            ("receipt_source", "operator"),
            ("tx_instructions", [])
        ]
        for (field, value) in invalidReceipts {
            var receipt = vpnReceiptResponsePayload()
            receipt[field] = value
            XCTAssertThrowsError(
                try decoder.decode(
                    ToriiVpnReceipt.self,
                    from: JSONSerialization.data(withJSONObject: receipt)
                ),
                field
            )
        }

        var oversizedItems: [String: Any] = [
            "items": Array(repeating: vpnReceiptResponsePayload(), count: 25),
            "total": 24
        ]
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceiptListResponse.self,
                from: JSONSerialization.data(withJSONObject: oversizedItems)
            )
        )
        oversizedItems = ["items": [], "total": 25]
        XCTAssertThrowsError(
            try decoder.decode(
                ToriiVpnReceiptListResponse.self,
                from: JSONSerialization.data(withJSONObject: oversizedItems)
            )
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetVpnProfileDeserializesNativeLeaseFields() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/vpn/profile")
            let payload: [String: Any] = [
                "available": true,
                "supported_exit_classes": ["standard", "low-latency", "high-security"],
                "default_exit_class": "standard",
                "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
                "lease_secs": 900,
                "dns_push_interval_secs": 60,
                "route_pushes": ["0.0.0.0/0"],
                "excluded_routes": ["10.0.0.0/8"],
                "dns_servers": ["1.1.1.1"],
                "tunnel_addresses": ["10.208.0.2/32"],
                "mtu_bytes": 1280,
                "meter_family": "vpn-standard",
                "display_billing_label": "standard vpn",
                "operator_account_id": "vpn_operator",
                "lease_fee": "1000000.25",
                "settlement_grace_secs": 60,
                "flow_label_bits": 24,
                "padding_budget_ms": 15,
                "relay_id_hex": self.vpnRelayIdHex,
                "relay_mldsa65_public_key_hex": self.vpnRelayMldsa65PublicKeyHex,
                "descriptor_commit_hex": String(repeating: "cd", count: 32),
                "tls_server_name": "vpn.sora.org",
                "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
                "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
                "directory_snapshot_digest_hex": String(repeating: "42", count: 32)
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, try JSONSerialization.data(withJSONObject: payload))
        }
        let profile = try await makeClient().getVpnProfile()
        XCTAssertTrue(profile.available)
        XCTAssertEqual(profile.leaseFee, "1000000.25")
        XCTAssertEqual(profile.dnsPushIntervalSecs, 60)
        XCTAssertEqual(profile.flowLabelBits, 24)
        XCTAssertEqual(profile.relayIdHex, vpnRelayIdHex)
        XCTAssertEqual(profile.relayMldsa65PublicKeyHex, vpnRelayMldsa65PublicKeyHex)
        XCTAssertEqual(profile.descriptorCommitHex, String(repeating: "cd", count: 32))
        XCTAssertEqual(profile.tlsServerName, "vpn.sora.org")
        XCTAssertEqual(profile.relayTlsSpkiSha256Hex, String(repeating: "ab", count: 32))
        XCTAssertEqual(profile.relayCertificateSha256Hex, String(repeating: "ef", count: 32))
        XCTAssertEqual(profile.directorySnapshotDigestHex, String(repeating: "42", count: 32))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVpnRoutesRejectInsecureBaseURLBeforeTransportDispatch() async {
        let client = makeClient(baseURL: URL(string: "http://example.test")!)
        let sessionId = String(repeating: "11", count: 16)
        let quoteId = String(repeating: "12", count: 32)
        let leaseId = String(repeating: "13", count: 32)
        let auth = ToriiCanonicalRequestAuth(
            accountId: "alice@universal",
            privateKey: Data(repeating: 7, count: 32)
        )
        let operations: [(String, () async throws -> Void)] = [
            ("profile", { _ = try await client.getVpnProfile() }),
            ("quote", {
                _ = try await client.createVpnQuote(
                    ToriiVpnQuoteCreateRequest(
                        exitClass: "standard",
                        meteringPublicKeyHex: String(repeating: "22", count: 32)
                    ),
                    canonicalAuth: auth
                )
            }),
            ("session create", {
                _ = try await client.createVpnSession(
                    ToriiVpnSessionCreateRequest(
                        exitClass: "standard",
                        quoteId: quoteId,
                        paymentTransactionHash: String(repeating: "33", count: 32),
                        meteringPublicKeyHex: String(repeating: "44", count: 32)
                    ),
                    canonicalAuth: auth
                )
            }),
            ("session read", {
                _ = try await client.getVpnSession(sessionId: sessionId, canonicalAuth: auth)
            }),
            ("receipt submit", {
                _ = try await client.submitVpnReceipt(
                    ToriiVpnReceiptSubmitRequest(
                        relayReceiptHex: "abcd",
                        clientVoucherHex: "beef",
                        leaseIdHex: leaseId
                    ),
                    canonicalAuth: auth
                )
            }),
            ("receipt list", {
                _ = try await client.listVpnReceipts(canonicalAuth: auth)
            }),
        ]

        var dispatched = false
        StubURLProtocol.handler = { request in
            dispatched = true
            XCTFail("insecure VPN request reached transport dispatch: \(request)")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data())
        }

        for (label, operation) in operations {
            await XCTAssertThrowsErrorAsync(try await operation()) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("expected HTTPS rejection for \(label), got \(error)")
                }
                XCTAssertEqual(
                    reason,
                    "Sora VPN Torii requests require an HTTPS base URL.",
                    label
                )
            }
            XCTAssertFalse(dispatched, "\(label) reached transport dispatch")
        }
    }

    func testVpnProfileRejectsMissingOrOutOfRangeDnsPushInterval() throws {
        let validPayload: [String: Any] = [
            "available": true,
            "supported_exit_classes": ["standard", "low-latency", "high-security"],
            "default_exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
            "lease_secs": 900,
            "dns_push_interval_secs": 60,
            "route_pushes": ["0.0.0.0/0"],
            "excluded_routes": ["10.0.0.0/8"],
            "dns_servers": ["1.1.1.1"],
            "tunnel_addresses": ["10.208.0.2/32"],
            "mtu_bytes": 1280,
            "meter_family": "vpn-standard",
            "display_billing_label": "standard vpn",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "settlement_grace_secs": 60,
            "flow_label_bits": 24,
            "padding_budget_ms": 15,
            "relay_id_hex": vpnRelayIdHex,
            "relay_mldsa65_public_key_hex": vpnRelayMldsa65PublicKeyHex,
            "descriptor_commit_hex": String(repeating: "cd", count: 32),
            "tls_server_name": "vpn.sora.org",
            "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
            "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
            "directory_snapshot_digest_hex": String(repeating: "42", count: 32)
        ]
        var missing = validPayload
        missing.removeValue(forKey: "dns_push_interval_secs")
        var belowMinimum = validPayload
        belowMinimum["dns_push_interval_secs"] = 29
        var nonInteger = validPayload
        nonInteger["dns_push_interval_secs"] = "60"

        for (label, payload) in [
            ("missing", missing),
            ("below minimum", belowMinimum),
            ("non-integer", nonInteger)
        ] {
            let data = try JSONSerialization.data(withJSONObject: payload)
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiVpnProfile.self, from: data), label)
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterAndUnregisterPushDeviceSignCanonicalBody() async throws {
        let auth = ToriiCanonicalRequestAuth(accountId: "alice@universal",
                                             privateKey: Data(repeating: 7, count: 32))
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            XCTAssertEqual(request.url?.path, "/v1/notify/devices")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount), "alice@universal")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature) == nil, false)
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["account_id"] as? String, "alice@universal")
            XCTAssertEqual(body["platform"] as? String, "FCM")
            XCTAssertEqual(body["token"] as? String, "token-1")
            XCTAssertEqual(body["topics"] as? [String], ["activity"])
            if callCount == 1 {
                XCTAssertEqual(request.httpMethod, "POST")
            } else {
                XCTAssertEqual(request.httpMethod, "DELETE")
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 202, httpVersion: nil,
                                           headerFields: [:])!
            return (response, Data())
        }
        let client = makeClient()
        let request = ToriiPushDeviceRequest(accountId: " alice@universal ",
                                             platform: "FCM",
                                             token: " token-1 ",
                                             topics: [" activity "])
        try await client.registerPushDevice(request, canonicalAuth: auth)
        let deleteAuth = ToriiCanonicalRequestAuth(accountId: "alice@universal",
                                                   privateKey: Data(repeating: 7, count: 32))
        try await client.unregisterPushDevice(request, canonicalAuth: deleteAuth)
        XCTAssertEqual(callCount, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCreateVpnQuoteSignsAndDeserializesOpenLeaseInstruction() async throws {
        let meteringKey = String(repeating: "ab", count: 32)
        let quoteId = String(repeating: "cd", count: 32)
        let auth = ToriiCanonicalRequestAuth(accountId: "alice@universal",
                                             privateKey: Data(repeating: 7, count: 32))
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/vpn/quotes")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount), "alice@universal")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs), "1700000000000")
            XCTAssertEqual(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce), "nonce-1")
            XCTAssertNotNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["exit_class"] as? String, "standard")
            XCTAssertEqual(body["metering_public_key_hex"] as? String, meteringKey)
            let payload: [String: Any] = [
                "quote_id": quoteId,
                "lease_id_hex": quoteId,
                "session_id_hex": String(repeating: "ef", count: 16),
                "payment_reference": quoteId,
                "account_id": "alice@universal",
                "exit_class": "standard",
                "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
                "lease_secs": 900,
                "quote_expires_at_ms": 1_700_000_900_000,
                "fee_asset_id": "xor#universal.universal",
                "escrow_account_id": "vpn_escrow",
                "operator_account_id": "vpn_operator",
                "lease_fee": "1000000.25",
                "route_pushes": [],
                "excluded_routes": [],
                "dns_servers": ["1.1.1.1"],
                "tunnel_addresses": ["10.208.0.2/32"],
                "mtu_bytes": 1280,
                "meter_family": "vpn-standard",
                "flow_label_bits": 24,
                "padding_budget_ms": 15,
                "relay_id_hex": self.vpnRelayIdHex,
                "relay_mldsa65_public_key_hex": self.vpnRelayMldsa65PublicKeyHex,
                "descriptor_commit_hex": String(repeating: "cd", count: 32),
                "tls_server_name": "vpn.sora.org",
                "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
                "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
                "directory_snapshot_digest_hex": String(repeating: "42", count: 32),
                "metering_public_key_hex": meteringKey,
                "open_lease_instruction": [
                    "wire_id": "OpenVpnLeaseEscrow",
                    "payload_hex": "abcd"
                ]
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, try JSONSerialization.data(withJSONObject: payload))
        }
        let quote = try await makeClient(
            canonicalRequestFreshness: ToriiCanonicalRequestFreshness(
                timestampMs: { 1_700_000_000_000 },
                nonce: { "nonce-1" }
            )
        ).createVpnQuote(
            ToriiVpnQuoteCreateRequest(exitClass: "standard", meteringPublicKeyHex: "0x\(meteringKey)"),
            canonicalAuth: auth
        )
        XCTAssertEqual(quote.quoteId, quoteId)
        XCTAssertEqual(quote.leaseFee, "1000000.25")
        XCTAssertEqual(quote.relayMldsa65PublicKeyHex, vpnRelayMldsa65PublicKeyHex)
        XCTAssertEqual(quote.openLeaseInstruction.wireId, "OpenVpnLeaseEscrow")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCreateVpnQuoteRejectsPaddedCanonicalAuthBeforeRequest() async throws {
        let meteringKey = String(repeating: "ab", count: 32)
        let request = ToriiVpnQuoteCreateRequest(
            exitClass: "standard",
            meteringPublicKeyHex: meteringKey
        )
        var called = false
        StubURLProtocol.handler = { request in
            called = true
            let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let client = makeClient()

        let paddedAccount = ToriiCanonicalRequestAuth(
            accountId: " alice",
            privateKey: Data(repeating: 7, count: 32)
        )
        do {
            _ = try await client.createVpnQuote(request, canonicalAuth: paddedAccount)
            XCTFail("padded canonical auth account should reject")
        } catch {
            XCTAssertEqual(error as? ToriiCanonicalRequestError, .invalidAccountId)
        }
        XCTAssertFalse(called)

        let validAuth = ToriiCanonicalRequestAuth(
            accountId: "alice@universal",
            privateKey: Data(repeating: 7, count: 32)
        )
        let paddedNonceClient = makeClient(
            canonicalRequestFreshness: ToriiCanonicalRequestFreshness(
                timestampMs: { 1_700_000_000_000 },
                nonce: { "nonce-1 " }
            )
        )
        do {
            _ = try await paddedNonceClient.createVpnQuote(request, canonicalAuth: validAuth)
            XCTFail("padded canonical auth nonce should reject")
        } catch {
            XCTAssertEqual(error as? ToriiCanonicalRequestError, .invalidNonce)
        }
        XCTAssertFalse(called)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCreateAndGetVpnSessionUseQuotePaymentAndMeteringKey() async throws {
        let quoteId = String(repeating: "11", count: 32)
        let sessionId = String(repeating: "44", count: 16)
        let paymentHash = String(repeating: "22", count: 32)
        let meteringKey = String(repeating: "33", count: 32)
        let helperTicketHex = "5356504e48543100" + String(repeating: "00", count: 780)
        let auth = ToriiCanonicalRequestAuth(accountId: "alice@universal",
                                             privateKey: Data(repeating: 7, count: 32))
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            if callCount == 1 {
                XCTAssertEqual(request.url?.path, "/v1/vpn/sessions")
                XCTAssertEqual(request.httpMethod, "POST")
                let body = self.bodyJSON(from: request)
                XCTAssertEqual(body["quote_id"] as? String, quoteId)
                XCTAssertEqual(body["payment_tx_hash"] as? String, paymentHash)
                XCTAssertEqual(body["metering_public_key_hex"] as? String, meteringKey)
            } else {
                XCTAssertEqual(request.url?.path, "/v1/vpn/sessions/\(sessionId)")
                XCTAssertEqual(request.httpMethod, "GET")
            }
            let payload: [String: Any] = [
                "session_id": sessionId,
                "account_id": "alice@universal",
                "exit_class": "standard",
                "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
                "lease_secs": 900,
                "expires_at_ms": 1_700_000_900_000,
                "connected_at_ms": 1_700_000_000_000,
                "meter_family": "vpn-standard",
                "quote_id": quoteId,
                "payment_reference": quoteId,
                "payment_tx_hash": paymentHash,
                "fee_asset_id": "xor#universal.universal",
                "escrow_account_id": "vpn_escrow",
                "operator_account_id": "vpn_operator",
                "lease_fee": "1000000.25",
                "flow_label_bits": 24,
                "padding_budget_ms": 15,
                "relay_id_hex": self.vpnRelayIdHex,
                "relay_mldsa65_public_key_hex": self.vpnRelayMldsa65PublicKeyHex,
                "descriptor_commit_hex": String(repeating: "cd", count: 32),
                "tls_server_name": "vpn.sora.org",
                "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
                "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
                "directory_snapshot_digest_hex": String(repeating: "42", count: 32),
                "route_pushes": [],
                "excluded_routes": [],
                "dns_servers": [],
                "tunnel_addresses": ["10.208.0.2/32"],
                "mtu_bytes": 1280,
                "helper_ticket_hex": helperTicketHex,
                "bytes_in": 0,
                "bytes_out": 0,
                "status": "active"
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: callCount == 1 ? 201 : 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, try JSONSerialization.data(withJSONObject: payload))
        }
        let client = makeClient()
        let created = try await client.createVpnSession(
            ToriiVpnSessionCreateRequest(quoteId: "0x\(quoteId)",
                                         paymentTransactionHash: paymentHash,
                                         meteringPublicKeyHex: meteringKey),
            canonicalAuth: auth
        )
        let fetched = try await client.getVpnSession(sessionId: sessionId, canonicalAuth: auth)
        XCTAssertEqual(created.sessionId, sessionId)
        XCTAssertEqual(created.leaseFee, "1000000.25")
        XCTAssertEqual(created.relayMldsa65PublicKeyHex, vpnRelayMldsa65PublicKeyHex)
        XCTAssertEqual(fetched?.paymentTransactionHash, paymentHash)
        XCTAssertEqual(fetched?.relayMldsa65PublicKeyHex, vpnRelayMldsa65PublicKeyHex)
        XCTAssertEqual(created.helperTicketHex, helperTicketHex)
        XCTAssertEqual(created.helperTicketHex.utf8.count, 1_576)
    }

    func testVpnSessionRejectsNonCanonicalHelperTicketHex() throws {
        let sessionId = String(repeating: "11", count: 16)
        let quoteId = String(repeating: "33", count: 32)
        let paymentHash = String(repeating: "22", count: 32)
        let validHelperTicketHex = "5356504e48543100" + String(repeating: "00", count: 780)

        func sessionData(helperTicketHex: String) throws -> Data {
            let payload: [String: Any] = [
                "session_id": sessionId,
                "account_id": "alice",
                "exit_class": "standard",
                "relay_endpoint": "/dns4/vpn.sora.org/udp/443/quic",
                "lease_secs": 900,
                "expires_at_ms": 1_700_000_900_000,
                "connected_at_ms": 1_700_000_000_000,
                "meter_family": "vpn-standard",
                "quote_id": quoteId,
                "payment_reference": quoteId,
                "payment_tx_hash": paymentHash,
                "fee_asset_id": "xor#universal.universal",
                "escrow_account_id": "vpn_escrow",
                "operator_account_id": "vpn_operator",
                "lease_fee": "1000000.25",
                "flow_label_bits": 24,
                "padding_budget_ms": 15,
                "relay_id_hex": vpnRelayIdHex,
                "relay_mldsa65_public_key_hex": vpnRelayMldsa65PublicKeyHex,
                "descriptor_commit_hex": String(repeating: "cd", count: 32),
                "tls_server_name": "vpn.sora.org",
                "relay_tls_spki_sha256_hex": String(repeating: "ab", count: 32),
                "relay_certificate_sha256_hex": String(repeating: "ef", count: 32),
                "directory_snapshot_digest_hex": String(repeating: "42", count: 32),
                "route_pushes": [],
                "excluded_routes": [],
                "dns_servers": [],
                "tunnel_addresses": ["10.208.0.2/32"],
                "mtu_bytes": 1280,
                "helper_ticket_hex": helperTicketHex,
                "bytes_in": 0,
                "bytes_out": 0,
                "status": "active"
            ]
            return try JSONSerialization.data(withJSONObject: payload)
        }

        let invalidValues = [
            "0x" + validHelperTicketHex,
            validHelperTicketHex.uppercased(),
            "5356504e48543100" + String(repeating: "00", count: 720),
            String(validHelperTicketHex.dropLast(2))
        ]
        for invalidValue in invalidValues {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiVpnSession.self,
                    from: sessionData(helperTicketHex: invalidValue)
                )
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSubmitAndListVpnReceiptsExposeSettlementInstruction() async throws {
        let quoteId = String(repeating: "44", count: 32)
        let sessionId = String(repeating: "33", count: 16)
        let leaseId = String(repeating: "66", count: 32)
        let auth = ToriiCanonicalRequestAuth(accountId: "alice@universal",
                                             privateKey: Data(repeating: 7, count: 32))
        let settle: [String: Any] = [
            "wire_id": "SettleVpnLease",
            "payload_hex": "cafe"
        ]
        let receiptPayload: [String: Any] = [
            "session_id": sessionId,
            "account_id": "alice@universal",
            "exit_class": "standard",
            "relay_endpoint": "/dns4/vpn.sora.org/tcp/443/wss",
            "meter_family": "vpn-standard",
            "connected_at_ms": 1,
            "disconnected_at_ms": 2,
            "duration_ms": 1,
            "bytes_in": 10,
            "bytes_out": 20,
            "status": "settled",
            "receipt_source": "relay",
            "quote_id": quoteId,
            "payment_tx_hash": String(repeating: "55", count: 32),
            "fee_asset_id": "xor#universal.universal",
            "escrow_account_id": "vpn_escrow",
            "operator_account_id": "vpn_operator",
            "lease_fee": "1000000.25",
            "earned_fee": "700000.125",
            "refunded_fee": "300000.125",
            "lease_id_hex": leaseId,
            "settle_lease_instruction": settle
        ]
        let pendingReceiptPayload = receiptPayload.merging(
            ["status": "settlement_pending"],
            uniquingKeysWith: { _, replacement in replacement }
        )
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            if callCount == 1 {
                XCTAssertEqual(request.url?.path, "/v1/vpn/receipts")
                XCTAssertEqual(request.httpMethod, "POST")
                let body = self.bodyJSON(from: request)
                XCTAssertEqual(body["relay_receipt_hex"] as? String, "abcd")
                XCTAssertEqual(body["client_voucher_hex"] as? String, "1234")
                XCTAssertEqual(body["lease_id_hex"] as? String, leaseId)
                let response = HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, try JSONSerialization.data(withJSONObject: pendingReceiptPayload))
            }
            XCTAssertEqual(callCount, 2)
            XCTAssertEqual(request.httpMethod, "GET")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, try JSONSerialization.data(withJSONObject: ["items": [receiptPayload], "total": 1]))
        }
        let client = makeClient()
        let submitted = try await client.submitVpnReceipt(
            ToriiVpnReceiptSubmitRequest(relayReceiptHex: "0xabcd",
                                         clientVoucherHex: "1234",
                                         leaseIdHex: leaseId),
            canonicalAuth: auth
        )
        let list = try await client.listVpnReceipts(canonicalAuth: auth)
        XCTAssertEqual(submitted.status, "settlement_pending")
        XCTAssertEqual(submitted.settleLeaseInstruction?.wireId, "SettleVpnLease")
        XCTAssertEqual(list.items.first?.status, "settled")
        XCTAssertEqual(list.items.first?.earnedFee, "700000.125")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListConnectAppsParsesPage() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/apps")
            let components = try XCTUnwrap(URLComponents(url: request.url!, resolvingAgainstBaseURL: false))
            XCTAssertTrue(try XCTUnwrap(components.queryItems).contains { $0.name == "cursor" && $0.value == "cursor-1" })
            XCTAssertTrue(try XCTUnwrap(components.queryItems).contains { $0.name == "limit" && $0.value == "5" })
            let payload: [String: Any] = [
                "items": [
                    [
                        "app_id": "demo-app",
                        "display_name": "Demo",
                        "description": "desc",
                        "icon_url": "https://example.test/icon.png",
                        "namespaces": ["sora"],
                        "metadata": ["a": 1],
                        "policy": ["relay_enabled": true],
                        "custom": "ok"
                    ]
                ],
                "total": 1,
                "next_cursor": "cursor-2",
                "page_note": "ok"
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }
        let page = try await makeClient().listConnectApps(options: ToriiConnectAppListOptions(limit: 5, cursor: "cursor-1"))
        XCTAssertEqual(page.items.first?.appId, "demo-app")
        XCTAssertEqual(page.nextCursor, "cursor-2")
        XCTAssertEqual(page.extra["page_note"], .string("ok"))
        XCTAssertEqual(page.items.first?.extra["custom"], .string("ok"))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConnectAppParsesRecord() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/apps/demo-app")
            let payload: [String: Any] = [
                "app_id": "demo-app",
                "namespaces": ["sora"],
                "metadata": ["k": "v"],
                "policy": [:]
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }
        let record = try await makeClient().getConnectApp(appId: "demo-app")
        XCTAssertEqual(record.appId, "demo-app")
        XCTAssertEqual(record.namespaces, ["sora"])
        XCTAssertEqual(record.metadata["k"], .string("v"))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterConnectAppAllowsEmptyResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/apps")
            XCTAssertEqual(request.httpMethod, "POST")
            let response = HTTPURLResponse(url: request.url!, statusCode: 202, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let input = ToriiConnectAppUpsertInput(appId: "demo", namespaces: ["sora"])
        let record = try await makeClient().registerConnectApp(input)
        XCTAssertNil(record)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testDeleteConnectAppReturnsTrueOn204() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/apps/demo")
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let deleted = try await makeClient().deleteConnectApp(appId: "demo")
        XCTAssertTrue(deleted)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConnectAppPolicyParsesPayload() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/policy")
            let payload: [String: Any] = [
                "relay_enabled": true,
                "ws_max_sessions": 10,
                "ws_per_ip_max_sessions": 5,
                "ws_rate_per_ip_per_min": 50,
                "session_ttl_ms": 1000,
                "frame_max_bytes": 4096,
                "session_buffer_max_bytes": 8192,
                "ping_interval_ms": 200,
                "ping_miss_tolerance": 2,
                "ping_min_interval_ms": 100,
                "note": "ok"
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }
        let policy = try await makeClient().getConnectAppPolicy()
        XCTAssertEqual(policy.wsMaxSessions, 10)
        XCTAssertEqual(policy.extra["note"], .string("ok"))
        XCTAssertEqual(policy.relayEnabled, true)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testUpdateConnectAppPolicyPostsPayload() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/connect/app/policy")
            XCTAssertEqual(request.httpMethod, "POST")
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["ws_max_sessions"] as? Int, 20)
            XCTAssertEqual(body["relay_enabled"] as? Bool, false)
            let payload: [String: Any] = [
                "ws_max_sessions": 20,
                "relay_enabled": false
            ]
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }
        let update = ToriiConnectAppPolicyUpdate(relayEnabled: false, wsMaxSessions: 20)
        let policy = try await makeClient().updateConnectAppPolicy(update)
        XCTAssertEqual(policy.wsMaxSessions, 20)
        XCTAssertEqual(policy.relayEnabled, false)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testConnectAdmissionManifestGetAndSet() async throws {
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            if request.httpMethod == "PUT" {
                XCTAssertEqual(request.url?.path, "/v1/connect/app/manifest")
                let body = self.bodyJSON(from: request)
                XCTAssertEqual(body["version"] as? Int, 3)
                XCTAssertEqual((body["entries"] as? [[String: Any]])?.first?["app_id"] as? String, "demo")
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let payload: [String: Any] = [
                    "entries": [
                        [
                            "app_id": "demo",
                            "namespaces": ["sora"],
                            "metadata": [:],
                            "policy": [:]
                        ]
                    ]
                ]
                let data = try JSONSerialization.data(withJSONObject: payload)
                return (response, data)
            } else {
                XCTAssertEqual(request.url?.path, "/v1/connect/app/manifest")
                let payload: [String: Any] = [
                    "version": 2,
                    "manifest_hash": "abcd",
                    "updated_at": "ts",
                    "entries": [
                        [
                            "app_id": "demo",
                            "namespaces": ["sora", "nexus"],
                            "metadata": ["k": "v"],
                            "policy": ["p": 1],
                            "extra_field": true
                        ]
                    ],
                    "note": "ok"
                ]
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let data = try JSONSerialization.data(withJSONObject: payload)
                return (response, data)
            }
        }
        let manifest = try await makeClient().getConnectAdmissionManifest()
        XCTAssertEqual(manifest.entries.first?.appId, "demo")
        XCTAssertEqual(manifest.entries.first?.extra["extra_field"], .bool(true))
        let entry = try ToriiConnectAdmissionManifestEntry(appId: "demo", namespaces: ["sora"])
        let updated = try await makeClient().setConnectAdmissionManifest(ToriiConnectAdmissionManifestInput(version: 3, entries: [entry]))
        XCTAssertEqual(updated.entries.count, 1)
        XCTAssertEqual(callCount, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetDaManifestBundleFetchesManifest() async throws {
        let expectation = expectation(description: "manifest request")
        let ticket = String(repeating: "ab", count: 32)
        let manifestB64 = Data("manifest-data".utf8).base64EncodedString()
        let body = """
        {
            "storage_ticket":"\(ticket)",
            "client_blob_id":"\(String(repeating: "cd", count: 32))",
            "blob_hash":"\(String(repeating: "ef", count: 32))",
            "manifest_hash":"\(String(repeating: "99", count: 32))",
            "chunk_root":"\(String(repeating: "11", count: 32))",
            "lane_id":7,
            "epoch":11,
            "manifest_len":\(manifestB64.count),
            "manifest_norito":"\(manifestB64)",
            "manifest":{"events":[],"enum_types":[],"permissions":[],"chunking":{"namespace":"sorafs","name":"sf1","semver":"1.2.3"}},
            "chunk_plan":{"schema":"sorafs.chunk_fetch_plan.v1","payload_digest_blake3_hex":"\(String(repeating: "ef", count: 32))","chunk_fetch_specs":[{"chunk_index":0,"offset":0,"length":4,"digest_blake3":"\(String(repeating: "22", count: 32))"}]}
        }
        """
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/da/manifests/\(ticket)")
            XCTAssertNil(request.url?.query)
            expectation.fulfill()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, body.data(using: .utf8))
        }

        let bundle = try await makeClient().getDaManifestBundle(storageTicketHex: "0x\(ticket)")
        await fulfillment(of: [expectation], timeout: 1.0)
        XCTAssertEqual(bundle.storageTicketHex, ticket)
        XCTAssertEqual(bundle.blobHashHex, String(repeating: "ef", count: 32))
        XCTAssertEqual(bundle.manifestBytes, Data("manifest-data".utf8))
        XCTAssertEqual(bundle.laneId, 7)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSorafsGatewayProviderEncodesAndValidatesTrustInputs() throws {
        let provider = try SorafsGatewayProvider(
            name: "alpha",
            providerIdHex: String(repeating: "01", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test/")!,
            streamTokenB64: Data("token".utf8).base64EncodedString(),
            privacyEventsURL: URL(string: "https://gateway.test/privacy/events")!
        )
        let encoded = try JSONEncoder().encode(provider)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: String]
        )
        XCTAssertEqual(object["gateway_public_key_hex"], String(repeating: "ab", count: 32))

        for key in [
            String(repeating: "0", count: 64),
            String(repeating: "AB", count: 32),
            "0x" + String(repeating: "ab", count: 32),
            String(repeating: "ab", count: 31)
        ] {
            XCTAssertThrowsError(try SorafsGatewayProvider(
                name: "alpha",
                providerIdHex: String(repeating: "01", count: 32),
                gatewayPublicKeyHex: key,
                baseURL: URL(string: "https://gateway.test/")!,
                streamTokenB64: Data("token".utf8).base64EncodedString()
            ))
        }
        for rawURL in [
            "http://gateway.test/",
            "https://user@gateway.test/",
            "https://gateway.test:443/",
            "https://gateway.test/path",
            "https://gateway.test/?query=1",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://192.0.2.1/",
            "https://198.51.100.1/",
            "https://203.0.113.1/",
            "https://[::1]/",
            "https://[fc00::1]/",
            "https://[fe80::1]/",
            "https://[2001:db8::1]/",
            "https://[::ffff:127.0.0.1]/"
        ] {
            XCTAssertThrowsError(try SorafsGatewayProvider(
                name: "alpha",
                providerIdHex: String(repeating: "01", count: 32),
                gatewayPublicKeyHex: String(repeating: "ab", count: 32),
                baseURL: URL(string: rawURL)!,
                streamTokenB64: Data("token".utf8).base64EncodedString()
            ))
        }
        XCTAssertNoThrow(try SorafsGatewayProvider(
            name: "alpha",
            providerIdHex: String(repeating: "01", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test/")!,
            streamTokenB64: Data(repeating: 0, count: 2 * 1_024).base64EncodedString()
        ))
        XCTAssertThrowsError(try SorafsGatewayProvider(
            name: "alpha",
            providerIdHex: String(repeating: "01", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test/")!,
            streamTokenB64: String(repeating: "A", count: 4 * 1_024 + 1)
        ))
        XCTAssertThrowsError(try SorafsGatewayProvider(
            name: "alpha",
            providerIdHex: String(repeating: "01", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test/")!,
            streamTokenB64: Data(repeating: 0, count: 2 * 1_024 + 1).base64EncodedString()
        ))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFetchDaPayloadViaGatewayUsesProvidedManifest() async throws {
        let bundle = try tcMakeSampleManifestBundle()
        let provider = try SorafsGatewayProvider(
            name: "alpha",
            providerIdHex: String(repeating: "01", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test")!,
            streamTokenB64: Data("token".utf8).base64EncodedString()
        )
        let fetcher = StubGatewayFetcher(result: tcMakeGatewayFetchResult())
        let session = try await tcMakeClient().fetchDaPayloadViaGateway(
            manifestBundle: bundle,
            providers: [provider],
            orchestrator: fetcher
        )
        XCTAssertEqual(session.manifest.storageTicketHex, bundle.storageTicketHex)
        XCTAssertEqual(session.chunkerHandle, "sorafs.sf1@1.0.0")
        XCTAssertEqual(fetcher.fetchCount, 1)
        XCTAssertEqual(fetcher.capturedPlan, bundle.chunkPlan)
        XCTAssertEqual(fetcher.capturedProviders?.first?.providerIdHex, provider.providerIdHex)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFetchDaPayloadViaGatewayDownloadsManifestWhenTicketProvided() async throws {
        let expectation = expectation(description: "manifest fetch")
        let ticket = String(repeating: "aa", count: 32)
        let raw = tcMakeSampleManifestRaw(storageTicket: ticket)
        let json = try ToriiJSONValue.object(raw).encodedData()
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/da/manifests/\(ticket)")
            expectation.fulfill()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, json)
        }
        let provider = try SorafsGatewayProvider(
            name: "beta",
            providerIdHex: String(repeating: "02", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test")!,
            streamTokenB64: Data("stream".utf8).base64EncodedString()
        )
        let fetcher = StubGatewayFetcher(result: tcMakeGatewayFetchResult())
        let session = try await tcMakeClient().fetchDaPayloadViaGateway(
            storageTicketHex: "0x\(ticket)",
            providers: [provider],
            orchestrator: fetcher
        )
        await fulfillment(of: [expectation], timeout: 1.0)
        XCTAssertEqual(session.manifest.storageTicketHex, ticket)
        XCTAssertEqual(fetcher.fetchCount, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFetchDaPayloadViaGatewayRequiresInputs() async throws {
        let provider = try SorafsGatewayProvider(
            name: "gamma",
            providerIdHex: String(repeating: "03", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test")!,
            streamTokenB64: Data("stream".utf8).base64EncodedString()
        )
        do {
            _ = try await makeClient().fetchDaPayloadViaGateway(
                providers: [provider],
                orchestrator: StubGatewayFetcher(result: tcMakeGatewayFetchResult())
            )
            XCTFail("Expected invalidPayload error")
        } catch {
            guard case ToriiClientError.invalidPayload = error else {
                XCTFail("Expected invalidPayload error, got \(error)")
                return
            }
        }
    }

    #if canImport(Darwin)
    func testNativeDaProofSummaryGeneratorEmitsExplicitProofs() throws {
        try requireNativeTestCapability(
            NoritoNativeBridge.shared.isAvailable,
            "Norito bridge unavailable on this platform"
        )
        let fixture = try tcLoadDaProofFixture()
        let options = ToriiDaProofSummaryOptions(sampleCount: 0, sampleSeed: 42, leafIndexes: [0, 1, 1])
        let summary = try NativeDaProofSummaryGenerator.shared.makeProofSummary(
            manifest: fixture.manifest,
            payload: fixture.payload,
            options: options
        )
        XCTAssertEqual(summary.blobHashHex.lowercased(), fixture.blobHashHex.lowercased())
        XCTAssertEqual(summary.sampleCount, 0)
        XCTAssertEqual(summary.proofCount, 2)
        XCTAssertEqual(summary.proofs.count, 2)
        XCTAssertTrue(summary.proofs.allSatisfy { $0.origin == "explicit" })
        XCTAssertEqual(summary.proofs.first?.leafIndex, 0)
    }
    #endif

    @available(iOS 15.0, macOS 12.0, *)
    func testFetchDaPayloadViaGatewayAttachesProofSummary() async throws {
        let bundle = try tcMakeSampleManifestBundle()
        let provider = try SorafsGatewayProvider(
            name: "delta",
            providerIdHex: String(repeating: "04", count: 32),
            gatewayPublicKeyHex: String(repeating: "ab", count: 32),
            baseURL: URL(string: "https://gateway.test")!,
            streamTokenB64: Data("token".utf8).base64EncodedString()
        )
        let fetcher = StubGatewayFetcher(result: tcMakeGatewayFetchResult())
        let stubSummary = tcMakeStubProofSummary()
        let generator = StubProofSummaryGenerator(summary: stubSummary)
        let session = try await tcMakeClient().fetchDaPayloadViaGateway(
            manifestBundle: bundle,
            providers: [provider],
            proofSummaryOptions: ToriiDaProofSummaryOptions(sampleCount: 0, leafIndexes: [0]),
            orchestrator: fetcher,
            proofSummaryGenerator: generator
        )
        XCTAssertNotNil(session.proofSummary)
        XCTAssertEqual(session.proofSummary?.proofCount, stubSummary.proofCount)
        XCTAssertEqual(session.proofSummary?.proofs.first?.origin, stubSummary.proofs.first?.origin)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerAccountQrDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            self.assertDecodedPath(request, contains: "/v1/explorer/accounts/sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV/qr")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertNil(components?.queryItems)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "canonical_id":"i105example",
                "literal":"i105example",
                "network_prefix":0,
                "error_correction":"M",
                "modules":192,
                "qr_version":5,
                "svg":"<svg viewBox=\\"0 0 192 192\\"></svg>"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let qr = try await makeClient().getExplorerAccountQr(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(qr.canonicalId, "i105example")
        XCTAssertEqual(qr.literal, "i105example")
        XCTAssertEqual(qr.networkPrefix, 0)
        XCTAssertEqual(qr.modules, 192)
        XCTAssertEqual(qr.qrVersion, 5)
        XCTAssertTrue(qr.svg.contains("<svg"))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerAccountQrAcceptsAccountAliasPathLiteral() async throws {
        let alias = "operator@banka.universal"
        StubURLProtocol.handler = { request in
            self.assertDecodedPath(request, contains: "/v1/explorer/accounts/operator@banka.universal/qr")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "canonical_id":"i105example",
                "literal":"operator@banka.universal",
                "network_prefix":0,
                "error_correction":"M",
                "modules":192,
                "qr_version":5,
                "svg":"<svg viewBox=\\"0 0 192 192\\"></svg>"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let qr = try await makeClient().getExplorerAccountQr(accountId: alias)
        XCTAssertEqual(qr.literal, alias)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerAccountQrDecodesAlternativeLiteral() async throws {
        StubURLProtocol.handler = { request in
            self.assertDecodedPath(request, contains: "/v1/explorer/accounts/sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV/qr")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertNil(components?.queryItems)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "canonical_id":"i105example",
                "literal":"soraexample",
                "network_prefix":1206,
                "error_correction":"M",
                "modules":192,
                "qr_version":6,
                "svg":"<svg class=\\"qr\\"></svg>"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let qr = try await makeClient().getExplorerAccountQr(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(qr.literal, "soraexample")
        XCTAssertEqual(qr.qrVersion, 6)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerInstructionsEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                canonicalRequestAccountHeaderValue(self.authority)
            )
            XCTAssertNotNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["cursor"], "Y3Vyc29y")
            XCTAssertEqual(query["limit"], "25")
            XCTAssertEqual(query["account"], "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
            XCTAssertEqual(query["authority"], "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(query["transaction_hash"], "deadbeef")
            XCTAssertEqual(query["transaction_status"], "Committed")
            XCTAssertEqual(query["block"], "5")
            XCTAssertEqual(query["kind"], "Transfer")
            XCTAssertEqual(query["asset_id"], "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": [
                    {
                        "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "created_at":"2025-01-01T00:00:00Z",
                        "kind":"Transfer",
                        "box":{
                            "encoded":"0xbeef",
                            "framed_sha256":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "json":{
                                "kind":"Transfer",
                                "payload":{
                                    "Asset":{
                                        "source":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                        "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                        "object":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                        "value":"10"
                                    }
                                },
                                "wire_id":"10",
                                "encoded":"beef"
                            }
                        },
                        "transaction_hash":"hash",
                        "transaction_status":"Committed",
                        "block":5,
                        "index":0
                    }
                ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let params = ToriiListQuery(
            filter: ToriiFilter.all([
                ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                ToriiField("authority") == "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                ToriiField("transaction_hash") == "deadbeef",
                ToriiField("transaction_status") == "Committed",
                ToriiField("block") == 5,
                ToriiField("kind") == "Transfer",
                ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            ]),
            limit: 25, cursor: "Y3Vyc29y"
        )
        let page = try await makeClient().explorerInstructions.page(params)

        XCTAssertNil(page.nextCursor)
        XCTAssertEqual(page.items.count, 1)
        let item = page.items[0]
        XCTAssertEqual(item.kind, "Transfer")
        XCTAssertEqual(item.transactionHash, "hash")
        XCTAssertEqual(item.box.encoded, "0xbeef")
        XCTAssertEqual(item.box.framedSha256, "0x" + String(repeating: "b", count: 64))
        XCTAssertNil(item.box.scale)
        guard case let .object(payload) = item.box.json else {
            return XCTFail("Expected instruction box json payload to be an object.")
        }
        guard case let .string(kind) = payload["kind"] else {
            return XCTFail("Expected instruction box json to contain a kind string.")
        }
        XCTAssertEqual(kind, "Transfer")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testDataspaceVisibleExplorerRequestRemainsAnonymousWithoutDefaultSigner() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            XCTAssertNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount)
            )
            XCTAssertNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: URLSession(configuration: configuration),
            localSigningContext: ToriiLocalSigningContext(networkId: TestNetworkIds.canonical)
        )
        let page = try await client.explorerInstructions.page()
        XCTAssertTrue(page.items.isEmpty)
    }

    func testCanonicalMintDestinationStaysCanonical() throws {
        let publicKey = try validEd25519PublicKey(seed: 0x44)
        let address = try AccountAddress.fromAccount(publicKey: publicKey, algorithm: "ed25519")
        let accountId = try address.toI105(networkPrefix: 0x02F1)
        let literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#\(accountId)"
        XCTAssertEqual(try CanonicalNorito.canonicalAssetIdLiteral(literal), literal)
        XCTAssertEqual(CanonicalNorito.assetDefinitionIdFromLiteral(literal), "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
    }

    func testCanonicalAssetDefinitionLiteralRemainsCanonical() {
        XCTAssertEqual(
            CanonicalNorito.assetDefinitionIdFromLiteral("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"),
            "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        )
    }

    func testMalformedPublicAssetLiteralReturnsNilDefinition() {
        XCTAssertNil(CanonicalNorito.assetDefinitionIdFromLiteral("62Fk4FPcMuLvW5QjDGNF2a4jAmjM#not-an-account"))
    }

    func testDecodeAccountIdReadsNoritoStringField() throws {
        let publicKey = try validEd25519PublicKey(seed: 0x33)
        let address = try AccountAddress.fromAccount(publicKey: publicKey, algorithm: "ed25519")
        let accountId = try address.toI105(networkPrefix: 0x02F1)
        let encodedLength = withUnsafeBytes(of: UInt64(accountId.utf8.count).littleEndian) { Data($0) }
        let encoded = encodedLength + Data(accountId.utf8)
        XCTAssertEqual(try CanonicalNorito.decodeAccountId(encoded), accountId)
    }

    func testExplorerBurnInstructionParsedAsSummary() throws {
        let json = """
        {
            "next_cursor":null,
            "items":[{
                "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "created_at":"2025-06-01T10:00:00Z",
                "kind":"Burn",
                "box":{
                    "json":{
                        "encoded":"00",
                        "kind":"Burn",
                        "payload":{
                            "value":{
                                "destination":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                "object":"25"
                            },
                            "variant":"Asset"
                        },
                        "wire_id":"iroha.instruction.v1::mint_burn::BurnBox"
                    }
                },
                "transaction_hash":"burn_hash_1",
                "transaction_status":"Committed",
                "block":5,
                "index":0
            }]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        XCTAssertEqual(page.items.count, 1)

        let item = page.items[0]
        XCTAssertEqual(item.kind, "Burn")

        let details = item.transferDetails()
        XCTAssertNotNil(details, "transferDetails() should parse Burn instructions")

        let summaries = page.transferSummaries(relativeTo: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(summaries.count, 1, "Burn should produce exactly 1 summary")

        let summary = try XCTUnwrap(summaries.first)
        XCTAssertEqual(summary.kind, "Burn")
        XCTAssertEqual(summary.amount, "25")
        XCTAssertEqual(summary.direction, .outgoing, "Burn should always be outgoing")
    }

    func testExplorerMixedKindsAllParsed() throws {
        // Page with Transfer + Mint + unknown kind — all parseable ones should be included
        let json = """
        {
            "next_cursor":null,
            "items":[
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":{
                        "json":{
                            "kind":"Transfer",
                            "payload":{
                                "variant":"Asset",
                                "value":{
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                    "object":"10"
                                }
                            },
                            "wire_id":"10",
                            "encoded":"beef"
                        }
                    },
                    "transaction_hash":"transfer_hash",
                    "transaction_status":"Committed",
                    "block":1,
                    "index":0
                },
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-02T00:00:00Z",
                    "kind":"Mint",
                    "box":{
                        "json":{
                            "encoded":"00",
                            "kind":"Mint",
                            "payload":{
                                "value":{
                                    "destination":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                    "object":"100"
                                },
                                "variant":"Asset"
                            },
                            "wire_id":"MintBox"
                        }
                    },
                    "transaction_hash":"mint_hash",
                    "transaction_status":"Committed",
                    "block":2,
                    "index":0
                },
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-03T00:00:00Z",
                    "kind":"SetKeyValue",
                    "box":{
                        "json":{
                            "encoded":"00",
                            "kind":"SetKeyValue",
                            "payload":{
                                "variant":"Domain",
                                "value":{"key":"foo","value":"bar"}
                            },
                            "wire_id":"SetKeyValueBox"
                        }
                    },
                    "transaction_hash":"skv_hash",
                    "transaction_status":"Committed",
                    "block":3,
                    "index":0
                }
            ]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerInstructionItem>.self, from: Data(json.utf8))
        XCTAssertEqual(page.items.count, 3, "All 3 items should decode")

        let summaries = page.transferSummaries()
        // Transfer + Mint should parse, SetKeyValue should be skipped
        XCTAssertEqual(summaries.count, 2, "Transfer + Mint should produce summaries, SetKeyValue should be skipped")
        XCTAssertEqual(summaries[0].kind, "Transfer")
        XCTAssertEqual(summaries[1].kind, "Mint")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerInstructionsCompletion() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertNil(components?.queryItems)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        let page = try await makeClient().explorerInstructions.page()
        XCTAssertTrue(page.items.isEmpty)
        XCTAssertNil(page.nextCursor)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransfersFiltersByAccount() async throws {
        let assetIdFilter = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["asset_id"], assetIdFilter)
            XCTAssertEqual(query["kind"], "Transfer")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": [
                    {
                        "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "created_at":"2025-01-01T00:00:00Z",
                        "kind":"Transfer",
                        "box":{
                            "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "json":{
                                "kind":"Transfer",
                                "payload":{
                                    "variant":"Asset",
                                    "value":{
                                        "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                        "object":"10",
                                        "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                    }
                                },
                                "wire_id":"10",
                                "encoded":"beef"
                            }
                        },
                        "transaction_hash":"hash1",
                        "transaction_status":"Committed",
                        "block":1,
                        "index":0
                    },
                    {
                        "authority":"sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM",
                        "created_at":"2025-01-01T00:00:00Z",
                        "kind":"Transfer",
                        "box":{
                            "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "json":{
                                "kind":"Transfer",
                                "payload":{
                                    "variant":"AssetBatch",
                                    "value":{
                                        "entries":[
                                            {
                                                "from":"sorauﾛ1Pﾀﾚｿ1ﾍｶsFｲAfｾeB3ｽヱヱｳcyﾊyｹ1ﾂﾈヰヰ6ﾛヰEAﾃｱｳﾖLPN4XM",
                                                "to":"sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY",
                                                "asset_definition":"61CtjvNd9T3THAR65GsMVHr82Bjc",
                                                "amount":"2"
                                            }
                                        ]
                                    }
                                },
                                "wire_id":"10",
                                "encoded":"beef"
                            }
                        },
                        "transaction_hash":"hash2",
                        "transaction_status":"Committed",
                        "block":1,
                        "index":1
                    }
                ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let transfers = try await makeClient().getExplorerTransfers(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                                    assetDefinitionId: assetIdFilter)
        XCTAssertEqual(transfers.count, 1)
        XCTAssertEqual(transfers.first?.instruction.transactionHash, "hash1")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionsEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/transactions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["cursor"], "Y3Vyc29y")
            XCTAssertEqual(query["limit"], "25")
            XCTAssertEqual(query["authority"], "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(query["block"], "5")
            XCTAssertEqual(query["status"], "Committed")
            XCTAssertEqual(query["asset_id"], "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": [
                    {
                        "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "hash":"deadbeef",
                        "block":5,
                        "created_at":"2025-01-01T00:00:00Z",
                        "executable":"Instructions",
                        "status":"Committed"
                    }
                ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let params = ToriiListQuery(
            filter: ToriiFilter.all([
                ToriiField("authority") == "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                ToriiField("block") == 5,
                ToriiField("status") == "Committed",
                ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
            ]),
            limit: 25, cursor: "Y3Vyc29y"
        )
        let page = try await makeClient().explorerTransactions.page(params)


        XCTAssertEqual(page.items.count, 1)
        XCTAssertEqual(page.items.first?.hash, "deadbeef")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionsCompletion() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/transactions/query")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        let page = try await makeClient().explorerTransactions.page()
        XCTAssertTrue(page.items.isEmpty)
        XCTAssertNil(page.nextCursor)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetContractActivityEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/activity/query")
            XCTAssertEqual(request.httpMethod, "POST")
            let query = try JSONSerialization.jsonObject(with: XCTUnwrap(self.bodyData(from: request))) as! [String: Any]
            XCTAssertEqual(query["limit"] as? Int, 20)
            XCTAssertNotNil(query["filter"])
            XCTAssertNil(query["offset"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "items": [
                    {
                        "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "timestamp_ms": 1234,
                        "block_index": 0,
                        "block_height": 7,
                        "entrypoint_hash": "0xabc",
                        "result_ok": true,
                        "contract_address": "cntr:deadbeef",
                        "contract_alias": "benefits::paynet",
                        "contract_entrypoint": "claim",
                        "contract_payload": {"amount": 500},
                        "fee_payment": {
                            "payer": "authority",
                            "value": {"charge_limits": [], "gas_limit": 50000}
                        }
                    }
                ],
                "next_cursor": null
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let query = ToriiListQuery(filterText: #"contract_alias = "benefits::paynet" and contract_entrypoint = "claim" and timestamp_ms >= 1000 and timestamp_ms <= 2000 and result_ok = true"#, limit: 20)
        let list = try await makeClient().contractActivity.page(query)
        XCTAssertNil(list.nextCursor)
        XCTAssertEqual(list.items.first?.contractAlias, "benefits::paynet")
        XCTAssertEqual(list.items.first?.contractEntrypoint, "claim")
        XCTAssertEqual(list.items.first?.timestampMs, 1234)
        XCTAssertEqual(list.items.first?.feePayment, testFeePayment(gasLimit: 50_000))
        guard case let .object(payload)? = list.items.first?.contractPayload,
              case let .number(amount)? = payload["amount"] else {
            return XCTFail("Expected numeric contract payload.")
        }
        XCTAssertEqual(amount, 500)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetContractEventsEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/events/query")
            XCTAssertEqual(request.httpMethod, "POST")
            let query = try JSONSerialization.jsonObject(with: XCTUnwrap(self.bodyData(from: request))) as! [String: Any]
            XCTAssertEqual(query["limit"] as? Int, 10)
            XCTAssertNotNil(query["filter"])
            XCTAssertNil(query["offset"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "items": [
                    {
                        "event_id": "0xblock:0:0",
                        "schema_version": 1,
                        "provenance": "emitted",
                        "authority": "beneficiary@paynet",
                        "timestamp_ms": 1234,
                        "execution_hash_hex": "0xabc",
                        "output_index": 0,
                        "emission_index": 0,
                        "block_height": 7,
                        "block_hash_hex": "0xblock",
                        "result_ok": true,
                        "contract_address": "cntr:deadbeef",
                        "event_kind": "Changed",
                        "participants": ["beneficiary@paynet", "merchant@paynet"],
                        "asset_ids": ["62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],
                        "numeric_fields": {},
                        "payload": {},
                        "emission": {
                            "contract": "cntr:deadbeef", "code_hash": "code", "entrypoint": 0, "event": 0, "caller": "beneficiary@paynet",
                            "definition": {"name": "Changed", "payload_type": {"nodes": [{"kind": "Struct", "value": {"name": "Demo::Changed", "fields": []}}]}},
                            "payload": {"schema_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], "atoms": []}
                        },
                        "fee_payment": {
                            "payer": "authority",
                            "value": {"charge_limits": [], "gas_limit": 70000}
                        }
                    }
                ],
                "next_cursor": null
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let query = ToriiListQuery(filterText: #"contract_address = "cntr:deadbeef" and event_kind = "Changed" and participants = "merchant@paynet" and asset_ids = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" and provenance = "emitted" and result_ok = true"#, limit: 10)
        let list = try await makeClient().contractEvents.page(query)
        XCTAssertNil(list.nextCursor)
        XCTAssertEqual(list.items.first?.eventId, "0xblock:0:0")
        XCTAssertEqual(list.items.first?.participants ?? [], ["beneficiary@paynet", "merchant@paynet"])
        XCTAssertEqual(list.items.first?.assetIds ?? [], ["62Fk4FPcMuLvW5QjDGNF2a4jAmjM"])
        XCTAssertEqual(list.items.first?.feePayment, testFeePayment(gasLimit: 70_000))
        XCTAssertEqual(list.items.first?.outputIndex, 0)
        XCTAssertEqual(list.items.first?.emissionIndex, 0)
        XCTAssertEqual(list.items.first?.emission.definition.name, "Changed")
        XCTAssertEqual(list.items.first?.emission.payload.atoms, [])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testContractEventsEmptyPage() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/events/query")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = #"{"items":[],"next_cursor":null}"#.data(using: .utf8)!
            return (response, body)
        }

        let page = try await makeClient().contractEvents.page()
        XCTAssertTrue(page.items.isEmpty)
        XCTAssertNil(page.nextCursor)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionDetailEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/transactions/deadbeef")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertNil(components?.queryItems)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "hash":"deadbeef",
                "block":5,
                "created_at":"2025-01-01T00:00:00Z",
                "executable":"Instructions",
                "status":"Committed",
                "rejection_reason": null,
                "metadata": {"note":"demo"},
                "nonce": 7,
                "signature": "0xabc",
                "time_to_live": {"ms": 60000}
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let detail = try await makeClient().getExplorerTransactionDetail(hashHex: "deadbeef")
        XCTAssertEqual(detail.hash, "deadbeef")
        XCTAssertEqual(detail.signature, "0xabc")
        XCTAssertEqual(detail.timeToLive?.ms, 60000)
        guard case let .object(meta) = detail.metadata else {
            return XCTFail("Expected metadata object.")
        }
        guard case let .string(note) = meta["note"] else {
            return XCTFail("Expected metadata.note string.")
        }
        XCTAssertEqual(note, "demo")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerInstructionDetailEncodesQueryAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/deadbeef/3")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            XCTAssertNil(components?.queryItems)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "created_at":"2025-01-01T00:00:00Z",
                "kind":"Transfer",
                "box":{
                    "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "json":{
                        "kind":"Transfer",
                        "payload":{
                            "variant":"Asset",
                            "value":{
                                "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                "object":"5",
                                "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                            }
                        }
                    }
                },
                "transaction_hash":"hash1",
                "transaction_status":"Committed",
                "block":10,
                "index":3
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let item = try await makeClient().getExplorerInstructionDetail(hashHex: "deadbeef",
                                                                       index: 3)
        XCTAssertEqual(item.kind, "Transfer")
        XCTAssertEqual(item.transactionHash, "hash1")
        XCTAssertEqual(item.index, 3)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionDetailCompletion() {
        let expectation = expectation(description: "explorer-transaction-detail")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/transactions/deadbeef")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "hash":"deadbeef",
                "block":5,
                "created_at":"2025-01-01T00:00:00Z",
                "executable":"Instructions",
                "status":"Committed",
                "rejection_reason": null,
                "metadata": {},
                "nonce": null,
                "signature": "0xabc",
                "time_to_live": null
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getExplorerTransactionDetail(hashHex: "deadbeef") { result in
            switch result {
            case .success(let detail):
                XCTAssertEqual(detail.hash, "deadbeef")
                XCTAssertEqual(detail.signature, "0xabc")
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    func testExplorerRwasSharedQueryBody() throws {
        let query = ToriiListQuery(filter: ToriiField("domain") == "commodities.sora", limit: 25, cursor: "Y3Vyc29y")
        let body = try JSONSerialization.jsonObject(with: query.requestBody()) as! [String: Any]
        XCTAssertEqual(body["cursor"] as? String, "Y3Vyc29y")
        XCTAssertEqual(body["limit"] as? Int, 25)
        XCTAssertNotNil(body["filter"])
        XCTAssertNil(body["domain"])
    }

    func testExplorerRwaCursorPageDecodesExactContract() throws {
        let json = """
        {
          "next_cursor":"Y3Vyc29y",
          "items":[]
        }
        """
        let page = try JSONDecoder().decode(ToriiPage<ToriiExplorerRwaRecord>.self, from: Data(json.utf8))

        XCTAssertEqual(page.nextCursor, "Y3Vyc29y")
        XCTAssertNotNil(page.nextCursor)
    }

    func testExplorerRwaCursorPageRejectsRetiredUnknownAndInconsistentFields() {
        let retired = """
        {"page":1,"per_page":25,"total_pages":1,"total_items":0}
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPage<ToriiExplorerRwaRecord>.self, from: Data(retired.utf8))
        )

        let inconsistent = """
        {"limit":25,"next_cursor":null,"has_more":true}
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPage<ToriiExplorerRwaRecord>.self, from: Data(inconsistent.utf8))
        )

        let unknownOuter = """
        {
          "next_cursor":null,
          "items":[],
          "total_items":0
        }
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPage<ToriiExplorerRwaRecord>.self, from: Data(unknownOuter.utf8))
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIterateExplorerRwasFollowsCursorAcrossEmptyScanPage() async throws {
        var observedCursors: [String?] = []
        var observedLimits: [String?] = []
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/rwas/query")
            let query = try self.explorerQueryValues(request)
            observedCursors.append(query["cursor"])
            observedLimits.append(query["limit"])
            XCTAssertEqual(query["domain"], "commodities")

            let body: String
            switch query["cursor"] {
            case nil:
                body = """
                {
                  "next_cursor":"Y3Vyc29yLTE",
                  "items":[]
                }
                """
            case "Y3Vyc29yLTE":
                body = """
                {
                  "next_cursor":"Y3Vyc29yLTI",
                  "items":[{
                    "id":"lot-001$commodities.sora",
                    "owned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "quantity":"1",
                    "held_quantity":"0",
                    "primary_reference":"vault://receipts/1",
                    "status":null,
                    "is_frozen":false,
                    "metadata":{}
                  }]
                }
                """
            case "Y3Vyc29yLTI":
                body = """
                {
                  "next_cursor":null,
                  "items":[{
                    "id":"lot-002$commodities.sora",
                    "owned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "quantity":"2",
                    "held_quantity":"0",
                    "primary_reference":"vault://receipts/2",
                    "status":null,
                    "is_frozen":false,
                    "metadata":{}
                  }]
                }
                """
            default:
                XCTFail("Unexpected cursor")
                body = """
                {"next_cursor":null,"items":[]}
                """
            }
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(body.utf8))
        }

        let stream = makeClient().explorerRwas.items(ToriiListQuery(filter: ToriiField("domain") == "commodities"))
        var identifiers: [String] = []
        for try await item in stream {
            identifiers.append(item.id)
        }

        XCTAssertEqual(identifiers, ["lot-001$commodities.sora", "lot-002$commodities.sora"])
        XCTAssertEqual(observedCursors, [nil, "Y3Vyc29yLTE", "Y3Vyc29yLTI"])
        XCTAssertEqual(observedLimits, [nil, nil, nil])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIterateExplorerRwasRejectsRepeatedCursor() async throws {
        StubURLProtocol.handler = { request in
            let query = try self.explorerQueryValues(request)
            let cursor = query["cursor"]
            let body = """
            {
              "next_cursor":"Y3Vyc29yLTE",
              "items":[]
            }
            """
            if cursor != nil {
                XCTAssertEqual(cursor, "Y3Vyc29yLTE")
            }
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(body.utf8))
        }

        do {
            for try await _ in makeClient().explorerRwas.items() {}
            XCTFail("Expected a repeated-cursor error")
        } catch {
            XCTAssertTrue(String(describing: error).contains("repeated a cursor"))
        }
    }

    func testExplorerRwaRecordDecodesNullStatusAndMetadataDefaults() throws {
        let json = """
        {
            "id":"lot-001$commodities.sora",
            "owned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            "quantity":"42",
            "held_quantity":"2",
            "primary_reference":"vault://receipts/2",
            "status":null,
            "is_frozen":true,
            "metadata":null
        }
        """
        let record = try JSONDecoder().decode(ToriiExplorerRwaRecord.self, from: Data(json.utf8))
        XCTAssertEqual(record.id, "lot-001$commodities.sora")
        XCTAssertEqual(record.quantity, "42")
        XCTAssertEqual(record.heldQuantity, "2")
        XCTAssertEqual(record.primaryReference, "vault://receipts/2")
        XCTAssertNil(record.status)
        XCTAssertTrue(record.isFrozen)
        XCTAssertTrue(record.metadata.isEmpty)
    }

    func testAssetAndRwaReadbacksRejectNoncanonicalQuantities() throws {
        for quantity in ["-1", "01", "1.0", "1.20", " 1", "1e0"] {
            let assetJSON = """
            {"asset":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","asset_name":"Gold","asset_alias":null,"scope":"global","account_id":"owner","quantity":"\(quantity)"}
            """
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiAccountAsset.self, from: Data(assetJSON.utf8)),
                "accepted asset quantity \(quantity)"
            )

            let rwaJSON = """
            {
              "id":"lot-001$commodities.sora",
              "owned_by":"owner",
              "quantity":"\(quantity)",
              "held_quantity":"0",
              "primary_reference":"vault://receipts/2",
              "status":null,
              "is_frozen":false,
              "metadata":{}
            }
            """
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiExplorerRwaRecord.self, from: Data(rwaJSON.utf8)),
                "accepted RWA quantity \(quantity)"
            )
        }

        let badHeld = """
        {
          "id":"lot-001$commodities.sora",
          "owned_by":"owner",
          "quantity":"1",
          "held_quantity":"0.0",
          "primary_reference":"vault://receipts/2",
          "status":null,
          "is_frozen":false,
          "metadata":{}
        }
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiExplorerRwaRecord.self, from: Data(badHeld.utf8))
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerRwaDetailEncodesPathAndDecodesResponse() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/rwas/lot-001$commodities.sora")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "id":"lot-001$commodities.sora",
                "owned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "quantity":"42",
                "held_quantity":"2",
                "primary_reference":"vault://receipts/2",
                "status":null,
                "is_frozen":true,
                "metadata":null
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let detail = try await makeClient().getExplorerRwaDetail(rwaId: "lot-001$commodities.sora")
        XCTAssertEqual(detail.id, "lot-001$commodities.sora")
        XCTAssertEqual(detail.quantity, "42")
        XCTAssertEqual(detail.heldQuantity, "2")
        XCTAssertEqual(detail.primaryReference, "vault://receipts/2")
        XCTAssertNil(detail.status)
        XCTAssertTrue(detail.isFrozen)
        XCTAssertTrue(detail.metadata.isEmpty)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionTransfersAggregatesCursors() async throws {
        let assetIdFilter = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        let pageOne = """
        {
            "next_cursor":"Y3Vyc29yMg",
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":{
                        "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json":{
                            "kind":"Transfer",
                            "payload":{
                                "variant":"Asset",
                                "value":{
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object":"5",
                                    "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash":"deadbeef",
                    "transaction_status":"Committed",
                    "block":10,
                    "index":0
                }
            ]
        }
        """.data(using: .utf8)!

        let pageTwo = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:01Z",
                    "kind":"Transfer",
                    "box":{
                        "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json":{
                            "kind":"Transfer",
                            "payload":{
                                "variant":"Asset",
                                "value":{
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object":"7",
                                    "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash":"deadbeef",
                    "transaction_status":"Committed",
                    "block":10,
                    "index":1
                }
            ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["transaction_hash"], "deadbeef")
            XCTAssertEqual(query["kind"], "Transfer")
            XCTAssertEqual(query["asset_id"], assetIdFilter)
            XCTAssertNil(query["page"])
            XCTAssertNil(query["per_page"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            switch query["cursor"] {
            case nil:
                XCTAssertNil(query["limit"])
                return (response, pageOne)
            case "Y3Vyc29yMg":
                XCTAssertNil(query["limit"])
                return (response, pageTwo)
            default:
                return (response, Data())
            }
        }

        let records = try await makeClient().getExplorerTransactionTransfers(hashHex: "deadbeef",
                                                                             assetDefinitionId: assetIdFilter)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records.first?.instruction.index, 0)
        XCTAssertEqual(records.last?.instruction.index, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionTransferSummariesCompletion() {
        let expectation = expectation(description: "explorer-transaction-transfer-summaries")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": [
                    {
                        "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "created_at":"2025-01-01T00:00:00Z",
                        "kind":"Transfer",
                        "box":{
                            "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "json":{
                                "kind":"Transfer",
                                "payload":{
                                    "variant":"Asset",
                                    "value":{
                                        "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                        "object":"5",
                                        "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                    }
                                }
                            }
                        },
                        "transaction_hash":"deadbeef",
                        "transaction_status":"Committed",
                        "block":10,
                        "index":0
                    }
                ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getExplorerTransactionTransferSummaries(hashHex: "deadbeef",
                                                                 matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D") { result in
            switch result {
            case .success(let summaries):
                XCTAssertEqual(summaries.count, 1)
                XCTAssertEqual(summaries.first?.transactionHash, "deadbeef")
                XCTAssertEqual(summaries.first?.direction, .incoming)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransactionTransferSummariesFiltersByAssetId() async throws {
        let body = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:00Z",
                    "kind":"Transfer",
                    "box":{
                        "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json":{
                            "kind":"Transfer",
                            "payload":{
                                "variant":"Asset",
                                "value":{
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object":"5",
                                    "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash":"deadbeef",
                    "transaction_status":"Committed",
                    "block":10,
                    "index":0
                },
                {
                    "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at":"2025-01-01T00:00:01Z",
                    "kind":"Transfer",
                    "box":{
                        "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json":{
                            "kind":"Transfer",
                            "payload":{
                                "variant":"Asset",
                                "value":{
                                    "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object":"7",
                                    "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash":"deadbeef",
                    "transaction_status":"Committed",
                    "block":10,
                    "index":1
                }
            ]
        }
        """
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["transaction_hash"], "deadbeef")
            XCTAssertEqual(query["kind"], "Transfer")
            XCTAssertEqual(query["asset_id"], "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, body)
        }

        let summaries = try await makeClient().getExplorerTransactionTransferSummaries(hashHex: "deadbeef",
                                                                                        assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(summaries.count, 1)
        XCTAssertEqual(summaries.first?.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerInstructionDetailCompletion() {
        let expectation = expectation(description: "explorer-instruction-detail")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/deadbeef/0")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "created_at":"2025-01-01T00:00:00Z",
                "kind":"Transfer",
                "box":{
                    "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "json":{
                        "kind":"Transfer",
                        "payload":{
                            "variant":"Asset",
                            "value":{
                                "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                "object":"5",
                                "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                            }
                        }
                    }
                },
                "transaction_hash":"hash1",
                "transaction_status":"Committed",
                "block":10,
                "index":0
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getExplorerInstructionDetail(hashHex: "deadbeef", index: 0) { result in
            switch result {
            case .success(let item):
                XCTAssertEqual(item.transactionHash, "hash1")
                XCTAssertEqual(item.index, 0)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransferSummariesFiltersByAccount() async throws {
        let assetIdFilter = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["asset_id"], assetIdFilter)
            XCTAssertEqual(query["kind"], "Transfer")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": [
                    {
                        "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "created_at":"2025-01-01T00:00:00Z",
                        "kind":"Transfer",
                        "box":{
                            "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "json":{
                                "kind":"Transfer",
                                "payload":{
                                    "variant":"Asset",
                                    "value":{
                                        "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                        "object":"10",
                                        "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                    }
                                },
                                "wire_id":"10",
                                "encoded":"beef"
                            }
                        },
                        "transaction_hash":"hash1",
                        "transaction_status":"Committed",
                        "block":1,
                        "index":0
                    }
                ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let summaries = try await makeClient().getExplorerTransferSummaries(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                                            assetDefinitionId: assetIdFilter)
        XCTAssertEqual(summaries.count, 1)
        XCTAssertEqual(summaries.first?.direction, .incoming)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetExplorerTransferSummariesCompletion() {
        let expectation = expectation(description: "explorer-transfer-summaries")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["kind"], "Transfer")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getExplorerTransferSummaries { result in
            switch result {
            case .success(let summaries):
                XCTAssertEqual(summaries.count, 0)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetAccountTransferHistoryBuildsTransferQuery() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["kind"], "Transfer")
            XCTAssertEqual(query["cursor"], "Y3Vyc29y")
            XCTAssertEqual(query["limit"], "20")
            XCTAssertNil(query["page"])
            XCTAssertNil(query["per_page"])
            XCTAssertEqual(query["asset_id"], "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": []
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let summaries = try await makeClient().getAccountTransferHistory(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                                          cursor: "Y3Vyc29y",
                                                                          limit: 20,
                                                                          assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(summaries.count, 0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetAccountTransferHistoryCompletion() {
        let expectation = expectation(description: "account-transfer-history")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getAccountTransferHistory(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV") { result in
            switch result {
            case .success(let summaries):
                XCTAssertEqual(summaries.count, 0)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionHistoryBuildsTransferQuery() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["kind"], "Transfer")
            XCTAssertEqual(query["cursor"], "Y3Vyc29y")
            XCTAssertEqual(query["limit"], "5")
            XCTAssertNil(query["page"])
            XCTAssertNil(query["per_page"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
                "next_cursor":null,
                "items": []
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let summaries = try await makeClient().getTransactionHistory(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                                                     cursor: "Y3Vyc29y",
                                                                     limit: 5)
        XCTAssertEqual(summaries.count, 0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionHistoryCompletion() {
        let expectation = expectation(description: "transaction-history")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"next_cursor":null,"items":[]}
            """.data(using: .utf8)!
            return (response, body)
        }

        _ = makeClient().getTransactionHistory(accountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV") { result in
            switch result {
            case .success(let summaries):
                XCTAssertEqual(summaries.count, 0)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIterateAccountTransferHistoryAcrossCursors() async throws {
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            XCTAssertEqual(request.url?.path, "/v1/explorer/instructions/query")
            let query = try self.explorerQueryValues(request)
            XCTAssertEqual(query["kind"], "Transfer")
            if callCount == 1 {
                XCTAssertNil(query["cursor"])
            } else {
                XCTAssertEqual(query["cursor"], "Y3Vyc29yMg")
            }
            XCTAssertEqual(query["limit"], "1")
            XCTAssertNil(query["page"])
            XCTAssertNil(query["per_page"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body: String
            if callCount == 1 {
                body = """
                {
                    "next_cursor":"Y3Vyc29yMg",
                    "items": [
                        {
                            "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                            "created_at":"2025-01-01T00:00:00Z",
                            "kind":"Transfer",
                            "box":{
                                "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "json":{
                                    "kind":"Transfer",
                                    "payload":{
                                        "variant":"Asset",
                                        "value":{
                                            "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                            "object":"10",
                                            "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                        }
                                    },
                                    "wire_id":"10",
                                    "encoded":"beef"
                                }
                            },
                            "transaction_hash":"hash1",
                            "transaction_status":"Committed",
                            "block":1,
                            "index":0
                        }
                    ]
                }
                """
            } else {
                body = """
                {
                    "next_cursor":null,
                    "items": [
                        {
                            "authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                            "created_at":"2025-01-01T00:00:01Z",
                            "kind":"Transfer",
                            "box":{
                                "encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "json":{
                                    "kind":"Transfer",
                                    "payload":{
                                        "variant":"Asset",
                                        "value":{
                                            "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                            "object":"5",
                                            "destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                        }
                                    },
                                    "wire_id":"10",
                                    "encoded":"beef"
                                }
                            },
                            "transaction_hash":"hash2",
                            "transaction_status":"Committed",
                            "block":2,
                            "index":0
                        }
                    ]
                }
                """
            }
            return (response, Data(body.utf8))
        }

        var summaries: [ToriiExplorerTransferSummary] = []
        for try await summary in makeClient().iterateAccountTransferHistory(accountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                                            limit: 1) {
            summaries.append(summary)
        }
        XCTAssertEqual(summaries.count, 2)
        XCTAssertEqual(summaries.first?.transactionHash, "hash1")
        XCTAssertEqual(summaries.last?.transactionHash, "hash2")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testIterateAccountTransferHistoryRejectsRepeatedCursor() async throws {
        var callCount = 0
        StubURLProtocol.handler = { request in
            callCount += 1
            let query = try self.explorerQueryValues(request)
            if callCount == 1 {
                XCTAssertNil(query["cursor"])
            } else {
                XCTAssertEqual(query["cursor"], "Y3Vyc29y")
            }
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {
              "next_cursor":"Y3Vyc29y",
              "items":[]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        let stream = makeClient().iterateAccountTransferHistory(
            accountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
        )
        do {
            for try await _ in stream {
                XCTFail("empty pages should not yield transfer summaries")
            }
            XCTFail("expected repeated cursor failure")
        } catch {
            guard case let ToriiClientError.invalidPayload(message) = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(message.contains("repeated a cursor"))
        }
        XCTAssertEqual(callCount, 2)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListSubscriptionPlansEncodesParams() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/subscriptions/plans/query")
            XCTAssertEqual(request.httpMethod, "POST")
            let query = try JSONSerialization.jsonObject(with: XCTUnwrap(self.bodyData(from: request))) as! [String: Any]
            XCTAssertEqual(query["limit"] as? Int, 10)
            XCTAssertNotNil(query["filter"])
            XCTAssertNil(query["offset"])
            let payload: [String: Any] = [
                "items": [
                    [
                        "id": "plan#subs",
                        "provider": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                        "pricing": ["kind": "fixed"]
                    ]
                ],
                "next_cursor": NSNull(),
                "total": 1
            ]
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }

        let query = ToriiListQuery(filter: ToriiField("provider") == "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", limit: 10, includeTotal: true)
        let response = try await makeClient().subscriptionPlans.page(query)
        XCTAssertEqual(response.total, 1)
        let item = try XCTUnwrap(response.items.first)
        XCTAssertEqual(item.id, "plan#subs")
        XCTAssertEqual(item.provider, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListSubscriptionsEncodesParams() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/subscriptions/query")
            XCTAssertEqual(request.httpMethod, "POST")
            let query = try JSONSerialization.jsonObject(with: XCTUnwrap(self.bodyData(from: request))) as! [String: Any]
            XCTAssertEqual(query["limit"] as? Int, 25)
            XCTAssertNotNil(query["filter"])
            XCTAssertNil(query["offset"])
            let payload: [String: Any] = [
                "items": [
                    [
                        "id": "sub-1$subscriptions",
                        "status": "active",
                        "plan_id": "plan#subs",
                        "invoice": ["amount": "120"],
                        "plan": ["provider": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"]
                    ]
                ],
                "next_cursor": NSNull(),
                "total": 1
            ]
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }

        let query = ToriiListQuery(filterText: #"owned_by = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D" and provider = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV" and status = "active""#, limit: 25, includeTotal: true)
        let response = try await makeClient().subscriptions.page(query)
        XCTAssertEqual(response.total, 1)
        let record = try XCTUnwrap(response.items.first)
        XCTAssertEqual(record.id, "sub-1$subscriptions")
        XCTAssertEqual(record.status, .active)
        XCTAssertEqual(record.planId, "plan#subs")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetSubscriptionDecodesRecord() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/subscriptions/sub-1$subscriptions")
            let payload: [String: Any] = [
                "subscription_id": "sub-1$subscriptions",
                "subscription": ["status": "active"],
                "invoice": NSNull(),
                "plan": ["provider": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"]
            ]
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let data = try JSONSerialization.data(withJSONObject: payload)
            return (response, data)
        }

        let record = try await makeClient().getSubscription(subscriptionId: "sub-1$subscriptions")
        XCTAssertEqual(record?.subscriptionId, "sub-1$subscriptions")
        if case let .string(provider)? = record?.plan?["provider"] {
            XCTAssertEqual(provider, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        } else {
            XCTFail("missing plan provider")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetSubscriptionReturnsNilFor404() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/subscriptions/sub-404$subscriptions")
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: [:])!
            return (response, Data())
        }
        let record = try await makeClient().getSubscription(subscriptionId: "sub-404$subscriptions")
        XCTAssertNil(record)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConfigurationParsesConfidentialGas() async throws {
        let payload = """
        {
          "public_key":"ed0123",
          "logger":{"level":"Info","filter":null},
          "network":{
            "block_gossip_size":32,
            "block_gossip_period_ms":150,
            "transaction_gossip_size":16,
            "transaction_gossip_period_ms":75
          },
          "queue":{"capacity":2048},
          "confidential_gas":{
            "proof_base":10,
            "per_public_input":2,
            "per_proof_byte":3,
            "per_nullifier":4,
            "per_commitment":5
          },
          "transport": {
            "norito_rpc": {
              "enabled": true,
              "stage": "ga",
              "require_mtls": false,
              "canary_allowlist_size": 2
            }
          },
          "nexus": {
            "axt": {
              "slot_length_ms": 1000,
              "max_clock_skew_ms": 250,
              "proof_cache_ttl_slots": 3,
              "replay_retention_slots": 64
            }
          }
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/configuration")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let snapshot = try await makeClient().getConfiguration()
        XCTAssertEqual(snapshot.publicKeyHex, "ed0123")
        XCTAssertEqual(snapshot.logger.level, "Info")
        XCTAssertNil(snapshot.logger.filter)
        XCTAssertEqual(snapshot.network.blockGossipSize, 32)
        XCTAssertEqual(snapshot.network.transactionGossipPeriodMs, 75)
        XCTAssertEqual(snapshot.queue?.capacity, 2048)
        let gas = try XCTUnwrap(snapshot.confidentialGas)
        XCTAssertEqual(gas.proofBase, 10)
        XCTAssertEqual(gas.perPublicInput, 2)
        XCTAssertEqual(gas.perProofByte, 3)
        XCTAssertEqual(gas.perNullifier, 4)
        XCTAssertEqual(gas.perCommitment, 5)
        let transport = try XCTUnwrap(snapshot.transport)
        let noritoRpc = try XCTUnwrap(transport.noritoRpc)
        XCTAssertTrue(noritoRpc.enabled)
        XCTAssertEqual(noritoRpc.stage, "ga")
        XCTAssertFalse(noritoRpc.requireMtls)
        XCTAssertEqual(noritoRpc.canaryAllowlistSize, 2)
        let axt = try XCTUnwrap(snapshot.nexus?.axt)
        XCTAssertEqual(axt.slotLengthMs, 1_000)
        XCTAssertEqual(axt.maxClockSkewMs, 250)
        XCTAssertEqual(axt.proofCacheTtlSlots, 3)
        XCTAssertEqual(axt.replayRetentionSlots, 64)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConfidentialGasScheduleNilWhenMissing() async throws {
        let payload = """
        {
          "public_key":"ed0123",
          "logger":{"level":"Info","filter":null},
          "network":{
            "block_gossip_size":32,
            "block_gossip_period_ms":150,
            "transaction_gossip_size":16,
            "transaction_gossip_period_ms":75
          },
          "queue":{"capacity":2048}
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/configuration")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let schedule = try await makeClient().getConfidentialGasSchedule()
        XCTAssertNil(schedule)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConfidentialAssetPolicyAsync() async throws {
        let payload = """
        {
          "asset":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
          "block_height":1024,
          "current_mode":"Convertible",
          "effective_mode":"Convertible",
          "vk_set_hash":"0123ABCD",
          "poseidon_params_id":7,
          "pedersen_params_id":11,
          "pending_transition":{
            "transition_id":"DEADBEEF",
            "previous_mode":"Convertible",
            "new_mode":"ShieldedOnly",
            "effective_height":2048,
            "conversion_window":200,
            "window_open_height":1848
          }
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/confidential/assets/62Fk4FPcMuLvW5QjDGNF2a4jAmjM/transitions"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let policy = try await makeClient().getConfidentialAssetPolicy(assetDefinitionId: "  62Fk4FPcMuLvW5QjDGNF2a4jAmjM  ")
        XCTAssertEqual(policy.assetId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(policy.blockHeight, 1024)
        XCTAssertEqual(policy.currentMode, "Convertible")
        XCTAssertEqual(policy.effectiveMode, "Convertible")
        XCTAssertEqual(policy.vkSetHashHex, "0123ABCD")
        XCTAssertEqual(policy.poseidonParamsId, 7)
        XCTAssertEqual(policy.pedersenParamsId, 11)
        XCTAssertEqual(policy.pendingTransition?.transitionId, "DEADBEEF")
        XCTAssertEqual(policy.pendingTransition?.previousMode, "Convertible")
        XCTAssertEqual(policy.pendingTransition?.newMode, "ShieldedOnly")
        XCTAssertEqual(policy.pendingTransition?.effectiveHeight, 2048)
        XCTAssertEqual(policy.pendingTransition?.conversionWindow, 200)
        XCTAssertEqual(policy.pendingTransition?.windowOpenHeight, 1848)
    }

    func testGetConfidentialAssetPolicyCompletion() {
        let expectation = expectation(description: "conf-policy")
        let payload = """
        {
          "asset":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
          "block_height":42,
          "current_mode":"TransparentOnly",
          "effective_mode":"TransparentOnly",
          "vk_set_hash":null,
          "poseidon_params_id":null,
          "pedersen_params_id":null,
          "pending_transition":null
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/confidential/assets/62Fk4FPcMuLvW5QjDGNF2a4jAmjM/transitions"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        makeClient().getConfidentialAssetPolicy(assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM") { result in
            switch result {
            case .success(let policy):
                XCTAssertEqual(policy.blockHeight, 42)
                XCTAssertNil(policy.vkSetHashHex)
                XCTAssertNil(policy.pendingTransition)
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetConfidentialAssetPolicyRejectsEmptyId() async {
        do {
            _ = try await makeClient().getConfidentialAssetPolicy(assetDefinitionId: "   ")
            XCTFail("Expected rejection for blank asset id")
        } catch {
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
        }
    }
}

final class ToriiClientHeaderTests: XCTestCase {
    func testAuthenticationContextDoesNotRetainOnboardingCredential() {
        let authentication = ToriiClientAuthentication(headers: [
            ToriiAccountOnboardingTokenHeader.lowercased(): String(repeating: "T", count: 32)
        ])

        XCTAssertFalse(authentication.headers.keys.contains {
            $0.caseInsensitiveCompare(ToriiAccountOnboardingTokenHeader) == .orderedSame
        })
    }

    func testDecodePdpCommitmentHeaderDecodesData() throws {
        let payload = Data([0x01, 0x02, 0x03])
        let header = payload.base64EncodedString()

        let decoded = try decodePdpCommitmentHeader([ToriiPdpCommitmentHeader: header])

        XCTAssertEqual(decoded, payload)
    }

    func testDecodePdpCommitmentHeaderFromResponse() throws {
        let payload = Data([0xAA, 0xBB])
        let header = payload.base64EncodedString()
        let response = HTTPURLResponse(
            url: URL(string: "https://example.com")!,
            statusCode: 202,
            httpVersion: nil,
            headerFields: ["Sora-PDP-Commitment": header]
        )!

        let decoded = try decodePdpCommitmentHeader(from: response)

        XCTAssertEqual(decoded, payload)
    }

    func testDecodePdpCommitmentHeaderRejectsInvalidPayload() {
        XCTAssertThrowsError(
            try decodePdpCommitmentHeader([ToriiPdpCommitmentHeader: "###"])
        ) { error in
            guard case ToriiClientError.invalidPayload = error else {
                XCTFail("Expected invalidPayload but got \(error)")
                return
            }
        }
    }
}

    private func verifyingKeyDraftResponse(
        payload: Data? = nil
    ) -> Data {
        let payload = payload ?? canonicalVerifyingKeyTransactionPayload()
        return try! JSONSerialization.data(withJSONObject: [
            "submitted": false,
            "transaction_payload_b64": payload.base64EncodedString(),
            "signing_message_b64": IrohaHash.hash(payload).base64EncodedString(),
        ])
    }

    private func canonicalVerifyingKeyTransactionPayload(
        wireName: String =
            "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
        networkId: NetworkId = TestNetworkIds.canonical,
        domainOverride: Data? = nil,
        authority: String =
            "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
        backend: String = "pipa-r/pasta",
        name: String = "vk_main",
        version: UInt32 = 1,
        circuitId: String = "pipa-r/pasta/confidential-transfer-v1",
        schemaHash: Data = Data(repeating: 0xee, count: 32),
        gasScheduleId: String? = "native_pipa_r_default",
        keyBytes: Data? = Data([0x01, 0x02, 0x03]),
        recordVersion: UInt32? = nil
    ) -> Data {
        func string(_ value: String) -> Data {
            CompactNorito.encodeString(value)
        }
        func option(_ value: Data?) -> Data {
            var writer = CompactNoritoWriter()
            guard let value else {
                writer.writeUInt8(0)
                return writer.data
            }
            writer.writeUInt8(1)
            writer.writeField(value)
            return writer.data
        }
        func byteVector(_ value: Data) -> Data {
            var writer = CompactNoritoWriter()
            writer.writeUInt64LE(UInt64(value.count))
            writer.writeBytes(value)
            return writer.data
        }
        func uint32(_ value: UInt32) -> Data {
            var writer = CompactNoritoWriter()
            writer.writeUInt32LE(value)
            return writer.data
        }
        func uint64(_ value: UInt64) -> Data {
            var writer = CompactNoritoWriter()
            writer.writeUInt64LE(value)
            return writer.data
        }
        func structure(_ fields: [Data]) -> Data {
            var writer = CompactNoritoWriter()
            for field in fields {
                writer.writeField(field)
            }
            return writer.data
        }

        let commitment: Data
        if let keyBytes {
            let backendBytes = Data(backend.utf8)
            var preimage = Data("iroha:zk:v1:vk".utf8)
            var backendLength = UInt64(backendBytes.count).bigEndian
            var keyLength = UInt64(keyBytes.count).bigEndian
            preimage.append(withUnsafeBytes(of: &backendLength) { Data($0) })
            preimage.append(backendBytes)
            preimage.append(withUnsafeBytes(of: &keyLength) { Data($0) })
            preimage.append(keyBytes)
            commitment = Data(SHA256.hash(data: preimage))
        } else {
            commitment = Data(repeating: 0x44, count: 32)
        }
        let id = structure([string(backend), string(name)])
        let inlineKey = keyBytes.map {
            structure([string(backend), byteVector($0)])
        }
        let record = structure([
            uint32(recordVersion ?? version),
            string(circuitId),
            option(nil),
            string("core"),
            uint32(backend.hasPrefix("stark/") ? 1 : 0),
            string("unknown"),
            schemaHash,
            commitment,
            uint32(UInt32(keyBytes?.count ?? 1)),
            uint32(0),
            option(gasScheduleId.map(string)),
            option(nil),
            option(nil),
            option(nil),
            option(nil),
            option(inlineKey),
            Data([1]),
        ])
        let instructionBody = structure([id, record])
        let archive = noritoEncode(
            typeName: wireName,
            payload: instructionBody,
            flags: NoritoHeader.compactLen
        )
        let instruction = structure([string(wireName), byteVector(archive)])
        var sequence = CompactNoritoWriter()
        sequence.writeUInt64LE(1)
        sequence.writeField(instruction)
        var executable = CompactNoritoWriter()
        executable.writeUInt32LE(0)
        executable.writeField(sequence.data)

        var networkDomain = CompactNoritoWriter()
        networkDomain.writeUInt32LE(0)
        networkDomain.writeField(networkId.bytes)
        let authorityPayload = try! AccountAddress.parseEncoded(authority)
            .compactNoritoAccountControllerPayload()
        var feeAuthority = CompactNoritoWriter()
        feeAuthority.writeField(uint64(0))
        feeAuthority.writeField(Data([0]))
        var feePayment = CompactNoritoWriter()
        feePayment.writeUInt32LE(0)
        feePayment.writeField(feeAuthority.data)
        var payload = CompactNoritoWriter()
        for field in [
            domainOverride ?? networkDomain.data,
            authorityPayload,
            uint64(1),
            executable.data,
            option(uint64(100_000)),
            Data([0]),
            feePayment.data,

            uint64(0),
            Data([0]),
        ] {
            payload.writeField(field)
        }
        return payload.data
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetRuntimeMetricsAsync() async throws {
        let payload = """
        {"abi_version":1,"upgrade_events_total":{"proposed":5,"activated":6,"canceled":1}}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/runtime/metrics")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let metrics = try await makeClient().getRuntimeMetrics(canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(metrics.abiVersion, 1)
        XCTAssertEqual(metrics.upgradeEventsTotal.proposed, 5)
        XCTAssertEqual(metrics.upgradeEventsTotal.activated, 6)
        XCTAssertEqual(metrics.upgradeEventsTotal.canceled, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetRuntimeAbiActiveAsync() async throws {
        let payload = """
        {"abi_version":1}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/runtime/abi/active")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let snapshot = try await makeClient().getRuntimeAbiActive(canonicalAuth: canonicalReadAuth)
        XCTAssertEqual(snapshot.abiVersion, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetRuntimeAbiHashAsync() async throws {
        let payload = """
        {"policy":"V1","abi_hash_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/runtime/abi/hash")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let hash = try await makeClient().getRuntimeAbiHash()
        XCTAssertEqual(hash.policy, "V1")
        XCTAssertEqual(hash.abiHashHex, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListRuntimeUpgradesAsync() async throws {
        let upgradeId = String(repeating: "9", count: 64)
        let payload = """
        {
          "items": [
            {
              "id_hex": "\(upgradeId)",
              "record": {
                "manifest": {
                  "name": "Upgrade Foo",
                  "description": "Test upgrade",
                  "abi_version": 1,
                  "abi_hash": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                  "added_syscalls": [],
                  "added_pointer_types": [],
                  "start_height": 100,
                  "end_height": 200
                },
                "status": { "ActivatedAt": 123 },
                "proposer": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "created_height": 90
              }
            }
          ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/runtime/upgrades")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let upgrades = try await makeClient().listRuntimeUpgrades()
        XCTAssertEqual(upgrades.count, 1)
        let item = upgrades[0]
        XCTAssertEqual(item.idHex, upgradeId)
        XCTAssertEqual(item.record.proposer, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(item.record.createdHeight, 90)
        guard case let .activatedAt(height) = item.record.status else {
            return XCTFail("Expected ActivatedAt status")
        }
        XCTAssertEqual(height, 123)
        let manifest = item.record.manifest
        XCTAssertEqual(manifest.name, "Upgrade Foo")
        XCTAssertEqual(manifest.description, "Test upgrade")
        XCTAssertEqual(manifest.abiVersion, 1)
        XCTAssertEqual(manifest.addedSyscalls, [])
        XCTAssertEqual(manifest.addedPointerTypes, [])
        XCTAssertEqual(manifest.startHeight, 100)
        XCTAssertEqual(manifest.endHeight, 200)
        XCTAssertEqual(manifest.abiHashHex, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testProposeRuntimeUpgradeAsync() async throws {
        let manifest = ToriiRuntimeUpgradeManifest(
            name: "Upgrade Foo",
            description: "Test",
            abiVersion: 1,
            abiHashHex: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            addedSyscalls: [],
            addedPointerTypes: [],
            startHeight: 123,
            endHeight: 456
        )
        let expectedResponse = """
        {"ok":true,"tx_instructions":[{"wire_id":"Upgrade","payload_hex":"00"}]}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/runtime/upgrades/propose")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let json = self.bodyJSON(from: request)
            guard let manifestJSON = json["manifest"] as? [String: Any] else {
                return (HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: nil, headerFields: nil)!, Data())
            }
            XCTAssertEqual(manifestJSON["name"] as? String, "Upgrade Foo")
            XCTAssertEqual(manifestJSON["abi_version"] as? Int, 1)
            XCTAssertEqual(manifestJSON["abi_hash"] as? String, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
            XCTAssertEqual(manifestJSON["start_height"] as? Int, 123)
            XCTAssertEqual(manifestJSON["end_height"] as? Int, 456)
            if let syscalls = manifestJSON["added_syscalls"] as? [NSNumber] {
                XCTAssertTrue(syscalls.isEmpty)
            }
            if let pointerTypes = manifestJSON["added_pointer_types"] as? [NSNumber] {
                XCTAssertTrue(pointerTypes.isEmpty)
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, expectedResponse)
        }

        let action = try await makeClient().proposeRuntimeUpgrade(manifest: manifest)
        XCTAssertTrue(action.ok)
        XCTAssertEqual(action.txInstructions.first?.wireId, "Upgrade")
        XCTAssertEqual(action.txInstructions.first?.payloadHex, "00")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListRuntimeUpgradesRejectsNonV1ManifestAsync() async throws {
        let upgradeId = String(repeating: "9", count: 64)
        let payload = """
        {
          "items": [
            {
              "id_hex": "\(upgradeId)",
              "record": {
                "manifest": {
                  "name": "Upgrade Foo",
                  "description": "Test upgrade",
                  "abi_version": 2,
                  "abi_hash": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                  "added_syscalls": [],
                  "added_pointer_types": [],
                  "start_height": 100,
                  "end_height": 200
                },
                "status": { "Proposed": null },
                "proposer": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                "created_height": 90
              }
            }
          ]
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/runtime/upgrades")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        do {
            _ = try await makeClient().listRuntimeUpgrades()
            XCTFail("expected listRuntimeUpgrades to reject non-v1 ABI manifests")
        } catch {
            XCTAssertTrue(String(describing: error).contains("abi_version must be 1"))
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testActivateRuntimeUpgradeAsync() async throws {
        let upgradeId = String(repeating: "a", count: 64)
        let expectedResponse = """
        {"ok":true,"tx_instructions":[{"wire_id":"Activate","payload_hex":"11"}]}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/runtime/upgrades/activate/\(upgradeId)")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.httpBody ?? Data(), Data())
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, expectedResponse)
        }

        let action = try await makeClient().activateRuntimeUpgrade(idHex: "  \(upgradeId) ")
        XCTAssertTrue(action.ok)
        XCTAssertEqual(action.txInstructions.first?.wireId, "Activate")
        XCTAssertEqual(action.txInstructions.first?.payloadHex, "11")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCancelRuntimeUpgradeAsync() async throws {
        let upgradeId = String(repeating: "b", count: 64)
        let expectedResponse = """
        {"ok":true,"tx_instructions":[{"wire_id":"Cancel","payload_hex":"22"}]}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/runtime/upgrades/cancel/\(upgradeId)")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.httpBody ?? Data(), Data())
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, expectedResponse)
        }

        let action = try await makeClient().cancelRuntimeUpgrade(idHex: upgradeId)
        XCTAssertTrue(action.ok)
        XCTAssertEqual(action.txInstructions.first?.wireId, "Cancel")
        XCTAssertEqual(action.txInstructions.first?.payloadHex, "22")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetVerifyingKeyAsync() async throws {
        let recordNorito = try canonicalVerifierRecordArchive(seed: 0x63)
        let payload = """
        {
          "id": { "backend": "pipa-r/pasta", "name": "vk main" },
          "record_norito_base64": "\(recordNorito.base64EncodedString())",
          "record": {
            "version": 2,
            "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
            "owner_manifest_id": "manifest-v2",
            "namespace": "confidential",
            "backend": "pipa-r/pasta",
            "curve": "pallas",
            "public_inputs_schema_hash": "fae4cbe786f280b4e2184dbb06305fe46b7aee20464c0be96023ffd8eac064d3",
            "commitment": "20574662a58708e02e0000000000000000000000000000000000000000000000",
            "vk_len": 3,
            "max_proof_bytes": 8192,
            "gas_schedule_id": "native_pipa_r_default",
            "metadata_uri_cid": "ipfs://vk-meta",
            "vk_bytes_cid": "ipfs://vk-bundle",
            "activation_height": 1024,
            "status": "Active",
            "key": { "backend": "pipa-r/pasta", "bytes_b64": "AQID" }
          }
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/zk/vk/pipa-r%2Fpasta/vk%20main"))
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, payload)
        }

        let detail = try await makeClient().getVerifyingKey(backend: "pipa-r/pasta", name: "vk main")
        XCTAssertEqual(detail.id.backend, "pipa-r/pasta")
        XCTAssertEqual(detail.id.name, "vk main")
        XCTAssertEqual(detail.record.version, 2)
        XCTAssertEqual(detail.record.ownerManifestId, "manifest-v2")
        XCTAssertEqual(detail.record.namespace, "confidential")
        XCTAssertEqual(detail.record.publicInputsSchemaHashHex,
                       "fae4cbe786f280b4e2184dbb06305fe46b7aee20464c0be96023ffd8eac064d3")
        XCTAssertEqual(detail.record.inlineKey?.backend, "pipa-r/pasta")
        XCTAssertEqual(detail.record.inlineKey?.bytes, Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(detail.recordNorito, recordNorito)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetVerifyingKeyRejectsCrossWiredDetail() async throws {
        let recordNorito = try canonicalVerifierRecordArchive(seed: 0x64)
        let payload = """
        {
          "id": { "backend": "pipa-r/pasta", "name": "different-vk" },
          "record_norito_base64": "\(recordNorito.base64EncodedString())",
          "record": {
            "version": 3,
            "circuit_id": "pipa-r/pasta/confidential-unshield-change-v1",
            "owner_manifest_id": "confidential-v3",
            "namespace": "confidential",
            "backend": "pipa-r/pasta",
            "curve": "pallas",
            "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "vk_len": 96,
            "max_proof_bytes": 196608,
            "status": "Active"
          }
        }
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/zk/vk/pipa-r%2Fpasta/unshield-v3"))
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, payload)
        }

        do {
            _ = try await makeClient().getVerifyingKey(
                backend: "pipa-r/pasta",
                name: "unshield-v3"
            )
            XCTFail("cross-wired verifier detail must be rejected")
        } catch let error as ToriiClientError {
            guard case let .invalidPayload(reason) = error else {
                return XCTFail("unexpected Torii error: \(error)")
            }
            XCTAssertEqual(
                reason,
                "verifying-key detail identifier does not match the requested verifier key"
            )
        }
    }

    func testVerifyingKeyDetailPreservesExactNoritoRecord() throws {
        let recordNorito = try canonicalVerifierRecordArchive(seed: 0x71)
        let payload = """
        {
          "id": { "backend": "pipa-r/pasta", "name": "unshield-v3" },
          "record_norito_base64": "\(recordNorito.base64EncodedString())",
          "record": {
            "version": 3,
            "circuit_id": "pipa-r/pasta/confidential-unshield-change-v1",
            "owner_manifest_id": "confidential-v3",
            "namespace": "confidential",
            "backend": "pipa-r/pasta",
            "curve": "pallas",
            "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "vk_len": 96,
            "max_proof_bytes": 196608,
            "status": "Active"
          }
        }
        """.data(using: .utf8)!

        let detail = try JSONDecoder().decode(ToriiVerifyingKeyDetail.self, from: payload)
        XCTAssertEqual(detail.id.backend, "pipa-r/pasta")
        XCTAssertEqual(detail.id.name, "unshield-v3")
        XCTAssertEqual(detail.recordNorito, recordNorito)
    }

    func testVerifyingKeyDetailRejectsNoncanonicalRecordNoritoBase64() throws {
        let recordNorito = try canonicalVerifierRecordArchive(
            seed: 0x79,
            verifierKeyLength: 96
        )
        let canonical = recordNorito.base64EncodedString()
        XCTAssertTrue(canonical.hasSuffix("="))

        func payload(recordBase64: String?) -> Data {
            let archiveField = recordBase64.map {
                "\"record_norito_base64\": \"\($0)\","
            } ?? ""
            return """
            {
              "id": { "backend": "pipa-r/pasta", "name": "unshield-v3" },
              \(archiveField)
              "record": {
                "version": 3,
                "circuit_id": "unshield-v3",
                "backend": "pipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "vk_len": 96,
                "max_proof_bytes": 196608,
                "status": "Active"
              }
            }
            """.data(using: .utf8)!
        }

        for noncanonical in ["", " \(canonical)", String(canonical.dropLast())] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiVerifyingKeyDetail.self,
                    from: payload(recordBase64: noncanonical)
                )
            ) { error in
                XCTAssertTrue(String(describing: error).contains("record_norito_base64"))
            }
        }

        let legacyDetail = try JSONDecoder().decode(
            ToriiVerifyingKeyDetail.self,
            from: payload(recordBase64: nil)
        )
        XCTAssertNil(legacyDetail.recordNorito)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListVerifyingKeysAsync() async throws {
        let payload = """
        [
          { "backend": "pipa-r/pasta", "name": "vk_ids_only" },
          {
            "id": { "backend": "pipa-r/pasta", "name": "vk_full" },
            "record": {
              "version": 5,
              "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
              "backend": "pipa-r/pasta",
              "curve": "pallas",
              "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "vk_len": 32,
              "max_proof_bytes": 4096,
              "gas_schedule_id": "native_pipa_r_default",
              "status": "Active"
            }
          }
        ]
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/zk/vk")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            let items = components?.queryItems ?? []
            let dictionary = Dictionary(uniqueKeysWithValues: items.compactMap { item in
                item.value.map { (item.name, $0) }
            })
            XCTAssertEqual(dictionary["backend"], "pipa-r/pasta")
            XCTAssertEqual(dictionary["status"], "Active")
            XCTAssertEqual(dictionary["name_contains"], "vk")
            XCTAssertEqual(dictionary["limit"], "2")
            XCTAssertEqual(dictionary["offset"], "1")
            XCTAssertEqual(dictionary["order"], "asc")
            XCTAssertEqual(dictionary["ids_only"], "true")

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, payload)
        }

        let query = ToriiVerifyingKeyListQuery(
            backend: "pipa-r/pasta",
            status: .active,
            nameContains: "vk",
            limit: 2,
            offset: 1,
            order: .ascending,
            idsOnly: true
        )
        let keys = try await makeClient().listVerifyingKeys(query: query)
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys[0].id.name, "vk_ids_only")
        XCTAssertNil(keys[0].record)
        XCTAssertEqual(keys[1].record?.version, 5)
        XCTAssertEqual(keys[1].record?.status, .active)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testListVerifyingKeysDecodesCanonicalArrayAndRejectsObjectEnvelope() async throws {
        let payload = """
        [
            {
              "id": { "backend": "pipa-r/pasta", "name": "vk_record" },
              "record": {
                "version": 1,
                "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
                "backend": "pipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "commitment": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "vk_len": 64,
                "max_proof_bytes": 2048,
                "gas_schedule_id": "native_pipa_r_default",
                "status": "Active"
              }
            }
        ]
        """.data(using: .utf8)!

        var responseBody = payload
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, responseBody)
        }

        let keys = try await makeClient().listVerifyingKeys()
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].id.name, "vk_record")
        XCTAssertEqual(keys[0].record?.verifyingKeyLength, 64)

        responseBody = Data("{\"items\":\(String(decoding: payload, as: UTF8.self))}".utf8)
        await XCTAssertThrowsErrorAsync(try await makeClient().listVerifyingKeys()) { error in
            guard case let ToriiClientError.decoding(underlying) = error,
                  case DecodingError.typeMismatch = underlying else {
                return XCTFail("Expected the canonical array shape error, got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyingKeyReadPathsRejectUnsupportedProductionBackendsBeforeRequest() async {
        var requests = 0
        StubURLProtocol.handler = { request in
            requests += 1
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data("[]".utf8))
        }

        for backend in [
            "halo2/ipa",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "halo2\u{FF0F}ipa",
            "halo2/\u{200B}ipa",
            "h\u{0430}lo2/ipa",
            "stark/fri/miden",
            " stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
            "halo2/ipa/orchard",
            "halo2/kzg",
            "halo2/ipa\0",
            "mock/dev"
        ] {
            await XCTAssertThrowsErrorAsync(
                try await makeClient().getVerifyingKey(backend: backend, name: "vk_main")
            ) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload, got \(error)")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }
            await XCTAssertThrowsErrorAsync(
                try await makeClient().listVerifyingKeys(query: ToriiVerifyingKeyListQuery(backend: backend))
            ) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload, got \(error)")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }
            XCTAssertThrowsError(try ToriiVerifyingKeyListQuery(backend: backend).queryItems()) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload, got \(error)")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }
        }
        XCTAssertEqual(requests, 0)
    }

    func testVerifyingKeyListDecodingRejectsNonCanonicalResponseBackends() {
        let record = """
        {
          "version": 1,
          "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
          "backend": "pipa-r/pasta",
          "curve": "pallas",
          "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "vk_len": 32,
          "max_proof_bytes": 4096,
          "status": "Active"
        }
        """
        let payloads = [
            #"[{ "backend": "halo2/ipa", "name": "retired_backend_vk" }]"#,
            #"[{ "backend": " pipa-r/pasta", "name": "flat_vk" }]"#,
            #"[{ "id": { "backend": "pipa-r/pasta ", "name": "object_vk" } }]"#,
            #"[{ "backend": "halo2\uFF0Fipa", "name": "fullwidth_slash_vk" }]"#,
            #"[{ "id": { "backend": "h\u0430lo2/ipa", "name": "cyrillic_a_vk" } }]"#,
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": "record_vk" },
              "record": {
                "version": 1,
                "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
                "backend": "\\tpipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "vk_len": 32,
                "max_proof_bytes": 4096,
                "status": "Active"
              }
            }]
            """,
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": "inline_vk" },
              "record": \(record.dropLast()) ,
                "key": { "backend": "pipa-r/pasta\\n", "bytes_b64": "AQID" }
              }
            }]
            """,
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": "zero_width_vk" },
              "record": \(record.dropLast()) ,
                "key": { "backend": "halo2/\\u200Bipa", "bytes_b64": "AQID" }
              }
            }]
            """
        ]
        let canonicalDiagnostics = [
            "backend is not an exact supported verifier-registry label:",
            "backend must not contain surrounding whitespace"
        ]
        for payload in payloads {
            let data = payload.data(using: .utf8)!
            XCTAssertThrowsError(try JSONDecoder().decode([ToriiVerifyingKeyListItem].self, from: data)) { error in
                let description = String(describing: error)
                XCTAssertEqual(
                    canonicalDiagnostics.filter { description.contains($0) }.count,
                    1,
                    description
                )
            }
        }
    }

    func testVerifyingKeyListDecodingRejectsPaddedSelectorMetadata() {
        let payloads = [
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": " vk_main" },
              "record": {
                "version": 1,
                "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
                "backend": "pipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "vk_len": 32,
                "max_proof_bytes": 4096,
                "gas_schedule_id": "native_pipa_r_default",
                "status": "Active"
              }
            }]
            """,
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": "vk_main" },
              "record": {
                "version": 1,
                "circuit_id": " pipa-r/pasta/confidential-transfer-v1",
                "backend": "pipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "vk_len": 32,
                "max_proof_bytes": 4096,
                "gas_schedule_id": "native_pipa_r_default",
                "status": "Active"
              }
            }]
            """,
            """
            [{
              "id": { "backend": "pipa-r/pasta", "name": "vk_main" },
              "record": {
                "version": 1,
                "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
                "backend": "pipa-r/pasta",
                "curve": "pallas",
                "public_inputs_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "commitment": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "vk_len": 32,
                "max_proof_bytes": 4096,
                "gas_schedule_id": "halo2_default ",
                "status": "Active"
              }
            }]
            """
        ]

        for payload in payloads {
            let data = payload.data(using: .utf8)!
            XCTAssertThrowsError(try JSONDecoder().decode([ToriiVerifyingKeyListItem].self, from: data)) { error in
                XCTAssertTrue(String(describing: error).contains("surrounding whitespace"))
            }
        }
    }

    func testVerifyingKeyDetailDecodingRejectsWithdrawHeightBeforeActivationHeight() {
        let payload = """
        {
          "id": { "backend": "pipa-r/pasta", "name": "vk_main" },
          "record": {
            "version": 2,
            "circuit_id": "pipa-r/pasta/confidential-transfer-v1",
            "backend": "pipa-r/pasta",
            "curve": "pallas",
            "public_inputs_schema_hash": "fae4cbe786f280b4e2184dbb06305fe46b7aee20464c0be96023ffd8eac064d3",
            "commitment": "20574662a58708e02e0000000000000000000000000000000000000000000000",
            "vk_len": 96,
            "max_proof_bytes": 8192,
            "gas_schedule_id": "native_pipa_r_default",
            "activation_height": 10,
            "withdraw_height": 9,
            "status": "Active"
          }
        }
        """.data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiVerifyingKeyDetail.self, from: payload)) { error in
            XCTAssertTrue(String(describing: error).contains("withdraw_height"))
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterVerifyingKeyReturnsUnsignedTransactionDraft() async throws {
        let requestBody = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02, 0x03])
        )
        var didSendRequest = false
        StubURLProtocol.handler = { request in
            didSendRequest = true
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/zk/vk/register")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["authority"] as? String, requestBody.authority)
            XCTAssertNil(body["private_key"])
            XCTAssertEqual(body["backend"] as? String, "pipa-r/pasta")
            XCTAssertEqual(body["name"] as? String, "vk_main")
            XCTAssertEqual(body["vk_bytes"] as? String, "AQID")
            XCTAssertEqual(body["vk_len"] as? Int, 3)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, self.verifyingKeyDraftResponse())
        }
        let draft = try await makeClient().registerVerifyingKey(requestBody)
        XCTAssertFalse(draft.submitted)
        XCTAssertEqual(draft.transactionPayload, canonicalVerifyingKeyTransactionPayload())
        XCTAssertEqual(draft.signingMessage, IrohaHash.hash(draft.transactionPayload))
        XCTAssertTrue(didSendRequest)
    }

    func testRegisterVerifyingKeyRejectsInvalidSchemaHash() {
        let requestBody = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: "abc",
            gasScheduleId: "native_pipa_r_default"
        )
        XCTAssertThrowsError(try JSONEncoder().encode(requestBody)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyingKeyTransactionDraftRejectsMalformedOrRetiredFields() async throws {
        let request = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "e", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02, 0x03])
        )
        let payload = canonicalVerifyingKeyTransactionPayload()
        let payloadB64 = payload.base64EncodedString()
        let signingB64 = IrohaHash.hash(payload).base64EncodedString()
        let cases: [(String, [String: Any])] = [
            (
                "submitted transaction",
                [
                    "submitted": true,
                    "transaction_payload_b64": payloadB64,
                    "signing_message_b64": signingB64,
                ]
            ),
            (
                "retired private key",
                [
                    "submitted": false,
                    "transaction_payload_b64": payloadB64,
                    "signing_message_b64": signingB64,
                    "private_key": "ed25519:must-not-be-accepted",
                ]
            ),
            (
                "missing signing message",
                [
                    "submitted": false,
                    "transaction_payload_b64": payloadB64,
                ]
            ),
            (
                "noncanonical payload base64",
                [
                    "submitted": false,
                    "transaction_payload_b64": "AQI",
                    "signing_message_b64": signingB64,
                ]
            ),
            (
                "noncanonical transaction payload",
                [
                    "submitted": false,
                    "transaction_payload_b64": Data([0x01, 0x02, 0x03]).base64EncodedString(),
                    "signing_message_b64": IrohaHash.hash(Data([0x01, 0x02, 0x03])).base64EncodedString(),
                ]
            ),
            (
                "wrong-size signing message",
                [
                    "submitted": false,
                    "transaction_payload_b64": payloadB64,
                    "signing_message_b64": Data(repeating: 0x01, count: 31).base64EncodedString(),
                ]
            ),
            (
                "mismatched signing message",
                [
                    "submitted": false,
                    "transaction_payload_b64": payloadB64,
                    "signing_message_b64": Data(repeating: 0x02, count: 32).base64EncodedString(),
                ]
            ),
        ]

        for (label, object) in cases {
            let data = try JSONSerialization.data(withJSONObject: object)
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, data)
            }
            await XCTAssertThrowsErrorAsync(
                try await makeClient().registerVerifyingKey(request),
                label
            ) { _ in }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyingKeyDraftRequiresImmutableLocalSigningContextBeforeDispatch() async {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: session
        )
        let request = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "e", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02, 0x03])
        )
        var didDispatch = false
        StubURLProtocol.handler = { request in
            didDispatch = true
            return (
                HTTPURLResponse(url: request.url!, statusCode: 500,
                                httpVersion: nil, headerFields: nil)!,
                Data()
            )
        }

        await XCTAssertThrowsErrorAsync(
            try await client.registerVerifyingKey(request)
        ) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error, got \(error)")
            }
            XCTAssertTrue(reason.contains("ToriiLocalSigningContext"))
        }
        XCTAssertFalse(didDispatch)
    }

    func testLocalSigningContextPinsNominalNetworkId() {
        let context = ToriiLocalSigningContext(networkId: TestNetworkIds.canonical)

        XCTAssertEqual(context.networkId, TestNetworkIds.canonical)
        XCTAssertEqual(context.networkId.bytes, TestNetworkIds.canonical.bytes)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterVerifyingKeyRejectsSemanticallySubstitutedDrafts() async throws {
        let request = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "e", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02, 0x03])
        )
        let cases: [(label: String, payload: Data, expectedReason: String)] = [
            (
                "wrong operation",
                canonicalVerifyingKeyTransactionPayload(
                    wireName: "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey"
                ),
                "requested registry operation"
            ),
            (
                "wrong identifier",
                canonicalVerifyingKeyTransactionPayload(name: "vk_substituted"),
                "identifier does not match"
            ),
            (
                "wrong full record",
                canonicalVerifyingKeyTransactionPayload(recordVersion: 2),
                "full requested record"
            ),
            (
                "wrong network",
                canonicalVerifyingKeyTransactionPayload(networkId: TestNetworkIds.other),
                "configured network"
            ),
            (
                "wrong authority",
                canonicalVerifyingKeyTransactionPayload(
                    authority: "sorauﾛ1NfｺｷﾘcﾙｦEﾑgsKti4Zﾘ6HKｳZCﾅｸｼ16fvSｲymｶｻﾘﾎ29JNWE"
                ),
                "requested authority"
            ),
        ]

        for item in cases {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (
                    response,
                    self.verifyingKeyDraftResponse(payload: item.payload)
                )
            }
            await XCTAssertThrowsErrorAsync(
                try await makeClient().registerVerifyingKey(request),
                item.label
            ) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error, got \(error)")
                }
                XCTAssertTrue(reason.contains(item.expectedReason), "\(item.label): \(reason)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterVerifyingKeyRejectsGenesisUnknownLegacyAndUnmarkedTransactionDomains() async throws {
        let request = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "e", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02, 0x03])
        )
        func domain(kind: UInt32, value: Data? = nil, trailing: Data = Data()) -> Data {
            var writer = CompactNoritoWriter()
            writer.writeUInt32LE(kind)
            if let value {
                writer.writeField(value)
            }
            writer.writeBytes(trailing)
            return writer.data
        }
        var unmarked = TestNetworkIds.canonical.bytes
        unmarked[unmarked.index(before: unmarked.endIndex)] &= 0xfe
        var legacyChain = CompactNoritoWriter()
        legacyChain.writeField(CompactNorito.encodeString("test-chain"))
        let cases: [(label: String, domain: Data, expectedReason: String)] = [
            ("genesis", domain(kind: 1), "TransactionDomain::Network"),
            ("unknown", domain(kind: 2), "TransactionDomain::Network"),
            ("legacy chain", legacyChain.data, "TransactionDomain::Network"),
            ("unmarked network", domain(kind: 0, value: unmarked), "invalid canonical NetworkId"),
            (
                "trailing network data",
                domain(kind: 0, value: TestNetworkIds.canonical.bytes, trailing: Data([0])),
                "exactly one NetworkId"
            ),
        ]

        for item in cases {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (
                    response,
                    self.verifyingKeyDraftResponse(
                        payload: self.canonicalVerifyingKeyTransactionPayload(
                            domainOverride: item.domain
                        )
                    )
                )
            }
            await XCTAssertThrowsErrorAsync(
                try await makeClient().registerVerifyingKey(request),
                item.label
            ) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error, got \(error)")
                }
                XCTAssertTrue(reason.contains(item.expectedReason), "\(item.label): \(reason)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteSendsOnlyCanonicalNetworkTransactionDomain() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/fees/quote")
            let body = self.bodyJSON(from: request)
            let payload = body["payload"] as? [String: Any]
            let domain = payload?["domain"] as? [String: Any]
            XCTAssertEqual(domain?["kind"] as? String, "network")
            XCTAssertEqual(
                domain?["value"] as? String,
                TestNetworkIds.canonical.literal
            )
            XCTAssertEqual(Set(domain?.keys.map { $0 } ?? []), Set(["kind", "value"]))
            XCTAssertNil(payload?["chain"])
            XCTAssertNil(payload?["chainId"])
            XCTAssertNil(payload?["chain_id"])
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let responseBody = Data(
                """
                {
                  "intent":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
                  "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
                  "components":[],
                  "capacities":[],
                  "decision":{
                    "status":"accepted",
                    "value":{"debit_source":{"kind":"account","value":"\(self.authority)"},"program_revision":null}
                  }
                }
                """.utf8
            )
            return (response, responseBody)
        }

        let quote = try await makeClient().quoteFees(
            unsignedPayload: try canonicalUnsignedFeePayload(),
            canonicalAuth: canonicalReadAuth
        )

        XCTAssertEqual(quote.observation.nextBlockHeight, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteAllowsActiveAliasCanonicalAuthentication() async throws {
        let alias = "alice@paynet"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-Iroha-Account"), alias)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (
                response,
                Data(
                    """
                    {
                      "intent":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
                      "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
                      "components":[],
                      "capacities":[],
                      "decision":{"status":"accepted","value":{"debit_source":{"kind":"account","value":"\(self.authority)"},"program_revision":null}}
                    }
                    """.utf8
                )
            )
        }
        let aliasAuth = ToriiCanonicalRequestAuth(
            accountId: alias,
            privateKey: canonicalReadAuth.privateKey
        )

        let quote = try await makeClient().quoteFees(
            unsignedPayload: try canonicalUnsignedFeePayload(),
            canonicalAuth: aliasAuth
        )

        XCTAssertEqual(quote.intent, .authority(chargeLimits: [], gasLimit: nil))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteRejectsDuplicateResponseKeys() async throws {
        let duplicateResponses = [
            """
            {
              "intent":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
              "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
              "components":[],
              "capacities":[],
              "decision":{"status":"accepted","value":{"debit_source":{"kind":"account","value":"\(authority)"},"program_revision":null,"program_revision":null}}
            }
            """,
            """
            {
              "intent":{"payer":"authority","value":{"charge_limits":[{"kind":{"kind":"nexus","value":null},"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","max_amount":"1"}],"gas_limit":null}},
              "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
              "components":[{"kind":{"kind":"nexus","value":null},"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","max_amount":"1","max_amount":"1"}],
              "capacities":[],
              "decision":{"status":"accepted","value":{"debit_source":{"kind":"account","value":"\(authority)"},"program_revision":null}}
            }
            """,
            """
            {
              "intent":{"payer":"sponsor","value":{"program_id":{"sponsor":"\(authority)","name":"wallet_fx"},"program_revision":7,"charge_limits":[{"kind":{"kind":"nexus","value":null},"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","max_amount":"1"}],"gas_limit":null}},
              "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
              "components":[{"kind":{"kind":"nexus","value":null},"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","max_amount":"1"}],
              "capacities":[{"asset_definition_id":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","vault_balance":"1","reserve_floor":"0","block_remaining":"1","block_remaining":"1","program_epoch_remaining":"1","beneficiary_epoch_remaining":"1"}],
              "decision":{"status":"accepted","value":{"debit_source":{"kind":"sponsor_program","value":{"sponsor":"\(authority)","name":"wallet_fx"}},"program_revision":7}}
            }
            """,
        ]

        for duplicateResponse in duplicateResponses {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, Data(duplicateResponse.utf8))
            }

            await XCTAssertThrowsErrorAsync(
                try await makeClient().quoteFees(
                    unsignedPayload: try canonicalUnsignedFeePayload(),
                    canonicalAuth: canonicalReadAuth
                )
            ) { error in
                guard case let ToriiClientError.invalidPayload(message) = error else {
                    return XCTFail("Expected invalidPayload, got \(error)")
                }
                XCTAssertTrue(message.contains("duplicate object keys"))
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteResponseBodyLimitAppliesBeforeSuccessAndErrorHandling() async throws {
        let maximumBytes = 65_536
        let validQuote = Data(
            """
            {
              "intent":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
              "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
              "components":[],
              "capacities":[],
              "decision":{"status":"accepted","value":{"debit_source":{"kind":"account","value":"\(authority)"},"program_revision":null}}
            }
            """.utf8
        )
        XCTAssertLessThan(validQuote.count, maximumBytes)

        func body(padding validPrefix: Data, to count: Int) -> Data {
            var body = validPrefix
            body.append(Data(repeating: 0x20, count: count - body.count))
            return body
        }

        func install(status: Int, body: Data) {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: status,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, body)
            }
        }

        install(status: 200, body: body(padding: validQuote, to: maximumBytes))
        _ = try await makeClient().quoteFees(
            unsignedPayload: try canonicalUnsignedFeePayload(),
            canonicalAuth: canonicalReadAuth
        )

        install(status: 200, body: body(padding: validQuote, to: maximumBytes + 1))
        await assertToriiInvalidPayload(contains: "response exceeded") {
            _ = try await self.makeClient().quoteFees(
                unsignedPayload: try self.canonicalUnsignedFeePayload(),
                canonicalAuth: self.canonicalReadAuth
            )
        }

        install(status: 400, body: Data(repeating: 0x20, count: maximumBytes))
        do {
            _ = try await makeClient().quoteFees(
                unsignedPayload: try canonicalUnsignedFeePayload(),
                canonicalAuth: canonicalReadAuth
            )
            XCTFail("exact-limit error response must reach status handling")
        } catch let ToriiClientError.api(apiError) {
            let code = apiError.status
            XCTAssertEqual(code, 400)
        } catch {
            XCTFail("unexpected exact-limit error: \(error)")
        }

        install(status: 400, body: Data(repeating: 0x20, count: maximumBytes + 1))
        await assertToriiInvalidPayload(contains: "response exceeded") {
            _ = try await self.makeClient().quoteFees(
                unsignedPayload: try self.canonicalUnsignedFeePayload(),
                canonicalAuth: self.canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteRequiresJsonResponseMediaType() async throws {
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/plain"]
            )!
            return (
                response,
                Data(
                    """
                    {
                      "intent":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},
                      "observation":{"ledger_time_ms":1,"next_block_height":1,"route_dataspace_id":0},
                      "components":[],
                      "capacities":[],
                      "decision":{"status":"accepted","value":{"debit_source":{"kind":"account","value":"\(self.authority)"},"program_revision":null}}
                    }
                    """.utf8
                )
            )
        }

        await assertToriiInvalidPayload(contains: "response Content-Type") {
            _ = try await self.makeClient().quoteFees(
                unsignedPayload: try self.canonicalUnsignedFeePayload(),
                canonicalAuth: self.canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeSponsorProgramLookupPinsControllerIdentityAndExactName() async throws {
        let requested = try FeeSponsorProgramId(sponsor: authority, name: "wallet_fx")
        let alternateSponsor = try exactCanonicalToriiAccountAddress(authority)
            .address.toI105(networkPrefix: 369)

        func installResponse(name: String) {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (
                    response,
                    Data(
                        """
                        {
                          "id":{"sponsor":"\(alternateSponsor)","name":"\(name)"},
                          "payout_account":"\(self.authority)",
                          "lifecycle":{"state":"active","value":null}
                        }
                        """.utf8
                    )
                )
            }
        }

        installResponse(name: requested.name)
        let program = try await makeClient().getFeeSponsorProgram(
            id: requested,
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(program.id, requested)
        XCTAssertEqual(program.id.sponsor, alternateSponsor)

        installResponse(name: "other")
        await assertToriiInvalidPayload(contains: "does not match the requested program") {
            _ = try await self.makeClient().getFeeSponsorProgram(
                id: requested,
                canonicalAuth: self.canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeSponsorProgramLookupResponseBodyLimitAppliesBeforeStatusAndDecode() async throws {
        let requested = try FeeSponsorProgramId(sponsor: authority, name: "wallet_fx")
        let maximumBytes = 65_536
        let validProgram = Data(
            """
            {
              "id":{"sponsor":"\(authority)","name":"\(requested.name)"},
              "payout_account":"\(authority)",
              "lifecycle":{"state":"active","value":null}
            }
            """.utf8
        )
        XCTAssertLessThan(validProgram.count, maximumBytes)

        func body(padding validPrefix: Data, to count: Int) -> Data {
            var body = validPrefix
            body.append(Data(repeating: 0x20, count: count - body.count))
            return body
        }

        func install(status: Int, body: Data) {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: status,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, body)
            }
        }

        install(status: 200, body: body(padding: validProgram, to: maximumBytes))
        _ = try await makeClient().getFeeSponsorProgram(
            id: requested,
            canonicalAuth: canonicalReadAuth
        )

        install(status: 200, body: body(padding: validProgram, to: maximumBytes + 1))
        await assertToriiInvalidPayload(contains: "response exceeded") {
            _ = try await self.makeClient().getFeeSponsorProgram(
                id: requested,
                canonicalAuth: self.canonicalReadAuth
            )
        }

        install(status: 400, body: Data(repeating: 0x20, count: maximumBytes))
        do {
            _ = try await makeClient().getFeeSponsorProgram(
                id: requested,
                canonicalAuth: canonicalReadAuth
            )
            XCTFail("exact-limit error response must reach status handling")
        } catch let ToriiClientError.api(apiError) {
            let code = apiError.status
            XCTAssertEqual(code, 400)
        } catch {
            XCTFail("unexpected exact-limit error: \(error)")
        }

        install(status: 400, body: Data(repeating: 0x20, count: maximumBytes + 1))
        await assertToriiInvalidPayload(contains: "response exceeded") {
            _ = try await self.makeClient().getFeeSponsorProgram(
                id: requested,
                canonicalAuth: self.canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeSponsorProgramLookupRequiresOneJsonResponseMediaType() async throws {
        let requested = try FeeSponsorProgramId(sponsor: authority, name: "wallet_fx")
        let validProgram = Data(
            """
            {
              "id":{"sponsor":"\(authority)","name":"\(requested.name)"},
              "payout_account":"\(authority)",
              "lifecycle":{"state":"active","value":null}
            }
            """.utf8
        )
        let invalidContentTypes: [String?] = [
            nil,
            "text/plain",
            "application/json, application/json",
            "application/json, text/plain",
            "application/json; profile=\"a,b\"",
            "application/json;",
            "application/json; charset",
            "application/json; profile=\"unterminated",
            "application/jſon",
            "applıcation/json",
        ]

        for contentType in invalidContentTypes {
            StubURLProtocol.handler = { request in
                let headers = contentType.map { ["Content-Type": $0] } ?? [:]
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: headers
                )!
                return (response, validProgram)
            }

            await assertToriiInvalidPayload(contains: "response Content-Type") {
                _ = try await self.makeClient().getFeeSponsorProgram(
                    id: requested,
                    canonicalAuth: self.canonicalReadAuth
                )
            }
        }

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: [
                    "Content-Type": "Application/JSON; charset=\"utf-8\"; note=\"é\""
                ]
            )!
            return (response, validProgram)
        }
        let resolved = try await makeClient().getFeeSponsorProgram(
            id: requested,
            canonicalAuth: canonicalReadAuth
        )
        XCTAssertEqual(resolved.id, requested)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeSponsorProgramLookupRejectsDuplicateResponseKeys() async throws {
        let requested = try FeeSponsorProgramId(sponsor: authority, name: "wallet_fx")
        let duplicateProgram = Data(
            """
            {
              "id":{"sponsor":"\(authority)","name":"\(requested.name)","name":"\(requested.name)"},
              "payout_account":"\(authority)",
              "lifecycle":{"state":"active","value":null}
            }
            """.utf8
        )
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, duplicateProgram)
        }

        await assertToriiInvalidPayload(contains: "without duplicate object keys") {
            _ = try await self.makeClient().getFeeSponsorProgram(
                id: requested,
                canonicalAuth: self.canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testFeeQuoteRejectsRetiredIdentityAliasesAndNonNetworkDomainsBeforeDispatch() async throws {
        let invalidDomains: [(label: String, value: ToriiJSONValue)] = [
            ("genesis", .object(["kind": .string("genesis")])),
            ("unknown kind", .object([
                "kind": .string("unknown"),
                "value": .string(TestNetworkIds.canonical.literal),
            ])),
            ("unmarked alias", .object([
                "kind": .string("network"),
                "value": .string("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91148#A2F0"),
            ])),
            ("extra field", .object([
                "kind": .string("network"),
                "value": .string(TestNetworkIds.canonical.literal),
                "chain": .string("legacy"),
            ])),
        ]

        for item in invalidDomains {
            await assertToriiInvalidPayload(contains: "domain") {
                _ = try await makeClient().quoteFees(
                    unsignedPayload: try canonicalUnsignedFeePayload(domain: item.value),
                    canonicalAuth: canonicalReadAuth
                )
            }
        }
        for alias in ["chain", "chainId", "chain_id"] {
            var payload = try canonicalUnsignedFeePayload()
            payload[alias] = .string("legacy")
            await assertToriiInvalidPayload(contains: alias) {
                _ = try await makeClient().quoteFees(
                    unsignedPayload: payload,
                    canonicalAuth: canonicalReadAuth
                )
            }
        }
        var missingAttachments = try canonicalUnsignedFeePayload()
        missingAttachments.removeValue(forKey: "attachments")
        await assertToriiInvalidPayload(contains: "exact TransactionPayload field set") {
            _ = try await makeClient().quoteFees(
                unsignedPayload: missingAttachments,
                canonicalAuth: canonicalReadAuth
            )
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterVerifyingKeyRequiresHttp200AndUniqueResponseFields() async throws {
        let request = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01])
        )
        StubURLProtocol.handler = { urlRequest in
            let response = HTTPURLResponse(
                url: urlRequest.url!,
                statusCode: 202,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, self.verifyingKeyDraftResponse())
        }
        await XCTAssertThrowsErrorAsync(
            try await makeClient().registerVerifyingKey(request)
        ) { error in
            guard case let ToriiClientError.api(apiError) = error else {
                return XCTFail("Expected HTTP status error, got \(error)")
            }
            let code = apiError.status
            XCTAssertEqual(code, 202)
        }

        StubURLProtocol.handler = { urlRequest in
            let response = HTTPURLResponse(
                url: urlRequest.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let payload = self.canonicalVerifyingKeyTransactionPayload()
            let signing = IrohaHash.hash(payload)
            let duplicate = """
            {"submitted":false,"submitted":false,"transaction_payload_b64":"\(payload.base64EncodedString())","signing_message_b64":"\(signing.base64EncodedString())"}
            """
            return (response, Data(duplicate.utf8))
        }
        await XCTAssertThrowsErrorAsync(
            try await makeClient().registerVerifyingKey(request)
        ) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error, got \(error)")
            }
        }
    }

    func testRegisterVerifyingKeyRejectsPaddedSelectorMetadata() {
        let base = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02])
        )

        var paddedName = base
        paddedName.name = " vk_main"
        XCTAssertThrowsError(try JSONEncoder().encode(paddedName)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("name"))
            XCTAssertTrue(reason.contains("surrounding whitespace"))
        }

        var paddedCircuit = base
        paddedCircuit.circuitId = "pipa-r/pasta/confidential-transfer-v1 "
        XCTAssertThrowsError(try JSONEncoder().encode(paddedCircuit)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("circuit_id"))
            XCTAssertTrue(reason.contains("surrounding whitespace"))
        }

        var paddedGasSchedule = base
        paddedGasSchedule.gasScheduleId = " halo2_default"
        XCTAssertThrowsError(try JSONEncoder().encode(paddedGasSchedule)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("gas_schedule_id"))
            XCTAssertTrue(reason.contains("surrounding whitespace"))
        }

        XCTAssertThrowsError(try ToriiVerifyingKeyId(backend: "pipa-r/pasta", name: "vk_main ")) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("name"))
            XCTAssertTrue(reason.contains("surrounding whitespace"))
        }
    }

    func testRegisterVerifyingKeyRejectsVkLengthMismatch() {
        var requestBody = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: Data([0x01, 0x02])
        )
        requestBody.verifyingKeyLength = 3
        XCTAssertThrowsError(try JSONEncoder().encode(requestBody)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    func testRegisterVerifyingKeyRejectsLengthOnlyVerifierMaterial() {
        var requestBody = ToriiVerifyingKeyRegisterRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default"
        )
        requestBody.verifyingKeyLength = 3
        XCTAssertThrowsError(try JSONEncoder().encode(requestBody)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("commitment_hex"))
        }
    }

    func testVerifyingKeyRequestsRejectMismatchedInlineCommitment() {
        let bytes = Data([0x01, 0x02, 0x03])
        var registerRequest = ToriiVerifyingKeyRegisterRequest(
            authority: "alice",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: bytes
        )
        registerRequest.commitmentHex = String(repeating: "0", count: 64)
        XCTAssertThrowsError(try JSONEncoder().encode(registerRequest)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("commitment_hex must match domain-separated SHA-256"))
        }

        var updateRequest = ToriiVerifyingKeyUpdateRequest(
            authority: "alice",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 2,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "b", count: 64)
        )
        updateRequest.verifyingKeyBytes = bytes
        updateRequest.commitmentHex = matchingVerifyingKeyCommitmentHex(
            backend: "pipa-r/pasta",
            bytes: bytes
        )
        XCTAssertNoThrow(try JSONEncoder().encode(updateRequest))
    }

    func testVerifyingKeyRequestsRejectWithdrawHeightBeforeActivationHeight() {
        let bytes = Data([0x01, 0x02, 0x03])
        var registerRequest = ToriiVerifyingKeyRegisterRequest(
            authority: "alice",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 1,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "native_pipa_r_default",
            verifyingKeyBytes: bytes
        )
        registerRequest.activationHeight = 10
        registerRequest.withdrawHeight = 9
        XCTAssertThrowsError(try JSONEncoder().encode(registerRequest)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("withdraw_height"))
        }

        var updateRequest = ToriiVerifyingKeyUpdateRequest(
            authority: "alice",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 2,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "b", count: 64)
        )
        updateRequest.verifyingKeyBytes = bytes
        updateRequest.activationHeight = 10
        updateRequest.withdrawHeight = 9
        XCTAssertThrowsError(try JSONEncoder().encode(updateRequest)) { error in
            guard case let ToriiClientError.invalidPayload(reason) = error else {
                return XCTFail("Expected invalidPayload error")
            }
            XCTAssertTrue(reason.contains("withdraw_height"))
        }
    }

    func testVerifyingKeyRequestsRejectUnsupportedProductionBackendsBeforeEncoding() {
        let unsupported = [
            "halo2/unknown-native-v1",
            "halo2/ipa:unknown-native-v1",
            "stark/unknown-native-v1",
            "halo2/ipa",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "halo2\u{FF0F}ipa",
            "halo2/\u{200B}ipa",
            "h\u{0430}lo2/ipa",
            "stark/fri/miden",
            " stark/fri/poseidon-x7-goldilocks-6x64-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
            "halo2/ipa/orchard",
            "halo2/kzg",
            "halo2/ipa\0",
            "mock/dev"
        ]

        for backend in unsupported {
            let registerRequest = ToriiVerifyingKeyRegisterRequest(
                authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                backend: backend,
                name: "vk_main",
                version: 1,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "a", count: 64),
                gasScheduleId: "native_pipa_r_default"
            )
            XCTAssertThrowsError(try JSONEncoder().encode(registerRequest), backend) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }

            let updateRequest = ToriiVerifyingKeyUpdateRequest(
                authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                backend: backend,
                name: "vk_main",
                version: 2,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "b", count: 64)
            )
            XCTAssertThrowsError(try JSONEncoder().encode(updateRequest), backend) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }
        }
    }

    func testVerifyingKeyRequestsRejectBlankNamesBeforeEncoding() {
        let blankNames = ["", "   ", "\t", "\n"]

        for name in blankNames {
            let registerRequest = ToriiVerifyingKeyRegisterRequest(
                authority: "alice",
                backend: "pipa-r/pasta",
                name: name,
                version: 1,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "a", count: 64),
                gasScheduleId: "native_pipa_r_default"
            )
            XCTAssertThrowsError(try JSONEncoder().encode(registerRequest),
                                 "register must reject blank VK name \(String(reflecting: name))") { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertTrue(reason.contains("name must be a non-empty string"))
            }

            let updateRequest = ToriiVerifyingKeyUpdateRequest(
                authority: "alice",
                backend: "pipa-r/pasta",
                name: name,
                version: 2,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "b", count: 64)
            )
            XCTAssertThrowsError(try JSONEncoder().encode(updateRequest),
                                 "update must reject blank VK name \(String(reflecting: name))") { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertTrue(reason.contains("name must be a non-empty string"))
            }
        }
    }

    func testVerifyingKeyRequestsRejectBlankAuthorityBeforeEncoding() {
        let blankValues = ["", "   ", "\t", "\n"]

        for blank in blankValues {
            let registerWithBlankAuthority = ToriiVerifyingKeyRegisterRequest(
                authority: blank,
                backend: "pipa-r/pasta",
                name: "vk_main",
                version: 1,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "a", count: 64),
                gasScheduleId: "native_pipa_r_default"
            )
            XCTAssertThrowsError(try JSONEncoder().encode(registerWithBlankAuthority),
                                 "register must reject blank authority \(String(reflecting: blank))") { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertTrue(reason.contains("authority must be a non-empty string"))
            }

            let updateWithBlankAuthority = ToriiVerifyingKeyUpdateRequest(
                authority: blank,
                backend: "pipa-r/pasta",
                name: "vk_main",
                version: 2,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                publicInputsSchemaHashHex: String(repeating: "b", count: 64)
            )
            XCTAssertThrowsError(try JSONEncoder().encode(updateWithBlankAuthority),
                                 "update must reject blank authority \(String(reflecting: blank))") { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertTrue(reason.contains("authority must be a non-empty string"))
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testUpdateVerifyingKeyReturnsUnsignedTransactionDraft() async throws {
        var requestBody = ToriiVerifyingKeyUpdateRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 2,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        requestBody.verifyingKeyBytes = Data([0xAA])
        requestBody.commitmentHex = matchingVerifyingKeyCommitmentHex(
            backend: "pipa-r/pasta",
            bytes: Data([0xAA])
        )
        var didSendRequest = false
        StubURLProtocol.handler = { request in
            didSendRequest = true
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/zk/vk/update")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["authority"] as? String, requestBody.authority)
            XCTAssertNil(body["private_key"])
            XCTAssertEqual(body["backend"] as? String, "pipa-r/pasta")
            XCTAssertEqual(body["name"] as? String, "vk_main")
            XCTAssertEqual(body["commitment_hex"] as? String, requestBody.commitmentHex)
            XCTAssertEqual(body["vk_bytes"] as? String, "qg==")
            XCTAssertEqual(body["vk_len"] as? Int, 1)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let payload = self.canonicalVerifyingKeyTransactionPayload(
                wireName: "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
                version: 2,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                schemaHash: Data(repeating: 0xff, count: 32),
                gasScheduleId: nil,
                keyBytes: Data([0xAA])
            )
            return (response, self.verifyingKeyDraftResponse(payload: payload))
        }
        let draft = try await makeClient().updateVerifyingKey(requestBody)
        XCTAssertFalse(draft.submitted)
        XCTAssertEqual(
            draft.transactionPayload,
            canonicalVerifyingKeyTransactionPayload(
                wireName: "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
                version: 2,
                circuitId: "pipa-r/pasta/confidential-transfer-v1",
                schemaHash: Data(repeating: 0xff, count: 32),
                gasScheduleId: nil,
                keyBytes: Data([0xAA])
            )
        )
        XCTAssertEqual(draft.signingMessage, IrohaHash.hash(draft.transactionPayload))
        XCTAssertTrue(didSendRequest)
    }

    func testUpdateVerifyingKeyRejectsInvalidCommitmentHex() {
        var requestBody = ToriiVerifyingKeyUpdateRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            backend: "pipa-r/pasta",
            name: "vk_main",
            version: 2,
            circuitId: "pipa-r/pasta/confidential-transfer-v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64)
        )
        requestBody.commitmentHex = "deadbeef"
        XCTAssertThrowsError(try JSONEncoder().encode(requestBody)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGenericEventStreamsSignExactFinalQueriesWithDefaultCanonicalAuth() async throws {
        // Verifying-key events have no event-stream fields; they are recognised locally.
        expectCanonicalEventRequest(queryItems: [])
        var verifyingKeyIterator = makeClient()
            .streamVerifyingKeyEvents()
            .makeAsyncIterator()
        let verifyingKeyEvent = try await verifyingKeyIterator.next()
        XCTAssertNil(verifyingKeyEvent)

        // Trigger events have no event-stream fields; they are recognised locally.
        expectCanonicalEventRequest(queryItems: [])
        var triggerIterator = makeClient()
            .streamTriggerEvents()
            .makeAsyncIterator()
        let triggerEvent = try await triggerIterator.next()
        XCTAssertNil(triggerEvent)

        let proofFilter = ToriiProofEventFilter(
            backend: "pipa-r/pasta",
            proofHashHex: String(repeating: "a", count: 64),
            includeVerified: false,
            includeRejected: true
        )
        XCTAssertEqual(try proofFilter.serverFilter()?.description, #"proof_backend = "pipa-r/pasta""#)
        expectCanonicalEventRequest(
            queryItems: [URLQueryItem(name: "filter", value: #"proof_backend = "pipa-r/pasta""#)]
        )
        var proofIterator = makeClient()
            .streamProofEvents(filter: proofFilter)
            .makeAsyncIterator()
        let proofEvent = try await proofIterator.next()
        XCTAssertNil(proofEvent)

        expectCanonicalEventRequest(
            queryItems: [URLQueryItem(name: "filter", value: "tx_hash = \"\(Self.pipelineHash)\"")]
        )
        var statusIterator = makeClient()
            .streamTransactionStatusEvents(hashHex: Self.pipelineHash)
            .makeAsyncIterator()
        let statusEvent = try await statusIterator.next()
        XCTAssertNil(statusEvent)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGenericEventStreamRemainsAnonymousWithoutDefaultCanonicalAuth() async throws {
        let filter = ToriiProofEventFilter(
            backend: "pipa-r/pasta",
            proofHashHex: String(repeating: "b", count: 64),
            includeVerified: true,
            includeRejected: false
        )
        let queryItems = [URLQueryItem(name: "filter", value: try XCTUnwrap(filter.serverFilter()).description)]
        var expectedComponents = try XCTUnwrap(
            URLComponents(string: "https://example.test/v1/events/sse")
        )
        expectedComponents.queryItems = queryItems
        let expectedURL = try XCTUnwrap(expectedComponents.url)

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url, expectedURL)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            for header in [
                ToriiCanonicalRequest.headerAccount,
                ToriiCanonicalRequest.headerSignature,
                ToriiCanonicalRequest.headerTimestampMs,
                ToriiCanonicalRequest.headerNonce,
            ] {
                XCTAssertNil(request.value(forHTTPHeaderField: header))
            }
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, Data())
        }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: URLSession(configuration: configuration)
        )
        var iterator = client.streamProofEvents(filter: filter).makeAsyncIterator()
        let event = try await iterator.next()
        XCTAssertNil(event)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamVerifyingKeyEventsAsync() async throws {
        let ssePayload = """
id: 15
event: message
data: {"category":"Data","event":"VerifyingKey","summary":"VerifyingKey(Registered(..))"}

id: 16
data: {"category":"Data","event":"Asset","summary":"Asset(Added(..))"}

id: 17
data: {"category":"Other","event":"Time","summary":"Time(..)"}

id: 18
data: {"category":"Data","event":"VerifyingKey"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamVerifyingKeyEvents().makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.eventId, "15")
        XCTAssertEqual(first?.eventName, "message")
        XCTAssertEqual(
            first?.event,
            ToriiEventNotice(category: "Data", event: "VerifyingKey", summary: "VerifyingKey(Registered(..))")
        )
        XCTAssertEqual(first?.rawEvent.contains("Registered"), true)

        let second = try await iterator.next()
        XCTAssertEqual(second?.eventId, "18")
        XCTAssertEqual(second?.event.event, "VerifyingKey")
        XCTAssertNil(second?.event.summary)

        let third = try await iterator.next()
        XCTAssertNil(third)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamVerifyingKeyEventsDoesNotEmitLastEventIdHeader() async throws {
        let ssePayload = """
id: 21
data: {"category":"Data","event":"VerifyingKey","summary":"VerifyingKey(Registered(..))"}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamVerifyingKeyEvents().makeAsyncIterator()
        let event = try await iterator.next()
        XCTAssertEqual(event?.event.event, "VerifyingKey")
        let finished = try await iterator.next()
        XCTAssertNil(finished)
        XCTAssertNil(lastEventIdHeader)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamExplorerTransactionsAsync() async throws {
        let ssePayload = """
id: 1
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","hash":"hash1","block":100,"created_at":"2025-01-01T00:00:00Z","executable":"Instructions","status":"Committed"}

data: {"authority":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D","hash":"hash2","block":101,"created_at":"2025-01-02T00:00:00Z","executable":"Instructions","status":"Rejected"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
                canonicalRequestAccountHeaderValue(self.authority)
            )
            XCTAssertNotNil(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            )
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        let stream = makeClient().streamExplorerTransactions()
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.authority, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(first?.hash, "hash1")
        XCTAssertEqual(first?.block, 100)
        XCTAssertEqual(first?.status, "Committed")

        let second = try await iterator.next()
        XCTAssertEqual(second?.authority, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        XCTAssertEqual(second?.hash, "hash2")
        XCTAssertEqual(second?.block, 101)
        XCTAssertEqual(second?.status, "Rejected")

        let third = try await iterator.next()
        XCTAssertNil(third)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamExplorerInstructionsAsync() async throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        let stream = makeClient().streamExplorerInstructions()
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.authority, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(first?.kind, "Transfer")
        XCTAssertEqual(first?.transactionHash, "hash1")
        XCTAssertEqual(first?.transactionStatus, "Committed")
        XCTAssertEqual(first?.block, 10)
        XCTAssertEqual(first?.index, 0)
        XCTAssertEqual(first?.box.encoded, "0x00")
        XCTAssertEqual(first?.box.framedSha256, "0x" + String(repeating: "a", count: 64))
        XCTAssertNil(first?.box.scale)

        let second = try await iterator.next()
        XCTAssertNil(second)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamExplorerTransfersAsync() async throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"6","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":2}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Mint","box":{"encoded":"0x01","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Mint","payload":{"variant":"Asset","value":{"destination":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","object":"1"}}}},"transaction_hash":"hash2","transaction_status":"Committed","block":10,"index":1}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        let stream = makeClient().streamExplorerTransfers(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                          assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.instruction.transactionHash, "hash1")
        switch first?.details {
        case .asset(let asset):
            XCTAssertEqual(asset.senderAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(asset.destinationAccountId, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
            XCTAssertEqual(asset.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
            XCTAssertEqual(asset.amount, "5")
        default:
            XCTFail("Expected asset transfer details")
        }

        let second = try await iterator.next()
        XCTAssertNil(second)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamExplorerTransferSummariesAsync() async throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"6","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":1}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        let stream = makeClient().streamExplorerTransferSummaries(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                                  assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        var iterator = stream.makeAsyncIterator()

        let summary = try await iterator.next()
        XCTAssertEqual(summary?.transactionHash, "hash1")
        XCTAssertEqual(summary?.senderAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
        XCTAssertEqual(summary?.receiverAccountId, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        XCTAssertEqual(summary?.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
        XCTAssertEqual(summary?.amount, "5")
        XCTAssertEqual(summary?.direction, .incoming)

        let second = try await iterator.next()
        XCTAssertNil(second)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamAccountTransferHistoryCombinesHistoryAndStream() async throws {
        let historyPayload = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "5",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "hash1",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 0
                },
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "6",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "hash3",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 1
                }
            ]
        }
        """
            .data(using: .utf8)!

        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"7","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash2","transaction_status":"Committed","block":11,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"8","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash4","transaction_status":"Committed","block":11,"index":1}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            guard let url = request.url else {
                throw ToriiClientError.invalidResponse
            }
            if url.path == "/v1/explorer/instructions/query" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
                let queryData = try XCTUnwrap(toriiClientTestBodyData(from: request))
                let query = try XCTUnwrap(try JSONSerialization.jsonObject(with: queryData) as? [String: Any])
                XCTAssertEqual(Set(query.keys), Set(["filter", "limit"]))
                XCTAssertNil(query["cursor"])
                XCTAssertEqual(query["limit"] as? Int, 2)
                XCTAssertNil(query["page"])
                XCTAssertNil(query["per_page"])
                let expectedFilter = (ToriiField("kind") == "Transfer")
                    .and(ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
                    .and(ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
                let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(query["filter"]))
                XCTAssertEqual(try ToriiFilter(jsonData: filterData), expectedFilter)
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, historyPayload)
            }
            if url.path == "/v1/explorer/instructions/stream" {
                lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/event-stream"])!
                return (response, ssePayload)
            }
            throw ToriiClientError.invalidResponse
        }

        let stream = makeClient().streamAccountTransferHistory(accountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                               limit: 2,
                                                               assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                               lastEventId: "5")
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.transactionHash, "hash1")

        let second = try await iterator.next()
        XCTAssertEqual(second?.transactionHash, "hash2")

        let third = try await iterator.next()
        XCTAssertNil(third)
        XCTAssertEqual(lastEventIdHeader, "5")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamAccountTransferHistoryPreservesBatchDuplicates() async throws {
        let historyPayload = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "AssetBatch",
                                "value": {
                                    "entries": [
                                        {
                                            "from": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                            "to": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                            "asset_definition": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                            "amount": "5"
                                        },
                                        {
                                            "from": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                            "to": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                            "asset_definition": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                            "amount": "5"
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "transaction_hash": "hash1",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 0
                }
            ]
        }
        """
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            guard let url = request.url else {
                throw ToriiClientError.invalidResponse
            }
            if url.path == "/v1/explorer/instructions/query" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
                let queryData = try XCTUnwrap(toriiClientTestBodyData(from: request))
                let query = try XCTUnwrap(try JSONSerialization.jsonObject(with: queryData) as? [String: Any])
                XCTAssertEqual(Set(query.keys), Set(["filter", "limit"]))
                XCTAssertNil(query["cursor"])
                XCTAssertEqual(query["limit"] as? Int, 1)
                let expectedFilter = (ToriiField("kind") == "Transfer")
                    .and(ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
                let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(query["filter"]))
                XCTAssertEqual(try ToriiFilter(jsonData: filterData), expectedFilter)
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, historyPayload)
            }
            throw ToriiClientError.invalidResponse
        }

        let stream = makeClient().streamAccountTransferHistory(accountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                               limit: 1,
                                                               maxItems: 2)
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        let second = try await iterator.next()
        let third = try await iterator.next()

        XCTAssertEqual(first?.transactionHash, "hash1")
        XCTAssertEqual(first?.transferIndex, 0)
        XCTAssertEqual(second?.transactionHash, "hash1")
        XCTAssertEqual(second?.transferIndex, 1)
        XCTAssertNil(third)
    }

#if canImport(Combine)

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyingKeyEventsPublisherBridgesSseStream() throws {
        let ssePayload = """
id: 15
event: message
data: {"category":"Data","event":"VerifyingKey","summary":"VerifyingKey(Registered(..))"}

id: 16
data: {"category":"Data","event":"Trigger","summary":"Trigger(Created(..))"}

id: 17
data: {"category":"Data","event":"VerifyingKey","summary":"VerifyingKey(Updated(..))"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            XCTAssertNil(request.value(forHTTPHeaderField: "Last-Event-ID"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received events")
        valueExpectation.expectedFulfillmentCount = 2
        let completionExpectation = expectation(description: "publisher completed")

        var events: [ToriiEventMessage<ToriiEventNotice>] = []
        client.verifyingKeyEventsPublisher(scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { message in
                events.append(message)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)

        XCTAssertEqual(events.map(\.eventId), ["15", "17"])
        XCTAssertEqual(events.map(\.event.summary), ["VerifyingKey(Registered(..))", "VerifyingKey(Updated(..))"])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testVerifyingKeyEventsPublisherPreservesTypedTerminalStreamError() throws {
        let ssePayload = """
event: stream_error
data: {"code":"stream_lagged","message":"The stream lost buffered events.","dropped_messages":3,"replay_available":false}

""".data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertNil(request.value(forHTTPHeaderField: "Last-Event-ID"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let completionExpectation = expectation(description: "publisher surfaced terminal error")
        var cancellables: Set<AnyCancellable> = []
        makeClient().verifyingKeyEventsPublisher(scheduler: nil)
            .sink { completion in
                switch completion {
                case .finished:
                    XCTFail("Expected terminal stream error")
                case .failure(let clientError):
                    guard case let .stream(error) = clientError else {
                        XCTFail("Expected ToriiClientError.stream, got \(clientError)")
                        completionExpectation.fulfill()
                        return
                    }
                    XCTAssertEqual(error.code, "stream_lagged")
                    XCTAssertEqual(error.droppedMessages, 3)
                    XCTAssertFalse(error.replayAvailable)
                }
                completionExpectation.fulfill()
            } receiveValue: { _ in
                XCTFail("Terminal stream error must not yield a verifying-key event")
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExplorerTransactionsPublisherDeliversItems() throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","hash":"hash1","block":100,"created_at":"2025-01-01T00:00:00Z","executable":"Instructions","status":"Committed"}

data: {"authority":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D","hash":"hash2","block":101,"created_at":"2025-01-02T00:00:00Z","executable":"Instructions","status":"Rejected"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received transaction events")
        valueExpectation.expectedFulfillmentCount = 2
        let completionExpectation = expectation(description: "publisher completed")

        var hashes: [String] = []
        client.explorerTransactionsPublisher(scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { item in
                hashes.append(item.hash)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(hashes, ["hash1", "hash2"])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExplorerInstructionsPublisherDeliversItems() throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received instruction event")
        let completionExpectation = expectation(description: "publisher completed")

        var received: [ToriiExplorerInstructionItem] = []
        client.explorerInstructionsPublisher(lastEventId: "42", scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { item in
                received.append(item)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(received.first?.transactionHash, "hash1")
        XCTAssertEqual(lastEventIdHeader, "42")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExplorerTransfersPublisherDeliversRecords() throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"6","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":1}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Mint","box":{"encoded":"0x01","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Mint","payload":{"variant":"Asset","value":{"destination":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM","object":"1"}}}},"transaction_hash":"hash2","transaction_status":"Committed","block":10,"index":1}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received transfer record")
        let completionExpectation = expectation(description: "publisher completed")

        var records: [ToriiExplorerTransferRecord] = []
        client.explorerTransfersPublisher(matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                           assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                           scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { record in
                records.append(record)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?.instruction.transactionHash, "hash1")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testExplorerTransferSummariesPublisherDeliversItems() throws {
        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"6","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":1}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/event-stream"])!
            return (response, ssePayload)
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received transfer summary")
        let completionExpectation = expectation(description: "publisher completed")

        var summaries: [ToriiExplorerTransferSummary] = []
        client.explorerTransferSummariesPublisher(lastEventId: "7",
                                                   matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                   assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                   scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { summary in
                summaries.append(summary)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(summaries.count, 1)
        XCTAssertEqual(summaries.first?.transactionHash, "hash1")
        XCTAssertEqual(lastEventIdHeader, "7")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testAccountTransferHistoryPublisherCombinesHistoryAndStream() throws {
        let historyPayload = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "5",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "hash1",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 0
                },
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "6",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "hash3",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 1
                }
            ]
        }
        """
            .data(using: .utf8)!

        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:00Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"5","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash1","transaction_status":"Committed","block":10,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"7","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash2","transaction_status":"Committed","block":11,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"8","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"hash4","transaction_status":"Committed","block":11,"index":1}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            guard let url = request.url else {
                throw ToriiClientError.invalidResponse
            }
            if url.path == "/v1/explorer/instructions/query" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
                let queryData = try XCTUnwrap(toriiClientTestBodyData(from: request))
                let query = try XCTUnwrap(try JSONSerialization.jsonObject(with: queryData) as? [String: Any])
                XCTAssertEqual(Set(query.keys), Set(["cursor", "filter", "limit"]))
                XCTAssertEqual(query["cursor"] as? String, "Y3Vyc29y")
                XCTAssertEqual(query["limit"] as? Int, 2)
                XCTAssertNil(query["page"])
                XCTAssertNil(query["per_page"])
                let expectedFilter = (ToriiField("kind") == "Transfer")
                    .and(ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
                    .and(ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
                let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(query["filter"]))
                XCTAssertEqual(try ToriiFilter(jsonData: filterData), expectedFilter)
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, historyPayload)
            }
            if url.path == "/v1/explorer/instructions/stream" {
                lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/event-stream"])!
                return (response, ssePayload)
            }
            throw ToriiClientError.invalidResponse
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received history + stream items")
        valueExpectation.expectedFulfillmentCount = 2
        let completionExpectation = expectation(description: "publisher completed")

        var hashes: [String] = []
        client.accountTransferHistoryPublisher(accountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                               cursor: "Y3Vyc29y",
                                               limit: 2,
                                               assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                               lastEventId: "9",
                                               scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { summary in
                hashes.append(summary.transactionHash)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(hashes, ["hash1", "hash2"])
        XCTAssertEqual(lastEventIdHeader, "9")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamTransactionTransferSummariesCombinesHistoryAndStream() async throws {
        let historyPayload = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "5",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "deadbeef",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 0
                },
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "6",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "deadbeef",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 1
                }
            ]
        }
        """
            .data(using: .utf8)!

        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"7","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"deadbeef","transaction_status":"Committed","block":11,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"8","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"deadbeef","transaction_status":"Committed","block":11,"index":2}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:02Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"9","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"otherhash","transaction_status":"Committed","block":11,"index":1}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            guard let url = request.url else {
                throw ToriiClientError.invalidResponse
            }
            if url.path == "/v1/explorer/instructions/query" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
                let queryData = try XCTUnwrap(toriiClientTestBodyData(from: request))
                let query = try XCTUnwrap(try JSONSerialization.jsonObject(with: queryData) as? [String: Any])
                XCTAssertEqual(Set(query.keys), Set(["filter"]))
                XCTAssertNil(query["cursor"])
                XCTAssertNil(query["limit"])
                let expectedFilter = (ToriiField("transaction_hash") == "deadbeef")
                    .and(ToriiField("kind") == "Transfer")
                    .and(ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
                    .and(ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
                let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(query["filter"]))
                XCTAssertEqual(try ToriiFilter(jsonData: filterData), expectedFilter)
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, historyPayload)
            }
            if url.path == "/v1/explorer/instructions/stream" {
                lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/event-stream"])!
                return (response, ssePayload)
            }
            throw ToriiClientError.invalidResponse
        }

        let stream = makeClient().streamTransactionTransferSummaries(hashHex: "deadbeef",
                                                                     matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                                     assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                                     lastEventId: "12")
        var iterator = stream.makeAsyncIterator()

        let first = try await iterator.next()
        XCTAssertEqual(first?.transactionHash, "deadbeef")
        XCTAssertEqual(first?.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")

        let second = try await iterator.next()
        XCTAssertEqual(second?.transactionHash, "deadbeef")
        XCTAssertEqual(second?.assetDefinitionId, "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")

        let third = try await iterator.next()
        XCTAssertNil(third)
        XCTAssertEqual(lastEventIdHeader, "12")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testTransactionTransferSummariesPublisherCombinesHistoryAndStream() throws {
        let historyPayload = """
        {
            "next_cursor":null,
            "items": [
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "5",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "deadbeef",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 0
                },
                {
                    "authority": "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                    "created_at": "2025-01-01T00:00:00Z",
                    "kind": "Transfer",
                    "box": {
                        "encoded": "0x00",
                        "framed_sha256": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "json": {
                            "kind": "Transfer",
                            "payload": {
                                "variant": "Asset",
                                "value": {
                                    "source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
                                    "object": "6",
                                    "destination": "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
                                }
                            }
                        }
                    },
                    "transaction_hash": "deadbeef",
                    "transaction_status": "Committed",
                    "block": 10,
                    "index": 1
                }
            ]
        }
        """
            .data(using: .utf8)!

        let ssePayload = """
data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"7","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"deadbeef","transaction_status":"Committed","block":11,"index":0}

data: {"authority":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","created_at":"2025-01-01T00:00:01Z","kind":"Transfer","box":{"encoded":"0x00","framed_sha256":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","json":{"kind":"Transfer","payload":{"variant":"Asset","value":{"source":"61CtjvNd9T3THAR65GsMVHr82Bjc#sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","object":"8","destination":"sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"}}}},"transaction_hash":"deadbeef","transaction_status":"Committed","block":11,"index":2}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            guard let url = request.url else {
                throw ToriiClientError.invalidResponse
            }
            if url.path == "/v1/explorer/instructions/query" {
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
                XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
                let queryData = try XCTUnwrap(toriiClientTestBodyData(from: request))
                let query = try XCTUnwrap(try JSONSerialization.jsonObject(with: queryData) as? [String: Any])
                XCTAssertEqual(Set(query.keys), Set(["filter"]))
                XCTAssertNil(query["cursor"])
                XCTAssertNil(query["limit"])
                let expectedFilter = (ToriiField("transaction_hash") == "deadbeef")
                    .and(ToriiField("kind") == "Transfer")
                    .and(ToriiField("account") == "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
                    .and(ToriiField("asset_id") == "62Fk4FPcMuLvW5QjDGNF2a4jAmjM")
                let filterData = try JSONSerialization.data(withJSONObject: XCTUnwrap(query["filter"]))
                XCTAssertEqual(try ToriiFilter(jsonData: filterData), expectedFilter)
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, historyPayload)
            }
            if url.path == "/v1/explorer/instructions/stream" {
                let response = HTTPURLResponse(url: url,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "text/event-stream"])!
                return (response, ssePayload)
            }
            throw ToriiClientError.invalidResponse
        }

        let client = makeClient()
        var cancellables: Set<AnyCancellable> = []
        let valueExpectation = expectation(description: "received tx history + stream items")
        valueExpectation.expectedFulfillmentCount = 2
        let completionExpectation = expectation(description: "publisher completed")

        var hashes: [String] = []
        client.transactionTransferSummariesPublisher(hashHex: "deadbeef",
                                                     matchingAccount: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
                                                     assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                                                     scheduler: nil)
            .sink { completion in
                if case .failure(let error) = completion {
                    XCTFail("Unexpected failure: \(error)")
                }
                completionExpectation.fulfill()
            } receiveValue: { summary in
                hashes.append(summary.transactionHash)
                valueExpectation.fulfill()
            }
            .store(in: &cancellables)

        waitForExpectations(timeout: 2.0)
        XCTAssertEqual(hashes, ["deadbeef", "deadbeef"])
    }
#endif

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamTriggerEventsAsync() async throws {
        let ssePayload = """
id: 101
event: lifecycle
data: {"category":"Data","event":"Trigger","summary":"Trigger(Created(..))"}

id: 102
data: {"category":"Other","event":"ExecuteTrigger","summary":"ExecuteTrigger(..)"}

id: 103
data: {"category":"Future","event":"Trigger","summary":"not a data event"}

id: 104
data: {"category":"Data","event":"Trigger","summary":"Trigger(Deleted(..))"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamTriggerEvents().makeAsyncIterator()

        let created = try await iterator.next()
        XCTAssertEqual(created?.eventId, "101")
        XCTAssertEqual(created?.eventName, "lifecycle")
        XCTAssertEqual(created?.event, ToriiEventNotice(category: "Data", event: "Trigger", summary: "Trigger(Created(..))"))

        let deleted = try await iterator.next()
        XCTAssertEqual(deleted?.eventId, "104")
        XCTAssertEqual(deleted?.event.summary, "Trigger(Deleted(..))")

        let finished = try await iterator.next()
        XCTAssertNil(finished)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamTriggerEventsDoesNotEmitLastEventIdHeader() async throws {
        let ssePayload = """
id: 205
data: {"category":"Data","event":"Trigger","summary":"Trigger(Deleted(..))"}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamTriggerEvents().makeAsyncIterator()
        let event = try await iterator.next()
        XCTAssertEqual(event?.event.event, "Trigger")
        XCTAssertNil(lastEventIdHeader)
        let finished = try await iterator.next()
        XCTAssertNil(finished)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsAsync() async throws {
        let ssePayload = """
id: 41
data: {"category":"Data","event":"Asset","summary":"Asset(Added(..))"}

id: 42
data: {"category":"Data","event":"ProofVerified","backend":"pipa-r/pasta","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","call_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","envelope_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","vk_ref":"pipa-r/pasta::vk_main","vk_commitment":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

id: 43
data: {"category":"Data","event":"ProofRejected","backend":"pipa-r/pasta","proof_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","call_hash":null,"envelope_hash":null,"vk_ref":null,"vk_commitment":null}

id: 44
data: {"category":"Data","event":"ProofPruned","backend":"pipa-r/pasta","removed_count":1,"remaining":9,"cap":10,"grace_blocks":2,"prune_batch":4,"pruned_at_height":77,"pruned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","origin":"Insert","removed":[{"backend":"pipa-r/pasta","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}

id: 45
data: {"category":"Data","event":"ProofPruned","backend":"pipa-r/pasta","removed_count":1,"remaining":9,"cap":10,"grace_blocks":2,"prune_batch":4,"pruned_at_height":78,"pruned_by":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","origin":"Manual","removed":[{"backend":"pipa-r/pasta","proof_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/event-stream")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        let stream = makeClient().streamProofEvents(filter: ToriiProofEventFilter(backend: "pipa-r/pasta",
                                                                                  proofHashHex: String(repeating: "a", count: 64)))
        var iterator = stream.makeAsyncIterator()

        let verified = try await iterator.next()
        guard case let .verified(payload)? = verified?.event else {
            return XCTFail("Expected verified proof event")
        }
        XCTAssertEqual(verified?.eventId, "42")
        XCTAssertEqual(payload.id, ToriiProofId(backend: "pipa-r/pasta", proofHashHex: String(repeating: "a", count: 64)))
        XCTAssertEqual(payload.verifyingKeyRef, "pipa-r/pasta::vk_main")
        XCTAssertEqual(payload.verifyingKeyId?.backend, "pipa-r/pasta")
        XCTAssertEqual(payload.verifyingKeyId?.name, "vk_main")
        XCTAssertEqual(payload.verifyingKeyCommitmentHex, String(repeating: "b", count: 64))
        XCTAssertEqual(payload.callHashHex, String(repeating: "c", count: 64))
        XCTAssertEqual(payload.envelopeHashHex, String(repeating: "d", count: 64))

        let rejected = try await iterator.next()
        guard case let .rejected(rejectedPayload)? = rejected?.event else {
            return XCTFail("Expected rejected proof event")
        }
        XCTAssertEqual(rejected?.eventId, "43")
        XCTAssertEqual(rejectedPayload.id.proofHashHex, String(repeating: "a", count: 64))
        XCTAssertNil(rejectedPayload.verifyingKeyRef)
        XCTAssertNil(rejectedPayload.verifyingKeyId)
        XCTAssertNil(rejectedPayload.callHashHex)

        let pruned = try await iterator.next()
        guard case let .pruned(prunedPayload)? = pruned?.event else {
            return XCTFail("Expected pruned proof event")
        }
        XCTAssertEqual(pruned?.eventId, "44")
        XCTAssertEqual(prunedPayload.origin, .insert)
        XCTAssertEqual(prunedPayload.prunedAtHeight, 77)
        XCTAssertEqual(prunedPayload.remaining, 9)
        XCTAssertEqual(prunedPayload.removed.map(\.proofHashHex), [String(repeating: "a", count: 64)])

        let finished = try await iterator.next()
        XCTAssertNil(finished, "event 45 prunes another proof and is filtered out locally")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsRejectsInvalidProofHashHex() async throws {
        let ssePayload = """
id: 90
data: {"category":"Data","event":"ProofRejected","backend":"pipa-r/pasta","proof_hash":"abcd"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamProofEvents().makeAsyncIterator()
        do {
            _ = try await iterator.next()
            XCTFail("Expected proof event decoding error")
        } catch {
            guard case ToriiClientError.decoding = error else {
                return XCTFail("Expected ToriiClientError.decoding, got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsRejectsInvalidCommitmentHex() async throws {
        let ssePayload = """
id: 91
data: {"category":"Data","event":"ProofVerified","backend":"pipa-r/pasta","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vk_commitment":"zzzz"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamProofEvents().makeAsyncIterator()
        do {
            _ = try await iterator.next()
            XCTFail("Expected proof event decoding error")
        } catch {
            guard case ToriiClientError.decoding = error else {
                return XCTFail("Expected ToriiClientError.decoding, got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsRejectsInvalidBackend() async throws {
        let ssePayload = """
id: 92
data: {"category":"Data","event":"ProofRejected","backend":"halo2:ipa","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

"""
            .data(using: .utf8)!

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamProofEvents().makeAsyncIterator()
        do {
            _ = try await iterator.next()
            XCTFail("Expected proof event decoding error")
        } catch {
            guard case ToriiClientError.decoding = error else {
                return XCTFail("Expected ToriiClientError.decoding, got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsDoesNotEmitLastEventIdHeader() async throws {
        let ssePayload = """
id: 88
data: {"category":"Data","event":"ProofRejected","backend":"pipa-r/pasta","proof_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","call_hash":null,"envelope_hash":null,"vk_ref":null,"vk_commitment":null}

"""
            .data(using: .utf8)!

        var lastEventIdHeader: String?
        StubURLProtocol.handler = { request in
            lastEventIdHeader = request.value(forHTTPHeaderField: "Last-Event-ID")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamProofEvents().makeAsyncIterator()
        let event = try await iterator.next()
        guard case .rejected? = event?.event else {
            return XCTFail("Expected rejected proof event")
        }
        XCTAssertNil(lastEventIdHeader)
        let finished = try await iterator.next()
        XCTAssertNil(finished)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamVerifyingKeyEventsSurfacesTerminalStreamError() async throws {
        let ssePayload = """
event: stream_error
data: {"code":"stream_lagged","message":"The stream lost buffered events.","dropped_messages":7,"replay_available":false}

""".data(using: .utf8)!

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamVerifyingKeyEvents().makeAsyncIterator()
        do {
            _ = try await iterator.next()
            XCTFail("Expected terminal stream error")
        } catch let ToriiClientError.stream(error) {
            XCTAssertEqual(error.code, "stream_lagged")
            XCTAssertEqual(error.message, "The stream lost buffered events.")
            XCTAssertEqual(error.droppedMessages, 7)
            XCTAssertFalse(error.replayAvailable)
        } catch {
            XCTFail("Expected ToriiClientError.stream, got \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStreamProofEventsSurfacesTerminalStreamErrorBeforePayloadProjection() async throws {
        let ssePayload = """
event: stream_error
data: {"code":"stream_source_closed","message":"The event source closed.","dropped_messages":null,"replay_available":false}

""".data(using: .utf8)!

        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamProofEvents().makeAsyncIterator()
        do {
            _ = try await iterator.next()
            XCTFail("Expected terminal stream error")
        } catch let ToriiClientError.stream(error) {
            XCTAssertEqual(error.code, "stream_source_closed")
            XCTAssertEqual(error.message, "The event source closed.")
            XCTAssertNil(error.droppedMessages)
            XCTAssertFalse(error.replayAvailable)
        } catch {
            XCTFail("Expected ToriiClientError.stream, got \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testTypedEventStreamsFailClosedOnMalformedTerminalStreamErrors() async throws {
        let malformedPayloads = [
            "null",
            "{\"code\":\"stream_lagged\",\"code\":\"stream_source_closed\",\"message\":\"closed\",\"dropped_messages\":null,\"replay_available\":false}",
            "{\"code\":\"stream_lagged\",\"message\":\"closed\",\"dropped_messages\":null}",
            "{\"code\":\"stream_lagged\",\"message\":\"closed\",\"dropped_messages\":-1,\"replay_available\":false}",
            "{\"code\":\"stream_lagged\",\"message\":\"closed\",\"dropped_messages\":null,\"replay_available\":\"false\"}",
            "{\"code\":\"stream_lagged\",\"message\":\"closed\",\"dropped_messages\":null,\"replay_available\":false,\"category\":\"Proof\"}",
        ]

        for payload in malformedPayloads {
            let ssePayload = "event: stream_error\ndata: \(payload)\n\n".data(using: .utf8)!
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "text/event-stream"]
                )!
                return (response, ssePayload)
            }

            var iterator = makeClient().streamTriggerEvents().makeAsyncIterator()
            do {
                _ = try await iterator.next()
                XCTFail("Expected malformed terminal stream error to fail closed: \(payload)")
            } catch ToriiClientError.invalidPayload {
                // Expected.
            } catch {
                XCTFail("Expected ToriiClientError.invalidPayload, got \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testTransactionStatusStreamStillFiltersOrdinaryNonTransactionEvents() async throws {
        let ssePayload = """
data: {"category":"Pipeline","event":"Block","status":"Applied"}

data: {"category":"Pipeline","event":"Transaction","hash":"\(Self.pipelineHash)","lane_id":0,"dataspace_id":0,"status":"Rejected","block_height":17,"rejection_code":"limit_check","rejection_reason":"transaction exceeded a limit"}

""".data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertNil(request.value(forHTTPHeaderField: "Last-Event-ID"))
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/event-stream"]
            )!
            return (response, ssePayload)
        }

        var iterator = makeClient().streamTransactionStatusEvents(hashHex: Self.pipelineHash).makeAsyncIterator()
        let message = try await iterator.next()
        XCTAssertEqual(message?.event.status, .rejected)
        XCTAssertEqual(message?.event.blockHeight, 17)
        XCTAssertEqual(message?.event.rejectionCode, .limitCheck)
        XCTAssertEqual(message?.event.rejectionReason, "transaction exceeded a limit")
        let finished = try await iterator.next()
        XCTAssertNil(finished)
    }

    func testProofEventFilterRequiresAnEventKindAndAValidHash() {
        XCTAssertThrowsError(try ToriiProofEventFilter(includeVerified: false, includeRejected: false, includePruned: false).serverFilter()) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
        XCTAssertThrowsError(try ToriiProofEventFilter(backend: "pipa-r/pasta", proofHashHex: "abc").serverFilter()) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
        XCTAssertNil(try ToriiProofEventFilter().serverFilter())
    }

    func testProofEventFilterRejectsInvalidBackendOrHash() {
        for backend in [
            "halo2/ipa",
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "stark/fri/miden",
            "halo2/ipa/orchard",
            "halo2/kzg",
            "halo2:ipa",
            "mock/dev"
        ] {
            XCTAssertThrowsError(try ToriiProofEventFilter(backend: backend).serverFilter()) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("Expected invalidPayload error")
                }
                XCTAssertEqual(reason, expectedVerifierRegistryBackendRejection(backend))
            }
        }

        for hash in [
            "",
            "abc",
            String(repeating: "z", count: 64),
            String(repeating: "a", count: 63),
            "0x" + String(repeating: "a", count: 63)
        ] {
            for filter in [
                ToriiProofEventFilter(proofHashHex: hash),
                ToriiProofEventFilter(callHashHex: hash),
                ToriiProofEventFilter(envelopeHashHex: hash),
            ] {
                XCTAssertThrowsError(try filter.serverFilter()) { error in
                    guard case ToriiClientError.invalidPayload = error else {
                        return XCTFail("Expected invalidPayload error")
                    }
                }
            }
        }
    }

    func testProofEventFilterRendersEventStreamTextFilter() throws {
        let call = "0x" + String(repeating: "A", count: 64)
        let envelope = String(repeating: "b", count: 64)
        let filter = ToriiProofEventFilter(backend: "pipa-r/pasta", callHashHex: call, envelopeHashHex: envelope)
        XCTAssertEqual(
            try filter.serverFilter()?.description,
            "proof_backend = \"pipa-r/pasta\" and proof_call_hash = \"\(String(repeating: "a", count: 64))\" and proof_envelope_hash = \"\(envelope)\""
        )
        XCTAssertNil(try ToriiProofEventFilter(proofHashHex: envelope).serverFilter())
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTimeStatusAsync() async throws {
        let payload = """
        {"peers":3,"samples":[{"peer":"peer1","last_offset_ms":1,"last_rtt_ms":2,"count":3}],"rtt":{"buckets":[{"le":5,"count":10}],"sum_ms":20,"count":10},"note":"NTS running"}
        """.data(using: .utf8)!

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/time/status")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            return (response, payload)
        }

        let status = try await makeClient().getTimeStatus()
        XCTAssertEqual(status.peers, 3)
        XCTAssertEqual(status.samples.first?.peer, "peer1")
        XCTAssertEqual(status.rtt?.buckets.first?.le, 5)
        XCTAssertEqual(status.note, "NTS running")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCoreAndPipelineOperatorReadsRejectMissingContextBeforeDispatch() async {
        StubURLProtocol.handler = { request in
            XCTFail("operator request dispatched without a signing context: \(request)")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data())
        }
        let client = makeClient(operatorSigningContext: nil)
        let reads: [(String, () async throws -> Void)] = [
            ("pipeline recovery", { _ = try await client.getPipelineRecovery(height: 42) }),
            ("pipeline preflight", { _ = try await client.getPipelinePreflight() }),
            ("time status", { _ = try await client.getTimeStatus() }),
        ]

        for (name, read) in reads {
            do {
                try await read()
                XCTFail("\(name) must require an operator signing context")
            } catch {
                XCTAssertTrue(String(describing: error).contains("ToriiOperatorSigningContext"))
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testSumeragiOperatorReadsRejectMissingContextAndFallbackAuthBeforeDispatch() async {
        StubURLProtocol.handler = { request in
            XCTFail("operator request should not dispatch without a clean signing context")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data())
        }

        do {
            _ = try await makeClient(operatorSigningContext: nil).getSumeragiStatus()
            XCTFail("missing operator context must fail before dispatch")
        } catch {
            XCTAssertTrue(String(describing: error).contains("ToriiOperatorSigningContext"))
        }

        for header in ["Authorization", "X-API-Token", "X-Iroha-Operator-Signature"] {
            do {
                _ = try await makeClient(defaultHeaders: [header: "retired"])
                    .getSumeragiStatus()
                XCTFail("fallback or precomputed authentication must fail before dispatch")
            } catch {
                XCTAssertTrue(String(describing: error).contains("reject"))
            }
        }
    }

    func testGetSumeragiStatusParsesNativeSnapshotAsync() async throws {
        let payload = try NativeStatusFixtures.json()
        var servedPayload = payload
        var servedStatus = 200
        var servedHeaders = ["Content-Type": "application/json"]
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/sumeragi/status")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: servedStatus,
                httpVersion: nil,
                headerFields: servedHeaders
            )!
            return (response, servedPayload)
        }
        let snapshot = try await makeClient().getSumeragiStatus()
        XCTAssertEqual(snapshot.protocolVersion, 1)
        XCTAssertEqual(snapshot.instance, String(repeating: "cd", count: 32))
        XCTAssertEqual(snapshot.height, 15)
        XCTAssertEqual(snapshot.view, UInt64.max)
        XCTAssertEqual(snapshot.stage, 2)
        XCTAssertEqual(snapshot.highQcView, UInt64.max)
        XCTAssertEqual(snapshot.level, UInt32.max)
        XCTAssertEqual(snapshot.committedHeight, 14)
        XCTAssertEqual(snapshot.appliedHeight, 13)
        XCTAssertEqual(snapshot.applyLag, 1)
        XCTAssertEqual(snapshot.footprint.votes, UInt64.max)
        XCTAssertEqual(snapshot.beaconHorizon?.activeSessionId, String(repeating: "AB", count: 32))
        XCTAssertTrue(snapshot.isSigning)
        XCTAssertFalse(snapshot.isHalted)

        XCTAssertEqual(payload.first, 0x7B, "Rust fixture begins with its root object")
        var duplicateProtocolVersion = Data(#"{"protocol_version":1,"#.utf8)
        duplicateProtocolVersion.append(payload.dropFirst())
        var invalidResponses: [(Data, Int, [String: String], String)] = [
            (
                duplicateProtocolVersion,
                200, ["Content-Type": "application/json"], #"invalidField("json.duplicateKey")"#
            ),
            (Data([0xff]), 200, ["Content-Type": "application/json"], #"invalidField("json")"#),
            (Data("{}".utf8), 200, ["Content-Type": "text/plain"], "Content-Type"),
            (Data("{}".utf8), 503, ["Content-Type": "application/json"], "503"),
            (
                Data("{}".utf8), 200,
                ["Content-Type": "application/json", "Content-Length": "1048577"], "1048576-byte limit"
            ),
            (
                Data(repeating: 0x20, count: 1_048_577), 200,
                ["Content-Type": "application/json"], "1048576-byte limit"
            ),
        ]
        for declaredLength in ["01", "+1", "1, 1", "18446744073709551616"] {
            invalidResponses.append((
                payload, 200,
                ["Content-Type": "application/json", "Content-Length": declaredLength],
                "malformed or noncanonical Content-Length"
            ))
        }
        invalidResponses.append((
            payload, 200,
            ["Content-Type": "application/json", "Content-Length": "1"],
            "did not match its Content-Length"
        ))
        for (body, statusCode, headers, errorFragment) in invalidResponses {
            servedPayload = body
            servedStatus = statusCode
            servedHeaders = headers
            do {
                _ = try await makeClient().getSumeragiStatus()
                XCTFail("invalid status response must fail closed")
            } catch {
                XCTAssertTrue(
                    String(describing: error).contains(errorFragment),
                    "expected \(errorFragment) for \(headers), got \(error)"
                )
            }
        }

        let maximumBytes = 1_048_576
        var exactPayload = payload
        XCTAssertLessThan(exactPayload.count, maximumBytes)
        exactPayload.append(Data(repeating: 0x20, count: maximumBytes - exactPayload.count))
        servedPayload = exactPayload
        servedStatus = 200
        servedHeaders = [
            "Content-Type": "application/json",
            "Content-Length": String(maximumBytes),
        ]
        let exactSnapshot = try await makeClient().getSumeragiStatus()
        XCTAssertEqual(exactSnapshot.height, 15)
        XCTAssertEqual(exactSnapshot, snapshot)
    }

    func testGetSumeragiLanesParsesRustLaneCorpusAsync() async throws {
        let payload = try NativeLaneFixtures.json("mixed_lanes")
        var servedPayload = payload
        var servedHeaders = ["Content-Type": "application/json"]
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/sumeragi/lanes")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            self.assertOperatorAuthentication(request)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: servedHeaders
            )!
            return (response, servedPayload)
        }
        let lanes = try await makeClient().getSumeragiLanes()
        XCTAssertEqual(lanes.count, 3)
        XCTAssertEqual(lanes[0].record.lane, 1)
        XCTAssertEqual(lanes[0].instance?.protocolVersion, 1)
        XCTAssertNil(lanes[1].instance)
        XCTAssertEqual(lanes[2].record.closing, UInt64.max)

        for (body, headers) in [
            (try NativeStatusFixtures.json(), ["Content-Type": "application/json"]),
            (payload, ["Content-Type": "text/plain"]),
        ] {
            servedPayload = body
            servedHeaders = headers
            do {
                _ = try await makeClient().getSumeragiLanes()
                XCTFail("invalid lane response must fail closed")
            } catch {}
        }
    }

    func testNativeStatusRejectsRetiredExecutionAndCertificateProjections() throws {
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: NativeStatusFixtures.json()) as? [String: Any])
        // Execution roots, manifests, transaction trees and quorum cardinality belong to
        // authenticated native finality artifacts; status no longer accepts a projection.
        for field in ["execution_commitment", "kagemusha_top_up_root", "kagemusha_top_up_count",
                      "topup_anchor_root", "topup_anchor_count", "native_amx_application_manifest_root",
                      "lane_finality_manifest", "merge_carrier", "transaction_input_commitment",
                      "transaction_output_commitment", "last_commit_qc", "locked_prepare_qc"] {
            for value: Any in [NSNull(), [:] as [String: Any], 0, 1, 1000] {
                var payload = original
                payload[field] = value
                XCTAssertThrowsError(try ToriiSumeragiStatusSnapshot.parseJSON(JSONSerialization.data(withJSONObject: payload)), field)
            }
        }
    }

    func testPipelineTransactionEventDecodesNumericDataspaceId() throws {
        let transactionHash = String(repeating: "b", count: 64)
        let payload = """
        {
            "category": "Pipeline",
            "event": "Transaction",
            "hash": "\(transactionHash)",
            "status": "Approved",
            "lane_id": 3,
            "dataspace_id": 9,
            "block_height": null
        }
        """

        let event = try JSONDecoder().decode(
            ToriiPipelineTransactionEvent.self,
            from: Data(payload.utf8)
        )

        XCTAssertEqual(event.dataspaceId, 9)
        XCTAssertEqual(event.laneId, 3)
        XCTAssertEqual(event.status, .approved)
        XCTAssertNil(event.blockHeight)
        XCTAssertNil(event.rejectionCode)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testStatusSnapshotTracksMetrics() async throws {
        var responses = [
            """
            {"observed_at_ms":10000,"peers":2,"queue_size":4,"queue_queued":3,"queue_inflight":1,"last_block_committed_at_ms":9900,"last_non_empty_block_committed_at_ms":9000,"time_since_last_block_ms":100,"time_since_last_non_empty_block_ms":1000,"commit_time_ms":45,"txs_approved":5,"txs_rejected":1,"view_changes":0}
            """.data(using: .utf8)!,
            """
            {"observed_at_ms":11000,"peers":3,"queue_size":11,"queue_queued":8,"queue_inflight":3,"last_block_committed_at_ms":10900,"last_non_empty_block_committed_at_ms":10000,"time_since_last_block_ms":100,"time_since_last_non_empty_block_ms":1000,"commit_time_ms":120,"txs_approved":9,"txs_rejected":3,"view_changes":2}
            """.data(using: .utf8)!,
        ]

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/status")
            guard let body = responses.first else {
                throw NSError(domain: "Stub", code: -1)
            }
            responses.removeFirst()
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, body)
        }

        let client = makeClient()
        let first = try await client.getStatusSnapshot()
        XCTAssertEqual(first.status.queueSize, 4)
        XCTAssertEqual(first.status.queueQueued, 3)
        XCTAssertEqual(first.status.queueInflight, 1)
        XCTAssertEqual(first.metrics.timeSinceLastNonEmptyBlockMs, 1000)
        XCTAssertTrue(first.status.isQueueStalled(stallThresholdMs: 999))
        XCTAssertFalse(first.status.isQueueStalled(stallThresholdMs: 1000))
        XCTAssertEqual(first.metrics.queueDelta, 0)
        XCTAssertEqual(first.metrics.txApprovedDelta, 0)
        XCTAssertFalse(first.metrics.hasActivity)

        let second = try await client.getStatusSnapshot()
        XCTAssertEqual(second.status.queueSize, 11)
        XCTAssertEqual(second.metrics.queueQueued, 8)
        XCTAssertEqual(second.metrics.queueInflight, 3)
        XCTAssertEqual(second.metrics.queueDelta, 7)
        XCTAssertEqual(second.metrics.txApprovedDelta, 4)
        XCTAssertEqual(second.metrics.txRejectedDelta, 2)
        XCTAssertEqual(second.metrics.viewChangeDelta, 2)
        XCTAssertTrue(second.metrics.hasActivity)
    }

    func testStatusStateDropsStaleSamples() throws {
        func makePayload(queue: Int, approved: Int, rejected: Int, viewChanges: Int) throws -> ToriiStatusPayload {
            try ToriiStatusPayload(raw: [
                "peers": .number(Double(queue)),
                "queue_size": .number(Double(queue)),
                "commit_time_ms": .number(30),
                "txs_approved": .number(Double(approved)),
                "txs_rejected": .number(Double(rejected)),
                "view_changes": .number(Double(viewChanges))
            ])
        }

        var state = ToriiStatusState()
        let slow = try makePayload(queue: 4, approved: 5, rejected: 1, viewChanges: 0)
        let fast = try makePayload(queue: 6, approved: 7, rejected: 2, viewChanges: 1)
        let newer = try makePayload(queue: 8, approved: 10, rejected: 3, viewChanges: 1)

        let slowSequence = state.reserveSequence()
        let fastSequence = state.reserveSequence()

        let fastMetrics = state.record(fast, sequence: fastSequence)
        XCTAssertEqual(fastMetrics.queueDelta, 0)
        XCTAssertEqual(fastMetrics.txApprovedDelta, 0)

        let staleMetrics = state.record(slow, sequence: slowSequence)
        XCTAssertEqual(staleMetrics.queueDelta, 0)
        XCTAssertEqual(staleMetrics.txApprovedDelta, 0)
        XCTAssertEqual(staleMetrics.txRejectedDelta, 0)

        let newerSequence = state.reserveSequence()
        let newerMetrics = state.record(newer, sequence: newerSequence)
        XCTAssertEqual(newerMetrics.queueDelta, 2)
        XCTAssertEqual(newerMetrics.txApprovedDelta, 3)
        XCTAssertEqual(newerMetrics.txRejectedDelta, 1)
        XCTAssertEqual(newerMetrics.viewChangeDelta, 0)
    }

    func testStatusPayloadDecodesGovernanceSeals() throws {
        let payload = try ToriiStatusPayload(raw: [
            "peers": .number(2),
            "queue_size": .number(1),
            "commit_time_ms": .number(42),
            "txs_approved": .number(7),
            "txs_rejected": .number(1),
            "view_changes": .number(0),
            "lane_governance_sealed_total": .number(2),
            "lane_governance_sealed_aliases": .array([.string("public"), .string("payments")]),
            "dataspace_catalog": .array([
                .object([
                    "lane_id": .number(7),
                    "lane_alias": .string("lane-alpha"),
                    "dataspace_id": .number(9),
                    "alias": .string("alpha"),
                    "visibility": .string("restricted"),
                    "storage_profile": .string("balanced"),
                    "manifest_required": .bool(true),
                    "manifest_ready": .bool(false),
                    "sealed": .bool(true),
                    "manifest_path": .null,
                    "protected_namespaces": .array([.string("alpha")])
                ])
            ])
        ])

        XCTAssertEqual(payload.laneGovernanceSealedTotal, 2)
        XCTAssertEqual(payload.laneGovernanceSealedAliases, ["public", "payments"])
        XCTAssertEqual(payload.dataspaceCatalog.first?.alias, "alpha")
        XCTAssertEqual(try payload.requireDataspace(alias: "alpha").sealed, true)
        XCTAssertEqual(payload.dataspace(id: 9)?.manifestRequired, true)
    }

    func testStatusPayloadDefaultsGovernanceSealsWhenMissing() throws {
        let payload = try ToriiStatusPayload(raw: [
            "peers": .number(1),
            "queue_size": .number(0),
            "commit_time_ms": .number(15),
            "txs_approved": .number(3),
            "txs_rejected": .number(0),
            "view_changes": .number(0)
        ])

        XCTAssertEqual(payload.laneGovernanceSealedTotal, 0)
        XCTAssertTrue(payload.laneGovernanceSealedAliases.isEmpty)
        XCTAssertTrue(payload.dataspaceCatalog.isEmpty)
    }

    func testGetTimeStatusCompletion() {
        let expectation = expectation(description: "time-status")
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"peers":0,"samples":[],"note":"empty"}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().getTimeStatus { result in
            switch result {
            case .success(let status):
                XCTAssertEqual(status.peers, 0)
                XCTAssertEqual(status.note, "empty")
            case .failure(let error):
                XCTFail("Unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testUploadAttachmentParsesMetadata() {
        let expectation = expectation(description: "upload")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/zk/attachments")
            XCTAssertEqual(request.httpMethod, "POST")
            let response = HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"id":"abc","content_type":"application/json","size":42,"created_ms":1234,"tenant":"token:xyz"}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().uploadAttachment(data: Data("test".utf8), contentType: "application/json", canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let meta):
                XCTAssertEqual(meta.id, "abc")
                XCTAssertEqual(meta.content_type, "application/json")
                XCTAssertEqual(meta.size, 42)
                XCTAssertEqual(meta.created_ms, 1234)
                XCTAssertEqual(meta.tenant, "token:xyz")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: 1)
    }

    func testListAttachmentsDecodesArray() {
        let expectation = expectation(description: "list attachments")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/zk/attachments")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            [{"id":"one","content_type":"text/plain","size":1,"created_ms":1},{"id":"two","content_type":"application/json","size":2,"created_ms":2,"tenant":"anon"}]
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().listAttachments(canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let metas):
                XCTAssertEqual(metas.count, 2)
                XCTAssertEqual(metas[0].id, "one")
                XCTAssertNil(metas[0].tenant)
                XCTAssertEqual(metas[1].tenant, "anon")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: 1)
    }

    func testGetAttachmentEncodesId() {
        let expectation = expectation(description: "get attachment")
        let attachmentId = "abc/def"
        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/zk/attachments/abc%2Fdef"))
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/octet-stream"])!
            return (response, Data([0x01]))
        }

        makeClient().getAttachment(id: attachmentId, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let payload):
                XCTAssertEqual(payload.0, Data([0x01]))
                XCTAssertEqual(payload.1, "application/octet-stream")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testDeleteAttachmentEncodesId() {
        let expectation = expectation(description: "delete attachment")
        let attachmentId = "abc/def"
        StubURLProtocol.handler = { request in
            // URL.path always returns decoded path. Check absoluteString to verify encoding.
            XCTAssertTrue(request.url!.absoluteString.contains("/v1/zk/attachments/abc%2Fdef"))
            XCTAssertEqual(request.httpMethod, "DELETE")
            let response = HTTPURLResponse(url: request.url!, statusCode: 204, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }

        makeClient().deleteAttachment(id: attachmentId, canonicalAuth: canonicalReadAuth) { result in
            if case let .failure(error) = result {
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testFetchContractManifestParsesResponse() throws {
        let expectation = expectation(description: "fetch manifest")
        let codeHash = String(repeating: "b", count: 64)
        let abiHash = String(repeating: "d", count: 64)
        let artifactId = try ContractArtifactId(dataspaceId: UInt64.max,
            codeHash: "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/artifacts/\(UInt64.max)/\(codeHash)")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"network_id":"\(TestNetworkIds.canonical.literal)","artifact_id":{"dataspace_id":18446744073709551615,"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"},"manifest":{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":null,"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2","abi_hash":"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071","compiler_fingerprint":"rustc","features_bitmap":1,"access_set_hints":{"read_keys":["account:alice#wonderland"],"write_keys":[]},"entrypoints":null,"states":null,"error_types":null},"code_hash":"\(codeHash)","abi_hash":"\(abiHash)"}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().fetchContractManifest(artifactId: artifactId, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let record):
                XCTAssertEqual(record.manifest.codeHash, codeHash)
                XCTAssertEqual(record.manifest.abiHash, abiHash)
                XCTAssertEqual(record.codeHash, codeHash)
                XCTAssertEqual(record.abiHash, abiHash)
                XCTAssertEqual(record.manifest.accessSetHints?.readKeys, ["account:alice#wonderland"])
                XCTAssertEqual(record.manifest.accessSetHints?.writeKeys ?? [], [])
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testContractManifestRecordRejectsMismatchedHashConveniences() throws {
        let manifest = #"{"permissions":[],"events":[],"enum_types":[],"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2","abi_hash":"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071"}"#
        let identity = "\"network_id\":\"\(TestNetworkIds.canonical.literal)\",\"artifact_id\":{\"dataspace_id\":18446744073709551615,\"code_hash\":\"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2\"},"
        let valid = "{\(identity)\"manifest\":\(manifest),\"code_hash\":\"\(String(repeating: "b", count: 64))\",\"abi_hash\":\"\(String(repeating: "d", count: 64))\"}"
        let record = try JSONDecoder().decode(
            ToriiContractManifestRecord.self,
            from: Data(valid.utf8)
        )
        XCTAssertEqual(record.codeHash, record.manifest.codeHash)
        XCTAssertEqual(record.abiHash, record.manifest.abiHash)

        let invalid = [
            "{\(identity)\"manifest\":\(manifest),\"code_hash\":\"\(String(repeating: "d", count: 64))\",\"abi_hash\":\"\(String(repeating: "d", count: 64))\"}",
            "{\(identity)\"manifest\":\(manifest),\"code_hash\":\"\(String(repeating: "B", count: 64))\",\"abi_hash\":\"\(String(repeating: "d", count: 64))\"}",
            "{\(identity)\"manifest\":\(manifest),\"abi_hash\":\"\(String(repeating: "d", count: 64))\"}",
        ]
        for payload in invalid {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiContractManifestRecord.self,
                    from: Data(payload.utf8)
                ),
                "accepted inconsistent manifest response: \(payload)"
            )
        }
    }

    func testContractManifestOptionalBytesAreCanonicalBoundedAndDigestBound() throws {
        let bytes = Data([0])
        let hash = IrohaHash.hash(Data("iroha:ivm:contract-artifact:v1\0".utf8) + bytes).hexLowercased()
        let literal = try XCTUnwrap(ToriiCanonicalHashLiteral.literal(fromNormalizedHex: hash))
        let prefix = "\"network_id\":\"\(TestNetworkIds.canonical.literal)\",\"artifact_id\":{\"dataspace_id\":17,\"code_hash\":\"\(literal)\"},\"manifest\":{\"events\":[],\"enum_types\":[],\"permissions\":[],\"code_hash\":\"\(literal)\",\"abi_hash\":\"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071\"},\"code_hash\":\"\(hash)\",\"abi_hash\":\"\(String(repeating: "d", count: 64))\""
        func decode(_ suffix: String) throws -> ToriiContractManifestRecord {
            try JSONDecoder().decode(ToriiContractManifestRecord.self, from: Data("{\(prefix)\(suffix)}".utf8))
        }
        XCTAssertNil(try decode("").codeBytes)
        XCTAssertNil(try decode(",\"code_bytes\":null").codeBytes)
        XCTAssertEqual(try decode(",\"code_bytes\":\"AA==\"").codeBytes, "AA==")
        for invalid in ["AB==", "AA", "AAAA", "", " AA==", String(repeating: "A", count: ((16 * 1_024 * 1_024 + 2) / 3) * 4)] {
            XCTAssertThrowsError(try decode(",\"code_bytes\":\"\(invalid)\""))
        }
        XCTAssertThrowsError(try decode(",\"code_bytes\":1"))
    }

    func testContractManifestPreservesExactV1InterfaceShape() throws {
        let payload = """
        {
          "events":[],"enum_types":[],"permissions":[{"name":"TransferAsset","scope":{"kind":"Instance","value":null}}],
                "seiyaku_name":"Ledger",
          "code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2",
          "abi_hash":"hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071",
          "compiler_fingerprint":"kotodama_lang",
          "features_bitmap":0,
          "access_set_hints":{
            "read_keys":["state:Balances"],
            "write_keys":["state:Balances"],
            "dynamic_reads":[{
              "base_key":"state:Balances",
              "key_type":"AccountId",
              "bound_kind":"take",
              "max_keys":64
            }],
            "dynamic_writes":[]
          },
          "entrypoints":[{
            "name":"transfer",
            "kind":{"kind":"Kotoage","value":null},
            "params":[
              {"name":"request","type_name":"struct Fixture::Transfer"},
              {"name":"tags","type_name":"List<Name, 64>"}
            ],
            "argument_schema":{"fields":[
              {"name":"request","ty":{"nodes":[
                {"kind":"Struct","value":{"name":"Fixture::Transfer","fields":["amount","memo"]}},
                {"kind":"Leaf","value":{"kind":"Quantity","value":null}},
                {"kind":"Option","value":null},
                {"kind":"Leaf","value":{"kind":"String","value":null}}
              ]}},
              {"name":"tags","ty":{"nodes":[
                {"kind":"List","value":{"capacity":64}},
                {"kind":"Leaf","value":{"kind":"Name","value":null}}
              ]}}
            ]},
            "return_type":"Result<(bool, decimal), string>",
            "return_schema":{"nodes":[
              {"kind":"Result","value":null},
              {"kind":"Tuple","value":2},
              {"kind":"Leaf","value":{"kind":"Bool","value":null}},
              {"kind":"Leaf","value":{"kind":"Decimal","value":null}},
              {"kind":"Leaf","value":{"kind":"String","value":null}}
            ]},
            "authorization":{"kind":"Permission","value":"TransferAsset"},
            "read_keys":["state:Balances"],
            "write_keys":["state:Balances"],
            "access_hints_complete":true,
            "access_hints_skipped":[],
            "triggers":[{
              "id":"settle",
              "repeats":{"Exactly":2},
              "filter":"TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA=",
              "authority":null,
              "metadata":{"purpose":"daily-settlement","round":7},
              "callback":{"namespace":null,"entrypoint":"transfer"}
            }]
          }],
          "states":[{"name":"Balances","type_name":"StateMap<AccountId, quantity>"}],
          "error_types":[{
            "identity":"Ledger::TransferError",
            "variants":[{"name":"InsufficientFunds","code":1001}]
          }],
          "kotoba":[{
            "msg_id":"transfer.denied",
            "translations":[
              {"lang":"en","text":"Transfer denied"},
              {"lang":"ja","text":"送金は拒否されました"}
            ]
          }],
          "provenance":{"signer":"ed25519:fixture","signature":"fixture-signature"}
        }
        """.data(using: .utf8)!

        let manifest = try JSONDecoder().decode(ToriiContractManifest.self, from: payload)
        XCTAssertEqual(manifest.seiyakuName, "Ledger")
        XCTAssertEqual(manifest.codeHash, String(repeating: "b", count: 64))
        XCTAssertEqual(manifest.abiHash, String(repeating: "d", count: 64))
        XCTAssertEqual(manifest.accessSetHints?.dynamicReads.first?.maxKeys, 64)
        let entrypoint = try XCTUnwrap(manifest.entrypoints?.first)
        XCTAssertEqual(entrypoint.kind, .kotoage)
        XCTAssertEqual(entrypoint.argumentSchema?.fields.first?.type.wordCount, 2)
        XCTAssertEqual(entrypoint.argumentSchema?.fields.last?.type.wordCount, 1)
        guard case let .list(listNode)? = entrypoint.argumentSchema?.fields.last?.type.nodes.first else {
            return XCTFail("expected bounded list argument schema")
        }
        XCTAssertEqual(listNode.capacity, 64)
        XCTAssertEqual(entrypoint.returnSchema?.wordCount, 1)
        guard case let .leaf(returnLeaf)? = entrypoint.returnSchema?.nodes[2] else {
            return XCTFail("expected bool return leaf")
        }
        XCTAssertEqual(returnLeaf, .bool)
        XCTAssertEqual(entrypoint.triggers.first?.callback.entrypoint, "transfer")
        XCTAssertEqual(entrypoint.triggers.first?.metadata["round"], .number(7))
        XCTAssertEqual(manifest.states?.first?.typeName, "StateMap<AccountId, quantity>")
        XCTAssertEqual(manifest.errorTypes?.first?.variants.first?.code, 1001)
        XCTAssertEqual(manifest.kotoba?.first?.translations.last?.language, "ja")
        XCTAssertEqual(manifest.provenance?.signer, "ed25519:fixture")

        let encoded = try JSONEncoder().encode(manifest)
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(object["seiyaku_name"] as? String, "Ledger")
        XCTAssertEqual(
            object["code_hash"] as? String,
            "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"
        )
        XCTAssertEqual(
            object["abi_hash"] as? String,
            "hash:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD#F071"
        )
        let entrypoints = try XCTUnwrap(object["entrypoints"] as? [[String: Any]])
        XCTAssertNotNil(entrypoints[0]["argument_schema"])
        XCTAssertNotNil(entrypoints[0]["return_schema"])
        XCTAssertEqual((entrypoints[0]["triggers"] as? [Any])?.count, 1)
        XCTAssertEqual((object["states"] as? [Any])?.count, 1)
        XCTAssertEqual((object["error_types"] as? [Any])?.count, 1)
        XCTAssertEqual((object["kotoba"] as? [Any])?.count, 1)
        XCTAssertNotNil(object["provenance"] as? [String: Any])
    }

    func testEntrypointSchemaUsesOneFlatPreorderTapeAndExactReservedNames() throws {
        func leaf(_ kind: String) -> String {
            "{\"kind\":\"Leaf\",\"value\":{\"kind\":\"\(kind)\",\"value\":null}}"
        }
        func structNode(_ name: String, _ fields: [String]) -> String {
            let name = ["AccountView", "AssetView", "AssetDefinitionView", "DomainView", "NftView", "QueryPage", "StatePage"].contains(name) ? "kotodama::" + name : name
            let encodedFields = fields.map { "\"\($0)\"" }.joined(separator: ",")
            return "{\"kind\":\"Struct\",\"value\":{\"name\":\"\(name)\",\"fields\":[\(encodedFields)]}}"
        }
        func decode(_ nodes: [String]) throws -> ToriiEntrypointValueTypeV1 {
            let payload = "{\"nodes\":[\(nodes.joined(separator: ","))]}"
            return try JSONDecoder().decode(
                ToriiEntrypointValueTypeV1.self,
                from: Data(payload.utf8)
            )
        }

        let views: [(String, [String], [String])] = [
            (
                "AccountView",
                ["id", "metadata"],
                [leaf("AccountId"), leaf("Json")]
            ),
            (
                "AssetView",
                ["id", "amount"],
                [leaf("AssetId"), leaf("Quantity")]
            ),
            (
                "AssetDefinitionView",
                ["id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"],
                [
                    leaf("AssetDefinitionId"),
                    leaf("String"),
                    #"{"kind":"Option","value":null}"#,
                    leaf("String"),
                    leaf("AccountId"),
                    leaf("Quantity"),
                    #"{"kind":"Option","value":null}"#,
                    leaf("Int"),
                    leaf("Json"),
                ]
            ),
            (
                "DomainView",
                ["id", "owned_by", "metadata"],
                [leaf("DomainId"), leaf("AccountId"), leaf("Json")]
            ),
            (
                "NftView",
                ["id", "owned_by", "content"],
                [leaf("NftId"), leaf("AccountId"), leaf("Json")]
            ),
        ]

        for (name, fields, children) in views {
            let viewNodes = [structNode(name, fields)] + children
            let view = try decode(viewNodes)
            XCTAssertEqual(view.canonicalTypeName, name)

            let optional = try decode([#"{"kind":"Option","value":null}"#] + viewNodes)
            XCTAssertEqual(optional.canonicalTypeName, "Option<\(name)>")

            let pageNodes = [
                structNode("QueryPage", ["items", "next_offset"]),
                #"{"kind":"List","value":{"capacity":64}}"#,
            ] + viewNodes + [
                #"{"kind":"Option","value":null}"#,
                leaf("Int"),
            ]
            let page = try decode(pageNodes)
            XCTAssertEqual(page.canonicalTypeName, "QueryPage<\(name)>")
            XCTAssertEqual(page.wordCount, 2)

            let encoded = try JSONEncoder().encode(page)
            let object = try XCTUnwrap(
                try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
            )
            let encodedNodes = try XCTUnwrap(object["nodes"] as? [[String: Any]])
            let listPayload = try XCTUnwrap(encodedNodes[1]["value"] as? [String: Any])
            XCTAssertEqual(listPayload["capacity"] as? Int, 64)
            XCTAssertEqual(Set(listPayload.keys), ["capacity"])
            XCTAssertEqual(
                try JSONDecoder().decode(ToriiEntrypointValueTypeV1.self, from: encoded),
                page
            )
        }

        let pair = try decode([
            structNode("Fixture::Pair", ["left", "right"]),
            leaf("Int"),
            leaf("Bool"),
        ])
        XCTAssertEqual(pair.canonicalTypeName, "struct Fixture::Pair")
    }

    func testEntrypointSchemaRejectsLegacyTruncatedDeepAndForgedTapes() throws {
        func leaf(_ kind: String) -> String {
            "{\"kind\":\"Leaf\",\"value\":{\"kind\":\"\(kind)\",\"value\":null}}"
        }
        func structNode(_ name: String, _ fields: [String]) -> String {
            let name = ["AccountView", "AssetView", "AssetDefinitionView", "DomainView", "NftView", "QueryPage", "StatePage"].contains(name) ? "kotodama::" + name : name
            let encodedFields = fields.map { "\"\($0)\"" }.joined(separator: ",")
            return "{\"kind\":\"Struct\",\"value\":{\"name\":\"\(name)\",\"fields\":[\(encodedFields)]}}"
        }
        func decode(_ nodes: [String]) throws -> ToriiEntrypointValueTypeV1 {
            let payload = "{\"nodes\":[\(nodes.joined(separator: ","))]}"
            return try JSONDecoder().decode(
                ToriiEntrypointValueTypeV1.self,
                from: Data(payload.utf8)
            )
        }
        func reject(_ nodes: [String], _ label: String) {
            XCTAssertThrowsError(try decode(nodes), "accepted \(label)")
        }

        let views: [(String, [String], [String])] = [
            ("AccountView", ["id", "metadata"], [leaf("AccountId"), leaf("Json")]),
            ("AssetView", ["id", "amount"], [leaf("AssetId"), leaf("Quantity")]),
            (
                "AssetDefinitionView",
                ["id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"],
                [
                    leaf("AssetDefinitionId"),
                    leaf("String"),
                    #"{"kind":"Option","value":null}"#,
                    leaf("String"),
                    leaf("AccountId"),
                    leaf("Quantity"),
                    #"{"kind":"Option","value":null}"#,
                    leaf("Int"),
                    leaf("Json"),
                ]
            ),
            (
                "DomainView",
                ["id", "owned_by", "metadata"],
                [leaf("DomainId"), leaf("AccountId"), leaf("Json")]
            ),
            (
                "NftView",
                ["id", "owned_by", "content"],
                [leaf("NftId"), leaf("AccountId"), leaf("Json")]
            ),
        ]

        for (name, fields, children) in views {
            let validView = [structNode(name, fields)] + children
            if name == "AssetDefinitionView" {
                let retiredFields = fields.filter { $0 != "numeric_scale" }
                let retiredChildren = Array(children.prefix(6)) + [children[8]]
                reject([structNode(name, retiredFields)] + retiredChildren, "retired six-field definition")
                var requiredPrecision = validView
                requiredPrecision.remove(at: 7)
                reject(requiredPrecision, "required numeric precision")
                var decimalPrecision = validView
                decimalPrecision[8] = leaf("Decimal")
                reject(decimalPrecision, "decimal numeric precision")
            }
            var wrongFields = fields
            wrongFields[wrongFields.count - 1] = "forged"
            reject(
                [structNode(name, wrongFields)] + children,
                "\(name) with forged fields"
            )

            var wrongLeaf = children
            wrongLeaf[wrongLeaf.count - 1] = leaf("Blob")
            reject(
                [structNode(name, fields)] + wrongLeaf,
                "\(name) with forged leaf kind"
            )

            let pagePrefix = [
                structNode("QueryPage", ["items", "next_offset"]),
                #"{"kind":"List","value":{"capacity":64}}"#,
            ]
            reject(
                pagePrefix + validView + [
                    #"{"kind":"Option","value":null}"#,
                    leaf("String"),
                ],
                "QueryPage<\(name)> with non-int next_offset"
            )
            reject(
                [
                    structNode("QueryPage", ["items", "next_offset"]),
                    #"{"kind":"List","value":{"capacity":32}}"#,
                ] + validView + [
                    #"{"kind":"Option","value":null}"#,
                    leaf("Int"),
                ],
                "QueryPage<\(name)> with capacity below 64"
            )
        }

        reject(
            [
                #"{"kind":"List","value":{"capacity":64,"element":{"nodes":[{"kind":"Leaf","value":{"kind":"Name","value":null}}]}}}"#,
            ],
            "retired nested list element"
        )
        reject([#"{"kind":"List","value":{"capacity":64}}"#], "truncated list tape")
        reject([leaf("Bool"), leaf("Bool")], "extra root node")
        reject(
            [#"{"kind":"List","value":{"capacity":0}}"#, leaf("Int")],
            "zero list capacity"
        )
        reject(
            [#"{"kind":"List","value":{"capacity":65}}"#, leaf("Int")],
            "list capacity above 64"
        )

        let forgedForEncoding = ToriiEntrypointValueTypeV1(nodes: [
            .structType(
                ToriiEntrypointStructTypeNodeV1(
                    name: "AccountView",
                    fields: ["id", "metadata"]
                )
            ),
            .leaf(.accountId),
            .leaf(.blob),
        ])
        XCTAssertThrowsError(try JSONEncoder().encode(forgedForEncoding))
        XCTAssertThrowsError(
            try JSONEncoder().encode(
                ToriiEntrypointValueTypeV1(
                    nodes: [.list(ToriiEntrypointListTypeNodeV1(capacity: 64))]
                )
            )
        )

        let atLimit = Array(
            repeating: #"{"kind":"List","value":{"capacity":1}}"#,
            count: 255
        ) + [leaf("Int")]
        XCTAssertEqual(try decode(atLimit).wordCount, 1)
        reject(
            Array(
                repeating: #"{"kind":"List","value":{"capacity":1}}"#,
                count: 256
            ) + [leaf("Int")],
            "schema depth and node budget overflow"
        )
    }

    func testContractManifestRejectsNoncanonicalV1InterfaceShapes() throws {
        let validLeaf = #"{"kind":"Leaf","value":{"kind":"Bool","value":null}}"#
        var cases = [
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":" Ledger "}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"Amount"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"amount"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"seiyaku"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"match"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"__kotodama_quantity_ratio_round"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"__kotodama_decimal_to_int_trunc"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"__kotodama_decimal_to_int_round"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Amount","type_name":"quantity"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Fixture::Transfer{Amount: quantity}"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"StateMap<AccountId, Amount>"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"StateMap<AccountId, amount>"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Amount: quantity"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"StateMap<AccountId, Amount: quantity>"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Fixture::Transfer{value: Result<int, Amount: quantity>}"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Fixture::Transfer{amount: Amount}"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Amount{amount: quantity}"}]}"#,
            #"{"code_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
            #"{"code_hash":"hash:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb#ABA2"}"#,
            #"{"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#0000"}"#,
            #"{"code_hash":"hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#aba2"}"#,
            #"{"code_hash":"hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#0E5B"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"provenance":"not-an-object"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Public","value":null},"params":[],"argument_schema":null,"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"Amount","kind":{"kind":"View","value":null},"params":[],"argument_schema":null,"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"View","value":null},"params":[{"name":"Amount","type_name":"bool"}],"argument_schema":{"fields":[{"name":"Amount","ty":{"nodes":[{"kind":"Leaf","value":{"kind":"Bool","value":null}}]}}]},"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":"Kotoage"},"params":[],"argument_schema":null,"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            "{\"events\":[],\"enum_types\":[],\"permissions\":[],\"entrypoints\":[{\"name\":\"run\",\"kind\":{\"kind\":\"Kotoage\",\"value\":null},\"params\":[{\"name\":\"flag\",\"type_name\":\"bool\"}],\"argument_schema\":{\"fields\":[{\"name\":\"flag\",\"ty\":{\"nodes\":[{\"kind\":\"Tuple\",\"value\":1},\(validLeaf)]}}]},\"return_type\":\"()\",\"return_schema\":{\"nodes\":[{\"kind\":\"Unit\",\"value\":null}]},\"authorization\":{\"kind\":\"Anyone\",\"value\":null},\"read_keys\":[],\"write_keys\":[],\"access_hints_complete\":true,\"access_hints_skipped\":[],\"triggers\":[]}]}",
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":null},"params":[],"argument_schema":null,"return_type":"bool","return_schema":{"nodes":[{"kind":"Leaf","value":{"kind":"Bool","value":null}},{"kind":"Leaf","value":{"kind":"Bool","value":null}}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":null},"params":[],"argument_schema":null,"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":["not-an-object"]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"error_types":[{"identity":"Ledger::Failure","variants":[{"name":"Denied","code":0}]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"error_types":[{"identity":"Ledger::Failure","variants":[{"name":"Amount","code":1}]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":null},"params":[],"argument_schema":null,"return_type":null,"return_schema":{"nodes":[{"kind":"Leaf","value":{"kind":"Bool","value":null}}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":null},"params":[{"name":"flag","type_name":"bool"}],"argument_schema":{"fields":[{"name":"different","ty":{"nodes":[{"kind":"Leaf","value":{"kind":"Bool","value":null}}]}}]},"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"run","kind":{"kind":"Kotoage","value":null},"params":[{"name":"tags","type_name":"List<Name, 64>"}],"argument_schema":{"fields":[{"name":"tags","ty":{"nodes":[{"kind":"List","value":{"capacity":65}},{"kind":"Leaf","value":{"kind":"Name","value":null}}]}}]},"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"Anyone","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}"#,
        ]
        let wideLeaves = Array(repeating: validLeaf, count: 14).joined(separator: ",")
        cases.append(
            "{\"events\":[],\"enum_types\":[],\"permissions\":[],\"entrypoints\":[{\"name\":\"run\",\"kind\":{\"kind\":\"Kotoage\",\"value\":null},\"params\":[],\"argument_schema\":null,\"return_type\":\"wide tuple\",\"return_schema\":{\"nodes\":[{\"kind\":\"Tuple\",\"value\":14},\(wideLeaves)]},\"authorization\":{\"kind\":\"Anyone\",\"value\":null},\"read_keys\":[],\"write_keys\":[],\"access_hints_complete\":true,\"access_hints_skipped\":[],\"triggers\":[]}]}")

        for payload in cases {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiContractManifest.self,
                    from: Data(payload.utf8)
                ),
                "accepted noncanonical manifest payload: \(payload)"
            )
        }
    }

    func testContractManifestAllowsAmountAsStructFieldIdentifier() throws {
        let payload =
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Balances","type_name":"Fixture::Transfer{amount: quantity}"}]}"#
        let manifest = try JSONDecoder().decode(
            ToriiContractManifest.self,
            from: Data(payload.utf8)
        )

        XCTAssertEqual(manifest.states?.first?.typeName, "Fixture::Transfer{amount: quantity}")
        let encoded = try JSONEncoder().encode(manifest)
        let decoded = try JSONDecoder().decode(ToriiContractManifest.self, from: encoded)
        XCTAssertEqual(decoded.states?.first?.typeName, "Fixture::Transfer{amount: quantity}")
    }

    func testDurableBuiltinProductsRequireExactShapes() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let vectors = try JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: root.appendingPathComponent("fixtures/kotodama/durable_builtin_shapes_v1.json")))
        func decode(_ type: String) throws -> ToriiContractManifest {
            let value: [String: Any] = ["permissions": [], "events": [], "enum_types": [], "states": [["name": "stored", "type_name": type]]]
            return try JSONDecoder().decode(ToriiContractManifest.self, from: JSONSerialization.data(withJSONObject: value))
        }
        for type in vectors["valid"]! { XCTAssertEqual(try decode(type).states?.first?.typeName, type) }
        for type in vectors["invalid"]! { XCTAssertThrowsError(try decode(type), type) }
    }

    func testContractManifestStateTypesUseExactCanonicalV1Grammar() throws {
        func decode(_ typeName: String) throws -> ToriiContractManifest {
            let data = try JSONSerialization.data(
                withJSONObject: [
                "events":[],"enum_types":[],"permissions": [],
                    "states": [
                        ["name": "Balances", "type_name": typeName],
                    ],
                ]
            )
            return try JSONDecoder().decode(ToriiContractManifest.self, from: data)
        }

        let scalarTypes = [
            "int", "decimal", "quantity", "bool", "string", "bytes", "DataSpaceId",
            "AccountId", "AssetDefinitionId", "AssetId", "NftId", "DomainId", "Name", "Json",
        ]
        let stateMapKeyTypes = scalarTypes.filter { $0 != "Json" }
        let canonical = scalarTypes + stateMapKeyTypes.map {
            "StateMap<\($0), quantity>"
        } + [
            "(int, decimal)",
            "Option<Result<quantity, string>>",
            "List<Fixture::Transfer{amount: quantity}, 64>",
            "StateMap<AccountId, Fixture::Transfer{amount: quantity}>",
            "StateMap<Name, Fixture::Transfer{amount: quantity, memo: Option<string>}>",
        ]
        for typeName in canonical {
            let manifest = try decode(typeName)
            XCTAssertEqual(manifest.states?.first?.typeName, typeName)
            XCTAssertNoThrow(try JSONEncoder().encode(manifest))
        }

        let noncanonical = [
            "Amount",
            "amount",
            "Fixture::Transfer{amount: amount}",
            "Fixture::Transfer{amount:: quantity}",
            "Fixture::Transfer{Amount: quantity}",
            "Fixture::Transfer{amount:quantity}",
            "Fixture::Transfer{amount:  quantity}",
            "Transfer {amount: quantity}",
            "Fixture::Transfer{ }",
            "Fixture::Transfer{amount: quantity, amount: int}",
            "Fixture::Transfer{__kotodama_link_amount: quantity}",
            "(int)",
            "(int,decimal)",
            "Option<quantity",
            "Fixture::Transfer{amount: Option<quantity>}}",
            "Option<StateMap<AccountId, quantity>>",
            "StateMap<AccountId, StateMap<Name, quantity>>",
            "StateMap<Json, quantity>",
            "StateMap<AccountId , quantity>",
            "StateMap<AccountId,quantity>",
            "List<quantity, 0>",
            "List<quantity, 01>",
            "List<quantity, 65>",
            "Trаnsfer{amount: quantity}",
            "Fixture::Transfer{amount: quаntity}",
        ]
        for typeName in noncanonical {
            XCTAssertThrowsError(try decode(typeName), "accepted state type \(typeName)")
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractStateDescriptor(name: "Balances", typeName: typeName)
                ),
                "encoded state type \(typeName)"
            )
        }
    }

    func testContractManifestStateTypeParserEnforcesDepthAndNodeBudgets() throws {
        func decode(_ typeName: String) throws -> ToriiContractManifest {
            let data = try JSONSerialization.data(
                withJSONObject: [
                "events":[],"enum_types":[],"permissions": [],
                    "states": [
                        ["name": "Balances", "type_name": typeName],
                    ],
                ]
            )
            return try JSONDecoder().decode(ToriiContractManifest.self, from: data)
        }

        let maximumDepth = String(repeating: "Option<", count: 255)
            + "int"
            + String(repeating: ">", count: 255)
        XCTAssertNoThrow(try decode(maximumDepth))
        let excessiveDepth = "Option<" + maximumDepth + ">"
        XCTAssertThrowsError(try decode(excessiveDepth))
        let maximumMapValueDepth = String(repeating: "Option<", count: 254)
            + "int"
            + String(repeating: ">", count: 254)
        XCTAssertNoThrow(try decode("StateMap<AccountId, \(maximumMapValueDepth)>"))
        XCTAssertThrowsError(try decode("StateMap<AccountId, \(maximumDepth)>"))

        let maximumNodes = "("
            + Array(repeating: "int", count: 255).joined(separator: ", ")
            + ")"
        XCTAssertNoThrow(try decode(maximumNodes))
        XCTAssertNoThrow(try decode("StateMap<AccountId, \(maximumNodes)>"))
        let excessiveNodes = String(maximumNodes.dropLast()) + ", int)"
        XCTAssertThrowsError(try decode(excessiveNodes))
        XCTAssertThrowsError(try decode("StateMap<AccountId, \(excessiveNodes)>"))
    }

    func testContractManifestDynamicAccessHintsUseExactV1Policy() throws {
        func payload(
            baseKey: String = "state:Balances",
            keyType: String = "AccountId",
            boundKind: String = "take",
            maxKeys: Int = 1,
            includeUnknown: Bool = false,
            stateName: String = "Balances",
            stateKeyType: String? = nil
        ) throws -> Data {
            var dynamicHint: [String: Any] = [
                "base_key": baseKey,
                "key_type": keyType,
                "bound_kind": boundKind,
                "max_keys": maxKeys,
            ]
            if includeUnknown {
                dynamicHint["unknown"] = true
            }
            return try JSONSerialization.data(withJSONObject: [
                "events":[],"enum_types":[],"permissions": [],
                "access_set_hints": [
                    "read_keys": [],
                    "write_keys": [],
                    "dynamic_reads": [dynamicHint],
                    "dynamic_writes": [],
                ],
                "states": [
                    [
                        "name": stateName,
                        "type_name": "StateMap<\(stateKeyType ?? keyType), quantity>",
                    ],
                ],
            ])
        }

        func decode(
            baseKey: String = "state:Balances",
            keyType: String = "AccountId",
            boundKind: String = "take",
            maxKeys: Int = 1,
            includeUnknown: Bool = false,
            stateName: String = "Balances",
            stateKeyType: String? = nil
        ) throws -> ToriiContractDynamicAccessHint {
            let manifest = try JSONDecoder().decode(
                ToriiContractManifest.self,
                from: payload(
                    baseKey: baseKey,
                    keyType: keyType,
                    boundKind: boundKind,
                    maxKeys: maxKeys,
                    includeUnknown: includeUnknown,
                    stateName: stateName,
                    stateKeyType: stateKeyType
                )
            )
            return try XCTUnwrap(manifest.accessSetHints?.dynamicReads.first)
        }

        let keyTypes = [
            "int",
            "decimal",
            "quantity",
            "bool",
            "string",
            "bytes",
            "DataSpaceId",
            "AccountId",
            "AssetDefinitionId",
            "AssetId",
            "NftId",
            "DomainId",
            "Name",
        ]
        for keyType in keyTypes {
            XCTAssertEqual(try decode(keyType: keyType).keyType, keyType)
            XCTAssertNoThrow(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Balances",
                        keyType: keyType,
                        boundKind: "page",
                        maxKeys: 64
                    )
                )
            )
        }
        for boundKind in ["page", "take"] {
            XCTAssertEqual(try decode(boundKind: boundKind).boundKind, boundKind)
        }
        for baseKey in ["state:Balances", "state:amount"] {
            let stateName = baseKey == "state:amount" ? "amount" : "Balances"
            XCTAssertEqual(
                try decode(baseKey: baseKey, stateName: stateName).baseKey,
                baseKey
            )
            XCTAssertNoThrow(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: baseKey,
                        keyType: "AccountId",
                        boundKind: "take",
                        maxKeys: 1
                    )
                )
            )
        }
        for maxKeys in [1, 64] {
            XCTAssertEqual(try decode(maxKeys: maxKeys).maxKeys, UInt32(maxKeys))
        }

        let invalidBaseKeys = [
            "",
            "state:",
            "state:*",
            "state:Balances.more",
            "state:Balances:Other",
            "state:Amount",
            "state:state:Balances",
            "state:match",
            "state:StateMap",
            "state:__kotodama_link_Balances",
            "state: Balances",
            "state:Balances ",
            "state:Бalances",
            "states:Balances",
            "Balances",
            "state:amount.more",
        ]
        for baseKey in invalidBaseKeys {
            XCTAssertThrowsError(try decode(baseKey: baseKey))
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: baseKey,
                        keyType: "AccountId",
                        boundKind: "take",
                        maxKeys: 1
                    )
                )
            )
        }

        let invalidKeyTypes = [
            "",
            "Json",
            "Int",
            "Amount",
            "amount",
            "AccountID",
            "Transfer",
            "StateMap",
            "StateMap<AccountId, quantity>",
            " AccountId",
            "AccountId ",
            "АccountId",
        ]
        for keyType in invalidKeyTypes {
            XCTAssertThrowsError(try decode(keyType: keyType))
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Balances",
                        keyType: keyType,
                        boundKind: "take",
                        maxKeys: 1
                    )
                )
            )
        }

        for boundKind in ["", "range", "Range", "Take", "all", "prefix", "range ", " take"] {
            XCTAssertThrowsError(try decode(boundKind: boundKind)) { error in
                if boundKind == "range" {
                    guard case DecodingError.dataCorrupted(let context) = error else {
                        XCTFail("Expected dataCorrupted for retired bound_kind, got \(error)")
                        return
                    }
                    XCTAssertEqual(context.codingPath.last?.stringValue, "bound_kind")
                    XCTAssertEqual(
                        context.debugDescription,
                        "dynamic access hint bound_kind must be take or page"
                    )
                }
            }
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Balances",
                        keyType: "AccountId",
                        boundKind: boundKind,
                        maxKeys: 1
                    )
                )
            ) { error in
                if boundKind == "range" {
                    guard case EncodingError.invalidValue(_, let context) = error else {
                        XCTFail("Expected invalidValue for retired bound_kind, got \(error)")
                        return
                    }
                    XCTAssertEqual(
                        context.debugDescription,
                        "dynamic access hint must use a canonical state declaration, "
                            + "StateMap key type, take/page bound, and max_keys in 1...64"
                    )
                }
            }
        }
        for maxKeys in [-1, 0, 65, 4_294_967_296] {
            XCTAssertThrowsError(try decode(maxKeys: maxKeys))
        }
        for maxKeys in [UInt32(0), UInt32(65), UInt32.max] {
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Balances",
                        keyType: "AccountId",
                        boundKind: "take",
                        maxKeys: maxKeys
                    )
                )
            )
        }
        XCTAssertThrowsError(try decode(includeUnknown: true))
    }

    func testContractManifestDynamicAccessHintsResolveExactDeclaredStateMaps() throws {
        let canonical = ToriiContractDynamicAccessHint(
            baseKey: "state:Balances",
            keyType: "AccountId",
            boundKind: "take",
            maxKeys: 1
        )

        func manifest(
            reads: [ToriiContractDynamicAccessHint],
            writes: [ToriiContractDynamicAccessHint],
            stateName: String = "Balances",
            stateType: String = "StateMap<AccountId, quantity>"
        ) -> ToriiContractManifest {
            ToriiContractManifest(
                accessSetHints: ToriiContractAccessSetHints(
                    dynamicReads: reads,
                    dynamicWrites: writes
                ),
                permissions: [],
                events: [],
                enumTypes: [],
                states: [
                    ToriiContractStateDescriptor(name: stateName, typeName: stateType),
                ]
            )
        }

        func payload(_ value: ToriiContractManifest) throws -> Data {
            let reads = value.accessSetHints?.dynamicReads ?? []
            let writes = value.accessSetHints?.dynamicWrites ?? []
            func render(_ hint: ToriiContractDynamicAccessHint) -> [String: Any] {
                [
                    "base_key": hint.baseKey,
                    "key_type": hint.keyType,
                    "bound_kind": hint.boundKind,
                    "max_keys": hint.maxKeys,
                ]
            }
            return try JSONSerialization.data(withJSONObject: [
                "events":[],"enum_types":[],"permissions": [],
                "access_set_hints": [
                    "read_keys": [],
                    "write_keys": [],
                    "dynamic_reads": reads.map(render),
                    "dynamic_writes": writes.map(render),
                ],
                "states": (value.states ?? []).map {
                    ["name": $0.name, "type_name": $0.typeName]
                },
            ])
        }

        let malformed = [
            manifest(reads: [canonical, canonical], writes: []),
            manifest(reads: [], writes: [canonical, canonical]),
            manifest(
                reads: [
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Missing",
                        keyType: "AccountId",
                        boundKind: "take",
                        maxKeys: 1
                    ),
                ],
                writes: []
            ),
            manifest(reads: [canonical], writes: [], stateType: "quantity"),
            manifest(
                reads: [
                    ToriiContractDynamicAccessHint(
                        baseKey: "state:Balances",
                        keyType: "Name",
                        boundKind: "take",
                        maxKeys: 1
                    ),
                ],
                writes: []
            ),
        ]
        for value in malformed {
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiContractManifest.self, from: payload(value))
            )
            XCTAssertThrowsError(try JSONEncoder().encode(value))
        }

        let amount = ToriiContractDynamicAccessHint(
            baseKey: "state:amount",
            keyType: "AccountId",
            boundKind: "page",
            maxKeys: 64
        )
        let accepted = manifest(
            reads: [amount],
            writes: [amount],
            stateName: "amount"
        )
        let decoded = try JSONDecoder().decode(
            ToriiContractManifest.self,
            from: payload(accepted)
        )
        XCTAssertEqual(decoded.accessSetHints?.dynamicReads.first?.baseKey, "state:amount")
        XCTAssertNoThrow(try JSONEncoder().encode(accepted))
    }

    func testContractManifestRejectsMalformedErrorIdentities() throws {
        for identity in ["Error<Injected>", "Invalid Error"] {
            let descriptor = ToriiContractErrorTypeDescriptor(identity: identity, variants: [.init(name: "Denied", code: 7)])
            XCTAssertThrowsError(try JSONEncoder().encode(descriptor))
            let payload = #"{"events":[],"enum_types":[],"permissions":[],"error_types":[{"identity":""# + identity + #"","variants":[{"name":"Denied","code":7}]}]}"#
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractManifest.self, from: Data(payload.utf8)))
        }
    }

    private struct ManifestFixture: Decodable {
        let manifest: ToriiContractManifest
    }

    func testExportedStructIdentitySurvivesPublicAndDurableSchemas() throws {
        struct NameVectors: Decodable { let valid: [String]; let invalid: [String] }
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while directory.path != "/" && !FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("fixtures/kotodama/exported_structs_v1.json").path
        ) { directory.deleteLastPathComponent() }
        let fixtures = directory.appendingPathComponent("fixtures/kotodama")
        let payload = try String(contentsOf: fixtures.appendingPathComponent("exported_structs_v1.json"), encoding: .utf8)
        let vectors = try JSONDecoder().decode(NameVectors.self, from: Data(contentsOf: fixtures.appendingPathComponent("exported_struct_names_v1.json")))
        let identity = "std/math@1.0.0::Math::Receipt"
        for name in vectors.valid {
            let bytes = Data(payload.replacingOccurrences(of: identity, with: name).utf8)
            let record = try JSONDecoder().decode(ManifestFixture.self, from: bytes)
            let entrypoint = try XCTUnwrap(record.manifest.entrypoints?.first)
            XCTAssertEqual(entrypoint.returnSchema?.canonicalTypeName, "struct \(name)")
            XCTAssertEqual(entrypoint.argumentSchema?.fields.first?.type.canonicalTypeName, "struct \(name)")
            XCTAssertTrue(try XCTUnwrap(record.manifest.states?.first?.typeName).contains("\(name){"))
            let encoded = try JSONEncoder().encode(record.manifest)
            XCTAssertEqual(try JSONDecoder().decode(ToriiContractManifest.self, from: encoded), record.manifest)
        }
        for name in vectors.invalid {
            let bytes = Data(payload.replacingOccurrences(of: identity, with: name).utf8)
            let root = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let manifest = try XCTUnwrap(root["manifest"] as? [String: Any])
            for removed in ["states", "entrypoints"] {
                var isolated = manifest
                isolated.removeValue(forKey: removed)
                let invalid = try JSONSerialization.data(withJSONObject: isolated)
                XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractManifest.self, from: invalid), "invalid \(removed)-independent identity: \(name)")
            }
        }
    }

    func testStaticErrorMessagesBindDeclaredVariants() throws {
        let error = ToriiContractErrorTypeDescriptor(identity: "Vault::Failure", variants: [ToriiContractErrorVariantDescriptor(name: "Missing", code: 1)])
        let message = ToriiContractErrorMessage(errorType: error.identity, code: 1, message: "残高が不足しています")
        var manifest = ToriiContractManifest(permissions: [], events: [], enumTypes: [], errorTypes: [error], errorMessages: [message])
        let encoded = try JSONEncoder().encode(manifest)
        XCTAssertEqual(try JSONDecoder().decode(ToriiContractManifest.self, from: encoded), manifest)
        for text in [" \n explanation \t", "\u{001c}", "😀"] {
            manifest.errorMessages = [.init(errorType: error.identity, code: 1, message: text)]
            let data = try JSONEncoder().encode(manifest)
            XCTAssertEqual(try JSONDecoder().decode(ToriiContractManifest.self, from: data).errorMessages?.first?.message, text)
        }
        manifest.errorMessages = [.init(errorType: error.identity, code: 1, message: "\u{0085}\u{00a0}")]
        XCTAssertThrowsError(try JSONEncoder().encode(manifest))
        manifest.errorMessages = [message, message]
        XCTAssertThrowsError(try JSONEncoder().encode(manifest))
        manifest.errorMessages = [.init(errorType: error.identity, code: 2, message: "Undeclared")]
        XCTAssertThrowsError(try JSONEncoder().encode(manifest))
        manifest.errorMessages = [.init(errorType: error.identity, code: 1, message: String(repeating: "é", count: 2049))]
        XCTAssertThrowsError(try JSONEncoder().encode(manifest))
    }

    func testTupleCursorAndStatePageBindTheCompleteKeySchema() throws {
        let key = ToriiEntrypointValueTypeV1(nodes: [.tuple(2), .leaf(.accountId), .tuple(2), .leaf(.int), .leaf(.name)])
        let cursor = ToriiEntrypointValueTypeV1(nodes: [.stateCursor(key)])
        XCTAssertEqual(cursor.canonicalTypeName, "StateCursor<(AccountId, (int, Name))>")
        let encoded = try JSONEncoder().encode(cursor)
        XCTAssertEqual(try JSONDecoder().decode(ToriiEntrypointValueTypeV1.self, from: encoded), cursor)
        var page = ToriiEntrypointValueTypeV1(nodes: [
            .structType(ToriiEntrypointStructTypeNodeV1(name: "kotodama::StatePage", fields: ["items", "next"])),
            .list(ToriiEntrypointListTypeNodeV1(capacity: 8)), .tuple(2),
        ] + key.nodes + [.leaf(.bool), .option, .stateCursor(key)])
        XCTAssertEqual(page.canonicalTypeName, "StatePage<(AccountId, (int, Name)), bool, 8>")
        var changed = key
        changed.nodes[3] = .leaf(.bool)
        page.nodes[page.nodes.count - 1] = .stateCursor(changed)
        XCTAssertNil(page.canonicalTypeName)
        for arity in [254, 255] {
            let wide = ToriiEntrypointValueTypeV1(nodes: [.stateCursor(ToriiEntrypointValueTypeV1(nodes: [.tuple(UInt16(arity))] + Array(repeating: .leaf(.int), count: arity)))])
            XCTAssertEqual(wide.wordCount != nil, arity == 254)
        }
        for raw in [
            #"{"nodes":[{"kind":"StateCursor","value":{"kind":"Int","value":null}}]}"#,
            #"{"nodes":[{"kind":"StateCursor","value":{"nodes":[{"kind":"Leaf","value":{"kind":"Json","value":null}}]}}]}"#,
            #"{"nodes":[{"kind":"StateCursor","value":{"nodes":[{"kind":"StateCursor","value":{}}]}}]}"#,
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiEntrypointValueTypeV1.self, from: Data(raw.utf8)))
        }
    }

    func testNominalErrorSharedFixturePreservesJapaneseIdentityAndUnit() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        var fixture: URL?
        while root.path != "/" {
            let candidate = root.appendingPathComponent("fixtures/kotodama/nominal_errors_v1.json")
            if FileManager.default.fileExists(atPath: candidate.path) { fixture = candidate; break }
            root.deleteLastPathComponent()
        }
        let bytes = try Data(contentsOf: XCTUnwrap(fixture))
        let record = try JSONDecoder().decode(ManifestFixture.self, from: bytes)
        let schema = try XCTUnwrap(record.manifest.entrypoints?.first?.returnSchema)
        XCTAssertEqual(schema.canonicalTypeName, "Result<(), example/vault@1.0.0::金庫::拒否>")
        XCTAssertEqual(schema.nodes[1], .unit)
        XCTAssertEqual(schema.wordCount, 1)
        XCTAssertEqual(record.manifest.errorTypes?.first?.variants.first?.name, "不足")
        XCTAssertEqual(record.manifest.errorTypes?.count, 2)
        let cursor = try XCTUnwrap(record.manifest.entrypoints?[1].returnSchema)
        XCTAssertEqual(cursor.canonicalTypeName, "Option<StateCursor<int>>")
        XCTAssertEqual(cursor.nodes[1], .stateCursor(ToriiEntrypointValueTypeV1(nodes: [.leaf(.int)])))
        XCTAssertEqual(cursor.wordCount, 1)
        XCTAssertEqual(record.manifest.entrypoints?[2].returnSchema?.canonicalTypeName, "StatePage<int, bool, 8>")
        XCTAssertEqual(record.manifest.entrypoints?[2].returnSchema?.wordCount, 2)
        let encoded = try JSONEncoder().encode(record.manifest)
        XCTAssertEqual(try JSONDecoder().decode(ToriiContractManifest.self, from: encoded), record.manifest)
        let changed = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "CapacityExceeded", with: "DifferentMeaning", range: String(decoding: bytes, as: UTF8.self).range(of: "CapacityExceeded"))
        XCTAssertThrowsError(try JSONDecoder().decode(ManifestFixture.self, from: Data(changed.utf8)))
        var stateOnly = record.manifest
        stateOnly.entrypoints = []
        XCTAssertNoThrow(try JSONEncoder().encode(stateOnly))
        stateOnly.errorTypes = []
        XCTAssertThrowsError(try JSONEncoder().encode(stateOnly))
        let unknownState = String(decoding: bytes, as: UTF8.self).replacingOccurrences(
            of: "\"type_name\": \"Result<(), example/vault@1.0.0::金庫::拒否>\"",
            with: "\"type_name\": \"Result<(), missing/vault@1.0.0::金庫::拒否>\"")
        XCTAssertThrowsError(try JSONDecoder().decode(ManifestFixture.self, from: Data(unknownState.utf8)))
        for forged in ["StatePage{anything: int}", "StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<bool>>}"] {
            let changedState = String(decoding: bytes, as: UTF8.self).replacingOccurrences(
                of: "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<int>>}", with: forged)
            XCTAssertThrowsError(try JSONDecoder().decode(ManifestFixture.self, from: Data(changedState.utf8)))
        }
    }

    func testContractManifestTriggerBoundariesRejectExactAmountSourceFormOnly() throws {
        let filter = "TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA="

        func payload(id: String, namespace: String?) -> Data {
            let encodedNamespace = namespace.map { "\"\($0)\"" } ?? "null"
            return Data(
                """
                {"id":"\(id)","repeats":{"Indefinitely":null},"filter":"\(filter)","authority":null,"metadata":{},"callback":{"namespace":\(encodedNamespace),"entrypoint":"transfer"}}
                """.utf8
            )
        }

        for (id, namespace) in [("Amount", nil), ("tick", "Amount")] {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiContractTriggerDescriptor.self,
                    from: payload(id: id, namespace: namespace)
                )
            )
        }

        let lowercase = try JSONDecoder().decode(
            ToriiContractTriggerDescriptor.self,
            from: payload(id: "amount", namespace: "RemoteLedger")
        )
        XCTAssertEqual(lowercase.id, "amount")
        XCTAssertEqual(lowercase.callback.namespace, "RemoteLedger")
    }

    func testContractManifestEnforcesStrictCrossFieldInvariants() throws {
        let boolLeaf = #"{"kind":"Leaf","value":{"kind":"Bool","value":null}}"#
        let boolSchema = "{\"fields\":[{\"name\":\"flag\",\"ty\":{\"nodes\":[\(boolLeaf)]}}]}"
        let validFilter = "TlJUMAAAl9+YQQ4oJZjALRf6FAto0QAKAAAAAAAAANzCjydU9+jNAgIAAAAFBAAAAAA="

        func descriptor(name: String = "run",
                        kind: String = "Kotoage",
                        params: String = "[]",
                        argumentSchema: String = "null",
                        returnType: String = "\"()\"",
                        returnSchema: String = #"{"nodes":[{"kind":"Unit","value":null}]}"#,
                        authorization: String = #"{"kind":"Permission","value":"Run"}"#,
                        complete: String = "true",
                        skipped: String = "[]",
                        triggers: String = "[]") -> String {
            """
            {"name":"\(name)","kind":{"kind":"\(kind)","value":null},"params":\(params),"argument_schema":\(argumentSchema),"return_type":\(returnType),"return_schema":\(returnSchema),"authorization":\(authorization),"read_keys":[],"write_keys":[],"access_hints_complete":\(complete),"access_hints_skipped":\(skipped),"triggers":\(triggers)}
            """
        }

        func manifest(_ entrypoints: [String]) -> String {
            "{\"events\":[],\"enum_types\":[],\"permissions\":[{\"name\":\"Run\",\"scope\":{\"kind\":\"Instance\",\"value\":null}}],\"entrypoints\":[\(entrypoints.joined(separator: ","))]}"
        }

        func trigger(id: String = "tick", callback: String = "run") -> String {
            """
            {"id":"\(id)","repeats":{"Indefinitely":null},"filter":"\(validFilter)","authority":null,"metadata":{},"callback":{"namespace":null,"entrypoint":"\(callback)"}}
            """
        }

        let invalid = [
            #"{"unknown":true}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"features_bitmap":4}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"Option"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"__kotodama_link_private"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"seiyaku_name":"state_map_get"}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"states":[{"name":"Option","type_name":"bool"}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"error_types":[{"identity":"Error<Injected>","variants":[{"name":"Denied","code":1}]}]}"#,
            #"{"events":[],"enum_types":[],"permissions":[],"provenance":{"signer":"fixture","signature":"sig","unknown":true}}"#,
            manifest([descriptor(authorization: "null")]),
            manifest([descriptor(name: "start", kind: "Hajimari", authorization: "null")]),
            manifest([descriptor(name: "始まり", kind: "Hajimari", authorization: "\"Deploy\"")]),
            manifest([descriptor(name: "hajimari", kind: "View", authorization: "null")]),
            manifest([descriptor(
                params: #"[{"name":"flag","type_name":"int"}]"#,
                argumentSchema: boolSchema
            )]),
            manifest([descriptor(
                returnType: "\"int\"",
                returnSchema: "{\"nodes\":[\(boolLeaf)]}"
            )]),
            manifest([descriptor(complete: "true", skipped: "[\"dynamic\"]")]),
            manifest([descriptor(complete: "false", skipped: "[]")]),
            manifest([descriptor(triggers: "[\(trigger(callback: "missing"))]")]),
            manifest([
                descriptor(name: "inspect", kind: "View", authorization: "null"),
                descriptor(triggers: "[\(trigger(callback: "inspect"))]"),
            ]),
            manifest([descriptor(triggers: "[\(trigger()),\(trigger())]")]),
            manifest([descriptor(triggers: "[\(trigger().replacingOccurrences(of: #"{"Indefinitely":null}"#, with: #"{"kind":"Indefinitely","value":null}"#))]")]),
            manifest([descriptor(triggers: "[\(trigger().replacingOccurrences(of: validFilter, with: "%%%"))]")]),
            manifest([descriptor().replacingOccurrences(
                of: #""triggers":[]"#,
                with: #""triggers":[],"unknown":true"#
            )]),
        ]

        for payload in invalid {
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiContractManifest.self,
                    from: Data(payload.utf8)
                ),
                "accepted inconsistent manifest payload: \(payload)"
            )
        }
    }

    func testEveryPublicEntrypointRequiresAnExplicitReturnSchema() throws {
        func payload(_ returns: String) -> Data {
            Data("""
            {"name":"done","kind":{"kind":"View","value":null},"authorization":{"kind":"Anyone","value":null},"params":[]\(returns)}
            """.utf8)
        }
        for returns in [
            "",
            #","return_type":null,"return_schema":null"#,
            #","return_type":"()""#,
            #","return_schema":{"nodes":[{"kind":"Unit","value":null}]}"#,
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(
                ToriiContractEntrypointDescriptor.self, from: payload(returns)))
        }
        let unit = try JSONDecoder().decode(ToriiContractEntrypointDescriptor.self, from: payload(
            #","return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]}"#))
        XCTAssertEqual(unit.returnType, "()")
        XCTAssertEqual(unit.returnSchema?.wordCount, 1)
        XCTAssertNoThrow(try JSONEncoder().encode(unit))
        for missingType in [false, true] {
            for missingSchema in [false, true] where missingType || missingSchema {
                var invalid = unit
                if missingType { invalid.returnType = nil }
                if missingSchema { invalid.returnSchema = nil }
                XCTAssertThrowsError(try JSONEncoder().encode(invalid))
            }
        }
    }

    func testContractManifestAcceptsRomanizedAndJapaneseLifecycleSelectors() throws {
        let selectors = [
            ("hajimari", "Hajimari"),
            ("始まり", "Hajimari"),
            ("kaizen", "Kaizen"),
            ("改善", "Kaizen"),
        ]
        for (name, kind) in selectors {
            let payload = """
            {"events":[],"enum_types":[],"permissions":[],"entrypoints":[{"name":"\(name)","kind":{"kind":"\(kind)","value":null},"params":[],"argument_schema":null,"return_type":"()","return_schema":{"nodes":[{"kind":"Unit","value":null}]},"authorization":{"kind":"RuntimeLifecycle","value":null},"read_keys":[],"write_keys":[],"access_hints_complete":true,"access_hints_skipped":[],"triggers":[]}]}
            """
            let manifest = try JSONDecoder().decode(
                ToriiContractManifest.self,
                from: Data(payload.utf8)
            )
            XCTAssertEqual(manifest.entrypoints?.first?.name, name)
        }
    }

    func testContractManifestAcceptsOnlyBrandedV1EntrypointKinds() throws {
        let cases: [(String, ToriiContractEntrypointKind)] = [
            ("Kotoage", .kotoage),
            ("View", .view),
            ("Hajimari", .hajimari),
            ("Kaizen", .kaizen),
        ]
        for (label, expected) in cases {
            let payload = #"{"kind":"\#(label)","value":null}"#
            XCTAssertEqual(
                try JSONDecoder().decode(
                    ToriiContractEntrypointKind.self,
                    from: Data(payload.utf8)
                ),
                expected
            )
        }
    }

    func testContractManifestAcceptsOnlyFirstReleaseNumericLeafKinds() throws {
        for (label, expected, canonicalName) in [
            ("Int", ToriiEntrypointValueKindV1.int, "int"),
            ("Decimal", ToriiEntrypointValueKindV1.decimal, "decimal"),
            ("Quantity", ToriiEntrypointValueKindV1.quantity, "quantity"),
        ] {
            let payload = #"{"nodes":[{"kind":"Leaf","value":{"kind":"\#(label)","value":null}}]}"#
            let valueType = try JSONDecoder().decode(
                ToriiEntrypointValueTypeV1.self,
                from: Data(payload.utf8)
            )
            guard case let .leaf(kind) = valueType.nodes[0] else {
                return XCTFail("expected numeric leaf")
            }
            XCTAssertEqual(kind, expected)
            XCTAssertEqual(valueType.canonicalTypeName, canonicalName)
        }

        for retired in ["U128", "Amount"] {
            let payload = #"{"nodes":[{"kind":"Leaf","value":{"kind":"\#(retired)","value":null}}]}"#
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiEntrypointValueTypeV1.self,
                    from: Data(payload.utf8)
                )
            )
        }
    }

    func testContractManifestDecodesCheckedInCanonicalKotodamaManifests() throws {
        let fixtures = [
            ("authority_probe.manifest.json", "AuthorityProbe"),
            ("irohaswap.manifest.json", "IrohaSwap"),
            ("ivm_smoke.manifest.json", "SmokeTransfer"),
            ("prediction_market.manifest.json", "PredictionMarket"),
        ]
        let demo = repositoryRootURL().appendingPathComponent("demo", isDirectory: true)
        for (filename, expectedName) in fixtures {
            let data = try Data(contentsOf: demo.appendingPathComponent(filename))
            let manifest = try JSONDecoder().decode(ToriiContractManifest.self, from: data)
            XCTAssertEqual(manifest.seiyakuName, expectedName)
            XCTAssertEqual(manifest.codeHash?.count, 64)
            XCTAssertEqual(manifest.abiHash?.count, 64)
            XCTAssertFalse(manifest.entrypoints?.isEmpty ?? true)
        }
    }

    func testContractCallBoundaryConsumesSharedRustArgumentRecordFixture() async throws {
        let fixtureURL = repositoryRootURL()
            .appendingPathComponent("fixtures/kotodama/entrypoint_argument_record_v1.json")
        let fixtureData = try Data(contentsOf: fixtureURL)
        guard let fixture = try JSONSerialization.jsonObject(with: fixtureData) as? [String: Any],
              let boundary = fixture["torii_boundary"] as? [String: Any],
              let fixtureAuthority = boundary["authority"] as? String,
              let contractAlias = boundary["contract_alias"] as? String,
              let entrypoint = boundary["entrypoint"] as? String,
              let fixturePayload = boundary["payload"] as? [String: Any],
              let fixtureFeePayment = boundary["fee_payment"] as? [String: Any],
              let schema = fixture["entrypoint_argument_schema_v1"] as? [String: Any],
              let schemaHash = schema["schema_hash_hex"] as? String,
              let record = fixture["entrypoint_argument_record_v1"] as? [String: Any],
              let recordHex = record["norito_hex"] as? String else {
            return XCTFail("invalid shared Kotodama argument-record fixture")
        }
        XCTAssertNoThrow(try AccountAddress.parseEncoded(fixtureAuthority))
        let authority = self.authority
        XCTAssertEqual(fixture["codec"] as? String, "EntrypointArgumentRecordV1")
        XCTAssertEqual(fixture["generator"] as? String, "ivm_abi::arguments::encode_argument_record_from_json")
        XCTAssertNotNil(schemaHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression))
        XCTAssertNotNil(recordHex.range(of: "^(?:[0-9a-f]{2})+$", options: .regularExpression))
        XCTAssertEqual(
            fixturePayload["exact_int"] as? String,
            "1606938044258990275541962092341162602522202993782792835301376"
        )
        XCTAssertEqual(
            fixturePayload["exact_decimal"] as? String,
            "-12345678901234567890.125"
        )
        XCTAssertEqual(
            fixturePayload["exact_quantity"] as? String,
            "12345678901234567890.0000000000000000000000000001"
        )

        let payloadData = try JSONSerialization.data(withJSONObject: fixturePayload)
        let payload = try JSONDecoder().decode(ToriiJSONValue.self, from: payloadData)
        let feePaymentData = try JSONSerialization.data(withJSONObject: fixtureFeePayment)
        let feePayment = try JSONDecoder().decode(FeePaymentIntent.self, from: feePaymentData)
        let request = ToriiContractCallRequest(
            authority: authority,
            contractAlias: contractAlias,
            entrypoint: entrypoint,
            payload: payload,
            feePayment: feePayment
        )

        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/call")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            guard let body = self.bodyData(from: request),
                  let submitted = try JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let submittedPayload = submitted["payload"] as? [String: Any] else {
                XCTFail("contract call did not send a JSON object")
                throw NSError(domain: "stub", code: -1)
            }

            XCTAssertEqual(submitted["authority"] as? String, authority)
            XCTAssertEqual(submitted["contract_alias"] as? String, contractAlias)
            XCTAssertNil(submitted["contract_address"])
            XCTAssertEqual(submitted["entrypoint"] as? String, entrypoint)
            XCTAssertEqual(submittedPayload as NSDictionary, fixturePayload as NSDictionary)
            XCTAssertEqual(
                submitted["fee_payment"] as? NSDictionary,
                fixtureFeePayment as NSDictionary
            )
            XCTAssertNil(submitted["gas_limit"])
            XCTAssertNil(submitted["argument_record"])
            XCTAssertNil(submitted["argument_record_norito_hex"])

            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 503,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/plain"]
            )!
            return (response, Data("fixture boundary reached".utf8))
        }

        await XCTAssertThrowsErrorAsync(try await makeClient().callContract(request)) { error in
            guard case let ToriiClientError.api(apiError) = error else {
                return XCTFail("expected an api error, got \(error)")
            }
            let code = apiError.status
            XCTAssertEqual(code, 503)
        }
    }

    func testCallContractParsesResponse() throws {
        let expectation = expectation(description: "call contract")
        let feePayment = testFeePayment(gasLimit: 7)
        let codeHash = String(repeating: "d", count: 64)
        let abiHash = String(repeating: "e", count: 64)
        let txHash = String(repeating: "f", count: 64)
        let entrypointHash = String(repeating: "a", count: 64)
        let payloadDigest = String(repeating: "b", count: 64)
        let contractAddress = "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
        let payload = ToriiJSONValue.object(["amount": .string("10")])
        let invocation = try TransactionContractInvocation(
            contractAddress: contractAddress,
            expectedCodeHash: Data(hexString: codeHash)!,
            entrypoint: "create",
            arguments: CanonicalUnsignedTransactionTestSupport.contractArgumentRecord(for: payload)
        )
        var requestBody = ToriiContractCallRequest(
            authority: authority,
            contractAlias: "mint::universal",
            entrypoint: "create",
            payload: payload,
            draftIntent: try ToriiContractCallDraftIntent(invocation: invocation, metadata: [:]),
            creationTimeMs: 321,
            transactionTtlMs: 60_000,
            feePayment: feePayment
        )
        let retainedPayload = try CanonicalUnsignedTransactionTestSupport.contractPayload(
            request: requestBody,
            contractAddress: contractAddress,
            codeHashHex: codeHash,
            networkId: TestNetworkIds.canonical
        )
        let keypair = try Keypair(privateKeyBytes: canonicalSigningSeed)
        requestBody.publicKeyHex = keypair.publicKey.map { String(format: "%02x", $0) }.joined()
        requestBody.signatureB64 = try keypair.sign(IrohaHash.hash(retainedPayload)).base64EncodedString()
        requestBody.transactionPayloadB64 = retainedPayload.base64EncodedString()
        let signedRequestBody = requestBody
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/call")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["authority"] as? String, self.authority)
            XCTAssertNil(json["private_key"])
            XCTAssertEqual(json["public_key_hex"] as? String, signedRequestBody.publicKeyHex)
            XCTAssertEqual(json["signature_b64"] as? String, signedRequestBody.signatureB64)
            XCTAssertEqual(json["transaction_payload_b64"] as? String, signedRequestBody.transactionPayloadB64)
            XCTAssertEqual(json["contract_alias"] as? String, "mint::universal")
            XCTAssertEqual(json["entrypoint"] as? String, "create")
            XCTAssertEqual(
                json["fee_payment"] as? NSDictionary,
                testFeePaymentObject(feePayment) as NSDictionary
            )
            XCTAssertNil(json["gas_limit"])
            XCTAssertNil(json["gas_asset_id"])
            XCTAssertNil(json["fee_sponsor"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"submitted":true,"dataspace":"universal","contract_address":"irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh","code_hash_hex":"\(codeHash)","abi_hash_hex":"\(abiHash)","creation_time_ms":321,"transaction_ttl_ms":60000,"tx_hash_hex":"\(txHash)","pipeline_status":null,"transaction_payload_b64":null,"signing_message_b64":null,"entrypoint_hash_hex":"\(entrypointHash)","entrypoint":"create","operation_receipt":{"operation_kind":"contract_call","status":"submitted","transport":"torii","dataspace":"universal","contract_alias":"mint::universal","contract_address":"irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh","code_hash_hex":"\(codeHash)","abi_hash_hex":"\(abiHash)","tx_hash_hex":"\(txHash)","entrypoint":"create","entrypoint_hash_hex":"\(entrypointHash)","gas_limit":7,"gas_used":null,"fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":7}},"payload_digest_hex":"\(payloadDigest)"}}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        makeClient().callContract(signedRequestBody) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.ok)
                XCTAssertTrue(response.submitted)
                XCTAssertEqual(response.dataspace, "universal")
                XCTAssertEqual(response.contractAddress, "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh")
                XCTAssertEqual(response.codeHashHex, codeHash)
                XCTAssertEqual(response.abiHashHex, abiHash)
                XCTAssertEqual(response.creationTimeMs, 321)
                XCTAssertEqual(response.txHashHex, txHash)
                XCTAssertNil(response.pipelineStatus)
                XCTAssertEqual(response.transactionTtlMs, 60_000)
                XCTAssertEqual(response.entrypointHashHex, entrypointHash)
                XCTAssertNil(response.transactionPayloadB64)
                XCTAssertNil(response.signingMessageB64)
                XCTAssertEqual(response.entrypoint, "create")
                XCTAssertEqual(response.operationReceipt.operationKind, "contract_call")
                XCTAssertEqual(response.operationReceipt.gasLimit, 7)
                XCTAssertNil(response.operationReceipt.gasUsed)
                XCTAssertEqual(response.operationReceipt.feePayment, feePayment)
                XCTAssertEqual(response.operationReceipt.payloadDigestHex, payloadDigest)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testCallContractRejectsZeroGasLimit() {
        let request = ToriiContractCallRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            contractAlias: "mint::universal",
            entrypoint: "create",
            feePayment: testFeePayment(gasLimit: 0)
        )
        XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    func testCallContractRejectsAmbiguousContractTarget() {
        let request = ToriiContractCallRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            contractAddress: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
            contractAlias: "mint::universal",
            entrypoint: "create",
            feePayment: testFeePayment(gasLimit: 7)
        )
        XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    func testCallContractRejectsBlankEntrypoint() {
        let request = ToriiContractCallRequest(
            authority: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            contractAlias: "mint::universal",
            entrypoint: "   ",
            feePayment: testFeePayment(gasLimit: 7)
        )
        XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    func testCallContractResponseRequiresOperationReceipt() {
        let codeHash = String(repeating: "d", count: 64)
        let abiHash = String(repeating: "e", count: 64)
        let payload = """
        {"ok":true,"submitted":true,"dataspace":"universal","code_hash_hex":"\(codeHash)","abi_hash_hex":"\(abiHash)","creation_time_ms":1,"entrypoint":"create"}
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractCallResponse.self, from: payload))
    }

    func testProposeMultisigEncodesStructuredJsonInstructions() throws {
        let expectation = expectation(description: "propose multisig")
        let proposalId = String(repeating: "a", count: 64)
        let feePayment = testFeePayment()
        let resolvedAccount = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let executable = CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([1])])
        let transactionPayload = try CanonicalUnsignedTransactionTestSupport.transactionPayload(
            networkId: TestNetworkIds.canonical,
            authority: resolvedAccount,
            creationTimeMs: 123,
            executable: executable,
            timeToLiveMs: ToriiMultisigUnsignedTransactionIntent.transactionTtlMs,
            feePayment: feePayment
        )
        let signingMessage = IrohaHash.hash(transactionPayload)
        let intent = try ToriiMultisigUnsignedTransactionIntent(
            networkId: TestNetworkIds.canonical,
            resolvedMultisigAccountId: resolvedAccount,
            instructionsHash: proposalId,
            executable: executable,
            metadata: [:]
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["multisig_account_alias"] as? String, "cbdc@banka")
            XCTAssertEqual(json["signer_account_id"] as? String, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(json["creation_time_ms"] as? Int, 123)
            XCTAssertEqual(
                json["fee_payment"] as? NSDictionary,
                testFeePaymentObject(feePayment) as NSDictionary
            )
            XCTAssertNil(json["fee_sponsor"])
            XCTAssertNil(json["validation_fee_policy_version"])
            XCTAssertNil(json["validation_fee_policy_hash"])
            XCTAssertNil(json["validation_fee_hijiri_fee_quote_hash"])
            XCTAssertNil(json["validation_fee_instruction_index"])
            XCTAssertNil(json["validation_fee_transfer_entry_index"])
            XCTAssertNil(json["unsigned_transaction_intent"])
            let instructions = json["instructions"] as? [[String: Any]]
            XCTAssertEqual(instructions?.first?["kind"] as? String, "Transfer")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"\(resolvedAccount)","submitted":false,"proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","creation_time_ms":123,"fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}},"transaction_payload_b64":"\(transactionPayload.base64EncodedString())","signing_message_b64":"\(signingMessage.base64EncodedString())"}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            creationTimeMs: 123,
            instructions: [
                try ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
            ],
            feePayment: feePayment,
            unsignedTransactionIntent: intent
        )
        makeClient().proposeMultisig(request) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.ok)
                XCTAssertEqual(response.resolvedMultisigAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
                XCTAssertEqual(response.proposalId, proposalId)
                XCTAssertEqual(response.instructionsHash, proposalId)
                XCTAssertEqual(response.creationTimeMs, 123)
                XCTAssertEqual(response.transactionPayloadB64, transactionPayload.base64EncodedString())
                XCTAssertEqual(response.signingMessageB64, signingMessage.base64EncodedString())
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigEncodesTheExactTypedRetailFeeAssessment() throws {
        struct Fixture: Decodable { let assessment: RetailFeeAssessmentV1 }
        let fixtureURL = try XCTUnwrap(Bundle.module.url(
            forResource: "retail_fee_codec_v1",
            withExtension: "json"
        ))
        let assessment = try JSONDecoder().decode(
            Fixture.self,
            from: Data(contentsOf: fixtureURL)
        ).assessment
        let signer = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountId: signer),
            signerAccountId: signer,
            validationFeeAssessment: assessment,
            instructions: [try ToriiMultisigProposeInstruction(base64: "AQID")],
            feePayment: .authority(chargeLimits: [], gasLimit: nil)
        )
        let native = try ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountId: signer),
            signerAccountId: signer,
            validationFeeAssessment: assessment,
            noritoInstructionBoxBytes: [Data([0x01, 0x02, 0x03])],
            feePayment: .authority(chargeLimits: [], gasLimit: nil)
        )
        XCTAssertEqual(native.validationFeeAssessment, assessment)
        XCTAssertEqual(native.instructions, request.instructions)
        let payload = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        )
        let encodedAssessment = try XCTUnwrap(
            payload["validation_fee_assessment"] as? [String: Any]
        )
        let expectedAssessment = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(assessment)) as? [String: Any]
        )
        XCTAssertEqual(
            Set(encodedAssessment.keys),
            Set([
                "account_id", "retail_enrolled", "billing_month_start_ms",
                "policy_revision", "payments_used_before", "qualifying_payments",
                "fee_minor", "state_commitment", "intent_hash", "expires_at_ms"
            ])
        )
        XCTAssertEqual(encodedAssessment as NSDictionary, expectedAssessment as NSDictionary)
        XCTAssertEqual(
            Set(payload.keys),
            Set([
                "multisig_account_id", "signer_account_id", "fee_payment",
                "validation_fee_assessment", "instructions"
            ])
        )
    }

    func testProposeMultisigSendsWholeNoritoDtoBody() {
        let expectation = expectation(description: "propose multisig native body")
        let proposalId = String(repeating: "b", count: 64)
        let txHash = String(repeating: "c", count: 64)
        let noritoBody = Data([0x4e, 0x52, 0x54, 0x30, 0x01, 0x02, 0x03])
        let resolvedAccount = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(self.bodyData(from: request), noritoBody)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"\(resolvedAccount)","submitted":true,"proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","tx_hash_hex":"\(txHash)","creation_time_ms":123,"fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}}}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        makeClient().proposeMultisig(noritoBody: noritoBody) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.ok)
                XCTAssertEqual(response.proposalId, proposalId)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigInstructionEncodesNativeInstructionStrings() throws {
        let base64Instruction = try ToriiMultisigProposeInstruction(base64: "AQID")
        let encodedBase64 = try JSONEncoder().encode(base64Instruction)
        XCTAssertEqual(String(data: encodedBase64, encoding: .utf8), "\"AQID\"")

        let bytesInstruction = try ToriiMultisigProposeInstruction(
            noritoInstructionBoxBytes: Data([0x4e, 0x52, 0x54, 0x30])
        )
        let encodedBytes = try JSONEncoder().encode(bytesInstruction)
        XCTAssertEqual(String(data: encodedBytes, encoding: .utf8), "\"TlJUMA==\"")

        XCTAssertThrowsError(try ToriiMultisigProposeInstruction(json: .string("AQID"))) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }
    }

    func testSwiftNexusTransferInstructionBoxUsesNativeNoritoWhenBridgeAvailable() throws {
        let authority = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let destination = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
        let sourceAsset = "61CtjvNd9T3THAR65GsMVHr82Bjc#\(authority)"
        let instruction = try SwiftNexusTransactionCodec().buildTransferInstructionBox(
            input: NexusTransferInput(
                sourceAssetID: sourceAsset,
                quantity: "5",
                destinationAccountID: destination,
                feePayment: .authority(chargeLimits: [], gasLimit: nil),
            ),
            accountChainDiscriminant: 753
        )
        let nativeMagic = Data([0x4e, 0x52, 0x54, 0x30])
        try requireNativeTestCapability(
            instruction.prefix(nativeMagic.count) == nativeMagic,
            "Native transfer InstructionBox bridge is not available in this artifact."
        )

        let wrapped = try ToriiMultisigProposeInstruction(noritoInstructionBoxBytes: instruction)
        let encoded = try JSONEncoder().encode(wrapped)
        let base64 = try JSONDecoder().decode(String.self, from: encoded)
        let decoded = try XCTUnwrap(Data(base64Encoded: base64))
        XCTAssertEqual(decoded.prefix(nativeMagic.count), nativeMagic)
    }

    func testProposeMultisigRejectsEmptyInstructionBytesAndBadRequestShape() {
        XCTAssertThrowsError(try ToriiMultisigProposeInstruction(noritoInstructionBoxBytes: Data())) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }

        let signer = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let instruction = try! ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
        let ambiguousSelectorRequest = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(
                multisigAccountId: signer,
                multisigAccountAlias: "cbdc@banka"
            ),
            signerAccountId: signer,
            instructions: [instruction],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        XCTAssertThrowsError(try JSONEncoder().encode(ambiguousSelectorRequest)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }

        let emptyBatchRequest = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: signer,
            instructions: [],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        XCTAssertThrowsError(try JSONEncoder().encode(emptyBatchRequest)) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("Expected invalidPayload error")
            }
        }

    }

    func testProposeMultisigRejectsMalformedResponseFields() {
        let expectation = expectation(description: "propose multisig malformed response")
        let instruction = try! ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","instructions_hash":"aa","signing_message_b64":"not base64"}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            instructions: [instruction],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        makeClient().proposeMultisig(request) { result in
            switch result {
            case .success:
                XCTFail("Malformed multisig response should be rejected")
            case .failure(let error):
                guard case ToriiClientError.decoding = error else {
                    return XCTFail("Expected decoding error, got \(error)")
                }
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigRejectsFalseOkResponse() {
        let expectation = expectation(description: "propose multisig false ok response")
        let instruction = try! ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":false,"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            instructions: [instruction],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        makeClient().proposeMultisig(request) { result in
            switch result {
            case .success:
                XCTFail("False ok response should be rejected")
            case .failure(let error):
                guard case ToriiClientError.decoding = error else {
                    return XCTFail("Expected decoding error, got \(error)")
                }
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigRejectsEmptySigningMessageResponse() {
        let expectation = expectation(description: "propose multisig empty signing message")
        let instruction = try! ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","signing_message_b64":""}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            instructions: [instruction],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        makeClient().proposeMultisig(request) { result in
            switch result {
            case .success:
                XCTFail("Empty signing message should be rejected")
            case .failure(let error):
                guard case ToriiClientError.decoding = error else {
                    return XCTFail("Expected decoding error, got \(error)")
                }
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigRejectsNegativeResponseCreationTime() {
        let expectation = expectation(description: "propose multisig negative creation time")
        let instruction = try! ToriiMultisigProposeInstruction(object: ["kind": .string("Transfer")])
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/propose")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","creation_time_ms":-1}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            instructions: [instruction],
            feePayment: .authority(chargeLimits: [], gasLimit: nil),
        )
        makeClient().proposeMultisig(request) { result in
            switch result {
            case .success:
                XCTFail("Negative response creation time should be rejected")
            case .failure(let error):
                guard case ToriiClientError.decoding = error else {
                    return XCTFail("Expected decoding error, got \(error)")
                }
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testProposeMultisigContractCallEncodesAliasSelector() {
        let expectation = expectation(description: "propose multisig contract call")
        let proposalId = String(repeating: "a", count: 64)
        let feePayment = testFeePayment(gasLimit: 5)
        let resolvedAccount = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let executable = CanonicalUnsignedTransactionTestSupport.instructionExecutable([Data([1])])
        let transactionPayload = try! CanonicalUnsignedTransactionTestSupport.transactionPayload(
            networkId: TestNetworkIds.canonical,
            authority: resolvedAccount,
            creationTimeMs: 123,
            executable: executable,
            timeToLiveMs: ToriiMultisigUnsignedTransactionIntent.transactionTtlMs,
            feePayment: feePayment
        )
        let signingMessage = IrohaHash.hash(transactionPayload)
        let intent = try! ToriiMultisigUnsignedTransactionIntent(
            networkId: TestNetworkIds.canonical,
            resolvedMultisigAccountId: resolvedAccount,
            instructionsHash: proposalId,
            executable: executable,
            metadata: [:]
        )
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/call/multisig/propose")
            XCTAssertEqual(request.httpMethod, "POST")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["multisig_account_alias"] as? String, "cbdc@banka")
            XCTAssertNil(json["private_key"])
            XCTAssertEqual(json["signer_account_id"] as? String, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(json["contract_alias"] as? String, "mint::universal")
            XCTAssertEqual(json["entrypoint"] as? String, "execute")
            XCTAssertEqual(
                json["fee_payment"] as? NSDictionary,
                testFeePaymentObject(feePayment) as NSDictionary
            )
            XCTAssertNil(json["gas_limit"])
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"\(resolvedAccount)","submitted":false,"proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","creation_time_ms":123,"fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":5}},"transaction_payload_b64":"\(transactionPayload.base64EncodedString())","signing_message_b64":"\(signingMessage.base64EncodedString())"}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigContractCallProposeRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            signerAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            contractAlias: "mint::universal",
            entrypoint: "execute",
            payload: .object(["amount": .string("10")]),
            feePayment: feePayment,
            unsignedTransactionIntent: intent
        )
        makeClient().proposeMultisigContractCall(request) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.ok)
                XCTAssertEqual(response.resolvedMultisigAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
                XCTAssertEqual(response.proposalId, proposalId)
                XCTAssertEqual(response.instructionsHash, proposalId)
                XCTAssertEqual(response.creationTimeMs, 123)
                XCTAssertEqual(response.transactionPayloadB64, transactionPayload.base64EncodedString())
                XCTAssertEqual(response.signingMessageB64, signingMessage.base64EncodedString())
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testSignatureB64RequestsRejectNoncanonicalBase64Text() throws {
        let account = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let signer = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
        let canonicalSignature = Data(repeating: 0x01, count: 64).base64EncodedString()
        let invalidSignatures = [
            " \(canonicalSignature)",
            noncanonicalStandardBase64PadBitAlias(canonicalSignature)
        ]

        for signatureB64 in invalidSignatures {
            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiContractCallRequest(
                        authority: account,
                        signatureB64: signatureB64,
                        contractAlias: "mint::universal",
                        entrypoint: "create",
                        feePayment: testFeePayment(gasLimit: 1)
                    )
                )
            ) { error in
                XCTAssertTrue("\(error)".contains("signature_b64"))
            }

            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiMultisigProposeRequest(
                        selector: ToriiMultisigAccountSelector(multisigAccountId: account),
                        signerAccountId: signer,
                        signatureB64: signatureB64,
                        instructions: [try ToriiMultisigProposeInstruction(base64: "AQID")],
                        feePayment: .authority(chargeLimits: [], gasLimit: nil),
                    )
                )
            ) { error in
                XCTAssertTrue("\(error)".contains("signature_b64"))
            }

            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiMultisigContractCallProposeRequest(
                        selector: ToriiMultisigAccountSelector(multisigAccountId: account),
                        signerAccountId: signer,
                        signatureB64: signatureB64,
                        contractAlias: "mint::universal",
                        entrypoint: "create",
                        feePayment: testFeePayment(gasLimit: 1)
                    )
                )
            ) { error in
                XCTAssertTrue("\(error)".contains("signature_b64"))
            }

            XCTAssertThrowsError(
                try JSONEncoder().encode(
                    ToriiMultisigContractCallApproveRequest(
                        selector: ToriiMultisigAccountSelector(multisigAccountId: account),
                        signerAccountId: signer,
                        signatureB64: signatureB64,
                        proposalId: String(repeating: "b", count: 64),
                        feePayment: testFeePayment()
                    )
                )
            ) { error in
                XCTAssertTrue("\(error)".contains("signature_b64"))
            }

        }
    }

    func testApproveMultisigContractCallEncodesConcreteSelector() {
        let expectation = expectation(description: "approve multisig contract call")
        let proposalId = String(repeating: "b", count: 64)
        let txHash = String(repeating: "c", count: 64)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/call/multisig/approve")
            XCTAssertEqual(request.httpMethod, "POST")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertNil(json["private_key"])
            XCTAssertEqual(json["multisig_account_id"] as? String, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            XCTAssertEqual(json["signer_account_id"] as? String, "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
            XCTAssertEqual(json["proposal_id"] as? String, proposalId)
            XCTAssertEqual(json["signature_b64"] as? String, "AQ==")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"ok":true,"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","submitted":true,"proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","tx_hash_hex":"\(txHash)","executed_tx_hash_hex":"\(txHash)","creation_time_ms":123,"fee_payment":{"payer":"authority","value":{"charge_limits":[],"gas_limit":null}}}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigContractCallApproveRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
            signerAccountId: "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
            signatureB64: "AQ==",
            proposalId: proposalId,
            feePayment: testFeePayment()
        )
        makeClient().approveMultisigContractCall(request) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.ok)
                XCTAssertEqual(response.proposalId, proposalId)
                XCTAssertEqual(response.txHashHex, txHash)
                XCTAssertEqual(response.executedTxHashHex, txHash)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGetMultisigSpecDecodesResolvedAccount() {
        let expectation = expectation(description: "multisig spec")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/spec")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["multisig_account_alias"] as? String, "cbdc@bankb")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","spec":{"quorum":2,"transaction_ttl_ms":60000}}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigSpecRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@bankb")
        )
        makeClient().getMultisigSpec(request, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.resolvedMultisigAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
                XCTAssertEqual(response.spec["quorum"], .number(2))
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGetMultisigSpecAcceptsDomainScopedAlias() {
        let expectation = expectation(description: "multisig spec with domain-scoped alias")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/spec")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["multisig_account_alias"] as? String, "cbdc@banka.universal")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","spec":{"quorum":2,"transaction_ttl_ms":60000}}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigSpecRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka.universal")
        )
        makeClient().getMultisigSpec(request, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.resolvedMultisigAccountId, "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGetMultisigSpecRejectsUnsupportedAliasShape() {
        let request = ToriiMultisigSpecRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka.universal.extra")
        )

        XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
            guard case let ToriiClientError.invalidPayload(message) = error else {
                return XCTFail("Expected invalidPayload, got \(error)")
            }
            XCTAssertTrue(
                message.contains("name@dataspace or name@domain.dataspace"),
                "Unexpected message: \(message)"
            )
        }
    }

    func testQueryMultisigProposalsDecodesEntries() {
        let expectation = expectation(description: "multisig proposals query")
        let proposalId = String(repeating: "d", count: 64)
        let approverId = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/proposals/query")
            XCTAssertNotEqual(request.url?.path, "/v1/multisig/proposals/list")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["status"] as? [String], ["FINALIZED"])
            XCTAssertEqual(json["cursor"] as? String, "page-1")
            XCTAssertEqual(json["limit"] as? Int, 25)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","proposals":[{"proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","operation_type":"TRANSFER","intent":{"asset_definition_id":"pkr#sbp"},"proposal":{"approvals":["\(approverId)"]},"status":"FINALIZED","terminal_at_ms":123}],"next_cursor":"page-2"}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposalsQueryRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            status: [.finalized],
            cursor: "page-1",
            limit: 25
        )
        makeClient().queryMultisigProposals(request, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.proposals.count, 1)
                XCTAssertEqual(response.proposals.first?.proposalId, proposalId)
                XCTAssertEqual(response.proposals.first?.operationType, "TRANSFER")
                XCTAssertEqual(response.proposals.first?.status, .finalized)
                XCTAssertEqual(response.proposals.first?.terminalAtMs, 123)
                XCTAssertEqual(response.nextCursor, "page-2")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testResolveMultisigProposalDecodesProposalResolveResponse() {
        let expectation = expectation(description: "multisig proposal resolve")
        let proposalId = String(repeating: "e", count: 64)
        let approverOne = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
        let approverTwo = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/multisig/proposals/resolve")
            XCTAssertNotEqual(request.url?.path, "/v1/multisig/proposals/get")
            guard let body = self.bodyData(from: request),
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                XCTFail("missing JSON body")
                throw NSError(domain: "stub", code: -1)
            }
            XCTAssertEqual(json["instructions_hash"] as? String, proposalId)
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let bodyData = """
            {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","operation_type":"TRANSFER","intent":null,"proposal":{"approvals":["\(approverOne)","\(approverTwo)"]},"status":"COLLECTING_SIGNATURES","terminal_at_ms":null}
            """.data(using: .utf8)!
            return (response, bodyData)
        }

        let request = ToriiMultisigProposalsResolveRequest(
            selector: ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka"),
            instructionsHash: proposalId
        )
        makeClient().resolveMultisigProposal(request, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.proposalId, proposalId)
                XCTAssertEqual(response.instructionsHash, proposalId)
                XCTAssertEqual(response.operationType, "TRANSFER")
                XCTAssertEqual(response.status, .collectingSignatures)
                XCTAssertNil(response.terminalAtMs)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testQueryMultisigProposalsRejectsInvalidPaginationAndDuplicateStatuses() throws {
        let selector = ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka")
        for request in [
            ToriiMultisigProposalsQueryRequest(
                selector: selector,
                status: [.finalized, .finalized]
            ),
            ToriiMultisigProposalsQueryRequest(selector: selector, cursor: " "),
            ToriiMultisigProposalsQueryRequest(selector: selector, limit: 0),
            ToriiMultisigProposalsQueryRequest(
                selector: selector,
                cursor: String(repeating: "x", count: 513)
            )
        ] {
            XCTAssertThrowsError(try JSONEncoder().encode(request))
        }
    }

    func testResolveMultisigProposalRejectsMissingOrDualProposalSelectors() throws {
        let selector = ToriiMultisigAccountSelector(multisigAccountAlias: "cbdc@banka")
        let proposalId = String(repeating: "f", count: 64)
        for request in [
            ToriiMultisigProposalsResolveRequest(selector: selector),
            ToriiMultisigProposalsResolveRequest(
                selector: selector,
                proposalId: proposalId,
                instructionsHash: proposalId
            )
        ] {
            XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
                guard case let ToriiClientError.invalidPayload(message) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertTrue(message.contains("exactly one"))
            }
        }
    }

    func testMultisigProposalResponseRejectsMissingCurrentContractFields() throws {
        let proposalId = String(repeating: "f", count: 64)
        let missingStatus = """
        {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","operation_type":"TRANSFER","proposal":{}}
        """.data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiMultisigProposalResolveResponse.self, from: missingStatus))

        let unknownStatus = """
        {"resolved_multisig_account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","proposal_id":"\(proposalId)","instructions_hash":"\(proposalId)","operation_type":"TRANSFER","intent":null,"proposal":{},"status":"READY_TO_SUBMIT","terminal_at_ms":null}
        """.data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiMultisigProposalResolveResponse.self, from: unknownStatus))
    }

    func testMultisigSelectorRejectsBothAccountIdAndAlias() throws {
        let selector = ToriiMultisigAccountSelector(
            multisigAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            multisigAccountAlias: "cbdc@banka"
        )
        XCTAssertThrowsError(try JSONEncoder().encode(selector)) { error in
            guard case let ToriiClientError.invalidPayload(message) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(message.contains("exactly one"))
        }
    }

    func testContractArtifactIdentityRejectsInvalidScopeAndHash() throws {
        let hash = "hash:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB#ABA2"
        let artifact = try ContractArtifactId(dataspaceId: UInt64.max, codeHash: hash)
        let encoded = try JSONEncoder().encode(artifact)
        XCTAssertEqual(try JSONDecoder().decode(ContractArtifactId.self, from: encoded), artifact)
        XCTAssertEqual(artifact.codeHashHex, String(repeating: "b", count: 64))
        XCTAssertThrowsError(try ContractArtifactId(dataspaceId: 17, codeHash: String(repeating: "b", count: 64)))
        for scope in ["-1", "18446744073709551616", "\"17\""] {
            let invalid = "{\"dataspace_id\":\(scope),\"code_hash\":\"\(hash)\"}"
            XCTAssertThrowsError(try JSONDecoder().decode(ContractArtifactId.self, from: Data(invalid.utf8)))
        }
    }

    func testContractArtifactReadsRejectForeignNetworkAndDataspace() async throws {
        let code = Data([0, 0, 0])
        let hash = IrohaHash.hash(Data("iroha:ivm:contract-artifact:v1\0".utf8) + code).hexLowercased()
        let literal = try XCTUnwrap(ToriiCanonicalHashLiteral.literal(fromNormalizedHex: hash))
        let artifact = try ContractArtifactId(dataspaceId: UInt64.max, codeHash: literal)
        let otherNetwork = try NetworkId(bytes: IrohaHash.hash(Data("foreign artifact network".utf8)))
        for (network, scope) in [(otherNetwork, UInt64.max), (TestNetworkIds.canonical, UInt64(17))] {
            StubURLProtocol.handler = { request in
                XCTAssertNotNil(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"])!
                let identity = "\"network_id\":\"\(network.literal)\",\"artifact_id\":{\"dataspace_id\":\(scope),\"code_hash\":\"\(literal)\"}"
                let payload: String
                if request.url!.path.hasSuffix("/bytes") {
                    payload = "{\(identity),\"code_b64\":\"AAAA\"}"
                } else {
                    payload = "{\(identity),\"manifest\":{\"events\":[],\"enum_types\":[],\"permissions\":[],\"code_hash\":\"\(literal)\"},\"code_hash\":\"\(hash)\",\"abi_hash\":null}"
                }
                return (response, Data(payload.utf8))
            }
            do {
                _ = try await makeClient().fetchContractManifest(artifactId: artifact, canonicalAuth: canonicalReadAuth)
                XCTFail("foreign manifest identity was accepted")
            } catch { XCTAssertTrue(error is ToriiClientError) }
            do {
                _ = try await makeClient().fetchContractCodeBytes(artifactId: artifact, canonicalAuth: canonicalReadAuth)
                XCTFail("foreign bytecode identity was accepted")
            } catch { XCTAssertTrue(error is ToriiClientError) }
        }
    }

    func testContractCodeBytesRejectNoncanonicalAndMismatchedArtifacts() throws {
        let bytes = Data([0])
        let hash = IrohaHash.hash(Data("iroha:ivm:contract-artifact:v1\0".utf8) + bytes).hexLowercased()
        let literal = try XCTUnwrap(ToriiCanonicalHashLiteral.literal(fromNormalizedHex: hash))
        let prefix = "\"network_id\":\"\(TestNetworkIds.canonical.literal)\",\"artifact_id\":{\"dataspace_id\":17,\"code_hash\":\"\(literal)\"}"
        let valid = "{\(prefix),\"code_b64\":\"AA==\"}"
        XCTAssertNoThrow(try JSONDecoder().decode(ToriiContractCodeBytes.self, from: Data(valid.utf8)))
        for invalid in ["AB==", "AA", "AAAA", "", " AA=="] {
            let payload = "{\(prefix),\"code_b64\":\"\(invalid)\"}"
            XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractCodeBytes.self, from: Data(payload.utf8)))
        }
        XCTAssertThrowsError(try JSONDecoder().decode(ToriiContractCodeBytes.self, from: Data("{\"code_b64\":\"AA==\"}".utf8)))
    }

    func testFetchContractCodeBytesDecodesResponse() throws {
        let expectation = expectation(description: "fetch code bytes")
        let codeHash = IrohaHash.hash(Data("iroha:ivm:contract-artifact:v1\0".utf8) + Data([0, 0, 0])).hexLowercased()
        let artifactId = try ContractArtifactId(dataspaceId: UInt64.max,
            codeHash: XCTUnwrap(ToriiCanonicalHashLiteral.literal(fromNormalizedHex: codeHash)))
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/artifacts/\(UInt64.max)/\(codeHash)/bytes")
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"network_id":"\(TestNetworkIds.canonical.literal)","artifact_id":{"dataspace_id":18446744073709551615,"code_hash":"\(artifactId.codeHash)"},"code_b64":"AAAA"}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().fetchContractCodeBytes(artifactId: artifactId, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let record):
                XCTAssertEqual(record.codeB64, "AAAA")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testFetchContractCodeBytesRejectsInvalidBase64() throws {
        let expectation = expectation(description: "fetch code bytes invalid b64")
        let codeHash = IrohaHash.hash(Data("iroha:ivm:contract-artifact:v1\0".utf8) + Data([0, 0, 0])).hexLowercased()
        let artifactId = try ContractArtifactId(dataspaceId: UInt64.max,
            codeHash: XCTUnwrap(ToriiCanonicalHashLiteral.literal(fromNormalizedHex: codeHash)))
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/contracts/artifacts/\(UInt64.max)/\(codeHash)/bytes")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let body = """
            {"network_id":"\(TestNetworkIds.canonical.literal)","artifact_id":{"dataspace_id":18446744073709551615,"code_hash":"\(artifactId.codeHash)"},"code_b64":"%%%"}
            """.data(using: .utf8)!
            return (response, body)
        }

        makeClient().fetchContractCodeBytes(artifactId: artifactId, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success:
                XCTFail("expected invalid base64 decoding failure")
            case .failure(let error):
                guard case ToriiClientError.decoding = error else {
                    return XCTFail("unexpected error: \(error)")
                }
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testSubmitTransactionPostsNorito() throws {
        let expectation = expectation(description: "submit transaction")
        let transaction = try canonicalSignedPipelineTransaction()
        StubURLProtocol.handler = { request in
            switch request.url?.path {
            case "/v1/node/capabilities":
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 200,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return (response, self.nodeCapabilitiesBody())
            case "/v1/pipeline/transactions":
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), ToriiWireFormatPreference.noritoPreferred.acceptHeader)
                XCTAssertEqual(self.bodyData(from: request), transaction)
                let response = HTTPURLResponse(url: request.url!,
                                               statusCode: 202,
                                               httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                let body = """
                {"payload":{"entrypoint_hash":"\(Self.pipelineHash)","signed_transaction_hash":null,"submitted_at_ms":1,"submitted_at_height":2,"signer":"signer"},"signature":"deadbeef"}
                """.data(using: .utf8)!
                return (response, body)
            default:
                XCTFail("unexpected request: \(request.url?.path ?? "")")
                let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        makeClient().submitTransaction(data: transaction) { result in
            switch result {
            case .success(let payload):
                XCTAssertEqual(payload?.hash, Self.pipelineHash)
                XCTAssertEqual(payload?.payload.submittedAtMs, 1)
                XCTAssertEqual(payload?.payload.submittedAtHeight, 2)
                XCTAssertEqual(payload?.payload.signer, "signer")
                XCTAssertEqual(payload?.signature, "deadbeef")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testSubmitGovernanceDeployContractProposalEncodesAliasSelector() {
        let expectation = expectation(description: "governance proposal")
        let proposalId = String(repeating: "3", count: 64)
        let codeHash = Data(repeating: 0x44, count: 32)
        let abiHash = Data(repeating: 0x55, count: 32)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/gov/proposals/deploy-contract")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            let body = self.bodyJSON(from: request)
            XCTAssertEqual(body["proposal_operator"] as? String, self.authority)
            XCTAssertEqual(body["contract_alias"] as? String, "demo::universal")
            XCTAssertEqual(body["code_hash"] as? String, codeHash.hexLowercased())
            XCTAssertEqual(body["abi_hash"] as? String, abiHash.hexLowercased())
            XCTAssertEqual((body["abi_version"] as? NSNumber)?.uint16Value, 1)
            XCTAssertNil(body["window"])
            XCTAssertNil(body["mode"])
            let provenance = body["manifest_provenance"] as? [String: Any]
            XCTAssertEqual(provenance?["signer"] as? String, "ed25519:public")
            XCTAssertEqual(provenance?["signature"] as? String, "ed25519:signature")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let payload = """
            {"proposal_id":"\(proposalId)","tx_instructions":[{"wire_id":"iroha.instruction.v1::governance::ProposeDeployContract","payload_hex":"00ff"}]}
            """.data(using: .utf8)!
            return (response, payload)
        }

        let request = ToriiGovernanceDeployContractProposalRequest(proposalOperator: authority,
                                                                   contractAlias: "demo::universal",
                                                                   codeHash: codeHash,
                                                                   abiHash: abiHash,
                                                                   manifestProvenance: .init(
                                                                    signer: "ed25519:public",
                                                                    signature: "ed25519:signature"
                                                                   ))
        makeClient().submitGovernanceDeployContractProposal(request, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertEqual(response.proposalId, proposalId)
                XCTAssertEqual(
                    response.txInstructions.first?.wireId,
                    "iroha.instruction.v1::governance::ProposeDeployContract"
                )
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGovernanceDeployContractProposalRejectsMismatchedOperatorBeforeTransport() throws {
        let expectation = expectation(description: "operator mismatch")
        var transportCalled = false
        StubURLProtocol.handler = { request in
            transportCalled = true
            throw NSError(
                domain: "unexpected governance transport",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: request.url?.absoluteString ?? ""]
            )
        }
        let otherOperator = try Keypair(privateKeyBytes: Data(repeating: 0x42, count: 32))
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
        let request = ToriiGovernanceDeployContractProposalRequest(
            proposalOperator: otherOperator,
            contractAlias: "demo::universal",
            codeHash: Data(repeating: 0x44, count: 32),
            abiHash: Data(repeating: 0x55, count: 32)
        )

        makeClient().submitGovernanceDeployContractProposal(
            request,
            canonicalAuth: canonicalReadAuth
        ) { result in
            guard case .failure(let error) = result,
                  let clientError = error as? ToriiClientError,
                  case .invalidPayload(let message) = clientError else {
                XCTFail("expected operator mismatch, got \(result)")
                expectation.fulfill()
                return
            }
            XCTAssertTrue(message.contains("proposal_operator must equal"))
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
        XCTAssertFalse(transportCalled)
    }

    func testGovernanceDeployContractProposalRejectsAmbiguousTarget() throws {
        let request = ToriiGovernanceDeployContractProposalRequest(
            proposalOperator: authority,
            contractAddress: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
            contractAlias: "demo::universal",
            codeHash: Data(repeating: 0x44, count: 32),
            abiHash: Data(repeating: 0x55, count: 32)
        )
        XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
            guard case let ToriiClientError.invalidPayload(message) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(message.contains("exactly one of contract_address or contract_alias"))
        }
    }

    func testGovernanceDeployContractProposalRejectsNonV1AbiVersion() {
        for abiVersion: UInt16 in [0, 2, .max] {
            let request = ToriiGovernanceDeployContractProposalRequest(
                proposalOperator: authority,
                contractAlias: "demo::universal",
                codeHash: Data(repeating: 0x44, count: 32),
                abiHash: Data(repeating: 0x55, count: 32),
                abiVersion: abiVersion
            )
            XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
                guard case let ToriiClientError.invalidPayload(message) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertTrue(message.contains("abi_version must be exactly 1"))
            }
        }
    }

    func testGovernanceDeployContractProposalRejectsWrongHashLengths() {
        for length in [0, 31, 33] {
            let request = ToriiGovernanceDeployContractProposalRequest(
                proposalOperator: authority,
                contractAlias: "demo::universal",
                codeHash: Data(repeating: 0x44, count: length),
                abiHash: Data(repeating: 0x55, count: 32)
            )
            XCTAssertThrowsError(try JSONEncoder().encode(request)) { error in
                guard case let ToriiClientError.invalidPayload(message) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertTrue(message.contains("code_hash must contain exactly 32 bytes"))
            }
        }
    }

    func testGovernanceProposalResponseRejectsLegacyOkField() {
        let proposalId = String(repeating: "3", count: 64)
        let legacy = Data(
            """
            {"ok":true,"proposal_id":"\(proposalId)","tx_instructions":[{"wire_id":"iroha.instruction.v1::governance::ProposeDeployContract","payload_hex":"00ff"}]}
            """.utf8
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiGovernanceProposalResponse.self, from: legacy)
        )
    }

    func testGovernanceProposalResponseRequiresOneFullWireInstruction() {
        let proposalId = String(repeating: "3", count: 64)
        for instructions in [
            "[]",
            "[{\"wire_id\":\"ProposeDeployContract\",\"payload_hex\":\"00ff\"}]",
            "[{\"wire_id\":\"iroha.instruction.v1::governance::ProposeDeployContract\",\"payload_hex\":\"00ff\"},{\"wire_id\":\"iroha.instruction.v1::governance::ProposeDeployContract\",\"payload_hex\":\"00ff\"}]",
        ] {
            let data = Data(
                """
                {"proposal_id":"\(proposalId)","tx_instructions":\(instructions)}
                """.utf8
            )
            XCTAssertThrowsError(
                try JSONDecoder().decode(ToriiGovernanceProposalResponse.self, from: data)
            )
        }
    }

    func testGetGovernanceProposalDecodesRecord() {
        let expectation = expectation(description: "proposal lookup")
        let proposalId = String(repeating: "6", count: 64)
        let codeHash = Data(repeating: 0x77, count: 32)
        let abiHash = Data(repeating: 0x88, count: 32)
        let contractAddress = "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/gov/proposals/\(proposalId)")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let payload = """
            {"found":true,"proposal":{"proposer":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","kind":{"kind":"DeployContract","payload":{"proposal_operator":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","contract_address":"\(contractAddress)","code_hash":"\(codeHash.hexLowercased())","abi_hash":"\(abiHash.hexLowercased())","abi_version":1,"manifest_provenance":{"signer":"ed25519:public","signature":"ed25519:signature"}}},"created_height":42,"status":"Enacted"}}
            """.data(using: .utf8)!
            return (response, payload)
        }

        makeClient().getGovernanceProposal(idHex: proposalId, canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let response):
                XCTAssertTrue(response.found)
                XCTAssertEqual(response.proposal?.createdHeight, 42)
                guard case .deployContract(let payload) = response.proposal?.kind else {
                    return XCTFail("expected deploy contract kind")
                }
                XCTAssertEqual(payload.contractAddress, contractAddress)
                XCTAssertEqual(payload.proposalOperator, response.proposal?.proposer)
                XCTAssertEqual(payload.codeHash, codeHash)
                XCTAssertEqual(payload.abiHash, abiHash)
                XCTAssertEqual(payload.abiVersion, 1)
                XCTAssertEqual(payload.manifestProvenance?.signer, "ed25519:public")
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGovernanceGetIdentifiersUseCanonicalUnreservedPathSegments() async throws {
        let proposalId = String(repeating: "ab", count: 32)
        var requestedURLs: [String] = []
        StubURLProtocol.handler = { request in
            let url = try XCTUnwrap(request.url)
            requestedURLs.append(url.absoluteString)
            let body: Data
            switch url.absoluteString {
            case "https://example.test/v1/gov/proposals/\(proposalId)":
                body = Data(#"{"found":false,"proposal":null}"#.utf8)
            case "https://example.test/v1/gov/referenda/ref.referendum~1":
                body = Data(#"{"found":false,"referendum":null}"#.utf8)
            case "https://example.test/v1/gov/tally/ref_tally-2":
                body = Data(
                    #"{"referendum_id":"ref_tally-2","approve":"0","reject":"0","abstain":"0"}"#.utf8
                )
            case "https://example.test/v1/gov/locks/Ref3":
                body = Data(#"{"found":false,"referendum_id":"Ref3","locks":null}"#.utf8)
            default:
                XCTFail("unexpected governance GET URL: \(url.absoluteString)")
                body = Data()
            }
            let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, body)
        }

        let client = makeClient()
        let proposal = try await client.getGovernanceProposal(idHex: proposalId, canonicalAuth: canonicalReadAuth)
        let referendum = try await client.getGovernanceReferendum(id: "ref.referendum~1", canonicalAuth: canonicalReadAuth)
        let tally = try await client.getGovernanceTally(id: "ref_tally-2", canonicalAuth: canonicalReadAuth)
        let locks = try await client.getGovernanceLocks(referendumId: "Ref3", canonicalAuth: canonicalReadAuth)

        XCTAssertFalse(proposal.found)
        XCTAssertFalse(referendum.found)
        XCTAssertEqual(tally.referendumId, "ref_tally-2")
        XCTAssertEqual(locks.referendumId, "Ref3")
        XCTAssertEqual(requestedURLs, [
            "https://example.test/v1/gov/proposals/\(proposalId)",
            "https://example.test/v1/gov/referenda/ref.referendum~1",
            "https://example.test/v1/gov/tally/ref_tally-2",
            "https://example.test/v1/gov/locks/Ref3",
        ])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGovernanceGetIdentifiersRejectAliasesBeforeTransportDispatch() async throws {
        let client = makeClient()
        let proposalId = String(repeating: "ab", count: 32)
        let auth = canonicalReadAuth
        let invalidCalls: [(String, () async throws -> Void)] = [
            ("uppercase proposal", {
                _ = try await client.getGovernanceProposal(idHex: proposalId.uppercased(), canonicalAuth: auth)
            }),
            ("prefixed proposal", {
                _ = try await client.getGovernanceProposal(idHex: "0x\(proposalId)", canonicalAuth: auth)
            }),
            ("padded proposal", {
                _ = try await client.getGovernanceProposal(idHex: " \(proposalId)", canonicalAuth: auth)
            }),
            ("slash proposal", {
                _ = try await client.getGovernanceProposal(idHex: "proposal/segment", canonicalAuth: auth)
            }),
            ("padded referendum", {
                _ = try await client.getGovernanceReferendum(id: " ref-1", canonicalAuth: auth)
            }),
            ("internal referendum whitespace", {
                _ = try await client.getGovernanceReferendum(id: "ref 1", canonicalAuth: auth)
            }),
            ("slash referendum", {
                _ = try await client.getGovernanceReferendum(id: "ref/1", canonicalAuth: auth)
            }),
            ("leading-dot referendum", {
                _ = try await client.getGovernanceReferendum(id: ".hidden", canonicalAuth: auth)
            }),
            ("percent referendum", {
                _ = try await client.getGovernanceReferendum(id: "ref%31", canonicalAuth: auth)
            }),
            ("unicode referendum", {
                _ = try await client.getGovernanceReferendum(id: "投票", canonicalAuth: auth)
            }),
            ("tally tab", {
                _ = try await client.getGovernanceTally(id: "ref\t1", canonicalAuth: auth)
            }),
            ("overlong tally", {
                _ = try await client.getGovernanceTally(
                    id: String(repeating: "a", count: 129), canonicalAuth: auth
                )
            }),
            ("locks control", {
                _ = try await client.getGovernanceLocks(referendumId: "ref\u{0000}1", canonicalAuth: auth)
            }),
            ("locks unicode whitespace", {
                _ = try await client.getGovernanceLocks(referendumId: "ref\u{2003}1", canonicalAuth: auth)
            }),
        ]
        var dispatched = false
        StubURLProtocol.handler = { request in
            dispatched = true
            XCTFail("invalid governance identifier reached transport dispatch: \(request)")
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 500,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                Data()
            )
        }

        for (label, invoke) in invalidCalls {
            await XCTAssertThrowsErrorAsync(try await invoke()) { error in
                guard case ToriiClientError.invalidPayload = error else {
                    return XCTFail("expected invalidPayload for \(label), got \(error)")
                }
            }
            XCTAssertFalse(dispatched, "\(label) reached transport dispatch")
        }
    }

    func testGetGovernanceUnlockStatsAddsQuery() {
        let expectation = expectation(description: "unlock stats")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/gov/unlocks/stats")
            let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
            let params = components?.queryItems?.reduce(into: [String: String]()) { result, item in
                if let value = item.value {
                    result[item.name] = value
                }
            }
            XCTAssertEqual(params?["height"], "120")
            XCTAssertEqual(params?["referendum_id"], "ref-1")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            let payload = """
            {"height_current":120,"expired_locks_now":2,"referenda_with_expired":1,"last_sweep_height":100}
            """.data(using: .utf8)!
            return (response, payload)
        }

        makeClient().getGovernanceUnlockStats(height: 120, referendumId: "ref-1", canonicalAuth: canonicalReadAuth) { result in
            switch result {
            case .success(let stats):
                XCTAssertEqual(stats.expiredLocksNow, 2)
                XCTAssertEqual(stats.referendaWithExpired, 1)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGetTransactionStatusFetchesJSON() {
        let expectation = expectation(description: "status")
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

        makeClient().getTransactionStatus(hashHex: Self.pipelineHash) { result in
            switch result {
            case .success(let status):
                XCTAssertEqual(status?.hash, Self.pipelineHash)
                XCTAssertEqual(status?.status.kind, "Rejected")
                XCTAssertEqual(status?.status.blockHeight, 12)
                XCTAssertEqual(status?.scope, "global")
                XCTAssertEqual(status?.resolvedFrom, "state")
                XCTAssertEqual(status?.isRejected, true)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    func testGetTransactionStatusReturnsNilFor404() {
        let expectation = expectation(description: "status")
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 404,
                                           httpVersion: nil,
                                           headerFields: nil)!
            return (response, nil)
        }

        makeClient().getTransactionStatus(hashHex: Self.pipelineHash) { result in
            switch result {
            case .success(let status):
                XCTAssertNil(status)
            case .failure(let error):
                XCTFail("unexpected error: \(error)")
            }
            expectation.fulfill()
        }
        waitForExpectations(timeout: 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusRejectsNoncanonicalHashBeforeDispatch() async {
        StubURLProtocol.handler = { _ in
            XCTFail("noncanonical pipeline hash reached HTTP dispatch")
            throw URLError(.badURL)
        }
        for hash in [
            "0x\(Self.pipelineHash)",
            Self.pipelineHash.uppercased(),
            " \(Self.pipelineHash)",
            "\(Self.pipelineHash) ",
            String(Self.pipelineHash.dropLast()) + "c",
        ] {
            await XCTAssertThrowsErrorAsync(
                try await makeClient().getTransactionStatus(hashHex: hash)
            ) { error in
                guard case let ToriiClientError.invalidPayload(reason) = error else {
                    return XCTFail("expected invalidPayload, got \(error)")
                }
                XCTAssertFalse(reason.isEmpty)
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusRejectsRetiredSuccessHttpCodes() async throws {
        for code in [202, 204] {
            StubURLProtocol.handler = { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: code,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, code == 202 ? Data("{}".utf8) : nil)
            }
            do {
                _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
                XCTFail("Expected HTTP \(code) to be rejected")
            } catch let ToriiClientError.api(apiError) {
                let actual = apiError.status
                XCTAssertEqual(actual, code)
            } catch {
                XCTFail("Unexpected error: \(error)")
            }
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusAllowsCachedTerminalHint() async throws {
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {"hash":"\(Self.pipelineHash)","status":{"kind":"Applied","block_height":12},"scope":"global","resolved_from":"cache"}
            """.data(using: .utf8)!
            return (response, body)
        }

        let status = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
        XCTAssertEqual(status?.status.kind, "Applied")
        XCTAssertEqual(status?.resolvedFrom, "cache")
        XCTAssertEqual(status?.isTerminal, false)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusMapsCancelledTransportToCancellationError() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            throw URLError(.cancelled)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected cancellation")
        } catch is CancellationError {
            // expected
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorSurfacesBodyMessageAndRejectCode() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 400,
                httpVersion: nil,
                headerFields: ["x-iroha-reject-code": "build_claim_missing"]
            )!
            let body = """
            {
              "code":"body_fallback_must_not_override_header",
              "message":"missing build claim for transaction status"
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 400)
            XCTAssertEqual(rejectCode, "build_claim_missing")
            XCTAssertEqual(message, "missing build claim for transaction status")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorDoesNotTrustTopLevelEnvelopeCode() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 503,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = """
            {
              "code": "transaction_status_unavailable",
              "message": "The transaction status is not available yet.",
              "details": {"retry_after_ms": 250}
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 503)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, "The transaction status is not available yet.")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorUsesNestedJsonMessage() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 502,
                httpVersion: nil,
                headerFields: nil
            )!
            let body = """
            {"error":{"detail":"upstream status pipeline unavailable"}}
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 502)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, "upstream status pipeline unavailable")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorDoesNotTrustEnvelopeDetailsRejectCode() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 429,
                httpVersion: nil,
                headerFields: nil
            )!
            let body = """
            {
              "code": "queue_full",
              "message": "transaction queue is at capacity",
              "details": {
                "reject_code": "TX_QUEUE_FULL",
                "retry_after_seconds": 1,
                "queue": {
                  "state": "saturated",
                  "queued": 128,
                  "capacity": 128,
                  "saturated": true
                }
              }
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 429)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, "transaction queue is at capacity")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorUsesPlainTextBody() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 503,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/plain"]
            )!
            return (response, Data("proxy temporarily unavailable".utf8))
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 503)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, "proxy temporarily unavailable")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorUsesErrorsArrayMessage() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 422,
                httpVersion: nil,
                headerFields: nil
            )!
            let body = """
            {
              "errors": [
                {"message":"status query validation failed"},
                {"message":"hash malformed"}
              ]
            }
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 422)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, "status query validation failed")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorUsesCompactJsonBody() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: nil
            )!
            let body = """
            {"status":"invalid","code":"E123"}
            """.data(using: .utf8)!
            return (response, body)
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 500)
            XCTAssertNil(rejectCode)
            XCTAssertEqual(message, #"{"code":"E123","status":"invalid"}"#)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusHttpErrorTruncatesOversizedBodyText() async throws {
        let oversized = String(repeating: "x", count: 700)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 500,
                httpVersion: nil,
                headerFields: ["Content-Type": "text/plain"]
            )!
            return (response, Data(oversized.utf8))
        }

        do {
            _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
            XCTFail("expected status failure")
        } catch let error as ToriiClientError {
            guard case let .api(apiError) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            let code = apiError.status
            let message: String? = apiError.message
            let rejectCode = apiError.rejectCode
            XCTAssertEqual(code, 500)
            XCTAssertNil(rejectCode)
            let value = try XCTUnwrap(message)
            XCTAssertEqual(value.count, 515)
            XCTAssertTrue(value.hasSuffix("..."), "message should be truncated with ASCII ellipsis")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetTransactionStatusMatchesSharedErrorMessageContractFixture() async throws {
        let fixtureCases = try loadTxStatusErrorContractCases()
        XCTAssertFalse(fixtureCases.isEmpty, "fixture cases should not be empty")

        for fixtureCase in fixtureCases {
            StubURLProtocol.handler = { request in
                XCTAssertEqual(request.url?.path, "/v1/pipeline/transactions/status")
                var headers: [String: String] = [:]
                if let contentType = fixtureCase.contentType {
                    headers["Content-Type"] = contentType
                }
                if let rejectCode = fixtureCase.rejectCodeHeader {
                    headers[fixtureCase.rejectCodeHeaderName ?? "X-Iroha-Reject-Code"] = rejectCode
                }
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: fixtureCase.statusCode,
                    httpVersion: nil,
                    headerFields: headers.isEmpty ? nil : headers
                )!
                let bodyData: Data?
                if let bodyJSON = fixtureCase.bodyJSON {
                    bodyData = try JSONSerialization.data(withJSONObject: bodyJSON, options: [])
                } else if let bodyText = fixtureCase.bodyText {
                    bodyData = Data(bodyText.utf8)
                } else {
                    bodyData = nil
                }
                return (response, bodyData)
            }

            do {
                _ = try await makeClient().getTransactionStatus(hashHex: Self.pipelineHash)
                XCTFail("\(fixtureCase.id): expected status failure")
            } catch let error as ToriiClientError {
                guard case let .api(apiError) = error else {
                    return XCTFail("\(fixtureCase.id): unexpected error shape \(error)")
                }
                let code = apiError.status
                let message: String? = apiError.message
                let rejectCode = apiError.rejectCode
                XCTAssertEqual(code, fixtureCase.statusCode, "\(fixtureCase.id): status code mismatch")
                if let expectedRejectCode = fixtureCase.expectedRejectCode {
                    XCTAssertEqual(rejectCode, expectedRejectCode, "\(fixtureCase.id): reject code mismatch")
                }
                if let expectedMessage = fixtureCase.expectedMessage {
                    XCTAssertEqual(message, expectedMessage, "\(fixtureCase.id): message mismatch")
                }
                if let expectedLength = fixtureCase.expectedMessageLength {
                    XCTAssertEqual(message?.count, expectedLength, "\(fixtureCase.id): message length mismatch")
                }
                if let expectedSuffix = fixtureCase.expectedMessageSuffix {
                    XCTAssertEqual(message?.hasSuffix(expectedSuffix), true, "\(fixtureCase.id): message suffix mismatch")
                }
            } catch {
                XCTFail("\(fixtureCase.id): unexpected error: \(error)")
            }
        }
    }

    func testPipelineStatusStateMapping() throws {
        let nestedJSON = """
        {"kind":"Transaction","content":{"hash":"deadbeef","status":{"kind":"Committed","content":null}}}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: nestedJSON)
        )

        let committedJSON = """
        {"hash":"\(Self.pipelineHash)","status":{"kind":"Committed"},"scope":"global","resolved_from":"cache"}
        """.data(using: .utf8)!
        let committed = try JSONDecoder().decode(
            ToriiPipelineTransactionStatus.self,
            from: committedJSON
        )
        XCTAssertEqual(committed.status.state, .committed)
        XCTAssertFalse(committed.status.state.isKnownTerminalSuccess)
        XCTAssertFalse(committed.isTerminal)
        XCTAssertFalse(PipelineTransactionState.approved.isKnownTerminalSuccess)

        let flatJSON = """
        {"hash":"\(Self.pipelineHash)","resolved_from":"state","scope":"global","status":{"block_height":64,"kind":"Applied"}}
        """.data(using: .utf8)!
        let flat = try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: flatJSON)
        XCTAssertEqual(flat.hash, Self.pipelineHash)
        XCTAssertEqual(flat.status.state, .applied)
        XCTAssertTrue(flat.status.state.isTerminalSuccess)
        XCTAssertTrue(flat.isApplied)

        for cachedKind in ["Applied", "Rejected", "Expired"] {
            let cachedJSON = """
            {"hash":"\(Self.pipelineHash)","status":{"kind":"\(cachedKind)","block_height":64},"scope":"global","resolved_from":"cache"}
            """.data(using: .utf8)!
            let cached = try JSONDecoder().decode(
                ToriiPipelineTransactionStatus.self,
                from: cachedJSON
            )
            XCTAssertFalse(cached.isTerminal, cachedKind)
            XCTAssertFalse(cached.isApplied, cachedKind)
            XCTAssertFalse(cached.isRejected, cachedKind)
        }

        let retiredDetailJSON = """
        {"hash":"\(Self.pipelineHash)","status":{"kind":"Rejected","rejection_reason":"secret"},"scope":"global","resolved_from":"state","summary":"secret","diagnostics":[]}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: retiredDetailJSON)
        )

        let unknownKindJSON = """
        {"hash":"\(Self.pipelineHash)","status":{"kind":"Finalizing"},"scope":"global","resolved_from":"state"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: unknownKindJSON)
        )

        let invalidAutoScopeJSON = """
        {"hash":"\(Self.pipelineHash)","status":{"kind":"Committed"},"scope":"auto","resolved_from":"cache"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: invalidAutoScopeJSON)
        )

        let evenHashMarker = String(Self.pipelineHash.dropLast()) + "c"
        for hash in ["0x\(Self.pipelineHash)", Self.pipelineHash.uppercased(), evenHashMarker] {
            let noncanonicalHashJSON = """
            {"hash":"\(hash)","status":{"kind":"Committed"},"scope":"global","resolved_from":"cache"}
            """.data(using: .utf8)!
            XCTAssertThrowsError(
                try JSONDecoder().decode(
                    ToriiPipelineTransactionStatus.self,
                    from: noncanonicalHashJSON
                )
            )
        }

        let nullHeightJSON = """
        {"hash":"\(Self.pipelineHash)","status":{"kind":"Applied","block_height":null},"scope":"global","resolved_from":"state"}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try JSONDecoder().decode(ToriiPipelineTransactionStatus.self, from: nullHeightJSON)
        )

        let other = PipelineTransactionState(kind: "CustomStatus")
        if case let .other(value) = other {
            XCTAssertEqual(value, "CustomStatus")
        } else {
            XCTFail("Expected other state")
        }
        XCTAssertEqual(PipelineTransactionState(kind: " Applied "), .other(" Applied "))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetHealthReturnsText() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/health")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/plain")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/plain"])!
            return (response, Data("Healthy".utf8))
        }
        let text = try await makeClient().getHealth()
        XCTAssertEqual(text, "Healthy")
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetMetricsAsText() async throws {
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/metrics")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "text/plain")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "text/plain"])!
            return (response, Data("metric_total 1\n".utf8))
        }
        let result = try await makeClient().getMetrics(asText: true)
        let expected = ToriiMetricsResponse.text("metric_total 1\n")
        XCTAssertEqual(result, expected)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetMetricsPrefersJSON() async throws {
        let body = #"{"ok":true}"#.data(using: .utf8)!
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/metrics")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: ["Content-Type": "application/json"])!
            return (response, body)
        }
        let result = try await makeClient().getMetrics()
        let expectedJSON = ToriiJSONValue.object(["ok": .bool(true)])
        XCTAssertEqual(result, ToriiMetricsResponse.json(expectedJSON))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testGetMetricsRejectsJSONWithoutHeader() async throws {
        let body = #"{"ok":true}"#.data(using: .utf8)!
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/metrics")
            let response = HTTPURLResponse(url: request.url!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: [:])!
            return (response, body)
        }
        do {
            _ = try await makeClient().getMetrics()
            XCTFail("expected missing metrics Content-Type to fail")
        } catch let error as ToriiClientError {
            guard case let .invalidPayload(reason) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(reason.contains("Content-Type"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterSoraFsPinManifestPostsOnlySignedNoritoAndReturnsAdmission() async throws {
        let signedBytes = Data([0x01, 0x02, 0x03])
        let envelope = SignedTransactionEnvelope(
            norito: signedBytes,
            signedTransaction: signedBytes,
            payload: nil,
            transactionHash: Data(repeating: 0xAA, count: 32)
        )
        let txHash = String(repeating: "a", count: 64)
        let manifestDigest = String(repeating: "b", count: 64)
        StubURLProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/sorafs/pin/register")
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Content-Type"),
                "application/x-norito"
            )
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(self.bodyData(from: request), signedBytes)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 202,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = Data(
                #"{"status":"submitted","tx_hash_hex":"\#(txHash)","manifest_digest_hex":"\#(manifestDigest)"}"#.utf8
            )
            return (response, body)
        }

        let admission = try await makeClient().registerSoraFsPinManifest(envelope)

        XCTAssertEqual(admission.status, "submitted")
        XCTAssertEqual(admission.txHashHex, txHash)
        XCTAssertEqual(admission.manifestDigestHex, manifestDigest)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRegisterSoraFsPinManifestRejectsPreFinalityFeeClaims() async throws {
        let signedBytes = Data([0x01])
        let envelope = SignedTransactionEnvelope(
            norito: signedBytes,
            signedTransaction: signedBytes,
            payload: nil,
            transactionHash: Data(repeating: 0xAA, count: 32)
        )
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 202,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = Data(
                #"{"status":"submitted","tx_hash_hex":"\#(String(repeating: "a", count: 64))","manifest_digest_hex":"\#(String(repeating: "b", count: 64))","pin_fee":"1"}"#.utf8
            )
            return (response, body)
        }

        await XCTAssertThrowsErrorAsync(
            try await makeClient().registerSoraFsPinManifest(envelope)
        ) { error in
            guard case ToriiClientError.invalidPayload = error else {
                return XCTFail("expected invalidPayload, got \(error)")
            }
        }
    }

}

private struct TxStatusErrorContractCase {
    let id: String
    let statusCode: Int
    let contentType: String?
    let bodyJSON: Any?
    let bodyText: String?
    let rejectCodeHeader: String?
    let rejectCodeHeaderName: String?
    let expectedMessage: String?
    let expectedRejectCode: String?
    let expectedMessageLength: Int?
    let expectedMessageSuffix: String?

    init?(raw: [String: Any]) {
        guard let id = raw["id"] as? String,
              let statusCode = raw["status_code"] as? Int
        else {
            return nil
        }
        self.id = id
        self.statusCode = statusCode
        contentType = raw["content_type"] as? String
        bodyJSON = raw["body_json"]
        bodyText = raw["body_text"] as? String
        rejectCodeHeader = raw["reject_code_header"] as? String
        rejectCodeHeaderName = raw["reject_code_header_name"] as? String
        expectedMessage = raw["expected_message"] as? String
        expectedRejectCode = raw["expected_reject_code"] as? String
        expectedMessageLength = raw["expected_message_length"] as? Int
        expectedMessageSuffix = raw["expected_message_suffix"] as? String
    }
}

private func loadTxStatusErrorContractCases() throws -> [TxStatusErrorContractCase] {
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // ToriiClientTests.swift
        .deletingLastPathComponent() // IrohaSwiftTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // IrohaSwift
        .appendingPathComponent("fixtures/sdk/tx_status_error_message_contract.json")
    let data = try Data(contentsOf: fixtureURL)
    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let rawCases = root["cases"] as? [[String: Any]]
    else {
        throw NSError(domain: "ToriiClientTests",
                      code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "invalid tx-status error-message contract fixture"])
    }
    return rawCases.compactMap(TxStatusErrorContractCase.init(raw:))
}
