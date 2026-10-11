import Foundation
import CryptoKit
import XCTest
@testable import IrohaSwift

private final class ApplicationPostURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data?))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
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

final class ToriiApplicationPostAuthTests: XCTestCase {
    private let signingSeed = Data(repeating: 0x41, count: 32)

    override func tearDown() {
        ApplicationPostURLProtocol.handler = nil
        super.tearDown()
    }

    private var auth: ToriiCanonicalRequestAuth {
        let accountId = try! Keypair(privateKeyBytes: signingSeed)
            .accountId(networkPrefix: AccountId.defaultNetworkPrefix)
        return ToriiCanonicalRequestAuth(
            accountId: accountId,
            privateKey: signingSeed
        )
    }

    private func client(
        networkId: NetworkId = TestNetworkIds.canonical,
        defaultHeaders: [String: String] = [:],
        canonicalRequestAuth: ToriiCanonicalRequestAuth? = nil
    ) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ApplicationPostURLProtocol.self]
        return ToriiClient(
            baseURL: URL(string: "https://torii.example")!,
            session: URLSession(configuration: configuration),
            defaultHeaders: defaultHeaders,
            localSigningContext: ToriiLocalSigningContext(networkId: networkId),
            canonicalRequestAuth: canonicalRequestAuth
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRamLfeSignatureSeparatesSameAccountAcrossForeignGenesis() async throws {
        var signatures: [String] = []
        ApplicationPostURLProtocol.handler = { request in
            signatures.append(try XCTUnwrap(
                request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature)
            ))
            return (
                HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!,
                Data()
            )
        }

        _ = try await client().executeRamLfeProgram(
            programId: "lookup",
            requestBody: try .ownerInput(normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32)),
            canonicalAuth: auth
        )
        _ = try await client(networkId: TestNetworkIds.other).executeRamLfeProgram(
            programId: "lookup",
            requestBody: try .ownerInput(normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32)),
            canonicalAuth: auth
        )

        XCTAssertEqual(signatures.count, 2)
        XCTAssertNotEqual(signatures[0], signatures[1])
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRamLfeRedirectIsNotReplayed() async {
        var dispatches = 0
        ApplicationPostURLProtocol.handler = { request in
            dispatches += 1
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 307,
                    httpVersion: nil,
                    headerFields: ["Location": "https://redirect.example/replayed"]
                )!,
                Data()
            )
        }

        do {
            _ = try await client().executeRamLfeProgram(
                programId: "lookup",
                requestBody: try .ownerInput(normalizedInput: "private@example.org", inputNonceHex: String(repeating: "12", count: 32)),
                canonicalAuth: auth
            )
            XCTFail("redirect must fail closed")
        } catch {
            XCTAssertEqual(dispatches, 1)
        }
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testPrecomputedCanonicalHeaderIsRejectedBeforeDispatch() async {
        var dispatched = false
        ApplicationPostURLProtocol.handler = { request in
            dispatched = true
            return (
                HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!,
                Data()
            )
        }

        do {
            _ = try await client(defaultHeaders: [
                ToriiCanonicalRequest.headerSignature: "precomputed"
            ]).verifyRamLfeReceipt(receipt: [:], canonicalAuth: auth)
            XCTFail("precomputed canonical header must be rejected")
        } catch let ToriiClientError.invalidPayload(reason) {
            XCTAssertTrue(reason.contains("cannot be precomputed"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertFalse(dispatched)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRwaCollectionQueryBindsExactGenesisPathAndBody() async throws {
        var requests: [URLRequest] = []
        ApplicationPostURLProtocol.handler = { request in
            requests.append(request)
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!,
                Data(#"{"items":[{"id":"lot-002$commodities.sora"}],"next_cursor":null,"total":1}"#.utf8)
            )
        }
        let first = ToriiListQuery(select: ["id"], limit: 1)
        let second = ToriiListQuery(select: ["id"], limit: 2)

        let page = try await client(canonicalRequestAuth: auth).rwas.page(first, as: ToriiJSONObject.self)
        _ = try await client(
            networkId: TestNetworkIds.other,
            canonicalRequestAuth: auth
        ).rwas.page(first, as: ToriiJSONObject.self)
        _ = try await client(canonicalRequestAuth: auth).rwas.page(second, as: ToriiJSONObject.self)

        XCTAssertEqual(page.items.first?["id"], .string("lot-002$commodities.sora"))
        XCTAssertEqual(page.total, 1)
        XCTAssertEqual(requests.count, 3)
        let signatures = try requests.map {
            try XCTUnwrap($0.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
        }
        XCTAssertNotEqual(signatures[0], signatures[1], "a foreign genesis must alter the signature")
        XCTAssertNotEqual(signatures[0], signatures[2], "the final JSON body must be signed")

        let request = requests[0]
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.path, "/v1/rwas/query")
        XCTAssertEqual(
            request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount),
            try AccountAddress.parseEncoded(auth.accountId).canonicalHex()
        )
        let body = try XCTUnwrap(toriiClientTestBodyData(from: request))
        let signature = try XCTUnwrap(Data(base64Encoded: signatures[0]))
        let timestamp = try XCTUnwrap(UInt64(try XCTUnwrap(
            request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs)
        )))
        let nonce = try XCTUnwrap(
            request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce)
        )
        let publicKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingSeed
        ).publicKey
        let exactMessage = try ToriiCanonicalRequest.signatureMessage(
            networkId: TestNetworkIds.canonical,
            method: "POST",
            url: try XCTUnwrap(request.url),
            body: body,
            timestampMs: timestamp,
            nonce: nonce
        )
        XCTAssertTrue(publicKey.isValidSignature(signature, for: exactMessage))

        let substitutedPathMessage = try ToriiCanonicalRequest.signatureMessage(
            networkId: TestNetworkIds.canonical,
            method: "POST",
            url: try XCTUnwrap(URL(string: "https://torii.example/v1/accounts/query")),
            body: body,
            timestampMs: timestamp,
            nonce: nonce
        )
        XCTAssertFalse(publicKey.isValidSignature(signature, for: substitutedPathMessage))
        var substitutedBody = body
        substitutedBody.append(0x20)
        let substitutedBodyMessage = try ToriiCanonicalRequest.signatureMessage(
            networkId: TestNetworkIds.canonical,
            method: "POST",
            url: try XCTUnwrap(request.url),
            body: substitutedBody,
            timestampMs: timestamp,
            nonce: nonce
        )
        XCTAssertFalse(publicKey.isValidSignature(signature, for: substitutedBodyMessage))
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testRwaCollectionQueryIsOneShotAndRejectsInvalidAuthBeforeDispatch() async {
        let query = ToriiListQuery(limit: 1)
        var dispatches = 0
        ApplicationPostURLProtocol.handler = { request in
            dispatches += 1
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 503,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                Data()
            )
        }
        do {
            _ = try await client(canonicalRequestAuth: auth).rwas.page(query)
            XCTFail("503 must fail closed")
        } catch {
            XCTAssertEqual(dispatches, 1)
            XCTAssertEqual((error as? ToriiClientError)?.status, 503)
        }

        var invalidDispatched = false
        ApplicationPostURLProtocol.handler = { request in
            invalidDispatched = true
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
        do {
            _ = try await client(
                defaultHeaders: [ToriiCanonicalRequest.headerSignature: "precomputed"],
                canonicalRequestAuth: auth
            ).rwas.page(query)
            XCTFail("precomputed canonical headers must fail before dispatch")
        } catch let ToriiClientError.invalidPayload(reason) {
            XCTAssertTrue(reason.contains("cannot be precomputed"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        let aliasAuth = ToriiCanonicalRequestAuth(
            accountId: "alice@wonderland",
            privateKey: signingSeed
        )
        do {
            _ = try await client(canonicalRequestAuth: aliasAuth).rwas.page(query)
            XCTFail("an alias must not authenticate the query")
        } catch let ToriiClientError.invalidPayload(reason) {
            XCTAssertTrue(reason.contains("canonical I105"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertFalse(invalidDispatched)
    }
}
