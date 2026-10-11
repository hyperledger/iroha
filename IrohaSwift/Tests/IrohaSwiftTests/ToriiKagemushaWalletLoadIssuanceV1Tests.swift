import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

final class ToriiKagemushaWalletLoadIssuanceV1Tests: XCTestCase {
    private let seed = Data(repeating: 0x41, count: 32)
    private let network = try! NetworkId(literal: "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0")
    private func selection() throws -> ToriiKagemushaWalletLoadSelectionV1 {
        try .init(schemeID: Data(repeating: 0xab, count: 32), walletID: Data(repeating: 0xcd, count: 32),
            requestID: Data(repeating: 0xef, count: 32))
    }
    private func auth() throws -> ToriiCanonicalRequestAuth {
        .init(accountId: try Keypair(privateKeyBytes: seed).accountId(networkPrefix: AccountId.defaultNetworkPrefix),
            privateKey: seed)
    }
    private func response(url: URL, headers: [String: String] = ["Content-Type": "application/x-norito"],
        status: Int = 200) -> HTTPURLResponse {
        HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: headers)!
    }
    private func original(_ bytes: Data, response: HTTPURLResponse, expected: URL) throws
        -> ToriiKagemushaWalletLoadIssuanceOriginalV1 {
        try .init(selection: selection(), payerAccountID: auth().accountId, networkID: network,
            expectedURL: expected, response: response, bytes: bytes)
    }

    func testSelectorsAreExactNonzero32Bytes() throws {
        let valid = Data(repeating: 1, count: 32)
        for bad in [Data(), Data(repeating: 1, count: 31), Data(repeating: 1, count: 33), Data(repeating: 0, count: 32)] {
            XCTAssertThrowsError(try ToriiKagemushaWalletLoadSelectionV1(schemeID: bad, walletID: valid, requestID: valid))
            XCTAssertThrowsError(try ToriiKagemushaWalletLoadSelectionV1(schemeID: valid, walletID: bad, requestID: valid))
            XCTAssertThrowsError(try ToriiKagemushaWalletLoadSelectionV1(schemeID: valid, walletID: valid, requestID: bad))
        }
    }

    func testExactEmptyGetUsesExistingAccountAndSigningNetwork() throws {
        let client = ToriiClient(baseURL: URL(string: "https://example.test/torii/")!,
            localSigningContext: .init(networkId: network))
        let signer = try auth(), selected = try selection()
        let request = try client.makeKagemushaWalletLoadIssuanceRequestV1(selection: selected, canonicalAuth: signer)
        XCTAssertEqual(request.url?.path, "/torii" + selected.path)
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/x-norito")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
        let accountHeader = try XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerAccount))
        XCTAssertEqual(accountHeader, try AccountAddress.parseEncoded(signer.accountId).canonicalHex())
        XCTAssertTrue(accountHeader.utf8.allSatisfy { $0 <= 0x7f })
        let timestamp = try XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs)).flatMapUInt64()
        let nonce = try XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
        let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))))
        let message = try ToriiCanonicalRequest.signatureMessage(networkId: network, method: "GET",
            url: XCTUnwrap(request.url), timestampMs: timestamp, nonce: nonce)
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
        XCTAssertEqual(accountHeader, try AccountAddress.fromAccount(publicKey: publicKey.rawRepresentation).canonicalHex())
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        var other = network.bytes; other[0] ^= 1
        let substituted = try ToriiCanonicalRequest.signatureMessage(networkId: .init(bytes: other), method: "GET",
            url: XCTUnwrap(request.url), timestampMs: timestamp, nonce: nonce)
        XCTAssertFalse(publicKey.isValidSignature(signature, for: substituted))
    }

    func testEveryReadRequestGetsFreshNonceAndSignature() throws {
        let client = ToriiClient(baseURL: URL(string: "https://example.test")!,
            localSigningContext: .init(networkId: network))
        let first = try client.makeKagemushaWalletLoadIssuanceRequestV1(selection: selection(), canonicalAuth: auth())
        let second = try client.makeKagemushaWalletLoadIssuanceRequestV1(selection: selection(), canonicalAuth: auth())
        XCTAssertNotEqual(first.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce),
            second.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
        XCTAssertNotEqual(first.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature),
            second.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))
    }

    func testChangedOwnerRejectsBeforeAnyRequestIsBuilt() async throws {
        enum OwnerFailure: Error { case changed }
        let client = ToriiClient(baseURL: URL(string: "https://example.test")!)
        do {
            _ = try await client.getKagemushaWalletLoadIssuanceOriginalV1(
                selection: selection(), canonicalAuth: auth(), requireCurrentOwner: { throw OwnerFailure.changed })
            XCTFail("changed owner must not proceed into signing or dispatch")
        } catch OwnerFailure.changed { }
    }

    func testMissingNetworkAndOfferedAuthHeadersAreRejected() throws {
        let unsigned = ToriiClient(baseURL: URL(string: "https://example.test")!)
        XCTAssertThrowsError(try unsigned.makeKagemushaWalletLoadIssuanceRequestV1(selection: selection(), canonicalAuth: auth()))
        for header in ["X-Iroha-Account", "x-iroha-signature", "X-Iroha-Timestamp-Ms", "x-iroha-nonce"] {
            let client = ToriiClient(baseURL: URL(string: "https://example.test")!, defaultHeaders: [header: "offered"],
                localSigningContext: .init(networkId: network))
            XCTAssertThrowsError(try client.makeKagemushaWalletLoadIssuanceRequestV1(selection: selection(), canonicalAuth: auth()))
        }
    }

    func testOriginalBytesArePreservedWithoutIssuanceOrCreditVerdict() throws {
        let url = URL(string: "https://example.test" + (try selection()).path)!
        let bytes = Data([0, 255, 0, 7]) // Transport-only fixture; Native must reject/admit its own actual codec.
        let value = try original(bytes, response: response(url: url), expected: url)
        XCTAssertEqual(value.canonicalResponseOriginal, bytes)
        XCTAssertEqual(value.payerAccountID, try auth().accountId)
        XCTAssertEqual(value.networkID, network)
    }

    func testRedirectJsonCompressionAndNonSuccessCannotProduceOriginal() throws {
        let url = URL(string: "https://example.test" + (try selection()).path)!
        let bytes = Data([1])
        XCTAssertThrowsError(try original(bytes, response: response(url: URL(string: "https://other.test")!), expected: url))
        for type in ["application/json", "application/x-norito; charset=binary", ""] {
            XCTAssertThrowsError(try original(bytes, response: response(url: url, headers: ["Content-Type": type]), expected: url))
        }
        XCTAssertThrowsError(try original(bytes, response: response(url: url,
            headers: ["Content-Type": "application/x-norito", "Content-Encoding": "gzip"]), expected: url))
        for status in [202, 401, 404, 406, 503] {
            XCTAssertThrowsError(try original(bytes, response: response(url: url, status: status), expected: url))
        }
    }

    func testMissingSourceOrEmptyBodyNeverBecomesAbsentWallet() throws {
        let url = URL(string: "https://example.test" + (try selection()).path)!
        XCTAssertThrowsError(try original(Data(), response: response(url: url), expected: url))
        XCTAssertThrowsError(try original(Data([1]), response: response(url: url, status: 503), expected: url))
    }

    func testFullResponseBoundAndLengthAreEnforced() throws {
        let url = URL(string: "https://example.test" + (try selection()).path)!
        XCTAssertThrowsError(try original(Data(repeating: 1, count: ToriiKagemushaWalletLoadIssuanceOriginalV1.maximumBytes + 1),
            response: response(url: url), expected: url))
        for length in ["0", "2", "-1", "+1", "1,1", String(repeating: "9", count: 40)] {
            XCTAssertThrowsError(try original(Data([1]), response: response(url: url,
                headers: ["Content-Type": "application/x-norito", "Content-Length": length]), expected: url))
        }
        XCTAssertEqual(try original(Data([1]), response: response(url: url,
            headers: ["Content-Type": "application/x-norito", "Content-Length": "1"]), expected: url).canonicalResponseOriginal, Data([1]))
    }

    func testCanonicalNativeFinalityTransportSignsItsExactTargetAndPreservesBytes() async throws {
        let selected = try selection(), signer = try auth(), bytes = Data([0, 255, 1])
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
        let network = self.network
        let (client, cleanup) = proofClient { request in
            XCTAssertEqual(request.url?.path, selected.path + "/finality")
            XCTAssertEqual(request.httpMethod, "GET"); XCTAssertNil(request.httpBody)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
            let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))))
            let timestamp = try XCTUnwrap(UInt64(XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs))))
            let nonce = try XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
            let message = try ToriiCanonicalRequest.signatureMessage(networkId: network, method: "GET",
                url: XCTUnwrap(request.url), timestampMs: timestamp, nonce: nonce)
            XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
            let receiptURL = request.url!.deletingLastPathComponent()
            let receiptMessage = try ToriiCanonicalRequest.signatureMessage(networkId: network, method: "GET",
                url: receiptURL, timestampMs: timestamp, nonce: nonce)
            XCTAssertFalse(publicKey.isValidSignature(signature, for: receiptMessage))
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/x-norito", "Content-Length": "3"])!, bytes)
        }
        defer { cleanup() }
        let received = try await client.getKagemushaWalletLoadFinalityOriginalV1(
            selection: selected, canonicalAuth: signer, requireCurrentOwner: {})
        XCTAssertEqual(received, bytes) // DATA only; no Native finality or credit is inferred.
    }

    func testCanonicalLedgerProofTransportUsesExactHeightAndBody() async throws {
        let bytes = Data([0, 255, 1])
        let (client, cleanup) = proofClient { request in
            XCTAssertEqual(request.url?.path, "/v1/bridge/finality/7")
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/x-norito"])!, bytes)
        }
        defer { cleanup() }
        let received = try await client.getKagemushaWalletLedgerFinalityOriginalV1(height: 7, requireCurrentOwner: {})
        XCTAssertEqual(received, bytes)
        do {
            _ = try await client.getKagemushaWalletLedgerFinalityOriginalV1(height: 0, requireCurrentOwner: {})
            XCTFail("zero height must fail before transport")
        } catch is ToriiClientError { }
    }

    func testEpochReadSignsExactBoundaryAndPreservesOnlyData() async throws {
        let selected = try selection(), signer = try auth(), bytes = Data([0, 255, 1])
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
        let network = self.network
        let (client, cleanup) = proofClient { request in
            XCTAssertEqual(request.url?.path, selected.path + "/epochs/10")
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertNil(request.httpBody)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
            let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))))
            let timestamp = try XCTUnwrap(UInt64(XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs))))
            let nonce = try XCTUnwrap(request.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
            for height in [10, 11] {
                let url = request.url!.deletingLastPathComponent().appendingPathComponent(String(height))
                let message = try ToriiCanonicalRequest.signatureMessage(networkId: network, method: "GET",
                    url: url, timestampMs: timestamp, nonce: nonce)
                XCTAssertEqual(publicKey.isValidSignature(signature, for: message), height == 10)
            }
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/x-norito"])!, bytes)
        }
        defer { cleanup() }
        let received = try await client.getKagemushaWalletLoadEpochOriginalV1(
            selection: selected, boundaryHeight: 10, canonicalAuth: signer, requireCurrentOwner: {})
        XCTAssertEqual(received, bytes)
        for height in [UInt64(0), UInt64(1)] {
            XCTAssertThrowsError(try client.makeKagemushaWalletLoadEpochRequestV1(
                selection: selected, boundaryHeight: height, canonicalAuth: signer))
        }
        let largest = try client.makeKagemushaWalletLoadEpochRequestV1(
            selection: selected, boundaryHeight: UInt64.max, canonicalAuth: signer)
        XCTAssertTrue(largest.url!.path.hasSuffix("/epochs/18446744073709551615"))
    }

    func testEpochOwnerChangeRefusesBeforeRequestAndBeforeDelivery() async throws {
        enum Failure: Error { case changed }
        let calls = ProofPollCalls()
        let (client, cleanup) = proofClient { request in
            _ = calls.record("request")
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/x-norito"])!, Data([1]))
        }
        defer { cleanup() }
        do {
            _ = try await client.getKagemushaWalletLoadEpochOriginalV1(selection: selection(),
                boundaryHeight: 10, canonicalAuth: auth(), requireCurrentOwner: { throw Failure.changed })
            XCTFail("changed owner must refuse before signing")
        } catch Failure.changed { }
        XCTAssertTrue(calls.values.isEmpty)
        actor Fence {
            var reads = 0
            func check() throws { reads += 1; if reads == 3 { throw Failure.changed } }
        }
        let fence = Fence()
        do {
            _ = try await client.getKagemushaWalletLoadEpochOriginalV1(selection: selection(),
                boundaryHeight: 10, canonicalAuth: auth(), requireCurrentOwner: { try await fence.check() })
            XCTFail("changed owner must refuse delivery")
        } catch Failure.changed { }
        XCTAssertEqual(calls.values.count, 1)
    }

    func testFinalityRejectsRetiredPendingProverResponse() async throws {
        let calls = ProofPollCalls()
        let (client, cleanup) = proofClient { request in
            _ = calls.record("request")
            return (HTTPURLResponse(url: request.url!, statusCode: 202, httpVersion: nil,
                headerFields: ["Retry-After": "1", "Content-Length": "0"])!, Data())
        }
        defer { cleanup() }
        do {
            _ = try await client.getKagemushaWalletLoadFinalityOriginalV1(
                selection: selection(), canonicalAuth: auth(), requireCurrentOwner: {})
            XCTFail("retired prover response must be rejected")
        } catch is ToriiClientError { }
        XCTAssertEqual(calls.values.count, 1)
    }

    func testNativeFinalityTransportRejectsOversizedOrChangedRepresentations() async throws {
        let selected = try selection(), signer = try auth()
        let variants: [(Int, [String: String], Data)] = [
            (200, ["Content-Type": "application/x-norito"], Data(repeating: 1, count: 256 * 1024 + 1)),
            (200, ["Content-Type": "application/x-norito", "Content-Length": "262145"], Data([1])),
            (200, ["Content-Type": "application/x-norito", "Content-Length": "2"], Data([1])),
            (200, ["Content-Type": "application/x-norito", "Content-Encoding": "gzip"], Data([1])),
            (200, ["Content-Type": "application/json"], Data([1])),
            (200, ["Content-Type": "application/x-norito"], Data()),
            (202, ["Content-Type": "application/x-norito"], Data([1])),
            (503, ["Content-Type": "application/x-norito"], Data([1])),
        ]
        for (status, headers, bytes) in variants {
            for epoch in [false, true] {
                let (client, cleanup) = proofClient { request in
                    (HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers)!, bytes)
                }
                defer { cleanup() }
                do {
                    if epoch {
                        _ = try await client.getKagemushaWalletLoadEpochOriginalV1(
                            selection: selected, boundaryHeight: 10, canonicalAuth: signer, requireCurrentOwner: {})
                    } else {
                        _ = try await client.getKagemushaWalletLoadFinalityOriginalV1(
                            selection: selected, canonicalAuth: signer, requireCurrentOwner: {})
                    }
                    XCTFail("invalid representation must not escape as an original")
                } catch is ToriiClientError { }
            }
        }
    }

    func testChangedOwnerAfterProofReplyCannotReleaseItsData() async throws {
        actor OwnerFence {
            enum Failure: Error { case changed }
            var reads = 0
            func check() throws { reads += 1; if reads == 3 { throw Failure.changed } }
        }
        let fence = OwnerFence()
        let (client, cleanup) = proofClient { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/x-norito"])!, Data([1]))
        }
        defer { cleanup() }
        do {
            _ = try await client.getKagemushaWalletLedgerFinalityOriginalV1(height: 7,
                requireCurrentOwner: { try await fence.check() })
            XCTFail("changed owner must reject a returned original")
        } catch OwnerFence.Failure.changed { }
    }

    private func proofClient(_ handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)) -> (ToriiClient, () -> Void) {
        let host = "proof-\(UUID().uuidString.lowercased()).example.test"
        KagemushaProofTransportProtocol.install(host: host, handler: handler)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [KagemushaProofTransportProtocol.self]
        let session = URLSession(configuration: configuration)
        return (ToriiClient(baseURL: URL(string: "https://\(host)")!, session: session,
            localSigningContext: .init(networkId: network)), {
                session.invalidateAndCancel(); KagemushaProofTransportProtocol.remove(host: host)
            })
    }
}

private final class ProofPollCalls: @unchecked Sendable {
    private let lock = NSLock()
    private var observed: [String] = []
    func record(_ nonce: String) -> Int {
        lock.lock(); defer { lock.unlock() }; observed.append(nonce); return observed.count
    }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return observed }
}

/// Transport fixture only. It never constructs a Native proof, receipt, wallet or monetary result.
private final class KagemushaProofTransportProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var handlers: [String: (URLRequest) throws -> (HTTPURLResponse, Data)] = [:]
    static func install(host: String, handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)) {
        lock.lock(); defer { lock.unlock() }; handlers[host] = handler
    }
    static func remove(host: String) { lock.lock(); defer { lock.unlock() }; handlers.removeValue(forKey: host) }
    override class func canInit(with request: URLRequest) -> Bool {
        lock.lock(); defer { lock.unlock() }; return handlers[request.url?.host ?? ""] != nil
    }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock(); let handler = Self.handlers[request.url?.host ?? ""]; Self.lock.unlock()
        do {
            let (response, bytes) = try XCTUnwrap(handler)(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: bytes)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}

private extension String {
    func flatMapUInt64() throws -> UInt64 {
        try XCTUnwrap(UInt64(self))
    }
}
