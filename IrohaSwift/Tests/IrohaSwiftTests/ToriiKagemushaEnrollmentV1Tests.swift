import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

/// Synthetic envelope DATA exercises transport only; it is never a valid native permit or E6.
final class ToriiKagemushaEnrollmentV1Tests: XCTestCase {
    private typealias Action = ToriiKagemushaEnrollmentActionV1
    private typealias Request = ToriiKagemushaEnrollmentRequestV1
    private typealias Response = ToriiKagemushaEnrollmentResponseV1
    private let seed = Data(repeating: 0x41, count: 32)

    override func tearDown() {
        EnrollmentURLProtocol.handler = nil
        super.tearDown()
    }

    private func request(_ action: Action) throws -> Request {
        try Request(action: action, dispatchOriginal: Data([1, 2, 3]),
                    evidenceOriginal: action == .evidence ? Data([4, 5, 6]) : Data())
    }

    private func auth() throws -> ToriiCanonicalRequestAuth {
        .init(accountId: try Keypair(privateKeyBytes: seed).accountId(
            networkPrefix: AccountId.defaultNetworkPrefix), privateKey: seed)
    }

    private func client(headers: [String: String] = [:], network: NetworkId? = TestNetworkIds.canonical,
                        requestTimeout: TimeInterval = 60, resourceTimeout: TimeInterval = 604_800,
                        endpoint: String = "https://torii.example",
                        freshness: ToriiCanonicalRequestFreshness? = nil,
                        monotonicMilliseconds: @escaping @Sendable () -> UInt64 = {
                            UInt64(max(0, ProcessInfo.processInfo.systemUptime * 1_000).rounded())
                        }) -> ToriiClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EnrollmentURLProtocol.self]
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout
        return ToriiClient(baseURL: URL(string: endpoint)!,
            session: URLSession(configuration: configuration), defaultHeaders: headers,
            localSigningContext: network.map { ToriiLocalSigningContext(networkId: $0) },
            canonicalRequestFreshness: freshness,
            currentMonotonicMilliseconds: monotonicMilliseconds)
    }

    private func frame(_ payload: Data, response: Bool = true, flags: UInt8 = NoritoHeader.compactLen) -> Data {
        noritoEncode(typeName: "iroha.torii.kagemusha.enrollment.\(response ? "response" : "request").v1",
                     payload: payload, flags: flags, payloadAlignment: 8)
    }

    private func response(_ tag: UInt32, original: Data? = nil) -> Data {
        var payload = CompactNoritoWriter()
        payload.writeUInt32LE(tag)
        if let original { payload.writeField(CompactNorito.encodeBytesVec(original)) }
        return frame(payload.data, flags: (tag == 0 || tag == 4) ? NoritoHeader.compactLen : 0)
    }

    private var replies: [(Action, Data, Response.Outcome)] {
        [(.preKey, response(0, original: Data([7, 8])), .permit(Data([7, 8]))),
         (.evidence, response(1), .evidenceReady), (.evidence, response(2), .pending),
         (.issue, response(3), .credentialReady),
         (.deliver, response(4, original: Data([9, 10])), .credential(Data([9, 10])))]
    }

    func testRustCanonicalFixtureFrames() throws {
        let fixture = try enrollmentFixture()
        XCTAssertEqual(fixture.version, 1)
        XCTAssertEqual(fixture.route, "/v1/kagemusha/enrollment")
        XCTAssertEqual(fixture.requestSchemaName, "iroha.torii.kagemusha.enrollment.request.v1")
        XCTAssertEqual(fixture.responseSchemaName, "iroha.torii.kagemusha.enrollment.response.v1")
        XCTAssertEqual(Data(noritoSchemaHash(forTypeName: fixture.requestSchemaName)).hexEncodedString(), fixture.requestSchemaHash)
        XCTAssertEqual(Data(noritoSchemaHash(forTypeName: fixture.responseSchemaName)).hexEncodedString(), fixture.responseSchemaHash)
        XCTAssertEqual(fixture.requestPayloadAlignment, 8)
        XCTAssertEqual(fixture.responsePayloadAlignment, 8)
        XCTAssertEqual(fixture.requestFrameMaxBytes, Request.maximumBytes)
        XCTAssertEqual(fixture.responseFrameMaxBytes, Response.maximumBytes)

        let actions: [String: Action] = ["pre_key": .preKey, "evidence": .evidence, "issue": .issue, "deliver": .deliver]
        XCTAssertEqual(fixture.requests.count, actions.count)
        XCTAssertEqual(Set(fixture.requests.map(\.name)), Set(actions.keys))
        for row in fixture.requests {
            let action = try XCTUnwrap(actions[row.name])
            let expected = try XCTUnwrap(Data(hexString: XCTUnwrap(row.wireHex)))
            let value = try Request(action: action,
                dispatchOriginal: XCTUnwrap(Data(hexString: fixture.dispatchHex)),
                evidenceOriginal: action == .evidence ? XCTUnwrap(Data(hexString: fixture.evidenceHex)) : Data())
            XCTAssertEqual(value.canonicalOriginal, expected, row.name)
            XCTAssertEqual(try Request(canonicalOriginal: expected), value)
            assertFixtureFrame(value.canonicalOriginal, row: row)
        }
        let outcomes: [String: Response.Outcome] = [
            "permit": .permit(try XCTUnwrap(Data(hexString: fixture.permitHex))),
            "evidence_ready": .evidenceReady, "pending": .pending, "credential_ready": .credentialReady,
            "credential": .credential(try XCTUnwrap(Data(hexString: fixture.credentialHex)))
        ]
        XCTAssertEqual(fixture.responses.count, outcomes.count)
        XCTAssertEqual(Set(fixture.responses.map(\.name)), Set(outcomes.keys))
        for row in fixture.responses {
            let wire = try XCTUnwrap(Data(hexString: XCTUnwrap(row.wireHex)))
            let value = try Response(canonicalOriginal: wire)
            XCTAssertEqual(value.outcome, try XCTUnwrap(outcomes[row.name]), row.name)
            XCTAssertEqual(value.canonicalOriginal, wire)
            assertFixtureFrame(value.canonicalOriginal, row: row)
            var wrongFlags = wire; wrongFlags[39] ^= NoritoHeader.compactLen
            XCTAssertThrowsError(try Response(canonicalOriginal: wrongFlags), row.name)
        }
    }

    func testRustInclusiveBoundaryFixtures() throws {
        let fixture = try enrollmentFixture()
        var frames: [String: Data] = [:]
        for (name, action) in [("pre_key", Action.preKey), ("evidence", .evidence), ("issue", .issue), ("deliver", .deliver)] {
            frames["request_" + name] = try Request(action: action,
                dispatchOriginal: Data(repeating: 1, count: Request.maximumDispatchBytes),
                evidenceOriginal: action == .evidence ? Data(repeating: 2, count: Request.maximumEvidenceBytes) : Data()).canonicalOriginal
        }
        frames["response_permit"] = response(0, original: Data(repeating: 1, count: Response.maximumPermitBytes))
        frames["response_credential"] = response(4, original: Data(repeating: 2, count: Response.maximumCredentialBytes))
        XCTAssertEqual(fixture.inclusiveBounds.count, 6)
        XCTAssertEqual(Set(fixture.inclusiveBounds.map(\.name)), Set(frames.keys))
        for row in fixture.inclusiveBounds {
            let wire = try XCTUnwrap(frames[row.name])
            assertFixtureFrame(wire, row: row)
            if row.name.hasPrefix("request_") {
                XCTAssertEqual(try Request(canonicalOriginal: wire).canonicalOriginal, wire)
            } else {
                XCTAssertEqual(try Response(canonicalOriginal: wire).canonicalOriginal, wire)
            }
        }
    }

    private func assertFixtureFrame(_ wire: Data, row: EnrollmentFixtureV1.Frame) {
        XCTAssertEqual(wire.count, row.wireLength, row.name)
        XCTAssertEqual(wire.prefix(NoritoHeader.encodedLength).hexEncodedString(), row.headerHex, row.name)
        XCTAssertEqual(Data(SHA256.hash(data: wire)).hexEncodedString(), row.sha256, row.name)
        XCTAssertEqual(wire[39], row.flags, row.name)
    }

    func testEveryActionRoundTripsAndPreservesExactOriginals() throws {
        for action in Action.allCases {
            let value = try request(action)
            XCTAssertEqual(try Request(canonicalOriginal: value.canonicalOriginal), value)
            XCTAssertEqual(value.dispatchOriginal, Data([1, 2, 3]))
            XCTAssertEqual(value.evidenceOriginal, action == .evidence ? Data([4, 5, 6]) : Data())
            var prefixed = Data([99]); prefixed.append(value.canonicalOriginal)
            XCTAssertEqual(try Request(canonicalOriginal: prefixed.dropFirst()), value)
        }
        var dispatch = Data([1, 2, 3]), evidence = Data([4, 5, 6])
        let frozen = try Request(action: .evidence, dispatchOriginal: dispatch, evidenceOriginal: evidence)
        dispatch[0] = 99; evidence[0] = 99
        XCTAssertEqual(frozen, try request(.evidence))
        XCTAssertFalse(frozen.description.contains("010203"))
    }

    func testOriginalCapsAndActionSeparation() throws {
        for action in Action.allCases {
            let value = try Request(action: action,
                dispatchOriginal: Data(repeating: 1, count: Request.maximumDispatchBytes),
                evidenceOriginal: action == .evidence ? Data(repeating: 2, count: Request.maximumEvidenceBytes) : Data())
            XCTAssertLessThanOrEqual(value.canonicalOriginal.count, Request.maximumBytes)
            XCTAssertEqual(try Request(canonicalOriginal: value.canonicalOriginal), value)
            XCTAssertThrowsError(try Request(action: action, dispatchOriginal: Data()))
            XCTAssertThrowsError(try Request(action: action,
                dispatchOriginal: Data(repeating: 1, count: Request.maximumDispatchBytes + 1)))
        }
        XCTAssertThrowsError(try Request(action: .evidence, dispatchOriginal: Data([1])))
        for action in [Action.preKey, .issue, .deliver] {
            XCTAssertThrowsError(try Request(action: action, dispatchOriginal: Data([1]), evidenceOriginal: Data([2])))
        }
        XCTAssertThrowsError(try Request(action: .evidence, dispatchOriginal: Data([1]),
            evidenceOriginal: Data(repeating: 2, count: Request.maximumEvidenceBytes + 1)))
    }

    func testRequestRejectsVersionTagCountAndNonminimalFieldLength() throws {
        for mutation in 0..<5 {
            var body = CompactNoritoWriter()
            body.writeField(CompactNorito.encodeUInt16(mutation == 0 ? 2 : 1))
            body.writeField(CompactNorito.encodeUInt32(mutation == 1 ? 4 : 0))
            if mutation == 2 {
                body.writeLength(9); body.writeUInt64LE(UInt64.max); body.writeUInt8(1)
            } else if mutation == 3 {
                body.writeBytes(Data([0x89, 0])); body.writeUInt64LE(1); body.writeUInt8(1)
            } else {
                body.writeField(CompactNorito.encodeBytesVec(Data([1])))
            }
            body.writeField(CompactNorito.encodeBytesVec(mutation == 4 ? Data([2]) : Data()))
            XCTAssertThrowsError(try Request(canonicalOriginal: frame(body.data, response: false)))
        }
    }

    func testCanonicalFramesRejectSchemaFlagsPaddingChecksumTruncationAndTrailingBytes() throws {
        for (original, decode) in [
            (try request(.preKey).canonicalOriginal, { (data: Data) in _ = try Request(canonicalOriginal: data) }),
            (response(2), { (data: Data) in _ = try Response(canonicalOriginal: data) })
        ] {
            XCTAssertThrowsError(try decode(Data()))
            for offset in [0, 4, 5, 6, 22, 23, 31, 39] {
                var changed = original; changed[offset] ^= 1
                XCTAssertThrowsError(try decode(changed), "header byte \(offset)")
            }
            var wrongLayout = original; wrongLayout[39] ^= NoritoHeader.compactLen
            XCTAssertThrowsError(try decode(wrongLayout))
            var padded = original; padded.insert(0, at: NoritoHeader.encodedLength)
            XCTAssertThrowsError(try decode(padded))
            var trailing = original; trailing.append(0)
            XCTAssertThrowsError(try decode(trailing))
            XCTAssertThrowsError(try decode(original.dropLast()))
        }
        XCTAssertThrowsError(try Request(canonicalOriginal: Data(repeating: 0, count: Request.maximumBytes + 1)))
        XCTAssertThrowsError(try Response(canonicalOriginal: Data(repeating: 0, count: Response.maximumBytes + 1)))
    }

    func testEveryResponseAndActionBinding() throws {
        for (action, bytes, expected) in replies {
            let value = try Response(canonicalOriginal: bytes)
            XCTAssertEqual(value.outcome, expected)
            XCTAssertEqual(value.canonicalOriginal, bytes)
            for candidate in Action.allCases {
                if candidate == action { XCTAssertNoThrow(try value.requireAction(candidate)) }
                else { XCTAssertThrowsError(try value.requireAction(candidate)) }
            }
        }
    }

    func testResponseRejectsEmptyOversizedUnknownAndExtraFields() throws {
        for (tag, bound) in [(UInt32(0), Response.maximumPermitBytes), (4, Response.maximumCredentialBytes)] {
            XCTAssertNoThrow(try Response(canonicalOriginal: response(tag, original: Data(repeating: 1, count: bound))))
            XCTAssertThrowsError(try Response(canonicalOriginal: response(tag, original: Data())))
            XCTAssertThrowsError(try Response(canonicalOriginal: response(tag, original: Data(repeating: 1, count: bound + 1))))
        }
        for tag in UInt32(1)...3 {
            XCTAssertThrowsError(try Response(canonicalOriginal: response(tag, original: Data([1]))))
        }
        XCTAssertThrowsError(try Response(canonicalOriginal: response(5)))
        var invalid = CompactNoritoWriter()
        invalid.writeUInt32LE(4); invalid.writeLength(8); invalid.writeUInt64LE(UInt64.max)
        XCTAssertThrowsError(try Response(canonicalOriginal: frame(invalid.data)))
    }

    func testSignsExactNetworkActionBodyMethodAndTarget() throws {
        let api = client(), signer = try auth()
        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
        for action in Action.allCases {
            let original = try request(action)
            let sent = try api.makeKagemushaEnrollmentRequestV1(original, canonicalAuth: signer)
            XCTAssertEqual(sent.httpMethod, "POST")
            XCTAssertEqual(sent.url?.path, "/v1/kagemusha/enrollment")
            XCTAssertNil(sent.url?.query)
            XCTAssertEqual(sent.httpBody, original.canonicalOriginal)
            XCTAssertEqual(sent.value(forHTTPHeaderField: "Accept"), "application/x-norito")
            XCTAssertEqual(sent.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
            XCTAssertEqual(sent.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
            let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(sent.value(forHTTPHeaderField: ToriiCanonicalRequest.headerSignature))))
            let timestamp = try XCTUnwrap(UInt64(XCTUnwrap(sent.value(forHTTPHeaderField: ToriiCanonicalRequest.headerTimestampMs))))
            let nonce = try XCTUnwrap(sent.value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
            for mutation in 0..<6 {
                let body = mutation == 4 ? try request(action == .preKey ? .issue : .preKey).canonicalOriginal
                    : mutation == 5 ? try Request(action: action, dispatchOriginal: Data([9]),
                        evidenceOriginal: original.evidenceOriginal).canonicalOriginal : original.canonicalOriginal
                let message = try ToriiCanonicalRequest.signatureMessage(
                    networkId: mutation == 1 ? TestNetworkIds.other : TestNetworkIds.canonical,
                    method: mutation == 2 ? "GET" : "POST",
                    url: mutation == 3 ? URL(string: "https://torii.example/v1/other")! : XCTUnwrap(sent.url),
                    body: body, timestampMs: timestamp, nonce: nonce)
                XCTAssertEqual(publicKey.isValidSignature(signature, for: message), mutation == 0)
            }
        }
    }

    func testRejectsStaleHeadersWitnessMissingNetworkAndDifferentSigner() throws {
        let original = try request(.preKey), signer = try auth()
        for header in ["x-iroha-account", "X-Iroha-Signature", "X-Iroha-Timestamp-Ms", "x-iroha-nonce", "x-Iroha-Witness",
                       "content-encoding", "X-Iroha-Operator-Public-Key", "X-Iroha-Operator-Signature",
                       "x-iroha-operator-timestamp-ms", "X-Iroha-Operator-Nonce"] {
            XCTAssertThrowsError(try client(headers: [header: "offered"]).makeKagemushaEnrollmentRequestV1(original, canonicalAuth: signer))
        }
        XCTAssertThrowsError(try client(network: nil).makeKagemushaEnrollmentRequestV1(original, canonicalAuth: signer))
        var wrong = signer; wrong.privateKey = Data(repeating: 0x42, count: 32)
        XCTAssertThrowsError(try client().makeKagemushaEnrollmentRequestV1(original, canonicalAuth: wrong))
    }

    func testRejectsInsecureOrDecoratedBaseURLBeforeSigning() throws {
        let original = try request(.preKey), signer = try auth()
        let freshness = ToriiCanonicalRequestFreshness(timestampMs: {
            XCTFail("invalid endpoint reached account signing"); return 1
        })
        for endpoint in ["http://torii.example", "https://user@torii.example", "https://user:pass@torii.example",
                         "https://torii.example/?query=1", "https://torii.example/#fragment"] {
            XCTAssertThrowsError(try client(endpoint: endpoint, freshness: freshness)
                .makeKagemushaEnrollmentRequestV1(original, canonicalAuth: signer), endpoint)
        }
        let canonical = try client(headers: ["accept": "application/json", "content-type": "application/json",
                                           "accept-encoding": "gzip", "cache-control": "public"])
            .makeKagemushaEnrollmentRequestV1(original, canonicalAuth: signer)
        XCTAssertEqual(canonical.value(forHTTPHeaderField: "Accept"), "application/x-norito")
        XCTAssertEqual(canonical.value(forHTTPHeaderField: "Content-Type"), "application/x-norito")
        XCTAssertEqual(canonical.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
        XCTAssertEqual(canonical.value(forHTTPHeaderField: "Cache-Control"), "no-cache, no-store")
    }

    func testTransportReturnsEveryTypedResultAndRecoveryUsesFreshAuthentication() async throws {
        let api = client(), signer = try auth()
        for (action, bytes, outcome) in replies {
            var sent: [URLRequest] = []
            EnrollmentURLProtocol.handler = { request in
                sent.append(request)
                return (Self.http(request, headers: ["Content-Type": "application/x-norito"]), bytes)
            }
            let original = try request(action)
            for _ in 0..<2 {
                let result = try await api.kagemushaEnrollmentV1(request: original, canonicalAuth: signer, requireCurrentOwner: {})
                XCTAssertEqual(result.outcome, outcome)
                XCTAssertEqual(result.canonicalOriginal, bytes)
            }
            XCTAssertEqual(sent.count, 2)
            XCTAssertEqual(toriiClientTestBodyData(from: sent[0]), original.canonicalOriginal)
            XCTAssertEqual(toriiClientTestBodyData(from: sent[1]), original.canonicalOriginal)
            XCTAssertNotEqual(sent[0].value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce),
                              sent[1].value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
        }
    }

    func testTransportRejectsCrossActionResponse() async throws {
        for (allowed, bytes, _) in replies {
            for action in Action.allCases where action != allowed {
                EnrollmentURLProtocol.handler = { (Self.http($0), bytes) }
                do {
                    _ = try await client().kagemushaEnrollmentV1(request: request(action), canonicalAuth: auth(), requireCurrentOwner: {})
                    XCTFail("cross-action result admitted")
                } catch { }
            }
        }
    }

    func testUncertainDeliveryRecoversOnlyExactRetainedEnvelopeWithFreshAuth() async throws {
        let api = client(), signer = try auth(), original = try request(.evidence)
        var sent: [URLRequest] = []
        EnrollmentURLProtocol.handler = { request in
            sent.append(request)
            if sent.count == 1 { throw URLError(.networkConnectionLost) }
            return (Self.http(request), self.response(2))
        }
        do {
            _ = try await api.kagemushaEnrollmentV1(request: original, canonicalAuth: signer, requireCurrentOwner: {})
            XCTFail("uncertain delivery became a response")
        } catch { XCTAssertEqual(sent.count, 1, "transport must not retry") }
        let restored = try Request(canonicalOriginal: original.canonicalOriginal)
        let result = try await api.kagemushaEnrollmentV1(request: restored, canonicalAuth: signer, requireCurrentOwner: {})
        XCTAssertEqual(result.outcome, .pending)
        XCTAssertEqual(sent.count, 2)
        XCTAssertEqual(toriiClientTestBodyData(from: sent[0]), original.canonicalOriginal)
        XCTAssertEqual(toriiClientTestBodyData(from: sent[1]), original.canonicalOriginal)
        XCTAssertNotEqual(sent[0].value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce),
                          sent[1].value(forHTTPHeaderField: ToriiCanonicalRequest.headerNonce))
    }

    func testFailuresNeverRetryOrBecomePending() async throws {
        for status in [202, 307, 401, 406, 503] {
            var dispatches = 0
            EnrollmentURLProtocol.handler = { request in
                dispatches += 1
                return (Self.http(request, status: status, headers: ["Location": "https://other.example"]), self.response(2))
            }
            do {
                _ = try await client().kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(), requireCurrentOwner: {})
                XCTFail("HTTP failure became enrollment progress")
            } catch { XCTAssertEqual(dispatches, 1) }
        }
        for failure in [URLError.Code.timedOut, .networkConnectionLost, .cancelled] {
            var dispatches = 0
            EnrollmentURLProtocol.handler = { _ in dispatches += 1; throw URLError(failure) }
            do {
                _ = try await client().kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(), requireCurrentOwner: {})
                XCTFail("transport failure became Pending")
            } catch { XCTAssertEqual(dispatches, 1) }
        }
    }

    func testTransportRejectsRepresentationSubstitutionAndOversizedStreamingBody() async throws {
        let valid = response(2)
        for mutation in 0..<8 {
            var dispatches = 0
            EnrollmentURLProtocol.handler = { request in
                dispatches += 1
                var headers = ["Content-Type": "application/x-norito"]
                if mutation == 0 { headers["Content-Type"] = "application/json" }
                if mutation == 1 { headers["Content-Type"] = "application/x-norito; charset=binary" }
                if mutation == 2 { headers["Content-Encoding"] = "gzip" }
                if mutation == 3 { headers["Content-Length"] = "999999" }
                if mutation == 4 { headers["Content-Length"] = "1" }
                let url = mutation == 5 ? URL(string: "https://foreign.example/v1/kagemusha/enrollment")! : request.url!
                let bytes = mutation == 6 ? Data(repeating: 0, count: Response.maximumBytes + 1)
                    : mutation == 7 ? Data() : valid
                return (HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: headers)!, bytes)
            }
            do {
                _ = try await client().kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(), requireCurrentOwner: {})
                XCTFail("invalid representation admitted: \(mutation)")
            } catch { XCTAssertEqual(dispatches, 1) }
        }
    }

    func testOwnerChangeAtEveryBoundaryPreventsResultPublication() async throws {
        for boundary in 1...3 {
            let owner = EnrollmentOwnerFence(failAt: boundary)
            var dispatches = 0
            EnrollmentURLProtocol.handler = { request in dispatches += 1; return (Self.http(request), self.response(2)) }
            do {
                _ = try await client().kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(),
                    requireCurrentOwner: { try await owner.check() })
                XCTFail("changed native owner published a result")
            } catch EnrollmentOwnerFence.Failure.changed {
                XCTAssertEqual(dispatches, boundary == 3 ? 1 : 0)
            }
        }
    }

    func testDeadlineIncludesEveryOwnerCallbackAndRejectsExactDeadline() async throws {
        for boundary in 1...3 {
            let clock = EnrollmentMonotonicClock()
            let owner = EnrollmentTimedOwner(clock: clock, advanceAt: boundary, milliseconds: 1_000)
            let api = client(requestTimeout: 1, monotonicMilliseconds: { clock.now() })
            var dispatches = 0
            EnrollmentURLProtocol.handler = { request in dispatches += 1; return (Self.http(request), self.response(2)) }
            do {
                _ = try await api.kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(),
                    requireCurrentOwner: { await owner.check() })
                XCTFail("owner callback overran the enrollment deadline")
            } catch ToriiClientError.transport(let error) {
                XCTAssertEqual((error as? URLError)?.code, .timedOut)
                XCTAssertEqual(dispatches, boundary == 3 ? 1 : 0)
            }
        }
    }

    func testResourceDeadlineIncludesHTTPDelayAndNeverReturnsLatePending() async throws {
        let clock = EnrollmentMonotonicClock()
        let api = client(requestTimeout: 60, resourceTimeout: 1, monotonicMilliseconds: { clock.now() })
        var dispatches = 0
        EnrollmentURLProtocol.handler = { request in
            dispatches += 1
            XCTAssertEqual(request.timeoutInterval, 1)
            clock.advance(by: 1_000)
            return (Self.http(request), self.response(2))
        }
        do {
            _ = try await api.kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(), requireCurrentOwner: {})
            XCTFail("late response became Pending")
        } catch ToriiClientError.transport(let error) {
            XCTAssertEqual((error as? URLError)?.code, .timedOut)
            XCTAssertEqual(dispatches, 1)
        }
    }

    func testDispatchTimeoutUsesOnlyRemainingMonotonicBudget() async throws {
        let clock = EnrollmentMonotonicClock()
        let owner = EnrollmentTimedOwner(clock: clock, advanceAt: 1, milliseconds: 400)
        let api = client(requestTimeout: 1, resourceTimeout: 10, monotonicMilliseconds: { clock.now() })
        EnrollmentURLProtocol.handler = { request in
            XCTAssertEqual(request.timeoutInterval, 0.6, accuracy: 0.000_001)
            clock.advance(by: 599)
            return (Self.http(request), self.response(2))
        }
        let result = try await api.kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(),
            requireCurrentOwner: { await owner.check() })
        XCTAssertEqual(result.outcome, .pending)
        XCTAssertEqual(clock.now(), 999)
    }

    func testNonpositiveAndNonfiniteTimeoutsRefuseBeforeOwnerOrDispatch() async throws {
        for invalid in [TimeInterval(0), -1, .infinity, -.infinity, .nan] {
            for resource in [false, true] {
                let api = client(requestTimeout: resource ? 60 : invalid, resourceTimeout: resource ? invalid : 60)
                EnrollmentURLProtocol.handler = { request in
                    XCTFail("invalid timeout reached transport")
                    return (Self.http(request), self.response(2))
                }
                do {
                    _ = try await api.kagemushaEnrollmentV1(request: request(.evidence), canonicalAuth: auth(),
                        requireCurrentOwner: { XCTFail("invalid timeout reached native owner") })
                    XCTFail("invalid timeout admitted")
                } catch ToriiClientError.invalidPayload { }
            }
        }
    }

    private static func http(_ request: URLRequest, status: Int = 200,
                             headers: [String: String] = ["Content-Type": "application/x-norito"]) -> HTTPURLResponse {
        HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers)!
    }
}

private struct EnrollmentFixtureV1: Decodable {
    struct Frame: Decodable {
        let name: String
        let flags: UInt8
        let wireHex: String?
        let headerHex: String
        let wireLength: Int
        let sha256: String
    }
    let version: Int
    let route: String
    let dispatchHex: String
    let evidenceHex: String
    let permitHex: String
    let credentialHex: String
    let requestSchemaName: String
    let requestSchemaHash: String
    let requestPayloadAlignment: Int
    let requestFrameMaxBytes: Int
    let responseSchemaName: String
    let responseSchemaHash: String
    let responsePayloadAlignment: Int
    let responseFrameMaxBytes: Int
    let requests: [Frame]
    let responses: [Frame]
    let inclusiveBounds: [Frame]
}

private func enrollmentFixture() throws -> EnrollmentFixtureV1 {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let bytes = try Data(contentsOf: root.appendingPathComponent("fixtures/kagemusha/enrollment_service_v1_vectors.json"))
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return try decoder.decode(EnrollmentFixtureV1.self, from: bytes)
}

private actor EnrollmentOwnerFence {
    enum Failure: Error { case changed }
    private let failAt: Int
    private var calls = 0
    init(failAt: Int) { self.failAt = failAt }
    func check() throws {
        calls += 1
        if calls == failAt { throw Failure.changed }
    }
}

private final class EnrollmentMonotonicClock: @unchecked Sendable {
    private let lock = NSLock()
    private var milliseconds: UInt64 = 0
    func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return milliseconds }
    func advance(by delta: UInt64) { lock.lock(); defer { lock.unlock() }; milliseconds += delta }
}

private actor EnrollmentTimedOwner {
    private let clock: EnrollmentMonotonicClock
    private let advanceAt: Int
    private let milliseconds: UInt64
    private var calls = 0
    init(clock: EnrollmentMonotonicClock, advanceAt: Int, milliseconds: UInt64) {
        self.clock = clock; self.advanceAt = advanceAt; self.milliseconds = milliseconds
    }
    func check() {
        calls += 1
        if calls == advanceAt { clock.advance(by: milliseconds) }
    }
}

private final class EnrollmentURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw URLError(.badServerResponse) }
            let (response, bytes) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: bytes)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
