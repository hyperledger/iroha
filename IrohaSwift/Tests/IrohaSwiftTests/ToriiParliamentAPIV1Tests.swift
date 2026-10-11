import CryptoKit
import Foundation
import XCTest
@testable import IrohaSwift

/// Pins the authenticated Parliament V1 SDK surface to the cross-SDK fixture.
final class ToriiParliamentAPIV1Tests: XCTestCase {
    private static let contractAddress =
        "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
    private static let proposalOperator =
        "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"
    private let attemptID = String(repeating: "ab", count: 32)
    private let proposalID = String(repeating: "cd", count: 32)
    private let root = [UInt8](repeating: 0x55, count: 32)

    override func tearDown() {
        ParliamentCastingProofStubURLProtocol.handler = nil
        super.tearDown()
    }

    private func deployProposal() throws -> ToriiParliamentProposalV1 {
        try ToriiParliamentProposalV1(
            validating: Data(
                """
                {"kind":"DeployContract","payload":{"proposal_operator":"\(Self.proposalOperator)","contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"manifest_provenance":null}}
                """.utf8
            )
        )
    }

    func testSharedFixturePinsCompletePublicAndAuditInventories() throws {
        let fixture = try fixtureObject()
        XCTAssertEqual(fixture["api_version"] as? Int, Int(ToriiParliamentAPIV1.version))
        let routes = try XCTUnwrap(fixture["routes"] as? [String: String])
        let limits = try XCTUnwrap(fixture["limits"] as? [String: Int])
        XCTAssertEqual(
            fixture["proposal_kinds"] as? [String],
            ToriiParliamentAPIV1.proposalKinds
        )
        XCTAssertEqual(ToriiParliamentAPIV1.proposalKinds.count, 10)
        XCTAssertEqual(
            fixture["contract_lifecycle_actions"] as? [String],
            ToriiParliamentAPIV1.contractLifecycleActions
        )
        XCTAssertEqual(
            limits["timed_ovn_ballot_chunk_max_records"],
            ToriiParliamentAPIV1.maximumTimedOvnBallotChunkRecords
        )
        XCTAssertEqual(
            limits["timed_ovn_corpus_entries"],
            ToriiParliamentAPIV1.maximumCorpusEntries
        )
        XCTAssertEqual(
            limits["timed_ovn_casting_proof_request_bytes"],
            ToriiParliamentAPIV1.timedOvnCastingProofRequestBytes
        )
        XCTAssertEqual(
            limits["timed_ovn_casting_proof_response_bytes"],
            ToriiParliamentAPIV1.maximumTimedOvnCastingProofResponseBytes
        )
        XCTAssertEqual(
            limits["timed_ovn_casting_proof_finality_entries"],
            ToriiParliamentAPIV1.maximumTimedOvnCastingProofFinalityProofs
        )
        XCTAssertEqual(routes["attempt_draft"], ToriiParliamentAPIV1.attemptDraftPath)
        XCTAssertEqual(routes["attempt_read"], ToriiParliamentAPIV1.attemptReadPathTemplate)
        XCTAssertEqual(
            routes["timed_ovn_casting_context_read"],
            ToriiParliamentAPIV1.timedOvnCastingContextReadPathTemplate
        )
        XCTAssertEqual(
            routes["timed_ovn_casting_proof"],
            ToriiParliamentAPIV1.timedOvnCastingProofPathTemplate
        )
        XCTAssertEqual(
            routes["tle_release_context_read"],
            ToriiParliamentAPIV1.tleReleaseContextReadPathTemplate
        )
        XCTAssertEqual(
            routes["tle_partial_release"],
            ToriiParliamentAPIV1.tlePartialReleasePathTemplate
        )
        XCTAssertEqual(routes["transition_draft"], ToriiParliamentAPIV1.transitionDraftPath)
        let nativeWallet = try XCTUnwrap(
            fixture["timed_ovn_native_wallet"] as? [String: Any]
        )
        XCTAssertEqual(
            nativeWallet["request_norito_schema"] as? String,
            ToriiParliamentAPIV1.timedOvnCastingProofRequestSchema
        )
        XCTAssertEqual(
            nativeWallet["response_norito_schema"] as? String,
            ToriiParliamentAPIV1.timedOvnCastingProofResponseSchema
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_request_schema_hash_hex"] as? String,
            ToriiParliamentAPIV1.timedOvnCastingProofRequestSchemaHashHex
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_response_schema_hash_hex"] as? String,
            ToriiParliamentAPIV1.timedOvnCastingProofResponseSchemaHashHex
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_request_version"] as? Int,
            Int(ToriiParliamentAPIV1.timedOvnCastingProofRequestVersion)
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_request_flags"] as? Int,
            Int(ToriiParliamentAPIV1.timedOvnCastingProofRequestFlags)
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_request_payload_alignment"] as? Int,
            ToriiParliamentAPIV1.timedOvnCastingProofRequestPayloadAlignment
        )
        XCTAssertEqual(
            nativeWallet["casting_proof_request_padding_bytes"] as? Int,
            ToriiParliamentAPIV1.timedOvnCastingProofRequestPaddingBytes
        )
        let golden = try XCTUnwrap(
            nativeWallet["casting_proof_request_golden"] as? [String: Any]
        )
        XCTAssertEqual(
            golden["frame_bytes"] as? Int,
            ToriiParliamentAPIV1.timedOvnCastingProofRequestBytes
        )
        XCTAssertEqual(
            try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
                trustedCheckpointHeight: UInt64(
                    try XCTUnwrap(golden["trusted_checkpoint_height"] as? Int)
                )
            ).hexEncodedString(),
            golden["frame_hex"] as? String
        )

        let transitions = try XCTUnwrap(fixture["public_transitions"] as? [[String: Any]])
        XCTAssertEqual(transitions.count, 22)
        XCTAssertEqual(transitions.count, ToriiParliamentAPIV1.publicTransitions.count)
        for (fixtureEntry, sdkEntry) in zip(transitions, ToriiParliamentAPIV1.publicTransitions) {
            XCTAssertEqual(fixtureEntry["norito_index"] as? Int, Int(sdkEntry.noritoIndex))
            XCTAssertEqual(fixtureEntry["json_tag"] as? String, sdkEntry.jsonTag)
            XCTAssertEqual(fixtureEntry["event_kind_index"] as? Int, Int(sdkEntry.eventKindIndex))
            XCTAssertEqual(
                fixtureEntry["json_payload"] as? String == "required",
                sdkEntry.jsonPayloadRequired
            )
        }

        let outcomes = try XCTUnwrap(
            fixture["automatic_execution_outcomes"] as? [[String: Any]]
        )
        XCTAssertEqual(outcomes.count, ToriiParliamentAPIV1.automaticExecutionOutcomes.count)
        let reasons = try XCTUnwrap(fixture["no_result_kinds"] as? [[String: Any]])
        XCTAssertEqual(
            reasons.compactMap { $0["json_tag"] as? String },
            ToriiParliamentAPIV1.noResultKinds.map(\.jsonTag)
        )
        XCTAssertEqual(
            reasons.compactMap { $0["norito_index"] as? Int },
            ToriiParliamentAPIV1.noResultKinds.map { Int($0.noritoIndex) }
        )
        let bodyState = try XCTUnwrap(
            fixture["attempt_read_body_state"] as? [String: Any]
        )
        XCTAssertEqual(
            bodyState["json_fields"] as? [String],
            ToriiParliamentAPIV1.bodyStateFields
        )
        XCTAssertEqual(
            fixture["canonical_body_order"] as? [String],
            ToriiParliamentAPIV1.canonicalBodyOrder
        )
        let bodyPresentation = try XCTUnwrap(
            fixture["attempt_read_body_presentation"] as? [String: String]
        )
        XCTAssertEqual(
            bodyPresentation["subset_rule"],
            "strictly increasing subset of canonical_body_order"
        )
        let binding = try XCTUnwrap(fixture["certificate_body_binding"] as? [String: Any])
        XCTAssertEqual(
            binding["norito_field_order"] as? [String],
            ToriiParliamentAPIV1.certificateBodyBindingNoritoFields
        )
        let publicBody = try XCTUnwrap(binding["public_nonbinding_body"] as? [String: Any])
        XCTAssertEqual(
            publicBody["public_finding_norito_field_order"] as? [String],
            ToriiParliamentAPIV1.publicFindingCertificateNoritoFields
        )
        let release = try XCTUnwrap(fixture["tle_release_context"] as? [String: Any])
        XCTAssertEqual(
            release["transcript_public_state_fields"] as? [String],
            [
                "version", "key_session_id", "network_id", "roster_hash", "committee_size",
                "threshold", "generator_h", "generator_v", "qualified_dealers",
                "qualified_dealer_commitments", "dkg_event_hash", "group_public_key",
                "public_shares", "transcript_hash",
            ]
        )
        let partial = try XCTUnwrap(fixture["tle_partial_release"] as? [String: Any])
        XCTAssertEqual((partial["response_fields"] as? [String])?.count, 9)
    }

    func testRetiredKagemushaProposalKindsCannotEnterAttemptDrafts() throws {
        let retiredKinds = [
            "KagemushaVerifierPolicyInstall",
            "KagemushaVerifierReleaseInstall",
            "KagemushaVerifierReleaseActivate",
            "KagemushaVerifierReleaseRetire",
        ]
        for kind in retiredKinds {
            XCTAssertFalse(ToriiParliamentAPIV1.proposalKinds.contains(kind))
            XCTAssertThrowsError(try ToriiParliamentProposalV1(
                validating: Data("{\"kind\":\"\(kind)\",\"payload\":{}}".utf8)
            )) { error in
                guard case ToriiClientError.invalidPayload(let message) = error else {
                    return XCTFail("expected closed-inventory rejection for \(kind)")
                }
                XCTAssertEqual(message, "proposal.kind is unknown or retired")
            }
        }
    }

    func testInitialSortitionDraftUsesOnlyTheEnclosingAttempt() throws {
        let transition = ToriiParliamentLifecycleTransitionV1.registerInitialSortition
        XCTAssertEqual(transition.layout.noritoIndex, 21)
        XCTAssertEqual(transition.layout.jsonTag, "RegisterInitialSortition")
        XCTAssertFalse(transition.layout.jsonPayloadRequired)
        XCTAssertEqual(transition.layout.eventKindIndex, 24)

        let encoded = try ToriiParliamentAPIV1.transitionDraftRequestData(
            governanceAttemptId: attemptID,
            transition: transition
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), ["version", "governance_attempt_id", "transition"])
        XCTAssertEqual(object["version"] as? Int, 1)
        XCTAssertEqual(object["governance_attempt_id"] as? String, attemptID)
        let tagged = try XCTUnwrap(object["transition"] as? [String: String])
        XCTAssertEqual(tagged, ["transition": "RegisterInitialSortition"])
        let standalone = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(transition)) as? [String: String]
        )
        XCTAssertEqual(standalone, tagged)
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.transitionDraftRequestData(
                governanceAttemptId: String(repeating: "00", count: 32),
                transition: transition
            )
        )
    }

    func testBuildersEmitOnlyCanonicalVersionedFields() throws {
        let attempt = try ToriiParliamentAPIV1.attemptDraftRequestData(
            proposal: deployProposal(),
            attemptSequence: 7
        )
        let attemptObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: attempt) as? [String: Any]
        )
        XCTAssertEqual(Set(attemptObject.keys), ["version", "proposal", "attempt_sequence"])
        XCTAssertEqual(
            try ToriiParliamentAPIV1.attemptReadPath(governanceAttemptId: attemptID),
            "/v1/gov/parliament/attempts/\(attemptID)"
        )
        let ballotID = identifier(0x33)
        XCTAssertEqual(
            try ToriiParliamentAPIV1.timedOvnCastingContextReadPath(
                ballotAttemptId: ballotID
            ),
            "/v1/gov/parliament/ballots/\(ballotID)/casting-context"
        )
        XCTAssertEqual(
            try ToriiParliamentAPIV1.timedOvnCastingProofPath(ballotAttemptId: ballotID),
            "/v1/gov/parliament/ballots/\(ballotID)/casting-proof"
        )
        XCTAssertEqual(
            try ToriiParliamentAPIV1.tleReleaseContextReadPath(ballotAttemptId: ballotID),
            "/v1/gov/parliament/ballots/\(ballotID)/release-context"
        )
        XCTAssertEqual(
            try ToriiParliamentAPIV1.tlePartialReleasePath(ballotAttemptId: ballotID),
            "/v1/gov/parliament/ballots/\(ballotID)/partial-release"
        )
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.attemptReadPath(
                governanceAttemptId: attemptID.uppercased()
            )
        )

        let transition = try ToriiParliamentAPIV1.transitionDraftRequestData(
            governanceAttemptId: attemptID,
            transition: .failPublicFindingNoResult(bodyInstanceId: identifier(1))
        )
        let transitionObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: transition) as? [String: Any]
        )
        XCTAssertEqual(
            Set(transitionObject.keys),
            ["version", "governance_attempt_id", "transition"]
        )
        let tagged = try XCTUnwrap(transitionObject["transition"] as? [String: Any])
        XCTAssertEqual(tagged["transition"] as? String, "FailPublicFindingNoResult")
    }

    func testAttemptDraftSequenceAcceptsSixteenAndRejectsSeventeen() throws {
        let accepted = try ToriiParliamentAPIV1.attemptDraftRequestData(
            proposal: deployProposal(),
            attemptSequence: ToriiParliamentAPIV1.maximumGovernanceAttemptRetries
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: accepted) as? [String: Any]
        )
        XCTAssertEqual(
            object["attempt_sequence"] as? Int,
            Int(ToriiParliamentAPIV1.maximumGovernanceAttemptRetries)
        )
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.attemptDraftRequestData(
                proposal: deployProposal(),
                attemptSequence: ToriiParliamentAPIV1.maximumGovernanceAttemptRetries + 1
            )
        )
    }

    func testCastingProofNoritoPinsU64GoldenAndRejectsNoncanonicalResponses() throws {
        let golden = try XCTUnwrap(
            Data(
                hexString:
                    "4e5254300000adccf322a5fcf43040e20bea238f55f3000c00000000000000" +
                    "dfab61022cefc29f02020100081100000000000000"
            )
        )
        XCTAssertEqual(
            try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
                trustedCheckpointHeight: 17
            ),
            golden
        )
        XCTAssertEqual(
            try ToriiParliamentTimedOvnCastingProofRequestV1(
                trustedCheckpointHeight: 17
            ).noritoData(),
            golden
        )
        let maximum = try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
            trustedCheckpointHeight: UInt64.max
        )
        XCTAssertEqual(maximum.suffix(8), Data(repeating: 0xff, count: 8))
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
                trustedCheckpointHeight: 0
            )
        )

        let payload = Data([2, 1, 0, 1])
        let canonical = noritoEncode(
            typeName: ToriiParliamentAPIV1.timedOvnCastingProofResponseSchema,
            payload: payload,
            flags: NoritoHeader.compactLen
        )
        let parsed = try ToriiParliamentAPIV1.decodeTimedOvnCastingProofResponse(canonical)
        XCTAssertEqual(parsed.canonicalNorito, canonical)
        XCTAssertEqual(parsed.payload, payload)

        let wrongSchema = noritoEncode(
            typeName: "iroha.torii.v1.parliament.wrong.response",
            payload: payload,
            flags: NoritoHeader.compactLen
        )
        var badChecksum = canonical
        badChecksum[badChecksum.index(before: badChecksum.endIndex)] ^= 1
        var compressed = canonical
        compressed[22] = 1
        let padded = Data(canonical.prefix(NoritoHeader.encodedLength))
            + Data([0]) + payload
        let wrongFlags = noritoEncode(
            typeName: ToriiParliamentAPIV1.timedOvnCastingProofResponseSchema,
            payload: payload,
            flags: 0
        )
        for hostile in [wrongSchema, badChecksum, compressed, padded, wrongFlags] {
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.decodeTimedOvnCastingProofResponse(hostile)
            )
        }
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTimedOvnCastingProofResponse(
                Data(
                    repeating: 0,
                    count: ToriiParliamentAPIV1.maximumTimedOvnCastingProofResponseBytes + 1
                )
            )
        )
    }

    func testAtomicSortitionBatchEncodesOnlyTypedRequestsAndRejectsSecrets() throws {
        let registrations = (0..<10).map { sequence in
            ToriiParliamentSortitionRequestRegistrationV1(
                sequence: UInt32(sequence),
                request: .object(["body": .string("rules-committee")])
            )
        }
        let encoded = try ToriiParliamentAPIV1.transitionDraftRequestData(
            governanceAttemptId: attemptID,
            transition: .registerSortitionRequest(requests: registrations)
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        let tagged = try XCTUnwrap(root["transition"] as? [String: Any])
        let payload = try XCTUnwrap(tagged["payload"] as? [String: Any])
        XCTAssertEqual(Set(payload.keys), ["requests"])
        let requests = try XCTUnwrap(payload["requests"] as? [[String: Any]])
        XCTAssertEqual(requests.count, 10)
        XCTAssertTrue(requests.allSatisfy { Set($0.keys) == ["sequence", "request"] })

        for invalid in [
            [ToriiParliamentSortitionRequestRegistrationV1](),
            Array(repeating: registrations[0], count: 11),
        ] {
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.transitionDraftRequestData(
                    governanceAttemptId: attemptID,
                    transition: .registerSortitionRequest(requests: invalid)
                )
            )
        }
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.transitionDraftRequestData(
                governanceAttemptId: attemptID,
                transition: .registerSortitionRequest(
                    requests: [
                        .init(
                            sequence: 0,
                            request: .object(["private_key": .string("forbidden")])
                        ),
                    ]
                )
            )
        )
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCastingProofTransportIsExactAuthenticatedBoundedAndOneShot() async throws {
        let responsePayload = Data([2, 1, 0, 1])
        let responseFrame = noritoEncode(
            typeName: ToriiParliamentAPIV1.timedOvnCastingProofResponseSchema,
            payload: responsePayload,
            flags: NoritoHeader.compactLen
        )
        var requestCount = 0
        let ballotID = identifier(0x33)
        ParliamentCastingProofStubURLProtocol.handler = { request in
            requestCount += 1
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(
                request.url?.path,
                "/v1/gov/parliament/ballots/\(ballotID)/casting-proof"
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Content-Type"),
                "application/x-norito"
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Accept"),
                "application/x-norito"
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Accept-Encoding"),
                "identity"
            )
            XCTAssertNotNil(request.value(forHTTPHeaderField: "X-Iroha-Signature"))
            XCTAssertEqual(
                toriiClientTestBodyData(from: request),
                try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
                    trustedCheckpointHeight: 17
                )
            )
            let response = try XCTUnwrap(
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: [
                        "Content-Type": "application/x-norito",
                        "Content-Length": String(responseFrame.count),
                    ]
                )
            )
            return (response, responseFrame)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ParliamentCastingProofStubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let seed = Data(repeating: 0x41, count: 32)
        let auth = ToriiCanonicalRequestAuth(
            accountId: try Keypair(privateKeyBytes: seed)
                .accountId(networkPrefix: AccountId.defaultNetworkPrefix),
            privateKey: seed
        )
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: session,
            localSigningContext: ToriiLocalSigningContext(
                networkId: TestNetworkIds.canonical
            )
        )
        let response = try await client.getParliamentTimedOvnCastingProofPageV1(
            ballotAttemptId: ballotID,
            trustedCheckpointHeight: 17,
            canonicalAuth: auth
        )
        XCTAssertEqual(response.canonicalNorito, responseFrame)
        XCTAssertEqual(response.payload, responsePayload)
        XCTAssertEqual(requestCount, 1)
    }

    @available(iOS 15.0, macOS 12.0, *)
    func testCastingProofPagingDurablyAdvancesStaleAnchorBeyondSixtyThreeHeights() async throws {
        let responsePayload = Data([2, 1, 0, 1])
        let responseFrame = noritoEncode(
            typeName: ToriiParliamentAPIV1.timedOvnCastingProofResponseSchema,
            payload: responsePayload,
            flags: NoritoHeader.compactLen
        )
        let recorder = ParliamentCastingProofPagingRecorder()
        let ballotID = identifier(0x55)
        ParliamentCastingProofStubURLProtocol.handler = { request in
            let requestIndex = recorder.recordRequest()
            let expectedHeight: UInt64 = requestIndex == 0 ? 7 : 70
            XCTAssertEqual(
                toriiClientTestBodyData(from: request),
                try ToriiParliamentAPIV1.timedOvnCastingProofRequestData(
                    trustedCheckpointHeight: expectedHeight
                )
            )
            if requestIndex == 1 {
                XCTAssertEqual(recorder.persistedHeights(), [70])
            }
            let response = try XCTUnwrap(
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: [
                        "Content-Type": "application/x-norito",
                        "Content-Length": String(responseFrame.count),
                    ]
                )
            )
            return (response, responseFrame)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ParliamentCastingProofStubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let seed = Data(repeating: 0x41, count: 32)
        let client = ToriiClient(
            baseURL: URL(string: "https://example.test")!,
            session: session,
            localSigningContext: ToriiLocalSigningContext(
                networkId: TestNetworkIds.canonical
            )
        )
        let initialAnchor = try ParliamentTimedOvnCastingTrustAnchorV1(
            networkID: Data(repeating: 0x01, count: 32),
            trustedCheckpointHeight: 7,
            trustedCheckpointNorito: Data(repeating: 0x11, count: 32),
            expectedBallotAttemptID: Data(repeating: 0x55, count: 32)
        )
        let terminal = try await client.requestParliamentTimedOvnCastingProofUntilTerminalV1(
            ballotAttemptId: ballotID,
            initialTrustAnchor: initialAnchor,
            canonicalAuth: ToriiCanonicalRequestAuth(
                accountId: try Keypair(privateKeyBytes: seed)
                    .accountId(networkPrefix: AccountId.defaultNetworkPrefix),
                privateKey: seed
            ),
            verifyPage: { _, anchor in
                switch recorder.nextVerifierCall() {
                case 0:
                    XCTAssertEqual(anchor.trustedCheckpointHeight, 7)
                    XCTAssertEqual(
                        anchor.trustedCheckpointNorito,
                        Data(repeating: 0x11, count: 32)
                    )
                    return try ParliamentTimedOvnCastingProofPageVerificationV1(
                        evaluatedBlockHeight: 70,
                        evaluatedContextID: Data(repeating: 0x22, count: 32),
                        moreAvailable: true,
                promotedCheckpointNorito: Data(repeating: 0x22, count: 32)
                    )
                case 1:
                    XCTAssertEqual(anchor.trustedCheckpointHeight, 70)
                    XCTAssertEqual(
                        anchor.trustedCheckpointNorito,
                        Data(repeating: 0x22, count: 32)
                    )
                    return try ParliamentTimedOvnCastingProofPageVerificationV1(
                        evaluatedBlockHeight: 75,
                        evaluatedContextID: Data(repeating: 0x33, count: 32),
                        moreAvailable: false,
                promotedCheckpointNorito: Data(repeating: 0x33, count: 32)
                    )
                default:
                    XCTFail("unexpected casting-proof page")
                    throw ToriiClientError.invalidResponse
                }
            },
            persistCheckpoint: { anchor in
                recorder.recordPersistence(anchor.trustedCheckpointHeight)
            }
        )

        XCTAssertEqual(recorder.requestCount(), 2)
        XCTAssertEqual(recorder.persistedHeights(), [70, 75])
        XCTAssertEqual(terminal.verifiedPageCount, 2)
        XCTAssertEqual(terminal.verificationAnchor.trustedCheckpointHeight, 70)
        XCTAssertEqual(terminal.promotedTrustAnchor.trustedCheckpointHeight, 75)
        XCTAssertEqual(terminal.verification.evaluatedBlockHeight, 75)
        XCTAssertFalse(terminal.verification.moreAvailable)
    }

    func testAttemptDraftRejectsRecognizedTagWithArbitraryPayload() {
        XCTAssertThrowsError(
            try ToriiParliamentProposalV1(
                validating: Data(
                    "{\"kind\":\"RuntimeUpgrade\",\"payload\":{}}".utf8
                )
            )
        )
        XCTAssertThrowsError(
            try ToriiParliamentProposalV1(
                validating: Data(
                    """
                    {"kind":"DeployContract","payload":{"proposal_operator":"\(Self.proposalOperator)","contract_address":"\(Self.contractAddress)","code_hash":"\(String(repeating: "11", count: 32))","abi_hash":"\(String(repeating: "22", count: 32))","abi_version":1,"abi_version":1,"manifest_provenance":null}}
                    """.utf8
                )
            )
        )
    }

    func testTimedOvnCorpusTransitionPreflightsOneThrough32RecordsPerChunk() {
        let record = [UInt8](
            repeating: 1,
            count: ToriiParliamentAPIV1.timedOvnBallotRecordBytes
        )
        for count in [1, ToriiParliamentAPIV1.maximumTimedOvnBallotChunkRecords] {
            XCTAssertNoThrow(
                try ToriiParliamentAPIV1.transitionDraftRequestData(
                    governanceAttemptId: attemptID,
                    transition: .freezeTimedOvnCorpus(
                        ballotAttemptId: identifier(1),
                        ballotRecords: Array(repeating: record, count: count)
                    )
                )
            )
        }
        for count in [0, ToriiParliamentAPIV1.maximumTimedOvnBallotChunkRecords + 1] {
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.transitionDraftRequestData(
                    governanceAttemptId: attemptID,
                    transition: .freezeTimedOvnCorpus(
                        ballotAttemptId: identifier(1),
                        ballotRecords: Array(repeating: record, count: count)
                    )
                )
            )
        }
    }

    func testReadProjectionValidatesScheduleNoResultAndExactSupporters() throws {
        let valid = try jsonData(makeReadResponse())
        let parsed = try ToriiParliamentAPIV1.decodeAttemptReadResponse(
            valid,
            expectedGovernanceAttemptId: attemptID
        )
        XCTAssertEqual(parsed.bodyStates.count, 2)
        XCTAssertEqual(parsed.requiredBodyOrder, ["rules-committee", "policy-jury"])
        XCTAssertEqual(parsed.bodyStates[0].body, "rules-committee")
        XCTAssertEqual(parsed.certificateBodyOrder, ["rules-committee", "policy-jury"])
        XCTAssertEqual(parsed.bodyStates[0].publicFindingDeadlineHeight, 8)
        XCTAssertEqual(
            parsed.publicFindingBindings[0].endorsingAssignments,
            [identifier(0x11), identifier(0x12)]
        )

        var canonicalOrder = makeReadResponse()
        var canonicalAttempt = try XCTUnwrap(canonicalOrder["attempt"] as? [String: Any])
        canonicalAttempt["stage"] = ["stage": "Qualification"]
        canonicalAttempt["status"] = ["status": "Active"]
        canonicalOrder["attempt"] = canonicalAttempt
        canonicalOrder["certificate"] = NSNull()
        canonicalOrder["required_bodies"] = ToriiParliamentAPIV1.canonicalBodyOrder.map { body in
            [
                "body": body,
                "decision_mode": [
                    "mode": body == "policy-jury" || body == "confirmation-jury"
                        ? "HiddenBindingBallot"
                        : "PublicFinding",
                ],
            ] as [String: Any]
        }
        canonicalOrder["body_states"] = ToriiParliamentAPIV1.canonicalBodyOrder.map { body in
            [
                "body": body,
                "body_instance_id": NSNull(),
                "status": NSNull(),
                "public_finding_opened_at_height": NSNull(),
                "public_finding_phase_blocks": NSNull(),
                "public_finding_deadline_height": NSNull(),
                "no_result_kind": NSNull(),
                "no_result_height": NSNull(),
                "timed_ovn_progress": NSNull(),
            ] as [String: Any]
        }
        let canonicalParsed = try ToriiParliamentAPIV1.decodeAttemptReadResponse(
            jsonData(canonicalOrder),
            expectedGovernanceAttemptId: attemptID
        )
        XCTAssertEqual(
            canonicalParsed.requiredBodyOrder,
            ToriiParliamentAPIV1.canonicalBodyOrder
        )
        XCTAssertEqual(
            canonicalParsed.bodyStates.map(\.body),
            ToriiParliamentAPIV1.canonicalBodyOrder
        )
        XCTAssertEqual(canonicalParsed.certificateBodyOrder, [])

        var reordered = canonicalOrder
        var reorderedRequired = try XCTUnwrap(
            reordered["required_bodies"] as? [[String: Any]]
        )
        reorderedRequired.swapAt(0, 1)
        reordered["required_bodies"] = reorderedRequired
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(reordered),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var wrongDeadline = makeReadResponse()
        var states = try XCTUnwrap(wrongDeadline["body_states"] as? [[String: Any]])
        states[0]["public_finding_deadline_height"] = 9
        wrongDeadline["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(wrongDeadline),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var automaticFailure = makeReadResponse()
        states = try XCTUnwrap(automaticFailure["body_states"] as? [[String: Any]])
        states[0]["status"] = ["status": "NoResult"]
        states[0]["no_result_kind"] = ["reason": "ExecutionFailed"]
        states[0]["no_result_height"] = 9
        automaticFailure["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(automaticFailure),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var unsorted = makeReadResponse(supporters: [identifier(0x12), identifier(0x11)])
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(unsorted),
                expectedGovernanceAttemptId: attemptID
            )
        )
        unsorted["version"] = 2
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(unsorted),
                expectedGovernanceAttemptId: attemptID
            )
        )
    }

    func testReadProjectionRejectsForgedCertificateBindingsAndBallots() throws {
        let forgedResponses = [
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["proposal_content_id"] = identifier(0xee)
            },
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["governance_attempt_sequence"] = 1
            },
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["risk_tier"] = ["tier": "Emergency"]
            },
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["policy_version"] = 2
            },
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["enact_at_height"] = 8
            },
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["certified_at_height"] = 13
            },
            mutateCertificate(makeReadResponse()) { _, _, request in
                request["beacon_session_id"] = identifier(0xee)
            },
            mutateCertificate(makeReadResponse()) { _, _, request in
                request["request_height"] = 0
            },
            mutateCertificate(makeReadResponse()) { _, binding, _ in
                binding["election_attempt_sequence"] = 17
            },
            mutateCertificate(makeReadResponse()) { _, binding, _ in
                binding["original_seats"] = 4
            },
        ]
        for forged in forgedResponses {
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                    jsonData(forged),
                    expectedGovernanceAttemptId: attemptID
                )
            )
        }

        let largeElectorate = mutateCertificate(makeReadResponse()) { _, _, request in
            request["candidate_count"] = 1_001
        }
        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(largeElectorate),
                expectedGovernanceAttemptId: attemptID
            )
        )

        let maximumElectorate = mutateCertificate(makeReadResponse()) { _, _, request in
            request["candidate_count"] = 4_294_967_295
        }
        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(maximumElectorate),
                expectedGovernanceAttemptId: attemptID
            )
        )
        let overflowingElectorate = mutateCertificate(makeReadResponse()) { _, _, request in
            request["candidate_count"] = 4_294_967_296
        }
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(overflowingElectorate),
                expectedGovernanceAttemptId: attemptID
            )
        )

        let zeroHeadVersion = mutateCertificate(makeReadResponse()) { certificate, _, _ in
            certificate["expected_head"] = [
                "state": "Present",
                "head": ["subject_id": root, "version": 0, "head_root": root],
            ]
        }
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(zeroHeadVersion),
                expectedGovernanceAttemptId: attemptID
            )
        )

        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(makePublicOnlyReadResponse()),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var wrongProjectionPolicy = makeReadResponse()
        wrongProjectionPolicy["policy_version"] = 2
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(wrongProjectionPolicy),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var excessiveAttemptRetry = makeReadResponse()
        var retryAttempt = try XCTUnwrap(excessiveAttemptRetry["attempt"] as? [String: Any])
        retryAttempt["sequence"] = 17
        excessiveAttemptRetry["attempt"] = retryAttempt
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(excessiveAttemptRetry),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var wrongMode = makeReadResponse()
        wrongMode["required_bodies"] = [[
            "body": "rules-committee",
            "decision_mode": ["mode": "HiddenBindingBallot"],
        ]]
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(wrongMode),
                expectedGovernanceAttemptId: attemptID
            )
        )

        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(makeHiddenBallotReadResponse()),
                expectedGovernanceAttemptId: attemptID
            )
        )
        let ballotMutations: [(inout [String: Any]) -> Void] = [
            { $0["ballot_attempt_sequence"] = 17 },
            { $0["max_corpus_entries"] = 2 },
            {
                var tally = $0["tally"] as! [String: Any]
                tally["abstain"] = 1
                $0["tally"] = tally
            },
            { $0["outcome"] = ["outcome": "Rejected"] },
        ]
        for mutation in ballotMutations {
            var forged = makeHiddenBallotReadResponse()
            var certificate = try XCTUnwrap(forged["certificate"] as? [String: Any])
            var bindings = try XCTUnwrap(certificate["body_bindings"] as? [[String: Any]])
            var ballot = try XCTUnwrap(bindings[0]["ballot"] as? [String: Any])
            mutation(&ballot)
            bindings[0]["ballot"] = ballot
            certificate["body_bindings"] = bindings
            forged["certificate"] = certificate
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                    jsonData(forged),
                    expectedGovernanceAttemptId: attemptID
                )
            )
        }

        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(makeConfirmationBallotReadResponse()),
                expectedGovernanceAttemptId: attemptID
            )
        )
        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(
                    makeConfirmationBallotReadResponse(
                        electionAttemptSequence: 1,
                        requestHeight: 49,
                        pulseHeight: 50
                    )
                ),
                expectedGovernanceAttemptId: attemptID
            )
        )
        assertConfirmationMutationRejected { policy, confirmation in
            confirmation["beacon_pulse_id"] = policy["beacon_pulse_id"]
        }
        assertConfirmationMutationRejected { _, confirmation in
            confirmation["election_attempt_sequence"] = 0
            var request = confirmation["sortition_request"] as! [String: Any]
            request["request_height"] = 49
            request["pulse_height"] = 50
            confirmation["sortition_request"] = request
        }
        assertConfirmationMutationRejected { _, confirmation in
            confirmation["election_attempt_sequence"] = 1
            var request = confirmation["sortition_request"] as! [String: Any]
            request["request_height"] = 48
            request["pulse_height"] = 49
            confirmation["sortition_request"] = request
        }
        var missingConfirmation = makeConfirmationBallotReadResponse()
        var missingCertificate = missingConfirmation["certificate"] as! [String: Any]
        let missingBindings = missingCertificate["body_bindings"] as! [[String: Any]]
        missingCertificate["body_bindings"] = [missingBindings[0]]
        missingCertificate["certified_at_height"] = 48
        missingCertificate["enact_at_height"] = 50
        missingConfirmation["certificate"] = missingCertificate
        missingConfirmation["required_bodies"] = [
            (missingConfirmation["required_bodies"] as! [[String: Any]])[0],
        ]
        missingConfirmation["body_states"] = [
            (missingConfirmation["body_states"] as! [[String: Any]])[0],
        ]
        missingConfirmation["current_height"] = 49
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(missingConfirmation),
                expectedGovernanceAttemptId: attemptID
            )
        )
        assertConfirmationMutationRejected { policy, _ in
            var ballot = policy["ballot"] as! [String: Any]
            var tally = ballot["tally"] as! [String: Any]
            tally["aye"] = 15
            tally["nay"] = 6
            ballot["tally"] = tally
            policy["ballot"] = ballot
        }
    }

    func testTimedOvnProgressIsAggregateOnlyAndCertificateBound() throws {
        let response = makeHiddenBallotReadResponse()
        let parsed = try ToriiParliamentAPIV1.decodeAttemptReadResponse(
            jsonData(response),
            expectedGovernanceAttemptId: attemptID
        )
        let progress = try XCTUnwrap(parsed.bodyStates[0].timedOvnProgress)
        XCTAssertEqual(progress.ballotAttemptId, identifier(0x21))
        XCTAssertEqual(progress.status, "Finalized")
        XCTAssertEqual(progress.frozenSurvivorCount, 3)
        XCTAssertEqual(progress.acceptedBallotPrefixCount, 3)

        var mismatched = response
        var states = try XCTUnwrap(mismatched["body_states"] as? [[String: Any]])
        var progressObject = try XCTUnwrap(
            states[0]["timed_ovn_progress"] as? [String: Any]
        )
        progressObject["accepted_ballot_prefix_count"] = 2
        states[0]["timed_ovn_progress"] = progressObject
        mismatched["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(mismatched),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var leaked = response
        states = try XCTUnwrap(leaked["body_states"] as? [[String: Any]])
        progressObject = try XCTUnwrap(states[0]["timed_ovn_progress"] as? [String: Any])
        progressObject["ballot_records"] = []
        states[0]["timed_ovn_progress"] = progressObject
        leaked["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(leaked),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var premature = response
        states = try XCTUnwrap(premature["body_states"] as? [[String: Any]])
        progressObject = try XCTUnwrap(states[0]["timed_ovn_progress"] as? [String: Any])
        progressObject["status"] = ["status": "TimedCommitment"]
        progressObject["accepted_ballot_prefix_count"] = 3
        states[0]["timed_ovn_progress"] = progressObject
        premature["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(premature),
                expectedGovernanceAttemptId: attemptID
            )
        )
    }

    func testReleaseContextRequiresCompleteTranscriptAndBindsEveryPartial() throws {
        let ballotID = identifier(0x33)
        let response = makeTleReleaseContextResponse()
        let context = try ToriiParliamentAPIV1.decodeTleReleaseContextResponse(
            jsonData(response),
            expectedBallotAttemptId: ballotID
        )
        XCTAssertEqual(context.keySession.publicShares.count, 4)
        XCTAssertEqual(context.keySession.qualifiedDealerCommitments.count, 2)

        let partial = makeTlePartialReleaseResponse(context: response)
        let parsedPartial = try ToriiParliamentAPIV1.decodeTlePartialReleaseResponse(
            jsonData(partial),
            expectedKeySessionId: context.keySession.keySessionId,
            expectedIdentityDigest: context.identityDigest,
            committeeSize: context.keySession.committeeSize
        )
        XCTAssertEqual(parsedPartial.participantIndex, 1)

        var missingShare = makeTleReleaseContextResponse()
        var session = try XCTUnwrap(missingShare["tle_key_session"] as? [String: Any])
        var shares = try XCTUnwrap(session["public_shares"] as? [[String: Any]])
        shares.removeLast()
        session["public_shares"] = shares
        missingShare["tle_key_session"] = session
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTleReleaseContextResponse(
                jsonData(missingShare),
                expectedBallotAttemptId: ballotID
            )
        )

        var wrongDigest = makeTleReleaseContextResponse()
        var digest = [UInt8](repeating: 0x88, count: 32)
        digest[0] = 1
        wrongDigest["identity_digest"] = digest
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTleReleaseContextResponse(
                jsonData(wrongDigest),
                expectedBallotAttemptId: ballotID
            )
        )

        var crossBound = makeTlePartialReleaseResponse(context: response)
        crossBound["key_session_id"] = identifier(0x77)
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTlePartialReleaseResponse(
                jsonData(crossBound),
                expectedKeySessionId: context.keySession.keySessionId,
                expectedIdentityDigest: context.identityDigest,
                committeeSize: context.keySession.committeeSize
            )
        )
    }

    func testCastingContextRequiresExactPublicCorpusAndCanonicalArchive() throws {
        let ballotID = identifier(0x33)
        let response = makeTimedOvnCastingContextResponse()
        let parsed = try ToriiParliamentAPIV1.decodeTimedOvnCastingContextResponse(
            jsonData(response),
            expectedBallotAttemptId: ballotID
        )
        XCTAssertEqual(parsed.phase, .registered)
        XCTAssertEqual(parsed.registrationRecordsHex.count, 1)
        XCTAssertEqual(parsed.archiveNorito, Data("NRT0".utf8))

        var unknown = response
        unknown["seed"] = [UInt8](repeating: 0x11, count: 32)
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTimedOvnCastingContextResponse(
                jsonData(unknown),
                expectedBallotAttemptId: ballotID
            )
        )

        var emptyClosed = response
        emptyClosed["phase"] = "RegistrationClosed"
        emptyClosed["registration_records_hex"] = []
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTimedOvnCastingContextResponse(
                jsonData(emptyClosed),
                expectedBallotAttemptId: ballotID
            )
        )

        var emptyFrozen = response
        let release = makeTleReleaseContextResponse()
        emptyFrozen["phase"] = "SurvivorsFrozen"
        emptyFrozen["survivor_participant_hashes"] = []
        emptyFrozen["release_identity"] = release["release_identity"]
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTimedOvnCastingContextResponse(
                jsonData(emptyFrozen),
                expectedBallotAttemptId: ballotID
            )
        )

        var noncanonicalArchive = response
        noncanonicalArchive["archive_norito_base64"] = "TlJUMA"
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTimedOvnCastingContextResponse(
                jsonData(noncanonicalArchive),
                expectedBallotAttemptId: ballotID
            )
        )
    }

    func testAutomaticOutcomeCannotMasqueradeAsPublicTransitionResponse() throws {
        let response: [String: Any] = [
            "version": 1,
            "governance_attempt_id": attemptID,
            "transition_kind": ["kind": "MarkEnacted"],
            "transition_digest": root,
            "tx_instructions": [[
                "wire_id": ToriiParliamentAPIV1.transitionSubmitWireId,
                "payload_hex": framedHex(),
            ]],
        ]
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeTransitionDraftResponse(
                jsonData(response),
                expectedGovernanceAttemptId: attemptID,
                expectedTransitionKind: "CompleteQualification",
                expectedTransitionDigest: root
            )
        )
    }

    private func mutateCertificate(
        _ response: [String: Any],
        mutation: (
            _ certificate: inout [String: Any],
            _ binding: inout [String: Any],
            _ sortitionRequest: inout [String: Any]
        ) -> Void
    ) -> [String: Any] {
        var result = response
        var certificate = result["certificate"] as! [String: Any]
        var bindings = certificate["body_bindings"] as! [[String: Any]]
        var binding = bindings[0]
        var request = binding["sortition_request"] as! [String: Any]
        mutation(&certificate, &binding, &request)
        binding["sortition_request"] = request
        bindings[0] = binding
        certificate["body_bindings"] = bindings
        result["certificate"] = certificate
        return result
    }

    private func makeReadResponse(
        supporters: [String]? = nil
    ) -> [String: Any] {
        var response = makePublicOnlyReadResponse(supporters: supporters)
        let policyResponse = makeHiddenBallotReadResponse()
        var requiredBodies = response["required_bodies"] as! [[String: Any]]
        requiredBodies.append(contentsOf: policyResponse["required_bodies"] as! [[String: Any]])
        response["required_bodies"] = requiredBodies
        var bodyStates = response["body_states"] as! [[String: Any]]
        bodyStates.append(contentsOf: policyResponse["body_states"] as! [[String: Any]])
        response["body_states"] = bodyStates
        var certificate = response["certificate"] as! [String: Any]
        var bindings = certificate["body_bindings"] as! [[String: Any]]
        let policyCertificate = policyResponse["certificate"] as! [String: Any]
        bindings.append(contentsOf: policyCertificate["body_bindings"] as! [[String: Any]])
        certificate["body_bindings"] = bindings
        certificate["certified_at_height"] = 12
        certificate["enact_at_height"] = 14
        response["certificate"] = certificate
        response["current_height"] = 13
        return response
    }

    private func makePublicOnlyReadResponse(
        supporters: [String]? = nil
    ) -> [String: Any] {
        let exactSupporters = supporters ?? [identifier(0x11), identifier(0x12)]
        return [
            "version": 1,
            "current_height": 9,
            "attempt": [
                "id": attemptID,
                "proposal_content_id": proposalID,
                "sequence": 0,
                "risk_tier": ["tier": "Standard"],
                "stage": ["stage": "Rules"],
                "status": ["status": "Certified"],
            ],
            "policy_version": 1,
            "required_bodies": [[
                "body": "rules-committee",
                "decision_mode": ["mode": "PublicFinding"],
            ]],
            "body_states": [[
                "body": "rules-committee",
                "body_instance_id": identifier(1),
                "status": ["status": "Approved"],
                "public_finding_opened_at_height": 1,
                "public_finding_phase_blocks": 7,
                "public_finding_deadline_height": 8,
                "no_result_kind": NSNull(),
                "no_result_height": NSNull(),
                "timed_ovn_progress": NSNull(),
            ]],
            "certificate": [
                "proposal_content_id": proposalID,
                "governance_attempt_id": attemptID,
                "governance_attempt_sequence": 0,
                "risk_tier": ["tier": "Standard"],
                "body_bindings": [[
                    "body_instance_id": identifier(1),
                    "election_attempt_id": identifier(2),
                    "election_attempt_sequence": 0,
                    "sortition_request_id": identifier(3),
                    "sortition_request": [
                        "id": identifier(3),
                        "governance_attempt_id": attemptID,
                        "body_election_attempt_id": identifier(2),
                        "body": "rules-committee",
                        "candidate_root": root,
                        "candidate_count": 3,
                        "target_seats": 3,
                        "request_height": 1,
                        "pulse_height": 2,
                        "beacon_session_id": identifier(4),
                    ],
                    "body": "rules-committee",
                    "original_seats": 3,
                    "beacon_session_id": identifier(4),
                    "beacon_pulse_id": identifier(5),
                    "roster_root": root,
                    "assignment_root": root,
                    "result_root": root,
                    "result_height": 8,
                    "public_finding": [
                        "endorsement_root": root,
                        "endorsing_assignments": exactSupporters,
                        "endorsements": 2,
                        "quorum": 2,
                    ],
                    "ballot": NSNull(),
                ]],
                "policy_version": 1,
                "effect_preimage_hash": root,
                "expected_head": ["state": "Absent", "head": ["subject_id": root]],
                "certified_at_height": 8,
                "enact_at_height": 10,
            ],
            "terminal_height": NSNull(),
            "execution_failure_root": NSNull(),
            "superseding_head": NSNull(),
            "state_payload_hex": framedHex(),
        ]
    }

    private func assertConfirmationMutationRejected(
        _ mutation: (inout [String: Any], inout [String: Any]) -> Void
    ) {
        var response = makeConfirmationBallotReadResponse()
        var certificate = response["certificate"] as! [String: Any]
        var bindings = certificate["body_bindings"] as! [[String: Any]]
        var policy = bindings[0]
        var confirmation = bindings[1]
        mutation(&policy, &confirmation)
        bindings[0] = policy
        bindings[1] = confirmation
        certificate["body_bindings"] = bindings
        response["certificate"] = certificate
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(response),
                expectedGovernanceAttemptId: attemptID
            )
        )
    }

    private func makeConfirmationBallotReadResponse(
        electionAttemptSequence: Int = 0,
        requestHeight: Int = 48,
        pulseHeight: Int = 49
    ) -> [String: Any] {
        var response = makeHiddenBallotReadResponse()
        var policyState = (response["body_states"] as! [[String: Any]])[0]
        policyState["timed_ovn_progress"] = [
            "ballot_attempt_id": identifier(0x21),
            "status": ["status": "Finalized"],
            "frozen_survivor_count": 21,
            "accepted_ballot_prefix_count": 21,
        ]

        var certificate = response["certificate"] as! [String: Any]
        var policy = (certificate["body_bindings"] as! [[String: Any]])[0]
        policy["original_seats"] = 21
        policy["result_height"] = 48
        var policyRequest = policy["sortition_request"] as! [String: Any]
        policyRequest["candidate_count"] = 21
        policyRequest["target_seats"] = 21
        policy["sortition_request"] = policyRequest
        var policyBallot = policy["ballot"] as! [String: Any]
        policyBallot["max_corpus_entries"] = 21
        policyBallot["registration_close_height"] = 23
        policyBallot["survivor_freeze_height"] = 44
        policyBallot["commitment_close_height"] = 45
        policyBallot["registration_closed_at_height"] = 23
        policyBallot["survivors_frozen_at_height"] = 44
        policyBallot["commitment_closed_at_height"] = 45
        policyBallot["release_height"] = 46
        policyBallot["opening_deadline_height"] = 50
        policyBallot["opening_height"] = 47
        policyBallot["tally"] = [
            "original_seats": 21,
            "accepted_ballots": 21,
            "aye": 11,
            "nay": 10,
            "abstain": 0,
        ]
        policy["ballot"] = policyBallot

        var confirmation = policy
        confirmation["body_instance_id"] = identifier(0x31)
        confirmation["election_attempt_id"] = identifier(0x32)
        confirmation["election_attempt_sequence"] = electionAttemptSequence
        confirmation["sortition_request_id"] = identifier(0x33)
        confirmation["body"] = "confirmation-jury"
        confirmation["beacon_session_id"] = identifier(0x34)
        confirmation["beacon_pulse_id"] = identifier(0x35)
        confirmation["result_height"] = 98
        var confirmationRequest = policyRequest
        confirmationRequest["id"] = identifier(0x33)
        confirmationRequest["body_election_attempt_id"] = identifier(0x32)
        confirmationRequest["body"] = "confirmation-jury"
        confirmationRequest["request_height"] = requestHeight
        confirmationRequest["pulse_height"] = pulseHeight
        confirmationRequest["beacon_session_id"] = identifier(0x34)
        confirmation["sortition_request"] = confirmationRequest
        var confirmationBallot = policyBallot
        confirmationBallot["ballot_attempt_id"] = identifier(0x36)
        confirmationBallot["tle_session_id"] = identifier(0x37)
        confirmationBallot["tle_key_session_id"] = identifier(0x38)
        confirmationBallot["release_beacon_session_id"] = identifier(0x39)
        confirmationBallot["registered_at_height"] = 50
        confirmationBallot["registration_close_height"] = 72
        confirmationBallot["survivor_freeze_height"] = 93
        confirmationBallot["commitment_close_height"] = 94
        confirmationBallot["registration_closed_at_height"] = 72
        confirmationBallot["survivors_frozen_at_height"] = 93
        confirmationBallot["commitment_closed_at_height"] = 94
        confirmationBallot["release_height"] = 95
        confirmationBallot["opening_deadline_height"] = 99
        confirmationBallot["release_pulse_id"] = identifier(0x3a)
        confirmationBallot["opening_height"] = 96
        confirmation["ballot"] = confirmationBallot

        var confirmationState = policyState
        confirmationState["body"] = "confirmation-jury"
        confirmationState["body_instance_id"] = identifier(0x31)
        confirmationState["timed_ovn_progress"] = [
            "ballot_attempt_id": identifier(0x36),
            "status": ["status": "Finalized"],
            "frozen_survivor_count": 21,
            "accepted_ballot_prefix_count": 21,
        ]
        response["required_bodies"] = [
            ["body": "policy-jury", "decision_mode": ["mode": "HiddenBindingBallot"]],
            ["body": "confirmation-jury", "decision_mode": ["mode": "HiddenBindingBallot"]],
        ]
        response["body_states"] = [policyState, confirmationState]
        certificate["body_bindings"] = [policy, confirmation]
        certificate["certified_at_height"] = 98
        certificate["enact_at_height"] = 100
        response["certificate"] = certificate
        response["current_height"] = 99
        return response
    }

    private func makeHiddenBallotReadResponse() -> [String: Any] {
        var response = mutateCertificate(makePublicOnlyReadResponse()) { certificate, binding, request in
            binding["body"] = "policy-jury"
            binding["body_instance_id"] = identifier(0x06)
            binding["election_attempt_id"] = identifier(0x07)
            binding["sortition_request_id"] = identifier(0x08)
            binding["beacon_session_id"] = identifier(0x09)
            binding["beacon_pulse_id"] = identifier(0x0a)
            request["id"] = identifier(0x08)
            request["body_election_attempt_id"] = identifier(0x07)
            request["body"] = "policy-jury"
            request["beacon_session_id"] = identifier(0x09)
            binding["public_finding"] = NSNull()
            binding["ballot"] = [
                "ballot_attempt_id": identifier(0x21),
                "ballot_attempt_sequence": 0,
                "tle_session_id": identifier(0x22),
                "tle_key_session_id": identifier(0x23),
                "registration_root": root,
                "dropout_root": root,
                "survivor_root": root,
                "corpus_root": root,
                "no_recovery_root": root,
                "timed_commitment_root": root,
                "release_beacon_session_id": identifier(0x24),
                "registered_at_height": 1,
                "registration_close_height": 5,
                "survivor_freeze_height": 8,
                "commitment_close_height": 9,
                "registration_closed_at_height": 5,
                "survivors_frozen_at_height": 8,
                "commitment_closed_at_height": 9,
                "max_ballot_retries": 16,
                "max_corpus_entries": 3,
                "release_height": 10,
                "opening_deadline_height": 13,
                "release_pulse_id": identifier(0x25),
                "opening_height": 11,
                "opening_root": root,
                "tally": [
                    "original_seats": 3,
                    "accepted_ballots": 3,
                    "aye": 2,
                    "nay": 1,
                    "abstain": 0,
                ],
                "outcome": ["outcome": "Approved"],
            ]
            binding["result_height"] = 12
            certificate["certified_at_height"] = 12
            certificate["enact_at_height"] = 14
        }
        response["required_bodies"] = [[
            "body": "policy-jury",
            "decision_mode": ["mode": "HiddenBindingBallot"],
        ]]
        var states = response["body_states"] as! [[String: Any]]
        states[0]["body"] = "policy-jury"
        states[0]["body_instance_id"] = identifier(0x06)
        states[0]["public_finding_opened_at_height"] = NSNull()
        states[0]["public_finding_phase_blocks"] = NSNull()
        states[0]["public_finding_deadline_height"] = NSNull()
        states[0]["timed_ovn_progress"] = [
            "ballot_attempt_id": identifier(0x21),
            "status": ["status": "Finalized"],
            "frozen_survivor_count": 3,
            "accepted_ballot_prefix_count": 3,
        ]
        response["body_states"] = states
        response["current_height"] = 13
        return response
    }

    private func makeTleReleaseContextResponse() -> [String: Any] {
        let ballotID = identifier(0x33)
        let bodyID = identifier(0x22)
        let keySessionID = identifier(0x44)
        let survivorRoot = [UInt8](repeating: 0x61, count: 32)
        let noRecoveryRoot = [UInt8](repeating: 0x62, count: 32)
        let parameterHash = [UInt8](repeating: 0x63, count: 32)
        var identityPayload = Data("iroha.parliament.tle.identity-payload.v1\0".utf8)
        identityPayload.append(contentsOf: bigEndian16(1))
        identityPayload.append(Data(hexString: attemptID)!)
        identityPayload.append(Data(hexString: bodyID)!)
        identityPayload.append(Data(hexString: ballotID)!)
        identityPayload.append(contentsOf: survivorRoot)
        identityPayload.append(contentsOf: noRecoveryRoot)
        identityPayload.append(contentsOf: bigEndian64(40))
        identityPayload.append(contentsOf: parameterHash)
        XCTAssertEqual(identityPayload.count, 243)

        let networkID = [UInt8](repeating: 0x45, count: 32)
        let rosterHash = [UInt8](repeating: 0x46, count: 32)
        var dealers = [[String: Any]]()
        for dealer in [1, 2] {
            let entry: [String: Any] = [
                "dealer_index": dealer,
                "coefficient_commitments": [
                    [UInt8](repeating: UInt8(0x50 + dealer), count: 96),
                    [UInt8](repeating: UInt8(0x60 + dealer), count: 96),
                ],
                "constant_pok_commitment": [UInt8](
                    repeating: UInt8(0x70 + dealer), count: 96
                ),
                "constant_pok_response": [UInt8](
                    repeating: UInt8(0x80 + dealer), count: 32
                ),
            ]
            dealers.append(entry)
        }
        var shares = [[String: Any]]()
        for index in 1...4 {
            let entry: [String: Any] = [
                "index": index,
                "participant_hash": [UInt8](
                    repeating: UInt8(0x20 + index), count: 32
                ),
                "public_key_share": [UInt8](
                    repeating: UInt8(0x30 + index), count: 96
                ),
            ]
            shares.append(entry)
        }
        let keySession: [String: Any] = [
            "version": 1,
            "key_session_id": keySessionID,
            "network_id": networkID,
            "roster_hash": rosterHash,
            "committee_size": 4,
            "threshold": 2,
            "generator_h": [UInt8](repeating: 0x47, count: 96),
            "generator_v": [UInt8](repeating: 0x48, count: 96),
            "qualified_dealers": [1, 2],
            "qualified_dealer_commitments": dealers,
            "dkg_event_hash": [UInt8](repeating: 0x49, count: 32),
            "group_public_key": [UInt8](repeating: 0x4a, count: 96),
            "public_shares": shares,
            "transcript_hash": [UInt8](repeating: 0x4b, count: 32),
        ]
        var framed = Data("iroha.threshold-bls.message.v1\0".utf8)
        framed.append(contentsOf: "iroha.threshold-bls.session.v1\0".utf8)
        framed.append(contentsOf: bigEndian16(1))
        framed.append(2)
        framed.append(contentsOf: networkID)
        framed.append(Data(hexString: keySessionID)!)
        framed.append(contentsOf: rosterHash)
        framed.append(contentsOf: bigEndian16(4))
        framed.append(contentsOf: bigEndian16(2))
        framed.append(contentsOf: bigEndian32(UInt32(identityPayload.count)))
        framed.append(identityPayload)
        return [
            "version": 1,
            "current_height": 42,
            "ballot_attempt_id": ballotID,
            "governance_attempt_id": attemptID,
            "body_instance_id": bodyID,
            "status": ["status": "Opening"],
            "release_height": 40,
            "opening_deadline_height": 45,
            "tle_key_session": keySession,
            "release_identity": [
                "tle_key_session_id": keySessionID,
                "governance_attempt_id": attemptID,
                "body_instance_id": bodyID,
                "ballot_attempt_id": ballotID,
                "survivor_corpus_root": survivorRoot,
                "no_recovery_root": noRecoveryRoot,
                "target_finalized_height": 40,
                "parameter_hash": parameterHash,
            ],
            "identity_digest": [UInt8](SHA256.hash(data: framed)),
            "identity_payload_hex": identityPayload.hexEncodedString(),
        ]
    }

    private func makeTlePartialReleaseResponse(
        context: [String: Any]
    ) -> [String: Any] {
        let session = context["tle_key_session"] as! [String: Any]
        return [
            "key_session_id": session["key_session_id"]!,
            "identity_digest": context["identity_digest"]!,
            "participant_index": 1,
            "sigma": [UInt8](repeating: 0x91, count: 48),
            "proof_x": [UInt8](repeating: 0x92, count: 96),
            "proof_y": [UInt8](repeating: 0x93, count: 48),
            "z_s": [UInt8](repeating: 0x94, count: 32),
            "z_r": [UInt8](repeating: 0x95, count: 32),
            "z_u": [UInt8](repeating: 0x96, count: 32),
        ]
    }

    private func makeTimedOvnCastingContextResponse() -> [String: Any] {
        let release = makeTleReleaseContextResponse()
        let keySession = release["tle_key_session"] as! [String: Any]
        let identity = release["release_identity"] as! [String: Any]
        return [
            "version": 1,
            "current_height": 30,
            "phase": "Registered",
            "session": [
                "network_id": keySession["network_id"]!,
                "proposal_content_id": proposalID,
                "governance_attempt_id": attemptID,
                "body_instance_id": release["body_instance_id"]!,
                "ballot_attempt_id": release["ballot_attempt_id"]!,
                "parameter_hash": identity["parameter_hash"]!,
                "tle_key_session_id": keySession["key_session_id"]!,
                "tle_key_transcript_hash": keySession["transcript_hash"]!,
                "tle_master_public_key": keySession["group_public_key"]!,
            ],
            "registration_opened_at_finalized_height": 20,
            "target_finalized_height": 40,
            "tle_key_session": keySession,
            "registration_records_hex": [String(repeating: "81", count: 3_624)],
            "survivor_participant_hashes": NSNull(),
            "release_identity": NSNull(),
            "archive_norito_base64": Data("NRT0".utf8).base64EncodedString(),
        ]
    }

    private func bigEndian16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xff)]
    }

    private func bigEndian32(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff), UInt8(value & 0xff),
        ]
    }

    private func bigEndian64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).map { offset in UInt8((value >> UInt64(8 * (7 - offset))) & 0xff) }
    }

    private func framedHex() -> String {
        noritoEncode(
            typeName: "iroha.governance.parliament.swift.fixture.v1",
            payload: Data([1, 2])
        ).hexEncodedString()
    }

    private func identifier(_ byte: UInt8) -> String {
        String(repeating: String(format: "%02x", byte), count: 32)
    }

    private func jsonData(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    private func fixtureObject() throws -> [String: Any] {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 {
            root.deleteLastPathComponent()
        }
        let fixture = root.appendingPathComponent(
            "fixtures/governance/parliament_api_v1.json"
        )
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixture)) as? [String: Any]
        )
    }
}

private final class ParliamentCastingProofPagingRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var requests = 0
    private var verifierCalls = 0
    private var persisted: [UInt64] = []

    func recordRequest() -> Int {
        lock.lock()
        defer { lock.unlock() }
        let current = requests
        requests += 1
        return current
    }

    func nextVerifierCall() -> Int {
        lock.lock()
        defer { lock.unlock() }
        let current = verifierCalls
        verifierCalls += 1
        return current
    }

    func recordPersistence(_ height: UInt64) {
        lock.lock()
        persisted.append(height)
        lock.unlock()
    }

    func requestCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    func persistedHeights() -> [UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return persisted
    }
}

private final class ParliamentCastingProofStubURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data?))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(
                self,
                didFailWithError: NSError(domain: "ParliamentCastingProofStub", code: -1)
            )
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if let data {
                client?.urlProtocol(self, didLoad: data)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
