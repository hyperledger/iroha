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
            Set(limits.keys),
            ["attempt_state_bytes", "governance_attempt_sequence_max"]
        )
        XCTAssertEqual(
            limits["attempt_state_bytes"],
            ToriiParliamentAPIV1.maximumAttemptStateBytes
        )
        XCTAssertEqual(
            limits["governance_attempt_sequence_max"],
            Int(ToriiParliamentAPIV1.maximumGovernanceAttemptRetries)
        )
        XCTAssertEqual(
            Set(routes.keys),
            ["attempt_draft", "attempt_read", "transition_draft"]
        )
        XCTAssertEqual(routes["attempt_draft"], ToriiParliamentAPIV1.attemptDraftPath)
        XCTAssertEqual(routes["attempt_read"], ToriiParliamentAPIV1.attemptReadPathTemplate)
        XCTAssertEqual(routes["transition_draft"], ToriiParliamentAPIV1.transitionDraftPath)
        let wireIds = try XCTUnwrap(fixture["wire_ids"] as? [String: String])
        XCTAssertEqual(wireIds["attempt_create"], ToriiParliamentAPIV1.attemptCreateWireId)
        XCTAssertEqual(wireIds["transition_submit"], ToriiParliamentAPIV1.transitionSubmitWireId)
        let digestDomains = try XCTUnwrap(fixture["digest_domains"] as? [String: String])
        XCTAssertEqual(
            digestDomains["public_transition"],
            ToriiParliamentAPIV1.publicTransitionDigestDomain
        )
        XCTAssertEqual(
            digestDomains["automatic_execution_outcome"],
            ToriiParliamentAPIV1.automaticOutcomeDigestDomain
        )

        let transitions = try XCTUnwrap(fixture["public_transitions"] as? [[String: Any]])
        XCTAssertEqual(transitions.count, 13)
        XCTAssertEqual(transitions.count, ToriiParliamentAPIV1.publicTransitions.count)
        for (fixtureEntry, sdkEntry) in zip(transitions, ToriiParliamentAPIV1.publicTransitions) {
            XCTAssertEqual(fixtureEntry["norito_index"] as? Int, Int(sdkEntry.noritoIndex))
            XCTAssertEqual(
                fixtureEntry["norito_prefix_hex"] as? String,
                String(format: "%02x", sdkEntry.noritoIndex)
            )
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
        XCTAssertEqual(outcomes.count, 3)
        XCTAssertEqual(outcomes.count, ToriiParliamentAPIV1.automaticExecutionOutcomes.count)
        for (fixtureEntry, sdkEntry) in zip(outcomes, ToriiParliamentAPIV1.automaticExecutionOutcomes) {
            XCTAssertEqual(fixtureEntry["norito_index"] as? Int, Int(sdkEntry.noritoIndex))
            XCTAssertEqual(fixtureEntry["json_tag"] as? String, sdkEntry.jsonTag)
            XCTAssertEqual(fixtureEntry["event_kind"] as? String, sdkEntry.eventKind)
            XCTAssertEqual(fixtureEntry["event_kind_index"] as? Int, Int(sdkEntry.eventKindIndex))
            XCTAssertEqual(
                fixtureEntry["json_payload"] as? String == "required",
                sdkEntry.jsonPayloadRequired
            )
        }
        let reasons = try XCTUnwrap(fixture["no_result_kinds"] as? [[String: Any]])
        XCTAssertEqual(reasons.count, 5)
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
        XCTAssertEqual(ToriiParliamentAPIV1.bodyStateFields.count, 8)
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
        XCTAssertEqual(transition.layout.noritoIndex, 12)
        XCTAssertEqual(transition.layout.jsonTag, "RegisterInitialSortition")
        XCTAssertFalse(transition.layout.jsonPayloadRequired)
        XCTAssertEqual(transition.layout.eventKindIndex, 15)

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

    func testEveryPublicTransitionCaseEncodesItsFixtureLayout() throws {
        let bodyID = identifier(5)
        let cases: [(ToriiParliamentLifecycleTransitionV1, Int)] = [
            (.escalateRisk(target: .object(["tier": .string("Constitutional")])), 0),
            (.completeQualification, 1),
            (
                .registerSortitionRequest(requests: [
                    .init(sequence: 0, request: .object(["body": .string("rules-committee")])),
                ]),
                2
            ),
            (
                .consumeSortitionPulseBatch(
                    requestIds: [identifier(1)],
                    beaconSessionId: identifier(2),
                    pulseHeight: 5,
                    pulseId: identifier(3)
                ),
                3
            ),
            (.beginInvitationAcceptance(electionAttemptId: identifier(4)), 4),
            (.failBodyElectionNoRoster(electionAttemptId: identifier(4)), 5),
            (.sealBodyRoster(electionAttemptId: identifier(4)), 6),
            (.advanceBodyPhase(bodyInstanceId: bodyID, target: .object(["phase": .string("Evidence")])), 7),
            (.recordAttemptAbsence(bodyInstanceId: bodyID, assignmentId: identifier(6)), 8),
            (.endorsePublicFinding(bodyInstanceId: bodyID, resultRoot: root), 9),
            (
                .recordInvitationResponse(
                    electionAttemptId: identifier(4),
                    body: "rules-committee",
                    decision: "Accept"
                ),
                10
            ),
            (.failPublicFindingNoResult(bodyInstanceId: bodyID), 11),
            (.registerInitialSortition, 12),
        ]
        XCTAssertEqual(cases.count, ToriiParliamentAPIV1.publicTransitions.count)
        XCTAssertEqual(cases.map { $0.1 }, Array(0..<cases.count))
        for (transition, expectedIndex) in cases {
            let layout = transition.layout
            XCTAssertEqual(layout, ToriiParliamentAPIV1.publicTransitions[expectedIndex])
            XCTAssertEqual(Int(layout.noritoIndex), expectedIndex, layout.jsonTag)
            let encoded = try ToriiParliamentAPIV1.transitionDraftRequestData(
                governanceAttemptId: attemptID,
                transition: transition
            )
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: encoded) as? [String: Any]
            )
            let tagged = try XCTUnwrap(object["transition"] as? [String: Any])
            XCTAssertEqual(tagged["transition"] as? String, layout.jsonTag)
            XCTAssertEqual(tagged["payload"] != nil, layout.jsonPayloadRequired, layout.jsonTag)
        }

        let response = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: ToriiParliamentAPIV1.transitionDraftRequestData(
                    governanceAttemptId: attemptID,
                    transition: .recordInvitationResponse(
                        electionAttemptId: identifier(4),
                        body: "rules-committee",
                        decision: "Decline"
                    )
                )
            ) as? [String: Any]
        )
        let tagged = try XCTUnwrap(response["transition"] as? [String: Any])
        let payload = try XCTUnwrap(tagged["payload"] as? [String: Any])
        XCTAssertEqual(Set(payload.keys), ["election_attempt_id", "body", "decision"])
        XCTAssertEqual(payload["decision"] as? [String: String], ["decision": "Decline"])
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.transitionDraftRequestData(
                governanceAttemptId: attemptID,
                transition: .recordInvitationResponse(
                    electionAttemptId: identifier(4),
                    body: "rules-committee",
                    decision: "Abstain"
                )
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

    func testReadProjectionValidatesScheduleNoResultAndExactSupporters() throws {
        let valid = try jsonData(makeReadResponse())
        let parsed = try ToriiParliamentAPIV1.decodeAttemptReadResponse(
            valid,
            expectedGovernanceAttemptId: attemptID
        )
        XCTAssertEqual(parsed.bodyStates.count, 2)
        XCTAssertEqual(parsed.requiredBodyOrder, ["rules-committee", "agenda-council"])
        XCTAssertEqual(parsed.bodyStates[0].body, "rules-committee")
        XCTAssertEqual(parsed.certificateBodyOrder, ["rules-committee", "agenda-council"])
        XCTAssertEqual(parsed.bodyStates[0].publicFindingDeadlineHeight, 8)
        XCTAssertEqual(parsed.bodyStates[1].publicFindingDeadlineHeight, 12)
        XCTAssertEqual(parsed.publicFindingBindings.count, 2)
        XCTAssertEqual(
            parsed.publicFindingBindings[0].endorsingAssignments,
            [identifier(0x11), identifier(0x12)]
        )
        XCTAssertEqual(
            parsed.publicFindingBindings[1].endorsingAssignments,
            [identifier(0x21), identifier(0x22)]
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

    func testReadProjectionRejectsForgedCertificateBindings() throws {
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
            mutateCertificate(makeReadResponse()) { certificate, _, _ in
                certificate["certified_at_height"] = 11
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
            mutateCertificate(makeReadResponse()) { _, binding, _ in
                binding["ballot"] = ["unexpected": "payload"]
            },
            mutateCertificate(makeReadResponse()) { _, binding, _ in
                binding["public_finding"] = NSNull()
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

        var reusedBodyInstance = makeReadResponse()
        var reusedCertificate = try XCTUnwrap(reusedBodyInstance["certificate"] as? [String: Any])
        var reusedBindings = try XCTUnwrap(reusedCertificate["body_bindings"] as? [[String: Any]])
        reusedBindings[1]["body_instance_id"] = reusedBindings[0]["body_instance_id"]
        reusedCertificate["body_bindings"] = reusedBindings
        reusedBodyInstance["certificate"] = reusedCertificate
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(reusedBodyInstance),
                expectedGovernanceAttemptId: attemptID
            )
        ) { error in
            guard case ToriiClientError.invalidPayload(let message) = error else {
                return XCTFail("expected an invalid-payload rejection")
            }
            XCTAssertEqual(
                message,
                "certificate.body_bindings reuse an attempt-local identifier."
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

        let seatBoundary = mutateCertificate(makeReadResponse()) { _, _, request in
            request["target_seats"] = ToriiParliamentAPIV1.maximumBodyTargetSeats
        }
        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(seatBoundary),
                expectedGovernanceAttemptId: attemptID
            )
        )
        let seatOverflow = mutateCertificate(makeReadResponse()) { _, _, request in
            request["target_seats"] = ToriiParliamentAPIV1.maximumBodyTargetSeats + 1
        }
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(seatOverflow),
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

        // A certificate whose required bodies are all public-finding bodies is admitted.
        let publicOnly = try ToriiParliamentAPIV1.decodeAttemptReadResponse(
            jsonData(makePublicOnlyReadResponse()),
            expectedGovernanceAttemptId: attemptID
        )
        XCTAssertEqual(publicOnly.certificateBodyOrder, ["rules-committee"])
        XCTAssertEqual(publicOnly.publicFindingBindings.count, 1)

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
    }

    func testCertificateWithPrivateJuryBindingIsRejectedUntilAnonymousBallotBindingLands() throws {
        let expectedMessage =
            "private-jury result binding is not admitted until the anonymous-ballot result binding is supported"
        let pipelines: [(bodies: [BodyParts], rejectedIndex: Int, name: String)] = [
            (
                [
                    makePublicBody("rules-committee", seed: 1, openedAt: 1, resultHeight: 8),
                    makePrivateJuryBody("policy-jury", seed: 0x30, resultHeight: 12),
                ],
                1,
                "policy-jury after a public body"
            ),
            (
                [makePrivateJuryBody("policy-jury", seed: 0x30, resultHeight: 12)],
                0,
                "policy-jury alone"
            ),
            (
                [
                    makePublicBody("agenda-council", seed: 0x10, openedAt: 5, resultHeight: 12),
                    makePrivateJuryBody("confirmation-jury", seed: 0x40, resultHeight: 12),
                ],
                1,
                "confirmation-jury after a public body"
            ),
        ]
        for pipeline in pipelines {
            let latestResultHeight = pipeline.bodies
                .compactMap { $0.binding["result_height"] as? Int }
                .max() ?? 0
            let response = makeAttemptReadResponse(
                bodies: pipeline.bodies,
                certifiedAtHeight: latestResultHeight,
                currentHeight: latestResultHeight + 1
            )
            XCTAssertThrowsError(
                try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                    jsonData(response),
                    expectedGovernanceAttemptId: attemptID
                ),
                pipeline.name
            ) { error in
                guard case ToriiClientError.invalidPayload(let message) = error else {
                    return XCTFail("expected an invalid-payload rejection for \(pipeline.name)")
                }
                XCTAssertEqual(
                    message,
                    "certificate.body_bindings[\(pipeline.rejectedIndex)] \(expectedMessage)",
                    pipeline.name
                )
            }
        }
    }

    func testPrivateJuryBodyStatesStayReadableWithoutCertificate() throws {
        func decodedPrivateState(
            status: [String: Any],
            noResultKind: [String: Any]?,
            noResultHeight: Int?
        ) throws -> ToriiParliamentAttemptReadResponseV1 {
            var jury = makePrivateJuryBody("policy-jury", seed: 0x30, resultHeight: 12)
            jury.state["status"] = status
            if let noResultKind {
                jury.state["no_result_kind"] = noResultKind
            } else {
                jury.state["no_result_kind"] = NSNull()
            }
            if let noResultHeight {
                jury.state["no_result_height"] = noResultHeight
            } else {
                jury.state["no_result_height"] = NSNull()
            }
            var response = makeAttemptReadResponse(
                bodies: [jury],
                certifiedAtHeight: 12,
                currentHeight: 9
            )
            response["certificate"] = NSNull()
            var attempt = try XCTUnwrap(response["attempt"] as? [String: Any])
            attempt["stage"] = ["stage": "PolicyJury"]
            attempt["status"] = ["status": "Active"]
            response["attempt"] = attempt
            return try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(response),
                expectedGovernanceAttemptId: attemptID
            )
        }

        let balloting = try decodedPrivateState(
            status: ["status": "Balloting"],
            noResultKind: nil,
            noResultHeight: nil
        )
        XCTAssertEqual(balloting.requiredBodyOrder, ["policy-jury"])
        XCTAssertEqual(balloting.bodyStates[0].status, "Balloting")
        XCTAssertEqual(balloting.certificateBodyOrder, [])
        XCTAssertTrue(balloting.publicFindingBindings.isEmpty)

        for kind in [
            "SortitionRetriesExhausted",
            "ConfirmationJuryCapacityUnavailable",
            "RandomnessRedrawBudgetExhausted",
        ] {
            let noResult = try decodedPrivateState(
                status: ["status": "NoResult"],
                noResultKind: ["reason": kind],
                noResultHeight: 9
            )
            XCTAssertEqual(noResult.bodyStates[0].noResultKind, kind)
            XCTAssertEqual(noResult.bodyStates[0].noResultHeight, 9)
        }
        for kind in ["PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired"] {
            XCTAssertThrowsError(
                try decodedPrivateState(
                    status: ["status": "NoResult"],
                    noResultKind: ["reason": kind],
                    noResultHeight: 9
                ),
                kind
            )
        }
    }

    func testNoResultKindsFollowTheClosedFiveKindInventory() throws {
        XCTAssertEqual(
            ToriiParliamentAPIV1.noResultKinds.map(\.jsonTag),
            [
                "PublicFindingQuorumUnreachable",
                "PublicFindingDeadlineExpired",
                "SortitionRetriesExhausted",
                "ConfirmationJuryCapacityUnavailable",
                "RandomnessRedrawBudgetExhausted",
            ]
        )
        func publicNoResult(kind: String) throws -> ToriiParliamentAttemptReadResponseV1 {
            var response = makePublicOnlyReadResponse()
            var states = try XCTUnwrap(response["body_states"] as? [[String: Any]])
            states[0]["status"] = ["status": "NoResult"]
            states[0]["no_result_kind"] = ["reason": kind]
            states[0]["no_result_height"] = 9
            response["body_states"] = states
            response["certificate"] = NSNull()
            var attempt = try XCTUnwrap(response["attempt"] as? [String: Any])
            attempt["status"] = ["status": "Active"]
            response["attempt"] = attempt
            return try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(response),
                expectedGovernanceAttemptId: attemptID
            )
        }
        for kind in ["PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired"] {
            XCTAssertEqual(try publicNoResult(kind: kind).bodyStates[0].noResultKind, kind)
        }
        for kind in [
            "ConfirmationJuryCapacityUnavailable",
            "RandomnessRedrawBudgetExhausted",
            "UnknownNoResultKind",
        ] {
            XCTAssertThrowsError(try publicNoResult(kind: kind), kind)
        }
    }

    func testBodyStateProjectionRejectsUnknownAndMissingFields() throws {
        XCTAssertNoThrow(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(makePublicOnlyReadResponse()),
                expectedGovernanceAttemptId: attemptID
            )
        )
        var withUnknownField = makePublicOnlyReadResponse()
        var states = try XCTUnwrap(withUnknownField["body_states"] as? [[String: Any]])
        XCTAssertEqual(Set(states[0].keys), Set(ToriiParliamentAPIV1.bodyStateFields))
        states[0]["unexpected_field"] = NSNull()
        withUnknownField["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(withUnknownField),
                expectedGovernanceAttemptId: attemptID
            )
        )

        var withMissingField = makePublicOnlyReadResponse()
        states = try XCTUnwrap(withMissingField["body_states"] as? [[String: Any]])
        states[0].removeValue(forKey: "no_result_height")
        withMissingField["body_states"] = states
        XCTAssertThrowsError(
            try ToriiParliamentAPIV1.decodeAttemptReadResponse(
                jsonData(withMissingField),
                expectedGovernanceAttemptId: attemptID
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

    /// One required body: its pipeline entry, body-state projection and certificate binding.
    private struct BodyParts {
        var required: [String: Any]
        var state: [String: Any]
        var binding: [String: Any]
    }

    /// Two public-finding bodies certified at height 12.
    private func makeReadResponse(
        supporters: [String]? = nil
    ) -> [String: Any] {
        makeAttemptReadResponse(
            bodies: [
                makePublicBody(
                    "rules-committee",
                    seed: 1,
                    supporters: supporters,
                    openedAt: 1,
                    resultHeight: 8
                ),
                makePublicBody(
                    "agenda-council",
                    seed: 0x10,
                    supporters: [identifier(0x21), identifier(0x22)],
                    openedAt: 5,
                    resultHeight: 12
                ),
            ],
            certifiedAtHeight: 12,
            currentHeight: 13
        )
    }

    /// One public-finding body certified at height 8.
    private func makePublicOnlyReadResponse(
        supporters: [String]? = nil
    ) -> [String: Any] {
        makeAttemptReadResponse(
            bodies: [
                makePublicBody(
                    "rules-committee",
                    seed: 1,
                    supporters: supporters,
                    openedAt: 1,
                    resultHeight: 8
                ),
            ],
            certifiedAtHeight: 8,
            currentHeight: 9
        )
    }

    private func makeAttemptReadResponse(
        bodies: [BodyParts],
        certifiedAtHeight: Int,
        currentHeight: Int
    ) -> [String: Any] {
        [
            "version": 1,
            "current_height": currentHeight,
            "attempt": [
                "id": attemptID,
                "proposal_content_id": proposalID,
                "sequence": 0,
                "risk_tier": ["tier": "Standard"],
                "stage": ["stage": "Rules"],
                "status": ["status": "Certified"],
            ],
            "policy_version": 1,
            "required_bodies": bodies.map { $0.required },
            "body_states": bodies.map { $0.state },
            "certificate": [
                "proposal_content_id": proposalID,
                "governance_attempt_id": attemptID,
                "governance_attempt_sequence": 0,
                "risk_tier": ["tier": "Standard"],
                "body_bindings": bodies.map { $0.binding },
                "policy_version": 1,
                "effect_preimage_hash": root,
                "expected_head": ["state": "Absent", "head": ["subject_id": root]],
                "certified_at_height": certifiedAtHeight,
                "enact_at_height": certifiedAtHeight + 2,
            ],
            "terminal_height": NSNull(),
            "execution_failure_root": NSNull(),
            "superseding_head": NSNull(),
            "state_payload_hex": framedHex(),
        ]
    }

    private func makePublicBody(
        _ body: String,
        seed: UInt8,
        supporters: [String]? = nil,
        openedAt: Int,
        resultHeight: Int
    ) -> BodyParts {
        let exactSupporters = supporters ?? [identifier(0x11), identifier(0x12)]
        return BodyParts(
            required: [
                "body": body,
                "decision_mode": ["mode": "PublicFinding"],
            ],
            state: [
                "body": body,
                "body_instance_id": identifier(seed),
                "status": ["status": "Approved"],
                "public_finding_opened_at_height": openedAt,
                "public_finding_phase_blocks": 7,
                "public_finding_deadline_height": openedAt + 7,
                "no_result_kind": NSNull(),
                "no_result_height": NSNull(),
            ],
            binding: makeBodyBinding(
                body,
                seed: seed,
                resultHeight: resultHeight,
                publicFinding: [
                    "endorsement_root": root,
                    "endorsing_assignments": exactSupporters,
                    "endorsements": 2,
                    "quorum": 2,
                ],
                ballot: NSNull()
            )
        )
    }

    /// A private-jury body whose binding carries an opaque non-public payload.
    private func makePrivateJuryBody(
        _ body: String,
        seed: UInt8,
        resultHeight: Int
    ) -> BodyParts {
        BodyParts(
            required: [
                "body": body,
                "decision_mode": ["mode": "HiddenBindingBallot"],
            ],
            state: [
                "body": body,
                "body_instance_id": identifier(seed),
                "status": ["status": "Approved"],
                "public_finding_opened_at_height": NSNull(),
                "public_finding_phase_blocks": NSNull(),
                "public_finding_deadline_height": NSNull(),
                "no_result_kind": NSNull(),
                "no_result_height": NSNull(),
            ],
            binding: makeBodyBinding(
                body,
                seed: seed,
                resultHeight: resultHeight,
                publicFinding: NSNull(),
                ballot: ["opaque": "payload"]
            )
        )
    }

    private func makeBodyBinding(
        _ body: String,
        seed: UInt8,
        resultHeight: Int,
        publicFinding: Any,
        ballot: Any
    ) -> [String: Any] {
        [
            "body_instance_id": identifier(seed),
            "election_attempt_id": identifier(seed + 1),
            "election_attempt_sequence": 0,
            "sortition_request_id": identifier(seed + 2),
            "sortition_request": [
                "id": identifier(seed + 2),
                "governance_attempt_id": attemptID,
                "body_election_attempt_id": identifier(seed + 1),
                "body": body,
                "candidate_root": root,
                "candidate_count": 3,
                "target_seats": 3,
                "request_height": 1,
                "pulse_height": 2,
                "beacon_session_id": identifier(seed + 3),
            ],
            "body": body,
            "original_seats": 3,
            "beacon_session_id": identifier(seed + 3),
            "beacon_pulse_id": identifier(seed + 4),
            "roster_root": root,
            "assignment_root": root,
            "result_root": root,
            "result_height": resultHeight,
            "public_finding": publicFinding,
            "ballot": ballot,
        ]
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
