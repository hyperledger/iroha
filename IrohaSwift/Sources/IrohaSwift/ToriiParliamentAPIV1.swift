import Foundation

/// Stable wire/JSON/event mapping for one public Parliament lifecycle transition.
public struct ToriiParliamentTransitionLayoutV1: Sendable, Equatable {
    public let noritoIndex: UInt8
    public let jsonTag: String
    public let jsonPayloadRequired: Bool
    public let eventKindIndex: UInt8
}

/// Stable wire/JSON/event mapping for one consensus-owned automatic outcome.
///
/// These values are intentionally audit-only. `ToriiParliamentLifecycleTransitionV1`
/// has no case that can submit one of these outcomes.
public struct ToriiParliamentAutomaticOutcomeLayoutV1: Sendable, Equatable {
    public let noritoIndex: UInt8
    public let jsonTag: String
    public let jsonPayloadRequired: Bool
    public let eventKind: String
    public let eventKindIndex: UInt8
}

/// Stable Norito/JSON mapping for one closed body no-result audit class.
public struct ToriiParliamentNoResultKindLayoutV1: Sendable, Equatable {
    public let noritoIndex: UInt8
    public let jsonTag: String
}

/// One recursively validated member of the closed Parliament V1 proposal inventory.
///
/// The wire value is private and can only be created after the shared typed governance
/// decoder has validated the nested payload, so callers cannot submit an arbitrary object
/// under a recognized outer tag. Every kind is decoded field by field except
/// `SccpRouteGovernance`: its closed `SccpGovernanceProposalV1` envelope (network, base
/// revisions, subjects and action tags) is checked, while each action payload is only
/// required to be a JSON object until typed SCCP action decoding lands (see the TODO on
/// `ToriiGovernanceSccpRouteProposal`).
public struct ToriiParliamentProposalV1: Sendable, Equatable, Encodable {
    /// Typed proposal projection produced by the same strict decoder used for reads.
    public let kind: ToriiGovernanceProposalKind

    private let wireValue: ToriiJSONValue
    fileprivate let exactWireData: Data

    /// Validate one exact closed-inventory proposal wire value before it can enter a draft request.
    public init(validating data: Data) throws {
        let validated: GovernanceValidatedProposalJSON
        do {
            validated = try governanceValidatedProposalJSON(data)
        } catch {
            throw ToriiClientError.invalidPayload(
                "proposal must be valid UTF-8 JSON without duplicate keys and use exact canonical first-release unsigned integers."
            )
        }
        guard case .object(let proposal) = validated.value,
              case .string(let tag) = proposal["kind"],
              ToriiParliamentAPIV1.proposalKinds.contains(tag) else {
            throw ToriiClientError.invalidPayload("proposal.kind is unknown or retired")
        }
        let decoder = JSONDecoder()
        decoder.userInfo[exactJSONNumberLexemesUserInfoKey] = validated.numberLexemes
        kind = try decoder.decode(ToriiGovernanceProposalKind.self, from: data)
        wireValue = validated.value
        exactWireData = data
        try ToriiParliamentAPIV1.rejectSigningMaterial(wireValue, context: "proposal")
    }

    public func encode(to encoder: Encoder) throws {
        try wireValue.encode(to: encoder)
    }
}

/// The closed, submit-able V1 lifecycle transition set.
///
/// Consensus-owned certificate construction and automatic execution outcomes
/// are deliberately absent from this enum.
public struct ToriiParliamentSortitionRequestRegistrationV1:
    Sendable, Equatable, Encodable
{
    public let sequence: UInt32
    public let request: ToriiJSONValue

    public init(sequence: UInt32, request: ToriiJSONValue) {
        self.sequence = sequence
        self.request = request
    }

    private enum CodingKeys: String, CodingKey {
        case sequence
        case request
    }
}

public enum ToriiParliamentLifecycleTransitionV1: Sendable, Equatable, Encodable {
    case escalateRisk(target: ToriiJSONValue)
    case completeQualification
    case registerSortitionRequest(requests: [ToriiParliamentSortitionRequestRegistrationV1])
    case consumeSortitionPulseBatch(requestIds: [String], beaconSessionId: String, pulseHeight: UInt64, pulseId: String)
    case beginInvitationAcceptance(electionAttemptId: String)
    case failBodyElectionNoRoster(electionAttemptId: String)
    case sealBodyRoster(electionAttemptId: String)
    case advanceBodyPhase(bodyInstanceId: String, target: ToriiJSONValue)
    case recordAttemptAbsence(bodyInstanceId: String, assignmentId: String)
    case endorsePublicFinding(bodyInstanceId: String, resultRoot: [UInt8])
    case recordInvitationResponse(electionAttemptId: String, body: String, decision: String)
    case failPublicFindingNoResult(bodyInstanceId: String)
    /// Register the first sortition generation using only the enclosing attempt binding.
    case registerInitialSortition

    public var layout: ToriiParliamentTransitionLayoutV1 {
        switch self {
        case .escalateRisk: ToriiParliamentAPIV1.publicTransitions[0]
        case .completeQualification: ToriiParliamentAPIV1.publicTransitions[1]
        case .registerSortitionRequest: ToriiParliamentAPIV1.publicTransitions[2]
        case .consumeSortitionPulseBatch: ToriiParliamentAPIV1.publicTransitions[3]
        case .beginInvitationAcceptance: ToriiParliamentAPIV1.publicTransitions[4]
        case .failBodyElectionNoRoster: ToriiParliamentAPIV1.publicTransitions[5]
        case .sealBodyRoster: ToriiParliamentAPIV1.publicTransitions[6]
        case .advanceBodyPhase: ToriiParliamentAPIV1.publicTransitions[7]
        case .recordAttemptAbsence: ToriiParliamentAPIV1.publicTransitions[8]
        case .endorsePublicFinding: ToriiParliamentAPIV1.publicTransitions[9]
        case .recordInvitationResponse: ToriiParliamentAPIV1.publicTransitions[10]
        case .failPublicFindingNoResult: ToriiParliamentAPIV1.publicTransitions[11]
        case .registerInitialSortition: ToriiParliamentAPIV1.publicTransitions[12]
        }
    }

    public func encode(to encoder: Encoder) throws {
        try validate()
        var root = encoder.container(keyedBy: ToriiParliamentCodingKey.self)
        try root.encode(layout.jsonTag, forKey: .init("transition"))
        guard layout.jsonPayloadRequired else { return }
        var payload = root.nestedContainer(
            keyedBy: ToriiParliamentCodingKey.self,
            forKey: .init("payload")
        )
        switch self {
        case let .escalateRisk(target):
            try payload.encode(target, forKey: .init("target"))
        case .completeQualification, .registerInitialSortition:
            break
        case let .registerSortitionRequest(requests):
            try payload.encode(requests, forKey: .init("requests"))
        case let .consumeSortitionPulseBatch(requestIds, beaconSessionId, pulseHeight, pulseId):
            try payload.encode(requestIds, forKey: .init("request_ids"))
            try payload.encode(beaconSessionId, forKey: .init("beacon_session_id"))
            try payload.encode(pulseHeight, forKey: .init("pulse_height"))
            try payload.encode(pulseId, forKey: .init("pulse_id"))
        case let .beginInvitationAcceptance(electionAttemptId),
             let .failBodyElectionNoRoster(electionAttemptId),
             let .sealBodyRoster(electionAttemptId):
            try payload.encode(electionAttemptId, forKey: .init("election_attempt_id"))
        case let .advanceBodyPhase(bodyInstanceId, target):
            try payload.encode(bodyInstanceId, forKey: .init("body_instance_id"))
            try payload.encode(target, forKey: .init("target"))
        case let .recordAttemptAbsence(bodyInstanceId, assignmentId):
            try payload.encode(bodyInstanceId, forKey: .init("body_instance_id"))
            try payload.encode(assignmentId, forKey: .init("assignment_id"))
        case let .endorsePublicFinding(bodyInstanceId, resultRoot):
            try payload.encode(bodyInstanceId, forKey: .init("body_instance_id"))
            try payload.encode(resultRoot, forKey: .init("result_root"))
        case let .recordInvitationResponse(electionAttemptId, body, decision):
            try payload.encode(electionAttemptId, forKey: .init("election_attempt_id"))
            try payload.encode(body, forKey: .init("body"))
            var encodedDecision = payload.nestedContainer(
                keyedBy: ToriiParliamentCodingKey.self,
                forKey: .init("decision")
            )
            try encodedDecision.encode(decision, forKey: .init("decision"))
        case let .failPublicFindingNoResult(bodyInstanceId):
            try payload.encode(bodyInstanceId, forKey: .init("body_instance_id"))
        }
    }

    private func validate() throws {
        switch self {
        case let .escalateRisk(target):
            try ToriiParliamentAPIV1.rejectSigningMaterial(target, context: "EscalateRisk.target")
        case .completeQualification, .registerInitialSortition:
            break
        case let .registerSortitionRequest(requests):
            guard (1...ToriiParliamentAPIV1.maximumSortitionRequestsPerBatch)
                .contains(requests.count) else {
                throw ToriiClientError.invalidPayload(
                    "requests must contain one through 10 sortition registrations."
                )
            }
            for (index, registration) in requests.enumerated() {
                try ToriiParliamentAPIV1.rejectSigningMaterial(
                    registration.request,
                    context: "sortition requests[\(index)].request"
                )
            }
        case let .consumeSortitionPulseBatch(requestIds, beaconSessionId, _, pulseId):
            try ToriiParliamentAPIV1.requireStrictIdentifiers(requestIds, field: "request_ids")
            _ = try ToriiParliamentAPIV1.requireIdentifier(beaconSessionId, field: "beacon_session_id")
            _ = try ToriiParliamentAPIV1.requireIdentifier(pulseId, field: "pulse_id")
        case let .beginInvitationAcceptance(id),
             let .failBodyElectionNoRoster(id),
             let .sealBodyRoster(id):
            _ = try ToriiParliamentAPIV1.requireIdentifier(id, field: "election_attempt_id")
        case let .advanceBodyPhase(id, target):
            _ = try ToriiParliamentAPIV1.requireIdentifier(id, field: "body_instance_id")
            try ToriiParliamentAPIV1.rejectSigningMaterial(target, context: "body phase target")
        case let .recordAttemptAbsence(bodyId, assignmentId):
            _ = try ToriiParliamentAPIV1.requireIdentifier(bodyId, field: "body_instance_id")
            _ = try ToriiParliamentAPIV1.requireIdentifier(assignmentId, field: "assignment_id")
        case let .endorsePublicFinding(bodyId, resultRoot):
            _ = try ToriiParliamentAPIV1.requireIdentifier(bodyId, field: "body_instance_id")
            try ToriiParliamentAPIV1.requireFixedBytes(resultRoot, count: 32, nonzero: true, field: "result_root")
        case let .recordInvitationResponse(id, body, decision):
            _ = try ToriiParliamentAPIV1.requireIdentifier(id, field: "election_attempt_id")
            try ToriiParliamentAPIV1.requireBody(body, field: "body")
            guard decision == "Accept" || decision == "Decline" else {
                throw ToriiClientError.invalidPayload("decision must be Accept or Decline.")
            }
        case let .failPublicFindingNoResult(id):
            _ = try ToriiParliamentAPIV1.requireIdentifier(id, field: "body_instance_id")
        }
    }
}

/// One canonical native instruction returned by a Parliament draft route.
public struct ToriiParliamentInstructionDraftV1: Sendable, Equatable {
    public let wireId: String
    public let payloadHex: String
}

/// Strict result from the attempt-draft route.
public struct ToriiParliamentAttemptDraftResponseV1: Sendable, Equatable {
    public let proposalContentId: String
    public let governanceAttemptId: String
    public let instruction: ToriiParliamentInstructionDraftV1
}

/// Strict result from the lifecycle-transition draft route.
public struct ToriiParliamentTransitionDraftResponseV1: Sendable, Equatable {
    public let governanceAttemptId: String
    public let transitionKind: String
    public let transitionDigest: [UInt8]
    public let instruction: ToriiParliamentInstructionDraftV1
}

/// Exact authority-authenticated supporter list included in a public-finding certificate.
public struct ToriiParliamentPublicFindingCertificateBindingV1: Sendable, Equatable {
    public let endorsementRoot: [UInt8]
    public let endorsingAssignments: [String]
    public let endorsements: UInt32
    public let quorum: UInt32
}

/// Bounded public lifecycle/deadline projection for one required Parliament body.
///
/// Only the lifecycle, the public-finding schedule and the closed terminal failure class are
/// public; private-ballot material is never represented here.
public struct ToriiParliamentBodyStateProjectionV1: Sendable, Equatable {
    public let body: String
    public let bodyInstanceId: String?
    public let status: String?
    public let deliberationPhase: String?
    public let publicFindingOpenedAtHeight: UInt64?
    public let publicFindingPhaseBlocks: UInt64?
    public let publicFindingDeadlineHeight: UInt64?
    public let noResultKind: String?
    public let noResultHeight: UInt64?
}

/// Strict outer projection from the authenticated attempt-read route.
public struct ToriiParliamentAttemptReadResponseV1: Sendable, Equatable {
    public let governanceAttemptId: String
    public let currentHeight: UInt64
    public let policyVersion: UInt64
    public let terminalHeight: UInt64?
    public let executionFailureRoot: [UInt8]?
    public let statePayloadHex: String
    /// Canonical ordered body names admitted from `required_bodies`.
    public let requiredBodyOrder: [String]
    public let bodyStates: [ToriiParliamentBodyStateProjectionV1]
    /// Canonical ordered body names carried by the certificate, or empty when absent.
    public let certificateBodyOrder: [String]
    public let publicFindingBindings: [ToriiParliamentPublicFindingCertificateBindingV1]
    public let rawJSON: Data
}

private struct ToriiParliamentCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init(_ stringValue: String) {
        self.stringValue = stringValue
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        return nil
    }
}

/// Canonical constants, request builders, and strict response admission for Parliament API V1.
public enum ToriiParliamentAPIV1 {
    public static let version: UInt16 = 1
    public static let attemptDraftPath = "/v1/gov/parliament/attempts/draft"
    public static let attemptReadPathTemplate =
        "/v1/gov/parliament/attempts/{governance_attempt_id}"
    public static let transitionDraftPath = "/v1/gov/parliament/transitions/draft"
    public static let attemptCreateWireId =
        "iroha.governance.parliament.attempt.create.v1"
    public static let transitionSubmitWireId =
        "iroha.governance.parliament.transition.submit.v1"
    public static let maximumAttemptStateBytes = 16 * 1024 * 1024
    /// Upper bound for one body's target seats and every count derived from them (original seats,
    /// endorsing assignments, endorsements, quorum); mirrors Rust
    /// `MAX_PARLIAMENT_BODY_TARGET_SEATS_V1`.
    public static let maximumBodyTargetSeats = 1_000
    /// Maximum retry sequence for a whole governance attempt; valid sequences are 0 through 16.
    public static let maximumGovernanceAttemptRetries: UInt32 = 16
    private static let governancePolicyVersion: UInt64 = 1
    private static let maximumSortitionRetries: UInt32 = 16
    public static let maximumSortitionRequestsPerBatch = 10

    /// Closed first-release Parliament proposal-kind inventory in Norito wire-index order.
    public static let proposalKinds = [
        "DeployContract",
        "RuntimeUpgrade",
        "SccpRouteGovernance",
        "ValidationFeePolicy",
        "ValidationFeePayoutLifecycle",
        "MusubiRegistryGovernance",
        "SorafsProviderGovernance",
        "ContractLifecycleGovernance",
        "ContractEmergencyHold",
        "GlobalDataTriggerPermissionGovernance",
    ]

    /// Closed contract-lifecycle governance action inventory in wire-tag order.
    public static let contractLifecycleActions = [
        "Activate",
        "Deactivate",
        "OfferOwnership",
        "CancelOwnershipOffer",
        "AcceptParliamentOwnership",
        "CompleteEmergencyHoldRetrospective",
    ]

    public static let publicTransitionDigestDomain =
        "iroha.governance.parliament.lifecycle_transition.digest.v1"
    public static let automaticOutcomeDigestDomain =
        "iroha.governance.parliament.automatic_execution_outcome.digest.v1"

    public static let publicTransitions: [ToriiParliamentTransitionLayoutV1] = [
        .init(noritoIndex: 0, jsonTag: "EscalateRisk", jsonPayloadRequired: true, eventKindIndex: 0),
        .init(noritoIndex: 1, jsonTag: "CompleteQualification", jsonPayloadRequired: false, eventKindIndex: 1),
        .init(noritoIndex: 2, jsonTag: "RegisterSortitionRequest", jsonPayloadRequired: true, eventKindIndex: 2),
        .init(noritoIndex: 3, jsonTag: "ConsumeSortitionPulseBatch", jsonPayloadRequired: true, eventKindIndex: 3),
        .init(noritoIndex: 4, jsonTag: "BeginInvitationAcceptance", jsonPayloadRequired: true, eventKindIndex: 4),
        .init(noritoIndex: 5, jsonTag: "FailBodyElectionNoRoster", jsonPayloadRequired: true, eventKindIndex: 5),
        .init(noritoIndex: 6, jsonTag: "SealBodyRoster", jsonPayloadRequired: true, eventKindIndex: 6),
        .init(noritoIndex: 7, jsonTag: "AdvanceBodyPhase", jsonPayloadRequired: true, eventKindIndex: 7),
        .init(noritoIndex: 8, jsonTag: "RecordAttemptAbsence", jsonPayloadRequired: true, eventKindIndex: 8),
        .init(noritoIndex: 9, jsonTag: "EndorsePublicFinding", jsonPayloadRequired: true, eventKindIndex: 9),
        .init(noritoIndex: 10, jsonTag: "RecordInvitationResponse", jsonPayloadRequired: true, eventKindIndex: 13),
        .init(noritoIndex: 11, jsonTag: "FailPublicFindingNoResult", jsonPayloadRequired: true, eventKindIndex: 14),
        .init(noritoIndex: 12, jsonTag: "RegisterInitialSortition", jsonPayloadRequired: false, eventKindIndex: 15),
    ]

    public static let automaticExecutionOutcomes: [ToriiParliamentAutomaticOutcomeLayoutV1] = [
        .init(
            noritoIndex: 0,
            jsonTag: "Enacted",
            jsonPayloadRequired: false,
            eventKind: "MarkEnacted",
            eventKindIndex: 10
        ),
        .init(
            noritoIndex: 1,
            jsonTag: "Superseded",
            jsonPayloadRequired: true,
            eventKind: "MarkSuperseded",
            eventKindIndex: 11
        ),
        .init(
            noritoIndex: 2,
            jsonTag: "ExecutionFailed",
            jsonPayloadRequired: true,
            eventKind: "MarkExecutionFailed",
            eventKindIndex: 12
        ),
    ]

    public static let noResultKinds: [ToriiParliamentNoResultKindLayoutV1] = [
        .init(noritoIndex: 0, jsonTag: "PublicFindingQuorumUnreachable"),
        .init(noritoIndex: 1, jsonTag: "PublicFindingDeadlineExpired"),
        .init(noritoIndex: 2, jsonTag: "SortitionRetriesExhausted"),
        .init(noritoIndex: 3, jsonTag: "ConfirmationJuryCapacityUnavailable"),
        .init(noritoIndex: 4, jsonTag: "RandomnessRedrawBudgetExhausted"),
    ]

    public static let bodyStateFields = [
        "body",
        "body_instance_id",
        "status",
        "public_finding_opened_at_height",
        "public_finding_phase_blocks",
        "public_finding_deadline_height",
        "no_result_kind",
        "no_result_height",
    ]

    /// Canonical presentation order for first-release Parliament bodies.
    public static let canonicalBodyOrder = [
        "rules-committee",
        "agenda-council",
        "interest-panel",
        "review-panel",
        "coordination-council",
        "mpc-committee",
        "fma-committee",
        "oversight-committee",
        "policy-jury",
        "confirmation-jury",
    ]

    public static let certificateBodyBindingNoritoFields = [
        "body_instance_id",
        "election_attempt_id",
        "election_attempt_sequence",
        "sortition_request_id",
        "sortition_request",
        "body",
        "original_seats",
        "beacon_session_id",
        "beacon_pulse_id",
        "roster_root",
        "assignment_root",
        "result_root",
        "result_height",
        "public_finding",
        "ballot",
    ]

    public static let publicFindingCertificateNoritoFields = [
        "endorsement_root",
        "endorsing_assignments",
        "endorsements",
        "quorum",
    ]

    private static let bodies = Set(canonicalBodyOrder)
    private static let privateBodies: Set<String> = ["policy-jury", "confirmation-jury"]
    private static let riskTiers: Set<String> = [
        "Routine", "Standard", "Constitutional", "Emergency",
    ]
    private static let stages: Set<String> = [
        "Qualification", "Rules", "Agenda", "Interest", "Review", "Coordination",
        "Mpc", "Fma", "Oversight", "PolicyJury", "ConfirmationJury",
        "Certification", "Enactment",
    ]
    private static let statuses: Set<String> = [
        "Active", "Certified", "Rejected", "Enacted", "Superseded", "ExecutionFailed",
    ]
    private static let bodyStatuses: Set<String> = [
        "AwaitingSortition", "AcceptingInvitations", "RosterSealed", "Deliberating",
        "Balloting", "Approved", "Rejected", "NoQuorum", "NoResult", "Superseded",
    ]
    private static let deliberationPhases: Set<String> = [
        "Orientation", "Evidence", "Questions", "Responses", "Deliberation", "Reflection", "Vote",
    ]
    private static let privateKeyFields: Set<String> = [
        "private_key", "privateKey", "seed", "mnemonic", "private_key_seed",
    ]

    /// Replace the sole path parameter after exact nonzero identifier validation.
    public static func attemptReadPath(governanceAttemptId: String) throws -> String {
        let identifier = try requireIdentifier(
            governanceAttemptId,
            field: "governanceAttemptId"
        )
        return attemptReadPathTemplate.replacingOccurrences(
            of: "{governance_attempt_id}",
            with: identifier
        )
    }

    /// Encode the exact, versioned attempt-draft request body.
    public static func attemptDraftRequestData(
        proposal: ToriiParliamentProposalV1,
        attemptSequence: UInt32
    ) throws -> Data {
        guard attemptSequence <= maximumGovernanceAttemptRetries else {
            throw ToriiClientError.invalidPayload(
                "attempt_sequence must be between zero and 16."
            )
        }
        // Assemble this tiny fixed envelope around the already validated proposal
        // bytes so the draft carries exactly the proposal wire bytes that were
        // validated, without re-encoding them through JSONEncoder.
        var data = Data("{\"attempt_sequence\":\(attemptSequence),\"proposal\":".utf8)
        data.append(proposal.exactWireData)
        data.append(Data(",\"version\":\(version)}".utf8))
        return data
    }

    /// Encode the exact, versioned lifecycle-transition draft request body.
    public static func transitionDraftRequestData(
        governanceAttemptId: String,
        transition: ToriiParliamentLifecycleTransitionV1
    ) throws -> Data {
        let identifier = try requireIdentifier(
            governanceAttemptId,
            field: "governanceAttemptId"
        )
        return try JSONEncoder().encode(
            ToriiParliamentTransitionDraftEnvelopeV1(
                version: version,
                governanceAttemptId: identifier,
                transition: transition
            )
        )
    }

    /// Strictly decode and bind one attempt-draft response.
    public static func decodeAttemptDraftResponse(
        _ data: Data,
        expectedProposalContentId: String,
        expectedGovernanceAttemptId: String
    ) throws -> ToriiParliamentAttemptDraftResponseV1 {
        let root = try exactRoot(
            data,
            fields: ["version", "proposal_content_id", "governance_attempt_id", "tx_instructions"],
            context: "Parliament attempt draft response"
        )
        try requireVersion(root["version"])
        let proposalId = try requireIdentifier(
            root["proposal_content_id"],
            field: "proposal_content_id"
        )
        let attemptId = try requireIdentifier(
            root["governance_attempt_id"],
            field: "governance_attempt_id"
        )
        guard proposalId == (try requireIdentifier(
            expectedProposalContentId,
            field: "expectedProposalContentId"
        )) else {
            throw ToriiClientError.invalidPayload(
                "proposal_content_id differs from the exact request binding."
            )
        }
        guard attemptId == (try requireIdentifier(
            expectedGovernanceAttemptId,
            field: "expectedGovernanceAttemptId"
        )) else {
            throw ToriiClientError.invalidPayload(
                "governance_attempt_id differs from the exact request binding."
            )
        }
        return .init(
            proposalContentId: proposalId,
            governanceAttemptId: attemptId,
            instruction: try instruction(
                root["tx_instructions"],
                expectedWireId: attemptCreateWireId
            )
        )
    }

    /// Strictly decode and bind one transition-draft response.
    public static func decodeTransitionDraftResponse(
        _ data: Data,
        expectedGovernanceAttemptId: String,
        expectedTransitionKind: String,
        expectedTransitionDigest: [UInt8]
    ) throws -> ToriiParliamentTransitionDraftResponseV1 {
        guard publicTransitions.contains(where: { $0.jsonTag == expectedTransitionKind }) else {
            throw ToriiClientError.invalidPayload(
                "expected transition kind is unknown or automatic-only."
            )
        }
        try requireFixedBytes(
            expectedTransitionDigest,
            count: 32,
            nonzero: true,
            field: "expectedTransitionDigest"
        )
        let root = try exactRoot(
            data,
            fields: [
                "version", "governance_attempt_id", "transition_kind",
                "transition_digest", "tx_instructions",
            ],
            context: "Parliament transition draft response"
        )
        try requireVersion(root["version"])
        let attemptId = try requireIdentifier(
            root["governance_attempt_id"],
            field: "governance_attempt_id"
        )
        guard attemptId == (try requireIdentifier(
            expectedGovernanceAttemptId,
            field: "expectedGovernanceAttemptId"
        )) else {
            throw ToriiClientError.invalidPayload(
                "governance_attempt_id differs from the exact request binding."
            )
        }
        let transitionKind = try taggedUnit(
            root["transition_kind"],
            tag: "kind",
            admitted: Set(publicTransitions.map(\.jsonTag)),
            context: "transition_kind"
        )
        guard transitionKind == expectedTransitionKind else {
            throw ToriiClientError.invalidPayload(
                "transition_kind differs from the exact request binding."
            )
        }
        let digest = try fixedBytes(
            root["transition_digest"],
            count: 32,
            nonzero: true,
            field: "transition_digest"
        )
        guard digest == expectedTransitionDigest else {
            throw ToriiClientError.invalidPayload(
                "transition_digest differs from the exact request binding."
            )
        }
        return .init(
            governanceAttemptId: attemptId,
            transitionKind: transitionKind,
            transitionDigest: digest,
            instruction: try instruction(
                root["tx_instructions"],
                expectedWireId: transitionSubmitWireId
            )
        )
    }

    /// Strictly decode one bounded attempt-read response and its public supporters.
    public static func decodeAttemptReadResponse(
        _ data: Data,
        expectedGovernanceAttemptId: String
    ) throws -> ToriiParliamentAttemptReadResponseV1 {
        let root = try exactRoot(
            data,
            fields: [
                "version", "current_height", "attempt", "policy_version", "required_bodies",
                "body_states", "certificate", "terminal_height", "execution_failure_root",
                "superseding_head", "state_payload_hex",
            ],
            context: "Parliament attempt read response"
        )
        try requireVersion(root["version"])
        let currentHeight = try unsigned(root["current_height"], field: "current_height")
        let policyVersion = try unsigned(root["policy_version"], field: "policy_version")
        guard policyVersion == governancePolicyVersion else {
            throw ToriiClientError.invalidPayload(
                "policy_version must equal the first-release Parliament policy version."
            )
        }
        let terminalHeight = try optionalUnsigned(root["terminal_height"], field: "terminal_height")
        let executionFailureRoot = try optionalFixedBytes(
            root["execution_failure_root"],
            count: 32,
            nonzero: true,
            field: "execution_failure_root"
        )

        let attempt = try exactObject(
            root["attempt"],
            fields: ["id", "proposal_content_id", "sequence", "risk_tier", "stage", "status"],
            context: "attempt"
        )
        let attemptId = try requireIdentifier(attempt["id"], field: "attempt.id")
        guard attemptId == (try requireIdentifier(
            expectedGovernanceAttemptId,
            field: "expectedGovernanceAttemptId"
        )) else {
            throw ToriiClientError.invalidPayload(
                "attempt.id differs from the requested canonical identifier."
            )
        }
        let proposalContentId = try requireIdentifier(
            attempt["proposal_content_id"],
            field: "attempt.proposal_content_id"
        )
        let attemptSequence = try unsigned32(attempt["sequence"], field: "attempt.sequence")
        guard attemptSequence <= maximumGovernanceAttemptRetries else {
            throw ToriiClientError.invalidPayload(
                "attempt.sequence exceeds the first-release retry ceiling."
            )
        }
        let riskTier = try taggedUnit(
            attempt["risk_tier"], tag: "tier", admitted: riskTiers, context: "attempt.risk_tier"
        )
        _ = try taggedUnit(
            attempt["stage"], tag: "stage", admitted: stages, context: "attempt.stage"
        )
        _ = try taggedUnit(
            attempt["status"], tag: "status", admitted: statuses, context: "attempt.status"
        )

        let requiredBodies = try validateRequiredBodies(root["required_bodies"])
        let bodyStates = try validateBodyStates(
            root["body_states"],
            requiredBodies: requiredBodies
        )
        let publicFindings = try validateCertificate(
            root["certificate"],
            expectedAttemptId: attemptId,
            expectedProposalContentId: proposalContentId,
            expectedAttemptSequence: attemptSequence,
            expectedRiskTier: riskTier,
            expectedPolicyVersion: policyVersion,
            requiredBodies: requiredBodies
        )
        let certificateBodyOrder = root["certificate"] is NSNull ? [] : requiredBodies
        if !(root["superseding_head"] is NSNull) {
            try validateExpectedHead(root["superseding_head"], context: "superseding_head")
        }
        let statePayloadHex = try requireFramedHex(
            root["state_payload_hex"],
            maximumBytes: maximumAttemptStateBytes,
            field: "state_payload_hex"
        )
        return .init(
            governanceAttemptId: attemptId,
            currentHeight: currentHeight,
            policyVersion: policyVersion,
            terminalHeight: terminalHeight,
            executionFailureRoot: executionFailureRoot,
            statePayloadHex: statePayloadHex,
            requiredBodyOrder: requiredBodies,
            bodyStates: bodyStates,
            certificateBodyOrder: certificateBodyOrder,
            publicFindingBindings: publicFindings,
            rawJSON: data
        )
    }
}

private struct ToriiParliamentAttemptDraftEnvelopeV1: Encodable {
    let version: UInt16
    let proposal: ToriiParliamentProposalV1
    let attemptSequence: UInt32

    enum CodingKeys: String, CodingKey {
        case version
        case proposal
        case attemptSequence = "attempt_sequence"
    }
}

private struct ToriiParliamentTransitionDraftEnvelopeV1: Encodable {
    let version: UInt16
    let governanceAttemptId: String
    let transition: ToriiParliamentLifecycleTransitionV1

    enum CodingKeys: String, CodingKey {
        case version
        case governanceAttemptId = "governance_attempt_id"
        case transition
    }
}

fileprivate extension ToriiParliamentAPIV1 {
    static func exactRoot(
        _ data: Data,
        fields: Set<String>,
        context: String
    ) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 64 * 1024 * 1024 else {
            throw ToriiClientError.invalidPayload("\(context) exceeds its response bound.")
        }
        let decoded: Any
        do {
            decoded = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw ToriiClientError.decoding(error)
        }
        return try exactObject(decoded, fields: fields, context: context)
    }

    static func exactObject(
        _ value: Any?,
        fields: Set<String>,
        context: String
    ) throws -> [String: Any] {
        guard let object = value as? [String: Any], Set(object.keys) == fields else {
            throw ToriiClientError.invalidPayload(
                "\(context) contains unknown, aliased, or missing fields."
            )
        }
        return object
    }

    static func requireVersion(_ value: Any?) throws {
        guard try unsigned(value, field: "version") == UInt64(version) else {
            throw ToriiClientError.invalidPayload("unsupported Parliament API version.")
        }
    }

    static func requireIdentifier(_ value: Any?, field: String) throws -> String {
        guard let string = value as? String else {
            throw ToriiClientError.invalidPayload(
                "\(field) must be exactly 64 lowercase nonzero hexadecimal characters."
            )
        }
        return try requireIdentifier(string, field: field)
    }

    static func requireIdentifier(_ value: String, field: String) throws -> String {
        let bytes = Array(value.utf8)
        guard bytes.count == 64,
              bytes.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }),
              bytes.contains(where: { $0 != 0x30 }) else {
            throw ToriiClientError.invalidPayload(
                "\(field) must be exactly 64 lowercase nonzero hexadecimal characters."
            )
        }
        return value
    }

    static func requireBody(_ value: String, field: String) throws {
        guard bodies.contains(value) else {
            throw ToriiClientError.invalidPayload("\(field) is not a Parliament body.")
        }
    }

    static func requireFixedBytes(
        _ value: [UInt8],
        count: Int,
        nonzero: Bool,
        field: String
    ) throws {
        guard value.count == count,
              !nonzero || value.contains(where: { $0 != 0 }) else {
            let suffix = nonzero ? " nonzero" : ""
            throw ToriiClientError.invalidPayload(
                "\(field) must contain exactly \(count)\(suffix) bytes."
            )
        }
    }

    static func fixedBytes(
        _ value: Any?,
        count: Int,
        nonzero: Bool,
        field: String
    ) throws -> [UInt8] {
        guard let raw = value as? [Any], raw.count == count else {
            throw ToriiClientError.invalidPayload(
                "\(field) must contain exactly \(count) bytes."
            )
        }
        var result = [UInt8]()
        result.reserveCapacity(count)
        for (index, item) in raw.enumerated() {
            let byte = try unsigned(item, field: "\(field)[\(index)]")
            guard byte <= UInt64(UInt8.max) else {
                throw ToriiClientError.invalidPayload("\(field)[\(index)] is not a byte.")
            }
            result.append(UInt8(byte))
        }
        try requireFixedBytes(result, count: count, nonzero: nonzero, field: field)
        return result
    }

    static func optionalFixedBytes(
        _ value: Any?,
        count: Int,
        nonzero: Bool,
        field: String
    ) throws -> [UInt8]? {
        guard let value else {
            throw ToriiClientError.invalidPayload("\(field) is missing.")
        }
        if value is NSNull { return nil }
        return try fixedBytes(value, count: count, nonzero: nonzero, field: field)
    }

    static func unsigned(_ value: Any?, field: String) throws -> UInt64 {
        guard let value,
              let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw ToriiClientError.invalidPayload("\(field) must be an unsigned integer.")
        }
        let decimal = number.stringValue
        guard !decimal.isEmpty,
              decimal.allSatisfy(\.isNumber),
              let parsed = UInt64(decimal),
              String(parsed) == decimal else {
            throw ToriiClientError.invalidPayload("\(field) must be an unsigned integer.")
        }
        return parsed
    }

    static func unsigned32(_ value: Any?, field: String) throws -> UInt32 {
        let parsed = try unsigned(value, field: field)
        guard parsed <= UInt64(UInt32.max) else {
            throw ToriiClientError.invalidPayload("\(field) is outside u32.")
        }
        return UInt32(parsed)
    }

    static func boundedUInt32(
        _ value: Any?,
        minimum: UInt32,
        maximum: UInt32,
        field: String
    ) throws -> UInt32 {
        let parsed = try unsigned32(value, field: field)
        guard parsed >= minimum, parsed <= maximum else {
            throw ToriiClientError.invalidPayload(
                "\(field) must be in \(minimum)...\(maximum)."
            )
        }
        return parsed
    }

    static func optionalUnsigned(_ value: Any?, field: String) throws -> UInt64? {
        guard let value else {
            throw ToriiClientError.invalidPayload("\(field) is missing.")
        }
        if value is NSNull { return nil }
        return try unsigned(value, field: field)
    }

    static func taggedUnit(
        _ value: Any?,
        tag: String,
        admitted: Set<String>,
        context: String
    ) throws -> String {
        let object = try exactObject(value, fields: [tag], context: context)
        guard let result = object[tag] as? String, admitted.contains(result) else {
            throw ToriiClientError.invalidPayload("\(context).\(tag) is unknown.")
        }
        return result
    }

    static func requireStrictIdentifiers(_ values: [String], field: String) throws {
        guard !values.isEmpty, values.count <= maximumBodyTargetSeats else {
            throw ToriiClientError.invalidPayload(
                "\(field) must contain one through 1000 identifiers."
            )
        }
        var previous: String?
        for (index, value) in values.enumerated() {
            let identifier = try requireIdentifier(value, field: "\(field)[\(index)]")
            if let previous, previous >= identifier {
                throw ToriiClientError.invalidPayload(
                    "\(field) must be strictly increasing and distinct."
                )
            }
            previous = identifier
        }
    }

    static func rejectSigningMaterial(_ value: ToriiJSONValue, context: String) throws {
        switch value {
        case let .array(values):
            for (index, item) in values.enumerated() {
                try rejectSigningMaterial(item, context: "\(context)[\(index)]")
            }
        case let .object(object):
            for (key, item) in object {
                guard !privateKeyFields.contains(key) else {
                    throw ToriiClientError.invalidPayload(
                        "\(context).\(key) is forbidden; sign the draft locally."
                    )
                }
                try rejectSigningMaterial(item, context: "\(context).\(key)")
            }
        case .string, .number, .integer, .bool, .null:
            break
        }
    }

    static func instruction(
        _ value: Any?,
        expectedWireId: String
    ) throws -> ToriiParliamentInstructionDraftV1 {
        guard let instructions = value as? [Any], instructions.count == 1 else {
            throw ToriiClientError.invalidPayload(
                "Parliament draft response must contain exactly one instruction."
            )
        }
        let instruction = try exactObject(
            instructions[0],
            fields: ["wire_id", "payload_hex"],
            context: "tx_instructions[0]"
        )
        guard instruction["wire_id"] as? String == expectedWireId else {
            throw ToriiClientError.invalidPayload("instruction draft has the wrong wire_id.")
        }
        return .init(
            wireId: expectedWireId,
            payloadHex: try requireFramedHex(
                instruction["payload_hex"],
                maximumBytes: maximumAttemptStateBytes,
                field: "tx_instructions[0].payload_hex"
            )
        )
    }

    static func requireFramedHex(
        _ value: Any?,
        maximumBytes: Int,
        field: String
    ) throws -> String {
        guard let string = value as? String,
              !string.isEmpty,
              string.utf8.count <= 2 * maximumBytes,
              string.utf8.count.isMultiple(of: 2),
              string.utf8.allSatisfy({
                  (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
              }),
              let data = Data(hexString: string),
              !data.isEmpty,
              data.count <= maximumBytes,
              let frame = noritoDecodeFrame(data),
              frame.header.compression == .none,
              data.prefix(NoritoHeader.encodedLength) == frame.header.encode() else {
            throw ToriiClientError.invalidPayload(
                "\(field) must contain one bounded canonical uncompressed NRT0 frame."
            )
        }
        return string
    }

    static func validateRequiredBodies(_ value: Any?) throws -> [String] {
        guard let entries = value as? [Any], (1...10).contains(entries.count) else {
            throw ToriiClientError.invalidPayload(
                "required_bodies must contain one through ten entries."
            )
        }
        var seen = Set<String>()
        var bodiesInOrder = [String]()
        bodiesInOrder.reserveCapacity(entries.count)
        var previousBodyIndex = -1
        for (index, raw) in entries.enumerated() {
            let entry = try exactObject(
                raw,
                fields: ["body", "decision_mode"],
                context: "required_bodies[\(index)]"
            )
            guard let body = entry["body"] as? String else {
                throw ToriiClientError.invalidPayload(
                    "required_bodies[\(index)].body must be a string."
                )
            }
            try requireBody(body, field: "required_bodies[\(index)].body")
            guard let bodyIndex = canonicalBodyOrder.firstIndex(of: body),
                  bodyIndex > previousBodyIndex else {
                throw ToriiClientError.invalidPayload(
                    "required_bodies must use strict canonical body order."
                )
            }
            previousBodyIndex = bodyIndex
            guard seen.insert(body).inserted else {
                throw ToriiClientError.invalidPayload("required_bodies contains a duplicate body.")
            }
            bodiesInOrder.append(body)
            let mode = try taggedUnit(
                entry["decision_mode"],
                tag: "mode",
                admitted: ["PublicFinding", "HiddenBindingBallot"],
                context: "required_bodies[\(index)].decision_mode"
            )
            let expected = privateBodies.contains(body) ? "HiddenBindingBallot" : "PublicFinding"
            guard mode == expected else {
                throw ToriiClientError.invalidPayload(
                    "required_bodies[\(index)] uses the wrong decision mode."
                )
            }
        }
        return bodiesInOrder
    }

    static func validateBodyStates(
        _ value: Any?,
        requiredBodies: [String]
    ) throws -> [ToriiParliamentBodyStateProjectionV1] {
        guard let entries = value as? [Any],
              entries.count == requiredBodies.count,
              (1...10).contains(entries.count) else {
            throw ToriiClientError.invalidPayload(
                "body_states must exactly match the required body pipeline."
            )
        }
        let noResultTags = Set(noResultKinds.map(\.jsonTag))
        let publicNoResultTags: Set<String> = [
            "PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired",
        ]
        var result = [ToriiParliamentBodyStateProjectionV1]()
        result.reserveCapacity(entries.count)
        for (index, raw) in entries.enumerated() {
            let context = "body_states[\(index)]"
            let entry = try exactObject(
                raw,
                fields: Set(bodyStateFields),
                context: context
            )
            guard let body = entry["body"] as? String, body == requiredBodies[index] else {
                throw ToriiClientError.invalidPayload(
                    "\(context).body differs from required_bodies order."
                )
            }

            let instanceIsNull = entry["body_instance_id"] is NSNull
            let statusIsNull = entry["status"] is NSNull
            guard instanceIsNull == statusIsNull else {
                throw ToriiClientError.invalidPayload(
                    "\(context) must bind body_instance_id and status together."
                )
            }
            let bodyInstanceId = instanceIsNull
                ? nil
                : try requireIdentifier(
                    entry["body_instance_id"],
                    field: "\(context).body_instance_id"
                )

            var status: String?
            var phase: String?
            if !statusIsNull {
                guard let object = entry["status"] as? [String: Any],
                      let parsedStatus = object["status"] as? String,
                      bodyStatuses.contains(parsedStatus) else {
                    throw ToriiClientError.invalidPayload("\(context).status is unknown.")
                }
                if parsedStatus == "Deliberating" {
                    guard Set(object.keys) == ["status", "phase"] else {
                        throw ToriiClientError.invalidPayload(
                            "\(context).status contains unknown, aliased, or missing fields."
                        )
                    }
                    phase = try taggedUnit(
                        object["phase"],
                        tag: "phase",
                        admitted: deliberationPhases,
                        context: "\(context).status.phase"
                    )
                } else {
                    guard Set(object.keys) == ["status"] else {
                        throw ToriiClientError.invalidPayload(
                            "\(context).status contains unknown, aliased, or missing fields."
                        )
                    }
                }
                status = parsedStatus
            }

            let opened = try optionalUnsigned(
                entry["public_finding_opened_at_height"],
                field: "\(context).public_finding_opened_at_height"
            )
            let phaseBlocks = try optionalUnsigned(
                entry["public_finding_phase_blocks"],
                field: "\(context).public_finding_phase_blocks"
            )
            let deadline = try optionalUnsigned(
                entry["public_finding_deadline_height"],
                field: "\(context).public_finding_deadline_height"
            )
            guard (opened == nil) == (phaseBlocks == nil),
                  (opened == nil) == (deadline == nil) else {
                throw ToriiClientError.invalidPayload(
                    "\(context) must expose the complete public-finding schedule or none."
                )
            }
            if let opened, let phaseBlocks, let deadline {
                let (expectedDeadline, overflow) = opened.addingReportingOverflow(phaseBlocks)
                guard phaseBlocks > 0,
                      !privateBodies.contains(body),
                      !overflow,
                      deadline == expectedDeadline else {
                    throw ToriiClientError.invalidPayload(
                        "\(context) public-finding deadline does not match its frozen schedule."
                    )
                }
            }

            let kindIsNull = entry["no_result_kind"] is NSNull
            let heightIsNull = entry["no_result_height"] is NSNull
            guard kindIsNull == heightIsNull else {
                throw ToriiClientError.invalidPayload(
                    "\(context) must bind no-result kind and height together."
                )
            }
            let noResultKind = kindIsNull
                ? nil
                : try taggedUnit(
                    entry["no_result_kind"],
                    tag: "reason",
                    admitted: noResultTags,
                    context: "\(context).no_result_kind"
                )
            let noResultHeight = try optionalUnsigned(
                entry["no_result_height"],
                field: "\(context).no_result_height"
            )
            if let noResultKind {
                guard status == "NoResult",
                      publicNoResultTags.contains(noResultKind) != privateBodies.contains(body) else {
                    throw ToriiClientError.invalidPayload(
                        "\(context) no-result facts do not match its lifecycle and decision protocol."
                    )
                }
            }
            result.append(.init(
                body: body,
                bodyInstanceId: bodyInstanceId,
                status: status,
                deliberationPhase: phase,
                publicFindingOpenedAtHeight: opened,
                publicFindingPhaseBlocks: phaseBlocks,
                publicFindingDeadlineHeight: deadline,
                noResultKind: noResultKind,
                noResultHeight: noResultHeight
            ))
        }
        return result
    }

    static func validateCertificate(
        _ value: Any?,
        expectedAttemptId: String,
        expectedProposalContentId: String,
        expectedAttemptSequence: UInt32,
        expectedRiskTier: String,
        expectedPolicyVersion: UInt64,
        requiredBodies: [String]
    ) throws -> [ToriiParliamentPublicFindingCertificateBindingV1] {
        guard let value else {
            throw ToriiClientError.invalidPayload("certificate is missing.")
        }
        if value is NSNull { return [] }
        let certificate = try exactObject(
            value,
            fields: [
                "proposal_content_id", "governance_attempt_id", "governance_attempt_sequence",
                "risk_tier", "body_bindings", "policy_version", "effect_preimage_hash",
                "expected_head", "certified_at_height", "enact_at_height",
            ],
            context: "certificate"
        )
        guard try requireIdentifier(
            certificate["proposal_content_id"],
            field: "certificate.proposal_content_id"
        ) == expectedProposalContentId else {
            throw ToriiClientError.invalidPayload(
                "certificate.proposal_content_id differs from attempt.proposal_content_id."
            )
        }
        guard try requireIdentifier(
            certificate["governance_attempt_id"],
            field: "certificate.governance_attempt_id"
        ) == expectedAttemptId else {
            throw ToriiClientError.invalidPayload(
                "certificate.governance_attempt_id differs from attempt.id."
            )
        }
        guard try unsigned32(
            certificate["governance_attempt_sequence"],
            field: "certificate.governance_attempt_sequence"
        ) == expectedAttemptSequence else {
            throw ToriiClientError.invalidPayload(
                "certificate.governance_attempt_sequence differs from attempt.sequence."
            )
        }
        guard try taggedUnit(
            certificate["risk_tier"],
            tag: "tier",
            admitted: riskTiers,
            context: "certificate.risk_tier"
        ) == expectedRiskTier else {
            throw ToriiClientError.invalidPayload(
                "certificate.risk_tier differs from attempt.risk_tier."
            )
        }
        guard try unsigned(
            certificate["policy_version"],
            field: "certificate.policy_version"
        ) == governancePolicyVersion else {
            throw ToriiClientError.invalidPayload(
                "certificate.policy_version must equal the first-release Parliament policy version."
            )
        }
        guard governancePolicyVersion == expectedPolicyVersion else {
            throw ToriiClientError.invalidPayload(
                "certificate.policy_version differs from the attempt projection."
            )
        }
        _ = try fixedBytes(
            certificate["effect_preimage_hash"],
            count: 32,
            nonzero: true,
            field: "certificate.effect_preimage_hash"
        )
        try validateExpectedHead(certificate["expected_head"], context: "certificate.expected_head")
        let certifiedAtHeight = try unsigned(
            certificate["certified_at_height"],
            field: "certificate.certified_at_height"
        )
        let enactAtHeight = try unsigned(
            certificate["enact_at_height"],
            field: "certificate.enact_at_height"
        )
        guard certifiedAtHeight > 0, enactAtHeight > certifiedAtHeight else {
            throw ToriiClientError.invalidPayload(
                "certificate enact_at_height must follow certified_at_height."
            )
        }
        guard let bindings = certificate["body_bindings"] as? [Any],
              bindings.count == requiredBodies.count,
              (1...10).contains(bindings.count) else {
            throw ToriiClientError.invalidPayload(
                "certificate.body_bindings must exactly match required_bodies."
            )
        }
        var findings = [ToriiParliamentPublicFindingCertificateBindingV1]()
        var seenBodyInstanceIds = Set<String>()
        var seenElectionAttemptIds = Set<String>()
        var seenSortitionRequestIds = Set<String>()
        var latestBodyResultHeight: UInt64 = 0
        for (index, binding) in bindings.enumerated() {
            let facts = try validateBodyBinding(
                binding,
                index: index,
                expectedBody: requiredBodies[index],
                governanceAttemptId: expectedAttemptId,
                certifiedAtHeight: certifiedAtHeight
            )
            guard seenBodyInstanceIds.insert(facts.bodyInstanceId).inserted,
                  seenElectionAttemptIds.insert(facts.electionAttemptId).inserted,
                  seenSortitionRequestIds.insert(facts.sortitionRequestId).inserted else {
                throw ToriiClientError.invalidPayload(
                    "certificate.body_bindings reuse an attempt-local identifier."
                )
            }
            latestBodyResultHeight = max(latestBodyResultHeight, facts.resultHeight)
            findings.append(facts.publicFinding)
        }
        guard certifiedAtHeight == latestBodyResultHeight else {
            throw ToriiClientError.invalidPayload(
                "certificate.certified_at_height must equal the latest body result height."
            )
        }
        return findings
    }

    struct CertificateBodyFacts {
        let bodyInstanceId: String
        let electionAttemptId: String
        let sortitionRequestId: String
        let resultHeight: UInt64
        let publicFinding: ToriiParliamentPublicFindingCertificateBindingV1
    }

    static func validateBodyBinding(
        _ value: Any,
        index: Int,
        expectedBody: String,
        governanceAttemptId: String,
        certifiedAtHeight: UInt64
    ) throws -> CertificateBodyFacts {
        let context = "certificate.body_bindings[\(index)]"
        let binding = try exactObject(
            value,
            fields: Set(certificateBodyBindingNoritoFields),
            context: context
        )
        let bodyInstanceId = try requireIdentifier(
            binding["body_instance_id"], field: "\(context).body_instance_id"
        )
        let electionAttemptId = try requireIdentifier(
            binding["election_attempt_id"], field: "\(context).election_attempt_id"
        )
        let sortitionRequestId = try requireIdentifier(
            binding["sortition_request_id"], field: "\(context).sortition_request_id"
        )
        let beaconSessionId = try requireIdentifier(
            binding["beacon_session_id"], field: "\(context).beacon_session_id"
        )
        _ = try requireIdentifier(
            binding["beacon_pulse_id"], field: "\(context).beacon_pulse_id"
        )
        for field in ["roster_root", "assignment_root", "result_root"] {
            _ = try fixedBytes(
                binding[field],
                count: 32,
                nonzero: true,
                field: "\(context).\(field)"
            )
        }
        let electionAttemptSequence = try unsigned32(
            binding["election_attempt_sequence"],
            field: "\(context).election_attempt_sequence"
        )
        guard electionAttemptSequence <= maximumSortitionRetries else {
            throw ToriiClientError.invalidPayload(
                "\(context).election_attempt_sequence exceeds the first-release retry ceiling."
            )
        }
        let seats = try boundedUInt32(
            binding["original_seats"],
            minimum: 1,
            maximum: UInt32(maximumBodyTargetSeats),
            field: "\(context).original_seats"
        )
        let resultHeight = try unsigned(
            binding["result_height"], field: "\(context).result_height"
        )
        guard let body = binding["body"] as? String, body == expectedBody else {
            throw ToriiClientError.invalidPayload(
                "\(context).body differs from required_bodies order."
            )
        }
        try validateSortitionRequest(
            binding["sortition_request"],
            governanceAttemptId: governanceAttemptId,
            expectedBody: body,
            electionAttemptId: electionAttemptId,
            sortitionRequestId: sortitionRequestId,
            beaconSessionId: beaconSessionId,
            originalSeats: seats,
            resultHeight: resultHeight,
            certifiedAtHeight: certifiedAtHeight,
            context: "\(context).sortition_request"
        )
        let publicFinding = binding["public_finding"]
        let ballot = binding["ballot"]
        if privateBodies.contains(body) {
            // TODO(parliament anonymous ballot, P4): validate the anonymous body-result binding
            // (BallotClosureRecordV1 + result_root) for private-jury bodies here; until it lands
            // this SDK admits no certificate that contains a private-jury body.
            throw ToriiClientError.invalidPayload(
                "\(context) private-jury result binding is not admitted until the anonymous-ballot result binding is supported"
            )
        }
        guard !(publicFinding is NSNull), let publicFinding, ballot is NSNull else {
            throw ToriiClientError.invalidPayload(
                "\(context) public body must carry public_finding only."
            )
        }
        let finding = try validatePublicFinding(
            publicFinding,
            originalSeats: seats,
            context: "\(context).public_finding"
        )
        return .init(
            bodyInstanceId: bodyInstanceId,
            electionAttemptId: electionAttemptId,
            sortitionRequestId: sortitionRequestId,
            resultHeight: resultHeight,
            publicFinding: finding
        )
    }

    /// Direct bindings are checked here; Norito-derived content identifiers and roots stay opaque.
    static func validateSortitionRequest(
        _ value: Any?,
        governanceAttemptId: String,
        expectedBody: String,
        electionAttemptId: String,
        sortitionRequestId: String,
        beaconSessionId: String,
        originalSeats: UInt32,
        resultHeight: UInt64,
        certifiedAtHeight: UInt64,
        context: String
    ) throws {
        let request = try exactObject(
            value,
            fields: [
                "id", "governance_attempt_id", "body_election_attempt_id", "body",
                "candidate_root", "candidate_count", "target_seats", "request_height",
                "pulse_height", "beacon_session_id",
            ],
            context: context
        )
        guard try requireIdentifier(request["id"], field: "\(context).id")
                == sortitionRequestId,
              try requireIdentifier(
                request["governance_attempt_id"],
                field: "\(context).governance_attempt_id"
              ) == governanceAttemptId,
              try requireIdentifier(
                request["body_election_attempt_id"],
                field: "\(context).body_election_attempt_id"
              ) == electionAttemptId,
              try requireIdentifier(
                request["beacon_session_id"],
                field: "\(context).beacon_session_id"
              ) == beaconSessionId else {
            throw ToriiClientError.invalidPayload(
                "\(context) differs from its repeated certificate bindings."
            )
        }
        _ = try fixedBytes(
            request["candidate_root"],
            count: 32,
            nonzero: true,
            field: "\(context).candidate_root"
        )
        let candidateCount = try boundedUInt32(
            request["candidate_count"],
            minimum: 1,
            maximum: UInt32.max,
            field: "\(context).candidate_count"
        )
        let targetSeats = try boundedUInt32(
            request["target_seats"],
            minimum: 1,
            maximum: UInt32(maximumBodyTargetSeats),
            field: "\(context).target_seats"
        )
        guard originalSeats <= targetSeats, originalSeats <= candidateCount else {
            throw ToriiClientError.invalidPayload(
                "\(context) original_seats exceeds its sortition bounds."
            )
        }
        let requestHeight = try unsigned(
            request["request_height"], field: "\(context).request_height"
        )
        let pulseHeight = try unsigned(
            request["pulse_height"], field: "\(context).pulse_height"
        )
        guard request["body"] as? String == expectedBody else {
            throw ToriiClientError.invalidPayload("\(context).body differs from its binding.")
        }
        guard requestHeight > 0,
              pulseHeight > requestHeight,
              resultHeight > pulseHeight,
              resultHeight <= certifiedAtHeight else {
            throw ToriiClientError.invalidPayload(
                "\(context) violates the sortition/result lifecycle."
            )
        }
    }

    static func validatePublicFinding(
        _ value: Any,
        originalSeats: UInt32,
        context: String
    ) throws -> ToriiParliamentPublicFindingCertificateBindingV1 {
        let finding = try exactObject(
            value,
            fields: Set(publicFindingCertificateNoritoFields),
            context: context
        )
        let root = try fixedBytes(
            finding["endorsement_root"],
            count: 32,
            nonzero: true,
            field: "\(context).endorsement_root"
        )
        guard let assignments = finding["endorsing_assignments"] as? [String] else {
            throw ToriiClientError.invalidPayload(
                "\(context).endorsing_assignments must be an identifier array."
            )
        }
        try requireStrictIdentifiers(assignments, field: "\(context).endorsing_assignments")
        let endorsements = try boundedUInt32(
            finding["endorsements"],
            minimum: 1,
            maximum: UInt32(maximumBodyTargetSeats),
            field: "\(context).endorsements"
        )
        let quorum = try boundedUInt32(
            finding["quorum"],
            minimum: 1,
            maximum: UInt32(maximumBodyTargetSeats),
            field: "\(context).quorum"
        )
        let expectedQuorum = (2 * originalSeats + 2) / 3
        guard UInt32(assignments.count) == endorsements,
              endorsements == quorum,
              quorum == expectedQuorum else {
            throw ToriiClientError.invalidPayload(
                "\(context) must contain the exact canonical two-thirds supporter list."
            )
        }
        return .init(
            endorsementRoot: root,
            endorsingAssignments: assignments,
            endorsements: endorsements,
            quorum: quorum
        )
    }

    static func validateExpectedHead(_ value: Any?, context: String) throws {
        let root = try exactObject(value, fields: ["state", "head"], context: context)
        guard let state = root["state"] as? String else {
            throw ToriiClientError.invalidPayload("\(context).state must be a string.")
        }
        switch state {
        case "Absent":
            let head = try exactObject(
                root["head"], fields: ["subject_id"], context: "\(context).head"
            )
            _ = try fixedBytes(
                head["subject_id"],
                count: 32,
                nonzero: true,
                field: "\(context).head.subject_id"
            )
        case "Present":
            let head = try exactObject(
                root["head"],
                fields: ["subject_id", "version", "head_root"],
                context: "\(context).head"
            )
            _ = try fixedBytes(
                head["subject_id"],
                count: 32,
                nonzero: true,
                field: "\(context).head.subject_id"
            )
            guard try unsigned(head["version"], field: "\(context).head.version") > 0 else {
                throw ToriiClientError.invalidPayload(
                    "\(context).head.version must be positive."
                )
            }
            _ = try fixedBytes(
                head["head_root"],
                count: 32,
                nonzero: true,
                field: "\(context).head.head_root"
            )
        default:
            throw ToriiClientError.invalidPayload("\(context).state is unknown.")
        }
    }
}
