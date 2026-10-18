package org.hyperledger.iroha.sdk.client

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import org.hyperledger.iroha.sdk.norito.NoritoHeader

/** One canonical native instruction returned by a Parliament draft route. */
data class ParliamentInstructionDraftV1(
    val wireId: String,
    val payloadHex: String,
)

/** Strict response from `/v1/gov/parliament/attempts/draft`. */
data class ParliamentAttemptDraftResponseV1(
    val proposalContentId: String,
    val governanceAttemptId: String,
    val instruction: ParliamentInstructionDraftV1,
)

/** Strict response from `/v1/gov/parliament/transitions/draft`. */
data class ParliamentTransitionDraftResponseV1(
    val governanceAttemptId: String,
    val transitionKind: String,
    val transitionDigest: ByteArray,
    val instruction: ParliamentInstructionDraftV1,
) {
    override fun equals(other: Any?): Boolean =
        other is ParliamentTransitionDraftResponseV1 &&
            governanceAttemptId == other.governanceAttemptId &&
            transitionKind == other.transitionKind &&
            transitionDigest.contentEquals(other.transitionDigest) &&
            instruction == other.instruction

    override fun hashCode(): Int =
        31 * (31 * (31 * governanceAttemptId.hashCode() + transitionKind.hashCode()) +
            transitionDigest.contentHashCode()) + instruction.hashCode()
}

/** Bounded outer projection returned by the authenticated Parliament read route. */
data class ParliamentAttemptReadResponseV1(
    val governanceAttemptId: String,
    val currentHeight: String,
    val statePayloadHex: String,
    /** Canonical ordered body names admitted from `required_bodies`. */
    val requiredBodyOrder: List<String>,
    val bodyStates: List<ParliamentBodyStateProjectionV1>,
    /** Canonical ordered body names carried by the certificate, or empty when absent. */
    val certificateBodyOrder: List<String>,
    val publicFindingBindings: List<ParliamentPublicFindingCertificateBindingV1>,
    val raw: Map<String, Any?>,
)

/** Safe lifecycle/deadline projection for one body; private ballot material is excluded. */
data class ParliamentBodyStateProjectionV1(
    val body: String,
    val bodyInstanceId: String?,
    val status: String?,
    val deliberationPhase: String?,
    val publicFindingOpenedAtHeight: String?,
    val publicFindingPhaseBlocks: String?,
    val publicFindingDeadlineHeight: String?,
    val noResultKind: String?,
    val noResultHeight: String?,
)

/** Exact canonical public-finding supporter list carried by a certificate. */
data class ParliamentPublicFindingCertificateBindingV1(
    val endorsementRoot: ByteArray,
    val endorsingAssignments: List<String>,
    val endorsements: Int,
    val quorum: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is ParliamentPublicFindingCertificateBindingV1 &&
            endorsementRoot.contentEquals(other.endorsementRoot) &&
            endorsingAssignments == other.endorsingAssignments &&
            endorsements == other.endorsements &&
            quorum == other.quorum

    override fun hashCode(): Int =
        31 * (31 * (31 * endorsementRoot.contentHashCode() + endorsingAssignments.hashCode()) +
            endorsements) + quorum
}

/** Stable Norito/JSON/event mapping for one public lifecycle transition. */
data class ParliamentTransitionLayoutV1(
    val noritoIndex: Int,
    val jsonTag: String,
    val jsonPayloadRequired: Boolean,
    val eventKindIndex: Int,
)

/** Stable Norito/JSON/event mapping for one consensus-owned execution outcome. */
data class ParliamentAutomaticOutcomeLayoutV1(
    val noritoIndex: Int,
    val jsonTag: String,
    val jsonPayloadRequired: Boolean,
    val eventKind: String,
    val eventKindIndex: Int,
)

/** Stable Norito/JSON mapping for one closed Parliament no-result class. */
data class ParliamentNoResultKindLayoutV1(
    val noritoIndex: Int,
    val jsonTag: String,
)

/** Reflection-free builders and strict response admission for Parliament API V1. */
object ParliamentApiV1 {
    const val VERSION: Int = 1
    const val ATTEMPT_DRAFT_PATH: String = "/v1/gov/parliament/attempts/draft"
    const val ATTEMPT_READ_PATH: String = "/v1/gov/parliament/attempts/{governance_attempt_id}"
    const val TRANSITION_DRAFT_PATH: String = "/v1/gov/parliament/transitions/draft"
    const val ATTEMPT_CREATE_WIRE_ID: String =
        "iroha.governance.parliament.attempt.create.v1"
    const val TRANSITION_SUBMIT_WIRE_ID: String =
        "iroha.governance.parliament.transition.submit.v1"
    const val MAX_STATE_BYTES: Int = 16 * 1024 * 1024
    /** Largest seat count of one body; mirrors Rust `MAX_PARLIAMENT_BODY_TARGET_SEATS_V1`. */
    const val MAX_BODY_TARGET_SEATS: Int = 1_000
    /** Maximum retry sequence for a whole governance attempt; valid sequences are 0 through 16. */
    const val MAX_GOVERNANCE_ATTEMPT_RETRIES: Int = 16
    private const val GOVERNANCE_POLICY_VERSION: Int = 1
    private const val MAX_SORTITION_RETRIES: Int = 16
    const val PUBLIC_TRANSITION_DIGEST_DOMAIN: String =
        "iroha.governance.parliament.lifecycle_transition.digest.v1"
    const val AUTOMATIC_OUTCOME_DIGEST_DOMAIN: String =
        "iroha.governance.parliament.automatic_execution_outcome.digest.v1"

    /** Closed first-release proposal-kind inventory in Norito wire-index order. */
    @JvmField
    val PROPOSAL_KINDS: List<String> = listOf(
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
    )

    /** Exact first-release actions admitted by contract-lifecycle governance proposals. */
    @JvmField
    val CONTRACT_LIFECYCLE_ACTIONS: List<String> = listOf(
        "Activate",
        "Deactivate",
        "OfferOwnership",
        "CancelOwnershipOffer",
        "AcceptParliamentOwnership",
        "CompleteEmergencyHoldRetrospective",
    )

    /** One recursively validated closed first-release proposal wire value. */
    class Proposal private constructor(internal val wire: Map<String, Any?>) {
        /** Exact admitted proposal variant. */
        val kind: String = wire["kind"] as String

        companion object {
            /** Parse and recursively validate one canonical proposal JSON value. */
            @JvmStatic
            fun fromJson(bytes: ByteArray): Proposal =
                Proposal(ParliamentProposalValidatorV1.parse(bytes))
        }
    }

    @JvmField
    val PUBLIC_TRANSITIONS: List<ParliamentTransitionLayoutV1> = listOf(
        ParliamentTransitionLayoutV1(0, "EscalateRisk", true, 0),
        ParliamentTransitionLayoutV1(1, "CompleteQualification", false, 1),
        ParliamentTransitionLayoutV1(2, "RegisterSortitionRequest", true, 2),
        ParliamentTransitionLayoutV1(3, "ConsumeSortitionPulseBatch", true, 3),
        ParliamentTransitionLayoutV1(4, "BeginInvitationAcceptance", true, 4),
        ParliamentTransitionLayoutV1(5, "FailBodyElectionNoRoster", true, 5),
        ParliamentTransitionLayoutV1(6, "SealBodyRoster", true, 6),
        ParliamentTransitionLayoutV1(7, "AdvanceBodyPhase", true, 7),
        ParliamentTransitionLayoutV1(8, "RecordAttemptAbsence", true, 8),
        ParliamentTransitionLayoutV1(9, "EndorsePublicFinding", true, 9),
        ParliamentTransitionLayoutV1(10, "RecordInvitationResponse", true, 13),
        ParliamentTransitionLayoutV1(11, "FailPublicFindingNoResult", true, 14),
        ParliamentTransitionLayoutV1(12, "RegisterInitialSortition", false, 15),
    )

    @JvmField
    val AUTOMATIC_EXECUTION_OUTCOMES: List<ParliamentAutomaticOutcomeLayoutV1> = listOf(
        ParliamentAutomaticOutcomeLayoutV1(0, "Enacted", false, "MarkEnacted", 10),
        ParliamentAutomaticOutcomeLayoutV1(1, "Superseded", true, "MarkSuperseded", 11),
        ParliamentAutomaticOutcomeLayoutV1(
            2,
            "ExecutionFailed",
            true,
            "MarkExecutionFailed",
            12,
        ),
    )

    @JvmField
    val NO_RESULT_KINDS: List<ParliamentNoResultKindLayoutV1> = listOf(
        ParliamentNoResultKindLayoutV1(0, "PublicFindingQuorumUnreachable"),
        ParliamentNoResultKindLayoutV1(1, "PublicFindingDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(2, "SortitionRetriesExhausted"),
        ParliamentNoResultKindLayoutV1(3, "ConfirmationJuryCapacityUnavailable"),
        ParliamentNoResultKindLayoutV1(4, "RandomnessRedrawBudgetExhausted"),
    )

    @JvmField
    val BODY_STATE_FIELDS: List<String> = listOf(
        "body",
        "body_instance_id",
        "status",
        "public_finding_opened_at_height",
        "public_finding_phase_blocks",
        "public_finding_deadline_height",
        "no_result_kind",
        "no_result_height",
    )

    /** Canonical presentation order for first-release Parliament bodies. */
    @JvmField
    val CANONICAL_BODY_ORDER: List<String> = listOf(
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
    )

    @JvmField
    val CERTIFICATE_RESULT_ROOT_DOMAINS: Map<String, String?> = linkedMapOf(
        "public_finding_result_root" to null,
        "public_finding_endorsement_root" to
            "iroha.governance.parliament.public_finding_endorsement.root.v1",
        "execution_failure_root" to
            "iroha.governance.parliament.execution_failure.root.v1",
        "governance_certificate_id" to "iroha.governance.certificate.id.v1",
    )

    @JvmField
    val CERTIFICATE_BODY_BINDING_NORITO_FIELDS: List<String> = listOf(
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
    )

    @JvmField
    val PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS: List<String> = listOf(
        "endorsement_root",
        "endorsing_assignments",
        "endorsements",
        "quorum",
    )

    private val PUBLIC_TRANSITIONS_BY_TAG = PUBLIC_TRANSITIONS.associateBy { it.jsonTag }
    private val ATTEMPT_RESPONSE_FIELDS = setOf(
        "version", "proposal_content_id", "governance_attempt_id", "tx_instructions",
    )
    private val TRANSITION_RESPONSE_FIELDS = setOf(
        "version", "governance_attempt_id", "transition_kind", "transition_digest",
        "tx_instructions",
    )
    private val READ_RESPONSE_FIELDS = setOf(
        "version", "current_height", "attempt", "policy_version", "required_bodies",
        "body_states", "certificate", "terminal_height", "superseding_head",
        "execution_failure_root", "state_payload_hex",
    )
    private val ATTEMPT_FIELDS = setOf(
        "id", "proposal_content_id", "sequence", "risk_tier", "stage", "status",
    )
    private val BODIES = CANONICAL_BODY_ORDER.toSet()
    private val PRIVATE_BODIES = setOf("policy-jury", "confirmation-jury")
    private val BODY_STATUSES = setOf(
        "AwaitingSortition", "AcceptingInvitations", "RosterSealed", "Deliberating",
        "Balloting", "Approved", "Rejected", "NoQuorum", "NoResult", "Superseded",
    )
    private val DELIBERATION_PHASES = setOf(
        "Orientation", "Evidence", "Questions", "Responses", "Deliberation", "Reflection", "Vote",
    )
    private val PUBLIC_NO_RESULT_KINDS = setOf(
        "PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired",
    )
    private val NO_RESULT_TAGS = NO_RESULT_KINDS.mapTo(linkedSetOf()) { it.jsonTag }

    /** Replace the sole attempt-id path parameter after exact lowercase validation. */
    @JvmStatic
    fun attemptReadPath(governanceAttemptId: String): String =
        ATTEMPT_READ_PATH.replace("{governance_attempt_id}", canonicalId(governanceAttemptId))

    /** Build the exact V1 attempt-draft JSON envelope without reflection. */
    @JvmStatic
    fun attemptDraftRequestJson(proposal: Proposal, attemptSequence: Long): ByteArray {
        require(attemptSequence in 0..MAX_GOVERNANCE_ATTEMPT_RETRIES.toLong()) {
            "attempt_sequence must be between 0 and 16"
        }
        return encode(
            linkedMapOf(
                "version" to VERSION,
                "proposal" to proposal.wire,
                "attempt_sequence" to attemptSequence,
            ),
        )
    }

    /** Build the exact V1 lifecycle-transition draft JSON envelope. */
    @JvmStatic
    fun transitionDraftRequestJson(
        governanceAttemptId: String,
        transitionJson: ByteArray,
    ): ByteArray {
        val transition = taggedObject(
            transitionJson,
            "transition",
            "payload",
            "transition",
            payloadOptional = true,
        )
        val tag = transition["transition"] as String
        val layout = PUBLIC_TRANSITIONS_BY_TAG[tag]
            ?: throw IllegalArgumentException("unknown or consensus-owned Parliament transition")
        require(("payload" in transition) == layout.jsonPayloadRequired) {
            if (layout.jsonPayloadRequired) {
                "Parliament transition payload is required"
            } else {
                "unit Parliament transition must not carry a payload"
            }
        }
        return encode(
            linkedMapOf(
                "version" to VERSION,
                "governance_attempt_id" to canonicalId(governanceAttemptId),
                "transition" to transition,
            ),
        )
    }

    /** Strictly admit one attempt draft and bind it to caller-derived identifiers. */
    @JvmStatic
    fun parseAttemptDraftResponse(
        bytes: ByteArray,
        expectedProposalContentId: String,
        expectedGovernanceAttemptId: String,
    ): ParliamentAttemptDraftResponseV1 {
        val root = exactRoot(bytes, ATTEMPT_RESPONSE_FIELDS, "Parliament attempt draft")
        version(root)
        val proposalId = id(root, "proposal_content_id")
        val attemptId = id(root, "governance_attempt_id")
        require(proposalId == canonicalId(expectedProposalContentId)) {
            "proposal_content_id differs from the exact request"
        }
        require(attemptId == canonicalId(expectedGovernanceAttemptId)) {
            "governance_attempt_id differs from the exact request"
        }
        return ParliamentAttemptDraftResponseV1(
            proposalId,
            attemptId,
            instruction(root, ATTEMPT_CREATE_WIRE_ID),
        )
    }

    /** Strictly admit one transition draft and bind all public response commitments. */
    @JvmStatic
    fun parseTransitionDraftResponse(
        bytes: ByteArray,
        expectedGovernanceAttemptId: String,
        expectedTransitionKind: String,
        expectedTransitionDigest: ByteArray,
    ): ParliamentTransitionDraftResponseV1 {
        require(expectedTransitionKind in PUBLIC_TRANSITIONS_BY_TAG) {
            "expected transition kind is unknown or consensus-owned"
        }
        require(expectedTransitionDigest.size == 32 && expectedTransitionDigest.any { it.toInt() != 0 }) {
            "expected transition digest must be nonzero and 32 bytes"
        }
        val root = exactRoot(bytes, TRANSITION_RESPONSE_FIELDS, "Parliament transition draft")
        version(root)
        val attemptId = id(root, "governance_attempt_id")
        require(attemptId == canonicalId(expectedGovernanceAttemptId)) {
            "governance_attempt_id differs from the exact request"
        }
        val kind = taggedUnit(root["transition_kind"], "kind", "transition_kind")
        require(kind in PUBLIC_TRANSITIONS_BY_TAG) {
            "transition_kind is unknown or consensus-owned"
        }
        require(kind == expectedTransitionKind) { "transition_kind differs from the exact request" }
        val digest = byteArray32(root["transition_digest"], "transition_digest")
        require(digest.contentEquals(expectedTransitionDigest)) {
            "transition_digest differs from the exact request"
        }
        return ParliamentTransitionDraftResponseV1(
            attemptId,
            kind,
            digest,
            instruction(root, TRANSITION_SUBMIT_WIRE_ID),
        )
    }

    /** Strictly admit the bounded outer read envelope and exact attempt id. */
    @JvmStatic
    fun parseAttemptReadResponse(
        bytes: ByteArray,
        expectedGovernanceAttemptId: String,
    ): ParliamentAttemptReadResponseV1 {
        val root = exactRoot(bytes, READ_RESPONSE_FIELDS, "Parliament attempt read")
        version(root)
        val attempt = exactObject(root["attempt"], ATTEMPT_FIELDS, "attempt")
        val attemptId = id(attempt, "id")
        require(attemptId == canonicalId(expectedGovernanceAttemptId)) {
            "attempt.id differs from the requested canonical id"
        }
        val proposalContentId = id(attempt, "proposal_content_id")
        val attemptSequence = u32(attempt["sequence"], "attempt.sequence")
        require(BigInteger(attemptSequence) <= BigInteger.valueOf(MAX_GOVERNANCE_ATTEMPT_RETRIES.toLong())) {
            "attempt.sequence exceeds the first-release retry ceiling"
        }
        val riskTier = taggedUnitIn(
            attempt["risk_tier"],
            "tier",
            setOf("Routine", "Standard", "Constitutional", "Emergency"),
            "attempt.risk_tier",
        )
        taggedUnitIn(
            attempt["stage"],
            "stage",
            setOf(
                "Qualification", "Rules", "Agenda", "Interest", "Review", "Coordination",
                "Mpc", "Fma", "Oversight", "PolicyJury", "ConfirmationJury",
                "Certification", "Enactment",
            ),
            "attempt.stage",
        )
        taggedUnitIn(
            attempt["status"],
            "status",
            setOf("Active", "Certified", "Rejected", "Enacted", "Superseded", "ExecutionFailed"),
            "attempt.status",
        )
        val height = unsignedInteger(root["current_height"], "current_height")
        val policyVersion = unsignedInteger(root["policy_version"], "policy_version")
        require(policyVersion == GOVERNANCE_POLICY_VERSION.toString()) {
            "policy_version must equal the first-release Parliament policy version"
        }
        optionalUnsignedInteger(root["terminal_height"], "terminal_height")
        optionalByteArray32(root["execution_failure_root"], "execution_failure_root")
        val requiredBodies = validateRequiredBodies(root["required_bodies"])
        val bodyStates = validateBodyStates(root["body_states"], requiredBodies)
        val publicFindingBindings = validateCertificate(
            root["certificate"],
            attemptId,
            proposalContentId,
            attemptSequence,
            riskTier,
            policyVersion,
            requiredBodies,
            bodyStates,
        )
        val certificateBodyOrder = if (root["certificate"] == null) {
            emptyList()
        } else {
            requiredBodies.toList()
        }
        val stateHex = canonicalHex(root["state_payload_hex"], "state_payload_hex", false)
        require(stateHex.length / 2 <= MAX_STATE_BYTES) { "state_payload_hex exceeds its bound" }
        validateStateFrame(decodeHex(stateHex))
        return ParliamentAttemptReadResponseV1(
            attemptId,
            height,
            stateHex,
            requiredBodies,
            bodyStates,
            certificateBodyOrder,
            publicFindingBindings,
            root,
        )
    }

    private fun validateRequiredBodies(value: Any?): List<String> {
        val entries = value as? List<*>
            ?: throw IllegalArgumentException("required_bodies must be an array")
        require(entries.size in 1..10) { "required_bodies must contain one through ten entries" }
        val bodies = ArrayList<String>(entries.size)
        var previousBodyIndex = -1
        entries.forEachIndexed { index, raw ->
            val context = "required_bodies[$index]"
            val entry = exactObject(raw, setOf("body", "decision_mode"), context)
            val body = entry["body"] as? String
                ?: throw IllegalArgumentException("$context.body must be text")
            require(body in BODIES && body !in bodies) { "$context.body is unknown or duplicated" }
            val bodyIndex = CANONICAL_BODY_ORDER.indexOf(body)
            require(bodyIndex > previousBodyIndex) {
                "required_bodies must use strict canonical body order"
            }
            previousBodyIndex = bodyIndex
            val mode = taggedUnitIn(
                entry["decision_mode"],
                "mode",
                setOf("PublicFinding", "HiddenBindingBallot"),
                "$context.decision_mode",
            )
            val expected = if (body in PRIVATE_BODIES) "HiddenBindingBallot" else "PublicFinding"
            require(mode == expected) { "$context uses the wrong decision protocol" }
            bodies.add(body)
        }
        return bodies
    }

    private fun validateBodyStates(
        value: Any?,
        requiredBodies: List<String>,
    ): List<ParliamentBodyStateProjectionV1> {
        val entries = value as? List<*>
            ?: throw IllegalArgumentException("body_states must be an array")
        require(entries.size == requiredBodies.size && entries.size in 1..10) {
            "body_states must exactly match the required body pipeline"
        }
        return entries.mapIndexed { index, raw ->
            val context = "body_states[$index]"
            val entry = exactObject(raw, BODY_STATE_FIELDS.toSet(), context)
            val body = entry["body"] as? String
                ?: throw IllegalArgumentException("$context.body must be text")
            require(body == requiredBodies[index]) { "$context.body differs from required_bodies order" }
            val bodyInstanceId = entry["body_instance_id"]?.let {
                canonicalId(
                    it as? String
                        ?: throw IllegalArgumentException("$context.body_instance_id must be text"),
                )
            }
            val statusObject = entry["status"]?.let { objectValue(it, "$context.status") }
            require((bodyInstanceId == null) == (statusObject == null)) {
                "$context must bind body_instance_id and status together"
            }
            val status = statusObject?.get("status") as? String
            var phase: String? = null
            if (statusObject != null) {
                require(status in BODY_STATUSES) { "$context.status is unknown" }
                if (status == "Deliberating") {
                    require(statusObject.keys == setOf("status", "phase")) {
                        "$context.status contains unknown, aliased, or missing fields"
                    }
                    phase = taggedUnitIn(
                        statusObject["phase"],
                        "phase",
                        DELIBERATION_PHASES,
                        "$context.status.phase",
                    )
                } else {
                    require(statusObject.keys == setOf("status")) {
                        "$context.status contains unknown, aliased, or missing fields"
                    }
                }
            }
            val opened = optionalUnsignedInteger(
                entry["public_finding_opened_at_height"],
                "$context.public_finding_opened_at_height",
            )
            val phaseBlocks = optionalUnsignedInteger(
                entry["public_finding_phase_blocks"],
                "$context.public_finding_phase_blocks",
            )
            val deadline = optionalUnsignedInteger(
                entry["public_finding_deadline_height"],
                "$context.public_finding_deadline_height",
            )
            require((opened == null) == (phaseBlocks == null) && (opened == null) == (deadline == null)) {
                "$context must expose the complete public-finding schedule or none"
            }
            if (opened != null && phaseBlocks != null && deadline != null) {
                require(body !in PRIVATE_BODIES && BigInteger(phaseBlocks).signum() > 0 &&
                    BigInteger(opened).add(BigInteger(phaseBlocks)) == BigInteger(deadline)) {
                    "$context public-finding deadline does not match its frozen schedule"
                }
            }
            val noResultKind = entry["no_result_kind"]?.let {
                taggedUnitIn(it, "reason", NO_RESULT_TAGS, "$context.no_result_kind")
            }
            val noResultHeight = optionalUnsignedInteger(
                entry["no_result_height"],
                "$context.no_result_height",
            )
            require((noResultKind == null) == (noResultHeight == null)) {
                "$context must bind no-result kind and height together"
            }
            if (noResultKind != null) {
                require(status == "NoResult" &&
                    ((noResultKind in PUBLIC_NO_RESULT_KINDS) != (body in PRIVATE_BODIES))) {
                    "$context no-result facts do not match its lifecycle and decision protocol"
                }
            }
            ParliamentBodyStateProjectionV1(
                body,
                bodyInstanceId,
                status,
                phase,
                opened,
                phaseBlocks,
                deadline,
                noResultKind,
                noResultHeight,
            )
        }
    }

    private fun validateCertificate(
        value: Any?,
        expectedAttemptId: String,
        expectedProposalContentId: String,
        expectedAttemptSequence: String,
        expectedRiskTier: String,
        expectedPolicyVersion: String,
        requiredBodies: List<String>,
        bodyStates: List<ParliamentBodyStateProjectionV1>,
    ): List<ParliamentPublicFindingCertificateBindingV1> {
        if (value == null) return emptyList()
        val certificate = exactObject(
            value,
            setOf(
                "proposal_content_id", "governance_attempt_id", "governance_attempt_sequence",
                "risk_tier", "body_bindings", "policy_version", "effect_preimage_hash",
                "expected_head", "certified_at_height", "enact_at_height",
            ),
            "certificate",
        )
        require(id(certificate, "proposal_content_id") == expectedProposalContentId) {
            "certificate.proposal_content_id differs from attempt.proposal_content_id"
        }
        require(id(certificate, "governance_attempt_id") == expectedAttemptId) {
            "certificate.governance_attempt_id differs from attempt.id"
        }
        require(
            u32(
                certificate["governance_attempt_sequence"],
                "certificate.governance_attempt_sequence",
            ) == expectedAttemptSequence,
        ) { "certificate.governance_attempt_sequence differs from attempt.sequence" }
        require(
            taggedUnitIn(
                certificate["risk_tier"],
                "tier",
                setOf("Routine", "Standard", "Constitutional", "Emergency"),
                "certificate.risk_tier",
            ) == expectedRiskTier,
        ) { "certificate.risk_tier differs from attempt.risk_tier" }
        byteArray32(certificate["effect_preimage_hash"], "certificate.effect_preimage_hash")
        val policyVersion = unsignedInteger(
            certificate["policy_version"],
            "certificate.policy_version",
        )
        require(policyVersion == GOVERNANCE_POLICY_VERSION.toString()) {
            "certificate.policy_version must equal the first-release Parliament policy version"
        }
        require(policyVersion == expectedPolicyVersion) {
            "certificate.policy_version differs from the attempt projection"
        }
        validateExpectedHead(certificate["expected_head"], "certificate.expected_head")
        val certifiedAtHeight = BigInteger(
            unsignedInteger(certificate["certified_at_height"], "certificate.certified_at_height"),
        )
        val enactAtHeight = BigInteger(
            unsignedInteger(certificate["enact_at_height"], "certificate.enact_at_height"),
        )
        require(certifiedAtHeight.signum() > 0 && enactAtHeight > certifiedAtHeight) {
            "certificate enact_at_height must follow certified_at_height"
        }
        val bindings = certificate["body_bindings"] as? List<*>
            ?: throw IllegalArgumentException("certificate.body_bindings must be an array")
        require(bindings.size == requiredBodies.size && bindings.size in 1..10) {
            "certificate.body_bindings must exactly match required_bodies"
        }
        val seenBodyInstanceIds = HashSet<String>()
        val seenElectionAttemptIds = HashSet<String>()
        val seenSortitionRequestIds = HashSet<String>()
        val findings = ArrayList<ParliamentPublicFindingCertificateBindingV1>()
        var latestBodyResultHeight = BigInteger.ZERO
        bindings.forEachIndexed { index, raw ->
            val context = "certificate.body_bindings[$index]"
            val binding = exactObject(raw, CERTIFICATE_BODY_BINDING_NORITO_FIELDS.toSet(), context)
            val body = binding["body"] as? String
                ?: throw IllegalArgumentException("$context.body must be text")
            require(body == requiredBodies[index]) {
                "$context.body differs from required_bodies order"
            }
            val seats = u32Int(
                binding["original_seats"],
                "$context.original_seats",
                1,
                MAX_BODY_TARGET_SEATS,
            )
            val bodyInstanceId = id(binding, "body_instance_id")
            require(bodyInstanceId == bodyStates[index].bodyInstanceId) {
                "$context.body_instance_id differs from body_states"
            }
            val electionAttemptId = id(binding, "election_attempt_id")
            val sortitionRequestId = id(binding, "sortition_request_id")
            val beaconSessionId = id(binding, "beacon_session_id")
            id(binding, "beacon_pulse_id")
            require(seenBodyInstanceIds.add(bodyInstanceId)) {
                "certificate.body_bindings reuses body_instance_id"
            }
            require(seenElectionAttemptIds.add(electionAttemptId)) {
                "certificate.body_bindings reuses election_attempt_id"
            }
            require(seenSortitionRequestIds.add(sortitionRequestId)) {
                "certificate.body_bindings reuses sortition_request_id"
            }
            for (field in listOf("roster_root", "assignment_root", "result_root")) {
                byteArray32(binding[field], "$context.$field")
            }
            u32Int(
                binding["election_attempt_sequence"],
                "$context.election_attempt_sequence",
                0,
                MAX_SORTITION_RETRIES,
            )
            val resultHeight = BigInteger(
                unsignedInteger(binding["result_height"], "$context.result_height"),
            )
            latestBodyResultHeight = latestBodyResultHeight.max(resultHeight)
            validateCertificateSortitionRequest(
                binding["sortition_request"],
                expectedAttemptId,
                body,
                electionAttemptId,
                sortitionRequestId,
                beaconSessionId,
                seats,
                resultHeight,
                certifiedAtHeight,
                "$context.sortition_request",
            )
            if (body in PRIVATE_BODIES) {
                // TODO(parliament anonymous ballot, P4): validate the anonymous body-result binding (BallotClosureRecordV1 + result_root) for private-jury bodies here; until it lands this SDK admits no certificate that contains a private-jury body.
                throw IllegalArgumentException(
                    "$context private-jury result binding is not admitted until the " +
                        "anonymous-ballot result binding is supported",
                )
            }
            require(binding["public_finding"] != null && binding["ballot"] == null) {
                "$context public body must carry public_finding only"
            }
            findings.add(validatePublicFinding(binding["public_finding"], seats, "$context.public_finding"))
        }
        require(certifiedAtHeight == latestBodyResultHeight) {
            "certificate.certified_at_height must equal the latest body result height"
        }
        return findings
    }

    /** Direct bindings are checked here; Norito-derived content identifiers and roots stay opaque. */
    private fun validateCertificateSortitionRequest(
        value: Any?,
        governanceAttemptId: String,
        body: String,
        electionAttemptId: String,
        sortitionRequestId: String,
        beaconSessionId: String,
        originalSeats: Int,
        resultHeight: BigInteger,
        certifiedAtHeight: BigInteger,
        context: String,
    ) {
        val request = exactObject(
            value,
            setOf(
                "id", "governance_attempt_id", "body_election_attempt_id", "body",
                "candidate_root", "candidate_count", "target_seats", "request_height",
                "pulse_height", "beacon_session_id",
            ),
            context,
        )
        require(id(request, "id") == sortitionRequestId &&
            id(request, "governance_attempt_id") == governanceAttemptId &&
            id(request, "body_election_attempt_id") == electionAttemptId &&
            request["body"] == body &&
            id(request, "beacon_session_id") == beaconSessionId) {
            "$context differs from its repeated certificate bindings"
        }
        byteArray32(request["candidate_root"], "$context.candidate_root")
        val candidateCount = BigInteger(u32(request["candidate_count"], "$context.candidate_count"))
        require(candidateCount.signum() > 0) { "$context.candidate_count must be positive" }
        val targetSeats = u32Int(
            request["target_seats"],
            "$context.target_seats",
            1,
            MAX_BODY_TARGET_SEATS,
        )
        require(
            originalSeats <= targetSeats &&
                BigInteger.valueOf(originalSeats.toLong()) <= candidateCount,
        ) { "$context original_seats exceeds its sortition bounds" }
        val requestHeight = BigInteger(unsignedInteger(request["request_height"], "$context.request_height"))
        val pulseHeight = BigInteger(unsignedInteger(request["pulse_height"], "$context.pulse_height"))
        require(requestHeight.signum() > 0 && pulseHeight > requestHeight &&
            resultHeight > pulseHeight && resultHeight <= certifiedAtHeight) {
            "$context violates the sortition/result lifecycle"
        }
    }

    private fun validateExpectedHead(value: Any?, context: String) {
        val root = exactObject(value, setOf("state", "head"), context)
        when (root["state"]) {
            "Absent" -> {
                val head = exactObject(root["head"], setOf("subject_id"), "$context.head")
                byteArray32(head["subject_id"], "$context.head.subject_id")
            }
            "Present" -> {
                val head = exactObject(
                    root["head"],
                    setOf("subject_id", "version", "head_root"),
                    "$context.head",
                )
                byteArray32(head["subject_id"], "$context.head.subject_id")
                require(BigInteger(unsignedInteger(head["version"], "$context.head.version")).signum() > 0) {
                    "$context.head.version must be positive"
                }
                byteArray32(head["head_root"], "$context.head.head_root")
            }
            else -> throw IllegalArgumentException("$context.state is unknown")
        }
    }

    private fun validatePublicFinding(
        value: Any?,
        originalSeats: Int,
        context: String,
    ): ParliamentPublicFindingCertificateBindingV1 {
        val finding = exactObject(value, PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS.toSet(), context)
        val root = byteArray32(finding["endorsement_root"], "$context.endorsement_root")
        val assignments = (finding["endorsing_assignments"] as? List<*>)?.map {
            canonicalId(it as? String ?: throw IllegalArgumentException("$context.endorsing_assignments must be text"))
        } ?: throw IllegalArgumentException("$context.endorsing_assignments must be an array")
        require(assignments.size in 1..MAX_BODY_TARGET_SEATS &&
            assignments.zipWithNext().all { (left, right) -> left < right }) {
            "$context.endorsing_assignments must be strictly increasing and distinct"
        }
        val endorsements = u32Int(
            finding["endorsements"],
            "$context.endorsements",
            1,
            MAX_BODY_TARGET_SEATS,
        )
        val quorum = u32Int(
            finding["quorum"],
            "$context.quorum",
            1,
            MAX_BODY_TARGET_SEATS,
        )
        val expectedQuorum = (2 * originalSeats + 2) / 3
        require(assignments.size == endorsements && endorsements == quorum && quorum == expectedQuorum) {
            "$context must contain the exact canonical two-thirds supporter list"
        }
        return ParliamentPublicFindingCertificateBindingV1(root, assignments, endorsements, quorum)
    }

    private fun validateStateFrame(bytes: ByteArray) {
        val decoded = try {
            NoritoHeader.decode(bytes, null)
        } catch (ex: IllegalArgumentException) {
            throw IllegalArgumentException("state_payload_hex must contain one valid Norito frame", ex)
        }
        require(decoded.header.compression == NoritoHeader.COMPRESSION_NONE) {
            "state_payload_hex must use uncompressed canonical Norito"
        }
        require(decoded.header.schemaHash.any { it.toInt() != 0 } && decoded.payload.isNotEmpty()) {
            "state_payload_hex must declare a nonzero schema and nonempty payload"
        }
        decoded.header.validateChecksum(decoded.payload)
    }

    @Suppress("UNCHECKED_CAST")
    private fun exactRoot(bytes: ByteArray, fields: Set<String>, label: String): Map<String, Any?> {
        val text = String(bytes, StandardCharsets.UTF_8)
        require(text.toByteArray(StandardCharsets.UTF_8).contentEquals(bytes)) {
            "$label must be UTF-8 JSON"
        }
        val root = objectValue(JsonParser.parse(text), label)
        val unknown = root.keys.firstOrNull { it !in fields }
        require(unknown == null) { "$label contains unknown or aliased field `$unknown`" }
        val missing = fields.firstOrNull { it !in root }
        require(missing == null) { "$label is missing field `$missing`" }
        return root
    }

    private fun version(root: Map<String, Any?>) {
        require(unsignedInteger(root["version"], "version") == VERSION.toString()) {
            "unsupported Parliament API version"
        }
    }

    private fun instruction(
        root: Map<String, Any?>,
        expectedWireId: String,
    ): ParliamentInstructionDraftV1 {
        val values = root["tx_instructions"] as? List<*>
            ?: throw IllegalArgumentException("tx_instructions must be an array")
        require(values.size == 1) { "Parliament draft must contain exactly one instruction" }
        val draft = objectValue(values[0], "tx_instructions[0]")
        require(draft.keys == setOf("wire_id", "payload_hex")) {
            "instruction draft contains unknown, aliased, or missing fields"
        }
        val wireId = draft["wire_id"] as? String
            ?: throw IllegalArgumentException("wire_id must be text")
        require(wireId == expectedWireId) { "instruction draft has the wrong wire_id" }
        return ParliamentInstructionDraftV1(
            wireId,
            canonicalHex(draft["payload_hex"], "payload_hex", false),
        )
    }

    private fun taggedObject(
        bytes: ByteArray,
        tagField: String,
        payloadField: String,
        label: String,
        payloadOptional: Boolean = false,
    ): Map<String, Any?> {
        val root = objectValue(
            JsonParser.parse(String(bytes, StandardCharsets.UTF_8)),
            label,
        )
        val allowed = setOf(tagField, payloadField)
        require(root.keys.all { it in allowed } && tagField in root) {
            "$label contains unknown, aliased, or missing tagged fields"
        }
        val tag = root[tagField] as? String
            ?: throw IllegalArgumentException("$label tag must be text")
        require(tag.isNotBlank() && tag == tag.trim()) { "$label tag must be canonical text" }
        require(payloadOptional || payloadField in root) { "$label payload is missing" }
        if (payloadField in root) objectValue(root[payloadField], "$label payload")
        return root
    }

    private fun taggedUnit(value: Any?, tagField: String, label: String): String {
        val root = objectValue(value, label)
        require(root.keys == setOf(tagField)) { "$label must be one exact unit tag" }
        return root[tagField] as? String
            ?: throw IllegalArgumentException("$label tag must be text")
    }

    private fun taggedUnitIn(
        value: Any?,
        tagField: String,
        admitted: Set<String>,
        label: String,
    ): String {
        val tag = taggedUnit(value, tagField, label)
        require(tag in admitted) { "$label.$tagField is unknown" }
        return tag
    }

    private fun exactObject(
        value: Any?,
        fields: Set<String>,
        label: String,
    ): Map<String, Any?> {
        val root = objectValue(value, label)
        require(root.keys == fields) { "$label contains unknown, aliased, or missing fields" }
        return root
    }

    @Suppress("UNCHECKED_CAST")
    private fun objectValue(value: Any?, label: String): Map<String, Any?> {
        require(value is Map<*, *> && value.keys.all { it is String }) { "$label must be an object" }
        return value as Map<String, Any?>
    }

    private fun id(root: Map<String, Any?>, field: String): String =
        canonicalId(root[field] as? String ?: throw IllegalArgumentException("$field must be text"))

    private fun canonicalId(value: String): String {
        require(Regex("[0-9a-f]{64}").matches(value) && value.any { it != '0' }) {
            "identifier must be exactly 64 lowercase nonzero hexadecimal characters"
        }
        return value
    }

    private fun canonicalHex(value: Any?, field: String, allowEmpty: Boolean): String {
        val text = value as? String ?: throw IllegalArgumentException("$field must be text")
        require(text.length % 2 == 0 && (allowEmpty || text.isNotEmpty())) {
            "$field must contain complete bytes"
        }
        require(text.all { it in '0'..'9' || it in 'a'..'f' }) {
            "$field must be lowercase hexadecimal"
        }
        return text
    }

    private fun decodeHex(text: String): ByteArray = ByteArray(text.length / 2) { index ->
        val offset = index * 2
        text.substring(offset, offset + 2).toInt(16).toByte()
    }

    private fun byteArray32(value: Any?, field: String): ByteArray {
        return fixedBytes(value, 32, field, true)
    }

    private fun fixedBytes(
        value: Any?,
        size: Int,
        field: String,
        nonzero: Boolean,
    ): ByteArray {
        val values = value as? List<*> ?: throw IllegalArgumentException("$field must be an array")
        require(values.size == size) { "$field must contain exactly $size bytes" }
        val bytes = ByteArray(size)
        values.forEachIndexed { index, item ->
            val canonical = unsignedInteger(item, "$field[$index]")
            val byte = canonical.toIntOrNull()
            require(byte != null && byte in 0..255) { "$field[$index] must be a byte" }
            bytes[index] = byte.toByte()
        }
        require(!nonzero || bytes.any { it.toInt() != 0 }) { "$field must be nonzero" }
        return bytes
    }

    private fun optionalByteArray32(value: Any?, field: String): ByteArray? =
        value?.let { byteArray32(it, field) }

    private fun optionalUnsignedInteger(value: Any?, field: String): String? =
        value?.let { unsignedInteger(it, field) }

    private fun u32(value: Any?, field: String): String {
        val text = unsignedInteger(value, field)
        require(BigInteger(text) <= BigInteger("4294967295")) { "$field is outside u32" }
        return text
    }

    private fun u32Int(
        value: Any?,
        field: String,
        minimum: Int,
        maximum: Int,
    ): Int {
        val parsed = u32(value, field).toIntOrNull()
            ?: throw IllegalArgumentException("$field is outside the supported bound")
        require(parsed in minimum..maximum) { "$field is outside $minimum..$maximum" }
        return parsed
    }

    private fun unsignedInteger(value: Any?, field: String): String {
        require(value is Number) { "$field must be an unsigned integer" }
        val text = value.toString()
        val number = try {
            BigInteger(text)
        } catch (ex: NumberFormatException) {
            throw IllegalArgumentException("$field must be an unsigned integer", ex)
        }
        require(number.signum() >= 0 && number.toString() == text) {
            "$field must be a canonical unsigned integer"
        }
        return text
    }

    private fun encode(value: Map<String, Any?>): ByteArray =
        JsonEncoder.encode(value).toByteArray(StandardCharsets.UTF_8)
}
