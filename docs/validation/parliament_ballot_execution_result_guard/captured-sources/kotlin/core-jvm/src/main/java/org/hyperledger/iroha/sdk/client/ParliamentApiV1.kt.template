package org.hyperledger.iroha.sdk.client

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import org.hyperledger.iroha.sdk.norito.CRC64
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
    val timedOvnProgress: ParliamentTimedOvnProgressProjectionV1?,
)

/** Aggregate-only active-ballot state and next contiguous corpus offset. */
data class ParliamentTimedOvnProgressProjectionV1(
    val ballotAttemptId: String,
    val status: String,
    val frozenSurvivorCount: Int?,
    val acceptedBallotPrefixCount: Int?,
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

/** Proof-carrying public broadcast for one qualified adaptive TLE dealer. */
data class ParliamentTleAdaptiveDealerCommitmentV1(
    val dealerIndex: Int,
    val coefficientCommitments: List<ByteArray>,
    val constantPokCommitment: ByteArray,
    val constantPokResponse: ByteArray,
)

/** Public composite verification share for one threshold participant. */
data class ParliamentTleAdaptivePublicShareV1(
    val index: Int,
    val participantHash: ByteArray,
    val publicKeyShare: ByteArray,
)

/** Complete bounded public transcript required to verify adaptive partial releases. */
data class ParliamentTleKeySessionPublicStateV1(
    val keySessionId: String,
    val networkId: ByteArray,
    val rosterHash: ByteArray,
    val committeeSize: Int,
    val threshold: Int,
    val generatorH: ByteArray,
    val generatorV: ByteArray,
    val qualifiedDealers: List<Int>,
    val qualifiedDealerCommitments: List<ParliamentTleAdaptiveDealerCommitmentV1>,
    val dkgEventHash: ByteArray,
    val groupPublicKey: ByteArray,
    val publicShares: List<ParliamentTleAdaptivePublicShareV1>,
    val transcriptHash: ByteArray,
)

/** Exact frozen public timed-OVN future release identity. */
data class ParliamentTimedOvnReleaseIdentityProjectionV1(
    val tleKeySessionId: String,
    val governanceAttemptId: String,
    val bodyInstanceId: String,
    val ballotAttemptId: String,
    val survivorCorpusRoot: ByteArray,
    val noRecoveryRoot: ByteArray,
    val targetFinalizedHeight: String,
    val parameterHash: ByteArray,
)

/** Exact cast-capable public timed-OVN phase. */
enum class ParliamentTimedOvnCastingPhaseV1 {
    Registered,
    RegistrationClosed,
    SurvivorsFrozen,
}

/** Immutable public timed-OVN wallet-session bindings. */
data class ParliamentTimedOvnSessionProjectionV1(
    val networkId: ByteArray,
    val proposalContentId: String,
    val governanceAttemptId: String,
    val bodyInstanceId: String,
    val ballotAttemptId: String,
    val parameterHash: ByteArray,
    val tleKeySessionId: String,
    val tleKeyTranscriptHash: ByteArray,
    val tleMasterPublicKey: ByteArray,
)

/** Replay-validated public context consumed by a secret-local native wallet bridge. */
data class ParliamentTimedOvnCastingContextResponseV1(
    val currentHeight: String,
    val phase: ParliamentTimedOvnCastingPhaseV1,
    val session: ParliamentTimedOvnSessionProjectionV1,
    val registrationOpenedAtFinalizedHeight: String,
    val targetFinalizedHeight: String,
    val keySession: ParliamentTleKeySessionPublicStateV1,
    val registrationRecordsHex: List<String>,
    val survivorParticipantHashes: List<ByteArray>?,
    val releaseIdentity: ParliamentTimedOvnReleaseIdentityProjectionV1?,
    val archiveNorito: ByteArray,
)

/** Canonical bounded checkpoint request for the Parliament timed-OVN casting proof route. */
class ParliamentTimedOvnCastingProofRequestV1(
    trustedCheckpointHeight: BigInteger,
) {
    @JvmField
    val trustedCheckpointHeight: BigInteger =
        ParliamentApiV1.requireTimedOvnCastingCheckpointHeight(trustedCheckpointHeight)

    /** Convenience constructor for positive signed heights. */
    constructor(trustedCheckpointHeight: Long) : this(BigInteger.valueOf(trustedCheckpointHeight))

    /** Encode the exact uncompressed, zero-padding Norito request frame. */
    fun toNoritoBytes(): ByteArray =
        ParliamentApiV1.timedOvnCastingProofRequestNorito(trustedCheckpointHeight)
}

/**
 * Schema- and checksum-admitted response frame passed unchanged to the native wallet bridge.
 *
 * Framing admission does not establish consensus validity. Wallets must verify the page with the
 * external network, complete canonical checkpoint, and expected ballot before accessing seed material.
 */
class ParliamentTimedOvnCastingProofResponseV1 internal constructor(
    canonicalNorito: ByteArray,
    payload: ByteArray,
) {
    private val canonicalNoritoBytes = canonicalNorito.copyOf()
    private val payloadBytes = payload.copyOf()

    /** Exact canonical response frame, including its Norito header. */
    fun canonicalNorito(): ByteArray = canonicalNoritoBytes.copyOf()

    /** Exact payload bytes covered by the frame CRC64-XZ checksum. */
    fun payload(): ByteArray = payloadBytes.copyOf()
}

/** Native-authenticated promotion carried by one bounded casting-proof page. */
class ParliamentTimedOvnCastingProofPageVerificationV1(
    evaluatedBlockHeight: BigInteger,
    evaluatedContextId: ByteArray,
    /** Whether another independently fetched and verified page is required. */
    val moreAvailable: Boolean,
    promotedCheckpointNorito: ByteArray,
) {
    /** Exact positive u64 height authenticated by the native finality verifier. */
    val evaluatedBlockHeight: BigInteger =
        ParliamentApiV1.requireTimedOvnCastingCheckpointHeight(evaluatedBlockHeight)
    private val evaluatedContextIdBytes = evaluatedContextId.copyOf()
    private val checkpointBytes = promotedCheckpointNorito.copyOf()

    init {
        require(checkpointBytes.size in 1..(68 * 1024 * 1024)) {
            "promotedCheckpointNorito must contain a bounded complete canonical checkpoint"
        }
        require(evaluatedContextIdBytes.size == 32) {
            "evaluatedContextId must contain exactly 32 bytes"
        }
        require(evaluatedContextIdBytes.any { it != 0.toByte() }) {
            "evaluatedContextId must be nonzero"
        }
    }

    /** Defensive copy of the authenticated `HeightContextId`. */
    fun evaluatedContextId(): ByteArray = evaluatedContextIdBytes.copyOf()

    /** Defensive copy of the complete native-authenticated checkpoint. */
    fun promotedCheckpointNorito(): ByteArray = checkpointBytes.copyOf()

    override fun equals(other: Any?): Boolean =
        other is ParliamentTimedOvnCastingProofPageVerificationV1 &&
            evaluatedBlockHeight == other.evaluatedBlockHeight &&
            evaluatedContextIdBytes.contentEquals(other.evaluatedContextIdBytes) &&
            moreAvailable == other.moreAvailable && checkpointBytes.contentEquals(other.checkpointBytes)

    override fun hashCode(): Int =
        31 * (31 * evaluatedBlockHeight.hashCode() + evaluatedContextIdBytes.contentHashCode()) +
            31 * moreAvailable.hashCode() + checkpointBytes.contentHashCode()
}

/** Native page verifier used by the bounded transport loop. */
fun interface ParliamentTimedOvnCastingProofPageVerifierV1 {
    /** Authenticate [response] against the supplied durable checkpoint. */
    fun verify(
        response: ParliamentTimedOvnCastingProofResponseV1,
        trustedCheckpointHeight: BigInteger,
        trustedCheckpointNorito: ByteArray,
    ): ParliamentTimedOvnCastingProofPageVerificationV1
}

/** Durable checkpoint sink; completion must mean the promoted anchor is committed. */
fun interface ParliamentTimedOvnCastingCheckpointPersisterV1 {
    /** Persist one native-authenticated promotion before any subsequent page is requested. */
    fun persist(
        verification: ParliamentTimedOvnCastingProofPageVerificationV1,
    ): java.util.concurrent.CompletableFuture<Void>
}

/** Terminal proof page plus the exact checkpoint against which native code authenticated it. */
class ParliamentTimedOvnCastingProofTerminalV1 internal constructor(
    /** Canonical terminal response suitable for a proof-gated native wallet operation. */
    val response: ParliamentTimedOvnCastingProofResponseV1,
    /** Checkpoint height supplied while authenticating [response]. */
    val verificationAnchorHeight: BigInteger,
    verificationAnchorCheckpointNorito: ByteArray,
    /** Native-authenticated terminal promotion. */
    val verification: ParliamentTimedOvnCastingProofPageVerificationV1,
    /** Total number of independently fetched and verified pages. */
    val verifiedPageCount: Int,
) {
    private val verificationAnchorCheckpointNoritoBytes = verificationAnchorCheckpointNorito.copyOf()

    /** Defensive copy of the complete checkpoint supplied while authenticating [response]. */
    fun verificationAnchorCheckpointNorito(): ByteArray = verificationAnchorCheckpointNoritoBytes.copyOf()
}

/** Core-authorized release context available only during the inclusive Opening window. */
data class ParliamentTleReleaseContextResponseV1(
    val currentHeight: String,
    val ballotAttemptId: String,
    val governanceAttemptId: String,
    val bodyInstanceId: String,
    val releaseHeight: String,
    val openingDeadlineHeight: String,
    val keySession: ParliamentTleKeySessionPublicStateV1,
    val releaseIdentity: ParliamentTimedOvnReleaseIdentityProjectionV1,
    val identityDigest: ByteArray,
    val identityPayloadHex: String,
)

/** One independently verifiable public adaptive partial release. */
data class ParliamentTlePartialReleaseShareV1(
    val keySessionId: String,
    val identityDigest: ByteArray,
    val participantIndex: Int,
    val sigma: ByteArray,
    val proofX: ByteArray,
    val proofY: ByteArray,
    val zS: ByteArray,
    val zR: ByteArray,
    val zU: ByteArray,
)

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
    const val TIMED_OVN_CASTING_CONTEXT_READ_PATH: String =
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context"
    const val TIMED_OVN_CASTING_PROOF_PATH: String =
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof"
    const val TLE_RELEASE_CONTEXT_READ_PATH: String =
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context"
    const val TLE_PARTIAL_RELEASE_PATH: String =
        "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release"
    const val TRANSITION_DRAFT_PATH: String = "/v1/gov/parliament/transitions/draft"
    const val ATTEMPT_CREATE_WIRE_ID: String =
        "iroha.governance.parliament.attempt.create.v1"
    const val TRANSITION_SUBMIT_WIRE_ID: String =
        "iroha.governance.parliament.transition.submit.v1"
    const val MAX_STATE_BYTES: Int = 16 * 1024 * 1024
    const val MAX_TLE_COMMITTEE_SIZE: Int = 31
    const val MAX_TIMED_OVN_CASTING_ARCHIVE_BYTES: Int = 4 * 1024 * 1024
    const val MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES: Int = 8 * 1024 * 1024
    const val MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS: Int = 64
    /** Maximum checkpoint advance authenticated by one checkpoint-inclusive finality page. */
    const val MAX_TIMED_OVN_CASTING_PROOF_PAGE_HEIGHT_ADVANCE: Int =
        MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS - 1
    /** Deterministic maximum number of pages admitted by one client catch-up operation. */
    const val MAX_TIMED_OVN_CASTING_PROOF_PAGES: Int = 64
    /** Deterministic aggregate height advance admitted by one client catch-up operation. */
    const val MAX_TIMED_OVN_CASTING_PROOF_HEIGHT_ADVANCE: Int =
        MAX_TIMED_OVN_CASTING_PROOF_PAGE_HEIGHT_ADVANCE * MAX_TIMED_OVN_CASTING_PROOF_PAGES
    const val TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA: String =
        "iroha.torii.v1.parliament.timed_ovn_casting_proof.request"
    const val TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA: String =
        "iroha.torii.v1.parliament.timed_ovn_casting_proof.response"
    const val TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX: String =
        "adccf322a5fcf43040e20bea238f55f3"
    const val TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX: String =
        "46d29299272433b1299646bee722bd11"
    const val TIMED_OVN_CASTING_PROOF_REQUEST_VERSION: Int = 1
    const val TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS: Int = NoritoHeader.COMPACT_LEN
    const val TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT: Int = 8
    const val TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES: Int = 0
    const val TIMED_OVN_CASTING_PROOF_REQUEST_BYTES: Int = 52
    const val TIMED_OVN_REGISTRATION_RECORD_BYTES: Int = 3_624
    const val TIMED_OVN_BALLOT_RECORD_BYTES: Int = 2_858
    /** Maximum records appended by one transition; the complete corpus may contain 1,000. */
    const val TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS: Int = 32
    const val MAX_TIMED_OVN_CORPUS_ENTRIES: Int = 1_000
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
        ParliamentTransitionLayoutV1(10, "RegisterBallotAttempt", true, 10),
        ParliamentTransitionLayoutV1(11, "CloseBallotRegistration", true, 11),
        ParliamentTransitionLayoutV1(12, "FreezeBallotSurvivors", true, 12),
        ParliamentTransitionLayoutV1(13, "FreezeTimedOvnCorpus", true, 13),
        ParliamentTransitionLayoutV1(14, "BeginBallotOpeningBatch", true, 14),
        ParliamentTransitionLayoutV1(15, "FailBallotNoResult", true, 15),
        ParliamentTransitionLayoutV1(16, "FinalizeOpenedBallot", true, 16),
        ParliamentTransitionLayoutV1(17, "RecordInvitationResponse", true, 20),
        ParliamentTransitionLayoutV1(18, "RegisterBallotParticipant", true, 21),
        ParliamentTransitionLayoutV1(19, "RecordBallotDropout", true, 22),
        ParliamentTransitionLayoutV1(20, "FailPublicFindingNoResult", true, 23),
        ParliamentTransitionLayoutV1(21, "RegisterInitialSortition", false, 24),
    )

    @JvmField
    val AUTOMATIC_EXECUTION_OUTCOMES: List<ParliamentAutomaticOutcomeLayoutV1> = listOf(
        ParliamentAutomaticOutcomeLayoutV1(0, "Enacted", false, "MarkEnacted", 17),
        ParliamentAutomaticOutcomeLayoutV1(1, "Superseded", true, "MarkSuperseded", 18),
        ParliamentAutomaticOutcomeLayoutV1(
            2,
            "ExecutionFailed",
            true,
            "MarkExecutionFailed",
            19,
        ),
    )

    @JvmField
    val NO_RESULT_KINDS: List<ParliamentNoResultKindLayoutV1> = listOf(
        ParliamentNoResultKindLayoutV1(0, "PublicFindingQuorumUnreachable"),
        ParliamentNoResultKindLayoutV1(1, "PublicFindingDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(2, "BallotRegistrationDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(3, "BallotSurvivorDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(4, "BallotCommitmentDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(5, "BallotReleasePulseUnavailable"),
        ParliamentNoResultKindLayoutV1(6, "BallotOpeningDeadlineExpired"),
        ParliamentNoResultKindLayoutV1(7, "SortitionRetriesExhausted"),
        ParliamentNoResultKindLayoutV1(8, "ConfirmationJuryCapacityUnavailable"),
        ParliamentNoResultKindLayoutV1(9, "RandomnessRedrawBudgetExhausted"),
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
        "timed_ovn_progress",
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
        "private_ballot_result_root" to
            "iroha.governance.parliament.ballot_result.root.v1",
        "private_ballot_failure_root" to
            "iroha.governance.parliament.ballot_failure.root.v1",
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
    private val TLE_RELEASE_CONTEXT_FIELDS = setOf(
        "version", "current_height", "ballot_attempt_id", "governance_attempt_id",
        "body_instance_id", "status", "release_height", "opening_deadline_height",
        "tle_key_session", "release_identity", "identity_digest", "identity_payload_hex",
    )
    private val TIMED_OVN_CASTING_CONTEXT_FIELDS = setOf(
        "version", "current_height", "phase", "session",
        "registration_opened_at_finalized_height", "target_finalized_height",
        "tle_key_session", "registration_records_hex", "survivor_participant_hashes",
        "release_identity", "archive_norito_base64",
    )
    private val TIMED_OVN_SESSION_FIELDS = setOf(
        "network_id", "proposal_content_id", "governance_attempt_id", "body_instance_id",
        "ballot_attempt_id", "parameter_hash", "tle_key_session_id",
        "tle_key_transcript_hash", "tle_master_public_key",
    )
    private val TLE_KEY_SESSION_FIELDS = setOf(
        "version", "key_session_id", "network_id", "roster_hash", "committee_size",
        "threshold", "generator_h", "generator_v", "qualified_dealers",
        "qualified_dealer_commitments", "dkg_event_hash", "group_public_key",
        "public_shares", "transcript_hash",
    )
    private val TLE_DEALER_FIELDS = setOf(
        "dealer_index", "coefficient_commitments", "constant_pok_commitment",
        "constant_pok_response",
    )
    private val TLE_PUBLIC_SHARE_FIELDS = setOf("index", "participant_hash", "public_key_share")
    private val TLE_RELEASE_IDENTITY_FIELDS = setOf(
        "tle_key_session_id", "governance_attempt_id", "body_instance_id",
        "ballot_attempt_id", "survivor_corpus_root", "no_recovery_root",
        "target_finalized_height", "parameter_hash",
    )
    private val TLE_PARTIAL_RELEASE_FIELDS = setOf(
        "key_session_id", "identity_digest", "participant_index", "sigma", "proof_x",
        "proof_y", "z_s", "z_r", "z_u",
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

    /** Replace the casting-context ballot parameter after exact lowercase validation. */
    @JvmStatic
    fun timedOvnCastingContextReadPath(ballotAttemptId: String): String =
        TIMED_OVN_CASTING_CONTEXT_READ_PATH.replace(
            "{ballot_attempt_id}",
            canonicalId(ballotAttemptId),
        )

    /** Replace the proof ballot parameter after exact lowercase validation. */
    @JvmStatic
    fun timedOvnCastingProofPath(ballotAttemptId: String): String =
        TIMED_OVN_CASTING_PROOF_PATH.replace(
            "{ballot_attempt_id}",
            canonicalId(ballotAttemptId),
        )

    /** Encode one positive u64 checkpoint height as the canonical zero-padding request frame. */
    @JvmStatic
    fun timedOvnCastingProofRequestNorito(trustedCheckpointHeight: BigInteger): ByteArray {
        val height = requireTimedOvnCastingCheckpointHeight(trustedCheckpointHeight)
        val payload = ByteArray(12)
        // Compact-Norito struct field count, version field, then aligned u64 field.
        payload[0] = 2
        payload[1] = TIMED_OVN_CASTING_PROOF_REQUEST_VERSION.toByte()
        payload[2] = 0
        payload[3] = TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT.toByte()
        for (index in 0 until 8) {
            payload[4 + index] =
                height.shiftRight(index * 8).and(BigInteger.valueOf(0xffL)).toByte()
        }
        val header = NoritoHeader(
            decodeHex(TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX),
            payload.size,
            CRC64.compute(payload),
            TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS,
            NoritoHeader.COMPRESSION_NONE,
        )
        return (header.encode() + payload).also { frame ->
            check(frame.size == TIMED_OVN_CASTING_PROOF_REQUEST_BYTES)
        }
    }

    /** Convenience overload for positive signed heights. */
    @JvmStatic
    fun timedOvnCastingProofRequestNorito(trustedCheckpointHeight: Long): ByteArray =
        timedOvnCastingProofRequestNorito(BigInteger.valueOf(trustedCheckpointHeight))

    /** Admit one exact, uncompressed, compact-length response frame with no header padding. */
    @JvmStatic
    fun parseTimedOvnCastingProofResponse(
        bytes: ByteArray,
    ): ParliamentTimedOvnCastingProofResponseV1 {
        require(bytes.isNotEmpty()) { "Parliament timed-OVN casting proof response is empty" }
        require(bytes.size <= MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES) {
            "Parliament timed-OVN casting proof response exceeds its 8 MiB bound"
        }
        val decoded = try {
            NoritoHeader.decode(
                bytes,
                decodeHex(TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX),
            )
        } catch (error: RuntimeException) {
            throw IllegalArgumentException(
                "Parliament timed-OVN casting proof response is not a valid Norito frame",
                error,
            )
        }
        require(decoded.header.compression == NoritoHeader.COMPRESSION_NONE) {
            "Parliament timed-OVN casting proof response must use identity encoding"
        }
        require(decoded.header.flags == TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS) {
            "Parliament timed-OVN casting proof response has non-canonical Norito flags"
        }
        require(bytes.size == NoritoHeader.HEADER_LENGTH + decoded.header.payloadLength) {
            "Parliament timed-OVN casting proof response must not contain header padding"
        }
        require(
            decoded.header.encode().contentEquals(
                bytes.copyOfRange(0, NoritoHeader.HEADER_LENGTH),
            ),
        ) { "Parliament timed-OVN casting proof response header is not canonical" }
        require(decoded.payload.isNotEmpty()) {
            "Parliament timed-OVN casting proof response payload is empty"
        }
        decoded.header.validateChecksum(decoded.payload)
        return ParliamentTimedOvnCastingProofResponseV1(bytes, decoded.payload)
    }

    internal fun requireTimedOvnCastingCheckpointHeight(value: BigInteger): BigInteger {
        require(value.signum() > 0 && value.bitLength() <= 64) {
            "trustedCheckpointHeight must be a positive u64"
        }
        return value
    }

    /** Replace the release-context ballot parameter after exact lowercase validation. */
    @JvmStatic
    fun tleReleaseContextReadPath(ballotAttemptId: String): String =
        TLE_RELEASE_CONTEXT_READ_PATH.replace(
            "{ballot_attempt_id}",
            canonicalId(ballotAttemptId),
        )

    /** Replace the local partial-release ballot parameter after exact lowercase validation. */
    @JvmStatic
    fun tlePartialReleasePath(ballotAttemptId: String): String =
        TLE_PARTIAL_RELEASE_PATH.replace("{ballot_attempt_id}", canonicalId(ballotAttemptId))

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
        if (layout.jsonPayloadRequired) {
            validateTransitionPayload(
                tag,
                objectValue(transition["payload"], "$tag payload"),
            )
        }
        return encode(
            linkedMapOf(
                "version" to VERSION,
                "governance_attempt_id" to canonicalId(governanceAttemptId),
                "transition" to transition,
            ),
        )
    }

    private fun validateTransitionPayload(tag: String, payload: Map<String, Any?>) {
        if (tag != "FreezeTimedOvnCorpus") return
        require(payload.keys == setOf("ballot_attempt_id", "ballot_records")) {
            "$tag payload contains unknown, aliased, or missing fields"
        }
        val ballotAttemptId = payload["ballot_attempt_id"] as? String
            ?: throw IllegalArgumentException("$tag.ballot_attempt_id must be text")
        canonicalId(ballotAttemptId)
        val records = payload["ballot_records"] as? List<*>
            ?: throw IllegalArgumentException("$tag.ballot_records must be an array")
        require(records.size in 1..TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS) {
            "$tag.ballot_records must contain one through $TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS records"
        }
        records.forEachIndexed { index, record ->
            fixedBytes(
                record,
                TIMED_OVN_BALLOT_RECORD_BYTES,
                "$tag.ballot_records[$index]",
                false,
            )
        }
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

    /** Strictly admit one replay-validated public timed-OVN wallet context. */
    @JvmStatic
    fun parseTimedOvnCastingContextResponse(
        bytes: ByteArray,
        expectedBallotAttemptId: String,
    ): ParliamentTimedOvnCastingContextResponseV1 {
        val root = exactRoot(
            bytes,
            TIMED_OVN_CASTING_CONTEXT_FIELDS,
            "Parliament timed-OVN casting context",
        )
        version(root)
        val currentHeight = unsignedInteger(root["current_height"], "current_height")
        require(BigInteger(currentHeight) > BigInteger.ZERO) { "current_height must be nonzero" }
        val phase = try {
            ParliamentTimedOvnCastingPhaseV1.valueOf(
                root["phase"] as? String
                    ?: throw IllegalArgumentException("phase must be text"),
            )
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("unknown cast-capable timed-OVN phase", error)
        }
        val sessionRoot = exactObject(root["session"], TIMED_OVN_SESSION_FIELDS, "session")
        val session = ParliamentTimedOvnSessionProjectionV1(
            byteArray32(sessionRoot["network_id"], "session.network_id"),
            id(sessionRoot, "proposal_content_id"),
            id(sessionRoot, "governance_attempt_id"),
            id(sessionRoot, "body_instance_id"),
            id(sessionRoot, "ballot_attempt_id"),
            byteArray32(sessionRoot["parameter_hash"], "session.parameter_hash"),
            id(sessionRoot, "tle_key_session_id"),
            byteArray32(
                sessionRoot["tle_key_transcript_hash"],
                "session.tle_key_transcript_hash",
            ),
            fixedBytes(
                sessionRoot["tle_master_public_key"],
                96,
                "session.tle_master_public_key",
                true,
            ),
        )
        require(session.ballotAttemptId == canonicalId(expectedBallotAttemptId)) {
            "session.ballot_attempt_id differs from the requested canonical id"
        }
        val registrationOpened = unsignedInteger(
            root["registration_opened_at_finalized_height"],
            "registration_opened_at_finalized_height",
        )
        val targetHeight = unsignedInteger(
            root["target_finalized_height"],
            "target_finalized_height",
        )
        require(BigInteger(registrationOpened) > BigInteger.ZERO &&
            BigInteger(registrationOpened) <= BigInteger(currentHeight) &&
            BigInteger(targetHeight) > BigInteger(registrationOpened)) {
            "casting-context height schedule is inconsistent"
        }
        val keySession = parseTleKeySession(root["tle_key_session"])
        require(session.tleKeySessionId == keySession.keySessionId &&
            session.tleKeyTranscriptHash.contentEquals(keySession.transcriptHash) &&
            session.tleMasterPublicKey.contentEquals(keySession.groupPublicKey)) {
            "timed-OVN session differs from the complete public TLE transcript"
        }
        val recordValues = root["registration_records_hex"] as? List<*>
            ?: throw IllegalArgumentException("registration_records_hex must be an array")
        require(recordValues.size <= MAX_TIMED_OVN_CORPUS_ENTRIES &&
            (phase == ParliamentTimedOvnCastingPhaseV1.Registered || recordValues.isNotEmpty())) {
            "registration corpus violates its casting-phase bound"
        }
        val registrationRecords = recordValues.mapIndexed { index, value ->
            canonicalHex(
                value,
                "registration_records_hex[$index]",
                false,
            ).also {
                require(it.length == TIMED_OVN_REGISTRATION_RECORD_BYTES * 2) {
                    "registration record has the wrong exact width"
                }
            }
        }
        require(registrationRecords.toSet().size == registrationRecords.size) {
            "registration records must be unique"
        }
        val survivorHashes = (root["survivor_participant_hashes"] as? List<*>)?.mapIndexed {
                index,
                value,
            ->
            byteArray32(value, "survivor_participant_hashes[$index]")
        }
        val releaseIdentity = root["release_identity"]?.let { value ->
            val identity = exactObject(value, TLE_RELEASE_IDENTITY_FIELDS, "release_identity")
            ParliamentTimedOvnReleaseIdentityProjectionV1(
                id(identity, "tle_key_session_id"),
                id(identity, "governance_attempt_id"),
                id(identity, "body_instance_id"),
                id(identity, "ballot_attempt_id"),
                byteArray32(identity["survivor_corpus_root"], "release_identity.survivor_corpus_root"),
                byteArray32(identity["no_recovery_root"], "release_identity.no_recovery_root"),
                unsignedInteger(
                    identity["target_finalized_height"],
                    "release_identity.target_finalized_height",
                ),
                byteArray32(identity["parameter_hash"], "release_identity.parameter_hash"),
            )
        }
        if (phase == ParliamentTimedOvnCastingPhaseV1.SurvivorsFrozen) {
            require(survivorHashes != null &&
                survivorHashes.isNotEmpty() &&
                survivorHashes.size <= registrationRecords.size &&
                survivorHashes.map(ByteArray::contentToString).toSet().size == survivorHashes.size &&
                releaseIdentity != null) {
                "SurvivorsFrozen requires bounded unique survivors and release identity"
            }
            require(releaseIdentity.tleKeySessionId == session.tleKeySessionId &&
                releaseIdentity.governanceAttemptId == session.governanceAttemptId &&
                releaseIdentity.bodyInstanceId == session.bodyInstanceId &&
                releaseIdentity.ballotAttemptId == session.ballotAttemptId &&
                releaseIdentity.targetFinalizedHeight == targetHeight &&
                releaseIdentity.parameterHash.contentEquals(session.parameterHash)) {
                "frozen release identity differs from the timed-OVN session"
            }
        } else {
            require(survivorHashes == null && releaseIdentity == null) {
                "pre-freeze casting context must not expose frozen state"
            }
        }
        val archiveLiteral = root["archive_norito_base64"] as? String
            ?: throw IllegalArgumentException("archive_norito_base64 must be text")
        val archive = try {
            Base64.getDecoder().decode(archiveLiteral)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("archive_norito_base64 is invalid", error)
        }
        require(archive.isNotEmpty() &&
            archive.size <= MAX_TIMED_OVN_CASTING_ARCHIVE_BYTES &&
            Base64.getEncoder().encodeToString(archive) == archiveLiteral) {
            "archive_norito_base64 is oversized or noncanonical"
        }
        return ParliamentTimedOvnCastingContextResponseV1(
            currentHeight,
            phase,
            session,
            registrationOpened,
            targetHeight,
            keySession,
            registrationRecords,
            survivorHashes,
            releaseIdentity,
            archive,
        )
    }

    /** Strictly admit one complete public adaptive-TLE transcript and release identity. */
    @JvmStatic
    fun parseTleReleaseContextResponse(
        bytes: ByteArray,
        expectedBallotAttemptId: String,
    ): ParliamentTleReleaseContextResponseV1 {
        val root = exactRoot(bytes, TLE_RELEASE_CONTEXT_FIELDS, "Parliament TLE release context")
        version(root)
        val currentHeight = unsignedInteger(root["current_height"], "current_height")
        val ballotAttemptId = id(root, "ballot_attempt_id")
        require(ballotAttemptId == canonicalId(expectedBallotAttemptId)) {
            "ballot_attempt_id differs from the requested canonical id"
        }
        val governanceAttemptId = id(root, "governance_attempt_id")
        val bodyInstanceId = id(root, "body_instance_id")
        require(taggedUnit(root["status"], "status", "status") == "Opening") {
            "release context status must be Opening"
        }
        val releaseHeight = unsignedInteger(root["release_height"], "release_height")
        val openingDeadline = unsignedInteger(
            root["opening_deadline_height"],
            "opening_deadline_height",
        )
        require(BigInteger(currentHeight) >= BigInteger(releaseHeight) &&
            BigInteger(currentHeight) <= BigInteger(openingDeadline)) {
            "release context lies outside its inclusive opening window"
        }
        val keySession = parseTleKeySession(root["tle_key_session"])
        val identityRoot = exactObject(
            root["release_identity"],
            TLE_RELEASE_IDENTITY_FIELDS,
            "release_identity",
        )
        val releaseIdentity = ParliamentTimedOvnReleaseIdentityProjectionV1(
            id(identityRoot, "tle_key_session_id"),
            id(identityRoot, "governance_attempt_id"),
            id(identityRoot, "body_instance_id"),
            id(identityRoot, "ballot_attempt_id"),
            byteArray32(identityRoot["survivor_corpus_root"], "release_identity.survivor_corpus_root"),
            byteArray32(identityRoot["no_recovery_root"], "release_identity.no_recovery_root"),
            unsignedInteger(
                identityRoot["target_finalized_height"],
                "release_identity.target_finalized_height",
            ),
            byteArray32(identityRoot["parameter_hash"], "release_identity.parameter_hash"),
        )
        require(releaseIdentity.tleKeySessionId == keySession.keySessionId &&
            releaseIdentity.governanceAttemptId == governanceAttemptId &&
            releaseIdentity.bodyInstanceId == bodyInstanceId &&
            releaseIdentity.ballotAttemptId == ballotAttemptId &&
            releaseIdentity.targetFinalizedHeight == releaseHeight) {
            "release_identity differs from the top-level Parliament/TLE bindings"
        }
        val payloadHex = canonicalHex(root["identity_payload_hex"], "identity_payload_hex", false)
        require(payloadHex.length == 486) {
            "identity_payload_hex must encode the exact 243-byte identity payload"
        }
        val payload = decodeHex(payloadHex)
        validateTleIdentityPayload(payload, governanceAttemptId, bodyInstanceId, ballotAttemptId, releaseIdentity)
        val identityDigest = byteArray32(root["identity_digest"], "identity_digest")
        require(identityDigest.contentEquals(tleReleaseMessageDigest(keySession, payload))) {
            "identity_digest differs from the exact threshold-session-framed release message"
        }
        return ParliamentTleReleaseContextResponseV1(
            currentHeight,
            ballotAttemptId,
            governanceAttemptId,
            bodyInstanceId,
            releaseHeight,
            openingDeadline,
            keySession,
            releaseIdentity,
            identityDigest,
            payloadHex,
        )
    }

    /** Strictly bind one public partial release to an already admitted release context. */
    @JvmStatic
    fun parseTlePartialReleaseResponse(
        bytes: ByteArray,
        expectedKeySessionId: String,
        expectedIdentityDigest: ByteArray,
        committeeSize: Int,
    ): ParliamentTlePartialReleaseShareV1 {
        require(expectedIdentityDigest.size == 32 && expectedIdentityDigest.any { it.toInt() != 0 }) {
            "expectedIdentityDigest must contain 32 nonzero bytes"
        }
        require(committeeSize in 4..MAX_TLE_COMMITTEE_SIZE && (committeeSize - 1) % 3 == 0) {
            "committeeSize must be an exact supported 3f+1 size"
        }
        val root = exactRoot(bytes, TLE_PARTIAL_RELEASE_FIELDS, "Parliament TLE partial release")
        val keySessionId = id(root, "key_session_id")
        require(keySessionId == canonicalId(expectedKeySessionId)) {
            "partial key_session_id differs from the authorized release context"
        }
        val identityDigest = byteArray32(root["identity_digest"], "identity_digest")
        require(identityDigest.contentEquals(expectedIdentityDigest)) {
            "partial identity_digest differs from the authorized release context"
        }
        val participantIndex = u32Int(root["participant_index"], "participant_index", 1, committeeSize)
        return ParliamentTlePartialReleaseShareV1(
            keySessionId,
            identityDigest,
            participantIndex,
            fixedBytes(root["sigma"], 48, "sigma", true),
            fixedBytes(root["proof_x"], 96, "proof_x", true),
            fixedBytes(root["proof_y"], 48, "proof_y", true),
            fixedBytes(root["z_s"], 32, "z_s", false),
            fixedBytes(root["z_r"], 32, "z_r", false),
            fixedBytes(root["z_u"], 32, "z_u", false),
        )
    }

    private fun parseTleKeySession(value: Any?): ParliamentTleKeySessionPublicStateV1 {
        val root = exactObject(value, TLE_KEY_SESSION_FIELDS, "tle_key_session")
        require(unsignedInteger(root["version"], "tle_key_session.version") == VERSION.toString()) {
            "unsupported TLE public-state version"
        }
        val keySessionId = id(root, "key_session_id")
        val networkId = byteArray32(root["network_id"], "tle_key_session.network_id")
        val rosterHash = byteArray32(root["roster_hash"], "tle_key_session.roster_hash")
        val committeeSize = u32Int(
            root["committee_size"],
            "tle_key_session.committee_size",
            4,
            MAX_TLE_COMMITTEE_SIZE,
        )
        val threshold = u32Int(root["threshold"], "tle_key_session.threshold", 2, 11)
        require((committeeSize - 1) % 3 == 0 && threshold == (committeeSize - 1) / 3 + 1) {
            "TLE committee_size/threshold is not an exact 3f+1/f+1 binding"
        }
        val qualified = root["qualified_dealers"] as? List<*>
            ?: throw IllegalArgumentException("tle_key_session.qualified_dealers must be an array")
        val qualifiedDealers = qualified.mapIndexed { index, dealer ->
            u32Int(
                dealer,
                "tle_key_session.qualified_dealers[$index]",
                1,
                committeeSize,
            )
        }
        require(qualifiedDealers.size in threshold..committeeSize &&
            qualifiedDealers.zipWithNext().all { (left, right) -> left < right }) {
            "qualified dealer indices violate the threshold bound or canonical ordering"
        }
        val dealerValues = root["qualified_dealer_commitments"] as? List<*>
            ?: throw IllegalArgumentException("qualified_dealer_commitments must be an array")
        require(dealerValues.size == qualifiedDealers.size) {
            "qualified dealer commitments must align exactly with qualified_dealers"
        }
        val dealers = dealerValues.mapIndexed { index, raw ->
            val dealer = exactObject(raw, TLE_DEALER_FIELDS, "qualified_dealer_commitments[$index]")
            val dealerIndex = u32Int(
                dealer["dealer_index"],
                "qualified_dealer_commitments[$index].dealer_index",
                1,
                committeeSize,
            )
            require(dealerIndex == qualifiedDealers[index]) {
                "dealer commitment index differs from the canonical qualified set"
            }
            val coefficients = dealer["coefficient_commitments"] as? List<*>
                ?: throw IllegalArgumentException("coefficient_commitments must be an array")
            require(coefficients.size == threshold) {
                "each dealer must carry the exact degree-f coefficient set"
            }
            ParliamentTleAdaptiveDealerCommitmentV1(
                dealerIndex,
                coefficients.mapIndexed { coefficientIndex, commitment ->
                    fixedBytes(
                        commitment,
                        96,
                        "qualified_dealer_commitments[$index].coefficient_commitments[$coefficientIndex]",
                        true,
                    )
                },
                fixedBytes(
                    dealer["constant_pok_commitment"],
                    96,
                    "qualified_dealer_commitments[$index].constant_pok_commitment",
                    true,
                ),
                fixedBytes(
                    dealer["constant_pok_response"],
                    32,
                    "qualified_dealer_commitments[$index].constant_pok_response",
                    false,
                ),
            )
        }
        val shareValues = root["public_shares"] as? List<*>
            ?: throw IllegalArgumentException("tle_key_session.public_shares must be an array")
        require(shareValues.size == committeeSize) {
            "public_shares must contain the complete ordered committee"
        }
        val shares = shareValues.mapIndexed { offset, raw ->
            val share = exactObject(raw, TLE_PUBLIC_SHARE_FIELDS, "public_shares[$offset]")
            val index = u32Int(share["index"], "public_shares[$offset].index", 1, committeeSize)
            require(index == offset + 1) {
                "public share indices must be the exact one-based committee sequence"
            }
            ParliamentTleAdaptivePublicShareV1(
                index,
                byteArray32(share["participant_hash"], "public_shares[$offset].participant_hash"),
                fixedBytes(share["public_key_share"], 96, "public_shares[$offset].public_key_share", true),
            )
        }
        return ParliamentTleKeySessionPublicStateV1(
            keySessionId,
            networkId,
            rosterHash,
            committeeSize,
            threshold,
            fixedBytes(root["generator_h"], 96, "tle_key_session.generator_h", true),
            fixedBytes(root["generator_v"], 96, "tle_key_session.generator_v", true),
            qualifiedDealers,
            dealers,
            byteArray32(root["dkg_event_hash"], "tle_key_session.dkg_event_hash"),
            fixedBytes(root["group_public_key"], 96, "tle_key_session.group_public_key", true),
            shares,
            byteArray32(root["transcript_hash"], "tle_key_session.transcript_hash"),
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
            val timedOvnProgress = entry["timed_ovn_progress"]?.let {
                validateTimedOvnProgress(it, "$context.timed_ovn_progress")
            }
            require(timedOvnProgress == null || (body in PRIVATE_BODIES && bodyInstanceId != null)) {
                "$context.timed_ovn_progress requires an active private body"
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
                timedOvnProgress,
            )
        }
    }

    private fun validateTimedOvnProgress(
        value: Any?,
        context: String,
    ): ParliamentTimedOvnProgressProjectionV1 {
        val progress = exactObject(
            value,
            setOf(
                "ballot_attempt_id", "status", "frozen_survivor_count",
                "accepted_ballot_prefix_count",
            ),
            context,
        )
        val ballotAttemptId = id(progress, "ballot_attempt_id")
        val status = taggedUnitIn(
            progress["status"],
            "status",
            setOf(
                "Registration", "SurvivorFreeze", "TimedCommitment", "AwaitingRelease",
                "Opening", "Finalized", "NoResult", "Superseded",
            ),
            "$context.status",
        )
        val survivorsValue = progress["frozen_survivor_count"]
        val prefixValue = progress["accepted_ballot_prefix_count"]
        require((survivorsValue == null) == (prefixValue == null)) {
            "$context survivor and prefix counts must appear together"
        }
        var survivors: Int? = null
        var prefix: Int? = null
        if (survivorsValue == null) {
            require(status in setOf("Registration", "SurvivorFreeze", "NoResult", "Superseded")) {
                "$context must expose counts after survivor freeze"
            }
        } else {
            survivors = u32Int(
                survivorsValue,
                "$context.frozen_survivor_count",
                1,
                MAX_TIMED_OVN_CORPUS_ENTRIES,
            )
            prefix = u32Int(
                prefixValue,
                "$context.accepted_ballot_prefix_count",
                0,
                survivors,
            )
            require(status != "TimedCommitment" || prefix < survivors) {
                "$context TimedCommitment prefix must remain incomplete"
            }
            require(status !in setOf("AwaitingRelease", "Opening", "Finalized") || prefix == survivors) {
                "$context sealed/released prefix must equal frozen survivors"
            }
            require(status !in setOf("Registration", "SurvivorFreeze")) {
                "$context exposes counts before survivor freeze"
            }
        }
        return ParliamentTimedOvnProgressProjectionV1(
            ballotAttemptId,
            status,
            survivors,
            prefix,
        )
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
        val seenBallotAttemptIds = HashSet<String>()
        val seenTleSessionIds = HashSet<String>()
        val seenReleasePulseIds = HashSet<String>()
        val seenReleaseSlots = HashSet<String>()
        val sortitionPulseIds = HashSet<String>()
        val findings = ArrayList<ParliamentPublicFindingCertificateBindingV1>()
        var latestBodyResultHeight = BigInteger.ZERO
        var policyJury: CertificateJuryFacts? = null
        var confirmationJury: CertificateJuryFacts? = null
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
                MAX_TIMED_OVN_CORPUS_ENTRIES,
            )
            val bodyInstanceId = id(binding, "body_instance_id")
            require(bodyInstanceId == bodyStates[index].bodyInstanceId) {
                "$context.body_instance_id differs from body_states"
            }
            val electionAttemptId = id(binding, "election_attempt_id")
            val sortitionRequestId = id(binding, "sortition_request_id")
            val beaconSessionId = id(binding, "beacon_session_id")
            val beaconPulseId = id(binding, "beacon_pulse_id")
            require(seenBodyInstanceIds.add(bodyInstanceId)) {
                "certificate.body_bindings reuses body_instance_id"
            }
            require(seenElectionAttemptIds.add(electionAttemptId)) {
                "certificate.body_bindings reuses election_attempt_id"
            }
            require(seenSortitionRequestIds.add(sortitionRequestId)) {
                "certificate.body_bindings reuses sortition_request_id"
            }
            sortitionPulseIds.add(beaconPulseId)
            for (field in listOf("roster_root", "assignment_root", "result_root")) {
                byteArray32(binding[field], "$context.$field")
            }
            val electionAttemptSequence = u32Int(
                binding["election_attempt_sequence"],
                "$context.election_attempt_sequence",
                0,
                MAX_SORTITION_RETRIES,
            )
            val resultHeight = BigInteger(
                unsignedInteger(binding["result_height"], "$context.result_height"),
            )
            latestBodyResultHeight = latestBodyResultHeight.max(resultHeight)
            val sortition = validateCertificateSortitionRequest(
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
                require(binding["public_finding"] == null && binding["ballot"] != null) {
                    "$context private jury must carry ballot only"
                }
                val ballot = validateCertificateBallot(
                    binding["ballot"],
                    seats,
                    resultHeight,
                    "$context.ballot",
                )
                val progress = bodyStates[index].timedOvnProgress
                require(progress != null && progress.status == "Finalized" &&
                    progress.ballotAttemptId == ballot.ballotAttemptId &&
                    progress.frozenSurvivorCount == ballot.acceptedBallots &&
                    progress.acceptedBallotPrefixCount == ballot.acceptedBallots) {
                    "$context.ballot differs from timed_ovn_progress"
                }
                require(seenBallotAttemptIds.add(ballot.ballotAttemptId)) {
                    "certificate.body_bindings reuses ballot_attempt_id"
                }
                require(seenTleSessionIds.add(ballot.tleSessionId)) {
                    "certificate.body_bindings reuses tle_session_id"
                }
                require(seenReleasePulseIds.add(ballot.releasePulseId)) {
                    "certificate.body_bindings reuses release_pulse_id"
                }
                require(seenReleaseSlots.add(ballot.releaseSlot)) {
                    "certificate.body_bindings reuses a TLE release slot"
                }
                val jury = CertificateJuryFacts(
                    electionAttemptSequence,
                    sortition.requestHeight,
                    resultHeight,
                    beaconPulseId,
                    ballot,
                )
                if (body == "policy-jury") {
                    require(policyJury == null) { "certificate contains more than one policy-jury" }
                    policyJury = jury
                } else {
                    require(confirmationJury == null) {
                        "certificate contains more than one confirmation-jury"
                    }
                    confirmationJury = jury
                }
            } else {
                require(bodyStates[index].timedOvnProgress == null) {
                    "$context public body exposes timed_ovn_progress"
                }
                require(binding["public_finding"] != null && binding["ballot"] == null) {
                    "$context public body must carry public_finding only"
                }
                findings.add(validatePublicFinding(binding["public_finding"], seats, "$context.public_finding"))
            }
        }
        require(sortitionPulseIds.intersect(seenReleasePulseIds).isEmpty()) {
            "certificate reuses a sortition pulse for ballot release"
        }
        require(certifiedAtHeight == latestBodyResultHeight) {
            "certificate.certified_at_height must equal the latest body result height"
        }
        val policy = requireNotNull(policyJury) {
            "certificate must contain exactly one approving policy-jury ballot"
        }
        val decisive = policy.ballot.aye + policy.ballot.nay
        val requiresConfirmation = decisive.signum() > 0 &&
            policy.ballot.aye.subtract(policy.ballot.nay).abs() * BigInteger.valueOf(100) <
            decisive * BigInteger.valueOf(5)
        require(requiresConfirmation == (confirmationJury != null)) {
            "certificate confirmation-jury presence differs from the policy margin"
        }
        confirmationJury?.let { confirmation ->
            val validRequestHeight = if (confirmation.electionAttemptSequence == 0) {
                confirmation.requestHeight == policy.resultHeight
            } else {
                confirmation.requestHeight > policy.resultHeight
            }
            require(validRequestHeight && confirmation.beaconPulseId != policy.beaconPulseId) {
                "certificate confirmation-jury request height must match the atomic initial " +
                    "request or follow it on retry, with a fresh pulse"
            }
        }
        return findings
    }

    private data class CertificateSortitionFacts(val requestHeight: BigInteger)

    private data class CertificateJuryFacts(
        val electionAttemptSequence: Int,
        val requestHeight: BigInteger,
        val resultHeight: BigInteger,
        val beaconPulseId: String,
        val ballot: CertificateBallotFacts,
    )

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
    ): CertificateSortitionFacts {
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
            MAX_TIMED_OVN_CORPUS_ENTRIES,
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
        return CertificateSortitionFacts(requestHeight)
    }

    private data class CertificateBallotFacts(
        val ballotAttemptId: String,
        val tleSessionId: String,
        val releasePulseId: String,
        val releaseSlot: String,
        val acceptedBallots: Int,
        val aye: BigInteger,
        val nay: BigInteger,
    )

    private fun validateCertificateBallot(
        value: Any?,
        originalSeats: Int,
        resultHeight: BigInteger,
        context: String,
    ): CertificateBallotFacts {
        val ballot = exactObject(
            value,
            setOf(
                "ballot_attempt_id", "ballot_attempt_sequence", "tle_session_id",
                "tle_key_session_id", "registration_root", "dropout_root", "survivor_root",
                "corpus_root", "no_recovery_root", "timed_commitment_root",
                "release_beacon_session_id", "registered_at_height", "registration_close_height",
                "survivor_freeze_height", "commitment_close_height",
                "registration_closed_at_height", "survivors_frozen_at_height",
                "commitment_closed_at_height", "max_ballot_retries", "max_corpus_entries",
                "release_height", "opening_deadline_height", "release_pulse_id",
                "opening_height", "opening_root", "tally", "outcome",
            ),
            context,
        )
        val ballotAttemptId = id(ballot, "ballot_attempt_id")
        val tleSessionId = id(ballot, "tle_session_id")
        id(ballot, "tle_key_session_id")
        val releaseBeaconSessionId = id(ballot, "release_beacon_session_id")
        val releasePulseId = id(ballot, "release_pulse_id")
        for (field in listOf(
            "registration_root", "dropout_root", "survivor_root", "corpus_root",
            "no_recovery_root", "timed_commitment_root", "opening_root",
        )) byteArray32(ballot[field], "$context.$field")
        val sequence = u32Int(ballot["ballot_attempt_sequence"], "$context.ballot_attempt_sequence", 0, 16)
        val maxRetries = u32Int(ballot["max_ballot_retries"], "$context.max_ballot_retries", 0, 16)
        require(sequence <= maxRetries) { "$context.ballot_attempt_sequence exceeds max_ballot_retries" }
        val maxCorpusEntries = u32Int(
            ballot["max_corpus_entries"],
            "$context.max_corpus_entries",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES,
        )
        fun height(field: String) = BigInteger(unsignedInteger(ballot[field], "$context.$field"))
        val registered = height("registered_at_height")
        val registrationClose = height("registration_close_height")
        val survivorFreeze = height("survivor_freeze_height")
        val commitmentClose = height("commitment_close_height")
        val registrationClosed = height("registration_closed_at_height")
        val survivorsFrozen = height("survivors_frozen_at_height")
        val commitmentClosed = height("commitment_closed_at_height")
        val release = height("release_height")
        val openingDeadline = height("opening_deadline_height")
        val opening = height("opening_height")
        val maxCorpus = BigInteger.valueOf(maxCorpusEntries.toLong())
        val requiredCommitmentBlocks = BigInteger.valueOf(
            ((maxCorpusEntries + TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS - 1) /
                TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS).toLong(),
        )
        require(registered.signum() > 0 && registrationClose > registered &&
            maxCorpusEntries >= originalSeats &&
            registrationClose - registered >= maxCorpus + BigInteger.ONE &&
            survivorFreeze > registrationClose && commitmentClose > survivorFreeze &&
            survivorFreeze - registrationClose >= maxCorpus &&
            commitmentClose - survivorFreeze >= requiredCommitmentBlocks &&
            release > commitmentClose && openingDeadline > release &&
            registrationClosed == registrationClose && survivorsFrozen == survivorFreeze &&
            commitmentClosed > survivorFreeze && commitmentClosed <= commitmentClose &&
            opening >= release && opening <= openingDeadline &&
            resultHeight >= opening && resultHeight <= openingDeadline) {
            "$context violates the frozen ballot lifecycle"
        }
        val tally = exactObject(
            ballot["tally"],
            setOf("original_seats", "accepted_ballots", "aye", "nay", "abstain"),
            "$context.tally",
        )
        val tallySeats = u32Int(
            tally["original_seats"],
            "$context.tally.original_seats",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES,
        )
        val accepted = u32Int(
            tally["accepted_ballots"],
            "$context.tally.accepted_ballots",
            0,
            MAX_TIMED_OVN_CORPUS_ENTRIES,
        )
        val aye = BigInteger(u32(tally["aye"], "$context.tally.aye"))
        val nay = BigInteger(u32(tally["nay"], "$context.tally.nay"))
        val abstain = BigInteger(u32(tally["abstain"], "$context.tally.abstain"))
        require(tallySeats == originalSeats && accepted <= maxCorpusEntries && accepted <= originalSeats &&
            aye + nay + abstain == BigInteger.valueOf(accepted.toLong())) {
            "$context.tally violates immutable bounds or count conservation"
        }
        val quorum = (2 * originalSeats + 2) / 3
        val outcome = taggedUnitIn(
            ballot["outcome"],
            "outcome",
            setOf("Approved", "Rejected", "NoQuorum", "NoResult"),
            "$context.outcome",
        )
        val expectedOutcome = when {
            accepted < quorum -> "NoQuorum"
            aye > nay -> "Approved"
            else -> "Rejected"
        }
        require(outcome == expectedOutcome && outcome == "Approved") {
            "$context must contain the deterministic approving aggregate outcome"
        }
        return CertificateBallotFacts(
            ballotAttemptId,
            tleSessionId,
            releasePulseId,
            "$releaseBeaconSessionId:$release",
            accepted,
            aye,
            nay,
        )
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
        require(assignments.size in 1..MAX_TIMED_OVN_CORPUS_ENTRIES &&
            assignments.zipWithNext().all { (left, right) -> left < right }) {
            "$context.endorsing_assignments must be strictly increasing and distinct"
        }
        val endorsements = u32Int(
            finding["endorsements"],
            "$context.endorsements",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES,
        )
        val quorum = u32Int(
            finding["quorum"],
            "$context.quorum",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES,
        )
        val expectedQuorum = (2 * originalSeats + 2) / 3
        require(assignments.size == endorsements && endorsements == quorum && quorum == expectedQuorum) {
            "$context must contain the exact canonical two-thirds supporter list"
        }
        return ParliamentPublicFindingCertificateBindingV1(root, assignments, endorsements, quorum)
    }

    private fun validateTleIdentityPayload(
        payload: ByteArray,
        governanceAttemptId: String,
        bodyInstanceId: String,
        ballotAttemptId: String,
        identity: ParliamentTimedOvnReleaseIdentityProjectionV1,
    ) {
        val domain = "iroha.parliament.tle.identity-payload.v1\u0000"
            .toByteArray(StandardCharsets.UTF_8)
        require(payload.size == 243 && payload.copyOfRange(0, domain.size).contentEquals(domain)) {
            "identity_payload_hex has the wrong domain or canonical width"
        }
        var offset = domain.size
        require(payload.copyOfRange(offset, offset + 2).contentEquals(u16Bytes(1))) {
            "identity payload version must equal one"
        }
        offset += 2
        for ((expected, field) in listOf(
            decodeHex(governanceAttemptId) to "governance_attempt_id",
            decodeHex(bodyInstanceId) to "body_instance_id",
            decodeHex(ballotAttemptId) to "ballot_attempt_id",
            identity.survivorCorpusRoot to "survivor_corpus_root",
            identity.noRecoveryRoot to "no_recovery_root",
        )) {
            require(payload.copyOfRange(offset, offset + 32).contentEquals(expected)) {
                "identity payload $field binding differs"
            }
            offset += 32
        }
        require(
            payload.copyOfRange(offset, offset + 8)
                .contentEquals(u64Bytes(BigInteger(identity.targetFinalizedHeight))),
        ) { "identity payload release height differs" }
        offset += 8
        require(payload.copyOfRange(offset, offset + 32).contentEquals(identity.parameterHash)) {
            "identity payload parameter_hash binding differs"
        }
    }

    private fun tleReleaseMessageDigest(
        session: ParliamentTleKeySessionPublicStateV1,
        identityPayload: ByteArray,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        fun append(value: ByteArray) = output.write(value, 0, value.size)
        append("iroha.threshold-bls.message.v1\u0000".toByteArray(StandardCharsets.UTF_8))
        append("iroha.threshold-bls.session.v1\u0000".toByteArray(StandardCharsets.UTF_8))
        append(u16Bytes(1))
        output.write(2)
        append(session.networkId)
        append(decodeHex(session.keySessionId))
        append(session.rosterHash)
        append(u16Bytes(session.committeeSize))
        append(u16Bytes(session.threshold))
        append(u32Bytes(identityPayload.size))
        append(identityPayload)
        return MessageDigest.getInstance("SHA-256").digest(output.toByteArray())
    }

    private fun u16Bytes(value: Int): ByteArray = byteArrayOf(
        ((value ushr 8) and 0xff).toByte(),
        (value and 0xff).toByte(),
    )

    private fun u32Bytes(value: Int): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xff).toByte(),
        ((value ushr 16) and 0xff).toByte(),
        ((value ushr 8) and 0xff).toByte(),
        (value and 0xff).toByte(),
    )

    private fun u64Bytes(value: BigInteger): ByteArray {
        require(value.signum() >= 0 && value.bitLength() <= 64) { "height is outside u64" }
        val encoded = value.toByteArray()
        val unsigned = if (encoded.size == 9 && encoded[0].toInt() == 0) {
            encoded.copyOfRange(1, encoded.size)
        } else {
            encoded
        }
        require(unsigned.size <= 8) { "height is outside u64" }
        return ByteArray(8 - unsigned.size) + unsigned
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
