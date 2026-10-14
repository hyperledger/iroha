package org.hyperledger.iroha.android.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import org.hyperledger.iroha.norito.CRC64;
import org.hyperledger.iroha.norito.NoritoHeader;

/** Reflection-free builders and strict response admission for Parliament API V1. */
public final class ParliamentApiV1 {

  public static final int VERSION = 1;
  public static final String ATTEMPT_DRAFT_PATH = "/v1/gov/parliament/attempts/draft";
  public static final String ATTEMPT_READ_PATH =
      "/v1/gov/parliament/attempts/{governance_attempt_id}";
  public static final String TIMED_OVN_CASTING_CONTEXT_READ_PATH =
      "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context";
  public static final String TIMED_OVN_CASTING_PROOF_PATH =
      "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof";
  public static final String TLE_RELEASE_CONTEXT_READ_PATH =
      "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context";
  public static final String TLE_PARTIAL_RELEASE_PATH =
      "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release";
  public static final String TRANSITION_DRAFT_PATH =
      "/v1/gov/parliament/transitions/draft";
  public static final String ATTEMPT_CREATE_WIRE_ID =
      "iroha.governance.parliament.attempt.create.v1";
  public static final String TRANSITION_SUBMIT_WIRE_ID =
      "iroha.governance.parliament.transition.submit.v1";
  public static final int MAX_STATE_BYTES = 16 * 1024 * 1024;
  public static final int MAX_TLE_COMMITTEE_SIZE = 31;
  public static final int MAX_TIMED_OVN_CASTING_ARCHIVE_BYTES = 4 * 1024 * 1024;
  public static final int MAX_TIMED_OVN_CASTING_PROOF_RESPONSE_BYTES = 8 * 1024 * 1024;
  public static final int MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS = 64;
  /** Maximum checkpoint advance authenticated by one checkpoint-inclusive finality page. */
  public static final int MAX_TIMED_OVN_CASTING_PROOF_PAGE_HEIGHT_ADVANCE =
      MAX_TIMED_OVN_CASTING_PROOF_FINALITY_PROOFS - 1;
  /** Deterministic maximum number of pages admitted by one client catch-up operation. */
  public static final int MAX_TIMED_OVN_CASTING_PROOF_PAGES = 64;
  /** Deterministic aggregate height advance admitted by one client catch-up operation. */
  public static final int MAX_TIMED_OVN_CASTING_PROOF_HEIGHT_ADVANCE =
      MAX_TIMED_OVN_CASTING_PROOF_PAGE_HEIGHT_ADVANCE * MAX_TIMED_OVN_CASTING_PROOF_PAGES;
  public static final String TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA =
      "iroha.torii.v1.parliament.timed_ovn_casting_proof.request";
  public static final String TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA =
      "iroha.torii.v1.parliament.timed_ovn_casting_proof.response";
  public static final String TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX =
      "adccf322a5fcf43040e20bea238f55f3";
  public static final String TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX =
      "46d29299272433b1299646bee722bd11";
  public static final int TIMED_OVN_CASTING_PROOF_REQUEST_VERSION = 1;
  public static final int TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS = NoritoHeader.COMPACT_LEN;
  public static final int TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT = 8;
  public static final int TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES = 0;
  public static final int TIMED_OVN_CASTING_PROOF_REQUEST_BYTES = 52;
  public static final int TIMED_OVN_REGISTRATION_RECORD_BYTES = 3_624;
  public static final int TIMED_OVN_BALLOT_RECORD_BYTES = 2_858;
  /** Maximum records appended by one transition; the complete corpus may contain 1,000. */
  public static final int TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS = 32;
  public static final int MAX_TIMED_OVN_CORPUS_ENTRIES = 1_000;
  /** Maximum retry sequence for a whole governance attempt; valid sequences are 0 through 16. */
  public static final int MAX_GOVERNANCE_ATTEMPT_RETRIES = 16;
  private static final int GOVERNANCE_POLICY_VERSION = 1;
  private static final int MAX_SORTITION_RETRIES = 16;
  public static final String PUBLIC_TRANSITION_DIGEST_DOMAIN =
      "iroha.governance.parliament.lifecycle_transition.digest.v1";
  public static final String AUTOMATIC_OUTCOME_DIGEST_DOMAIN =
      "iroha.governance.parliament.automatic_execution_outcome.digest.v1";

  /** Exact first-release actions admitted by contract-lifecycle governance proposals. */
  public static final List<String> CONTRACT_LIFECYCLE_ACTIONS =
      listOf(
          "Activate",
          "Deactivate",
          "OfferOwnership",
          "CancelOwnershipOffer",
          "AcceptParliamentOwnership",
          "CompleteEmergencyHoldRetrospective");

  public static final List<TransitionLayout> PUBLIC_TRANSITIONS =
      listOf(
          new TransitionLayout(0, "EscalateRisk", true, 0),
          new TransitionLayout(1, "CompleteQualification", false, 1),
          new TransitionLayout(2, "RegisterSortitionRequest", true, 2),
          new TransitionLayout(3, "ConsumeSortitionPulseBatch", true, 3),
          new TransitionLayout(4, "BeginInvitationAcceptance", true, 4),
          new TransitionLayout(5, "FailBodyElectionNoRoster", true, 5),
          new TransitionLayout(6, "SealBodyRoster", true, 6),
          new TransitionLayout(7, "AdvanceBodyPhase", true, 7),
          new TransitionLayout(8, "RecordAttemptAbsence", true, 8),
          new TransitionLayout(9, "EndorsePublicFinding", true, 9),
          new TransitionLayout(10, "RegisterBallotAttempt", true, 10),
          new TransitionLayout(11, "CloseBallotRegistration", true, 11),
          new TransitionLayout(12, "FreezeBallotSurvivors", true, 12),
          new TransitionLayout(13, "FreezeTimedOvnCorpus", true, 13),
          new TransitionLayout(14, "BeginBallotOpeningBatch", true, 14),
          new TransitionLayout(15, "FailBallotNoResult", true, 15),
          new TransitionLayout(16, "FinalizeOpenedBallot", true, 16),
          new TransitionLayout(17, "RecordInvitationResponse", true, 20),
          new TransitionLayout(18, "RegisterBallotParticipant", true, 21),
          new TransitionLayout(19, "RecordBallotDropout", true, 22),
          new TransitionLayout(20, "FailPublicFindingNoResult", true, 23),
          new TransitionLayout(21, "RegisterInitialSortition", false, 24));

  public static final List<AutomaticOutcomeLayout> AUTOMATIC_EXECUTION_OUTCOMES =
      listOf(
          new AutomaticOutcomeLayout(0, "Enacted", false, "MarkEnacted", 17),
          new AutomaticOutcomeLayout(1, "Superseded", true, "MarkSuperseded", 18),
          new AutomaticOutcomeLayout(
              2, "ExecutionFailed", true, "MarkExecutionFailed", 19));

  public static final List<NoResultKindLayout> NO_RESULT_KINDS =
      listOf(
          new NoResultKindLayout(0, "PublicFindingQuorumUnreachable"),
          new NoResultKindLayout(1, "PublicFindingDeadlineExpired"),
          new NoResultKindLayout(2, "BallotRegistrationDeadlineExpired"),
          new NoResultKindLayout(3, "BallotSurvivorDeadlineExpired"),
          new NoResultKindLayout(4, "BallotCommitmentDeadlineExpired"),
          new NoResultKindLayout(5, "BallotReleasePulseUnavailable"),
          new NoResultKindLayout(6, "BallotOpeningDeadlineExpired"),
          new NoResultKindLayout(7, "SortitionRetriesExhausted"),
          new NoResultKindLayout(8, "ConfirmationJuryCapacityUnavailable"),
          new NoResultKindLayout(9, "RandomnessRedrawBudgetExhausted"));

  public static final Map<String, String> CERTIFICATE_RESULT_ROOT_DOMAINS =
      certificateResultRootDomains();
  public static final List<String> CERTIFICATE_BODY_BINDING_NORITO_FIELDS =
      listOf(
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
          "ballot");
  public static final List<String> PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS =
      listOf("endorsement_root", "endorsing_assignments", "endorsements", "quorum");
  public static final List<String> BODY_STATE_FIELDS =
      listOf(
          "body",
          "body_instance_id",
          "status",
          "public_finding_opened_at_height",
          "public_finding_phase_blocks",
          "public_finding_deadline_height",
          "no_result_kind",
          "no_result_height",
          "timed_ovn_progress");
  /** Canonical presentation order for first-release Parliament bodies. */
  public static final List<String> CANONICAL_BODY_ORDER =
      listOf(
          "rules-committee",
          "agenda-council",
          "interest-panel",
          "review-panel",
          "coordination-council",
          "mpc-committee",
          "fma-committee",
          "oversight-committee",
          "policy-jury",
          "confirmation-jury");

  private static final Pattern ID = Pattern.compile("[0-9a-f]{64}");
  private static final Map<String, TransitionLayout> PUBLIC_TRANSITIONS_BY_TAG =
      publicTransitionsByTag();
  private static final Set<String> ATTEMPT_RESPONSE_FIELDS =
      setOf("version", "proposal_content_id", "governance_attempt_id", "tx_instructions");
  private static final Set<String> TRANSITION_RESPONSE_FIELDS =
      setOf(
          "version",
          "governance_attempt_id",
          "transition_kind",
          "transition_digest",
          "tx_instructions");
  private static final Set<String> READ_RESPONSE_FIELDS =
      setOf(
          "version",
          "current_height",
          "attempt",
          "policy_version",
          "required_bodies",
          "body_states",
          "certificate",
          "terminal_height",
          "superseding_head",
          "execution_failure_root",
          "state_payload_hex");
  private static final Set<String> TLE_RELEASE_CONTEXT_FIELDS =
      setOf(
          "version",
          "current_height",
          "ballot_attempt_id",
          "governance_attempt_id",
          "body_instance_id",
          "status",
          "release_height",
          "opening_deadline_height",
          "tle_key_session",
          "release_identity",
          "identity_digest",
          "identity_payload_hex");
  private static final Set<String> TIMED_OVN_CASTING_CONTEXT_FIELDS =
      setOf(
          "version",
          "current_height",
          "phase",
          "session",
          "registration_opened_at_finalized_height",
          "target_finalized_height",
          "tle_key_session",
          "registration_records_hex",
          "survivor_participant_hashes",
          "release_identity",
          "archive_norito_base64");
  private static final Set<String> TIMED_OVN_SESSION_FIELDS =
      setOf(
          "network_id",
          "proposal_content_id",
          "governance_attempt_id",
          "body_instance_id",
          "ballot_attempt_id",
          "parameter_hash",
          "tle_key_session_id",
          "tle_key_transcript_hash",
          "tle_master_public_key");
  private static final Set<String> TLE_KEY_SESSION_FIELDS =
      setOf(
          "version",
          "key_session_id",
          "network_id",
          "roster_hash",
          "committee_size",
          "threshold",
          "generator_h",
          "generator_v",
          "qualified_dealers",
          "qualified_dealer_commitments",
          "dkg_event_hash",
          "group_public_key",
          "public_shares",
          "transcript_hash");
  private static final Set<String> TLE_DEALER_FIELDS =
      setOf(
          "dealer_index",
          "coefficient_commitments",
          "constant_pok_commitment",
          "constant_pok_response");
  private static final Set<String> TLE_PUBLIC_SHARE_FIELDS =
      setOf("index", "participant_hash", "public_key_share");
  private static final Set<String> TLE_RELEASE_IDENTITY_FIELDS =
      setOf(
          "tle_key_session_id",
          "governance_attempt_id",
          "body_instance_id",
          "ballot_attempt_id",
          "survivor_corpus_root",
          "no_recovery_root",
          "target_finalized_height",
          "parameter_hash");
  private static final Set<String> TLE_PARTIAL_RELEASE_FIELDS =
      setOf(
          "key_session_id",
          "identity_digest",
          "participant_index",
          "sigma",
          "proof_x",
          "proof_y",
          "z_s",
          "z_r",
          "z_u");
  private static final Set<String> ATTEMPT_FIELDS =
      setOf("id", "proposal_content_id", "sequence", "risk_tier", "stage", "status");
  private static final Set<String> BODIES = new LinkedHashSet<>(CANONICAL_BODY_ORDER);
  private static final Set<String> PRIVATE_BODIES =
      setOf("policy-jury", "confirmation-jury");
  private static final Set<String> BODY_STATUSES =
      setOf(
          "AwaitingSortition",
          "AcceptingInvitations",
          "RosterSealed",
          "Deliberating",
          "Balloting",
          "Approved",
          "Rejected",
          "NoQuorum",
          "NoResult",
          "Superseded");
  private static final Set<String> TIMED_OVN_PROGRESS_FIELDS =
      setOf(
          "ballot_attempt_id",
          "status",
          "frozen_survivor_count",
          "accepted_ballot_prefix_count");
  private static final Set<String> TIMED_OVN_BALLOT_STATUSES =
      setOf(
          "Registration",
          "SurvivorFreeze",
          "TimedCommitment",
          "AwaitingRelease",
          "Opening",
          "Finalized",
          "NoResult",
          "Superseded");
  private static final Set<String> DELIBERATION_PHASES =
      setOf(
          "Orientation", "Evidence", "Questions", "Responses", "Deliberation", "Reflection", "Vote");
  private static final Set<String> PUBLIC_NO_RESULT_KINDS =
      setOf("PublicFindingQuorumUnreachable", "PublicFindingDeadlineExpired");
  private static final Set<String> NO_RESULT_TAGS = noResultTags();

  private ParliamentApiV1() {}

  /** Stable Norito/JSON/event mapping for one public lifecycle transition. */
  public static final class TransitionLayout {
    public final int noritoIndex;
    public final String jsonTag;
    public final boolean jsonPayloadRequired;
    public final int eventKindIndex;

    private TransitionLayout(
        final int noritoIndex,
        final String jsonTag,
        final boolean jsonPayloadRequired,
        final int eventKindIndex) {
      this.noritoIndex = noritoIndex;
      this.jsonTag = jsonTag;
      this.jsonPayloadRequired = jsonPayloadRequired;
      this.eventKindIndex = eventKindIndex;
    }
  }

  /** Stable Norito/JSON/event mapping for one consensus-owned execution outcome. */
  public static final class AutomaticOutcomeLayout {
    public final int noritoIndex;
    public final String jsonTag;
    public final boolean jsonPayloadRequired;
    public final String eventKind;
    public final int eventKindIndex;

    private AutomaticOutcomeLayout(
        final int noritoIndex,
        final String jsonTag,
        final boolean jsonPayloadRequired,
        final String eventKind,
        final int eventKindIndex) {
      this.noritoIndex = noritoIndex;
      this.jsonTag = jsonTag;
      this.jsonPayloadRequired = jsonPayloadRequired;
      this.eventKind = eventKind;
      this.eventKindIndex = eventKindIndex;
    }
  }

  /** Stable Norito/JSON mapping for one closed Parliament no-result class. */
  public static final class NoResultKindLayout {
    public final int noritoIndex;
    public final String jsonTag;

    private NoResultKindLayout(final int noritoIndex, final String jsonTag) {
      this.noritoIndex = noritoIndex;
      this.jsonTag = jsonTag;
    }
  }

  /** One canonical native instruction returned by a Parliament draft route. */
  public static final class InstructionDraft {
    public final String wireId;
    public final String payloadHex;

    private InstructionDraft(final String wireId, final String payloadHex) {
      this.wireId = wireId;
      this.payloadHex = payloadHex;
    }
  }

  /** Strict response from the attempt-draft route. */
  public static final class AttemptDraftResponse {
    public final String proposalContentId;
    public final String governanceAttemptId;
    public final InstructionDraft instruction;

    private AttemptDraftResponse(
        final String proposalContentId,
        final String governanceAttemptId,
        final InstructionDraft instruction) {
      this.proposalContentId = proposalContentId;
      this.governanceAttemptId = governanceAttemptId;
      this.instruction = instruction;
    }
  }

  /** Strict response from the transition-draft route. */
  public static final class TransitionDraftResponse {
    public final String governanceAttemptId;
    public final String transitionKind;
    public final byte[] transitionDigest;
    public final InstructionDraft instruction;

    private TransitionDraftResponse(
        final String governanceAttemptId,
        final String transitionKind,
        final byte[] transitionDigest,
        final InstructionDraft instruction) {
      this.governanceAttemptId = governanceAttemptId;
      this.transitionKind = transitionKind;
      this.transitionDigest = transitionDigest.clone();
      this.instruction = instruction;
    }
  }

  /** Bounded outer projection from the authenticated attempt-read route. */
  public static final class AttemptReadResponse {
    public final String governanceAttemptId;
    public final String currentHeight;
    public final String statePayloadHex;
    /** Canonical ordered body names admitted from {@code required_bodies}. */
    public final List<String> requiredBodyOrder;
    public final List<BodyStateProjection> bodyStates;
    /** Canonical ordered body names carried by the certificate, or empty when absent. */
    public final List<String> certificateBodyOrder;
    public final List<PublicFindingCertificateBinding> publicFindingBindings;
    public final Map<String, Object> raw;

    private AttemptReadResponse(
        final String governanceAttemptId,
        final String currentHeight,
        final String statePayloadHex,
        final List<String> requiredBodyOrder,
        final List<BodyStateProjection> bodyStates,
        final List<String> certificateBodyOrder,
        final List<PublicFindingCertificateBinding> publicFindingBindings,
        final Map<String, Object> raw) {
      this.governanceAttemptId = governanceAttemptId;
      this.currentHeight = currentHeight;
      this.statePayloadHex = statePayloadHex;
      this.requiredBodyOrder = List.copyOf(requiredBodyOrder);
      this.bodyStates = List.copyOf(bodyStates);
      this.certificateBodyOrder = List.copyOf(certificateBodyOrder);
      this.publicFindingBindings = List.copyOf(publicFindingBindings);
      this.raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }
  }

  /** Safe lifecycle/deadline projection that excludes private ballot material. */
  public static final class BodyStateProjection {
    public final String body;
    public final String bodyInstanceId;
    public final String status;
    public final String deliberationPhase;
    public final String publicFindingOpenedAtHeight;
    public final String publicFindingPhaseBlocks;
    public final String publicFindingDeadlineHeight;
    public final String noResultKind;
    public final String noResultHeight;
    public final TimedOvnProgressProjection timedOvnProgress;

    private BodyStateProjection(
        final String body,
        final String bodyInstanceId,
        final String status,
        final String deliberationPhase,
        final String publicFindingOpenedAtHeight,
        final String publicFindingPhaseBlocks,
        final String publicFindingDeadlineHeight,
        final String noResultKind,
        final String noResultHeight,
        final TimedOvnProgressProjection timedOvnProgress) {
      this.body = body;
      this.bodyInstanceId = bodyInstanceId;
      this.status = status;
      this.deliberationPhase = deliberationPhase;
      this.publicFindingOpenedAtHeight = publicFindingOpenedAtHeight;
      this.publicFindingPhaseBlocks = publicFindingPhaseBlocks;
      this.publicFindingDeadlineHeight = publicFindingDeadlineHeight;
      this.noResultKind = noResultKind;
      this.noResultHeight = noResultHeight;
      this.timedOvnProgress = timedOvnProgress;
    }
  }

  /** Aggregate-only active-ballot state and next contiguous corpus offset. */
  public static final class TimedOvnProgressProjection {
    public final String ballotAttemptId;
    public final String status;
    public final Integer frozenSurvivorCount;
    public final Integer acceptedBallotPrefixCount;

    private TimedOvnProgressProjection(
        final String ballotAttemptId,
        final String status,
        final Integer frozenSurvivorCount,
        final Integer acceptedBallotPrefixCount) {
      this.ballotAttemptId = ballotAttemptId;
      this.status = status;
      this.frozenSurvivorCount = frozenSurvivorCount;
      this.acceptedBallotPrefixCount = acceptedBallotPrefixCount;
    }
  }

  /** Exact canonical supporter list included in a public-finding certificate. */
  public static final class PublicFindingCertificateBinding {
    public final byte[] endorsementRoot;
    public final List<String> endorsingAssignments;
    public final int endorsements;
    public final int quorum;

    private PublicFindingCertificateBinding(
        final byte[] endorsementRoot,
        final List<String> endorsingAssignments,
        final int endorsements,
        final int quorum) {
      this.endorsementRoot = endorsementRoot.clone();
      this.endorsingAssignments = List.copyOf(endorsingAssignments);
      this.endorsements = endorsements;
      this.quorum = quorum;
    }
  }

  /** Proof-carrying public broadcast for one qualified adaptive TLE dealer. */
  public static final class TleAdaptiveDealerCommitment {
    public final int dealerIndex;
    public final List<byte[]> coefficientCommitments;
    public final byte[] constantPokCommitment;
    public final byte[] constantPokResponse;

    private TleAdaptiveDealerCommitment(
        final int dealerIndex,
        final List<byte[]> coefficientCommitments,
        final byte[] constantPokCommitment,
        final byte[] constantPokResponse) {
      this.dealerIndex = dealerIndex;
      final List<byte[]> copied = new ArrayList<>(coefficientCommitments.size());
      for (final byte[] commitment : coefficientCommitments) copied.add(commitment.clone());
      this.coefficientCommitments = Collections.unmodifiableList(copied);
      this.constantPokCommitment = constantPokCommitment.clone();
      this.constantPokResponse = constantPokResponse.clone();
    }
  }

  /** Public composite verification share for one threshold participant. */
  public static final class TleAdaptivePublicShare {
    public final int index;
    public final byte[] participantHash;
    public final byte[] publicKeyShare;

    private TleAdaptivePublicShare(
        final int index, final byte[] participantHash, final byte[] publicKeyShare) {
      this.index = index;
      this.participantHash = participantHash.clone();
      this.publicKeyShare = publicKeyShare.clone();
    }
  }

  /** Complete bounded public transcript required to verify adaptive partial releases. */
  public static final class TleKeySessionPublicState {
    public final String keySessionId;
    public final byte[] networkId;
    public final byte[] rosterHash;
    public final int committeeSize;
    public final int threshold;
    public final byte[] generatorH;
    public final byte[] generatorV;
    public final List<Integer> qualifiedDealers;
    public final List<TleAdaptiveDealerCommitment> qualifiedDealerCommitments;
    public final byte[] dkgEventHash;
    public final byte[] groupPublicKey;
    public final List<TleAdaptivePublicShare> publicShares;
    public final byte[] transcriptHash;

    private TleKeySessionPublicState(
        final String keySessionId,
        final byte[] networkId,
        final byte[] rosterHash,
        final int committeeSize,
        final int threshold,
        final byte[] generatorH,
        final byte[] generatorV,
        final List<Integer> qualifiedDealers,
        final List<TleAdaptiveDealerCommitment> qualifiedDealerCommitments,
        final byte[] dkgEventHash,
        final byte[] groupPublicKey,
        final List<TleAdaptivePublicShare> publicShares,
        final byte[] transcriptHash) {
      this.keySessionId = keySessionId;
      this.networkId = networkId.clone();
      this.rosterHash = rosterHash.clone();
      this.committeeSize = committeeSize;
      this.threshold = threshold;
      this.generatorH = generatorH.clone();
      this.generatorV = generatorV.clone();
      this.qualifiedDealers = List.copyOf(qualifiedDealers);
      this.qualifiedDealerCommitments = List.copyOf(qualifiedDealerCommitments);
      this.dkgEventHash = dkgEventHash.clone();
      this.groupPublicKey = groupPublicKey.clone();
      this.publicShares = List.copyOf(publicShares);
      this.transcriptHash = transcriptHash.clone();
    }
  }

  /** Exact frozen public timed-OVN future release identity. */
  public static final class TimedOvnReleaseIdentityProjection {
    public final String tleKeySessionId;
    public final String governanceAttemptId;
    public final String bodyInstanceId;
    public final String ballotAttemptId;
    public final byte[] survivorCorpusRoot;
    public final byte[] noRecoveryRoot;
    public final String targetFinalizedHeight;
    public final byte[] parameterHash;

    private TimedOvnReleaseIdentityProjection(
        final String tleKeySessionId,
        final String governanceAttemptId,
        final String bodyInstanceId,
        final String ballotAttemptId,
        final byte[] survivorCorpusRoot,
        final byte[] noRecoveryRoot,
        final String targetFinalizedHeight,
        final byte[] parameterHash) {
      this.tleKeySessionId = tleKeySessionId;
      this.governanceAttemptId = governanceAttemptId;
      this.bodyInstanceId = bodyInstanceId;
      this.ballotAttemptId = ballotAttemptId;
      this.survivorCorpusRoot = survivorCorpusRoot.clone();
      this.noRecoveryRoot = noRecoveryRoot.clone();
      this.targetFinalizedHeight = targetFinalizedHeight;
      this.parameterHash = parameterHash.clone();
    }
  }

  /** Exact cast-capable public timed-OVN phase. */
  public enum TimedOvnCastingPhase {
    Registered,
    RegistrationClosed,
    SurvivorsFrozen
  }

  /** Immutable public timed-OVN wallet-session bindings. */
  public static final class TimedOvnSessionProjection {
    public final byte[] networkId;
    public final String proposalContentId;
    public final String governanceAttemptId;
    public final String bodyInstanceId;
    public final String ballotAttemptId;
    public final byte[] parameterHash;
    public final String tleKeySessionId;
    public final byte[] tleKeyTranscriptHash;
    public final byte[] tleMasterPublicKey;

    private TimedOvnSessionProjection(
        final byte[] networkId,
        final String proposalContentId,
        final String governanceAttemptId,
        final String bodyInstanceId,
        final String ballotAttemptId,
        final byte[] parameterHash,
        final String tleKeySessionId,
        final byte[] tleKeyTranscriptHash,
        final byte[] tleMasterPublicKey) {
      this.networkId = networkId.clone();
      this.proposalContentId = proposalContentId;
      this.governanceAttemptId = governanceAttemptId;
      this.bodyInstanceId = bodyInstanceId;
      this.ballotAttemptId = ballotAttemptId;
      this.parameterHash = parameterHash.clone();
      this.tleKeySessionId = tleKeySessionId;
      this.tleKeyTranscriptHash = tleKeyTranscriptHash.clone();
      this.tleMasterPublicKey = tleMasterPublicKey.clone();
    }
  }

  /** Replay-validated public context consumed by a secret-local native wallet bridge. */
  public static final class TimedOvnCastingContextResponse {
    public final String currentHeight;
    public final TimedOvnCastingPhase phase;
    public final TimedOvnSessionProjection session;
    public final String registrationOpenedAtFinalizedHeight;
    public final String targetFinalizedHeight;
    public final TleKeySessionPublicState keySession;
    public final List<String> registrationRecordsHex;
    public final List<byte[]> survivorParticipantHashes;
    public final TimedOvnReleaseIdentityProjection releaseIdentity;
    public final byte[] archiveNorito;

    private TimedOvnCastingContextResponse(
        final String currentHeight,
        final TimedOvnCastingPhase phase,
        final TimedOvnSessionProjection session,
        final String registrationOpenedAtFinalizedHeight,
        final String targetFinalizedHeight,
        final TleKeySessionPublicState keySession,
        final List<String> registrationRecordsHex,
        final List<byte[]> survivorParticipantHashes,
        final TimedOvnReleaseIdentityProjection releaseIdentity,
        final byte[] archiveNorito) {
      this.currentHeight = currentHeight;
      this.phase = phase;
      this.session = session;
      this.registrationOpenedAtFinalizedHeight = registrationOpenedAtFinalizedHeight;
      this.targetFinalizedHeight = targetFinalizedHeight;
      this.keySession = keySession;
      this.registrationRecordsHex = List.copyOf(registrationRecordsHex);
      if (survivorParticipantHashes == null) {
        this.survivorParticipantHashes = null;
      } else {
        final List<byte[]> copied = new ArrayList<>(survivorParticipantHashes.size());
        for (final byte[] hash : survivorParticipantHashes) copied.add(hash.clone());
        this.survivorParticipantHashes = Collections.unmodifiableList(copied);
      }
      this.releaseIdentity = releaseIdentity;
      this.archiveNorito = archiveNorito.clone();
    }
  }

  /** Canonical bounded checkpoint request for the Parliament timed-OVN casting proof route. */
  public static final class TimedOvnCastingProofRequest {
    public final BigInteger trustedCheckpointHeight;

    public TimedOvnCastingProofRequest(final BigInteger trustedCheckpointHeight) {
      this.trustedCheckpointHeight =
          requireTimedOvnCastingCheckpointHeight(trustedCheckpointHeight);
    }

    public TimedOvnCastingProofRequest(final long trustedCheckpointHeight) {
      this(BigInteger.valueOf(trustedCheckpointHeight));
    }

    /** Encodes the exact uncompressed, zero-padding Norito request frame. */
    public byte[] toNoritoBytes() {
      return timedOvnCastingProofRequestNorito(trustedCheckpointHeight);
    }
  }

  /** Core-authorized release context available only during the inclusive Opening window. */
  public static final class TleReleaseContextResponse {
    public final String currentHeight;
    public final String ballotAttemptId;
    public final String governanceAttemptId;
    public final String bodyInstanceId;
    public final String releaseHeight;
    public final String openingDeadlineHeight;
    public final TleKeySessionPublicState keySession;
    public final TimedOvnReleaseIdentityProjection releaseIdentity;
    public final byte[] identityDigest;
    public final String identityPayloadHex;

    private TleReleaseContextResponse(
        final String currentHeight,
        final String ballotAttemptId,
        final String governanceAttemptId,
        final String bodyInstanceId,
        final String releaseHeight,
        final String openingDeadlineHeight,
        final TleKeySessionPublicState keySession,
        final TimedOvnReleaseIdentityProjection releaseIdentity,
        final byte[] identityDigest,
        final String identityPayloadHex) {
      this.currentHeight = currentHeight;
      this.ballotAttemptId = ballotAttemptId;
      this.governanceAttemptId = governanceAttemptId;
      this.bodyInstanceId = bodyInstanceId;
      this.releaseHeight = releaseHeight;
      this.openingDeadlineHeight = openingDeadlineHeight;
      this.keySession = keySession;
      this.releaseIdentity = releaseIdentity;
      this.identityDigest = identityDigest.clone();
      this.identityPayloadHex = identityPayloadHex;
    }
  }

  /** One independently verifiable public adaptive partial release. */
  public static final class TlePartialReleaseShare {
    public final String keySessionId;
    public final byte[] identityDigest;
    public final int participantIndex;
    public final byte[] sigma;
    public final byte[] proofX;
    public final byte[] proofY;
    public final byte[] zS;
    public final byte[] zR;
    public final byte[] zU;

    private TlePartialReleaseShare(
        final String keySessionId,
        final byte[] identityDigest,
        final int participantIndex,
        final byte[] sigma,
        final byte[] proofX,
        final byte[] proofY,
        final byte[] zS,
        final byte[] zR,
        final byte[] zU) {
      this.keySessionId = keySessionId;
      this.identityDigest = identityDigest.clone();
      this.participantIndex = participantIndex;
      this.sigma = sigma.clone();
      this.proofX = proofX.clone();
      this.proofY = proofY.clone();
      this.zS = zS.clone();
      this.zR = zR.clone();
      this.zU = zU.clone();
    }
  }

  /** Replace the sole attempt-id path parameter after exact lowercase validation. */
  public static String attemptReadPath(final String governanceAttemptId) {
    return ATTEMPT_READ_PATH.replace(
        "{governance_attempt_id}", canonicalId(governanceAttemptId));
  }

  /** Replaces the casting-context ballot parameter after exact lowercase validation. */
  public static String timedOvnCastingContextReadPath(final String ballotAttemptId) {
    return TIMED_OVN_CASTING_CONTEXT_READ_PATH.replace(
        "{ballot_attempt_id}", canonicalId(ballotAttemptId));
  }

  /** Replaces the proof ballot parameter after exact lowercase validation. */
  public static String timedOvnCastingProofPath(final String ballotAttemptId) {
    return TIMED_OVN_CASTING_PROOF_PATH.replace(
        "{ballot_attempt_id}", canonicalId(ballotAttemptId));
  }

  /** Encodes one positive u64 checkpoint height as the canonical zero-padding request frame. */
  public static byte[] timedOvnCastingProofRequestNorito(
      final BigInteger trustedCheckpointHeight) {
    final BigInteger height =
        requireTimedOvnCastingCheckpointHeight(trustedCheckpointHeight);
    final byte[] payload = new byte[12];
    // Compact-Norito struct field count, version field, then aligned u64 field.
    payload[0] = 2;
    payload[1] = (byte) TIMED_OVN_CASTING_PROOF_REQUEST_VERSION;
    payload[2] = 0;
    payload[3] = (byte) TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT;
    for (int index = 0; index < 8; index++) {
      payload[4 + index] = height.shiftRight(index * 8).byteValue();
    }
    final NoritoHeader header =
        new NoritoHeader(
            decodeHex(TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX),
            payload.length,
            CRC64.compute(payload),
            TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS,
            NoritoHeader.COMPRESSION_NONE);
    final byte[] encodedHeader = header.encode();
    final byte[] frame = Arrays.copyOf(encodedHeader, encodedHeader.length + payload.length);
    System.arraycopy(payload, 0, frame, encodedHeader.length, payload.length);
    if (frame.length != TIMED_OVN_CASTING_PROOF_REQUEST_BYTES) {
      throw new IllegalStateException("canonical casting-proof request frame width changed");
    }
    return frame;
  }

  /** Convenience overload for positive signed heights. */
  public static byte[] timedOvnCastingProofRequestNorito(
      final long trustedCheckpointHeight) {
    return timedOvnCastingProofRequestNorito(BigInteger.valueOf(trustedCheckpointHeight));
  }


  static BigInteger requireTimedOvnCastingCheckpointHeight(final BigInteger value) {
    if (value == null || value.signum() <= 0 || value.bitLength() > 64) {
      throw new IllegalArgumentException(
          "trustedCheckpointHeight must be a positive u64");
    }
    return value;
  }

  /** Replace the release-context ballot parameter after exact lowercase validation. */
  public static String tleReleaseContextReadPath(final String ballotAttemptId) {
    return TLE_RELEASE_CONTEXT_READ_PATH.replace(
        "{ballot_attempt_id}", canonicalId(ballotAttemptId));
  }

  /** Replace the local partial-release ballot parameter after exact lowercase validation. */
  public static String tlePartialReleasePath(final String ballotAttemptId) {
    return TLE_PARTIAL_RELEASE_PATH.replace(
        "{ballot_attempt_id}", canonicalId(ballotAttemptId));
  }


  /** Build the exact V1 lifecycle-transition draft JSON envelope. */
  public static byte[] transitionDraftRequestJson(
      final String governanceAttemptId, final byte[] transitionJson) {
    final Map<String, Object> transition =
        taggedObject(transitionJson, "transition", "payload", "transition", true);
    final TransitionLayout layout =
        PUBLIC_TRANSITIONS_BY_TAG.get((String) transition.get("transition"));
    if (layout == null) {
      throw new IllegalArgumentException(
          "unknown or consensus-owned Parliament transition");
    }
    if (transition.containsKey("payload") != layout.jsonPayloadRequired) {
      throw new IllegalArgumentException(
          layout.jsonPayloadRequired
              ? "Parliament transition payload is required"
              : "unit Parliament transition must not carry a payload");
    }
    if (layout.jsonPayloadRequired) {
      validateTransitionPayload(
          layout.jsonTag, objectValue(transition.get("payload"), layout.jsonTag + " payload"));
    }
    final Map<String, Object> request = new LinkedHashMap<>();
    request.put("version", VERSION);
    request.put("governance_attempt_id", canonicalId(governanceAttemptId));
    request.put("transition", transition);
    return encode(request);
  }

  private static void validateTransitionPayload(
      final String tag, final Map<String, Object> payload) {
    if (!tag.equals("FreezeTimedOvnCorpus")) return;
    if (!payload.keySet().equals(setOf("ballot_attempt_id", "ballot_records"))) {
      throw new IllegalArgumentException(
          tag + " payload contains unknown, aliased, or missing fields");
    }
    if (!(payload.get("ballot_attempt_id") instanceof String ballotAttemptId)) {
      throw new IllegalArgumentException(tag + ".ballot_attempt_id must be text");
    }
    canonicalId(ballotAttemptId);
    if (!(payload.get("ballot_records") instanceof List<?> records)) {
      throw new IllegalArgumentException(tag + ".ballot_records must be an array");
    }
    if (records.isEmpty() || records.size() > TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS) {
      throw new IllegalArgumentException(
          tag
              + ".ballot_records must contain one through "
              + TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS
              + " records");
    }
    for (int index = 0; index < records.size(); index++) {
      fixedBytes(
          records.get(index),
          TIMED_OVN_BALLOT_RECORD_BYTES,
          tag + ".ballot_records[" + index + "]",
          false);
    }
  }

  /** Strictly admit an attempt draft bound to caller-derived identifiers. */
  public static AttemptDraftResponse parseAttemptDraftResponse(
      final byte[] bytes,
      final String expectedProposalContentId,
      final String expectedGovernanceAttemptId) {
    final Map<String, Object> root =
        exactRoot(bytes, ATTEMPT_RESPONSE_FIELDS, "Parliament attempt draft");
    version(root);
    final String proposalId = id(root, "proposal_content_id");
    final String attemptId = id(root, "governance_attempt_id");
    if (!proposalId.equals(canonicalId(expectedProposalContentId))) {
      throw new IllegalArgumentException("proposal_content_id differs from the exact request");
    }
    if (!attemptId.equals(canonicalId(expectedGovernanceAttemptId))) {
      throw new IllegalArgumentException("governance_attempt_id differs from the exact request");
    }
    return new AttemptDraftResponse(
        proposalId, attemptId, instruction(root, ATTEMPT_CREATE_WIRE_ID));
  }

  /** Strictly admit a transition draft bound to all caller-derived commitments. */
  public static TransitionDraftResponse parseTransitionDraftResponse(
      final byte[] bytes,
      final String expectedGovernanceAttemptId,
      final String expectedTransitionKind,
      final byte[] expectedTransitionDigest) {
    if (!PUBLIC_TRANSITIONS_BY_TAG.containsKey(expectedTransitionKind)) {
      throw new IllegalArgumentException(
          "expected transition kind is unknown or consensus-owned");
    }
    if (expectedTransitionDigest == null
        || expectedTransitionDigest.length != 32
        || allZero(expectedTransitionDigest)) {
      throw new IllegalArgumentException(
          "expected transition digest must be nonzero and 32 bytes");
    }
    final Map<String, Object> root =
        exactRoot(bytes, TRANSITION_RESPONSE_FIELDS, "Parliament transition draft");
    version(root);
    final String attemptId = id(root, "governance_attempt_id");
    if (!attemptId.equals(canonicalId(expectedGovernanceAttemptId))) {
      throw new IllegalArgumentException("governance_attempt_id differs from the exact request");
    }
    final String kind = taggedUnit(root.get("transition_kind"), "kind", "transition_kind");
    if (!PUBLIC_TRANSITIONS_BY_TAG.containsKey(kind)) {
      throw new IllegalArgumentException("transition_kind is unknown or consensus-owned");
    }
    if (!kind.equals(expectedTransitionKind)) {
      throw new IllegalArgumentException("transition_kind differs from the exact request");
    }
    final byte[] digest = byteArray32(root.get("transition_digest"), "transition_digest");
    if (!Arrays.equals(digest, expectedTransitionDigest)) {
      throw new IllegalArgumentException("transition_digest differs from the exact request");
    }
    return new TransitionDraftResponse(
        attemptId, kind, digest, instruction(root, TRANSITION_SUBMIT_WIRE_ID));
  }

  /** Strictly admit the bounded outer read envelope and exact attempt id. */
  public static AttemptReadResponse parseAttemptReadResponse(
      final byte[] bytes, final String expectedGovernanceAttemptId) {
    final Map<String, Object> root =
        exactRoot(bytes, READ_RESPONSE_FIELDS, "Parliament attempt read");
    version(root);
    final Map<String, Object> attempt = exactObject(root.get("attempt"), ATTEMPT_FIELDS, "attempt");
    final String attemptId = id(attempt, "id");
    if (!attemptId.equals(canonicalId(expectedGovernanceAttemptId))) {
      throw new IllegalArgumentException("attempt.id differs from the requested canonical id");
    }
    final String proposalContentId = id(attempt, "proposal_content_id");
    final String attemptSequence = u32(attempt.get("sequence"), "attempt.sequence");
    if (new BigInteger(attemptSequence).compareTo(BigInteger.valueOf(MAX_GOVERNANCE_ATTEMPT_RETRIES))
        > 0) {
      throw new IllegalArgumentException(
          "attempt.sequence exceeds the first-release retry ceiling");
    }
    final String riskTier = taggedUnitIn(
        attempt.get("risk_tier"),
        "tier",
        setOf("Routine", "Standard", "Constitutional", "Emergency"),
        "attempt.risk_tier");
    taggedUnitIn(
        attempt.get("stage"),
        "stage",
        setOf(
            "Qualification",
            "Rules",
            "Agenda",
            "Interest",
            "Review",
            "Coordination",
            "Mpc",
            "Fma",
            "Oversight",
            "PolicyJury",
            "ConfirmationJury",
            "Certification",
            "Enactment"),
        "attempt.stage");
    taggedUnitIn(
        attempt.get("status"),
        "status",
        setOf("Active", "Certified", "Rejected", "Enacted", "Superseded", "ExecutionFailed"),
        "attempt.status");
    final String height = unsignedInteger(root.get("current_height"), "current_height");
    final String policyVersion = unsignedInteger(root.get("policy_version"), "policy_version");
    if (!policyVersion.equals(Integer.toString(GOVERNANCE_POLICY_VERSION))) {
      throw new IllegalArgumentException(
          "policy_version must equal the first-release Parliament policy version");
    }
    optionalUnsignedInteger(root.get("terminal_height"), "terminal_height");
    optionalByteArray32(root.get("execution_failure_root"), "execution_failure_root");
    final List<String> requiredBodies = validateRequiredBodies(root.get("required_bodies"));
    final List<BodyStateProjection> bodyStates =
        validateBodyStates(root.get("body_states"), requiredBodies);
    final List<PublicFindingCertificateBinding> publicFindings =
        validateCertificate(
            root.get("certificate"),
            attemptId,
            proposalContentId,
            attemptSequence,
            riskTier,
            policyVersion,
            requiredBodies,
            bodyStates);
    final List<String> certificateBodyOrder =
        root.get("certificate") == null ? List.of() : List.copyOf(requiredBodies);
    final String stateHex = canonicalHex(root.get("state_payload_hex"), "state_payload_hex", false);
    if (stateHex.length() / 2 > MAX_STATE_BYTES) {
      throw new IllegalArgumentException("state_payload_hex exceeds its bound");
    }
    validateStateFrame(decodeHex(stateHex));
    return new AttemptReadResponse(
        attemptId,
        height,
        stateHex,
        requiredBodies,
        bodyStates,
        certificateBodyOrder,
        publicFindings,
        root);
  }

  /** Strictly admit one replay-validated public timed-OVN wallet context. */
  @SuppressWarnings("unchecked")
  public static TimedOvnCastingContextResponse parseTimedOvnCastingContextResponse(
      final byte[] bytes, final String expectedBallotAttemptId) {
    final Map<String, Object> root =
        exactRoot(
            bytes,
            TIMED_OVN_CASTING_CONTEXT_FIELDS,
            "Parliament timed-OVN casting context");
    version(root);
    final String currentHeight = unsignedInteger(root.get("current_height"), "current_height");
    if (new BigInteger(currentHeight).signum() <= 0) {
      throw new IllegalArgumentException("current_height must be nonzero");
    }
    final TimedOvnCastingPhase phase;
    try {
      phase = TimedOvnCastingPhase.valueOf((String) root.get("phase"));
    } catch (final RuntimeException error) {
      throw new IllegalArgumentException("unknown cast-capable timed-OVN phase", error);
    }
    final Map<String, Object> sessionRoot =
        exactObject(root.get("session"), TIMED_OVN_SESSION_FIELDS, "session");
    final TimedOvnSessionProjection session =
        new TimedOvnSessionProjection(
            byteArray32(sessionRoot.get("network_id"), "session.network_id"),
            id(sessionRoot, "proposal_content_id"),
            id(sessionRoot, "governance_attempt_id"),
            id(sessionRoot, "body_instance_id"),
            id(sessionRoot, "ballot_attempt_id"),
            byteArray32(sessionRoot.get("parameter_hash"), "session.parameter_hash"),
            id(sessionRoot, "tle_key_session_id"),
            byteArray32(
                sessionRoot.get("tle_key_transcript_hash"),
                "session.tle_key_transcript_hash"),
            fixedBytes(
                sessionRoot.get("tle_master_public_key"),
                96,
                "session.tle_master_public_key",
                true));
    if (!session.ballotAttemptId.equals(canonicalId(expectedBallotAttemptId))) {
      throw new IllegalArgumentException(
          "session.ballot_attempt_id differs from the requested canonical id");
    }
    final String registrationOpened =
        unsignedInteger(
            root.get("registration_opened_at_finalized_height"),
            "registration_opened_at_finalized_height");
    final String targetHeight =
        unsignedInteger(root.get("target_finalized_height"), "target_finalized_height");
    if (new BigInteger(registrationOpened).signum() <= 0
        || new BigInteger(registrationOpened).compareTo(new BigInteger(currentHeight)) > 0
        || new BigInteger(targetHeight).compareTo(new BigInteger(registrationOpened)) <= 0) {
      throw new IllegalArgumentException("casting-context height schedule is inconsistent");
    }
    final TleKeySessionPublicState keySession = parseTleKeySession(root.get("tle_key_session"));
    if (!session.tleKeySessionId.equals(keySession.keySessionId)
        || !Arrays.equals(session.tleKeyTranscriptHash, keySession.transcriptHash)
        || !Arrays.equals(session.tleMasterPublicKey, keySession.groupPublicKey)) {
      throw new IllegalArgumentException(
          "timed-OVN session differs from the complete public TLE transcript");
    }
    if (!(root.get("registration_records_hex") instanceof List<?>)) {
      throw new IllegalArgumentException("registration_records_hex must be an array");
    }
    final List<Object> recordValues = (List<Object>) root.get("registration_records_hex");
    if (recordValues.size() > MAX_TIMED_OVN_CORPUS_ENTRIES
        || (phase != TimedOvnCastingPhase.Registered && recordValues.isEmpty())) {
      throw new IllegalArgumentException("registration corpus violates its casting-phase bound");
    }
    final List<String> registrationRecords = new ArrayList<>(recordValues.size());
    final Set<String> uniqueRegistrations = new HashSet<>();
    for (int index = 0; index < recordValues.size(); index++) {
      final String record =
          canonicalHex(
              recordValues.get(index), "registration_records_hex[" + index + "]", false);
      if (record.length() != TIMED_OVN_REGISTRATION_RECORD_BYTES * 2
          || !uniqueRegistrations.add(record)) {
        throw new IllegalArgumentException(
            "registration records must have exact width and be unique");
      }
      registrationRecords.add(record);
    }

    final List<byte[]> survivorHashes;
    if (root.get("survivor_participant_hashes") == null) {
      survivorHashes = null;
    } else if (root.get("survivor_participant_hashes") instanceof List<?>) {
      survivorHashes = new ArrayList<>();
      final Set<String> uniqueSurvivors = new HashSet<>();
      final List<Object> values = (List<Object>) root.get("survivor_participant_hashes");
      for (int index = 0; index < values.size(); index++) {
        final byte[] hash =
            byteArray32(values.get(index), "survivor_participant_hashes[" + index + "]");
        if (!uniqueSurvivors.add(Arrays.toString(hash))) {
          throw new IllegalArgumentException("survivor participant hashes must be unique");
        }
        survivorHashes.add(hash);
      }
    } else {
      throw new IllegalArgumentException("survivor_participant_hashes must be null or an array");
    }
    final TimedOvnReleaseIdentityProjection releaseIdentity =
        root.get("release_identity") == null
            ? null
            : parseTimedOvnReleaseIdentity(root.get("release_identity"));
    if (phase == TimedOvnCastingPhase.SurvivorsFrozen) {
      if (survivorHashes == null
          || survivorHashes.isEmpty()
          || survivorHashes.size() > registrationRecords.size()
          || releaseIdentity == null) {
        throw new IllegalArgumentException(
            "SurvivorsFrozen requires bounded survivor hashes and release identity");
      }
      if (!releaseIdentity.tleKeySessionId.equals(session.tleKeySessionId)
          || !releaseIdentity.governanceAttemptId.equals(session.governanceAttemptId)
          || !releaseIdentity.bodyInstanceId.equals(session.bodyInstanceId)
          || !releaseIdentity.ballotAttemptId.equals(session.ballotAttemptId)
          || !releaseIdentity.targetFinalizedHeight.equals(targetHeight)
          || !Arrays.equals(releaseIdentity.parameterHash, session.parameterHash)) {
        throw new IllegalArgumentException(
            "frozen release identity differs from the timed-OVN session");
      }
    } else if (survivorHashes != null || releaseIdentity != null) {
      throw new IllegalArgumentException(
          "pre-freeze casting context must not expose frozen state");
    }
    if (!(root.get("archive_norito_base64") instanceof String)) {
      throw new IllegalArgumentException("archive_norito_base64 must be text");
    }
    final String archiveLiteral = (String) root.get("archive_norito_base64");
    final byte[] archive;
    try {
      archive = Base64.getDecoder().decode(archiveLiteral);
    } catch (final IllegalArgumentException error) {
      throw new IllegalArgumentException("archive_norito_base64 is invalid", error);
    }
    if (archive.length == 0
        || archive.length > MAX_TIMED_OVN_CASTING_ARCHIVE_BYTES
        || !Base64.getEncoder().encodeToString(archive).equals(archiveLiteral)) {
      throw new IllegalArgumentException(
          "archive_norito_base64 is oversized or noncanonical");
    }
    return new TimedOvnCastingContextResponse(
        currentHeight,
        phase,
        session,
        registrationOpened,
        targetHeight,
        keySession,
        registrationRecords,
        survivorHashes,
        releaseIdentity,
        archive);
  }

  /** Strictly admit one complete public adaptive-TLE transcript and release identity. */
  public static TleReleaseContextResponse parseTleReleaseContextResponse(
      final byte[] bytes, final String expectedBallotAttemptId) {
    final Map<String, Object> root =
        exactRoot(bytes, TLE_RELEASE_CONTEXT_FIELDS, "Parliament TLE release context");
    version(root);
    final String currentHeight = unsignedInteger(root.get("current_height"), "current_height");
    final String ballotAttemptId = id(root, "ballot_attempt_id");
    if (!ballotAttemptId.equals(canonicalId(expectedBallotAttemptId))) {
      throw new IllegalArgumentException(
          "ballot_attempt_id differs from the requested canonical id");
    }
    final String governanceAttemptId = id(root, "governance_attempt_id");
    final String bodyInstanceId = id(root, "body_instance_id");
    if (!"Opening".equals(taggedUnit(root.get("status"), "status", "status"))) {
      throw new IllegalArgumentException("release context status must be Opening");
    }
    final String releaseHeight = unsignedInteger(root.get("release_height"), "release_height");
    final String openingDeadline =
        unsignedInteger(root.get("opening_deadline_height"), "opening_deadline_height");
    if (new BigInteger(currentHeight).compareTo(new BigInteger(releaseHeight)) < 0
        || new BigInteger(currentHeight).compareTo(new BigInteger(openingDeadline)) > 0) {
      throw new IllegalArgumentException(
          "release context lies outside its inclusive opening window");
    }

    final TleKeySessionPublicState keySession = parseTleKeySession(root.get("tle_key_session"));
    final Map<String, Object> identityRoot =
        exactObject(root.get("release_identity"), TLE_RELEASE_IDENTITY_FIELDS, "release_identity");
    final TimedOvnReleaseIdentityProjection identity =
        new TimedOvnReleaseIdentityProjection(
            id(identityRoot, "tle_key_session_id"),
            id(identityRoot, "governance_attempt_id"),
            id(identityRoot, "body_instance_id"),
            id(identityRoot, "ballot_attempt_id"),
            byteArray32(
                identityRoot.get("survivor_corpus_root"),
                "release_identity.survivor_corpus_root"),
            byteArray32(
                identityRoot.get("no_recovery_root"), "release_identity.no_recovery_root"),
            unsignedInteger(
                identityRoot.get("target_finalized_height"),
                "release_identity.target_finalized_height"),
            byteArray32(identityRoot.get("parameter_hash"), "release_identity.parameter_hash"));
    if (!identity.tleKeySessionId.equals(keySession.keySessionId)
        || !identity.governanceAttemptId.equals(governanceAttemptId)
        || !identity.bodyInstanceId.equals(bodyInstanceId)
        || !identity.ballotAttemptId.equals(ballotAttemptId)
        || !identity.targetFinalizedHeight.equals(releaseHeight)) {
      throw new IllegalArgumentException(
          "release_identity differs from the top-level Parliament/TLE bindings");
    }

    final String payloadHex =
        canonicalHex(root.get("identity_payload_hex"), "identity_payload_hex", false);
    if (payloadHex.length() != 486) {
      throw new IllegalArgumentException(
          "identity_payload_hex must encode the exact 243-byte identity payload");
    }
    final byte[] payload = decodeHex(payloadHex);
    validateTleIdentityPayload(
        payload, governanceAttemptId, bodyInstanceId, ballotAttemptId, identity);
    final byte[] identityDigest = byteArray32(root.get("identity_digest"), "identity_digest");
    if (!Arrays.equals(identityDigest, tleReleaseMessageDigest(keySession, payload))) {
      throw new IllegalArgumentException(
          "identity_digest differs from the exact threshold-session-framed release message");
    }
    return new TleReleaseContextResponse(
        currentHeight,
        ballotAttemptId,
        governanceAttemptId,
        bodyInstanceId,
        releaseHeight,
        openingDeadline,
        keySession,
        identity,
        identityDigest,
        payloadHex);
  }

  /** Strictly bind one public partial release to an already admitted release context. */
  public static TlePartialReleaseShare parseTlePartialReleaseResponse(
      final byte[] bytes,
      final String expectedKeySessionId,
      final byte[] expectedIdentityDigest,
      final int committeeSize) {
    if (expectedIdentityDigest == null
        || expectedIdentityDigest.length != 32
        || allZero(expectedIdentityDigest)) {
      throw new IllegalArgumentException(
          "expectedIdentityDigest must contain 32 nonzero bytes");
    }
    if (committeeSize < 4
        || committeeSize > MAX_TLE_COMMITTEE_SIZE
        || (committeeSize - 1) % 3 != 0) {
      throw new IllegalArgumentException(
          "committeeSize must be an exact supported 3f+1 size");
    }
    final Map<String, Object> root =
        exactRoot(bytes, TLE_PARTIAL_RELEASE_FIELDS, "Parliament TLE partial release");
    final String keySessionId = id(root, "key_session_id");
    if (!keySessionId.equals(canonicalId(expectedKeySessionId))) {
      throw new IllegalArgumentException(
          "partial key_session_id differs from the authorized release context");
    }
    final byte[] identityDigest = byteArray32(root.get("identity_digest"), "identity_digest");
    if (!Arrays.equals(identityDigest, expectedIdentityDigest)) {
      throw new IllegalArgumentException(
          "partial identity_digest differs from the authorized release context");
    }
    final int participantIndex =
        u32Int(root.get("participant_index"), "participant_index", 1, committeeSize);
    return new TlePartialReleaseShare(
        keySessionId,
        identityDigest,
        participantIndex,
        fixedBytes(root.get("sigma"), 48, "sigma", true),
        fixedBytes(root.get("proof_x"), 96, "proof_x", true),
        fixedBytes(root.get("proof_y"), 48, "proof_y", true),
        fixedBytes(root.get("z_s"), 32, "z_s", false),
        fixedBytes(root.get("z_r"), 32, "z_r", false),
        fixedBytes(root.get("z_u"), 32, "z_u", false));
  }

  private static TimedOvnReleaseIdentityProjection parseTimedOvnReleaseIdentity(
      final Object value) {
    final Map<String, Object> identity =
        exactObject(value, TLE_RELEASE_IDENTITY_FIELDS, "release_identity");
    return new TimedOvnReleaseIdentityProjection(
        id(identity, "tle_key_session_id"),
        id(identity, "governance_attempt_id"),
        id(identity, "body_instance_id"),
        id(identity, "ballot_attempt_id"),
        byteArray32(
            identity.get("survivor_corpus_root"), "release_identity.survivor_corpus_root"),
        byteArray32(identity.get("no_recovery_root"), "release_identity.no_recovery_root"),
        unsignedInteger(
            identity.get("target_finalized_height"),
            "release_identity.target_finalized_height"),
        byteArray32(identity.get("parameter_hash"), "release_identity.parameter_hash"));
  }

  private static TleKeySessionPublicState parseTleKeySession(final Object value) {
    final Map<String, Object> root = exactObject(value, TLE_KEY_SESSION_FIELDS, "tle_key_session");
    if (!Integer.toString(VERSION)
        .equals(unsignedInteger(root.get("version"), "tle_key_session.version"))) {
      throw new IllegalArgumentException("unsupported TLE public-state version");
    }
    final String keySessionId = id(root, "key_session_id");
    final byte[] networkId = byteArray32(root.get("network_id"), "tle_key_session.network_id");
    final byte[] rosterHash = byteArray32(root.get("roster_hash"), "tle_key_session.roster_hash");
    final int committeeSize =
        u32Int(
            root.get("committee_size"),
            "tle_key_session.committee_size",
            4,
            MAX_TLE_COMMITTEE_SIZE);
    final int threshold = u32Int(root.get("threshold"), "tle_key_session.threshold", 2, 11);
    if ((committeeSize - 1) % 3 != 0 || threshold != (committeeSize - 1) / 3 + 1) {
      throw new IllegalArgumentException(
          "TLE committee_size/threshold is not an exact 3f+1/f+1 binding");
    }

    if (!(root.get("qualified_dealers") instanceof List<?> qualifiedValues)) {
      throw new IllegalArgumentException("tle_key_session.qualified_dealers must be an array");
    }
    final List<Integer> qualifiedDealers = new ArrayList<>(qualifiedValues.size());
    int previousDealer = 0;
    for (int index = 0; index < qualifiedValues.size(); index++) {
      final int dealer =
          u32Int(
              qualifiedValues.get(index),
              "tle_key_session.qualified_dealers[" + index + "]",
              1,
              committeeSize);
      if (dealer <= previousDealer) {
        throw new IllegalArgumentException(
            "qualified dealer indices violate canonical ordering");
      }
      qualifiedDealers.add(dealer);
      previousDealer = dealer;
    }
    if (qualifiedDealers.size() < threshold || qualifiedDealers.size() > committeeSize) {
      throw new IllegalArgumentException(
          "qualified dealer indices violate the threshold bound");
    }

    if (!(root.get("qualified_dealer_commitments") instanceof List<?> dealerValues)
        || dealerValues.size() != qualifiedDealers.size()) {
      throw new IllegalArgumentException(
          "qualified dealer commitments must align exactly with qualified_dealers");
    }
    final List<TleAdaptiveDealerCommitment> dealers = new ArrayList<>(dealerValues.size());
    for (int index = 0; index < dealerValues.size(); index++) {
      final String context = "qualified_dealer_commitments[" + index + "]";
      final Map<String, Object> dealer =
          exactObject(dealerValues.get(index), TLE_DEALER_FIELDS, context);
      final int dealerIndex =
          u32Int(dealer.get("dealer_index"), context + ".dealer_index", 1, committeeSize);
      if (dealerIndex != qualifiedDealers.get(index)) {
        throw new IllegalArgumentException(
            "dealer commitment index differs from the canonical qualified set");
      }
      if (!(dealer.get("coefficient_commitments") instanceof List<?> coefficientValues)
          || coefficientValues.size() != threshold) {
        throw new IllegalArgumentException(
            "each dealer must carry the exact degree-f coefficient set");
      }
      final List<byte[]> coefficients = new ArrayList<>(threshold);
      for (int coefficientIndex = 0; coefficientIndex < coefficientValues.size(); coefficientIndex++) {
        coefficients.add(
            fixedBytes(
                coefficientValues.get(coefficientIndex),
                96,
                context + ".coefficient_commitments[" + coefficientIndex + "]",
                true));
      }
      dealers.add(
          new TleAdaptiveDealerCommitment(
              dealerIndex,
              coefficients,
              fixedBytes(
                  dealer.get("constant_pok_commitment"),
                  96,
                  context + ".constant_pok_commitment",
                  true),
              fixedBytes(
                  dealer.get("constant_pok_response"),
                  32,
                  context + ".constant_pok_response",
                  false)));
    }

    if (!(root.get("public_shares") instanceof List<?> shareValues)
        || shareValues.size() != committeeSize) {
      throw new IllegalArgumentException(
          "public_shares must contain the complete ordered committee");
    }
    final List<TleAdaptivePublicShare> shares = new ArrayList<>(committeeSize);
    for (int offset = 0; offset < shareValues.size(); offset++) {
      final String context = "public_shares[" + offset + "]";
      final Map<String, Object> share =
          exactObject(shareValues.get(offset), TLE_PUBLIC_SHARE_FIELDS, context);
      final int index = u32Int(share.get("index"), context + ".index", 1, committeeSize);
      if (index != offset + 1) {
        throw new IllegalArgumentException(
            "public share indices must be the exact one-based committee sequence");
      }
      shares.add(
          new TleAdaptivePublicShare(
              index,
              byteArray32(share.get("participant_hash"), context + ".participant_hash"),
              fixedBytes(share.get("public_key_share"), 96, context + ".public_key_share", true)));
    }

    return new TleKeySessionPublicState(
        keySessionId,
        networkId,
        rosterHash,
        committeeSize,
        threshold,
        fixedBytes(root.get("generator_h"), 96, "tle_key_session.generator_h", true),
        fixedBytes(root.get("generator_v"), 96, "tle_key_session.generator_v", true),
        qualifiedDealers,
        dealers,
        byteArray32(root.get("dkg_event_hash"), "tle_key_session.dkg_event_hash"),
        fixedBytes(root.get("group_public_key"), 96, "tle_key_session.group_public_key", true),
        shares,
        byteArray32(root.get("transcript_hash"), "tle_key_session.transcript_hash"));
  }

  private static List<String> validateRequiredBodies(final Object value) {
    if (!(value instanceof List<?> entries) || entries.isEmpty() || entries.size() > 10) {
      throw new IllegalArgumentException(
          "required_bodies must contain one through ten entries");
    }
    final List<String> bodies = new ArrayList<>(entries.size());
    int previousBodyIndex = -1;
    for (int index = 0; index < entries.size(); index++) {
      final String context = "required_bodies[" + index + "]";
      final Map<String, Object> entry =
          exactObject(entries.get(index), setOf("body", "decision_mode"), context);
      if (!(entry.get("body") instanceof String body)
          || !BODIES.contains(body)
          || bodies.contains(body)) {
        throw new IllegalArgumentException(context + ".body is unknown or duplicated");
      }
      final int bodyIndex = CANONICAL_BODY_ORDER.indexOf(body);
      if (bodyIndex <= previousBodyIndex) {
        throw new IllegalArgumentException(
            "required_bodies must use strict canonical body order");
      }
      previousBodyIndex = bodyIndex;
      final String mode =
          taggedUnitIn(
              entry.get("decision_mode"),
              "mode",
              setOf("PublicFinding", "HiddenBindingBallot"),
              context + ".decision_mode");
      final String expected = PRIVATE_BODIES.contains(body) ? "HiddenBindingBallot" : "PublicFinding";
      if (!mode.equals(expected)) {
        throw new IllegalArgumentException(context + " uses the wrong decision protocol");
      }
      bodies.add(body);
    }
    return bodies;
  }

  private static List<BodyStateProjection> validateBodyStates(
      final Object value, final List<String> requiredBodies) {
    if (!(value instanceof List<?> entries)
        || entries.size() != requiredBodies.size()
        || entries.isEmpty()
        || entries.size() > 10) {
      throw new IllegalArgumentException(
          "body_states must exactly match the required body pipeline");
    }
    final List<BodyStateProjection> result = new ArrayList<>(entries.size());
    for (int index = 0; index < entries.size(); index++) {
      final String context = "body_states[" + index + "]";
      final Map<String, Object> entry =
          exactObject(entries.get(index), new HashSet<>(BODY_STATE_FIELDS), context);
      if (!(entry.get("body") instanceof String body)
          || !body.equals(requiredBodies.get(index))) {
        throw new IllegalArgumentException(
            context + ".body differs from required_bodies order");
      }
      final String bodyInstanceId;
      if (entry.get("body_instance_id") == null) {
        bodyInstanceId = null;
      } else if (entry.get("body_instance_id") instanceof String identifier) {
        bodyInstanceId = canonicalId(identifier);
      } else {
        throw new IllegalArgumentException(context + ".body_instance_id must be text or null");
      }
      final Map<String, Object> statusObject =
          entry.get("status") == null ? null : objectValue(entry.get("status"), context + ".status");
      if ((bodyInstanceId == null) != (statusObject == null)) {
        throw new IllegalArgumentException(
            context + " must bind body_instance_id and status together");
      }
      String status = null;
      String phase = null;
      if (statusObject != null) {
        if (!(statusObject.get("status") instanceof String candidate)
            || !BODY_STATUSES.contains(candidate)) {
          throw new IllegalArgumentException(context + ".status is unknown");
        }
        status = candidate;
        if (status.equals("Deliberating")) {
          if (!statusObject.keySet().equals(setOf("status", "phase"))) {
            throw new IllegalArgumentException(
                context + ".status contains unknown, aliased, or missing fields");
          }
          phase =
              taggedUnitIn(
                  statusObject.get("phase"),
                  "phase",
                  DELIBERATION_PHASES,
                  context + ".status.phase");
        } else if (!statusObject.keySet().equals(setOf("status"))) {
          throw new IllegalArgumentException(
              context + ".status contains unknown, aliased, or missing fields");
        }
      }
      final String opened =
          optionalUnsignedInteger(
              entry.get("public_finding_opened_at_height"),
              context + ".public_finding_opened_at_height");
      final String phaseBlocks =
          optionalUnsignedInteger(
              entry.get("public_finding_phase_blocks"),
              context + ".public_finding_phase_blocks");
      final String deadline =
          optionalUnsignedInteger(
              entry.get("public_finding_deadline_height"),
              context + ".public_finding_deadline_height");
      if ((opened == null) != (phaseBlocks == null) || (opened == null) != (deadline == null)) {
        throw new IllegalArgumentException(
            context + " must expose the complete public-finding schedule or none");
      }
      if (opened != null
          && (PRIVATE_BODIES.contains(body)
              || new BigInteger(phaseBlocks).signum() <= 0
              || !new BigInteger(opened)
                  .add(new BigInteger(phaseBlocks))
                  .equals(new BigInteger(deadline)))) {
        throw new IllegalArgumentException(
            context + " public-finding deadline does not match its frozen schedule");
      }
      final String noResultKind =
          entry.get("no_result_kind") == null
              ? null
              : taggedUnitIn(
                  entry.get("no_result_kind"),
                  "reason",
                  NO_RESULT_TAGS,
                  context + ".no_result_kind");
      final String noResultHeight =
          optionalUnsignedInteger(entry.get("no_result_height"), context + ".no_result_height");
      if ((noResultKind == null) != (noResultHeight == null)) {
        throw new IllegalArgumentException(
            context + " must bind no-result kind and height together");
      }
      if (noResultKind != null
          && (!"NoResult".equals(status)
              || (PUBLIC_NO_RESULT_KINDS.contains(noResultKind)
                  == PRIVATE_BODIES.contains(body)))) {
        throw new IllegalArgumentException(
            context + " no-result facts do not match its lifecycle and decision protocol");
      }
      final TimedOvnProgressProjection timedOvnProgress =
          entry.get("timed_ovn_progress") == null
              ? null
              : validateTimedOvnProgress(
                  entry.get("timed_ovn_progress"), context + ".timed_ovn_progress");
      if (timedOvnProgress != null
          && (!PRIVATE_BODIES.contains(body) || bodyInstanceId == null)) {
        throw new IllegalArgumentException(
            context + ".timed_ovn_progress requires an active private body");
      }
      result.add(
          new BodyStateProjection(
              body,
              bodyInstanceId,
              status,
              phase,
              opened,
              phaseBlocks,
              deadline,
              noResultKind,
              noResultHeight,
              timedOvnProgress));
    }
    return result;
  }

  private static TimedOvnProgressProjection validateTimedOvnProgress(
      final Object value, final String context) {
    final Map<String, Object> progress =
        exactObject(value, TIMED_OVN_PROGRESS_FIELDS, context);
    final String ballotAttemptId = id(progress, "ballot_attempt_id");
    final String status =
        taggedUnitIn(
            progress.get("status"),
            "status",
            TIMED_OVN_BALLOT_STATUSES,
            context + ".status");
    final Object survivorsValue = progress.get("frozen_survivor_count");
    final Object prefixValue = progress.get("accepted_ballot_prefix_count");
    if ((survivorsValue == null) != (prefixValue == null)) {
      throw new IllegalArgumentException(
          context + " survivor and prefix counts must appear together");
    }
    Integer survivors = null;
    Integer prefix = null;
    if (survivorsValue == null) {
      if (!setOf("Registration", "SurvivorFreeze", "NoResult", "Superseded")
          .contains(status)) {
        throw new IllegalArgumentException(
            context + " must expose counts after survivor freeze");
      }
    } else {
      survivors =
          u32Int(
              survivorsValue,
              context + ".frozen_survivor_count",
              1,
              MAX_TIMED_OVN_CORPUS_ENTRIES);
      prefix =
          u32Int(
              prefixValue,
              context + ".accepted_ballot_prefix_count",
              0,
              survivors);
      if ((status.equals("Registration") || status.equals("SurvivorFreeze"))
          || (status.equals("TimedCommitment") && prefix >= survivors)
          || (setOf("AwaitingRelease", "Opening", "Finalized").contains(status)
              && !prefix.equals(survivors))) {
        throw new IllegalArgumentException(
            context + " counts do not match the ballot lifecycle phase");
      }
    }
    return new TimedOvnProgressProjection(ballotAttemptId, status, survivors, prefix);
  }

  private static List<PublicFindingCertificateBinding> validateCertificate(
      final Object value,
      final String expectedAttemptId,
      final String expectedProposalContentId,
      final String expectedAttemptSequence,
      final String expectedRiskTier,
      final String expectedPolicyVersion,
      final List<String> requiredBodies,
      final List<BodyStateProjection> bodyStates) {
    if (value == null) {
      return listOf();
    }
    final Map<String, Object> certificate =
        exactObject(
            value,
            setOf(
                "proposal_content_id",
                "governance_attempt_id",
                "governance_attempt_sequence",
                "risk_tier",
                "body_bindings",
                "policy_version",
                "effect_preimage_hash",
                "expected_head",
                "certified_at_height",
                "enact_at_height"),
            "certificate");
    if (!id(certificate, "proposal_content_id").equals(expectedProposalContentId)) {
      throw new IllegalArgumentException(
          "certificate.proposal_content_id differs from attempt.proposal_content_id");
    }
    if (!id(certificate, "governance_attempt_id").equals(expectedAttemptId)) {
      throw new IllegalArgumentException(
          "certificate.governance_attempt_id differs from attempt.id");
    }
    if (!u32(
            certificate.get("governance_attempt_sequence"),
            "certificate.governance_attempt_sequence")
        .equals(expectedAttemptSequence)) {
      throw new IllegalArgumentException(
          "certificate.governance_attempt_sequence differs from attempt.sequence");
    }
    if (!taggedUnitIn(
            certificate.get("risk_tier"),
            "tier",
            setOf("Routine", "Standard", "Constitutional", "Emergency"),
            "certificate.risk_tier")
        .equals(expectedRiskTier)) {
      throw new IllegalArgumentException(
          "certificate.risk_tier differs from attempt.risk_tier");
    }
    byteArray32(certificate.get("effect_preimage_hash"), "certificate.effect_preimage_hash");
    final String policyVersion =
        unsignedInteger(certificate.get("policy_version"), "certificate.policy_version");
    if (!policyVersion.equals(Integer.toString(GOVERNANCE_POLICY_VERSION))) {
      throw new IllegalArgumentException(
          "certificate.policy_version must equal the first-release Parliament policy version");
    }
    if (!policyVersion.equals(expectedPolicyVersion)) {
      throw new IllegalArgumentException(
          "certificate.policy_version differs from the attempt projection");
    }
    validateExpectedHead(certificate.get("expected_head"), "certificate.expected_head");
    final BigInteger certifiedAtHeight =
        new BigInteger(
            unsignedInteger(
                certificate.get("certified_at_height"), "certificate.certified_at_height"));
    final BigInteger enactAtHeight =
        new BigInteger(
            unsignedInteger(certificate.get("enact_at_height"), "certificate.enact_at_height"));
    if (certifiedAtHeight.signum() <= 0 || enactAtHeight.compareTo(certifiedAtHeight) <= 0) {
      throw new IllegalArgumentException(
          "certificate enact_at_height must follow certified_at_height");
    }
    if (!(certificate.get("body_bindings") instanceof List<?> bindings)
        || bindings.size() != requiredBodies.size()
        || bindings.isEmpty()
        || bindings.size() > 10) {
      throw new IllegalArgumentException(
          "certificate.body_bindings must exactly match required_bodies");
    }
    final Set<String> seenBodyInstanceIds = new HashSet<>();
    final Set<String> seenElectionAttemptIds = new HashSet<>();
    final Set<String> seenSortitionRequestIds = new HashSet<>();
    final Set<String> seenBallotAttemptIds = new HashSet<>();
    final Set<String> seenTleSessionIds = new HashSet<>();
    final Set<String> seenReleasePulseIds = new HashSet<>();
    final Set<String> seenReleaseSlots = new HashSet<>();
    final Set<String> sortitionPulseIds = new HashSet<>();
    final List<PublicFindingCertificateBinding> findings = new ArrayList<>();
    BigInteger latestBodyResultHeight = BigInteger.ZERO;
    CertificateJuryFacts policyJury = null;
    CertificateJuryFacts confirmationJury = null;
    for (int index = 0; index < bindings.size(); index++) {
      final String context = "certificate.body_bindings[" + index + "]";
      final Map<String, Object> binding =
          exactObject(
              bindings.get(index),
              new HashSet<>(CERTIFICATE_BODY_BINDING_NORITO_FIELDS),
              context);
      if (!(binding.get("body") instanceof String body)
          || !body.equals(requiredBodies.get(index))) {
        throw new IllegalArgumentException(
            context + ".body differs from required_bodies order");
      }
      final int seats =
          u32Int(
              binding.get("original_seats"),
              context + ".original_seats",
              1,
              MAX_TIMED_OVN_CORPUS_ENTRIES);
      final String bodyInstanceId = id(binding, "body_instance_id");
      if (!bodyInstanceId.equals(bodyStates.get(index).bodyInstanceId)) {
        throw new IllegalArgumentException(
            context + ".body_instance_id differs from body_states");
      }
      final String electionAttemptId = id(binding, "election_attempt_id");
      final String sortitionRequestId = id(binding, "sortition_request_id");
      final String beaconSessionId = id(binding, "beacon_session_id");
      final String beaconPulseId = id(binding, "beacon_pulse_id");
      if (!seenBodyInstanceIds.add(bodyInstanceId)) {
        throw new IllegalArgumentException(
            "certificate.body_bindings reuses body_instance_id");
      }
      if (!seenElectionAttemptIds.add(electionAttemptId)) {
        throw new IllegalArgumentException(
            "certificate.body_bindings reuses election_attempt_id");
      }
      if (!seenSortitionRequestIds.add(sortitionRequestId)) {
        throw new IllegalArgumentException(
            "certificate.body_bindings reuses sortition_request_id");
      }
      sortitionPulseIds.add(beaconPulseId);
      for (final String field : listOf("roster_root", "assignment_root", "result_root")) {
        byteArray32(binding.get(field), context + "." + field);
      }
      final int electionAttemptSequence =
          u32Int(
              binding.get("election_attempt_sequence"),
              context + ".election_attempt_sequence",
              0,
              MAX_SORTITION_RETRIES);
      final BigInteger resultHeight =
          new BigInteger(
              unsignedInteger(binding.get("result_height"), context + ".result_height"));
      latestBodyResultHeight = latestBodyResultHeight.max(resultHeight);
      final CertificateSortitionFacts sortition =
          validateCertificateSortitionRequest(
              binding.get("sortition_request"),
              expectedAttemptId,
              body,
              electionAttemptId,
              sortitionRequestId,
              beaconSessionId,
              seats,
              resultHeight,
              certifiedAtHeight,
              context + ".sortition_request");
      if (PRIVATE_BODIES.contains(body)) {
        if (binding.get("public_finding") != null || binding.get("ballot") == null) {
          throw new IllegalArgumentException(context + " private jury must carry ballot only");
        }
        final CertificateBallotFacts ballot =
            validateCertificateBallot(
                binding.get("ballot"), seats, resultHeight, context + ".ballot");
        final TimedOvnProgressProjection progress = bodyStates.get(index).timedOvnProgress;
        if (progress == null
            || !progress.status.equals("Finalized")
            || !progress.ballotAttemptId.equals(ballot.ballotAttemptId)
            || !progress.frozenSurvivorCount.equals(ballot.acceptedBallots)
            || !progress.acceptedBallotPrefixCount.equals(ballot.acceptedBallots)) {
          throw new IllegalArgumentException(
              context + ".ballot differs from timed_ovn_progress");
        }
        if (!seenBallotAttemptIds.add(ballot.ballotAttemptId)) {
          throw new IllegalArgumentException(
              "certificate.body_bindings reuses ballot_attempt_id");
        }
        if (!seenTleSessionIds.add(ballot.tleSessionId)) {
          throw new IllegalArgumentException("certificate.body_bindings reuses tle_session_id");
        }
        if (!seenReleasePulseIds.add(ballot.releasePulseId)) {
          throw new IllegalArgumentException(
              "certificate.body_bindings reuses release_pulse_id");
        }
        if (!seenReleaseSlots.add(ballot.releaseSlot)) {
          throw new IllegalArgumentException(
              "certificate.body_bindings reuses a TLE release slot");
        }
        final CertificateJuryFacts jury =
            new CertificateJuryFacts(
                electionAttemptSequence,
                sortition.requestHeight,
                resultHeight,
                beaconPulseId,
                ballot);
        if (body.equals("policy-jury")) {
          if (policyJury != null) {
            throw new IllegalArgumentException(
                "certificate contains more than one policy-jury");
          }
          policyJury = jury;
        } else {
          if (confirmationJury != null) {
            throw new IllegalArgumentException(
                "certificate contains more than one confirmation-jury");
          }
          confirmationJury = jury;
        }
      } else {
        if (bodyStates.get(index).timedOvnProgress != null) {
          throw new IllegalArgumentException(
              context + " public body exposes timed_ovn_progress");
        }
        if (binding.get("public_finding") == null || binding.get("ballot") != null) {
          throw new IllegalArgumentException(
              context + " public body must carry public_finding only");
        }
        findings.add(
            validatePublicFinding(
                binding.get("public_finding"), seats, context + ".public_finding"));
      }
    }
    for (final String releasePulseId : seenReleasePulseIds) {
      if (sortitionPulseIds.contains(releasePulseId)) {
        throw new IllegalArgumentException(
            "certificate reuses a sortition pulse for ballot release");
      }
    }
    if (!certifiedAtHeight.equals(latestBodyResultHeight)) {
      throw new IllegalArgumentException(
          "certificate.certified_at_height must equal the latest body result height");
    }
    if (policyJury == null) {
      throw new IllegalArgumentException(
          "certificate must contain exactly one approving policy-jury ballot");
    }
    final BigInteger decisive = policyJury.ballot.aye.add(policyJury.ballot.nay);
    final boolean requiresConfirmation =
        decisive.signum() > 0
            && policyJury.ballot.aye
                    .subtract(policyJury.ballot.nay)
                    .abs()
                    .multiply(BigInteger.valueOf(100))
                    .compareTo(decisive.multiply(BigInteger.valueOf(5)))
                < 0;
    if (requiresConfirmation != (confirmationJury != null)) {
      throw new IllegalArgumentException(
          "certificate confirmation-jury presence differs from the policy margin");
    }
    if (confirmationJury != null) {
      final boolean validRequestHeight =
          confirmationJury.electionAttemptSequence == 0
              ? confirmationJury.requestHeight.equals(policyJury.resultHeight)
              : confirmationJury.requestHeight.compareTo(policyJury.resultHeight) > 0;
      if (!validRequestHeight || confirmationJury.beaconPulseId.equals(policyJury.beaconPulseId)) {
        throw new IllegalArgumentException(
            "certificate confirmation-jury request height must match the atomic initial "
                + "request or follow it on retry, with a fresh pulse");
      }
    }
    return findings;
  }

  private static final class CertificateSortitionFacts {
    private final BigInteger requestHeight;

    private CertificateSortitionFacts(final BigInteger requestHeight) {
      this.requestHeight = requestHeight;
    }
  }

  private static final class CertificateJuryFacts {
    private final int electionAttemptSequence;
    private final BigInteger requestHeight;
    private final BigInteger resultHeight;
    private final String beaconPulseId;
    private final CertificateBallotFacts ballot;

    private CertificateJuryFacts(
        final int electionAttemptSequence,
        final BigInteger requestHeight,
        final BigInteger resultHeight,
        final String beaconPulseId,
        final CertificateBallotFacts ballot) {
      this.electionAttemptSequence = electionAttemptSequence;
      this.requestHeight = requestHeight;
      this.resultHeight = resultHeight;
      this.beaconPulseId = beaconPulseId;
      this.ballot = ballot;
    }
  }

  /** Direct bindings are checked here; Norito-derived content identifiers and roots stay opaque. */
  private static CertificateSortitionFacts validateCertificateSortitionRequest(
      final Object value,
      final String governanceAttemptId,
      final String body,
      final String electionAttemptId,
      final String sortitionRequestId,
      final String beaconSessionId,
      final int originalSeats,
      final BigInteger resultHeight,
      final BigInteger certifiedAtHeight,
      final String context) {
    final Map<String, Object> request =
        exactObject(
            value,
            setOf(
                "id",
                "governance_attempt_id",
                "body_election_attempt_id",
                "body",
                "candidate_root",
                "candidate_count",
                "target_seats",
                "request_height",
                "pulse_height",
                "beacon_session_id"),
            context);
    if (!id(request, "id").equals(sortitionRequestId)
        || !id(request, "governance_attempt_id").equals(governanceAttemptId)
        || !id(request, "body_election_attempt_id").equals(electionAttemptId)
        || !body.equals(request.get("body"))
        || !id(request, "beacon_session_id").equals(beaconSessionId)) {
      throw new IllegalArgumentException(
          context + " differs from its repeated certificate bindings");
    }
    byteArray32(request.get("candidate_root"), context + ".candidate_root");
    final BigInteger candidateCount =
        new BigInteger(u32(request.get("candidate_count"), context + ".candidate_count"));
    if (candidateCount.signum() <= 0) {
      throw new IllegalArgumentException(context + ".candidate_count must be positive");
    }
    final int targetSeats = u32Int(
        request.get("target_seats"),
        context + ".target_seats",
        1,
        MAX_TIMED_OVN_CORPUS_ENTRIES);
    if (originalSeats > targetSeats
        || BigInteger.valueOf(originalSeats).compareTo(candidateCount) > 0) {
      throw new IllegalArgumentException(
          context + " original_seats exceeds its sortition bounds");
    }
    final BigInteger requestHeight =
        new BigInteger(unsignedInteger(request.get("request_height"), context + ".request_height"));
    final BigInteger pulseHeight =
        new BigInteger(unsignedInteger(request.get("pulse_height"), context + ".pulse_height"));
    if (requestHeight.signum() <= 0
        || pulseHeight.compareTo(requestHeight) <= 0
        || resultHeight.compareTo(pulseHeight) <= 0
        || resultHeight.compareTo(certifiedAtHeight) > 0) {
      throw new IllegalArgumentException(
          context + " violates the sortition/result lifecycle");
    }
    return new CertificateSortitionFacts(requestHeight);
  }

  private static final class CertificateBallotFacts {
    private final String ballotAttemptId;
    private final String tleSessionId;
    private final String releasePulseId;
    private final String releaseSlot;
    private final Integer acceptedBallots;
    private final BigInteger aye;
    private final BigInteger nay;

    private CertificateBallotFacts(
        final String ballotAttemptId,
        final String tleSessionId,
        final String releasePulseId,
        final String releaseSlot,
        final Integer acceptedBallots,
        final BigInteger aye,
        final BigInteger nay) {
      this.ballotAttemptId = ballotAttemptId;
      this.tleSessionId = tleSessionId;
      this.releasePulseId = releasePulseId;
      this.releaseSlot = releaseSlot;
      this.acceptedBallots = acceptedBallots;
      this.aye = aye;
      this.nay = nay;
    }
  }

  private static CertificateBallotFacts validateCertificateBallot(
      final Object value,
      final int originalSeats,
      final BigInteger resultHeight,
      final String context) {
    final Map<String, Object> ballot =
        exactObject(
            value,
            setOf(
                "ballot_attempt_id",
                "ballot_attempt_sequence",
                "tle_session_id",
                "tle_key_session_id",
                "registration_root",
                "dropout_root",
                "survivor_root",
                "corpus_root",
                "no_recovery_root",
                "timed_commitment_root",
                "release_beacon_session_id",
                "registered_at_height",
                "registration_close_height",
                "survivor_freeze_height",
                "commitment_close_height",
                "registration_closed_at_height",
                "survivors_frozen_at_height",
                "commitment_closed_at_height",
                "max_ballot_retries",
                "max_corpus_entries",
                "release_height",
                "opening_deadline_height",
                "release_pulse_id",
                "opening_height",
                "opening_root",
                "tally",
                "outcome"),
            context);
    final String ballotAttemptId = id(ballot, "ballot_attempt_id");
    final String tleSessionId = id(ballot, "tle_session_id");
    id(ballot, "tle_key_session_id");
    final String releaseBeaconSessionId = id(ballot, "release_beacon_session_id");
    final String releasePulseId = id(ballot, "release_pulse_id");
    for (final String field :
        listOf(
            "registration_root",
            "dropout_root",
            "survivor_root",
            "corpus_root",
            "no_recovery_root",
            "timed_commitment_root",
            "opening_root")) {
      byteArray32(ballot.get(field), context + "." + field);
    }
    final int sequence =
        u32Int(ballot.get("ballot_attempt_sequence"), context + ".ballot_attempt_sequence", 0, 16);
    final int maxRetries =
        u32Int(ballot.get("max_ballot_retries"), context + ".max_ballot_retries", 0, 16);
    if (sequence > maxRetries) {
      throw new IllegalArgumentException(
          context + ".ballot_attempt_sequence exceeds max_ballot_retries");
    }
    final int maxCorpusEntries =
        u32Int(
            ballot.get("max_corpus_entries"),
            context + ".max_corpus_entries",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES);
    final BigInteger registered = certificateHeight(ballot, "registered_at_height", context);
    final BigInteger registrationClose =
        certificateHeight(ballot, "registration_close_height", context);
    final BigInteger survivorFreeze =
        certificateHeight(ballot, "survivor_freeze_height", context);
    final BigInteger commitmentClose =
        certificateHeight(ballot, "commitment_close_height", context);
    final BigInteger registrationClosed =
        certificateHeight(ballot, "registration_closed_at_height", context);
    final BigInteger survivorsFrozen =
        certificateHeight(ballot, "survivors_frozen_at_height", context);
    final BigInteger commitmentClosed =
        certificateHeight(ballot, "commitment_closed_at_height", context);
    final BigInteger release = certificateHeight(ballot, "release_height", context);
    final BigInteger openingDeadline =
        certificateHeight(ballot, "opening_deadline_height", context);
    final BigInteger opening = certificateHeight(ballot, "opening_height", context);
    final BigInteger maxCorpus = BigInteger.valueOf(maxCorpusEntries);
    final BigInteger requiredCommitmentBlocks =
        BigInteger.valueOf(
            (maxCorpusEntries + TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS - 1L)
                / TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS);
    if (registered.signum() <= 0
        || registrationClose.compareTo(registered) <= 0
        || maxCorpusEntries < originalSeats
        || registrationClose.subtract(registered).compareTo(maxCorpus.add(BigInteger.ONE)) < 0
        || survivorFreeze.compareTo(registrationClose) <= 0
        || survivorFreeze.subtract(registrationClose).compareTo(maxCorpus) < 0
        || commitmentClose.compareTo(survivorFreeze) <= 0
        || commitmentClose.subtract(survivorFreeze).compareTo(requiredCommitmentBlocks) < 0
        || release.compareTo(commitmentClose) <= 0
        || openingDeadline.compareTo(release) <= 0
        || !registrationClosed.equals(registrationClose)
        || !survivorsFrozen.equals(survivorFreeze)
        || commitmentClosed.compareTo(survivorFreeze) <= 0
        || commitmentClosed.compareTo(commitmentClose) > 0
        || opening.compareTo(release) < 0
        || opening.compareTo(openingDeadline) > 0
        || resultHeight.compareTo(opening) < 0
        || resultHeight.compareTo(openingDeadline) > 0) {
      throw new IllegalArgumentException(context + " violates the frozen ballot lifecycle");
    }
    final Map<String, Object> tally =
        exactObject(
            ballot.get("tally"),
            setOf("original_seats", "accepted_ballots", "aye", "nay", "abstain"),
            context + ".tally");
    final int tallySeats =
        u32Int(
            tally.get("original_seats"),
            context + ".tally.original_seats",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES);
    final int accepted =
        u32Int(
            tally.get("accepted_ballots"),
            context + ".tally.accepted_ballots",
            0,
            MAX_TIMED_OVN_CORPUS_ENTRIES);
    final BigInteger aye = new BigInteger(u32(tally.get("aye"), context + ".tally.aye"));
    final BigInteger nay = new BigInteger(u32(tally.get("nay"), context + ".tally.nay"));
    final BigInteger abstain =
        new BigInteger(u32(tally.get("abstain"), context + ".tally.abstain"));
    if (tallySeats != originalSeats
        || accepted > maxCorpusEntries
        || accepted > originalSeats
        || !aye.add(nay).add(abstain).equals(BigInteger.valueOf(accepted))) {
      throw new IllegalArgumentException(
          context + ".tally violates immutable bounds or count conservation");
    }
    final int quorum = (2 * originalSeats + 2) / 3;
    final String outcome =
        taggedUnitIn(
            ballot.get("outcome"),
            "outcome",
            setOf("Approved", "Rejected", "NoQuorum", "NoResult"),
            context + ".outcome");
    final String expectedOutcome =
        accepted < quorum ? "NoQuorum" : aye.compareTo(nay) > 0 ? "Approved" : "Rejected";
    if (!outcome.equals(expectedOutcome) || !outcome.equals("Approved")) {
      throw new IllegalArgumentException(
          context + " must contain the deterministic approving aggregate outcome");
    }
    return new CertificateBallotFacts(
        ballotAttemptId,
        tleSessionId,
        releasePulseId,
        releaseBeaconSessionId + ":" + release,
        accepted,
        aye,
        nay);
  }

  private static BigInteger certificateHeight(
      final Map<String, Object> ballot, final String field, final String context) {
    return new BigInteger(unsignedInteger(ballot.get(field), context + "." + field));
  }

  private static void validateExpectedHead(final Object value, final String context) {
    final Map<String, Object> root =
        exactObject(value, setOf("state", "head"), context);
    if ("Absent".equals(root.get("state"))) {
      final Map<String, Object> head =
          exactObject(root.get("head"), setOf("subject_id"), context + ".head");
      byteArray32(head.get("subject_id"), context + ".head.subject_id");
    } else if ("Present".equals(root.get("state"))) {
      final Map<String, Object> head =
          exactObject(
              root.get("head"),
              setOf("subject_id", "version", "head_root"),
              context + ".head");
      byteArray32(head.get("subject_id"), context + ".head.subject_id");
      if (new BigInteger(unsignedInteger(head.get("version"), context + ".head.version"))
              .signum()
          <= 0) {
        throw new IllegalArgumentException(context + ".head.version must be positive");
      }
      byteArray32(head.get("head_root"), context + ".head.head_root");
    } else {
      throw new IllegalArgumentException(context + ".state is unknown");
    }
  }

  private static PublicFindingCertificateBinding validatePublicFinding(
      final Object value, final int originalSeats, final String context) {
    final Map<String, Object> finding =
        exactObject(
            value,
            new HashSet<>(PUBLIC_FINDING_CERTIFICATE_NORITO_FIELDS),
            context);
    final byte[] root = byteArray32(finding.get("endorsement_root"), context + ".endorsement_root");
    if (!(finding.get("endorsing_assignments") instanceof List<?> rawAssignments)) {
      throw new IllegalArgumentException(context + ".endorsing_assignments must be an array");
    }
    final List<String> assignments = new ArrayList<>(rawAssignments.size());
    String previous = null;
    for (final Object raw : rawAssignments) {
      if (!(raw instanceof String candidate)) {
        throw new IllegalArgumentException(
            context + ".endorsing_assignments must contain text identifiers");
      }
      final String identifier = canonicalId(candidate);
      if (previous != null && previous.compareTo(identifier) >= 0) {
        throw new IllegalArgumentException(
            context + ".endorsing_assignments must be strictly increasing and distinct");
      }
      assignments.add(identifier);
      previous = identifier;
    }
    if (assignments.isEmpty() || assignments.size() > MAX_TIMED_OVN_CORPUS_ENTRIES) {
      throw new IllegalArgumentException(
          context + ".endorsing_assignments must contain one through 1000 identifiers");
    }
    final int endorsements =
        u32Int(
            finding.get("endorsements"),
            context + ".endorsements",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES);
    final int quorum =
        u32Int(
            finding.get("quorum"),
            context + ".quorum",
            1,
            MAX_TIMED_OVN_CORPUS_ENTRIES);
    final int expectedQuorum = (2 * originalSeats + 2) / 3;
    if (assignments.size() != endorsements || endorsements != quorum || quorum != expectedQuorum) {
      throw new IllegalArgumentException(
          context + " must contain the exact canonical two-thirds supporter list");
    }
    return new PublicFindingCertificateBinding(root, assignments, endorsements, quorum);
  }

  private static void validateTleIdentityPayload(
      final byte[] payload,
      final String governanceAttemptId,
      final String bodyInstanceId,
      final String ballotAttemptId,
      final TimedOvnReleaseIdentityProjection identity) {
    final byte[] domain =
        "iroha.parliament.tle.identity-payload.v1\0".getBytes(StandardCharsets.UTF_8);
    if (payload.length != 243
        || !Arrays.equals(Arrays.copyOfRange(payload, 0, domain.length), domain)) {
      throw new IllegalArgumentException(
          "identity_payload_hex has the wrong domain or canonical width");
    }
    int offset = domain.length;
    if (!Arrays.equals(Arrays.copyOfRange(payload, offset, offset + 2), u16Bytes(1))) {
      throw new IllegalArgumentException("identity payload version must equal one");
    }
    offset += 2;
    final List<byte[]> expectedBindings =
        listOf(
            decodeHex(governanceAttemptId),
            decodeHex(bodyInstanceId),
            decodeHex(ballotAttemptId),
            identity.survivorCorpusRoot,
            identity.noRecoveryRoot);
    final List<String> bindingNames =
        listOf(
            "governance_attempt_id",
            "body_instance_id",
            "ballot_attempt_id",
            "survivor_corpus_root",
            "no_recovery_root");
    for (int index = 0; index < expectedBindings.size(); index++) {
      final byte[] expected = expectedBindings.get(index);
      if (!Arrays.equals(Arrays.copyOfRange(payload, offset, offset + 32), expected)) {
        throw new IllegalArgumentException(
            "identity payload " + bindingNames.get(index) + " binding differs");
      }
      offset += 32;
    }
    if (!Arrays.equals(
        Arrays.copyOfRange(payload, offset, offset + 8),
        u64Bytes(new BigInteger(identity.targetFinalizedHeight)))) {
      throw new IllegalArgumentException("identity payload release height differs");
    }
    offset += 8;
    if (!Arrays.equals(
        Arrays.copyOfRange(payload, offset, offset + 32), identity.parameterHash)) {
      throw new IllegalArgumentException("identity payload parameter_hash binding differs");
    }
  }

  private static byte[] tleReleaseMessageDigest(
      final TleKeySessionPublicState session, final byte[] identityPayload) {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    write(output, "iroha.threshold-bls.message.v1\0".getBytes(StandardCharsets.UTF_8));
    write(output, "iroha.threshold-bls.session.v1\0".getBytes(StandardCharsets.UTF_8));
    write(output, u16Bytes(1));
    output.write(2);
    write(output, session.networkId);
    write(output, decodeHex(session.keySessionId));
    write(output, session.rosterHash);
    write(output, u16Bytes(session.committeeSize));
    write(output, u16Bytes(session.threshold));
    write(output, u32Bytes(identityPayload.length));
    write(output, identityPayload);
    try {
      return MessageDigest.getInstance("SHA-256").digest(output.toByteArray());
    } catch (final NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 is unavailable", error);
    }
  }

  private static void write(final ByteArrayOutputStream output, final byte[] value) {
    output.write(value, 0, value.length);
  }

  private static byte[] u16Bytes(final int value) {
    if (value < 0 || value > 0xffff) {
      throw new IllegalArgumentException("value is outside u16");
    }
    return new byte[] {(byte) (value >>> 8), (byte) value};
  }

  private static byte[] u32Bytes(final int value) {
    if (value < 0) throw new IllegalArgumentException("value is outside u32");
    return new byte[] {
      (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
    };
  }

  private static byte[] u64Bytes(final BigInteger value) {
    if (value.signum() < 0 || value.bitLength() > 64) {
      throw new IllegalArgumentException("height is outside u64");
    }
    byte[] encoded = value.toByteArray();
    if (encoded.length == 9 && encoded[0] == 0) {
      encoded = Arrays.copyOfRange(encoded, 1, encoded.length);
    }
    final byte[] result = new byte[8];
    System.arraycopy(encoded, 0, result, result.length - encoded.length, encoded.length);
    return result;
  }

  private static void validateStateFrame(final byte[] bytes) {
    final NoritoHeader.DecodeResult decoded;
    try {
      decoded = NoritoHeader.decode(bytes, null);
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "state_payload_hex must contain one valid Norito frame", ex);
    }
    if (decoded.header().compression() != NoritoHeader.COMPRESSION_NONE) {
      throw new IllegalArgumentException(
          "state_payload_hex must use uncompressed canonical Norito");
    }
    if (allZero(decoded.header().schemaHash()) || decoded.payload().length == 0) {
      throw new IllegalArgumentException(
          "state_payload_hex must declare a nonzero schema and nonempty payload");
    }
    decoded.header().validateChecksum(decoded.payload());
  }

  private static Map<String, Object> exactRoot(
      final byte[] bytes, final Set<String> fields, final String label) {
    final String text = new String(bytes, StandardCharsets.UTF_8);
    if (!Arrays.equals(bytes, text.getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException(label + " must be UTF-8 JSON");
    }
    final Map<String, Object> root = objectValue(JsonParser.parse(text), label);
    for (final String field : root.keySet()) {
      if (!fields.contains(field)) {
        throw new IllegalArgumentException(
            label + " contains unknown or aliased field `" + field + "`");
      }
    }
    for (final String field : fields) {
      if (!root.containsKey(field)) {
        throw new IllegalArgumentException(label + " is missing field `" + field + "`");
      }
    }
    return root;
  }

  private static void version(final Map<String, Object> root) {
    if (!Integer.toString(VERSION).equals(unsignedInteger(root.get("version"), "version"))) {
      throw new IllegalArgumentException("unsupported Parliament API version");
    }
  }

  private static InstructionDraft instruction(
      final Map<String, Object> root, final String expectedWireId) {
    if (!(root.get("tx_instructions") instanceof List<?> values) || values.size() != 1) {
      throw new IllegalArgumentException(
          "Parliament draft must contain exactly one instruction");
    }
    final Map<String, Object> draft = objectValue(values.get(0), "tx_instructions[0]");
    if (!draft.keySet().equals(setOf("wire_id", "payload_hex"))) {
      throw new IllegalArgumentException(
          "instruction draft contains unknown, aliased, or missing fields");
    }
    if (!(draft.get("wire_id") instanceof String wireId) || !wireId.equals(expectedWireId)) {
      throw new IllegalArgumentException("instruction draft has the wrong wire_id");
    }
    return new InstructionDraft(
        wireId, canonicalHex(draft.get("payload_hex"), "payload_hex", false));
  }

  private static Map<String, Object> taggedObject(
      final byte[] bytes,
      final String tagField,
      final String payloadField,
      final String label,
      final boolean payloadOptional) {
    final Map<String, Object> root =
        objectValue(JsonParser.parse(new String(bytes, StandardCharsets.UTF_8)), label);
    for (final String field : root.keySet()) {
      if (!field.equals(tagField) && !field.equals(payloadField)) {
        throw new IllegalArgumentException(
            label + " contains unknown, aliased, or missing tagged fields");
      }
    }
    if (!root.containsKey(tagField)
        || (!payloadOptional && !root.containsKey(payloadField))) {
      throw new IllegalArgumentException(
          label + " contains unknown, aliased, or missing tagged fields");
    }
    if (!(root.get(tagField) instanceof String tag)
        || tag.trim().isEmpty()
        || !tag.equals(tag.trim())) {
      throw new IllegalArgumentException(label + " tag must be canonical text");
    }
    if (root.containsKey(payloadField)) {
      objectValue(root.get(payloadField), label + " payload");
    }
    return root;
  }

  private static String taggedUnit(
      final Object value, final String tagField, final String label) {
    final Map<String, Object> root = objectValue(value, label);
    if (!root.keySet().equals(setOf(tagField)) || !(root.get(tagField) instanceof String tag)) {
      throw new IllegalArgumentException(label + " must be one exact unit tag");
    }
    return tag;
  }

  private static String taggedUnitIn(
      final Object value,
      final String tagField,
      final Set<String> admitted,
      final String label) {
    final String tag = taggedUnit(value, tagField, label);
    if (!admitted.contains(tag)) {
      throw new IllegalArgumentException(label + "." + tagField + " is unknown");
    }
    return tag;
  }

  private static Map<String, Object> exactObject(
      final Object value, final Set<String> fields, final String label) {
    final Map<String, Object> root = objectValue(value, label);
    if (!root.keySet().equals(fields)) {
      throw new IllegalArgumentException(
          label + " contains unknown, aliased, or missing fields");
    }
    return root;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> objectValue(final Object value, final String label) {
    if (!(value instanceof Map<?, ?> map)) {
      throw new IllegalArgumentException(label + " must be an object");
    }
    for (final Object key : map.keySet()) {
      if (!(key instanceof String)) {
        throw new IllegalArgumentException(label + " must have text keys");
      }
    }
    return (Map<String, Object>) map;
  }

  private static String id(final Map<String, Object> root, final String field) {
    if (!(root.get(field) instanceof String value)) {
      throw new IllegalArgumentException(field + " must be text");
    }
    return canonicalId(value);
  }

  private static String canonicalId(final String value) {
    if (value == null || !ID.matcher(value).matches() || value.chars().allMatch(c -> c == '0')) {
      throw new IllegalArgumentException(
          "identifier must be exactly 64 lowercase nonzero hexadecimal characters");
    }
    return value;
  }

  private static String canonicalHex(
      final Object value, final String field, final boolean allowEmpty) {
    if (!(value instanceof String text)
        || text.length() % 2 != 0
        || (!allowEmpty && text.isEmpty())) {
      throw new IllegalArgumentException(field + " must contain complete bytes");
    }
    for (int i = 0; i < text.length(); i++) {
      final char c = text.charAt(i);
      if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) {
        throw new IllegalArgumentException(field + " must be lowercase hexadecimal");
      }
    }
    return text;
  }

  private static byte[] decodeHex(final String text) {
    final byte[] bytes = new byte[text.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private static byte[] byteArray32(final Object value, final String field) {
    return fixedBytes(value, 32, field, true);
  }

  private static byte[] fixedBytes(
      final Object value, final int size, final String field, final boolean nonzero) {
    if (!(value instanceof List<?> values) || values.size() != size) {
      throw new IllegalArgumentException(field + " must contain exactly " + size + " bytes");
    }
    final byte[] bytes = new byte[size];
    for (int i = 0; i < bytes.length; i++) {
      final String canonical = unsignedInteger(values.get(i), field + "[" + i + "]");
      final int item;
      try {
        item = Integer.parseInt(canonical);
      } catch (final NumberFormatException ex) {
        throw new IllegalArgumentException(field + "[" + i + "] must be a byte", ex);
      }
      if (item > 255) {
        throw new IllegalArgumentException(field + "[" + i + "] must be a byte");
      }
      bytes[i] = (byte) item;
    }
    if (nonzero && allZero(bytes)) {
      throw new IllegalArgumentException(field + " must be nonzero");
    }
    return bytes;
  }

  private static byte[] optionalByteArray32(final Object value, final String field) {
    return value == null ? null : byteArray32(value, field);
  }

  private static String optionalUnsignedInteger(final Object value, final String field) {
    return value == null ? null : unsignedInteger(value, field);
  }

  private static String u32(final Object value, final String field) {
    final String text = unsignedInteger(value, field);
    if (new BigInteger(text).compareTo(new BigInteger("4294967295")) > 0) {
      throw new IllegalArgumentException(field + " is outside u32");
    }
    return text;
  }

  private static int u32Int(
      final Object value,
      final String field,
      final int minimum,
      final int maximum) {
    final int parsed;
    try {
      parsed = Integer.parseInt(u32(value, field));
    } catch (final NumberFormatException ex) {
      throw new IllegalArgumentException(field + " is outside the supported bound", ex);
    }
    if (parsed < minimum || parsed > maximum) {
      throw new IllegalArgumentException(
          field + " is outside " + minimum + ".." + maximum);
    }
    return parsed;
  }

  private static boolean allZero(final byte[] bytes) {
    for (final byte value : bytes) {
      if (value != 0) return false;
    }
    return true;
  }

  private static String unsignedInteger(final Object value, final String field) {
    if (!(value instanceof Number)) {
      throw new IllegalArgumentException(field + " must be an unsigned integer");
    }
    final String text = value.toString();
    final BigInteger number;
    try {
      number = new BigInteger(text);
    } catch (final NumberFormatException ex) {
      throw new IllegalArgumentException(field + " must be an unsigned integer", ex);
    }
    if (number.signum() < 0 || !number.toString().equals(text)) {
      throw new IllegalArgumentException(field + " must be a canonical unsigned integer");
    }
    return text;
  }

  private static byte[] encode(final Map<String, Object> value) {
    return JsonEncoder.encode(value).getBytes(StandardCharsets.UTF_8);
  }

  private static Map<String, TransitionLayout> publicTransitionsByTag() {
    final Map<String, TransitionLayout> layouts = new LinkedHashMap<>();
    for (final TransitionLayout layout : PUBLIC_TRANSITIONS) {
      if (layouts.put(layout.jsonTag, layout) != null) {
        throw new IllegalStateException("duplicate Parliament transition tag");
      }
    }
    return Collections.unmodifiableMap(layouts);
  }

  private static Set<String> noResultTags() {
    final Set<String> tags = new HashSet<>();
    for (final NoResultKindLayout layout : NO_RESULT_KINDS) {
      if (!tags.add(layout.jsonTag)) {
        throw new IllegalStateException("duplicate Parliament no-result tag");
      }
    }
    return Collections.unmodifiableSet(tags);
  }

  @SafeVarargs
  private static <T> List<T> listOf(final T... values) {
    return Collections.unmodifiableList(Arrays.asList(values));
  }

  @SafeVarargs
  private static <T> Set<T> setOf(final T... values) {
    return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(values)));
  }

  private static Map<String, String> certificateResultRootDomains() {
    final Map<String, String> domains = new LinkedHashMap<>();
    domains.put("public_finding_result_root", null);
    domains.put(
        "public_finding_endorsement_root",
        "iroha.governance.parliament.public_finding_endorsement.root.v1");
    domains.put(
        "private_ballot_result_root",
        "iroha.governance.parliament.ballot_result.root.v1");
    domains.put(
        "private_ballot_failure_root",
        "iroha.governance.parliament.ballot_failure.root.v1");
    domains.put(
        "execution_failure_root",
        "iroha.governance.parliament.execution_failure.root.v1");
    domains.put("governance_certificate_id", "iroha.governance.certificate.id.v1");
    return Collections.unmodifiableMap(domains);
  }
}
