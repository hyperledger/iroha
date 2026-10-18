package org.hyperledger.iroha.android.client;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import org.hyperledger.iroha.norito.NoritoHeader;

/** Reflection-free builders and strict response admission for Parliament API V1. */
public final class ParliamentApiV1 {

  public static final int VERSION = 1;
  public static final String ATTEMPT_DRAFT_PATH = "/v1/gov/parliament/attempts/draft";
  public static final String ATTEMPT_READ_PATH =
      "/v1/gov/parliament/attempts/{governance_attempt_id}";
  public static final String TRANSITION_DRAFT_PATH =
      "/v1/gov/parliament/transitions/draft";
  public static final String ATTEMPT_CREATE_WIRE_ID =
      "iroha.governance.parliament.attempt.create.v1";
  public static final String TRANSITION_SUBMIT_WIRE_ID =
      "iroha.governance.parliament.transition.submit.v1";
  public static final int MAX_STATE_BYTES = 16 * 1024 * 1024;
  /** Largest seat count of one body; mirrors Rust {@code MAX_PARLIAMENT_BODY_TARGET_SEATS_V1}. */
  public static final int MAX_BODY_TARGET_SEATS = 1_000;
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
          new TransitionLayout(10, "RecordInvitationResponse", true, 13),
          new TransitionLayout(11, "FailPublicFindingNoResult", true, 14),
          new TransitionLayout(12, "RegisterInitialSortition", false, 15));

  public static final List<AutomaticOutcomeLayout> AUTOMATIC_EXECUTION_OUTCOMES =
      listOf(
          new AutomaticOutcomeLayout(0, "Enacted", false, "MarkEnacted", 10),
          new AutomaticOutcomeLayout(1, "Superseded", true, "MarkSuperseded", 11),
          new AutomaticOutcomeLayout(
              2, "ExecutionFailed", true, "MarkExecutionFailed", 12));

  public static final List<NoResultKindLayout> NO_RESULT_KINDS =
      listOf(
          new NoResultKindLayout(0, "PublicFindingQuorumUnreachable"),
          new NoResultKindLayout(1, "PublicFindingDeadlineExpired"),
          new NoResultKindLayout(2, "SortitionRetriesExhausted"),
          new NoResultKindLayout(3, "ConfirmationJuryCapacityUnavailable"),
          new NoResultKindLayout(4, "RandomnessRedrawBudgetExhausted"));

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
          "no_result_height");
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

    private BodyStateProjection(
        final String body,
        final String bodyInstanceId,
        final String status,
        final String deliberationPhase,
        final String publicFindingOpenedAtHeight,
        final String publicFindingPhaseBlocks,
        final String publicFindingDeadlineHeight,
        final String noResultKind,
        final String noResultHeight) {
      this.body = body;
      this.bodyInstanceId = bodyInstanceId;
      this.status = status;
      this.deliberationPhase = deliberationPhase;
      this.publicFindingOpenedAtHeight = publicFindingOpenedAtHeight;
      this.publicFindingPhaseBlocks = publicFindingPhaseBlocks;
      this.publicFindingDeadlineHeight = publicFindingDeadlineHeight;
      this.noResultKind = noResultKind;
      this.noResultHeight = noResultHeight;
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

  /** Replace the sole attempt-id path parameter after exact lowercase validation. */
  public static String attemptReadPath(final String governanceAttemptId) {
    return ATTEMPT_READ_PATH.replace(
        "{governance_attempt_id}", canonicalId(governanceAttemptId));
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
    final Map<String, Object> request = new LinkedHashMap<>();
    request.put("version", VERSION);
    request.put("governance_attempt_id", canonicalId(governanceAttemptId));
    request.put("transition", transition);
    return encode(request);
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
              noResultHeight));
    }
    return result;
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
    final List<PublicFindingCertificateBinding> findings = new ArrayList<>();
    BigInteger latestBodyResultHeight = BigInteger.ZERO;
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
              MAX_BODY_TARGET_SEATS);
      final String bodyInstanceId = id(binding, "body_instance_id");
      if (!bodyInstanceId.equals(bodyStates.get(index).bodyInstanceId)) {
        throw new IllegalArgumentException(
            context + ".body_instance_id differs from body_states");
      }
      final String electionAttemptId = id(binding, "election_attempt_id");
      final String sortitionRequestId = id(binding, "sortition_request_id");
      final String beaconSessionId = id(binding, "beacon_session_id");
      id(binding, "beacon_pulse_id");
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
      for (final String field : listOf("roster_root", "assignment_root", "result_root")) {
        byteArray32(binding.get(field), context + "." + field);
      }
      u32Int(
          binding.get("election_attempt_sequence"),
          context + ".election_attempt_sequence",
          0,
          MAX_SORTITION_RETRIES);
      final BigInteger resultHeight =
          new BigInteger(
              unsignedInteger(binding.get("result_height"), context + ".result_height"));
      latestBodyResultHeight = latestBodyResultHeight.max(resultHeight);
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
        // TODO(parliament anonymous ballot, P4): validate the anonymous body-result binding (BallotClosureRecordV1 + result_root) for private-jury bodies here; until it lands this SDK admits no certificate that contains a private-jury body.
        throw new IllegalArgumentException(
            context
                + " private-jury result binding is not admitted until the anonymous-ballot result"
                + " binding is supported");
      }
      if (binding.get("public_finding") == null || binding.get("ballot") != null) {
        throw new IllegalArgumentException(
            context + " public body must carry public_finding only");
      }
      findings.add(
          validatePublicFinding(
              binding.get("public_finding"), seats, context + ".public_finding"));
    }
    if (!certifiedAtHeight.equals(latestBodyResultHeight)) {
      throw new IllegalArgumentException(
          "certificate.certified_at_height must equal the latest body result height");
    }
    return findings;
  }

  /** Direct bindings are checked here; Norito-derived content identifiers and roots stay opaque. */
  private static void validateCertificateSortitionRequest(
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
        MAX_BODY_TARGET_SEATS);
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
    if (assignments.isEmpty() || assignments.size() > MAX_BODY_TARGET_SEATS) {
      throw new IllegalArgumentException(
          context + ".endorsing_assignments must contain one through 1000 identifiers");
    }
    final int endorsements =
        u32Int(
            finding.get("endorsements"),
            context + ".endorsements",
            1,
            MAX_BODY_TARGET_SEATS);
    final int quorum =
        u32Int(
            finding.get("quorum"),
            context + ".quorum",
            1,
            MAX_BODY_TARGET_SEATS);
    final int expectedQuorum = (2 * originalSeats + 2) / 3;
    if (assignments.size() != endorsements || endorsements != quorum || quorum != expectedQuorum) {
      throw new IllegalArgumentException(
          context + " must contain the exact canonical two-thirds supporter list");
    }
    return new PublicFindingCertificateBinding(root, assignments, endorsements, quorum);
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
        "execution_failure_root",
        "iroha.governance.parliament.execution_failure.root.v1");
    domains.put("governance_certificate_id", "iroha.governance.certificate.id.v1");
    return Collections.unmodifiableMap(domains);
  }
}
