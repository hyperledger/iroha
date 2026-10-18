// SPDX-License-Identifier: Apache-2.0

import { validateNoritoFrame } from "./norito.js";
import { normalizeGovernanceProposalWireV1 } from "./governanceProposalV1.js";

export const PARLIAMENT_API_VERSION_V1 = 1;
export const PARLIAMENT_ATTEMPT_DRAFT_PATH_V1 =
  "/v1/gov/parliament/attempts/draft";
export const PARLIAMENT_ATTEMPT_READ_PATH_V1 =
  "/v1/gov/parliament/attempts/{governance_attempt_id}";
export const PARLIAMENT_TRANSITION_DRAFT_PATH_V1 =
  "/v1/gov/parliament/transitions/draft";
export const PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1 =
  "iroha.governance.parliament.attempt.create.v1";
export const PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1 =
  "iroha.governance.parliament.transition.submit.v1";
export const PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1 = 16 * 1024 * 1024;
export const PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 = 16;
// Mirrors Rust `MAX_PARLIAMENT_BODY_TARGET_SEATS_V1`: the bound on a body's target and
// original seat counts and on every count derived from them (endorsements and quorum).
const MAX_BODY_TARGET_SEATS = 1_000;
// Mirrors Rust `MAX_PARLIAMENT_SORTITION_RETRIES_V1`: the bound on a body election
// attempt sequence.
const MAX_SORTITION_RETRIES = 16;
const PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 = 1;

// Closed first-release ProposalKind inventory in Norito index order.
export const PARLIAMENT_PROPOSAL_KINDS_V1 = Object.freeze([
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
]);

// Closed ContractLifecycleGovernance action inventory in wire-tag order.
export const PARLIAMENT_CONTRACT_LIFECYCLE_ACTIONS_V1 = Object.freeze([
  "Activate",
  "Deactivate",
  "OfferOwnership",
  "CancelOwnershipOffer",
  "AcceptParliamentOwnership",
  "CompleteEmergencyHoldRetrospective",
]);

export const PARLIAMENT_PUBLIC_TRANSITIONS_V1 = Object.freeze([
  [0, "EscalateRisk", true, 0],
  [1, "CompleteQualification", false, 1],
  [2, "RegisterSortitionRequest", true, 2],
  [3, "ConsumeSortitionPulseBatch", true, 3],
  [4, "BeginInvitationAcceptance", true, 4],
  [5, "FailBodyElectionNoRoster", true, 5],
  [6, "SealBodyRoster", true, 6],
  [7, "AdvanceBodyPhase", true, 7],
  [8, "RecordAttemptAbsence", true, 8],
  [9, "EndorsePublicFinding", true, 9],
  [10, "RecordInvitationResponse", true, 13],
  [11, "FailPublicFindingNoResult", true, 14],
  [12, "RegisterInitialSortition", false, 15],
].map(([noritoIndex, jsonTag, jsonPayloadRequired, eventKindIndex]) =>
  Object.freeze({ noritoIndex, jsonTag, jsonPayloadRequired, eventKindIndex }),
));

// These outcomes are exported for read/audit decoding only. The transition
// builder below deliberately accepts only PARLIAMENT_PUBLIC_TRANSITIONS_V1.
export const PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOMES_V1 = Object.freeze([
  [0, "Enacted", false, "MarkEnacted", 10],
  [1, "Superseded", true, "MarkSuperseded", 11],
  [2, "ExecutionFailed", true, "MarkExecutionFailed", 12],
].map(([noritoIndex, jsonTag, jsonPayloadRequired, eventKind, eventKindIndex]) =>
  Object.freeze({
    noritoIndex,
    jsonTag,
    jsonPayloadRequired,
    eventKind,
    eventKindIndex,
  }),
));

export const PARLIAMENT_NO_RESULT_KINDS_V1 = Object.freeze([
  [0, "PublicFindingQuorumUnreachable"],
  [1, "PublicFindingDeadlineExpired"],
  [2, "SortitionRetriesExhausted"],
  [3, "ConfirmationJuryCapacityUnavailable"],
  [4, "RandomnessRedrawBudgetExhausted"],
].map(([noritoIndex, jsonTag]) => Object.freeze({ noritoIndex, jsonTag })));

export const PARLIAMENT_BODY_STATE_FIELDS_V1 = Object.freeze([
  "body",
  "body_instance_id",
  "status",
  "public_finding_opened_at_height",
  "public_finding_phase_blocks",
  "public_finding_deadline_height",
  "no_result_kind",
  "no_result_height",
]);

export const PARLIAMENT_CERTIFICATE_BODY_BINDING_FIELDS_V1 = Object.freeze([
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
]);

export const PARLIAMENT_PUBLIC_FINDING_CERTIFICATE_FIELDS_V1 = Object.freeze([
  "endorsement_root",
  "endorsing_assignments",
  "endorsements",
  "quorum",
]);

const PUBLIC_TRANSITIONS_BY_TAG = new Map(
  PARLIAMENT_PUBLIC_TRANSITIONS_V1.map((entry) => [entry.jsonTag, entry]),
);
const TRANSITION_PAYLOAD_FIELDS = new Map([
  ["EscalateRisk", ["target"]],
  ["RegisterSortitionRequest", ["requests"]],
  ["ConsumeSortitionPulseBatch", ["request_ids", "beacon_session_id", "pulse_height", "pulse_id"]],
  ["BeginInvitationAcceptance", ["election_attempt_id"]],
  ["FailBodyElectionNoRoster", ["election_attempt_id"]],
  ["SealBodyRoster", ["election_attempt_id"]],
  ["AdvanceBodyPhase", ["body_instance_id", "target"]],
  ["RecordAttemptAbsence", ["body_instance_id", "assignment_id"]],
  ["EndorsePublicFinding", ["body_instance_id", "result_root"]],
  ["RecordInvitationResponse", ["election_attempt_id", "body", "decision"]],
  ["FailPublicFindingNoResult", ["body_instance_id"]],
]);
const ATTEMPT_RESPONSE_FIELDS = [
  "version", "proposal_content_id", "governance_attempt_id", "tx_instructions",
];
const TRANSITION_RESPONSE_FIELDS = [
  "version", "governance_attempt_id", "transition_kind", "transition_digest",
  "tx_instructions",
];
const READ_RESPONSE_FIELDS = [
  "version", "current_height", "attempt", "policy_version", "required_bodies",
  "body_states", "certificate", "terminal_height", "execution_failure_root", "superseding_head",
  "state_payload_hex",
];
const ATTEMPT_FIELDS = [
  "id", "proposal_content_id", "sequence", "risk_tier", "stage", "status",
];
const CERTIFICATE_FIELDS = [
  "proposal_content_id", "governance_attempt_id", "governance_attempt_sequence",
  "risk_tier", "body_bindings", "policy_version", "effect_preimage_hash",
  "expected_head", "certified_at_height", "enact_at_height",
];
const SORTITION_REQUEST_FIELDS = [
  "id", "governance_attempt_id", "body_election_attempt_id", "body",
  "candidate_root", "candidate_count", "target_seats", "request_height",
  "pulse_height", "beacon_session_id",
];
/** Canonical presentation order for first-release Parliament bodies. */
export const PARLIAMENT_CANONICAL_BODY_ORDER_V1 = Object.freeze([
  "rules-committee", "agenda-council", "interest-panel", "review-panel",
  "coordination-council", "mpc-committee", "fma-committee",
  "oversight-committee", "policy-jury", "confirmation-jury",
]);
const PRIVATE_KEY_FIELDS = new Set([
  "private_key", "privateKey", "seed", "mnemonic", "private_key_seed",
]);
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const LOWER_HEX_BYTES = /^(?:[0-9a-f]{2})+$/u;

/** Replace the sole read-path placeholder after exact non-zero ID validation. */
export function parliamentAttemptReadPathV1(governanceAttemptId) {
  return PARLIAMENT_ATTEMPT_READ_PATH_V1.replace(
    "{governance_attempt_id}",
    canonicalId(governanceAttemptId, "governanceAttemptId"),
  );
}

/** Build the exact closed V1 attempt-draft request body. */
export function buildParliamentAttemptDraftRequestV1(proposal, attemptSequence) {
  rejectPrivateKeyFields(proposal, "proposal");
  const tagged = normalizeGovernanceProposalWireV1(proposal, "proposal");
  return {
    version: PARLIAMENT_API_VERSION_V1,
    proposal: tagged,
    attempt_sequence: uint(
      attemptSequence,
      PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
      "attemptSequence",
    ),
  };
}

/** Build the exact closed V1 public lifecycle-transition draft request body. */
export function buildParliamentTransitionDraftRequestV1(
  governanceAttemptId,
  transition,
) {
  const tagged = normalizePublicTransition(transition);
  return {
    version: PARLIAMENT_API_VERSION_V1,
    governance_attempt_id: canonicalId(governanceAttemptId, "governanceAttemptId"),
    transition: tagged,
  };
}

/** Strictly admit and bind an attempt-draft response. */
export function normalizeParliamentAttemptDraftResponseV1(
  value,
  { expectedProposalContentId, expectedGovernanceAttemptId },
) {
  const root = exactObject(value, ATTEMPT_RESPONSE_FIELDS, "Parliament attempt draft response");
  version(root.version);
  const proposalContentId = canonicalId(root.proposal_content_id, "proposal_content_id");
  const governanceAttemptId = canonicalId(root.governance_attempt_id, "governance_attempt_id");
  if (proposalContentId !== canonicalId(expectedProposalContentId, "expectedProposalContentId")) {
    throw new Error("proposal_content_id differs from the exact request binding");
  }
  if (governanceAttemptId !== canonicalId(expectedGovernanceAttemptId, "expectedGovernanceAttemptId")) {
    throw new Error("governance_attempt_id differs from the exact request binding");
  }
  return {
    version: PARLIAMENT_API_VERSION_V1,
    proposal_content_id: proposalContentId,
    governance_attempt_id: governanceAttemptId,
    tx_instructions: [instruction(root.tx_instructions, PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1)],
  };
}

/** Strictly admit and bind a transition-draft response. */
export function normalizeParliamentTransitionDraftResponseV1(
  value,
  { expectedGovernanceAttemptId, expectedTransitionKind, expectedTransitionDigest },
) {
  if (!PUBLIC_TRANSITIONS_BY_TAG.has(expectedTransitionKind)) {
    throw new TypeError("expectedTransitionKind is not a submit-able Parliament transition");
  }
  const expectedDigest = bytes(expectedTransitionDigest, 32, "expectedTransitionDigest", true);
  const root = exactObject(value, TRANSITION_RESPONSE_FIELDS, "Parliament transition draft response");
  version(root.version);
  const attemptId = canonicalId(root.governance_attempt_id, "governance_attempt_id");
  if (attemptId !== canonicalId(expectedGovernanceAttemptId, "expectedGovernanceAttemptId")) {
    throw new Error("governance_attempt_id differs from the exact request binding");
  }
  const kindObject = exactObject(root.transition_kind, ["kind"], "transition_kind");
  if (!PUBLIC_TRANSITIONS_BY_TAG.has(kindObject.kind)) {
    throw new TypeError("transition_kind is automatic, unknown, or consensus-owned");
  }
  if (kindObject.kind !== expectedTransitionKind) {
    throw new Error("transition_kind differs from the exact request binding");
  }
  const digest = bytes(root.transition_digest, 32, "transition_digest", true);
  if (!digest.equals(expectedDigest)) {
    throw new Error("transition_digest differs from the exact request binding");
  }
  return {
    version: PARLIAMENT_API_VERSION_V1,
    governance_attempt_id: attemptId,
    transition_kind: { kind: kindObject.kind },
    transition_digest: [...digest],
    tx_instructions: [instruction(root.tx_instructions, PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1)],
  };
}

/** Strictly admit one bounded attempt-read projection and its certificate. */
export function normalizeParliamentAttemptReadResponseV1(value, expectedGovernanceAttemptId) {
  const root = exactObject(value, READ_RESPONSE_FIELDS, "Parliament attempt read response");
  version(root.version);
  unsigned(root.current_height, "current_height");
  optionalUnsigned(root.terminal_height, "terminal_height");
  optionalBytes32(root.execution_failure_root, "execution_failure_root");
  const attempt = exactObject(root.attempt, ATTEMPT_FIELDS, "attempt");
  const attemptId = canonicalId(attempt.id, "attempt.id");
  if (attemptId !== canonicalId(expectedGovernanceAttemptId, "expectedGovernanceAttemptId")) {
    throw new Error("attempt.id differs from the requested canonical identifier");
  }
  const proposalContentId = canonicalId(
    attempt.proposal_content_id,
    "attempt.proposal_content_id",
  );
  const attemptSequence = uint(
    attempt.sequence,
    PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    "attempt.sequence",
  );
  const riskTier = validateTaggedUnit(attempt.risk_tier, "tier", ["Routine", "Standard", "Constitutional", "Emergency"], "attempt.risk_tier");
  validateTaggedUnit(attempt.stage, "stage", [
    "Qualification", "Rules", "Agenda", "Interest", "Review", "Coordination",
    "Mpc", "Fma", "Oversight", "PolicyJury", "ConfirmationJury",
    "Certification", "Enactment",
  ], "attempt.stage");
  validateTaggedUnit(attempt.status, "status", [
    "Active", "Certified", "Rejected", "Enacted", "Superseded", "ExecutionFailed",
  ], "attempt.status");
  const policyVersion = unsigned(root.policy_version, "policy_version");
  if (BigInt(policyVersion) !== BigInt(PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1)) {
    throw new TypeError("policy_version must equal the first-release Parliament policy version");
  }
  const requiredBodies = validateRequiredBodies(root.required_bodies);
  const bodyStates = validateBodyStates(root.body_states, requiredBodies);
  if (root.certificate !== null) {
    validateCertificate(root.certificate, {
      attemptId,
      proposalContentId,
      attemptSequence,
      riskTier,
      policyVersion,
      requiredBodies,
      bodyStates,
    });
  }
  if (root.superseding_head !== null) {
    validateExpectedHead(root.superseding_head, "superseding_head");
  }
  const statePayloadHex = canonicalHex(root.state_payload_hex, "state_payload_hex");
  const stateBytes = Buffer.from(statePayloadHex, "hex");
  if (stateBytes.length > PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1) {
    throw new RangeError("state_payload_hex exceeds the 16 MiB Parliament bound");
  }
  validateNoritoFrame(stateBytes, {
    context: "Parliament attempt state_payload_hex",
    requireNonEmptyPayload: true,
  });
  return { ...root, attempt: { ...attempt }, state_payload_hex: statePayloadHex };
}

function validateRequiredBodies(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10) {
    throw new TypeError("required_bodies must contain one through ten exact body projections");
  }
  let previousBodyIndex = -1;
  return value.map((raw, index) => {
    const context = `required_bodies[${index}]`;
    const entry = exactObject(raw, ["body", "decision_mode"], context);
    const bodyIndex = PARLIAMENT_CANONICAL_BODY_ORDER_V1.indexOf(entry.body);
    if (bodyIndex < 0 || bodyIndex <= previousBodyIndex) {
      throw new TypeError("required_bodies must use strict canonical body order");
    }
    previousBodyIndex = bodyIndex;
    const decisionMode = validateTaggedUnit(
      entry.decision_mode,
      "mode",
      ["PublicFinding", "HiddenBindingBallot"],
      `${context}.decision_mode`,
    );
    const expectedMode = entry.body === "policy-jury" || entry.body === "confirmation-jury"
      ? "HiddenBindingBallot"
      : "PublicFinding";
    if (decisionMode !== expectedMode) {
      throw new TypeError(`${context}.decision_mode differs from the body protocol`);
    }
    return { body: entry.body, decisionMode };
  });
}

function validateBodyStates(value, requiredBodies) {
  if (!Array.isArray(value) || value.length !== requiredBodies.length || value.length < 1 || value.length > 10) {
    throw new TypeError("body_states must exactly match the required body pipeline");
  }
  const admittedStatuses = [
    "AwaitingSortition", "AcceptingInvitations", "RosterSealed", "Deliberating",
    "Balloting", "Approved", "Rejected", "NoQuorum", "NoResult", "Superseded",
  ];
  const admittedPhases = [
    "Orientation", "Evidence", "Questions", "Responses", "Deliberation", "Reflection", "Vote",
  ];
  const noResultKinds = new Set(PARLIAMENT_NO_RESULT_KINDS_V1.map(({ jsonTag }) => jsonTag));
  return value.map((raw, index) => {
    const context = `body_states[${index}]`;
    const body = exactObject(raw, PARLIAMENT_BODY_STATE_FIELDS_V1, context);
    if (body.body !== requiredBodies[index].body) {
      throw new Error(`${context}.body differs from required_bodies order`);
    }
    if ((body.body_instance_id === null) !== (body.status === null)) {
      throw new TypeError(`${context} must bind body_instance_id and status together`);
    }
    if (body.body_instance_id !== null) canonicalId(body.body_instance_id, `${context}.body_instance_id`);
    let status = null;
    if (body.status !== null) {
      const tagged = plainObject(body.status, `${context}.status`);
      status = tagged.status;
      if (!admittedStatuses.includes(status)) throw new TypeError(`${context}.status is unknown`);
      exactObject(tagged, status === "Deliberating" ? ["status", "phase"] : ["status"], `${context}.status`);
      if (status === "Deliberating") {
        validateTaggedUnit(tagged.phase, "phase", admittedPhases, `${context}.status.phase`);
      }
    }
    const opened = body.public_finding_opened_at_height;
    const phaseBlocks = body.public_finding_phase_blocks;
    const deadline = body.public_finding_deadline_height;
    if ((opened === null) !== (phaseBlocks === null) || (opened === null) !== (deadline === null)) {
      throw new TypeError(`${context} must expose the complete public-finding schedule or none`);
    }
    if (opened !== null) {
      unsigned(opened, `${context}.public_finding_opened_at_height`);
      uint(phaseBlocks, Number.MAX_SAFE_INTEGER, `${context}.public_finding_phase_blocks`, 1);
      unsigned(deadline, `${context}.public_finding_deadline_height`);
      if (BigInt(deadline) !== BigInt(opened) + BigInt(phaseBlocks)) {
        throw new Error(`${context} public-finding deadline does not match its frozen schedule`);
      }
    }
    if ((body.no_result_kind === null) !== (body.no_result_height === null)) {
      throw new TypeError(`${context} must bind no-result kind and height together`);
    }
    if (body.no_result_kind !== null) {
      const kind = validateTaggedUnit(
        body.no_result_kind,
        "reason",
        [...noResultKinds],
        `${context}.no_result_kind`,
      );
      unsigned(body.no_result_height, `${context}.no_result_height`);
      if (status !== "NoResult") throw new Error(`${context} no-result facts require NoResult status`);
      const publicFailure = kind === "PublicFindingQuorumUnreachable" || kind === "PublicFindingDeadlineExpired";
      const privateBody = body.body === "policy-jury" || body.body === "confirmation-jury";
      if (publicFailure === privateBody) {
        throw new Error(`${context} no-result kind does not match the body's decision protocol`);
      }
    }
    return {
      body: body.body,
      bodyInstanceId: body.body_instance_id,
      status,
    };
  });
}

function normalizePublicTransition(value) {
  rejectPrivateKeyFields(value, "transition");
  const root = plainObject(value, "transition");
  const tag = root.transition;
  if (typeof tag !== "string" || !PUBLIC_TRANSITIONS_BY_TAG.has(tag)) {
    throw new TypeError("transition tag is unknown, removed, or automatic-only");
  }
  const layout = PUBLIC_TRANSITIONS_BY_TAG.get(tag);
  exactObject(root, layout.jsonPayloadRequired ? ["transition", "payload"] : ["transition"], "transition");
  if (layout.jsonPayloadRequired) {
    exactObject(root.payload, TRANSITION_PAYLOAD_FIELDS.get(tag), `transition.${tag}.payload`);
    validateTransitionPayload(tag, root.payload);
  }
  return root;
}

function validateTransitionPayload(tag, payload) {
  const idFields = [
    "assignment_id", "beacon_session_id", "body_instance_id", "election_attempt_id",
    "pulse_id",
  ];
  for (const field of idFields) {
    if (Object.hasOwn(payload, field)) canonicalId(payload[field], `${tag}.${field}`);
  }
  if (Object.hasOwn(payload, "pulse_height")) {
    unsigned(payload.pulse_height, `${tag}.pulse_height`);
  }
  if (Object.hasOwn(payload, "result_root")) bytes(payload.result_root, 32, `${tag}.result_root`, true);
  if (Object.hasOwn(payload, "request_ids")) {
    validateStrictIdList(payload.request_ids, `${tag}.request_ids`);
  }
}

/**
 * Validate one complete GovernanceCertificateV1 embedded outside an attempt response.
 *
 * The returned object retains the exact canonical JSON wire shape. Certificate
 * identifiers are content hashes computed by Rust; callers must bind those
 * separately because this JavaScript boundary does not reimplement Norito
 * fingerprinting. Only public-finding bodies are admitted: a binding for a private-jury
 * body is rejected until the anonymous-ballot result binding is supported.
 */
export function normalizeParliamentGovernanceCertificateV1(value) {
  return validateCertificate(value);
}

function validateCertificate(value, expectations = {}) {
  const certificate = exactObject(value, CERTIFICATE_FIELDS, "certificate");
  const proposalContentId = canonicalId(
    certificate.proposal_content_id,
    "certificate.proposal_content_id",
  );
  const attemptId = canonicalId(
    certificate.governance_attempt_id,
    "certificate.governance_attempt_id",
  );
  if (expectations.attemptId !== undefined && attemptId !== expectations.attemptId) {
    throw new Error("certificate.governance_attempt_id differs from attempt.id");
  }
  if (expectations.proposalContentId !== undefined
    && proposalContentId !== expectations.proposalContentId) {
    throw new Error("certificate.proposal_content_id differs from attempt.proposal_content_id");
  }
  const attemptSequence = uint(
    certificate.governance_attempt_sequence,
    PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    "certificate.governance_attempt_sequence",
  );
  if (expectations.attemptSequence !== undefined
    && attemptSequence !== expectations.attemptSequence) {
    throw new Error("certificate.governance_attempt_sequence differs from attempt.sequence");
  }
  const riskTier = validateNativeCertificateUnit(
    certificate.risk_tier,
    "tier",
    ["Routine", "Standard", "Constitutional", "Emergency"],
    "certificate.risk_tier",
  );
  if (expectations.riskTier !== undefined && riskTier !== expectations.riskTier) {
    throw new Error("certificate.risk_tier differs from attempt.risk_tier");
  }
  if (!Array.isArray(certificate.body_bindings) || certificate.body_bindings.length < 1 || certificate.body_bindings.length > 10) {
    throw new TypeError("certificate.body_bindings must contain one through ten bindings");
  }
  const certifiedAtHeight = unsigned(
    certificate.certified_at_height,
    "certificate.certified_at_height",
  );
  const enactAtHeight = unsigned(certificate.enact_at_height, "certificate.enact_at_height");
  if (
    BigInt(certifiedAtHeight) === 0n ||
    BigInt(enactAtHeight) <= BigInt(certifiedAtHeight)
  ) {
    throw new TypeError("certificate enactment height must follow a positive certified height");
  }
  const bindings = certificate.body_bindings.map((binding, index) =>
    validateBodyCertificateBinding(binding, index, attemptId, certifiedAtHeight));
  const latestBodyResultHeight = bindings.reduce(
    (latest, binding) => BigInt(binding.resultHeight) > latest
      ? BigInt(binding.resultHeight)
      : latest,
    0n,
  );
  if (BigInt(certifiedAtHeight) !== latestBodyResultHeight) {
    throw new TypeError("certificate.certified_at_height must equal the latest body result height");
  }
  for (let index = 1; index < bindings.length; index += 1) {
    if (bindings[index - 1].bodyIndex >= bindings[index].bodyIndex) {
      throw new TypeError("certificate.body_bindings must use strict canonical body order");
    }
  }
  for (const field of ["bodyInstanceId", "electionAttemptId", "sortitionRequestId"]) {
    const values = bindings.map((binding) => binding[field]);
    if (new Set(values).size !== values.length) {
      throw new TypeError(`certificate.body_bindings reuse ${field}`);
    }
  }
  if (expectations.requiredBodies !== undefined) {
    if (bindings.length !== expectations.requiredBodies.length) {
      throw new TypeError("certificate.body_bindings must exactly match required_bodies");
    }
    for (const [index, binding] of bindings.entries()) {
      if (binding.body !== expectations.requiredBodies[index].body) {
        throw new TypeError(
          `certificate.body_bindings[${index}] differs from required_bodies`,
        );
      }
    }
  }
  if (expectations.bodyStates !== undefined) {
    for (const [index, binding] of bindings.entries()) {
      if (binding.bodyInstanceId !== expectations.bodyStates[index].bodyInstanceId) {
        throw new TypeError(
          `certificate.body_bindings[${index}].body_instance_id differs from body_states`,
        );
      }
    }
  }
  bytes(certificate.effect_preimage_hash, 32, "certificate.effect_preimage_hash", true);
  validateExpectedHead(certificate.expected_head, "certificate.expected_head");
  const policyVersion = unsigned(certificate.policy_version, "certificate.policy_version");
  if (BigInt(policyVersion) !== BigInt(PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1)) {
    throw new TypeError(
      "certificate.policy_version must equal the first-release Parliament policy version",
    );
  }
  if (expectations.policyVersion !== undefined
    && BigInt(policyVersion) !== BigInt(expectations.policyVersion)) {
    throw new Error("certificate.policy_version differs from the attempt projection");
  }
  return certificate;
}

function validateBodyCertificateBinding(value, index, governanceAttemptId, certifiedAtHeight) {
  const context = `certificate.body_bindings[${index}]`;
  const binding = exactObject(value, PARLIAMENT_CERTIFICATE_BODY_BINDING_FIELDS_V1, context);
  const seats = uint(
    binding.original_seats,
    MAX_BODY_TARGET_SEATS,
    `${context}.original_seats`,
    1,
  );
  for (const field of [
    "body_instance_id", "election_attempt_id", "sortition_request_id",
    "beacon_session_id", "beacon_pulse_id",
  ]) canonicalId(binding[field], `${context}.${field}`);
  for (const field of ["roster_root", "assignment_root", "result_root"]) {
    bytes(binding[field], 32, `${context}.${field}`, true);
  }
  uint(
    binding.election_attempt_sequence,
    MAX_SORTITION_RETRIES,
    `${context}.election_attempt_sequence`,
  );
  const resultHeight = unsigned(binding.result_height, `${context}.result_height`);
  const sortitionRequest = validateSortitionRequest(
    binding.sortition_request,
    binding,
    governanceAttemptId,
    `${context}.sortition_request`,
  );
  if (
    seats > sortitionRequest.targetSeats ||
    seats > sortitionRequest.candidateCount
  ) {
    throw new TypeError(`${context}.original_seats exceeds its sortition bounds`);
  }
  if (
    BigInt(resultHeight) <= sortitionRequest.pulseHeight ||
    BigInt(resultHeight) > BigInt(certifiedAtHeight)
  ) {
    throw new TypeError(`${context}.result_height violates the certificate lifecycle`);
  }
  const bodyIndex = PARLIAMENT_CANONICAL_BODY_ORDER_V1.indexOf(binding.body);
  if (bodyIndex < 0) throw new TypeError(`${context}.body is unknown`);
  if (binding.body === "policy-jury" || binding.body === "confirmation-jury") {
    // TODO(parliament anonymous ballot, P4): validate the anonymous body-result binding
    // (BallotClosureRecordV1 + result_root) for private-jury bodies here; until it lands
    // this SDK admits no certificate that contains a private-jury body.
    throw new TypeError(
      `${context} private-jury result binding is not admitted until the anonymous-ballot result binding is supported`,
    );
  }
  if (binding.public_finding === null || binding.ballot !== null) {
    throw new TypeError(`${context} public body must carry public_finding only`);
  }
  validatePublicFinding(binding.public_finding, seats, `${context}.public_finding`);
  return {
    body: binding.body,
    bodyIndex,
    bodyInstanceId: binding.body_instance_id,
    electionAttemptId: binding.election_attempt_id,
    resultHeight,
    sortitionRequestId: binding.sortition_request_id,
  };
}

function validateSortitionRequest(value, binding, governanceAttemptId, context) {
  const request = exactObject(value, SORTITION_REQUEST_FIELDS, context);
  const id = canonicalId(request.id, `${context}.id`);
  const requestAttemptId = canonicalId(
    request.governance_attempt_id,
    `${context}.governance_attempt_id`,
  );
  const electionAttemptId = canonicalId(
    request.body_election_attempt_id,
    `${context}.body_election_attempt_id`,
  );
  const beaconSessionId = canonicalId(
    request.beacon_session_id,
    `${context}.beacon_session_id`,
  );
  bytes(request.candidate_root, 32, `${context}.candidate_root`, true);
  const candidateCount = uint(
    request.candidate_count,
    0xffff_ffff,
    `${context}.candidate_count`,
    1,
  );
  const targetSeats = uint(
    request.target_seats,
    MAX_BODY_TARGET_SEATS,
    `${context}.target_seats`,
    1,
  );
  const requestHeight = BigInt(unsigned(request.request_height, `${context}.request_height`));
  const pulseHeight = BigInt(unsigned(request.pulse_height, `${context}.pulse_height`));
  if (requestHeight === 0n || pulseHeight <= requestHeight) {
    throw new TypeError(`${context} sortition heights must be positive and strictly ordered`);
  }
  if (
    id !== binding.sortition_request_id ||
    requestAttemptId !== governanceAttemptId ||
    electionAttemptId !== binding.election_attempt_id ||
    request.body !== binding.body ||
    beaconSessionId !== binding.beacon_session_id
  ) {
    throw new TypeError(`${context} differs from its repeated certificate bindings`);
  }
  return { candidateCount, pulseHeight, targetSeats };
}

function validatePublicFinding(value, originalSeats, context) {
  const finding = exactObject(value, PARLIAMENT_PUBLIC_FINDING_CERTIFICATE_FIELDS_V1, context);
  bytes(finding.endorsement_root, 32, `${context}.endorsement_root`, true);
  validateStrictIdList(finding.endorsing_assignments, `${context}.endorsing_assignments`);
  const endorsements = uint(
    finding.endorsements,
    MAX_BODY_TARGET_SEATS,
    `${context}.endorsements`,
    1,
  );
  const quorum = uint(
    finding.quorum,
    MAX_BODY_TARGET_SEATS,
    `${context}.quorum`,
    1,
  );
  const expectedQuorum = Math.floor((2 * originalSeats + 2) / 3);
  if (endorsements !== finding.endorsing_assignments.length || endorsements !== quorum || quorum !== expectedQuorum) {
    throw new Error(`${context} must contain the exact canonical 2/3 supporter list`);
  }
}

function validateExpectedHead(value, context) {
  const root = exactObject(value, ["state", "head"], context);
  if (root.state === "Absent") {
    const head = exactObject(root.head, ["subject_id"], `${context}.head`);
    bytes(head.subject_id, 32, `${context}.head.subject_id`, true);
  } else if (root.state === "Present") {
    const head = exactObject(root.head, ["subject_id", "version", "head_root"], `${context}.head`);
    bytes(head.subject_id, 32, `${context}.head.subject_id`, true);
    nonZeroU64(head.version, `${context}.head.version`);
    bytes(head.head_root, 32, `${context}.head.head_root`, true);
  } else {
    throw new TypeError(`${context}.state must be Absent or Present`);
  }
}

function instruction(value, expectedWireId) {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new TypeError("Parliament draft response must contain exactly one instruction");
  }
  const draft = exactObject(value[0], ["wire_id", "payload_hex"], "tx_instructions[0]");
  if (draft.wire_id !== expectedWireId) throw new Error("instruction draft has the wrong wire_id");
  return { wire_id: expectedWireId, payload_hex: canonicalHex(draft.payload_hex, "payload_hex") };
}

function validateStrictIdList(value, context) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 1_000) {
    throw new RangeError(`${context} must contain one through 1000 identifiers`);
  }
  let previous = null;
  for (const [index, item] of value.entries()) {
    const current = canonicalId(item, `${context}[${index}]`);
    if (previous !== null && previous >= current) {
      throw new TypeError(`${context} must be strictly increasing and distinct`);
    }
    previous = current;
  }
}

function validateTaggedUnit(value, tagField, accepted, context) {
  const root = exactObject(value, [tagField], context);
  if (!accepted.includes(root[tagField])) throw new TypeError(`${context}.${tagField} is unknown`);
  return root[tagField];
}

function exactObject(value, fields, context) {
  const root = plainObject(value, context);
  const actual = Object.keys(root);
  if (actual.length !== fields.length || actual.some((key) => !fields.includes(key))) {
    throw new TypeError(`${context} contains unknown, aliased, or missing fields`);
  }
  return root;
}

function plainObject(value, context) {
  const prototype = value === null || typeof value !== "object"
    ? undefined
    : Object.getPrototypeOf(value);
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (prototype !== Object.prototype && prototype !== null)
  ) {
    throw new TypeError(`${context} must be a plain object`);
  }
  return value;
}

function canonicalId(value, context) {
  if (typeof value !== "string" || !LOWER_HEX_32.test(value) || /^0{64}$/u.test(value)) {
    throw new TypeError(`${context} must be exactly 64 lowercase non-zero hexadecimal characters`);
  }
  return value;
}

function canonicalHex(value, context) {
  if (typeof value !== "string" || !LOWER_HEX_BYTES.test(value)) {
    throw new TypeError(`${context} must be non-empty complete lowercase hexadecimal bytes`);
  }
  return value;
}

function validateNativeCertificateUnit(value, tagField, accepted, context) {
  const root = exactObject(value, [tagField, "details"], context);
  if (!accepted.includes(root[tagField]) || root.details !== null) {
    throw new TypeError(`${context} must contain the native unit variant and null details`);
  }
  return root[tagField];
}

function bytes(value, length, context, nonZero = false) {
  const buffer = Buffer.isBuffer(value)
    ? Buffer.from(value)
    : Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
      ? Buffer.from(value)
      : null;
  if (buffer === null || buffer.length !== length) {
    throw new TypeError(`${context} must contain exactly ${length} bytes`);
  }
  if (nonZero && buffer.every((byte) => byte === 0)) throw new TypeError(`${context} must be non-zero`);
  return buffer;
}

function uint(value, maximum, context, minimum = 0) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${context} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function unsigned(value, context) {
  if ((typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === "bigint" && value >= 0n)) return value;
  throw new TypeError(`${context} must be a losslessly decoded unsigned integer`);
}

function nonZeroU64(value, context) {
  if (
    (typeof value !== "number" || !Number.isSafeInteger(value))
    && typeof value !== "bigint"
  ) {
    throw new TypeError(`${context} must be a lossless unsigned 64-bit integer`);
  }
  const normalized = BigInt(value);
  if (normalized <= 0n || normalized > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`${context} must be within 1..=18446744073709551615`);
  }
  return normalized;
}

function optionalUnsigned(value, context) {
  if (value !== null) unsigned(value, context);
}

function optionalBytes32(value, context) {
  if (value !== null) bytes(value, 32, context, true);
}

function version(value) {
  if (value !== PARLIAMENT_API_VERSION_V1) throw new TypeError("unsupported Parliament API version");
}

function rejectPrivateKeyFields(value, context) {
  const pending = [[value, context]];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const [current, path] = pending.pop();
    if (current === null || typeof current !== "object") continue;
    if (seen.has(current)) continue;
    seen.add(current);
    if (Array.isArray(current)) {
      current.forEach((item, index) => pending.push([item, `${path}[${index}]`]));
      continue;
    }
    for (const [key, item] of Object.entries(current)) {
      if (PRIVATE_KEY_FIELDS.has(key)) throw new TypeError(`${path}.${key} is forbidden; sign drafts locally`);
      pending.push([item, `${path}.${key}`]);
    }
  }
}
