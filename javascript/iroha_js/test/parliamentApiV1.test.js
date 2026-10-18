// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2";

import { crc64Xz } from "../src/crc64Xz.js";
import {
  AccountAddress,
  AccountAddressError,
  AccountAddressErrorCode,
  NetworkId,
  PARLIAMENT_API_VERSION_V1,
  PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
  PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
  PARLIAMENT_ATTEMPT_READ_PATH_V1,
  PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
  PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
  PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOMES_V1,
  PARLIAMENT_CANONICAL_BODY_ORDER_V1,
  PARLIAMENT_BODY_STATE_FIELDS_V1,
  PARLIAMENT_CERTIFICATE_BODY_BINDING_FIELDS_V1,
  PARLIAMENT_CONTRACT_LIFECYCLE_ACTIONS_V1,
  PARLIAMENT_NO_RESULT_KINDS_V1,
  PARLIAMENT_PROPOSAL_KINDS_V1,
  PARLIAMENT_PUBLIC_FINDING_CERTIFICATE_FIELDS_V1,
  PARLIAMENT_PUBLIC_TRANSITIONS_V1,
  PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
  PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
  ToriiClient,
  buildParliamentAttemptDraftRequestV1,
  buildParliamentTransitionDraftRequestV1,
  normalizeParliamentAttemptDraftResponseV1,
  normalizeParliamentAttemptReadResponseV1,
  normalizeParliamentTransitionDraftResponseV1,
  parliamentAttemptReadPathV1,
} from "../src/index.js";
import { normalizeParliamentGovernanceCertificateV1 } from "../src/parliamentApiV1.js";

const ATTEMPT_ID = "ab".repeat(32);
const PROPOSAL_ID = "cd".repeat(32);
const ROOT = Object.freeze(Array(32).fill(0x55));
const ID = (byte) => byte.toString(16).padStart(2, "0").repeat(32);
const CONTRACT_ADDRESS =
  "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
const RUST_INVALID_ZERO_KEY_ACCOUNT =
  ["sora", "uﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"].join("");
const NETWORK_ID = NetworkId.fromBytes(Uint8Array.from([
  ...Array(31).fill(0),
  1,
])).toString();
const ACCOUNTS = Object.freeze([
  "treasury",
  "vault",
  "recipient-a",
  "recipient-b",
  "recipient-c",
  "recipient-d",
].map(fixtureAccountId));
const fixturePath = fileURLToPath(
  new URL("../../../fixtures/governance/parliament_api_v1.json", import.meta.url),
);

test("shared Parliament fixture pins routes, all transition inventories, and certificate supporters", () => {
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.equal(fixture.schema, "iroha.governance.parliament.api_fixture.v1");
  assert.equal(fixture.api_version, PARLIAMENT_API_VERSION_V1);
  assert.deepEqual(fixture.routes, {
    attempt_draft: PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
    attempt_read: PARLIAMENT_ATTEMPT_READ_PATH_V1,
    transition_draft: PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
  });
  assert.deepEqual(fixture.wire_ids, {
    attempt_create: PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
    transition_submit: PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
  });
  assert.deepEqual(fixture.proposal_kinds, PARLIAMENT_PROPOSAL_KINDS_V1);
  assert.deepEqual(
    fixture.contract_lifecycle_actions,
    PARLIAMENT_CONTRACT_LIFECYCLE_ACTIONS_V1,
  );
  assert.deepEqual(fixture.limits, {
    attempt_state_bytes: PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
    governance_attempt_sequence_max: PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
  });
  assert.equal(fixture.public_transitions.length, PARLIAMENT_PUBLIC_TRANSITIONS_V1.length);
  for (const [index, layout] of PARLIAMENT_PUBLIC_TRANSITIONS_V1.entries()) {
    const entry = fixture.public_transitions[index];
    assert.deepEqual(
      [entry.norito_index, entry.json_tag, entry.json_payload === "required", entry.event_kind_index],
      [layout.noritoIndex, layout.jsonTag, layout.jsonPayloadRequired, layout.eventKindIndex],
    );
    buildParliamentTransitionDraftRequestV1(
      ATTEMPT_ID,
      transitionFixture(layout.jsonTag),
    );
  }
  assert.equal(
    fixture.automatic_execution_outcomes.length,
    PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOMES_V1.length,
  );
  for (const [index, outcome] of PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOMES_V1.entries()) {
    const entry = fixture.automatic_execution_outcomes[index];
    assert.deepEqual(
      [entry.norito_index, entry.json_tag, entry.event_kind, entry.event_kind_index],
      [outcome.noritoIndex, outcome.jsonTag, outcome.eventKind, outcome.eventKindIndex],
    );
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(
        ATTEMPT_ID,
        outcome.jsonPayloadRequired
          ? { transition: outcome.eventKind, payload: {} }
          : { transition: outcome.eventKind },
      ),
      /unknown, removed, or automatic-only/u,
    );
  }
  const binding = fixture.certificate_body_binding;
  assert.deepEqual(binding.norito_field_order, PARLIAMENT_CERTIFICATE_BODY_BINDING_FIELDS_V1);
  assert.deepEqual(
    binding.public_nonbinding_body.public_finding_norito_field_order,
    PARLIAMENT_PUBLIC_FINDING_CERTIFICATE_FIELDS_V1,
  );
  assert.equal(
    binding.public_nonbinding_body.endorsing_assignments,
    "strictly increasing distinct nonzero assignment ids",
  );
  assert.equal(
    binding.public_nonbinding_body.endorsements,
    "endorsing_assignments.length == quorum",
  );
  assert.deepEqual(
    fixture.no_result_kinds.map(({ norito_index, json_tag }) => [norito_index, json_tag]),
    PARLIAMENT_NO_RESULT_KINDS_V1.map(({ noritoIndex, jsonTag }) => [noritoIndex, jsonTag]),
  );
  assert.deepEqual(
    fixture.attempt_read_body_state.json_fields,
    PARLIAMENT_BODY_STATE_FIELDS_V1,
  );
  assert.deepEqual(
    fixture.canonical_body_order,
    PARLIAMENT_CANONICAL_BODY_ORDER_V1,
  );
  assert.equal(
    fixture.attempt_read_body_presentation.subset_rule,
    "strictly increasing subset of canonical_body_order",
  );
});

test("initial sortition draft accepts only the enclosing attempt binding", () => {
  const transition = { transition: "RegisterInitialSortition" };
  assert.deepEqual(PARLIAMENT_PUBLIC_TRANSITIONS_V1[12], {
    noritoIndex: 12,
    jsonTag: "RegisterInitialSortition",
    jsonPayloadRequired: false,
    eventKindIndex: 15,
  });
  assert.deepEqual(
    buildParliamentTransitionDraftRequestV1(ATTEMPT_ID, transition),
    { version: 1, governance_attempt_id: ATTEMPT_ID, transition },
  );
  assert.throws(
    () => buildParliamentTransitionDraftRequestV1(ID(0), transition),
    /non-zero/u,
  );
  for (const payload of [undefined, null, {}, { target_seats: 1 }]) {
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(
        ATTEMPT_ID,
        { ...transition, payload },
      ),
      /unknown, aliased, or missing/u,
    );
  }
  for (const field of [
    "candidates", "candidate_root", "candidate_count", "target_seats",
    "request_height", "pulse_height", "beacon_session_id", "body",
    "body_election_attempt_id", "sequence",
  ]) {
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(
        ATTEMPT_ID,
        { ...transition, [field]: "caller selected" },
      ),
      /unknown, aliased, or missing/u,
      field,
    );
  }
});

test("initial sortition declarations expose an intent without caller payload fields", () => {
  const packageRoot = fileURLToPath(new URL("..", import.meta.url));
  const result = spawnSync(
    process.execPath,
    [
      "./node_modules/typescript/bin/tsc",
      "--noEmit", "--strict", "--skipLibCheck",
      "--module", "NodeNext", "--moduleResolution", "NodeNext",
      "--target", "ES2022", "--types", "node",
      "./test/fixtures/typescript/parliamentInitialSortition.types.ts",
    ],
    { cwd: packageRoot, encoding: "utf8" },
  );
  assert.equal(
    result.status,
    0,
    [result.stdout, result.stderr].filter(Boolean).join("\n"),
  );
});

test("request builders expose only canonical V1 fields and reject removed aliases", () => {
  const proposal = parliamentProposalFixtures()[0];
  assert.deepEqual(
    buildParliamentAttemptDraftRequestV1(
      proposal,
      PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    ),
    {
      version: 1,
      proposal,
      attempt_sequence: PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    },
  );
  assert.throws(
    () => buildParliamentAttemptDraftRequestV1(
      proposal,
      PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 + 1,
    ),
    /attemptSequence/u,
  );
  assert.equal(
    parliamentAttemptReadPathV1(ATTEMPT_ID),
    `/v1/gov/parliament/attempts/${ATTEMPT_ID}`,
  );
  assert.throws(() => parliamentAttemptReadPathV1(ATTEMPT_ID.toUpperCase()), /lowercase/u);
  assert.throws(
    () => buildParliamentTransitionDraftRequestV1(
      ATTEMPT_ID,
      { transition: "ConstructCertificate", payload: {} },
    ),
    /automatic-only/u,
  );
  assert.throws(
    () => buildParliamentTransitionDraftRequestV1(
      ATTEMPT_ID,
      { transition: "CompleteQualification", payload: {} },
    ),
    /unknown, aliased, or missing/u,
  );
});

test("transition drafts reject every unknown or removed tag named by the shared negative cases", () => {
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const tags = fixture.negative_json_cases
    .filter(({ name }) => name.endsWith("_tag"))
    .map(({ value }) => value);
  assert.deepEqual(tags, [
    "PlainBallotFallback",
    "ConstructCertificate",
    "MarkEnacted",
    "MarkSuperseded",
    "MarkExecutionFailed",
  ]);
  for (const tag of tags) {
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(
        ATTEMPT_ID,
        { transition: tag, payload: {} },
      ),
      /unknown, removed, or automatic-only/u,
      tag,
    );
  }
});

test("transition payload validators keep their identifier, root, height, and list bounds", () => {
  const cases = [
    ["RecordAttemptAbsence", { body_instance_id: ID(1), assignment_id: ID(0) }, /assignment_id/u],
    ["BeginInvitationAcceptance", { election_attempt_id: "AB".repeat(32) }, /election_attempt_id/u],
    [
      "EndorsePublicFinding",
      { body_instance_id: ID(1), result_root: Array(31).fill(1) },
      /result_root must contain exactly 32 bytes/u,
    ],
    [
      "ConsumeSortitionPulseBatch",
      { request_ids: [ID(2), ID(1)], beacon_session_id: ID(1), pulse_height: 1, pulse_id: ID(2) },
      /request_ids must be strictly increasing/u,
    ],
    [
      "ConsumeSortitionPulseBatch",
      { request_ids: [ID(1)], beacon_session_id: ID(1), pulse_height: -1, pulse_id: ID(2) },
      /pulse_height must be a losslessly decoded unsigned integer/u,
    ],
  ];
  for (const [tag, payload, pattern] of cases) {
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(ATTEMPT_ID, { transition: tag, payload }),
      pattern,
      tag,
    );
  }
});

test("attempt drafts admit all ten exact proposal wire variants", () => {
  const proposals = parliamentProposalFixtures();
  assert.deepEqual(
    proposals.map((proposal) => (
      buildParliamentAttemptDraftRequestV1(proposal, 0).proposal.kind
    )),
    [
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
    ],
  );
  const musubi = buildParliamentAttemptDraftRequestV1(proposals[5], 1).proposal;
  assert.deepEqual(musubi.payload.value.alias, ["stable-alias"]);
  assert.deepEqual(musubi.payload.value.target.name, ["governed-package"]);
  const provider = buildParliamentAttemptDraftRequestV1(proposals[6], 1).proposal;
  assert.deepEqual(provider.payload.action.value.provider_id, [Array(32).fill(0x31)]);
  const retrospective = buildParliamentAttemptDraftRequestV1(proposals[7], 1).proposal;
  assert.equal(retrospective.payload.action.action, "CompleteEmergencyHoldRetrospective");
  assert.deepEqual(retrospective.payload.action.payload.retrospective_finding_root, Array(32).fill(0x45));
});

test("effect-bound proposal drafts require an explicit canonical operator", () => {
  for (const index of [0, 1, 7]) {
    const proposal = structuredClone(parliamentProposalFixtures()[index]);
    delete proposal.payload.proposal_operator;
    assert.throws(
      () => buildParliamentAttemptDraftRequestV1(proposal, 0),
      /missing required fields/u,
    );
  }
});

test("retired Kagemusha proposal kinds reject at the current draft boundary", () => {
  for (const proposal of retiredParliamentProposalFixtures()) {
    assert.ok(!PARLIAMENT_PROPOSAL_KINDS_V1.includes(proposal.kind));
    assert.throws(
      () => buildParliamentAttemptDraftRequestV1(proposal, 0),
      /unsupported V1 proposal variant/u,
    );
  }
});

test("Parliament declarations expose the closed wire union and tuple newtypes", () => {
  const declarations = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const start = declarations.indexOf("export interface ParliamentMusubiPackageIdV1");
  const end = declarations.indexOf("export type ParliamentLifecycleTransitionV1", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const proposalDeclarations = declarations.slice(start, end);
  assert.match(proposalDeclarations, /name: readonly \[string\];/u);
  assert.match(proposalDeclarations, /alias: readonly \[string\];/u);
  assert.match(proposalDeclarations, /reason: readonly \[string\];/u);
  assert.match(
    proposalDeclarations,
    /provider_id: readonly \[ReadonlyArray<number>\];/u,
  );
  assert.match(proposalDeclarations, /kind: "ContractLifecycleGovernance";/u);
  assert.match(proposalDeclarations, /kind: "ContractEmergencyHold";/u);
  assert.match(
    proposalDeclarations,
    /kind: "GlobalDataTriggerPermissionGovernance";/u,
  );
  assert.doesNotMatch(proposalDeclarations, /Kagemusha/u);
  assert.doesNotMatch(proposalDeclarations, /payload: Record<string, unknown>/u);
});

test("contract lifecycle unit actions retain their explicit null wire payload", () => {
  for (const action of ["CancelOwnershipOffer", "AcceptParliamentOwnership"]) {
    const proposal = structuredClone(parliamentProposalFixtures()[7]);
    proposal.payload.action = { action, payload: null };
    assert.deepEqual(
      buildParliamentAttemptDraftRequestV1(proposal, 0).proposal.payload.action,
      { action, payload: null },
    );
    delete proposal.payload.action.payload;
    assert.throws(
      () => buildParliamentAttemptDraftRequestV1(proposal, 0),
      /missing required fields/u,
    );
  }
});

test("contract lifecycle action inventory admits exactly six wire tags", () => {
  const actionPayloads = new Map([
    ["Activate", {
      code_hash: "11".repeat(32),
      abi_hash: "22".repeat(32),
      abi_version: 1,
      manifest_provenance: null,
    }],
    ["Deactivate", { expected_code_hash: "33".repeat(32) }],
    ["OfferOwnership", { new_owner: ACCOUNTS[0] }],
    ["CancelOwnershipOffer", null],
    ["AcceptParliamentOwnership", null],
    ["CompleteEmergencyHoldRetrospective", {
      hold_proposal_content_id: Array(32).fill(0x42),
      hold_governance_attempt_id: Array(32).fill(0x43),
      incident_digest: Array(32).fill(0x44),
      retrospective_finding_root: Array(32).fill(0x45),
    }],
  ]);
  assert.deepEqual([...actionPayloads.keys()], PARLIAMENT_CONTRACT_LIFECYCLE_ACTIONS_V1);
  for (const [action, payload] of actionPayloads) {
    const proposal = structuredClone(parliamentProposalFixtures()[7]);
    proposal.payload.action = { action, payload };
    assert.equal(
      buildParliamentAttemptDraftRequestV1(proposal, 0).proposal.payload.action.action,
      action,
    );
  }

  const unknown = structuredClone(parliamentProposalFixtures()[7]);
  unknown.payload.action = { action: "Unknown", payload: null };
  assert.throws(
    () => buildParliamentAttemptDraftRequestV1(unknown, 0),
    /unsupported lifecycle action/u,
  );
});

test("attempt drafts reject malformed nested fields and open proposal shapes", () => {
  const mutations = [
    (proposal) => { proposal.payload.future = null; },
    (proposal) => { proposal.payload.manifest.future = null; },
    (proposal) => { proposal.payload.proposal.future = null; },
    (proposal) => { proposal.payload.policy.future = null; },
    (proposal) => { proposal.payload.payout_binding.future = null; },
    (proposal) => { proposal.payload.value.target.name = "governed-package"; },
    (proposal) => { proposal.payload.action.value.provider_id = Array(32).fill(0x31); },
    (proposal) => { proposal.payload.action.payload.future = null; },
    (proposal) => { proposal.payload.future = null; },
    (proposal) => { proposal.payload.action.future = null; },
  ];
  const fixtures = parliamentProposalFixtures();
  assert.equal(mutations.length, fixtures.length, "every proposal variant needs a malformed nested fixture");
  for (const [index, canonical] of fixtures.entries()) {
    const malformed = structuredClone(canonical);
    mutations[index](malformed);
    assert.throws(
      () => buildParliamentAttemptDraftRequestV1(malformed, 0),
      /unsupported fields|exact one-field/u,
      canonical.kind,
    );
  }
  const unknown = structuredClone(parliamentProposalFixtures()[0]);
  unknown.kind = "FutureProposal";
  assert.throws(
    () => buildParliamentAttemptDraftRequestV1(unknown, 0),
    /unsupported V1 proposal variant/u,
  );
  const wrapped = { ...parliamentProposalFixtures()[0], raw: {} };
  assert.throws(
    () => buildParliamentAttemptDraftRequestV1(wrapped, 0),
    /unsupported fields/u,
  );
  const zeroKeyOwner = structuredClone(parliamentProposalFixtures()[6]);
  zeroKeyOwner.payload.action.value.owner = RUST_INVALID_ZERO_KEY_ACCOUNT;
  assert.throws(
    () => buildParliamentAttemptDraftRequestV1(zeroKeyOwner, 0),
    { name: "AccountAddressError", code: "ERR_INVALID_PUBLIC_KEY" },
  );
});

test("draft responses bind exact IDs, public kind, digest, and wire IDs", () => {
  const attempt = normalizeParliamentAttemptDraftResponseV1({
    version: 1,
    proposal_content_id: PROPOSAL_ID,
    governance_attempt_id: ATTEMPT_ID,
    tx_instructions: [{
      wire_id: PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
      payload_hex: "0102",
    }],
  }, {
    expectedProposalContentId: PROPOSAL_ID,
    expectedGovernanceAttemptId: ATTEMPT_ID,
  });
  assert.equal(attempt.governance_attempt_id, ATTEMPT_ID);

  const transition = normalizeParliamentTransitionDraftResponseV1({
    version: 1,
    governance_attempt_id: ATTEMPT_ID,
    transition_kind: { kind: "CompleteQualification" },
    transition_digest: ROOT,
    tx_instructions: [{
      wire_id: PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
      payload_hex: "0304",
    }],
  }, {
    expectedGovernanceAttemptId: ATTEMPT_ID,
    expectedTransitionKind: "CompleteQualification",
    expectedTransitionDigest: ROOT,
  });
  assert.deepEqual(transition.transition_digest, ROOT);
  assert.throws(
    () => normalizeParliamentTransitionDraftResponseV1({
      version: 1,
      governance_attempt_id: ATTEMPT_ID,
      transition_kind: { kind: "MarkEnacted" },
      transition_digest: ROOT,
      tx_instructions: [{
        wire_id: PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
        payload_hex: "0304",
      }],
    }, {
      expectedGovernanceAttemptId: ATTEMPT_ID,
      expectedTransitionKind: "CompleteQualification",
      expectedTransitionDigest: ROOT,
    }),
    /automatic, unknown, or consensus-owned/u,
  );
});

test("attempt read validates NRT0 and the exact canonical public-finding supporter list", () => {
  const response = readResponse();
  const parsed = normalizeParliamentAttemptReadResponseV1(response, ATTEMPT_ID);
  assert.deepEqual(
    parsed.required_bodies.map(({ body }) => body),
    ["rules-committee", "agenda-council"],
  );
  assert.deepEqual(
    parsed.certificate.body_bindings.map(({ body }) => body),
    ["rules-committee", "agenda-council"],
  );
  assert.deepEqual(
    parsed.certificate.body_bindings[0].public_finding.endorsing_assignments,
    [ID(0x11), ID(0x12)],
  );

  const fullOrder = readResponse();
  fullOrder.attempt.stage = { stage: "Qualification" };
  fullOrder.attempt.status = { status: "Active" };
  fullOrder.certificate = null;
  fullOrder.required_bodies = PARLIAMENT_CANONICAL_BODY_ORDER_V1.map((body) => ({
    body,
    decision_mode: {
      mode: body === "policy-jury" || body === "confirmation-jury"
        ? "HiddenBindingBallot"
        : "PublicFinding",
    },
  }));
  fullOrder.body_states = PARLIAMENT_CANONICAL_BODY_ORDER_V1.map((body) => ({
    body,
    body_instance_id: null,
    status: null,
    public_finding_opened_at_height: null,
    public_finding_phase_blocks: null,
    public_finding_deadline_height: null,
    no_result_kind: null,
    no_result_height: null,
  }));
  const fullOrderParsed = normalizeParliamentAttemptReadResponseV1(fullOrder, ATTEMPT_ID);
  assert.deepEqual(
    fullOrderParsed.required_bodies.map(({ body }) => body),
    PARLIAMENT_CANONICAL_BODY_ORDER_V1,
  );
  assert.deepEqual(
    fullOrderParsed.body_states.map(({ body }) => body),
    PARLIAMENT_CANONICAL_BODY_ORDER_V1,
  );
  const reordered = structuredClone(fullOrder);
  [reordered.required_bodies[0], reordered.required_bodies[1]] =
    [reordered.required_bodies[1], reordered.required_bodies[0]];
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(reordered, ATTEMPT_ID),
    /canonical body order/u,
  );
  const unsorted = structuredClone(response);
  unsorted.certificate.body_bindings[0].public_finding.endorsing_assignments.reverse();
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(unsorted, ATTEMPT_ID),
    /strictly increasing/u,
  );
  const alias = { ...response, statePayloadHex: response.state_payload_hex };
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(alias, ATTEMPT_ID),
    /unknown, aliased, or missing/u,
  );
  const bare = { ...response, state_payload_hex: "0102" };
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(bare, ATTEMPT_ID),
    /not an NRT0 frame|shorter than/u,
  );
  const wrongDeadline = structuredClone(response);
  wrongDeadline.body_states[0].public_finding_deadline_height += 1;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(wrongDeadline, ATTEMPT_ID),
    /frozen schedule/u,
  );
  const aliasBodyState = structuredClone(response);
  aliasBodyState.body_states[0].noResultKind = null;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(aliasBodyState, ATTEMPT_ID),
    /unknown, aliased, or missing/u,
  );
  const automaticAsFailure = structuredClone(response);
  automaticAsFailure.body_states[0].no_result_kind = { reason: "ExecutionFailed" };
  automaticAsFailure.body_states[0].no_result_height = 9;
  automaticAsFailure.body_states[0].status = { status: "NoResult" };
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(automaticAsFailure, ATTEMPT_ID),
    /unknown/u,
  );
});

test("attempt read rejects forged certificate cross-bindings and lifecycle fields", () => {
  const mutations = [
    [
      (response) => { response.certificate.proposal_content_id = ID(0xee); },
      /proposal_content_id differs/u,
    ],
    [
      (response) => { response.certificate.governance_attempt_sequence = 1; },
      /governance_attempt_sequence differs/u,
    ],
    [
      (response) => { response.certificate.risk_tier = { tier: "Emergency", details: null }; },
      /risk_tier differs/u,
    ],
    [
      (response) => { response.certificate.risk_tier = { tier: "Emergency" }; },
      /certificate\.risk_tier contains unknown, aliased, or missing fields/u,
    ],
    [
      (response) => { response.certificate.policy_version = 2; },
      /policy_version must equal/u,
    ],
    [
      (response) => { response.certificate.enact_at_height = 8; },
      /enactment height/u,
    ],
    [
      (response) => {
        response.certificate.body_bindings[0].sortition_request.beacon_session_id = ID(0xee);
      },
      /repeated certificate bindings/u,
    ],
    [
      (response) => {
        response.certificate.body_bindings[0].sortition_request.request_height = 0;
      },
      /sortition heights/u,
    ],
    [
      (response) => {
        response.certificate.body_bindings[1].body = "interest-panel";
        response.certificate.body_bindings[1].sortition_request.body = "interest-panel";
      },
      /differs from required_bodies/u,
    ],
  ];
  for (const [mutate, pattern] of mutations) {
    const forged = readResponse();
    mutate(forged);
    assert.throws(
      () => normalizeParliamentAttemptReadResponseV1(forged, ATTEMPT_ID),
      pattern,
    );
  }

  const largeElectorate = readResponse();
  largeElectorate.certificate.body_bindings[0].sortition_request.candidate_count = 1_001;
  assert.doesNotThrow(
    () => normalizeParliamentAttemptReadResponseV1(largeElectorate, ATTEMPT_ID),
  );

  const impossibleSeats = readResponse();
  impossibleSeats.certificate.body_bindings[0].original_seats = 4;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(impossibleSeats, ATTEMPT_ID),
    /original_seats exceeds its sortition bounds/u,
  );

  const reorderedRequired = readResponse();
  reorderedRequired.required_bodies = [
    { body: "policy-jury", decision_mode: { mode: "HiddenBindingBallot" } },
    ...reorderedRequired.required_bodies,
  ];
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(reorderedRequired, ATTEMPT_ID),
    /canonical body order/u,
  );

  const duplicateBinding = readResponse();
  duplicateBinding.required_bodies.push({
    body: "interest-panel",
    decision_mode: { mode: "PublicFinding" },
  });
  const thirdState = structuredClone(duplicateBinding.body_states[0]);
  thirdState.body = "interest-panel";
  duplicateBinding.body_states.push(thirdState);
  const thirdBinding = structuredClone(duplicateBinding.certificate.body_bindings[0]);
  thirdBinding.body = "interest-panel";
  thirdBinding.sortition_request.body = "interest-panel";
  duplicateBinding.certificate.body_bindings.push(thirdBinding);
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(duplicateBinding, ATTEMPT_ID),
    /reuse bodyInstanceId/u,
  );
});

test("certificates containing a private-jury binding are rejected until the anonymous-ballot binding is supported", () => {
  for (const body of ["policy-jury", "confirmation-jury"]) {
    const response = readResponse();
    response.required_bodies[1] = { body, decision_mode: { mode: "HiddenBindingBallot" } };
    response.body_states[1].body = body;
    response.certificate.body_bindings[1].body = body;
    response.certificate.body_bindings[1].sortition_request.body = body;
    const message =
      "certificate.body_bindings[1] private-jury result binding is not admitted until the anonymous-ballot result binding is supported";
    assert.throws(
      () => normalizeParliamentAttemptReadResponseV1(response, ATTEMPT_ID),
      { name: "TypeError", message },
      body,
    );
    assert.throws(
      () => normalizeParliamentGovernanceCertificateV1(response.certificate),
      { name: "TypeError", message },
      body,
    );
  }
});

test("certificate admission pins policy V1, retry ceilings, and nonzero present heads", () => {
  const unsupportedProjection = readResponse();
  unsupportedProjection.certificate = null;
  unsupportedProjection.policy_version = 2;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(unsupportedProjection, ATTEMPT_ID),
    /policy_version must equal/u,
  );

  const zeroHeadVersion = readResponse();
  zeroHeadVersion.certificate.expected_head = {
    state: "Present",
    head: { subject_id: ROOT, version: 0, head_root: ROOT },
  };
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(zeroHeadVersion, ATTEMPT_ID),
    /must be within 1/u,
  );

  const overLimitAttempt = readResponse();
  overLimitAttempt.attempt.sequence = PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 + 1;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(overLimitAttempt, ATTEMPT_ID),
    /attempt.sequence/u,
  );

  const overLimitElection = readResponse();
  overLimitElection.certificate.body_bindings[0].election_attempt_sequence = 17;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(overLimitElection, ATTEMPT_ID),
    /election_attempt_sequence/u,
  );
});

test("ToriiClient exposes every canonical authenticated Parliament path", async () => {
  const canonicalAuth = { accountId: "alice-1@wonderland", privateKey: Buffer.alloc(32, 7) };
  const calls = [];
  const client = new ToriiClient("https://example.invalid");
  client._expectStatus = async () => {};
  client._readBoundedLosslessIntegerJson = async (response) => response.payload;
  client._request = async (method, path, options) => {
    calls.push({ method, path, options });
    if (path === PARLIAMENT_ATTEMPT_DRAFT_PATH_V1) {
      return { payload: {
        version: 1,
        proposal_content_id: PROPOSAL_ID,
        governance_attempt_id: ATTEMPT_ID,
        tx_instructions: [{ wire_id: PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1, payload_hex: "0102" }],
      } };
    }
    if (path === PARLIAMENT_TRANSITION_DRAFT_PATH_V1) {
      return { payload: {
        version: 1,
        governance_attempt_id: ATTEMPT_ID,
        transition_kind: { kind: "CompleteQualification" },
        transition_digest: ROOT,
        tx_instructions: [{ wire_id: PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1, payload_hex: "0304" }],
      } };
    }
    return { payload: readResponse() };
  };
  await client.draftParliamentAttemptV1(
    parliamentProposalFixtures()[0],
    0,
    {
      canonicalAuth,
      expectedProposalContentId: PROPOSAL_ID,
      expectedGovernanceAttemptId: ATTEMPT_ID,
    },
  );
  await client.getParliamentAttemptV1(ATTEMPT_ID, { canonicalAuth });
  await client.draftParliamentTransitionV1(
    ATTEMPT_ID,
    { transition: "CompleteQualification" },
    { canonicalAuth, expectedTransitionDigest: ROOT },
  );
  assert.deepEqual(calls.map(({ method, path }) => [method, path]), [
    ["POST", PARLIAMENT_ATTEMPT_DRAFT_PATH_V1],
    ["GET", `/v1/gov/parliament/attempts/${ATTEMPT_ID}`],
    ["POST", PARLIAMENT_TRANSITION_DRAFT_PATH_V1],
  ]);
  const attemptBody = JSON.parse(calls[0].options.body);
  assert.deepEqual(Object.keys(attemptBody), ["version", "proposal", "attempt_sequence"]);
  const transitionBody = JSON.parse(calls[2].options.body);
  assert.deepEqual(Object.keys(transitionBody), ["version", "governance_attempt_id", "transition"]);
});

test("ToriiClient typed proposal reads use the strict local V1 parser", async () => {
  const proposals = parliamentProposalFixtures();
  const client = new ToriiClient("https://example.invalid");
  client.getGovernanceProposal = async () => {
    const kind = proposals.shift();
    return {
      found: true,
      proposal: {
        proposer: kind.payload.proposal_operator ?? ACCOUNTS[0],
        kind,
        created_height: 1,
        status: "Proposed",
      },
    };
  };
  const variants = [];
  while (proposals.length > 0) {
    const result = await client.getGovernanceProposalTyped(PROPOSAL_ID);
    variants.push(result.proposal.kind.variant);
  }
  assert.deepEqual(variants, [
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

  const malformed = structuredClone(parliamentProposalFixtures()[0]);
  malformed.payload.future = null;
  client.getGovernanceProposal = async () => ({
    found: true,
    proposal: {
      proposer: ACCOUNTS[0],
      kind: malformed,
      created_height: 1,
      status: "Proposed",
    },
  });
  await assert.rejects(
    client.getGovernanceProposalTyped(PROPOSAL_ID),
    /unsupported fields/u,
  );

  for (const index of [0, 1, 7]) {
    const operatorBoundKind = parliamentProposalFixtures()[index];
    client.getGovernanceProposal = async () => ({
      found: true,
      proposal: {
        proposer: ACCOUNTS[1],
        kind: operatorBoundKind,
        created_height: 1,
        status: "Proposed",
      },
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(
      client.getGovernanceProposalTyped(PROPOSAL_ID),
      /operator must match the retained proposer/u,
    );
  }
});

test("ToriiClient typed proposal reads reject retired Kagemusha variants", async () => {
  const client = new ToriiClient("https://example.invalid");
  for (const kind of retiredParliamentProposalFixtures()) {
    client.getGovernanceProposal = async () => ({
      found: true,
      proposal: {
        proposer: kind.payload.proposal_operator,
        kind,
        created_height: 1,
        status: "Proposed",
      },
    });
    // eslint-disable-next-line no-await-in-loop
    await assert.rejects(client.getGovernanceProposalTyped(PROPOSAL_ID), /unsupported proposal variant/u);
  }
});

function retiredParliamentProposalFixtures() {
  return [
    "KagemushaVerifierPolicyInstall",
    "KagemushaVerifierReleaseInstall",
    "KagemushaVerifierReleaseActivate",
    "KagemushaVerifierReleaseRetire",
  ].map((kind) => ({ kind, payload: { proposal_operator: ACCOUNTS[0] } }));
}

function fixtureAccountId(label) {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const publicKey = sha256(new TextEncoder().encode(`parliament:${label}:${attempt}`));
    try {
      return AccountAddress.fromAccount({ publicKey }).toI105(0x2f1);
    } catch (error) {
      if (
        !(error instanceof AccountAddressError) ||
        error.code !== AccountAddressErrorCode.INVALID_PUBLIC_KEY
      ) {
        throw error;
      }
    }
  }
  throw new Error(`unable to derive a canonical Parliament fixture account for ${label}`);
}

function parliamentProposalFixtures() {
  const [treasury] = ACCOUNTS;
  const packageId = {
    home_dataspace: 7,
    scope: { kind: "DataspaceRoot", value: null },
    name: ["governed-package"],
  };
  const payoutBinding = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_conversion_v1.json", import.meta.url), "utf8"));
  const policy = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_policy_v1.json", import.meta.url), "utf8"));
  policy.network_id = NETWORK_ID;
  return [
    {
      kind: "DeployContract",
      payload: {
        proposal_operator: treasury,
        contract_address: CONTRACT_ADDRESS,
        code_hash: "aa".repeat(32),
        abi_hash: "bb".repeat(32),
        abi_version: 1,
        manifest_provenance: {
          signer: "ed012017CB79FB2B4120F2B1EC65E4198D6E08B28E813FEB01E4A400839B85E18080CE",
          signature:
            "C74557F062FDC5799D64FD2561103F6B13263B1FCE11F3148D48A34781F43D6C3ACB87C885BA666624A98D848AF3BF48A0A0C79FB3F28B244703269A52128809",
        },
      },
    },
    {
      kind: "RuntimeUpgrade",
      payload: {
        proposal_operator: treasury,
        manifest: {
          name: "runtime-v1-refresh",
          description: "Canonical V1 runtime image",
          abi_version: 1,
          abi_hash: Array(32).fill(0x11),
          added_syscalls: [],
          added_pointer_types: [],
          start_height: 100,
          end_height: 120,
          sbom_digests: [{ algorithm: "sha256", digest: "AQID" }],
          slsa_attestation: "BAUG",
          provenance: [],
        },
      },
    },
    {
      kind: "SccpRouteGovernance",
      payload: {
        proposal: {
          network_id: NETWORK_ID,
          base_revisions: [{
            subject: { subject: "route", key: { network: "bsc_mainnet", profile: null } },
            revision: 1,
          }],
          actions: [{
            action: "remove_staged",
            payload: { network: { network: "bsc_mainnet", profile: null }, revision: 1 },
          }],
        },
      },
    },
    {
      kind: "ValidationFeePolicy",
      payload: {
        proposal_operator: treasury,
        policy,
      },
    },
    {
      kind: "ValidationFeePayoutLifecycle",
      payload: { proposal_operator: treasury, payout_binding: payoutBinding },
    },
    {
      kind: "MusubiRegistryGovernance",
      payload: {
        kind: "RetargetAlias",
        value: {
          alias: ["stable-alias"],
          target: packageId,
          expected_revision: 1,
        },
      },
    },
    {
      kind: "SorafsProviderGovernance",
      payload: {
        action: {
          action: "establish",
          value: { provider_id: [Array(32).fill(0x31)], owner: treasury },
        },
      },
    },
    {
      kind: "ContractLifecycleGovernance",
      payload: {
        proposal_operator: treasury,
        contract_address: CONTRACT_ADDRESS,
        expected_revision: 3,
        action: {
          action: "CompleteEmergencyHoldRetrospective",
          payload: {
            hold_proposal_content_id: Array(32).fill(0x42),
            hold_governance_attempt_id: Array(32).fill(0x43),
            incident_digest: Array(32).fill(0x44),
            retrospective_finding_root: Array(32).fill(0x45),
          },
        },
      },
    },
    {
      kind: "ContractEmergencyHold",
      payload: {
        contract_address: CONTRACT_ADDRESS,
        expected_revision: 2,
        expected_code_hash: "cc".repeat(32),
        incident_digest: Array(32).fill(0x46),
        reason: "contain active exploit",
        duration_blocks: 3600,
      },
    },
    {
      kind: "GlobalDataTriggerPermissionGovernance",
      payload: {
        authority: treasury,
        action: { action: "grant", value: null },
      },
    },
  ];
}

function transitionFixture(tag) {
  const one = ID(1);
  const two = ID(2);
  const payloads = {
    EscalateRisk: { target: { tier: "Standard" } },
    RegisterSortitionRequest: { requests: [{ sequence: 0, request: {} }] },
    ConsumeSortitionPulseBatch: { request_ids: [one], beacon_session_id: one, pulse_height: 1, pulse_id: two },
    BeginInvitationAcceptance: { election_attempt_id: one },
    FailBodyElectionNoRoster: { election_attempt_id: one },
    SealBodyRoster: { election_attempt_id: one },
    AdvanceBodyPhase: { body_instance_id: one, target: { phase: "Evidence" } },
    RecordAttemptAbsence: { body_instance_id: one, assignment_id: two },
    EndorsePublicFinding: { body_instance_id: one, result_root: ROOT },
    RecordInvitationResponse: {
      election_attempt_id: one,
      body: "rules-committee",
      decision: { decision: "Accept" },
    },
    FailPublicFindingNoResult: { body_instance_id: one },
  };
  return tag === "CompleteQualification" || tag === "RegisterInitialSortition"
    ? { transition: tag }
    : { transition: tag, payload: payloads[tag] };
}

function readResponse() {
  return {
    version: 1,
    current_height: 20,
    attempt: {
      id: ATTEMPT_ID,
      proposal_content_id: PROPOSAL_ID,
      sequence: 0,
      risk_tier: { tier: "Standard" },
      stage: { stage: "Certification" },
      status: { status: "Certified" },
    },
    policy_version: 1,
    required_bodies: [
      { body: "rules-committee", decision_mode: { mode: "PublicFinding" } },
      { body: "agenda-council", decision_mode: { mode: "PublicFinding" } },
    ],
    body_states: [
      publicBodyState("rules-committee", ID(1), 1, 7),
      publicBodyState("agenda-council", ID(0x21), 10, 8),
    ],
    certificate: {
      proposal_content_id: PROPOSAL_ID,
      governance_attempt_id: ATTEMPT_ID,
      governance_attempt_sequence: 0,
      risk_tier: { tier: "Standard", details: null },
      body_bindings: [
        publicBodyBinding("rules-committee", 1, 8, [ID(0x11), ID(0x12)]),
        publicBodyBinding("agenda-council", 0x21, 18, [ID(0x31), ID(0x32)]),
      ],
      policy_version: 1,
      effect_preimage_hash: ROOT,
      expected_head: { state: "Absent", head: { subject_id: ROOT } },
      certified_at_height: 18,
      enact_at_height: 30,
    },
    terminal_height: null,
    execution_failure_root: null,
    superseding_head: null,
    state_payload_hex: stateFrame().toString("hex"),
  };
}

function publicBodyState(body, bodyInstanceId, openedAtHeight, phaseBlocks) {
  return {
    body,
    body_instance_id: bodyInstanceId,
    status: { status: "Approved" },
    public_finding_opened_at_height: openedAtHeight,
    public_finding_phase_blocks: phaseBlocks,
    public_finding_deadline_height: openedAtHeight + phaseBlocks,
    no_result_kind: null,
    no_result_height: null,
  };
}

// One public-finding binding whose five repeated identifiers are the consecutive bytes
// starting at `firstId`: body instance, election attempt, sortition request, beacon
// session and beacon pulse.
function publicBodyBinding(body, firstId, resultHeight, supporters) {
  return {
    body_instance_id: ID(firstId),
    election_attempt_id: ID(firstId + 1),
    election_attempt_sequence: 0,
    sortition_request_id: ID(firstId + 2),
    sortition_request: {
      id: ID(firstId + 2),
      governance_attempt_id: ATTEMPT_ID,
      body_election_attempt_id: ID(firstId + 1),
      body,
      candidate_root: ROOT,
      candidate_count: 3,
      target_seats: 3,
      request_height: 1,
      pulse_height: 2,
      beacon_session_id: ID(firstId + 3),
    },
    body,
    original_seats: 3,
    beacon_session_id: ID(firstId + 3),
    beacon_pulse_id: ID(firstId + 4),
    roster_root: ROOT,
    assignment_root: ROOT,
    result_root: ROOT,
    result_height: resultHeight,
    public_finding: {
      endorsement_root: ROOT,
      endorsing_assignments: supporters,
      endorsements: 2,
      quorum: 2,
    },
    ballot: null,
  };
}

function stateFrame() {
  const payload = Buffer.from([1, 2]);
  const header = Buffer.alloc(40);
  header.write("NRT0", 0, "ascii");
  header[6] = 3;
  header.writeBigUInt64LE(BigInt(payload.length), 23);
  header.writeBigUInt64LE(crc64Xz(payload), 31);
  return Buffer.concat([header, payload]);
}
