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
  PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1,
  PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
  PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1,
  PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
  PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
  PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1,
  PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1,
  PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
  PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
  ToriiClient,
  buildParliamentAttemptDraftRequestV1,
  buildParliamentTransitionDraftRequestV1,
  encodeParliamentTimedOvnCastingProofRequestV1,
  normalizeParliamentAttemptDraftResponseV1,
  normalizeParliamentAttemptReadResponseV1,
  normalizeParliamentTimedOvnCastingContextResponseV1,
  normalizeParliamentTlePartialReleaseShareV1,
  normalizeParliamentTleReleaseContextResponseV1,
  normalizeParliamentTransitionDraftResponseV1,
  parliamentAttemptReadPathV1,
  parliamentTimedOvnCastingContextReadPathV1,
  parliamentTimedOvnCastingProofPathV1,
  parliamentTlePartialReleasePathV1,
  parliamentTleReleaseContextReadPathV1,
  validateParliamentTimedOvnCastingProofResponseFrameV1,
} from "../src/index.js";

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
function exactNoritoFrame(payload, schemaHashHex, { flags = 0x02, padding = 0 } = {}) {
  const body = Buffer.from(payload);
  const frame = Buffer.alloc(40 + padding + body.length);
  frame.write("NRT0", 0, "ascii");
  Buffer.from(schemaHashHex, "hex").copy(frame, 6);
  frame.writeBigUInt64LE(BigInt(body.length), 23);
  frame.writeBigUInt64LE(crc64Xz(body), 31);
  frame[39] = flags;
  body.copy(frame, 40 + padding);
  return frame;
}

test("shared Parliament fixture pins routes, all transition inventories, and certificate supporters", () => {
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.equal(fixture.schema, "iroha.governance.parliament.api_fixture.v1");
  assert.equal(fixture.api_version, PARLIAMENT_API_VERSION_V1);
  assert.deepEqual(fixture.routes, {
    attempt_draft: PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
    attempt_read: PARLIAMENT_ATTEMPT_READ_PATH_V1,
    timed_ovn_casting_context_read: PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1,
    timed_ovn_casting_proof: PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1,
    tle_release_context_read: PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1,
    tle_partial_release: PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1,
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
  assert.equal(fixture.limits.attempt_state_bytes, PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1);
  assert.equal(
    fixture.limits.governance_attempt_sequence_max,
    PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
  );
  assert.equal(
    fixture.limits.timed_ovn_ballot_chunk_max_records,
    PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
  );
  assert.equal(
    fixture.limits.timed_ovn_corpus_entries,
    PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
  );
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
  assert.deepEqual(PARLIAMENT_PUBLIC_TRANSITIONS_V1[21], {
    noritoIndex: 21,
    jsonTag: "RegisterInitialSortition",
    jsonPayloadRequired: false,
    eventKindIndex: 24,
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

test("casting-proof request and response frames match the shared Rust contract", () => {
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const wallet = fixture.timed_ovn_native_wallet;
  const golden = wallet.casting_proof_request_golden;
  assert.equal(
    wallet.request_norito_schema,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_NAME_V1,
  );
  assert.equal(
    wallet.response_norito_schema,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_NAME_V1,
  );
  assert.equal(
    wallet.casting_proof_request_schema_hash_hex,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1,
  );
  assert.equal(
    wallet.casting_proof_response_schema_hash_hex,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
  );
  assert.equal(wallet.casting_proof_request_version, PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1);
  assert.equal(wallet.casting_proof_request_flags, PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1);
  assert.equal(
    wallet.casting_proof_request_payload_alignment,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1,
  );
  assert.equal(
    wallet.casting_proof_request_padding_bytes,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1,
  );
  assert.equal(
    fixture.limits.timed_ovn_casting_proof_request_bytes,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1,
  );
  assert.equal(
    fixture.limits.timed_ovn_casting_proof_response_bytes,
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
  );
  assert.equal(golden.frame_bytes, PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1);
  const request = encodeParliamentTimedOvnCastingProofRequestV1(
    golden.trusted_checkpoint_height,
  );
  assert.equal(request.toString("hex"), golden.frame_hex);
  assert.equal(request.subarray(40).toString("hex"), golden.payload_hex);

  for (const invalid of [0, -1, 2 ** 53, -1n, 1n << 64n, "17"]) {
    assert.throws(
      () => encodeParliamentTimedOvnCastingProofRequestV1(invalid),
      /trustedCheckpointHeight/u,
    );
  }

  const response = exactNoritoFrame(
    Buffer.from([1]),
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
  );
  assert.deepEqual(validateParliamentTimedOvnCastingProofResponseFrameV1(response), response);
  assert.throws(
    () => validateParliamentTimedOvnCastingProofResponseFrameV1(
      exactNoritoFrame(Buffer.from([1]), PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1),
    ),
    /schema hash/u,
  );
  assert.throws(
    () => validateParliamentTimedOvnCastingProofResponseFrameV1(
      exactNoritoFrame(
        Buffer.from([1]),
        PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
        { flags: 0 },
      ),
    ),
    /canonical Norito flags/u,
  );
  assert.throws(
    () => validateParliamentTimedOvnCastingProofResponseFrameV1(
      exactNoritoFrame(
        Buffer.from([1]),
        PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
        { padding: 1 },
      ),
    ),
    /exactly 0 bytes of header padding/u,
  );
});

test("timed-OVN corpus transitions preflight one through 32 records per chunk", () => {
  const record = Array(PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1).fill(1);
  for (const count of [1, PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1]) {
    assert.doesNotThrow(() => buildParliamentTransitionDraftRequestV1(
      ATTEMPT_ID,
      {
        transition: "FreezeTimedOvnCorpus",
        payload: { ballot_attempt_id: ID(1), ballot_records: Array(count).fill(record) },
      },
    ));
  }
  for (const count of [0, PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1 + 1]) {
    assert.throws(
      () => buildParliamentTransitionDraftRequestV1(
        ATTEMPT_ID,
        {
          transition: "FreezeTimedOvnCorpus",
          payload: { ballot_attempt_id: ID(1), ballot_records: Array(count).fill(record) },
        },
      ),
      /one through 32 records/u,
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
    (proposal) => { proposal.payload.authority_policy.future = null; },
    (proposal) => { proposal.payload.manifest.future = null; },
    (proposal) => { proposal.payload.expected_predecessor.future = null; },
    (proposal) => { proposal.payload.expected_predecessor.future = null; },
  ];
  const fixtures = parliamentProposalFixtures();
  assert.equal(mutations.length, fixtures.length, "every proposal variant needs a malformed nested fixture");
  for (const [index, canonical] of fixtures.entries()) {
    const malformed = structuredClone(canonical);
    mutations[index](malformed);
    assert.throws(
      () => buildParliamentAttemptDraftRequestV1(malformed, 0),
      index >= 11 ? /has unknown field 'future'/u : /unsupported fields|exact one-field/u,
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
    ["rules-committee", "policy-jury"],
  );
  assert.deepEqual(
    parsed.certificate.body_bindings.map(({ body }) => body),
    ["rules-committee", "policy-jury"],
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
    timed_ovn_progress: null,
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

test("attempt read accepts terminal commitment chunks only inside the frozen liveness window", () => {
  const early = hiddenBallotReadResponse(10);
  const parsed = normalizeParliamentAttemptReadResponseV1(early, ATTEMPT_ID);
  assert.equal(
    parsed.certificate.body_bindings[0].ballot.commitment_closed_at_height,
    10,
  );
  for (const invalidHeight of [8, 14]) {
    assert.throws(
      () => normalizeParliamentAttemptReadResponseV1(
        hiddenBallotReadResponse(invalidHeight),
        ATTEMPT_ID,
      ),
      /frozen ballot lifecycle/u,
    );
  }
});

test("attempt read exposes only phase-bound aggregate timed-OVN progress", () => {
  const finalized = hiddenBallotReadResponse(10);
  assert.equal(
    normalizeParliamentAttemptReadResponseV1(finalized, ATTEMPT_ID)
      .body_states[0].timed_ovn_progress.accepted_ballot_prefix_count,
    3,
  );

  const active = hiddenBallotReadResponse(10);
  active.attempt.status = { status: "Active" };
  active.certificate = null;
  active.body_states[0].status = { status: "Balloting" };
  active.body_states[0].timed_ovn_progress.status = { status: "TimedCommitment" };
  active.body_states[0].timed_ovn_progress.accepted_ballot_prefix_count = 1;
  assert.equal(
    normalizeParliamentAttemptReadResponseV1(active, ATTEMPT_ID)
      .body_states[0].timed_ovn_progress.accepted_ballot_prefix_count,
    1,
  );
  active.body_states[0].timed_ovn_progress.accepted_ballot_prefix_count = 0;
  assert.doesNotThrow(() => normalizeParliamentAttemptReadResponseV1(active, ATTEMPT_ID));

  const malformed = [
    (response) => { response.body_states[0].timed_ovn_progress.accepted_ballot_prefix_count = 3; },
    (response) => { response.body_states[0].timed_ovn_progress.frozen_survivor_count = null; },
    (response) => { response.body_states[0].timed_ovn_progress.ballot_records = []; },
  ];
  for (const mutate of malformed) {
    const response = structuredClone(active);
    mutate(response);
    assert.throws(
      () => normalizeParliamentAttemptReadResponseV1(response, ATTEMPT_ID),
      /prefix|appear together|unknown, aliased, or missing/u,
    );
  }

  const forgedBinding = hiddenBallotReadResponse(10);
  forgedBinding.body_states[0].timed_ovn_progress.ballot_attempt_id = ID(0xfe);
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(forgedBinding, ATTEMPT_ID),
    /differs from timed_ovn_progress/u,
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
        response.certificate.body_bindings[0].body = "agenda-council";
        response.certificate.body_bindings[0].sortition_request.body = "agenda-council";
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
  duplicateBinding.required_bodies.splice(1, 0, {
    body: "agenda-council",
    decision_mode: { mode: "PublicFinding" },
  });
  const secondState = structuredClone(duplicateBinding.body_states[0]);
  secondState.body = "agenda-council";
  duplicateBinding.body_states.splice(1, 0, secondState);
  const secondBinding = structuredClone(duplicateBinding.certificate.body_bindings[0]);
  secondBinding.body = "agenda-council";
  secondBinding.sortition_request.body = "agenda-council";
  duplicateBinding.certificate.body_bindings.splice(1, 0, secondBinding);
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(duplicateBinding, ATTEMPT_ID),
    /reuse bodyInstanceId/u,
  );
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

test("narrow policy certificates enforce atomic initial and delayed retry confirmation heights", () => {
  assert.doesNotThrow(() => normalizeParliamentAttemptReadResponseV1(
    narrowPolicyReadResponse(),
    ATTEMPT_ID,
  ));
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(
      narrowPolicyReadResponse({ confirmationRequestHeight: 53 }),
      ATTEMPT_ID,
    ),
    /atomic initial request/u,
  );
  assert.doesNotThrow(() => normalizeParliamentAttemptReadResponseV1(
    narrowPolicyReadResponse({ confirmationSequence: 1, confirmationRequestHeight: 53 }),
    ATTEMPT_ID,
  ));
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(
      narrowPolicyReadResponse({ confirmationSequence: 1 }),
      ATTEMPT_ID,
    ),
    /follow it on retry/u,
  );
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(
      narrowPolicyReadResponse({ includeConfirmation: false }),
      ATTEMPT_ID,
    ),
    /confirmation-jury presence/u,
  );
  const reusedPulse = narrowPolicyReadResponse();
  reusedPulse.certificate.body_bindings[1].beacon_pulse_id =
    reusedPulse.certificate.body_bindings[0].beacon_pulse_id;
  assert.throws(
    () => normalizeParliamentAttemptReadResponseV1(reusedPulse, ATTEMPT_ID),
    /fresh pulse/u,
  );
});

test("attempt read rejects malformed hidden-ballot retry, corpus, tally, and outcome", () => {
  const mutations = [
    [
      (response) => { response.certificate.body_bindings[0].ballot.ballot_attempt_sequence = 17; },
      /retri/u,
    ],
    [
      (response) => { response.certificate.body_bindings[0].ballot.max_corpus_entries = 2; },
      /frozen ballot lifecycle/u,
    ],
    [
      (response) => { response.certificate.body_bindings[0].ballot.tally.abstain = 1; },
      /tally/u,
    ],
    [
      (response) => { response.certificate.body_bindings[0].ballot.outcome = { outcome: "Rejected", details: null }; },
      /approving aggregate outcome/u,
    ],
    [
      (response) => { response.certificate.body_bindings[0].ballot.outcome = { outcome: "Rejected" }; },
      /ballot\.outcome contains unknown, aliased, or missing fields/u,
    ],
  ];
  for (const [mutate, expected] of mutations) {
    const forged = hiddenBallotReadResponse(10);
    mutate(forged);
    assert.throws(
      () => normalizeParliamentAttemptReadResponseV1(forged, ATTEMPT_ID),
      expected,
    );
  }
});

test("release context exposes a complete bounded transcript and partials remain context-bound", () => {
  const response = tleReleaseContextResponse();
  const parsed = normalizeParliamentTleReleaseContextResponseV1(response, ID(0x33));
  assert.equal(parsed.tle_key_session.public_shares.length, 4);
  assert.equal(parsed.tle_key_session.qualified_dealer_commitments.length, 2);
  assert.equal(
    parliamentTleReleaseContextReadPathV1(ID(0x33)),
    `/v1/gov/parliament/ballots/${ID(0x33)}/release-context`,
  );
  assert.equal(
    parliamentTlePartialReleasePathV1(ID(0x33)),
    `/v1/gov/parliament/ballots/${ID(0x33)}/partial-release`,
  );
  const partial = tlePartialReleaseResponse(response);
  assert.equal(normalizeParliamentTlePartialReleaseShareV1(partial, {
    expectedKeySessionId: response.tle_key_session.key_session_id,
    expectedIdentityDigest: response.identity_digest,
    committeeSize: response.tle_key_session.committee_size,
  }).participant_index, 1);

  const missingShare = structuredClone(response);
  missingShare.tle_key_session.public_shares.pop();
  assert.throws(
    () => normalizeParliamentTleReleaseContextResponseV1(missingShare, ID(0x33)),
    /complete ordered committee/u,
  );
  const aliasedDealer = structuredClone(response);
  aliasedDealer.tle_key_session.qualified_dealer_commitments[0].dealerIndex = 1;
  assert.throws(
    () => normalizeParliamentTleReleaseContextResponseV1(aliasedDealer, ID(0x33)),
    /unknown, aliased, or missing/u,
  );
  const wrongDigest = structuredClone(response);
  wrongDigest.identity_digest[0] ^= 1;
  assert.throws(
    () => normalizeParliamentTleReleaseContextResponseV1(wrongDigest, ID(0x33)),
    /threshold-session-framed/u,
  );
  const crossBound = structuredClone(partial);
  crossBound.key_session_id = ID(0x77);
  assert.throws(
    () => normalizeParliamentTlePartialReleaseShareV1(crossBound, {
      expectedKeySessionId: response.tle_key_session.key_session_id,
      expectedIdentityDigest: response.identity_digest,
      committeeSize: 4,
    }),
    /authorized release context/u,
  );
});

test("casting context is strict, phase-safe, and carries one bounded canonical archive", () => {
  const response = timedOvnCastingContextResponse();
  const parsed = normalizeParliamentTimedOvnCastingContextResponseV1(response, ID(0x33));
  assert.equal(parsed.phase, "Registered");
  assert.equal(parsed.registration_records_hex[0].length, 2 * 3_624);
  assert.equal(
    parliamentTimedOvnCastingContextReadPathV1(ID(0x33)),
    `/v1/gov/parliament/ballots/${ID(0x33)}/casting-context`,
  );
  assert.equal(
    parliamentTimedOvnCastingProofPathV1(ID(0x33)),
    `/v1/gov/parliament/ballots/${ID(0x33)}/casting-proof`,
  );
  const wrongPhase = structuredClone(response);
  wrongPhase.phase = "SurvivorsFrozen";
  assert.throws(
    () => normalizeParliamentTimedOvnCastingContextResponseV1(wrongPhase, ID(0x33)),
    /requires bounded survivor/u,
  );
  const emptyFrozen = structuredClone(response);
  emptyFrozen.phase = "SurvivorsFrozen";
  emptyFrozen.survivor_participant_hashes = [];
  emptyFrozen.release_identity = tleReleaseContextResponse().release_identity;
  assert.throws(
    () => normalizeParliamentTimedOvnCastingContextResponseV1(emptyFrozen, ID(0x33)),
    /requires bounded survivor/u,
  );
  const alias = structuredClone(response);
  alias.archiveNoritoBase64 = alias.archive_norito_base64;
  delete alias.archive_norito_base64;
  assert.throws(
    () => normalizeParliamentTimedOvnCastingContextResponseV1(alias, ID(0x33)),
    /unknown, aliased, or missing/u,
  );
  const noncanonicalArchive = structuredClone(response);
  noncanonicalArchive.archive_norito_base64 = "TlJUMA";
  assert.throws(
    () => normalizeParliamentTimedOvnCastingContextResponseV1(noncanonicalArchive, ID(0x33)),
    /canonical padded standard base64/u,
  );
});

test("ToriiClient exposes every canonical authenticated Parliament path", async () => {
  const canonicalAuth = { accountId: "alice-1@wonderland", privateKey: Buffer.alloc(32, 7) };
  const calls = [];
  const castingProofResponse = exactNoritoFrame(
    Buffer.from([1]),
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1,
  );
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
    if (path.endsWith("/release-context")) {
      return { payload: tleReleaseContextResponse() };
    }
    if (path.endsWith("/casting-context")) {
      return { payload: timedOvnCastingContextResponse() };
    }
    if (path.endsWith("/casting-proof")) {
      return new Response(castingProofResponse, {
        status: 200,
        headers: { "Content-Type": "application/x-norito" },
      });
    }
    if (path.endsWith("/partial-release")) {
      const context = tleReleaseContextResponse();
      return { payload: tlePartialReleaseResponse(context) };
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
  await client.getParliamentTimedOvnCastingContextV1(ID(0x33), { canonicalAuth });
  assert.deepEqual(
    await client.getParliamentTimedOvnCastingProofPageV1(ID(0x33), 17, { canonicalAuth }),
    castingProofResponse,
  );
  const releaseContext = await client.getParliamentTleReleaseContextV1(ID(0x33), {
    canonicalAuth,
  });
  await client.requestParliamentTlePartialReleaseV1(ID(0x33), {
    canonicalAuth,
    expectedKeySessionId: releaseContext.tle_key_session.key_session_id,
    expectedIdentityDigest: releaseContext.identity_digest,
    committeeSize: releaseContext.tle_key_session.committee_size,
  });
  await client.draftParliamentTransitionV1(
    ATTEMPT_ID,
    { transition: "CompleteQualification" },
    { canonicalAuth, expectedTransitionDigest: ROOT },
  );
  assert.deepEqual(calls.map(({ method, path }) => [method, path]), [
    ["POST", PARLIAMENT_ATTEMPT_DRAFT_PATH_V1],
    ["GET", `/v1/gov/parliament/attempts/${ATTEMPT_ID}`],
    ["GET", `/v1/gov/parliament/ballots/${ID(0x33)}/casting-context`],
    ["POST", `/v1/gov/parliament/ballots/${ID(0x33)}/casting-proof`],
    ["GET", `/v1/gov/parliament/ballots/${ID(0x33)}/release-context`],
    ["POST", `/v1/gov/parliament/ballots/${ID(0x33)}/partial-release`],
    ["POST", PARLIAMENT_TRANSITION_DRAFT_PATH_V1],
  ]);
  const attemptBody = JSON.parse(calls[0].options.body);
  assert.deepEqual(Object.keys(attemptBody), ["version", "proposal", "attempt_sequence"]);
  assert.equal(
    Buffer.from(calls[3].options.body).toString("hex"),
    encodeParliamentTimedOvnCastingProofRequestV1(17).toString("hex"),
  );
  assert.deepEqual(calls[3].options.headers, {
    "Content-Type": "application/x-norito",
    Accept: "application/x-norito",
    "Accept-Encoding": "identity",
  });
  assert.equal(calls[3].options.disableRetries, true);
  assert.equal(calls[3].options.redirect, "error");
  assert.equal(calls[5].options.body, undefined);
  const transitionBody = JSON.parse(calls[6].options.body);
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
    RegisterBallotAttempt: {
      body_instance_id: one,
      ballot_attempt_id: two,
      sequence: 0,
      tle_session_id: one,
      tle_key_session_id: two,
      release_beacon_session_id: one,
      release_height: 1,
    },
    CloseBallotRegistration: { ballot_attempt_id: one },
    FreezeBallotSurvivors: { ballot_attempt_id: one },
    FreezeTimedOvnCorpus: {
      ballot_attempt_id: one,
      ballot_records: [Array(2_858).fill(1)],
    },
    BeginBallotOpeningBatch: {
      ballot_attempt_ids: [one],
      release_beacon_session_id: two,
      release_height: 1,
      pulse_id: one,
    },
    FailBallotNoResult: { ballot_attempt_id: one },
    FinalizeOpenedBallot: {
      ballot_attempt_id: one,
      final_release: {
        key_session_id: two,
        identity_digest: ROOT,
        signature: Array(48).fill(1),
      },
    },
    RecordInvitationResponse: {
      election_attempt_id: one,
      body: "rules-committee",
      decision: { decision: "Accept" },
    },
    RegisterBallotParticipant: {
      ballot_attempt_id: one,
      registration_record: Array(3_624).fill(1),
    },
    RecordBallotDropout: { ballot_attempt_id: one },
    FailPublicFindingNoResult: { body_instance_id: one },
  };
  return tag === "CompleteQualification" || tag === "RegisterInitialSortition"
    ? { transition: tag }
    : { transition: tag, payload: payloads[tag] };
}

function readResponse() {
  const response = {
    version: 1,
    current_height: 20,
    attempt: {
      id: ATTEMPT_ID,
      proposal_content_id: PROPOSAL_ID,
      sequence: 0,
      risk_tier: { tier: "Standard" },
      stage: { stage: "Rules" },
      status: { status: "Certified" },
    },
    policy_version: 1,
    required_bodies: [{
      body: "rules-committee",
      decision_mode: { mode: "PublicFinding" },
    }],
    body_states: [{
      body: "rules-committee",
      body_instance_id: ID(1),
      status: { status: "Approved" },
      public_finding_opened_at_height: 1,
      public_finding_phase_blocks: 7,
      public_finding_deadline_height: 8,
      no_result_kind: null,
      no_result_height: null,
      timed_ovn_progress: null,
    }],
    certificate: {
      proposal_content_id: PROPOSAL_ID,
      governance_attempt_id: ATTEMPT_ID,
      governance_attempt_sequence: 0,
      risk_tier: { tier: "Standard", details: null },
      body_bindings: [{
        body_instance_id: ID(1),
        election_attempt_id: ID(2),
        election_attempt_sequence: 0,
        sortition_request_id: ID(3),
        sortition_request: {
          id: ID(3),
          governance_attempt_id: ATTEMPT_ID,
          body_election_attempt_id: ID(2),
          body: "rules-committee",
          candidate_root: ROOT,
          candidate_count: 3,
          target_seats: 3,
          request_height: 1,
          pulse_height: 2,
          beacon_session_id: ID(4),
        },
        body: "rules-committee",
        original_seats: 3,
        beacon_session_id: ID(4),
        beacon_pulse_id: ID(5),
        roster_root: ROOT,
        assignment_root: ROOT,
        result_root: ROOT,
        result_height: 8,
        public_finding: {
          endorsement_root: ROOT,
          endorsing_assignments: [ID(0x11), ID(0x12)],
          endorsements: 2,
          quorum: 2,
        },
        ballot: null,
      }],
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
  const policy = policyJuryCertificateComponents(10);
  response.required_bodies.push(policy.requiredBody);
  response.body_states.push(policy.bodyState);
  response.certificate.body_bindings.push(policy.binding);
  return response;
}

function policyJuryCertificateComponents(commitmentClosedAtHeight) {
  const requiredBody = {
    body: "policy-jury",
    decision_mode: { mode: "HiddenBindingBallot" },
  };
  const bodyState = {
    body: "policy-jury",
    body_instance_id: ID(0x21),
    status: { status: "Approved" },
    public_finding_opened_at_height: null,
    public_finding_phase_blocks: null,
    public_finding_deadline_height: null,
    no_result_kind: null,
    no_result_height: null,
    timed_ovn_progress: {
      ballot_attempt_id: ID(0x26),
      status: { status: "Finalized" },
      frozen_survivor_count: 3,
      accepted_ballot_prefix_count: 3,
    },
  };
  const binding = {
    body_instance_id: ID(0x21),
    election_attempt_id: ID(0x22),
    election_attempt_sequence: 0,
    sortition_request_id: ID(0x23),
    sortition_request: {
      id: ID(0x23),
      governance_attempt_id: ATTEMPT_ID,
      body_election_attempt_id: ID(0x22),
      body: "policy-jury",
      candidate_root: ROOT,
      candidate_count: 3,
      target_seats: 3,
      request_height: 1,
      pulse_height: 2,
      beacon_session_id: ID(0x24),
    },
    body: "policy-jury",
    original_seats: 3,
    beacon_session_id: ID(0x24),
    beacon_pulse_id: ID(0x25),
    roster_root: ROOT,
    assignment_root: ROOT,
    result_root: ROOT,
    result_height: 18,
    public_finding: null,
    ballot: {
    ballot_attempt_id: ID(0x26),
    ballot_attempt_sequence: 0,
    tle_session_id: ID(0x27),
    tle_key_session_id: ID(0x28),
    registration_root: Array(32).fill(0x41),
    dropout_root: Array(32).fill(0x42),
    survivor_root: Array(32).fill(0x43),
    corpus_root: Array(32).fill(0x44),
    no_recovery_root: Array(32).fill(0x45),
    timed_commitment_root: Array(32).fill(0x46),
    release_beacon_session_id: ID(0x29),
    registered_at_height: 1,
    registration_close_height: 5,
    survivor_freeze_height: 8,
    commitment_close_height: 13,
    registration_closed_at_height: 5,
    survivors_frozen_at_height: 8,
    commitment_closed_at_height: commitmentClosedAtHeight,
    max_ballot_retries: 16,
    max_corpus_entries: 3,
    release_height: 15,
    opening_deadline_height: 21,
    release_pulse_id: ID(0x2a),
    opening_height: 16,
    opening_root: Array(32).fill(0x47),
    tally: {
      original_seats: 3,
      accepted_ballots: 3,
      aye: 2,
      nay: 1,
      abstain: 0,
    },
    outcome: { outcome: "Approved", details: null },
    },
  };
  return { binding, bodyState, requiredBody };
}

function hiddenBallotReadResponse(commitmentClosedAtHeight) {
  const response = readResponse();
  response.attempt.stage = { stage: "PolicyJury" };
  response.attempt.status = { status: "Certified" };
  response.required_bodies = [response.required_bodies.at(-1)];
  response.body_states = [response.body_states.at(-1)];
  response.certificate.body_bindings = [response.certificate.body_bindings.at(-1)];
  response.certificate.body_bindings[0].ballot.commitment_closed_at_height =
    commitmentClosedAtHeight;
  response.certificate.certified_at_height = 18;
  response.certificate.enact_at_height = 30;
  return response;
}

function narrowPolicyReadResponse({
  confirmationSequence = 0,
  confirmationRequestHeight = 52,
  includeConfirmation = true,
} = {}) {
  const response = hiddenBallotReadResponse(47);
  const policy = response.certificate.body_bindings[0];
  policy.original_seats = 21;
  policy.sortition_request.candidate_count = 21;
  policy.sortition_request.target_seats = 21;
  policy.result_height = 52;
  Object.assign(policy.ballot, {
    registered_at_height: 3,
    registration_close_height: 25,
    survivor_freeze_height: 46,
    commitment_close_height: 47,
    registration_closed_at_height: 25,
    survivors_frozen_at_height: 46,
    commitment_closed_at_height: 47,
    max_corpus_entries: 21,
    release_height: 49,
    opening_deadline_height: 55,
    opening_height: 50,
    tally: {
      original_seats: 21,
      accepted_ballots: 21,
      aye: 11,
      nay: 10,
      abstain: 0,
    },
  });
  response.body_states[0].timed_ovn_progress.frozen_survivor_count = 21;
  response.body_states[0].timed_ovn_progress.accepted_ballot_prefix_count = 21;
  response.current_height = 110;
  response.certificate.certified_at_height = 52;
  response.certificate.enact_at_height = 120;
  if (!includeConfirmation) return response;

  const confirmation = structuredClone(policy);
  confirmation.body = "confirmation-jury";
  confirmation.body_instance_id = ID(0x31);
  confirmation.election_attempt_id = ID(0x32);
  confirmation.election_attempt_sequence = confirmationSequence;
  confirmation.sortition_request_id = ID(0x33);
  Object.assign(confirmation.sortition_request, {
    id: ID(0x33),
    body_election_attempt_id: ID(0x32),
    body: "confirmation-jury",
    request_height: confirmationRequestHeight,
    pulse_height: confirmationRequestHeight + 1,
    beacon_session_id: ID(0x34),
  });
  confirmation.beacon_session_id = ID(0x34);
  confirmation.beacon_pulse_id = ID(0x35);
  confirmation.result_height = 103;
  Object.assign(confirmation.ballot, {
    ballot_attempt_id: ID(0x36),
    tle_session_id: ID(0x37),
    tle_key_session_id: ID(0x38),
    release_beacon_session_id: ID(0x39),
    registered_at_height: 55,
    registration_close_height: 77,
    survivor_freeze_height: 98,
    commitment_close_height: 99,
    registration_closed_at_height: 77,
    survivors_frozen_at_height: 98,
    commitment_closed_at_height: 99,
    release_height: 101,
    opening_deadline_height: 106,
    release_pulse_id: ID(0x3a),
    opening_height: 102,
  });
  response.required_bodies.push({
    body: "confirmation-jury",
    decision_mode: { mode: "HiddenBindingBallot" },
  });
  response.body_states.push({
    ...structuredClone(response.body_states[0]),
    body: "confirmation-jury",
    body_instance_id: confirmation.body_instance_id,
    timed_ovn_progress: {
      ...structuredClone(response.body_states[0].timed_ovn_progress),
      ballot_attempt_id: confirmation.ballot.ballot_attempt_id,
    },
  });
  response.certificate.body_bindings.push(confirmation);
  response.certificate.certified_at_height = confirmation.result_height;
  return response;
}

function tleReleaseContextResponse() {
  const ballotAttemptId = ID(0x33);
  const bodyInstanceId = ID(0x22);
  const keySessionId = ID(0x44);
  const releaseHeight = 40;
  const survivorRoot = Array(32).fill(0x61);
  const noRecoveryRoot = Array(32).fill(0x62);
  const parameterHash = Array(32).fill(0x63);
  const identityPayload = Buffer.concat([
    Buffer.from("iroha.parliament.tle.identity-payload.v1\0", "utf8"),
    uint16be(1),
    Buffer.from(ATTEMPT_ID, "hex"),
    Buffer.from(bodyInstanceId, "hex"),
    Buffer.from(ballotAttemptId, "hex"),
    Buffer.from(survivorRoot),
    Buffer.from(noRecoveryRoot),
    uint64be(releaseHeight),
    Buffer.from(parameterHash),
  ]);
  assert.equal(identityPayload.length, 243);
  const tleKeySession = {
    version: 1,
    key_session_id: keySessionId,
    network_id: Array(32).fill(0x45),
    roster_hash: Array(32).fill(0x46),
    committee_size: 4,
    threshold: 2,
    generator_h: Array(96).fill(0x47),
    generator_v: Array(96).fill(0x48),
    qualified_dealers: [1, 2],
    qualified_dealer_commitments: [1, 2].map((dealerIndex) => ({
      dealer_index: dealerIndex,
      coefficient_commitments: [
        Array(96).fill(0x50 + dealerIndex),
        Array(96).fill(0x60 + dealerIndex),
      ],
      constant_pok_commitment: Array(96).fill(0x70 + dealerIndex),
      constant_pok_response: Array(32).fill(0x80 + dealerIndex),
    })),
    dkg_event_hash: Array(32).fill(0x49),
    group_public_key: Array(96).fill(0x4a),
    public_shares: [1, 2, 3, 4].map((index) => ({
      index,
      participant_hash: Array(32).fill(0x20 + index),
      public_key_share: Array(96).fill(0x30 + index),
    })),
    transcript_hash: Array(32).fill(0x4b),
  };
  const message = Buffer.concat([
    Buffer.from("iroha.threshold-bls.message.v1\0", "utf8"),
    Buffer.from("iroha.threshold-bls.session.v1\0", "utf8"),
    uint16be(1),
    Buffer.from([2]),
    Buffer.from(tleKeySession.network_id),
    Buffer.from(keySessionId, "hex"),
    Buffer.from(tleKeySession.roster_hash),
    uint16be(tleKeySession.committee_size),
    uint16be(tleKeySession.threshold),
    uint32be(identityPayload.length),
    identityPayload,
  ]);
  return {
    version: 1,
    current_height: 42,
    ballot_attempt_id: ballotAttemptId,
    governance_attempt_id: ATTEMPT_ID,
    body_instance_id: bodyInstanceId,
    status: { status: "Opening" },
    release_height: releaseHeight,
    opening_deadline_height: 45,
    tle_key_session: tleKeySession,
    release_identity: {
      tle_key_session_id: keySessionId,
      governance_attempt_id: ATTEMPT_ID,
      body_instance_id: bodyInstanceId,
      ballot_attempt_id: ballotAttemptId,
      survivor_corpus_root: survivorRoot,
      no_recovery_root: noRecoveryRoot,
      target_finalized_height: releaseHeight,
      parameter_hash: parameterHash,
    },
    identity_digest: [...sha256(message)],
    identity_payload_hex: identityPayload.toString("hex"),
  };
}

function timedOvnCastingContextResponse() {
  const release = tleReleaseContextResponse();
  return {
    version: 1,
    current_height: 20,
    phase: "Registered",
    session: {
      network_id: release.tle_key_session.network_id,
      proposal_content_id: PROPOSAL_ID,
      governance_attempt_id: ATTEMPT_ID,
      body_instance_id: release.body_instance_id,
      ballot_attempt_id: release.ballot_attempt_id,
      parameter_hash: release.release_identity.parameter_hash,
      tle_key_session_id: release.tle_key_session.key_session_id,
      tle_key_transcript_hash: release.tle_key_session.transcript_hash,
      tle_master_public_key: release.tle_key_session.group_public_key,
    },
    registration_opened_at_finalized_height: 10,
    target_finalized_height: 40,
    tle_key_session: release.tle_key_session,
    registration_records_hex: [Buffer.alloc(3_624, 0x81).toString("hex")],
    survivor_participant_hashes: null,
    release_identity: null,
    archive_norito_base64: Buffer.from("NRT0", "ascii").toString("base64"),
  };
}

function tlePartialReleaseResponse(context) {
  return {
    key_session_id: context.tle_key_session.key_session_id,
    identity_digest: context.identity_digest,
    participant_index: 1,
    sigma: Array(48).fill(0x91),
    proof_x: Array(96).fill(0x92),
    proof_y: Array(48).fill(0x93),
    z_s: Array(32).fill(0x94),
    z_r: Array(32).fill(0x95),
    z_u: Array(32).fill(0x96),
  };
}

function uint16be(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
}

function uint32be(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function uint64be(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
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
