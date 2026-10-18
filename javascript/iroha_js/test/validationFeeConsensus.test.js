import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const nativePolicy = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_policy_v1.json", import.meta.url), "utf8"));
const nativeConversion = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_native_conversion_v1.json", import.meta.url), "utf8"));
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import {
  createValidationFeeConsensusApi,
  normalizeValidationFeeLedgerBindingV1,
  normalizeValidationFeeCheckpointV1,
} from "../src/validationFeeConsensus.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { NetworkId } from "../src/networkId.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { TORII_TEST_NATIVE_BINDING } from "../src/toriiTestHooks.js";

const binding = Object.freeze({
  schema: "iroha.validation-fee-ledger-binding.v1",
  networkId: NetworkId.fromBytes(Buffer.from("13".repeat(32), "hex")),
  policyChainGenesisHash: "35".repeat(32),
  checkpoint: Object.freeze({
    // Opaque transport tokens in mocked native-owner tests, not finality authority.
    checkpointNorito: Buffer.from([100, 57]),
  }),
});
const proposalOperator = AccountAddress.fromAccount({
  publicKey: Buffer.from(ed25519.getPublicKey(Buffer.alloc(32, 0x31))),
}).toI105();

function id(byte) {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

function completeParliamentProposal(kind, proposalOctet, offset) {
  const proposalId = proposalOctet.repeat(32);
  const governanceAttemptId = id(offset);
  const bodyInstanceId = id(offset + 1);
  const electionAttemptId = id(offset + 2);
  const sortitionRequestId = id(offset + 3);
  const beaconSessionId = id(offset + 4);
  const beaconPulseId = id(offset + 5);
  const root = (delta) => Array(32).fill(offset + delta);
  // Synthetic projection only: a three-seat public-finding body keeps its lifecycle below
  // result/certification 119 without changing the mocked proof-page heights. The private-jury
  // binding has no SDK parser until the anonymous-ballot result binding is supported.
  return {
    proposal_kind: kind,
    proposal_operator: proposalOperator,
    proposal_id: proposalId,
    payload_hash: proposalId,
    governance_certificate_id: id(offset + 6),
    governance_certificate: {
      proposal_content_id: proposalId,
      governance_attempt_id: governanceAttemptId,
      governance_attempt_sequence: 0,
      risk_tier: { tier: "Standard", details: null },
      body_bindings: [{
        body_instance_id: bodyInstanceId,
        election_attempt_id: electionAttemptId,
        election_attempt_sequence: 0,
        sortition_request_id: sortitionRequestId,
        sortition_request: {
          id: sortitionRequestId,
          governance_attempt_id: governanceAttemptId,
          body_election_attempt_id: electionAttemptId,
          body: "rules-committee",
          candidate_root: root(7),
          candidate_count: 3,
          target_seats: 3,
          request_height: 10,
          pulse_height: 11,
          beacon_session_id: beaconSessionId,
        },
        body: "rules-committee",
        original_seats: 3,
        beacon_session_id: beaconSessionId,
        beacon_pulse_id: beaconPulseId,
        roster_root: root(8),
        assignment_root: root(9),
        result_root: root(10),
        result_height: 119,
        public_finding: {
          endorsement_root: root(11),
          endorsing_assignments: [id(offset + 12), id(offset + 13)],
          endorsements: 2,
          quorum: 2,
        },
        ballot: null,
      }],
      policy_version: 1,
      effect_preimage_hash: root(23),
      expected_head: { state: "Absent", head: { subject_id: root(24) } },
      certified_at_height: 119,
      enact_at_height: 120,
    },
    certified_at_height: "119",
    enacted_at_height: "120",
  };
}

function completeCurrentPolicy() {
  return {
    activePolicyVersion: "1",
    activePolicyHash: "ab".repeat(32),
    feeAssetDefinitionId: nativePolicy.ds_asset_id,
    feeScale: 2,
    feeMinorUnits: "10",
    chargingMode: "RETAIL_MONTHLY_ALLOWANCE",
    effective_from_ms: 1793451600000,
    notice_published_at_ms: 1790859600000,
    retail_schedule: { included_payments: 50, overage_minor: 10, maintenance_tiers: [
      [0,100],[50000,200],[250000,300],[1000000,500],[5000000,1000],
    ].map(([minimum_average_balance_minor,monthly_fee_minor]) => ({minimum_average_balance_minor,monthly_fee_minor})) },
    effectiveFromHeight: "121",
    parliament: completeParliamentProposal("ValidationFeePolicyV1", "02", 0x20),
    reward_custody: structuredClone(nativePolicy.reward_custody),
  };
}

function completeVerifiedProjection() {
  return {
    schema: "iroha.validation_fee.verified_policy_projection.v1",
    version: 1,
    network_id: binding.networkId.toString(),
    policy_chain_genesis_hash: binding.policyChainGenesisHash,
    registry_hash: "79".repeat(32),
    head_policy_version: 1,
    head_policy_hash: "ab".repeat(32),
    current_policy: completeCurrentPolicy(),
    conversion_policy: {revision: 1, binding: structuredClone(nativeConversion),
      authority: completeParliamentProposal("ValidationFeePayoutLifecycleV1", "08", 0x50),
      lifecycle_seal_hash: "cd".repeat(32)},
    trusted_checkpoint_height: 100,
    trusted_checkpoint_context_id: "57".repeat(32),
    evaluated_block_height: 127,
    evaluated_context_id: "bd".repeat(32),
    evaluated_block_hash: "df".repeat(32),
    observed_ledger_tip_height: 190,
    more_available: true,
  };
}

function withNativeBinding(native, body) {
  return body(
    createValidationFeeConsensusApi(createNativeRuntime(native)),
  );
}

test("validation-fee consensus factories isolate immutable native runtimes", async () => {
  const checkpoint = { checkpointNorito: Buffer.from([100, 3]) };
  const bindingA = {
    connectNoritoBridgeAbiVersion: () => 30,
    validationFeeCurrentPolicyProofRequestV1: () => Buffer.from([0xa1]),
    validationFeeVerifyCurrentPolicyProofV1() {},
  };
  const apiA = createValidationFeeConsensusApi(createNativeRuntime(bindingA));
  const apiB = createValidationFeeConsensusApi(createNativeRuntime({
    connectNoritoBridgeAbiVersion: () => 30,
    validationFeeCurrentPolicyProofRequestV1: () => Buffer.from([0xb2]),
    validationFeeVerifyCurrentPolicyProofV1() {},
  }));
  bindingA.validationFeeCurrentPolicyProofRequestV1 = () => Buffer.from([0xff]);

  const [requestA, requestB] = await Promise.all([
    Promise.resolve().then(() =>
      apiA.encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint)),
    Promise.resolve().then(() =>
      apiB.encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint)),
  ]);
  assert.equal(Object.isFrozen(apiA), true);
  assert.deepEqual(requestA, Buffer.from([0xa1]));
  assert.deepEqual(requestB, Buffer.from([0xb2]));
});

function nativePage(projection, promotedCheckpointNorito = Buffer.from([127, 189])) {
  return { projectionJson: JSON.stringify(projection), promotedCheckpointNorito };
}

function verifyProjectionFixture(projection) {
  return withNativeBinding(
    {
      connectNoritoBridgeAbiVersion() {
        return 30;
      },
      validationFeeCurrentPolicyProofRequestV1() {},
      validationFeeVerifyCurrentPolicyProofV1() {
        return nativePage(projection);
      },
    },
    ({ verifyValidationFeeCurrentPolicyProofV1: verify }) =>
      verify(
        Buffer.from([9]),
        binding,
        binding.checkpoint, 753,
      ).projection,
  );
}

test("immutable ledger binding requires marked Iroha hashes and rejects aliases", () => {
  const normalized = normalizeValidationFeeLedgerBindingV1(binding);
  assert.equal(normalized.networkId, binding.networkId);
  assert.equal(normalized.policyChainGenesisHash, "35".repeat(32));
  assert.deepEqual(normalized.checkpoint.checkpointNorito, binding.checkpoint.checkpointNorito);
  assert.throws(
    () =>
      normalizeValidationFeeLedgerBindingV1({
        ...binding,
        signedPolicy: {},
      }),
    /must contain exactly/u,
  );
  assert.throws(
    () =>
      normalizeValidationFeeLedgerBindingV1({
        ...binding,
        chainId: "legacy-label",
      }),
    /must contain exactly/u,
  );
  assert.throws(
    () => NetworkId.fromBytes(Buffer.from("12".repeat(32), "hex")),
    /canonical Iroha hash marker/u,
  );
});

test("request encoder delegates only full independently retained checkpoint bytes", () => {
  const bytes = Buffer.from([100, 3]);
  const checkpoint = normalizeValidationFeeCheckpointV1({ checkpointNorito: bytes });
  let nativeCalls = 0;
  bytes.fill(0);
  checkpoint.checkpointNorito.fill(0);
  withNativeBinding(
    {
      connectNoritoBridgeAbiVersion: () => 30,
      validationFeeCurrentPolicyProofRequestV1(checkpointNorito) {
        nativeCalls += 1;
        assert.deepEqual(checkpointNorito, Buffer.from([100, 3]));
        return Buffer.from([1, 2, 3]);
      },
      validationFeeVerifyCurrentPolicyProofV1() {},
    },
    ({ encodeValidationFeeCurrentPolicyProofRequestV1: encode }) => {
      assert.deepEqual(encode(checkpoint), Buffer.from([1, 2, 3]));
      for (const [malformed, message] of [
        [{ height: 100, contextId: "03".repeat(32) }, /must contain exactly/u],
        [{ ...checkpoint, height: 100 }, /must contain exactly/u],
        [{ checkpointNorito: "0303" }, /must be exact bytes backed by an ordinary ArrayBuffer/u],
        [{ checkpointNorito: Buffer.alloc(0) }, /must contain 1/u],
        [{ checkpointNorito: new Uint8Array(68 * 1024 * 1024 + 1) }, /must contain 1/u],
      ]) assert.throws(() => encode(malformed), { name: "TypeError", message });
      assert.equal(nativeCalls, 1, "malformed checkpoints must fail before native encoding");
      const sliced = new Uint8Array([0, 100, 3, 0]).subarray(1, 3);
      assert.deepEqual(encode({ checkpointNorito: sliced }), Buffer.from([1, 2, 3]));
    },
  );
});

test("native verified projection remains bound to the release checkpoint", () => {
  const projection = {
    schema: "iroha.validation_fee.verified_policy_projection.v1",
    version: 1,
    network_id: binding.networkId.toString(),
    policy_chain_genesis_hash: binding.policyChainGenesisHash,
    registry_hash: "79".repeat(32),
    head_policy_version: 2,
    head_policy_hash: "9b".repeat(32),
    current_policy: null,
    conversion_policy: null,
    trusted_checkpoint_height: 100,
    trusted_checkpoint_context_id: "57".repeat(32),
    evaluated_block_height: 127,
    evaluated_context_id: "bd".repeat(32),
    evaluated_block_hash: "df".repeat(32),
    observed_ledger_tip_height: 190,
    more_available: true,
  };
  withNativeBinding(
    {
      connectNoritoBridgeAbiVersion() {
        return 30;
      },
      validationFeeCurrentPolicyProofRequestV1() {},
      validationFeeVerifyCurrentPolicyProofV1(
        proof,
        networkId,
        policyGenesis,
        checkpointNorito,
        networkPrefix,
      ) {
        assert.deepEqual(proof, Buffer.from([9]));
        assert.deepEqual(networkId, Buffer.from(binding.networkId.toBytes()));
        assert.deepEqual(
          policyGenesis,
          Buffer.from(binding.policyChainGenesisHash, "hex"),
        );
        assert.deepEqual(checkpointNorito, binding.checkpoint.checkpointNorito);
        assert.equal(networkPrefix, 753);
        return nativePage(projection);
      },
    },
    ({ verifyValidationFeeCurrentPolicyProofV1: verify }) => {
      const { projection: verified, promotedCheckpoint } = verify(
        Buffer.from([9]),
        binding,
        binding.checkpoint, 753,
      );
      assert.deepEqual(promotedCheckpoint.checkpointNorito, Buffer.from([127, 189]));
      promotedCheckpoint.checkpointNorito.fill(0);
      assert.deepEqual(promotedCheckpoint.checkpointNorito, Buffer.from([127, 189]));
      assert.equal(verified.head_policy_version, 2n);
      assert.equal(verified.evaluated_block_height, 127n);
      assert.equal(verified.more_available, true);
      assert.equal(Object.isFrozen(verified), true);
      projection.evaluated_block_hash = "de".repeat(32);
      assert.throws(
        () =>
          verify(
            Buffer.from([9]),
            binding,
            binding.checkpoint, 753,
          ),
        /canonical Iroha hash marker/u,
      );
      projection.evaluated_block_hash = "df".repeat(32);
    },
  );
});

test("verified current policy enforces and freezes the complete nested projection", () => {
  const verified = verifyProjectionFixture(completeVerifiedProjection());
  assert.equal(verified.current_policy.activePolicyVersion, "1");
  assert.equal(
    verified.current_policy.parliament
      .governance_certificate.proposal_content_id,
    "02".repeat(32),
  );
  assert.equal(
    verified.current_policy.parliament.proposal_operator,
    proposalOperator,
  );
  assert.equal(
    verified.conversion_policy.authority
      .governance_certificate.body_bindings[0].body,
    "rules-committee",
  );
  assert.equal(
    verified.current_policy.retail_schedule.included_payments,
    50,
  );
  assert.equal(
    verified.current_policy.reward_custody.ds_asset_id,
    nativePolicy.ds_asset_id,
  );
  assert.equal(verified.conversion_policy.binding.max_sbd_per_attempt_minor, 1000);
  assert.equal(verified.current_policy.feeScale, 2);
  assert.equal(Object.isFrozen(verified.current_policy), true);
  assert.equal(Object.isFrozen(verified.current_policy.parliament), true);
  assert.equal(
    Object.isFrozen(
      verified.current_policy.parliament
        .governance_certificate.body_bindings[0].public_finding.endorsing_assignments,
    ),
    true,
  );
  assert.equal(Object.isFrozen(verified.current_policy.retail_schedule.maintenance_tiers), true);
  assert.equal(
    Object.isFrozen(verified.current_policy.retail_schedule.maintenance_tiers[0]),
    true,
  );
});

test("verified current policy rejects missing, extra, and mistyped nested fields", () => {
  const malformedFixtures = [
    {
      label: "missing proposal operator",
      mutate(projection) {
        delete projection.current_policy.parliament
          .proposal_operator;
      },
      error: /parliament must contain exactly/u,
    },
    {
      label: "empty proposal operator",
      mutate(projection) {
        projection.current_policy.parliament.proposal_operator =
          "";
      },
      error: /proposal_operator must be a non-empty string/u,
    },
    {
      label: "retired PLAIN electorate projection",
      mutate(projection) {
        projection.current_policy.parliament
          .plainElectorateRules = {};
      },
      error: /parliament must contain exactly/u,
    },
    {
      label: "extra certificate field",
      mutate(projection) {
        projection.conversion_policy.authority
          .governance_certificate.legacy = null;
      },
      error: /certificate contains unknown, aliased, or missing fields/u,
    },
    {
      label: "missing sortition binding",
      mutate(projection) {
        delete projection.current_policy.parliament
          .governance_certificate.body_bindings[0].sortition_request.candidate_root;
      },
      error: /sortition_request contains unknown, aliased, or missing fields/u,
    },
    {
      label: "sortition target exceeds the Rust contract",
      mutate(projection) {
        projection.current_policy.parliament
          .governance_certificate.body_bindings[0].sortition_request.target_seats =
          1001;
      },
      error: /target_seats must be an integer from 1 through 1000/u,
    },
    {
      label: "private-jury result binding is not admitted",
      mutate(projection) {
        const body = projection.current_policy.parliament
          .governance_certificate.body_bindings[0];
        body.body = "policy-jury";
        body.sortition_request.body = "policy-jury";
      },
      error: /private-jury result binding is not admitted until the anonymous-ballot result binding is supported/u,
    },
    {
      label: "retired SBD payout field",
      mutate(projection) {
        projection.conversion_policy.binding.sbdAssetDefinitionId =
          projection.current_policy.reward_custody.ds_asset_id;
      },
      error: /binding contains unsupported fields: sbdAssetDefinitionId$/u,
    },
    {
      label: "invalid conversion loss limit",
      mutate(projection) {
        projection.conversion_policy.binding.max_slippage_bps = 10000;
      },
      error: /conversion limits exceed native bounds/u,
    },
    {
      label: "certificate targets another proposal",
      mutate(projection) {
        projection.current_policy.parliament
          .governance_certificate.proposal_content_id = "04".repeat(32);
      },
      error: /differs from its retained governance certificate/u,
    },
    {
      label: "outer certification height differs",
      mutate(projection) {
        projection.current_policy.parliament
          .certified_at_height = "118";
      },
      error: /differs from its retained governance certificate/u,
    },
    {
      label: "outer certification height is not a decimal string",
      mutate(projection) {
        projection.current_policy.parliament
          .certified_at_height = 119;
      },
      error: /certified_at_height must be a canonical unsigned decimal string/u,
    },
    {
      label: "conversion authority is not available at its enactment height",
      mutate(projection) {
        projection.evaluated_block_height = 120;
      },
      error: /conversion_policy is not available at the finalized height/u,
    },
  ];
  for (const fixture of malformedFixtures) {
    const projection = completeVerifiedProjection();
    fixture.mutate(projection);
    assert.throws(
      () => verifyProjectionFixture(projection),
      fixture.error,
      fixture.label,
    );
  }
});

test("validation-fee proof path rejects a stale native bridge ABI", () => {
  for (const abiVersion of [20, 29, 31]) {
    withNativeBinding(
      {
        connectNoritoBridgeAbiVersion() {
          return abiVersion;
        },
        validationFeeCurrentPolicyProofRequestV1() {
          return Buffer.from([1]);
        },
        validationFeeVerifyCurrentPolicyProofV1() {},
      },
      ({ encodeValidationFeeCurrentPolicyProofRequestV1: encode }) => {
        assert.throws(
          () => encode(binding.checkpoint),
          /ABI 30/u,
          String(abiVersion),
        );
      },
    );
  }
});

test("Torii validation-fee proofs use the client native runtime", async () => {
  const native = {
    connectNoritoBridgeAbiVersion: () => 30,
    validationFeeCurrentPolicyProofRequestV1(checkpointNorito) {
      assert.deepEqual(checkpointNorito, binding.checkpoint.checkpointNorito);
      return Buffer.from([1, 2, 3]);
    },
    validationFeeVerifyCurrentPolicyProofV1(proofNorito) {
      assert.deepEqual(proofNorito, Buffer.from([9]));
      return nativePage(completeVerifiedProjection());
    },
  };
  const client = new ToriiClient("https://torii.invalid", {
    localSigningContext: new LocalSigningContext(binding.networkId, 753),
    fetchImpl: async () => assert.fail("overridden request path should be used"),
    [TORII_TEST_NATIVE_BINDING]: native,
  });
  client._request = async (method, path, init) => {
    assert.equal(method, "POST");
    assert.equal(path, "/v1/validation-fee/policy/current/proof");
    assert.deepEqual(init.body, Buffer.from([1, 2, 3]));
    return new Response(Buffer.from([9]), {
      status: 200,
      headers: { "Content-Type": "application/x-norito" },
    });
  };

  const page = await client.getValidationFeeCurrentPolicyProofPage(
    binding,
    null,
    {
      canonicalAuth: {
        accountId: proposalOperator,
        privateKey: Buffer.alloc(32, 0x31),
      },
    },
  );
  assert.equal(page.projection.evaluated_block_height, 127n);
  assert.deepEqual(page.promotedCheckpoint.checkpointNorito, Buffer.from([127, 189]));
});

const PROOF_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;

// Hand-built response so the raw Content-Length reaches the reader untouched:
// WHATWG `Headers` trims " 1" and "1 " to "1", which would hide the
// canonical-form check.
function proofResponse({
  bytes = Buffer.from([9]),
  chunks: providedChunks,
  contentType = "application/x-norito",
  contentLength,
  readable = true,
} = {}) {
  const chunks = (providedChunks ?? [bytes]).map((chunk) => new Uint8Array(chunk));
  const streamState = { cancelled: false, released: false };
  let locked = false;
  let nextChunk = 0;
  const body = readable
    ? {
        get locked() { return locked; },
        getReader() {
          if (locked) throw new TypeError("test response body is already locked");
          locked = true;
          return {
            async read() {
              if (streamState.cancelled || nextChunk >= chunks.length) {
                return { done: true, value: undefined };
              }
              const value = chunks[nextChunk];
              nextChunk += 1;
              return { done: false, value };
            },
            async cancel() { streamState.cancelled = true; },
            releaseLock() { locked = false; streamState.released = true; },
          };
        },
        async cancel() { streamState.cancelled = true; },
      }
    : {
        locked: false,
        async cancel() { streamState.cancelled = true; },
      };
  return {
    status: 200,
    statusText: "OK",
    headers: {
      get(name) {
        const normalized = String(name).toLowerCase();
        if (normalized === "content-length") return contentLength ?? null;
        if (normalized === "content-type") return contentType;
        return null;
      },
    },
    body,
    streamState,
  };
}

function proofPageClient(response, verifyProof = () => {
  assert.fail("rejected proof responses must not reach the native verifier");
}) {
  const native = {
    connectNoritoBridgeAbiVersion: () => 30,
    validationFeeCurrentPolicyProofRequestV1: () => Buffer.from([1, 2, 3]),
    validationFeeVerifyCurrentPolicyProofV1(proofNorito) {
      verifyProof(proofNorito);
      return nativePage(completeVerifiedProjection());
    },
  };
  const client = new ToriiClient("https://torii.invalid", {
    localSigningContext: new LocalSigningContext(binding.networkId, 753),
    fetchImpl: async () => assert.fail("overridden request path should be used"),
    [TORII_TEST_NATIVE_BINDING]: native,
  });
  client._request = async () => response;
  return client;
}

function fetchProofPage(client) {
  return client.getValidationFeeCurrentPolicyProofPage(binding, null, {
    canonicalAuth: {
      accountId: proposalOperator,
      privateKey: Buffer.alloc(32, 0x31),
    },
  });
}

test("Torii validation-fee proof pages accept an exact-bound streamed response", async () => {
  const exact = Buffer.alloc(PROOF_RESPONSE_MAX_BYTES, 0x5a);
  const streamed = proofResponse({
    chunks: [
      exact.subarray(0, 7),
      exact.subarray(7, PROOF_RESPONSE_MAX_BYTES - 1),
      exact.subarray(PROOF_RESPONSE_MAX_BYTES - 1),
    ],
    contentLength: String(PROOF_RESPONSE_MAX_BYTES),
  });
  let verifiedLength = null;
  const client = proofPageClient(streamed, (proofNorito) => {
    verifiedLength = proofNorito.length;
  });

  const page = await fetchProofPage(client);
  assert.equal(verifiedLength, PROOF_RESPONSE_MAX_BYTES);
  assert.equal(page.proofNorito.length, PROOF_RESPONSE_MAX_BYTES);
  assert.deepEqual(page.promotedCheckpoint.checkpointNorito, Buffer.from([127, 189]));
  assert.equal(page.projection.evaluated_block_height, 127n);
  assert.equal(streamed.streamState.cancelled, false);
  assert.equal(streamed.streamState.released, true);
});

test("Torii validation-fee proof pages reject malformed and noncanonical Content-Length values", async () => {
  for (const contentLength of ["", "-1", "+1", "01", "1.0", "1, 1", "1 ", " 1"]) {
    const malformed = proofResponse({ contentLength });
    await assert.rejects(
      () => fetchProofPage(proofPageClient(malformed)),
      /validation-fee proof response Content-Length must be a canonical unsigned decimal integer/u,
      JSON.stringify(contentLength),
    );
    assert.equal(malformed.streamState.cancelled, true, JSON.stringify(contentLength));
  }
});

test("Torii validation-fee proof pages reject declared, missing-length, and understated overflows", async () => {
  const oversized = Buffer.alloc(PROOF_RESPONSE_MAX_BYTES + 1, 0x5a);
  const cases = [
    {
      name: "declared overflow",
      response: proofResponse({ contentLength: String(PROOF_RESPONSE_MAX_BYTES + 1) }),
    },
    {
      name: "actual overflow without Content-Length",
      response: proofResponse({ bytes: oversized }),
    },
    {
      name: "actual overflow with understated Content-Length",
      response: proofResponse({ bytes: oversized, contentLength: "1" }),
    },
  ];
  for (const entry of cases) {
    await assert.rejects(
      () => fetchProofPage(proofPageClient(entry.response)),
      /validation-fee proof response exceeds its 4194304-byte size bound/u,
      entry.name,
    );
    assert.equal(entry.response.streamState.cancelled, true, entry.name);
  }
});

test("Torii validation-fee proof pages reject a body that is not a byte stream", async () => {
  const unreadable = proofResponse({ readable: false });
  await assert.rejects(
    () => fetchProofPage(proofPageClient(unreadable)),
    /validation-fee proof response body is not readable as a byte stream/u,
  );
  assert.equal(unreadable.streamState.cancelled, true);
});

test("Torii validation-fee proof pages reject non-Norito content before reading", async () => {
  const json = proofResponse({ contentType: "application/json" });
  await assert.rejects(
    () => fetchProofPage(proofPageClient(json)),
    /validation-fee proof response must use application\/x-norito/u,
  );
  assert.equal(json.streamState.cancelled, true);
  assert.equal(json.streamState.released, false);
});

test("proof catch-up promotes only consecutive locally verified pages", async () => {
  const client = new ToriiClient("https://torii.invalid", {
    fetchImpl: async () => {
      throw new Error("network must not be used by this fixture");
    },
  });
  const visited = [];
  client.getValidationFeeCurrentPolicyProofPage = async (
    normalizedBinding,
    checkpoint,
  ) => {
    const height = BigInt(checkpoint.checkpointNorito[0]);
    visited.push(height);
    assert.equal(normalizedBinding.networkId, binding.networkId);
    const nextHeight = height === 100n ? 127n : 190n;
    return Object.freeze({
      proofNorito: Buffer.from([Number(nextHeight % 256n)]),
      projection: Object.freeze({
        trusted_checkpoint_height: height,
        evaluated_block_height: nextHeight,
        more_available: nextHeight !== 190n,
      }),
      promotedCheckpoint: Object.freeze({
        checkpointNorito: Buffer.from([Number(nextHeight), 1]),
      }),
    });
  };

  const result = await client.catchUpValidationFeeCurrentPolicyProof(binding, {});
  assert.deepEqual(visited, [100n, 127n]);
  assert.equal(result.pagesVerified, 2);
  assert.deepEqual(result.promotedCheckpoint.checkpointNorito, Buffer.from([190, 1]));
  assert.equal(Object.isFrozen(result), true);
});

test("proof catch-up fails closed when a non-final page does not advance", async () => {
  const client = new ToriiClient("https://torii.invalid", {
    fetchImpl: async () => {
      throw new Error("network must not be used by this fixture");
    },
  });
  client.getValidationFeeCurrentPolicyProofPage = async (_binding, checkpoint) =>
    Object.freeze({
      proofNorito: Buffer.from([1]),
      projection: Object.freeze({
        trusted_checkpoint_height: 100n,
        evaluated_block_height: 100n,
        more_available: true,
      }),
      promotedCheckpoint: checkpoint,
    });

  await assert.rejects(
    client.catchUpValidationFeeCurrentPolicyProof(binding, {}),
    /did not advance/u,
  );
});


test("ledger binding accepts only the first-release Iroha schema", () => {
  assert.equal(
    normalizeValidationFeeLedgerBindingV1(binding).schema,
    "iroha.validation-fee-ledger-binding.v1",
  );
  for (const schema of [
    "cbsi.mobile-validation-fee-ledger-binding.v1",
    "boi.validation-fee-ledger-binding.v1",
    "",
  ]) {
    assert.throws(
      () => normalizeValidationFeeLedgerBindingV1({ ...binding, schema }),
      /binding.schema/u,
    );
  }
});


test("native promotion is required and cannot be synthesized from projection scalars", () => {
  const projection = completeVerifiedProjection();
  for (const result of [
    JSON.stringify(projection),
    { projectionJson: JSON.stringify(projection) },
    { ...nativePage(projection), height: 127 },
    nativePage(projection, Buffer.alloc(0)),
  ]) {
    withNativeBinding({
      connectNoritoBridgeAbiVersion: () => 30,
      validationFeeCurrentPolicyProofRequestV1() {},
      validationFeeVerifyCurrentPolicyProofV1() { return result; },
    }, ({ verifyValidationFeeCurrentPolicyProofV1: verify }) => {
      assert.throws(() => verify(Buffer.of(9), binding, binding.checkpoint, 753),
        /plain object|must contain exactly|must contain 1/u);
    });
  }
});

test("native fee projection metadata must remain coherent with its verified page", () => {
  for (const changes of [
    { trusted_checkpoint_context_id: "02".repeat(32) },
    { network_id: NetworkId.fromBytes(Buffer.alloc(32, 7)).toString() },
    { policy_chain_genesis_hash: "79".repeat(32) },
    { evaluated_block_height: 99 },
    { evaluated_block_height: 100 },
    { observed_ledger_tip_height: 126 },
    { more_available: false },
  ]) {
    // Isolate page/checkpoint consistency from optional policy activation. A page
    // before either enactment has explicit null policy projections in Rust.
    const projection = {
      ...completeVerifiedProjection(),
      current_policy: null,
      conversion_policy: null,
      ...changes,
    };
    assert.throws(() => verifyProjectionFixture(projection),
      /canonical Iroha hash marker|immutable binding|did not advance/u);
  }
});
