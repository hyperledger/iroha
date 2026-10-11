// Mocked native-owner contract tests: transport tokens grant no cryptographic authority.
import assert from "node:assert/strict";
import test from "node:test";
import { createValidationFeeConsensusApi, normalizeValidationFeeCheckpointV1 } from "../src/validationFeeConsensus.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { NetworkId } from "../src/networkId.js";
import { ToriiClient } from "../src/toriiClient.js";
import { exactKeys } from "../src/validationFeeTrust.js";

const anchor = Buffer.from([100, 57]);
const promoted = Buffer.from([127, 189]);
const binding = {
  schema: "iroha.validation-fee-ledger-binding.v1",
  networkId: NetworkId.fromBytes(Buffer.alloc(32, 0x13)),
  policyChainGenesisHash: "35".repeat(32),
  checkpoint: { checkpointNorito: anchor },
};
function projection(changes = {}) {
  return {
    schema: "iroha.validation_fee.verified_policy_projection.v1", version: 1,
    network_id: binding.networkId.toString(), policy_chain_genesis_hash: binding.policyChainGenesisHash,
    registry_hash: "79".repeat(32), head_policy_version: 1, head_policy_hash: "ab".repeat(32),
    current_policy: null, conversion_policy: null,
    trusted_checkpoint_height: 100, trusted_checkpoint_context_id: "57".repeat(32),
    evaluated_block_height: 127, evaluated_context_id: "bd".repeat(32), evaluated_block_hash: "df".repeat(32),
    observed_ledger_tip_height: 190, more_available: true, ...changes,
  };
}
function api(verify, encode = () => Buffer.of(8)) {
  return createValidationFeeConsensusApi(createNativeRuntime({
    connectNoritoBridgeAbiVersion: () => 29,
    validationFeeCurrentPolicyProofRequestV1: encode,
    validationFeeVerifyCurrentPolicyProofV1: verify,
  }));
}
function check(owner) {
  return owner.verifyValidationFeeCurrentPolicyProofV1(Buffer.of(9), binding, binding.checkpoint, 753);
}

test("exact policy fields do not depend on declaration or object insertion order", () => {
  const expected = Object.freeze(["revision", "binding", "authority", "lifecycle_seal_hash"]);
  for (const fields of [expected, [...expected].reverse(), [...expected].sort()]) {
    const value = Object.fromEntries(fields.map((field) => [field, null]));
    assert.doesNotThrow(() => exactKeys(value, expected, "conversion policy"));
    assert.throws(() => exactKeys({ ...value, unknown: null }, expected, "conversion policy"));
    for (const field of expected) {
      const incomplete = { ...value };
      delete incomplete[field];
      assert.throws(() => exactKeys(incomplete, expected, "conversion policy"));
    }
  }
  assert.deepEqual(expected, ["revision", "binding", "authority", "lifecycle_seal_hash"]);
  assert.throws(() => exactKeys({ revision: 1, binding: null }, ["revision", "revision"], "conversion policy"));
});

test("full checkpoint bytes retain private immutable copies and exact subview bounds", () => {
  const bytes = Uint8Array.from([0, 100, 57, 0]);
  const checkpoint = normalizeValidationFeeCheckpointV1({ checkpointNorito: new DataView(bytes.buffer, 1, 2) });
  bytes.fill(0);
  checkpoint.checkpointNorito.fill(0);
  assert.deepEqual(checkpoint.checkpointNorito, anchor);
  assert.equal(Object.isFrozen(checkpoint), true);
  const owner = api(() => assert.fail("request must not verify a response"), (checkpointNorito) => {
    assert.deepEqual(checkpointNorito, anchor);
    return Buffer.of(8);
  });
  assert.deepEqual(owner.encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint), Buffer.of(8));
});

test("retired scalar checkpoints and unbounded bytes fail before the native owner", () => {
  const owner = api(() => assert.fail("must not verify"), () => assert.fail("must not encode"));
  for (const checkpoint of [
    { height: 100, contextId: "57".repeat(32) },
    { checkpointNorito: anchor, height: 100 },
    { checkpointNorito: "0064" },
    { checkpointNorito: Buffer.alloc(0) },
    { checkpointNorito: new Uint8Array(68 * 1024 * 1024 + 1) },
  ]) assert.throws(() => owner.encodeValidationFeeCurrentPolicyProofRequestV1(checkpoint),
    /must contain exactly|ArrayBuffer|must contain 1/u);
});

test("fee verification forwards the complete pinned checkpoint and retains only actual native promotion", () => {
  const nativePromotion = Buffer.from(promoted);
  const owner = api((proof, network, genesis, checkpointNorito, prefix) => {
    assert.deepEqual(proof, Buffer.of(9));
    assert.deepEqual(network, Buffer.from(binding.networkId.toBytes()));
    assert.deepEqual(genesis, Buffer.from(binding.policyChainGenesisHash, "hex"));
    assert.deepEqual(checkpointNorito, anchor);
    assert.equal(prefix, 753);
    return { projectionJson: JSON.stringify(projection()), promotedCheckpointNorito: nativePromotion };
  });
  const bytes = Uint8Array.from([0, 9, 0]);
  const result = owner.verifyValidationFeeCurrentPolicyProofV1(new DataView(bytes.buffer, 1, 1), binding, binding.checkpoint, 753);
  nativePromotion.fill(0);
  result.promotedCheckpoint.checkpointNorito.fill(0);
  assert.deepEqual(result.promotedCheckpoint.checkpointNorito, promoted);
  assert.equal(result.projection.evaluated_block_height, 127n);
  assert.equal(Object.isFrozen(result.projection), true);
  assert.equal(Object.isFrozen(result), true);
});

test("a projection alone never synthesizes a checkpoint and a native refusal propagates", () => {
  for (const result of [
    JSON.stringify(projection()),
    { projectionJson: JSON.stringify(projection()) },
    { projectionJson: JSON.stringify(projection()), promotedCheckpointNorito: Buffer.alloc(0) },
  ]) assert.throws(() => check(api(() => result)), /plain object|must contain exactly|must contain 1/u);
  const refusal = new Error("native exact pinned decision rejected");
  assert.throws(() => check(api(() => { throw refusal; })), (error) => error === refusal);
});

test("verified projections require both explicit policy fields", () => {
  for (const field of ["current_policy", "conversion_policy"]) {
    const incomplete = projection();
    delete incomplete[field];
    assert.throws(() => check(api(() => ({
      projectionJson: JSON.stringify(incomplete), promotedCheckpointNorito: promoted,
    }))), /verified projection must contain exactly/u);
  }
});

test("verified page metadata cannot regress or change immutable deployment bindings", () => {
  for (const changes of [
    { network_id: NetworkId.fromBytes(Buffer.alloc(32, 7)).toString() },
    { policy_chain_genesis_hash: "79".repeat(32) },
    { trusted_checkpoint_context_id: "02".repeat(32) },
    { evaluated_block_height: 99 }, { evaluated_block_height: 100 },
    { observed_ledger_tip_height: 126 }, { more_available: false },
  ]) assert.throws(() => check(api(() => ({
    projectionJson: JSON.stringify(projection(changes)), promotedCheckpointNorito: promoted,
  }))), /immutable binding|canonical Iroha hash marker|did not advance/u);
});

test("catch-up passes native-promoted bytes to the next page without scalar reconstruction", async () => {
  const visited = [];
  const receiver = {
    async getValidationFeeCurrentPolicyProofPage(_binding, checkpoint) {
      visited.push(checkpoint.checkpointNorito);
      const first = visited.length === 1;
      return {
        proofNorito: Buffer.of(9),
        projection: { trusted_checkpoint_height: first ? 100n : 127n, evaluated_block_height: first ? 127n : 190n, more_available: first },
        promotedCheckpoint: normalizeValidationFeeCheckpointV1({ checkpointNorito: first ? promoted : Buffer.of(190, 1) }),
      };
    },
  };
  const result = await ToriiClient.prototype.catchUpValidationFeeCurrentPolicyProof.call(receiver, binding, {});
  assert.deepEqual(visited, [anchor, promoted]);
  assert.equal(result.pagesVerified, 2);
  assert.deepEqual(result.promotedCheckpoint.checkpointNorito, Buffer.of(190, 1));
});
