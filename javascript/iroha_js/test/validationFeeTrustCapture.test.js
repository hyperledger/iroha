// Mocked native verification isolates the original asynchronous trust-input owner.
import assert from "node:assert/strict";
import test from "node:test";
import { NetworkId } from "../src/networkId.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { TORII_TEST_NATIVE_BINDING } from "../src/toriiTestHooks.js";

const network = NetworkId.fromBytes(Buffer.alloc(32, 0x13));
const accountId = "alice@wonderland";
function trust() {
  return { schema: "iroha.validation-fee-ledger-binding.v1", networkId: network,
    policyChainGenesisHash: "35".repeat(32), checkpoint: { checkpointNorito: Buffer.from([100, 57]) } };
}
function projection() {
  return { schema: "iroha.validation_fee.verified_policy_projection.v1", version: 1,
    network_id: network.toString(), policy_chain_genesis_hash: "35".repeat(32),
    registry_hash: "79".repeat(32), head_policy_version: 1, head_policy_hash: "ab".repeat(32),
    current_policy: null, conversion_policy: null,
    trusted_checkpoint_height: 100, trusted_checkpoint_context_id: "57".repeat(32),
    evaluated_block_height: 127, evaluated_context_id: "bd".repeat(32), evaluated_block_hash: "df".repeat(32),
    observed_ledger_tip_height: 127, more_available: false };
}

test("proof page captures original trust bytes, credentials and request before lazy loading", async () => {
  const binding = trust();
  const checkpoint = { checkpointNorito: Buffer.from([100, 57]) };
  const controller = new AbortController();
  const options = { signal: controller.signal, canonicalAuth: { accountId, privateKey: Buffer.alloc(32, 0x31) } };
  const client = new ToriiClient("https://torii.invalid", {
    localSigningContext: new LocalSigningContext(network, 753),
    fetchImpl: async () => assert.fail("the captured request owner must be used"),
    [TORII_TEST_NATIVE_BINDING]: {
      connectNoritoBridgeAbiVersion: () => 29,
      validationFeeCurrentPolicyProofRequestV1(bytes) {
        assert.deepEqual(bytes, Buffer.from([100, 57])); return Buffer.of(8);
      },
      validationFeeVerifyCurrentPolicyProofV1(proof, id, genesis, bytes, prefix) {
        assert.deepEqual(proof, Buffer.of(9)); assert.deepEqual(id, Buffer.alloc(32, 0x13));
        assert.deepEqual(genesis, Buffer.alloc(32, 0x35)); assert.deepEqual(bytes, Buffer.from([100, 57]));
        assert.equal(prefix, 753);
        return { projectionJson: JSON.stringify(projection()), promotedCheckpointNorito: Buffer.from([127, 189]) };
      },
    },
  });
  let requests = 0;
  client._request = async (_method, _path, init) => {
    requests += 1;
    assert.strictEqual(init.signal, controller.signal);
    assert.equal(init.canonicalAuth.accountId, accountId);
    assert.deepEqual(init.canonicalAuth.privateKey, Buffer.alloc(32, 0x31));
    return new Response(Buffer.of(9), { status: 200, headers: { "content-type": "application/x-norito" } });
  };
  const pending = client.getValidationFeeCurrentPolicyProofPage(binding, checkpoint, options);
  binding.policyChainGenesisHash = "79".repeat(32);
  binding.networkId = NetworkId.fromBytes(Buffer.alloc(32, 0x33));
  binding.checkpoint.checkpointNorito.fill(0);
  checkpoint.checkpointNorito.fill(0);
  options.canonicalAuth.privateKey.fill(0);
  options.signal = new AbortController().signal;
  client._request = () => assert.fail("request owner changed after invocation");
  const result = await pending;
  assert.equal(requests, 1);
  assert.equal(result.projection.evaluated_block_height, 127n);
});

test("catch-up retains initial trust, options and page owner across every await", async () => {
  const binding = trust();
  const options = { checkpoint: { checkpointNorito: Buffer.from([100, 57]) }, maxPages: 2,
    canonicalAuth: { accountId, privateKey: Buffer.alloc(32, 0x31) } };
  const visited = [];
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const receiver = { async getValidationFeeCurrentPolicyProofPage(selected, checkpoint, auth) {
    const page = visited.length;
    visited.push(Buffer.from(checkpoint.checkpointNorito));
    assert.equal(selected.policyChainGenesisHash, "35".repeat(32));
    assert.strictEqual(selected.networkId, network);
    assert.deepEqual(auth.canonicalAuth.privateKey, Buffer.alloc(32, 0x31));
    if (page === 0) await gate;
    return { projection: { trusted_checkpoint_height: page === 0 ? 100n : 127n,
      evaluated_block_height: page === 0 ? 127n : 190n, more_available: page === 0 },
      promotedCheckpoint: { checkpointNorito: Buffer.from(page === 0 ? [127, 189] : [190, 1]) } };
  } };
  const pending = ToriiClient.prototype.catchUpValidationFeeCurrentPolicyProof.call(receiver, binding, options);
  binding.policyChainGenesisHash = "79".repeat(32);
  binding.checkpoint.checkpointNorito.fill(0);
  options.checkpoint.checkpointNorito.fill(0);
  options.canonicalAuth.privateKey.fill(0);
  options.maxPages = 1;
  receiver.getValidationFeeCurrentPolicyProofPage = () => assert.fail("page owner changed during catch-up");
  release();
  const result = await pending;
  assert.deepEqual(visited, [Buffer.from([100, 57]), Buffer.from([127, 189])]);
  assert.equal(result.pagesVerified, 2);
});

test("checkpoint ownership bounds branded storage before copying and rejects shared backing", async () => {
  const { normalizeValidationFeeCheckpointV1 } = await import("../src/validationFeeTrust.js");
  const oversized = new Uint8Array(68 * 1024 * 1024 + 1);
  Object.defineProperty(oversized, "byteLength", { value: 1 });
  Object.defineProperty(oversized, "buffer", { value: new ArrayBuffer(1) });
  const from = Buffer.from;
  let copies = 0;
  Buffer.from = (...args) => { copies += 1; return from(...args); };
  try {
    assert.throws(() => normalizeValidationFeeCheckpointV1({ checkpointNorito: oversized }),
      { name: "TypeError", message: "validation-fee checkpoint.checkpointNorito must contain 1..71303168 bytes" });
    assert.equal(copies, 0);
  } finally {
    Buffer.from = from;
  }
  assert.throws(() => normalizeValidationFeeCheckpointV1({ checkpointNorito: new DataView(new SharedArrayBuffer(2)) }),
    /ordinary ArrayBuffer/u);
});

test("fee trust capture keeps native proof and governance verification in the optional graph", async () => {
  const { build } = await import("esbuild");
  const { fileURLToPath } = await import("node:url");
  const { resolve } = await import("node:path");
  const { BUNDLE_TARGETS, analyzeSplitBundle } = await import("../scripts/bundle-size-check.mjs");
  const root = fileURLToPath(new URL("..", import.meta.url));
  const target = BUNDLE_TARGETS.find(({ label }) => label === "toriiClient.js");
  const result = await build({
    absWorkingDir: root, entryPoints: [target.entryPoint], bundle: true, splitting: true,
    write: false, outdir: resolve(root, ".fee-trust-boundary-audit"), entryNames: "entry", chunkNames: "[hash]",
    platform: target.platform, target: target.target, format: "esm", treeShaking: true,
    minify: true, metafile: true, charset: "utf8",
  });
  const metrics = analyzeSplitBundle(result, target);
  const contains = (outputs, name) => outputs.some((output) =>
    Object.hasOwn(result.metafile.outputs[output].inputs, `src/${name}`));
  assert.ok(contains(metrics.eagerOutputs, "validationFeeTrust.js"));
  assert.equal(contains(metrics.eagerOutputs, "validationFeeConsensus.js"), false);
  assert.ok(contains(metrics.lazyChunks.find(({ specifier }) => specifier === "./toriiOptional.js").outputs,
    "validationFeeConsensus.js"));
});
