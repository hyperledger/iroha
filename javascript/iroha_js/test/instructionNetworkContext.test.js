import assert from "node:assert/strict";
import test from "node:test";
import { _createNoritoInstructionApi } from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { requireNetworkPrefix } from "../src/networkPrefix.js";
import {
  buildBrowserInstructionTransactionPayload,
  browserTransactionPayloadHashHex,
} from "../src/transactionCodec.js";
import { NetworkId } from "../src/networkId.js";
import { _createTransactionApi } from "../src/transaction.js";
import { createValidationFeeConsensusApi } from "../src/validationFeeConsensus.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";

const fixture = { Log: { level: "INFO", msg: "selected network" } };
const json = JSON.stringify(fixture);

test("every instruction codec path passes the caller-selected prefix unchanged", () => {
  const calls = [];
  const frame = Buffer.from(json);
  const archive = Buffer.of(7, 8);
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(value, prefix) { calls.push(["encode", prefix]); assert.equal(value, json); return frame; },
    noritoDecodeInstruction(_value, prefix) { calls.push(["decode", prefix]); return json; },
    noritoEncodeInstructionBoxArchive(value, prefix) { calls.push(["archive encode", prefix]); assert.equal(value, json); return archive; },
    noritoDecodeInstructionBoxArchive(_value, prefix) { calls.push(["archive decode", prefix]); return json; },
  }));
  for (const prefix of [369, 753, 0, 65535, 369]) {
    for (const input of [fixture, json, frame, frame.toString("base64"), `0x${frame.toString("hex")}`]) {
      assert.deepEqual(api.noritoEncodeInstruction(input, prefix), frame);
      assert.deepEqual(api.noritoEncodeInstructionBoxArchive(input, prefix), archive);
    }
    assert.deepEqual(api.noritoDecodeInstruction(frame, prefix), fixture);
    assert.equal(api.noritoDecodeInstruction(frame, prefix, { parseJson: false }), json);
    assert.deepEqual(api.noritoDecodeInstructionBoxArchive(archive, prefix), fixture);
    assert.ok(calls.length > 0);
    assert.ok(calls.every(([_name, actual]) => actual === prefix));
    calls.length = 0;
  }
});

test("missing and invalid instruction contexts fail before any owner call", () => {
  let calls = 0;
  const fail = () => { calls += 1; throw new Error("native must not be entered"); };
  const api = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction: fail, noritoDecodeInstruction: fail,
    noritoEncodeInstructionBoxArchive: fail, noritoDecodeInstructionBoxArchive: fail,
    inspectSubscriptionTriggerAction: fail,
  }));
  for (const prefix of [undefined, null, "369", 369n, -1, 65536, 0.5, NaN, Infinity, true]) {
    for (const call of [
      () => api.noritoEncodeInstruction(fixture, prefix),
      () => api.noritoEncodeInstruction(Buffer.of(1), prefix),
      () => api.noritoDecodeInstruction(Buffer.of(1), prefix),
      () => api.noritoEncodeInstructionBoxArchive(fixture, prefix),
      () => api.noritoDecodeInstructionBoxArchive(Buffer.of(1), prefix),
      () => api._encodeMultisigInstructions([], prefix),
      () => api.inspectSubscriptionTriggerAction("action", prefix),
    ]) assert.throws(call, /networkPrefix must be an integer/);
  }
  assert.equal(calls, 0);
});

test("network prefix validation accepts only numeric u16 values", () => {
  for (const prefix of [0, 369, 753, 65535]) assert.equal(requireNetworkPrefix(prefix), prefix);
  for (const prefix of [undefined, null, "369", 369n, -1, 65536, 1.1, NaN, Infinity]) {
    assert.throws(() => requireNetworkPrefix(prefix), TypeError);
  }
});

test("transaction boundaries never infer the instruction context from archive bytes", () => {
  for (const prefix of [undefined, null, "369", -1, 65536]) {
    assert.throws(() => browserTransactionPayloadHashHex(Buffer.of(1), prefix), /networkPrefix/);
    assert.throws(() => buildBrowserInstructionTransactionPayload({
      networkId: NetworkId.fromBytes(new Uint8Array(32).fill(1)),
      networkPrefix: prefix,
      authority: "not consulted before selected context validation",
      instructions: [fixture],
    }), /networkPrefix/);
  }
});

test("transaction inspection, batch hashing and contract arguments forward each selected context", () => {
  const calls = [];
  const api = _createTransactionApi(createNativeRuntime({
    decodeSignedTransactionJson(_wire, prefix) { calls.push(["decode", prefix]); return "{}"; },
    hashInstructionBatch(_instructions, prefix) { calls.push(["hash", prefix]); return Buffer.alloc(32, 1); },
    encodeContractArgumentRecordJson(_schema, _payload, prefix) { calls.push(["arguments", prefix]); return Buffer.of(1); },
  }));
  for (const prefix of [0, 369, 753, 65535, 369]) {
    assert.deepEqual(api.decodeSignedTransaction(Buffer.of(1), prefix), {});
    assert.deepEqual(api.hashInstructionBatch([fixture], prefix, { encoding: "buffer" }), Buffer.alloc(32, 1));
    assert.deepEqual(api.encodeContractArgumentRecord({}, {}, prefix), Buffer.of(1));
    assert.deepEqual(calls.splice(0), [["decode", prefix], ["hash", prefix], ["arguments", prefix]]);
  }
  for (const prefix of [undefined, null, "369", 369n, -1, 65536, 0.5, NaN, Infinity]) {
    assert.throws(() => api.decodeSignedTransaction(Buffer.of(1), prefix), /networkPrefix/);
    assert.throws(() => api.hashInstructionBatch([fixture], prefix), /networkPrefix/);
    assert.throws(() => api.encodeContractArgumentRecord({}, {}, prefix), /networkPrefix/);
  }
  assert.deepEqual(calls, []);
});

test("fee verification binds every projection to the selected prefix before entering the owner", () => {
  const calls = [];
  const stop = new Error("owner reached");
  const runtime = createNativeRuntime({
    connectNoritoBridgeAbiVersion: () => 30,
    validationFeeCurrentPolicyProofRequestV1() {},
    validationFeeVerifyCurrentPolicyProofV1(...args) { calls.push(["policy", args.at(-1)]); throw stop; },
  });
  const policy = createValidationFeeConsensusApi(runtime);
  const binding = {
    schema: "iroha.validation-fee-ledger-binding.v1",
    networkId: NetworkId.fromBytes(Buffer.alloc(32, 1)),
    policyChainGenesisHash: "35".repeat(32),
    checkpoint: { checkpointNorito: Buffer.of(1, 2, 3) },
  };
  for (const prefix of [undefined, null, "369", 369n, -1, 65536, 0.5, NaN, Infinity]) {
    assert.throws(() => policy.verifyValidationFeeCurrentPolicyProofV1(Buffer.of(1), binding, binding.checkpoint, prefix), /networkPrefix/);
  }
  assert.deepEqual(calls, []);
  for (const prefix of [0, 369, 753, 65535, 369]) {
    assert.throws(() => policy.verifyValidationFeeCurrentPolicyProofV1(Buffer.of(1), binding, binding.checkpoint, prefix), (error) => error === stop);
    assert.deepEqual(calls.splice(0), [["policy", prefix]]);
  }
});



test("client contexts are caller-selected and missing codec context fails before network I/O", async () => {
  const networkId = NetworkId.fromBytes(Buffer.alloc(32, 1));
  let requests = 0;
  const fetchImpl = async () => { requests += 1; throw new Error("unexpected network request"); };
  for (const prefix of [undefined, null, "369", 369n, -1, 65536, 0.5, NaN, Infinity]) {
    assert.throws(() => new LocalSigningContext(networkId, prefix), /chainDiscriminant/);
    if (prefix !== undefined) {
      assert.throws(() => new ToriiBrowserClient("https://example.invalid", { networkPrefix: prefix, fetchImpl }), /networkPrefix/);
    }
  }
  const browser = new ToriiBrowserClient("https://example.invalid", { fetchImpl });
  await assert.rejects(browser.submitMultisigPropose({ instructions: [] }), /requires one account selector/);
  const full = new ToriiClient("https://example.invalid", { fetchImpl });
  await assert.rejects(full.getValidationFeeCurrentPolicyProofPage({}, null, {}), /localSigningContext/);
  assert.equal(requests, 0);
});
