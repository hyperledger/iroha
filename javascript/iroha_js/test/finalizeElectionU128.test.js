import { test } from "node:test";
import assert from "node:assert/strict";

import { buildFinalizeElectionInstruction } from "../src/instructionBuilders.js";
import { _createNoritoInstructionApi } from "../src/norito.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";

function election(tally) {
  return buildFinalizeElectionInstruction({
    electionId: "election-u128",
    tally,
    tallyProof: {
      backend: "pipa-r/pasta",
      proof: Buffer.from("proof"),
      verifyingKeyRef: { backend: "pipa-r/pasta", name: "vk_tally" },
    },
  });
}

test("FinalizeElection emits exact u128 tally tokens through the V1 Norito owner", () => {
  const maximum = (1n << 128n) - 1n;
  const first = 1n << 64n;
  const second = maximum - first;
  const instruction = election([first, second.toString(10)]);
  assert.deepEqual(instruction.zk.FinalizeElection.tally, [first, second]);
  let captured;
  const encodeWithNative = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction(json) {
      captured = json;
      return Buffer.from([0]);
    },
  })).noritoEncodeInstruction;
  encodeWithNative(instruction, 753);
  assert.ok(captured.includes(`"tally":[${first},${second}]`));
  assert.doesNotMatch(captured, /"tally":\["/u);
});

test("FinalizeElection rejects lossy or out-of-range u128 tally weights", () => {
  for (const bad of [Number.MAX_SAFE_INTEGER + 1, -1n, 1n << 128n, "01", "-1"]) {
    assert.throws(() => election([0, bad]), /tally\[1\]/u);
  }
  assert.throws(() => election([(1n << 128n) - 1n, 1]), /tally total/u);
});

test("FinalizeElection rejects bigint outside the exact tally slot", () => {
  const instruction = election([1n << 64n, 0]);
  instruction.zk.FinalizeElection.unexpected_bigint = 1n;
  const encodeWithNative = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction() {
      throw new Error("native must not see invalid bigint");
    },
  })).noritoEncodeInstruction;
  assert.throws(() => encodeWithNative(instruction, 753), /bigint values require exact JSON text/u);
});

test("FinalizeElection refuses exact-number marker collision", () => {
  const instruction = election([1n << 64n, 0]);
  instruction.zk.FinalizeElection.unexpected_marker = "__iroha-v1-u128-tally-0__";
  const encodeWithNative = _createNoritoInstructionApi(createNativeRuntime({
    noritoEncodeInstruction() {
      throw new Error("native must not see colliding marker");
    },
  })).noritoEncodeInstruction;
  assert.throws(() => encodeWithNative(instruction, 753), /marker collision/u);
});
