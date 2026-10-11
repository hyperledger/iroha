import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { validateEmbeddedStates } from "../src/kotodamaCompiler/embeddedStateSchema.js";
import { readCompactField } from "../src/kotodamaCompiler/embeddedNorito.js";

const join = (...parts) => Buffer.concat(parts);
function u64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
}
function field(bytes) {
  const prefix = [];
  let length = bytes.length;
  do {
    const byte = length % 128;
    length = Math.floor(length / 128);
    prefix.push(byte | (length ? 128 : 0));
  } while (length);
  return join(Buffer.from(prefix), bytes);
}
function stateVector(encodedType) {
  const entry = join(field(field(Buffer.from("counter"))), field(encodedType));
  return join(u64(1), field(entry));
}
const expectedStates = [{ name: "counter", type_name: "int" }];

// Extract only the state field from an authentic compiler fixture. The complete
// frame, hash, and declaration boundary is tested by currentRustContractArtifact.
function fixtureStates(artifact) {
  assert.equal(artifact.subarray(49, 53).toString(), "CNTR");
  const frameLength = artifact.readUInt32LE(53);
  const frame = artifact.subarray(57, 57 + frameLength);
  const payload = frame.subarray(frame.length - Number(frame.readBigUInt64LE(23)));
  const state = { offset: 0 };
  const fields = Array.from({ length: 14 }, () => readCompactField(payload, state, "CNTR"));
  assert.equal(state.offset, payload.length);
  return fields[10];
}

test("current Rust state descriptors decode their required byte-vector envelope", () => {
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/current_rust_contract_artifact.json", import.meta.url), "utf8"));
  assert.ok(fixture.manifest.states.length > 0);
  validateEmbeddedStates(
    fixtureStates(Buffer.from(fixture.artifact_base64, "base64")),
    fixture.manifest.states,
    fixture.manifest.error_types ?? [],
    fixture.manifest.enum_types,
  );
});

test("state descriptor byte vectors require exact length and one complete tagged tree", () => {
  validateEmbeddedStates(stateVector(join(u64(1), Buffer.of(0))), expectedStates, [], []);
  for (const [label, bytes] of [
    ["missing vector envelope", Buffer.of(0)],
    ["truncated vector length", Buffer.alloc(7)],
    ["short vector length", join(u64(0), Buffer.of(0))],
    ["long vector length", join(u64(2), Buffer.of(0))],
    ["empty tagged tree", u64(0)],
    ["trailing tree byte", join(u64(2), Buffer.of(0, 0))],
  ]) {
    assert.throws(() => validateEmbeddedStates(stateVector(bytes), expectedStates, [], []), TypeError, label);
  }
});
