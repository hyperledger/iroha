import assert from "node:assert/strict";
import test from "node:test";
import { NetworkId } from "../src/networkId.js";
import {
  assertOwnerReceiptNetwork,
  buildOwnerIdentifierRequest,
  flattenOriginalOpening,
  normalizeTypedOriginalOpening,
  ownerExecuteHashData,
  requireOwnerInput,
  requireOwnerInputNonce,
} from "../src/identifierOwnerPrf.js";

// Public SOFTWARE DATA envelope tests. No Native frame, authority, admission,
// resolver/opener signature verification or private device material is invented.
const NETWORK = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const OTHER_NETWORK = NetworkId.fromBytes(Buffer.alloc(32, 0xa7));
const HASH = NETWORK.literal;
function opening() {
  return {
    payload: {
      program_id: { name: "identifier_lookup_retail" },
      input_ciphertext_hash: HASH, output_ciphertext_hash: HASH,
      parameter_digest: HASH, evaluation_key_digest: HASH,
      opened_output_hash: HASH, opened_at_ms: 10, expires_at_ms: 120010,
    },
    signature: "AB".repeat(64),
  };
}
function fields() {
  return { policyId: "email#retail", normalizedInput: "alice@example.test", inputNonce: "a1".repeat(32) };
}

test("owner input and nonce preserve exact private originals and refuse aliases", () => {
  assert.equal(requireOwnerInput("é".repeat(256), "input"), "é".repeat(256));
  assert.equal(requireOwnerInput(" a ", "input"), " a ");
  for (const value of ["", "a".repeat(513), "\ud800", null, 7]) {
    assert.throws(() => requireOwnerInput(value, "input"));
  }
  assert.equal(requireOwnerInputNonce("a1".repeat(32), "nonce"), "a1".repeat(32));
  for (const value of ["00".repeat(32), "A1".repeat(32), `0x${"a1".repeat(32)}`, "a1".repeat(31), "a1 ", null]) {
    assert.throws(() => requireOwnerInputNonce(value, "nonce"));
  }
});

test("response audience is mandatory raw32 and independently selected", () => {
  assert.equal(assertOwnerReceiptNetwork("a5".repeat(32), NETWORK, "network"), "a5".repeat(32));
  assert.throws(() => assertOwnerReceiptNetwork("a5".repeat(32), OTHER_NETWORK, "network"), /independently selected/);
  for (const value of [undefined, null, NETWORK.literal, "A5".repeat(32), "a4".repeat(32), "a5".repeat(31)]) {
    assert.throws(() => assertOwnerReceiptNetwork(value, NETWORK, "network"));
  }
  assert.throws(() => assertOwnerReceiptNetwork("a5".repeat(32), undefined, "network"));
});

test("original opening keeps strict typed Model grammar and bounded lease", () => {
  const source = opening();
  const normalized = normalizeTypedOriginalOpening(source, "opening");
  source.payload.program_id.name = "other";
  assert.equal(normalized.payload.program_id.name, "identifier_lookup_retail");
  assert.equal(Object.isFrozen(normalized.payload.program_id), true);
  assert.deepEqual(flattenOriginalOpening(normalized, "opening"), {
    payload: { ...normalized.payload, program_id: "identifier_lookup_retail",
      input_ciphertext_hash: "a5".repeat(32), output_ciphertext_hash: "a5".repeat(32),
      parameter_digest: "a5".repeat(32), evaluation_key_digest: "a5".repeat(32), opened_output_hash: "a5".repeat(32) },
    signature: "ab".repeat(64),
  });
  for (const mutate of [
    (v) => { v.payload.program_id = "identifier_lookup_retail"; },
    (v) => { v.payload.program_id.name = "email#retail"; },
    (v) => { v.payload.program_id.ignored = true; },
    (v) => { v.payload.input_ciphertext_hash = "a5".repeat(32); },
    (v) => { v.signature = v.signature.toLowerCase(); },
    (v) => { v.signature = "00".repeat(64); },
    (v) => { v.payload.opened_at_ms = "10"; },
    (v) => { v.payload.expires_at_ms = null; },
    (v) => { v.payload.expires_at_ms = 120011; },
    (v) => { v.payload.expires_at_ms = 10; },
  ]) {
    const changed = opening(); mutate(changed);
    assert.throws(() => normalizeTypedOriginalOpening(changed, "opening"));
  }
});

test("current phases have exact fields and never accept encrypted predecessors", () => {
  assert.deepEqual(buildOwnerIdentifierRequest(fields(), "prepare", "request", NETWORK), {
    phase: "prepare", policy_id: "email#retail", normalized_input: "alice@example.test", input_nonce: "a1".repeat(32),
  });
  const claim = buildOwnerIdentifierRequest({ ...fields(), outputOpening: opening() }, "claim", "request", NETWORK);
  assert.equal(claim.output_opening.payload.program_id.name, "identifier_lookup_retail");
  for (const value of [
    { ...fields(), encryptedInput: "ABCD" }, { ...fields(), outputOpening: opening() },
    { ...fields(), policyId: "email#retail#extra" }, { ...fields(), policyId: "email #retail" },
  ]) assert.throws(() => buildOwnerIdentifierRequest(value, "prepare", "request", NETWORK));
  assert.throws(() => buildOwnerIdentifierRequest(fields(), "claim", "request", NETWORK));
  assert.throws(() => buildOwnerIdentifierRequest(fields(), "legacy", "request", NETWORK));
  assert.throws(() => buildOwnerIdentifierRequest(fields(), "prepare", "request", undefined));
});

test("phone claims require an independent typed original and exact phone program", () => {
  const original = opening(); original.payload.program_id.name = "phone_retail";
  assert.throws(() => buildOwnerIdentifierRequest({ ...fields(), policyId: "phone#retail", outputOpening: original }, "claim", "request", NETWORK), /phoneRetailCanonicality/);
  assert.throws(() => buildOwnerIdentifierRequest({ ...fields(), outputOpening: original }, "claim", "request", NETWORK), /phone#retail/);
  assert.throws(() => buildOwnerIdentifierRequest({ ...fields(), outputOpening: opening(), phoneRetailCanonicality: {} }, "claim", "request", NETWORK), /only for phone#retail/);
});

test("DATA domain hashes retain the final opaque chunk and original associated bytes", () => {
  // Independently computed Python hashlib BLAKE2b-256 reference; this string
  // is deliberately arbitrary DATA, and is not a valid Native ProgramId frame.
  const data = Buffer.from("unadmitted program DATA only", "utf8");
  const output = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  assert.deepEqual(ownerExecuteHashData(data, output), {
    output_hash: "16fe1893e3f4b7f1f34ee843638f9a809196a918dce91e56b3356354c8595103",
    opaque_hash: "c5934a0864827109f637aed79c43b9b3c6899bf856eef6f30e323a1846d06035",
    receipt_hash: "f92e266302bde29d44da8378225a75356062dc39f2427ca40efc51c6e6cef393",
    associated_data_hash: "f0c1bcefcb236e23d243d332e3350dc1ba8a2159918fcaf36d3734620b91d80f",
  });
  const changed = ownerExecuteHashData(Buffer.from("different unadmitted DATA"), output);
  assert.equal(changed.output_hash, ownerExecuteHashData(data, output).output_hash);
  assert.notEqual(changed.opaque_hash, ownerExecuteHashData(data, output).opaque_hash);
  assert.notEqual(changed.receipt_hash, ownerExecuteHashData(data, output).receipt_hash);
});
