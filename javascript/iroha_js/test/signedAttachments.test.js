/** Cross-language descriptor fixtures; no transaction-admission or proof-verification claims. */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { blake3 } from "@noble/hashes/blake3";
import {
  SIGNED_ATTACHMENT_LIMITS_V1, actionStatementDigestV1,
  decodeSignedAttachmentsV1, encodeSignedAttachmentsV1,
  signedAttachmentsFromJsonV1, signedAttachmentsToJsonV1,
  signedAttachmentsIntentProjectionV1,
} from "../src/signedAttachments.js";
import {
  BufferReader, decodeStructFields, encodeNoritoField, frameNoritoPayload,
  readNoritoField, schemaHashForTypeName, u64ToLittleEndianBuffer,
  validateNoritoFrame, withNoritoCompactLengths,
} from "../src/noritoValueCodecs.js";

const fixtures = JSON.parse(fs.readFileSync(new URL("../../../fixtures/zk/signed_attachments_v1/vectors.json", import.meta.url)));
const SCHEMA = "iroha_data_model::transaction::signed_attachments::SignedAttachmentsV1";
const PAYLOAD_FIELDS = ["domain", "authority", "creationTime", "executable", "ttl", "nonce", "fee", "metadata", "attachments"];
const frame = (payload) => frameNoritoPayload(payload, schemaHashForTypeName(SCHEMA), 2);
const fields = (payload, names) => withNoritoCompactLengths(() => decodeStructFields(payload, "fixture", names));
const structure = (values) => withNoritoCompactLengths(() => Buffer.concat(values.map(encodeNoritoField)));
function attachmentPayload(payload) {
  return withNoritoCompactLengths(() => {
    const option = fields(payload, PAYLOAD_FIELDS).attachments;
    const reader = new BufferReader(option, "attachment option");
    assert.equal(reader.readU8("tag"), 1);
    const value = readNoritoField(reader, "value"); reader.assertEof(); return value;
  });
}
function fresh() { return signedAttachmentsFromJsonV1(fixtures.accepted[0].attachments_frame_base64); }

for (const fixture of fixtures.accepted) {
  test(`canonical shared descriptor and statement: ${fixture.name}`, () => {
    const original = Buffer.from(fixture.attachments_frame_base64, "base64");
    const decoded = decodeSignedAttachmentsV1(original);
    assert.deepEqual(Buffer.from(encodeSignedAttachmentsV1(decoded)), original);
    assert.equal(signedAttachmentsToJsonV1(decoded), fixture.attachments_frame_base64);
    assert.deepEqual(signedAttachmentsFromJsonV1(fixture.attachments_frame_base64), decoded);
    assert.deepEqual(decoded.occurrences.map((o) => o.length), fixture.occurrence_lengths);
    assert.deepEqual(decoded.occurrences.map((o) => Buffer.from(o.contentHash).toString("hex")), fixture.content_hashes_hex);
    assert.deepEqual(decoded.actions.map((a) => Buffer.from(a.publicInputsDigest).toString("hex")), fixture.public_inputs_digests_hex);
    assert.deepEqual(decoded.actions.map((action) => Buffer.from(actionStatementDigestV1(action, Buffer.from(fixture.ordered_intent_digest_hex, "hex"))).toString("hex")), fixture.statement_digests_hex);
    const projection = validateNoritoFrame(Buffer.from(fixture.ordered_intent_projection_hex, "hex")).payload;
    assert.deepEqual(Buffer.from(signedAttachmentsIntentProjectionV1(decoded)), frame(attachmentPayload(projection)));
    assert.throws(() => decodeSignedAttachmentsV1(signedAttachmentsIntentProjectionV1(decoded)), /zero|length/u);
  });
}

// The last three shared rejection vectors require transaction context: stale statement,
// wrong executable and duplicate execution carrier. This descriptor codec does not admit them.
const structuralRejections = new Set(["reordered_actions", "reordered_occurrences", "substituted_proof", "omitted_occurrence", "duplicated_reference", "unused_occurrence", "declared_type_mismatch", "declared_length_mismatch", "occurrence_hash_mismatch"]);
assert.equal(fixtures.rejected.filter((v) => structuralRejections.has(v.name)).length, 9);
for (const fixture of fixtures.rejected.filter((v) => structuralRejections.has(v.name))) {
  test(`shared structural rejection: ${fixture.name}`, () => {
    const signed = validateNoritoFrame(Buffer.from(fixture.signed_transaction_hex, "hex")).payload;
    const payload = fields(signed, ["signature", "payload", "multisig"]).payload;
    assert.throws(() => decodeSignedAttachmentsV1(frame(attachmentPayload(payload))), /signed attachments/u);
  });
}

test("descriptor limits match the canonical Rust fixture", () => {
  assert.deepEqual(Object.values(SIGNED_ATTACHMENT_LIMITS_V1), [16, 16, fixtures.bounds.occurrence_max_bytes, fixtures.bounds.frame_max_bytes, 32, 128]);
});

test("count preflight rejects both tables before inspecting any action", () => {
  for (const counts of [[17n, 0n], [0n, 0n], [1n, 17n], [0xffff_ffff_ffff_ffffn, 0n]]) {
    const payload = structure(counts.map(u64ToLittleEndianBuffer));
    assert.throws(() => decodeSignedAttachmentsV1(frame(payload)), /count bound/u);
  }
});

test("framing rejects foreign schema, CRC, flags, compression, padding and trailing data", () => {
  const valid = Buffer.from(fixtures.accepted[0].attachments_frame_base64, "base64");
  for (const offset of [0, 4, 6, 22, 23, 31, 39, valid.length - 1]) {
    const changed = Buffer.from(valid); changed[offset] ^= 1;
    assert.throws(() => decodeSignedAttachmentsV1(changed));
  }
  assert.throws(() => decodeSignedAttachmentsV1(Buffer.concat([valid, Buffer.of(0)])));
  assert.throws(() => decodeSignedAttachmentsV1(valid.subarray(0, valid.length - 1)));
  const payload = validateNoritoFrame(valid).payload;
  assert.throws(() => decodeSignedAttachmentsV1(frameNoritoPayload(payload, schemaHashForTypeName(SCHEMA), 2, 1)), /padding/u);
  // Overlong compact field prefix with a correct frame checksum still fails.
  let end = 0; while ((payload[end] & 128) !== 0) end += 1;
  const overlong = Buffer.concat([payload.subarray(0, end), Buffer.of(payload[end] | 128, 0), payload.subarray(end + 1)]);
  assert.throws(() => decodeSignedAttachmentsV1(frame(overlong)), /minimally/u);
});

test("JSON is bounded exact padded standard base64", () => {
  const valid = fixtures.accepted[0].attachments_frame_base64;
  for (const invalid of [null, "", ` ${valid}`, `${valid}\n`, valid.replaceAll("+", "-"), valid.slice(0, -1)]) {
    if (invalid !== valid) assert.throws(() => signedAttachmentsFromJsonV1(invalid));
  }
  assert.throws(() => signedAttachmentsFromJsonV1("A".repeat(4 * Math.ceil(SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes / 3) + 4)), /bound/u);
});

test("decoded byte ownership is independent from input and other decodes", () => {
  const input = Buffer.from(fixtures.accepted[0].attachments_frame_base64, "base64");
  const a = decodeSignedAttachmentsV1(input), b = decodeSignedAttachmentsV1(input);
  const original = Buffer.from(encodeSignedAttachmentsV1(b));
  input.fill(0); a.occurrences[0].bytes.fill(0); a.actions[0].statementDigest.fill(0);
  assert.deepEqual(Buffer.from(encodeSignedAttachmentsV1(b)), original);
  assert.throws(() => encodeSignedAttachmentsV1(a));
});

test("closed bindings and exact model fields reject malformed descriptors", () => {
  const mutations = [
    (v) => { v.actions[0].invocation = { type: "Direct", instructionIndex: 0 }; },
    (v) => { v.actions[0].role = "Effect"; },
    (v) => { v.actions[0].operation = { type: "Other" }; },
    (v) => { v.actions[0].attachments[0].role = "VerifyingKey"; },
    (v) => { v.actions[0].publicInputsDigest = Buffer.alloc(32); },
    (v) => { v.actions[0].statementDigest = Buffer.alloc(32); },
    (v) => { v.actions[0].actionIndex = 1; },
    (v) => { v.actions[0].extra = 1; },
    (v) => { v.occurrences[0].length += 1; },
    (v) => { v.occurrences[0].kind = "Other"; },
    (v) => { v.occurrences[0].bytes[0] ^= 1; },
    (v) => { v.actions = Array(17).fill(v.actions[0]); },
    (v) => { v.occurrences = Array(17).fill(v.occurrences[0]); },
  ];
  for (const mutate of mutations) { const value = fresh(); mutate(value); assert.throws(() => encodeSignedAttachmentsV1(value)); }
});

test("native metadata limits are checked without relying on occurrence payload bounds", () => {
  const base = signedAttachmentsFromJsonV1(fixtures.accepted[6].attachments_frame_base64);
  for (const wireId of ["", "a".repeat(129), "has space", "é"]) {
    const changed = structuredClone(base); changed.actions[1].operation.wireId = wireId;
    assert.throws(() => encodeSignedAttachmentsV1(changed), /wire ID/u);
  }
  const changed = structuredClone(base);
  changed.actions[1].authority = { type: "Account", accountId: "invalid" };
  assert.throws(() => encodeSignedAttachmentsV1(changed));
  changed.actions[1].authority = { type: "TransactionAuthority" };
  changed.actions[1].invocation.instructionIndex = 0x1_0000_0000;
  assert.throws(() => encodeSignedAttachmentsV1(changed), /u32/u);
});

test("exact frame accounting refuses aggregate overflow before concatenating occurrences", () => {
  const value = fresh();
  value.occurrences[0].bytes = Buffer.alloc(SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes + 1);
  assert.throws(() => encodeSignedAttachmentsV1(value), /bound/u);
  const data = Buffer.alloc(SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes, 0x5a);
  const hash = Buffer.from(blake3(data));
  value.occurrences[0] = { index: 0, kind: "Proof", length: data.length, contentHash: hash, bytes: data };
  value.actions[0].attachments[0] = { index: 0, kind: "Proof", role: "ActionProof", length: data.length, contentHash: hash };
  // Structural descriptors do not interpret carrier bytes as a valid proof wrapper.
  const encoded = encodeSignedAttachmentsV1(value);
  assert.ok(encoded.length <= SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes);
  assert.equal(decodeSignedAttachmentsV1(encoded).occurrences[0].length, data.length);
  const second = structuredClone(value);
  second.actions[0].actionIndex = 1; second.actions[0].attachments[0].index = 1;
  second.occurrences[0].index = 1; second.occurrences[0].bytes[0] ^= 1;
  second.occurrences[0].contentHash = Buffer.from(blake3(second.occurrences[0].bytes));
  second.actions[0].attachments[0].contentHash = second.occurrences[0].contentHash;
  value.actions.push(second.actions[0]); value.occurrences.push(second.occurrences[0]);
  assert.throws(() => encodeSignedAttachmentsV1(value), /aggregate frame/u);
});

test("statement commits supplied intent, authority-independent metadata and invocation", () => {
  const value = fresh(), action = value.actions[0];
  const intent = Buffer.from(fixtures.accepted[0].ordered_intent_digest_hex, "hex");
  const original = actionStatementDigestV1(action, intent);
  const changed = Buffer.from(intent); changed[0] ^= 1;
  assert.notDeepEqual(actionStatementDigestV1(action, changed), original);
  action.actionIndex += 1;
  assert.notDeepEqual(actionStatementDigestV1(action, intent), original);
  assert.throws(() => actionStatementDigestV1(action, Buffer.alloc(31)), /32 bytes/u);
});


test("invocation path count and unsigned indices have independent bounds", () => {
  const action = fresh().actions[0];
  const intent = Buffer.alloc(32, 1);
  action.invocation = { type: "Contract", rootIndex: 0, callPath: Array(32).fill(0) };
  const first = actionStatementDigestV1(action, intent);
  action.invocation.callPath[31] = 1;
  assert.notDeepEqual(actionStatementDigestV1(action, intent), first);
  action.invocation.callPath.push(0);
  assert.throws(() => actionStatementDigestV1(action, intent), /count bound/u);
  action.invocation.callPath = [-1];
  assert.throws(() => actionStatementDigestV1(action, intent), /u32/u);
});

test("package transaction codec exports the descriptor API without changing transaction admission", async () => {
  const api = await import("../src/public/transactionCodec.js");
  for (const name of ["encodeSignedAttachmentsV1", "decodeSignedAttachmentsV1", "actionStatementDigestV1", "signedAttachmentsFromJsonV1", "signedAttachmentsToJsonV1", "signedAttachmentsIntentProjectionV1"]) assert.equal(typeof api[name], "function");
  assert.equal(api.SIGNED_ATTACHMENT_LIMITS_V1, SIGNED_ATTACHMENT_LIMITS_V1);
});


test("occurrence ordinal alone is rejected with every reference and byte unchanged", () => {
  const value = fresh(); value.occurrences[0].index = 1;
  assert.throws(() => encodeSignedAttachmentsV1(value), /occurrence index is out of order/u);
});
