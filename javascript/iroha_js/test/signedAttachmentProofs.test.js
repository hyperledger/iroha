/** Cross-language carrier metadata bindings, independent of transaction/proof admission. */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { blake3 } from "@noble/hashes/blake3";
import { blake2b } from "@noble/hashes/blake2b";
import {
  decodeProofCarrierV1, encodeProofCarrierV1, proofCarrierPublicInputsDigestV1,
  inspectSignedAttachmentProofBindingsV1,
} from "../src/signedAttachmentProofs.js";
import { actionStatementDigestV1, signedAttachmentsFromJsonV1 } from "../src/signedAttachments.js";
import {
  BufferReader, decodeStructFields, encodeNoritoField, frameNoritoPayload,
  readNoritoField, schemaHashForTypeName, u64ToLittleEndianBuffer,
  validateNoritoFrame, withNoritoCompactLengths,
} from "../src/noritoValueCodecs.js";

const fixtures = JSON.parse(fs.readFileSync(new URL("../../../fixtures/zk/signed_attachments_v1/vectors.json", import.meta.url)));
const SCHEMA = "iroha_data_model::proof::ProofAttachment";
const selected = fixtures.accepted.filter((f) => !["contract_subject_nested_invocation", "explicit_account_direct_invocation"].includes(f.name));
assert.equal(selected.length, 5);
const from = (fixture) => signedAttachmentsFromJsonV1(fixture.attachments_frame_base64);
const fresh = (index = 0) => decodeProofCarrierV1(from(fixtures.accepted[index]).occurrences[0].bytes);
const frame = (payload) => frameNoritoPayload(payload, schemaHashForTypeName(SCHEMA), 2);
const struct = (parts) => withNoritoCompactLengths(() => Buffer.concat(parts.map(encodeNoritoField)));
function rawFields(encoded) {
  return withNoritoCompactLengths(() => {
    const reader = new BufferReader(validateNoritoFrame(encoded).payload, "raw carrier");
    const result = [];
    while (reader.offset < reader.buffer.length) result.push(readNoritoField(reader, "field"));
    return result;
  });
}
function rawString(value) { return withNoritoCompactLengths(() => encodeNoritoField(Buffer.from(value))); }
function updateOccurrence(descriptor, carrier, index = 0) {
  const bytes = encodeProofCarrierV1(carrier), hash = Buffer.from(blake3(bytes));
  const occurrence = descriptor.occurrences[index];
  occurrence.bytes = bytes; occurrence.length = bytes.length; occurrence.contentHash = hash;
  const reference = descriptor.actions.flatMap((a) => a.attachments).find((r) => r.index === index);
  reference.length = bytes.length; reference.contentHash = hash;
}
for (const fixture of selected) {
  test(`actual canonical carrier and public-input binding: ${fixture.name}`, () => {
    const descriptor = from(fixture);
    const carriers = inspectSignedAttachmentProofBindingsV1(descriptor, Buffer.from(fixture.ordered_intent_digest_hex, "hex"));
    assert.equal(carriers.length, 1);
    for (const { actionIndex, attachment } of carriers) {
      const action = descriptor.actions[actionIndex];
      assert.deepEqual(Buffer.from(encodeProofCarrierV1(attachment)), Buffer.from(descriptor.occurrences[action.attachments[0].index].bytes));
      assert.deepEqual(Buffer.from(proofCarrierPublicInputsDigestV1(attachment)), Buffer.from(fixture.public_inputs_digests_hex[actionIndex], "hex"));
    }
  });
}

test("shared lane witness preserves raw leaf, nested commitment and canonical siblings", () => {
  const carrier = fresh(2);
  assert.equal(carrier.verifyingKey.name, "vk_lane");
  assert.deepEqual([...carrier.proofBytes], [7, 8, 9]);
  assert.equal(carrier.lanePrivacy.commitmentId, 3);
  assert.deepEqual(Buffer.from(carrier.lanePrivacy.leaf), Buffer.alloc(32, 0x44));
  assert.equal(carrier.lanePrivacy.leafIndex, 1);
  assert.deepEqual(carrier.lanePrivacy.auditPath.map((p) => [p[0], p[31]]), [[0x55, 0x55], [0x66, 0x67]]);
});

test("proof-free binding clears generated proof and envelope while retaining key and lane metadata", () => {
  const carrier = fresh(1), original = proofCarrierPublicInputsDigestV1(carrier);
  carrier.proofBytes = Uint8Array.of(9, 4, 2, 1);
  carrier.envelopeHash = Buffer.from(blake2b(carrier.proofBytes, { dkLen: 32 })); carrier.envelopeHash[31] |= 1;
  assert.deepEqual(proofCarrierPublicInputsDigestV1(carrier), original);
  carrier.verifyingKeyCommitment[0] ^= 1;
  assert.notDeepEqual(proofCarrierPublicInputsDigestV1(carrier), original);
  const lane = fresh(2), laneDigest = proofCarrierPublicInputsDigestV1(lane);
  lane.lanePrivacy.leaf[0] ^= 1;
  assert.notDeepEqual(proofCarrierPublicInputsDigestV1(lane), laneDigest);
  lane.verifyingKey.name = "another_key";
  assert.notDeepEqual(proofCarrierPublicInputsDigestV1(lane), laneDigest);
});

test("actual inner proof and verifier backend mismatch reject before metadata binding", () => {
  const original = encodeProofCarrierV1(fresh());
  const f = rawFields(original);
  const box = withNoritoCompactLengths(() => decodeStructFields(f[1], "proof", ["backend", "bytes"]));
  f[1] = struct([rawString("another/backend"), box.bytes]);
  assert.throws(() => decodeProofCarrierV1(frame(struct(f))), /proof backend mismatch/u);
  const g = rawFields(original);
  g[2] = struct([rawString("another/backend"), rawString("vk")]);
  assert.throws(() => decodeProofCarrierV1(frame(struct(g))), /verifier backend mismatch/u);
});

test("portable identifiers, proof bytes, hashes and exact object fields reject malformed values", () => {
  for (const backend of ["", "Upper", "bad space", "a..b", "a//b", "a:::b", "a/:b", "a:/b", "a/.b", "a./b", "a:.b", "a.:b", "_a", "a_", "a".repeat(257), "é"]) {
    const value = fresh(); value.backend = backend; value.verifyingKey.backend = backend;
    assert.throws(() => encodeProofCarrierV1(value), /portable/u);
  }
  for (const mutate of [
    (v) => { v.proofBytes = new Uint8Array(); },
    (v) => { v.verifyingKey.name = ""; },
    (v) => { v.verifyingKeyCommitment = Buffer.alloc(32); },
    (v) => { v.envelopeHash = Buffer.alloc(32); },
    (v) => { v.envelopeHash = Buffer.alloc(32, 1); },
    (v) => { v.verifyingKey.extra = 1; },
    (v) => { v.extra = 1; },
  ]) { const value = fresh(); mutate(value); assert.throws(() => encodeProofCarrierV1(value)); }
  for (const good of ["a", "a/b::c.d_e-f", "a".repeat(256)]) {
    const value = fresh(); value.backend = good; value.verifyingKey.backend = good;
    assert.equal(decodeProofCarrierV1(encodeProofCarrierV1(value)).backend, good);
  }
});

test("lane depth, index, sibling presence and hash representation remain strict", () => {
  for (const mutate of [
    (v) => { v.auditPath = []; },
    (v) => { v.auditPath = Array(256).fill(Buffer.alloc(32, 1)); },
    (v) => { v.auditPath[0] = null; },
    (v) => { v.auditPath[0][31] &= 254; },
    (v) => { v.auditPath[0] = Buffer.alloc(31); },
    (v) => { v.leafIndex = 4; },
    (v) => { v.leafIndex = -1; },
    (v) => { v.commitmentId = 65536; },
    (v) => { v.leaf = Buffer.alloc(31); },
  ]) { const value = fresh(2); mutate(value.lanePrivacy); assert.throws(() => encodeProofCarrierV1(value)); }
  const value = fresh(2); value.lanePrivacy.auditPath = Array(255).fill(Buffer.alloc(32, 1));
  value.lanePrivacy.leafIndex = 0xffff_ffff;
  assert.equal(decodeProofCarrierV1(encodeProofCarrierV1(value)).lanePrivacy.auditPath.length, 255);
});

test("exact framing, optional tail minimality, hash array widths and proof count are enforced", () => {
  const original = Buffer.from(encodeProofCarrierV1(fresh()));
  for (const offset of [0, 4, 6, 22, 23, 31, 39, original.length - 1]) {
    const bad = Buffer.from(original); bad[offset] ^= 1;
    assert.throws(() => decodeProofCarrierV1(bad));
  }
  assert.throws(() => decodeProofCarrierV1(Buffer.concat([original, Buffer.of(0)])));
  const f = rawFields(original);
  assert.throws(() => decodeProofCarrierV1(frame(struct([...f, Buffer.of(0)]))), /redundant optional tail/u);
  const g = rawFields(original);
  g[1] = struct([rawString("halo2/ipa"), u64ToLittleEndianBuffer(0xffff_ffff_ffff_ffffn)]);
  assert.throws(() => decodeProofCarrierV1(frame(struct(g))), /count exceeds/u);
  const h = rawFields(encodeProofCarrierV1(fresh(1)));
  h[3] = Buffer.concat([Buffer.of(1), withNoritoCompactLengths(() => encodeNoritoField(Buffer.alloc(32, 1)))]);
  assert.throws(() => decodeProofCarrierV1(frame(struct(h))), /fixed hash\.byte16\.length varint is truncated/u);
});

test("complete carrier size includes canonical metadata and frame overhead", () => {
  const value = fresh(); value.proofBytes = Buffer.alloc(9 * 1024 * 1024);
  assert.throws(() => encodeProofCarrierV1(value), /complete carrier exceeds/u);
  assert.throws(() => decodeProofCarrierV1(Buffer.alloc(9 * 1024 * 1024 + 1)), /byte bound/u);
});

test("substituted inner metadata, role and stale statements fail with consistent outer occurrence hashes", () => {
  const fixture = fixtures.accepted[0], intent = Buffer.from(fixture.ordered_intent_digest_hex, "hex");
  const changed = from(fixture), carrier = fresh();
  carrier.verifyingKey.name = "substituted_key"; updateOccurrence(changed, carrier);
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(changed, intent), /public inputs mismatch/u);
  const role = from(fixtures.accepted[2]); role.actions[0].attachments[0].role = "ActionProof";
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(role, Buffer.from(fixtures.accepted[2].ordered_intent_digest_hex, "hex")), /role and lane/u);
  const stale = from(fixture); stale.actions[0].statementDigest[0] ^= 1;
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(stale, intent), /statement digest mismatch/u);
  const wrongIntent = Buffer.from(intent); wrongIntent[0] ^= 1;
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(from(fixture), wrongIntent), /statement digest mismatch/u);
  // Rebinding a statement cannot excuse wrong carrier public inputs.
  changed.actions[0].statementDigest = actionStatementDigestV1(changed.actions[0], intent);
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(changed, intent), /public inputs mismatch/u);
});

test("carrier decoder ownership is independent across source buffers and calls", () => {
  const original = Buffer.from(encodeProofCarrierV1(fresh(2)));
  const a = decodeProofCarrierV1(original), b = decodeProofCarrierV1(original), expected = encodeProofCarrierV1(b);
  original.fill(0); a.proofBytes.fill(0); a.lanePrivacy.leaf.fill(0); a.lanePrivacy.auditPath[0].fill(0);
  assert.deepEqual(encodeProofCarrierV1(b), expected);
});


test("actual shared stale statement vector refuses against its changed nonce intent", () => {
  const rejected = fixtures.rejected.find((v) => v.name === "stale_statement_binding");
  const signed = validateNoritoFrame(Buffer.from(rejected.signed_transaction_hex, "hex")).payload;
  let changedNonce;
  const descriptor = withNoritoCompactLengths(() => {
    const outer = decodeStructFields(signed, "signed", ["signature", "payload", "multisig"]);
    const f = decodeStructFields(outer.payload, "payload", ["domain", "authority", "time", "executable", "ttl", "nonce", "fee", "metadata", "attachments"]);
    changedNonce = f.nonce;
    const option = new BufferReader(f.attachments, "attachment option");
    assert.equal(option.readU8("tag"), 1);
    const value = readNoritoField(option, "value"); option.assertEof();
    return signedAttachmentsFromJsonV1(frameNoritoPayload(value, schemaHashForTypeName("iroha_data_model::transaction::signed_attachments::SignedAttachmentsV1"), 2).toString("base64"));
  });
  // This mutation only changes nonce; reuse the published proof-free projection
  // and replace exactly that canonical field, without pretending this is a
  // general executable/privacy normalizer.
  const projection = withNoritoCompactLengths(() => {
    const names = ["domain", "authority", "time", "executable", "ttl", "nonce", "fee", "metadata", "attachments"];
    const f = decodeStructFields(validateNoritoFrame(Buffer.from(fixtures.accepted[6].ordered_intent_projection_hex, "hex")).payload, "projection", names);
    assert.notDeepEqual(f.nonce, changedNonce); f.nonce = changedNonce;
    return frameNoritoPayload(struct(names.map((n) => f[n])), schemaHashForTypeName("iroha_data_model::transaction::signed::model::TransactionPayload"), 2);
  });
  const intent = blake3(Buffer.concat([Buffer.from("iroha.transaction.ordered-intent-digest.v1"), u64ToLittleEndianBuffer(projection.length), projection]));
  assert.throws(() => inspectSignedAttachmentProofBindingsV1(descriptor, intent), /statement digest mismatch/u);
});


test("proof-free planning needs no fabricated proof or precomputed envelope", () => {
  for (const index of [0, 1, 2]) {
    const completed = fresh(index), expected = proofCarrierPublicInputsDigestV1(completed);
    const planned = structuredClone(completed); planned.proofBytes = new Uint8Array();
    planned.envelopeHash = Buffer.alloc(32); // ignored generated field, never admitted
    assert.deepEqual(proofCarrierPublicInputsDigestV1(planned), expected);
    assert.throws(() => encodeProofCarrierV1(planned), /nonempty/u);
    planned.verifyingKey.name = "";
    assert.throws(() => proofCarrierPublicInputsDigestV1(planned), /portable/u);
  }
  const completed = fresh(1), expected = proofCarrierPublicInputsDigestV1(completed);
  completed.envelopeHash = Buffer.alloc(32, 1);
  assert.deepEqual(proofCarrierPublicInputsDigestV1(completed), expected);
  assert.throws(() => encodeProofCarrierV1(completed), /envelope hash must match/u);
});
