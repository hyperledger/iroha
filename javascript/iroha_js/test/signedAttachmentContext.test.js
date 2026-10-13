/** JS boundary controls with a source-test dependency; actual native context has separate Rust fixture tests. */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { blake2b } from "@noble/hashes/blake2b";
import { createNativeRuntime } from "../src/nativeRuntime.js";
import { _createSignedAttachmentContextApi } from "../src/signedAttachmentContext.js";

const fixtures = JSON.parse(fs.readFileSync(new URL("../../../fixtures/zk/signed_attachments_v1/vectors.json", import.meta.url)));
const fixture = fixtures.accepted[0];
const input = () => Buffer.from(fixture.payload_hex, "hex");
const expected = () => ({ networkId: Buffer.alloc(32, 7), authority: "canonical-authority-is-checked-by-native" });
function result() {
  const hash = Buffer.from(blake2b(input(), { dkLen: 32 })); hash[31] |= 1;
  return { payloadHash: hash, orderedIntentDigest: Buffer.from(fixture.ordered_intent_digest_hex, "hex"),
    orderedIntentProjection: Buffer.from(fixture.ordered_intent_projection_hex, "hex"),
    attachmentFrame: Buffer.from(fixture.attachments_frame_base64, "base64"),
    statementDigests: fixture.statement_digests_hex.map((v) => Buffer.from(v, "hex")) };
}
function api(callback) {
  return _createSignedAttachmentContextApi(createNativeRuntime(callback === undefined ? {} : { inspectTransactionAttachmentContextV1: callback }));
}

test("canonical context passes exact copied inputs and returns independently owned metadata", () => {
  const payload = input(), binding = expected(), sourceResult = result(); let calls = 0;
  const context = api((bytes, network, authority) => {
    calls += 1; assert.deepEqual(Buffer.from(bytes), payload); assert.deepEqual(Buffer.from(network), binding.networkId);
    assert.equal(authority, binding.authority); assert.notEqual(bytes, payload); assert.notEqual(network, binding.networkId);
    return sourceResult;
  }).inspectCanonicalTransactionAttachmentContextV1(payload, binding);
  assert.equal(calls, 1);
  const before = Buffer.from(context.attachmentFrame);
  sourceResult.attachmentFrame.fill(0); sourceResult.statementDigests[0].fill(0);
  payload.fill(0); binding.networkId.fill(0);
  assert.deepEqual(Buffer.from(context.attachmentFrame), before);
  assert.deepEqual(Buffer.from(context.statementDigests[0]), Buffer.from(fixture.statement_digests_hex[0], "hex"));
});

test("input size and explicit identity bounds fail before invoking native", () => {
  let calls = 0; const checker = api(() => { calls += 1; return result(); });
  for (const bytes of [new Uint8Array(), Buffer.alloc(10 * 1024 * 1024 + 1), "bytes"]) {
    assert.throws(() => checker.inspectCanonicalTransactionAttachmentContextV1(bytes, expected()), /payloadBytes/u);
  }
  for (const binding of [null, {}, { ...expected(), extra: true }, { ...expected(), networkId: Buffer.alloc(31) }, { ...expected(), authority: " " }]) {
    assert.throws(() => checker.inspectCanonicalTransactionAttachmentContextV1(input(), binding));
  }
  assert.equal(calls, 0);
});

test("missing native method and actual native rejection have no alternate path", () => {
  assert.throws(() => api().inspectCanonicalTransactionAttachmentContextV1(input(), expected()), /lacks canonical/u);
  const original = new Error("actual payload native rejection");
  assert.throws(() => api(() => { throw original; }).inspectCanonicalTransactionAttachmentContextV1(input(), expected()), (error) => error === original);
});

test("native returned projection, carrier and statement shape are independently checked", () => {
  for (const mutate of [
    (v) => { v.payloadHash = Buffer.alloc(31); },
    (v) => { v.payloadHash[0] ^= 1; },
    (v) => { v.orderedIntentDigest[0] ^= 1; },
    (v) => { v.orderedIntentProjection[0] ^= 1; },
    (v) => { v.attachmentFrame[0] ^= 1; },
    (v) => { v.statementDigests[0][0] ^= 1; },
    (v) => { v.statementDigests = []; },
    (v) => { v.statementDigests = Array(17).fill(Buffer.alloc(32)); },
    (v) => { v.attachmentFrame = null; },
  ]) { const value = result(); mutate(value); assert.throws(() => api(() => value).inspectCanonicalTransactionAttachmentContextV1(input(), expected())); }
});
