import test from "node:test";
import { crc64Xz } from "../src/crc64Xz.js";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decodeRetailFeeAssessmentMarkerMessage, encodeRetailFeeQuoteRequestV1, retailFeePaymentIntentHash, encodeRetailFeeAssessmentV1, retailFeeAssessmentMarkerMessage, validateNoritoFrame } from "../src/norito.js";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/retail_fee_codec_v1.json", import.meta.url), "utf8"));
const hash = (request) => Buffer.from(retailFeePaymentIntentHash(request)).toString("hex");

test("retail frames bind the declared Rust schema and exact native header geometry", () => {
  for (const [typeName, encoded, nativeHex] of [
    ["RetailFeeQuoteRequestV1", encodeRetailFeeQuoteRequestV1(fixture.request), fixture.request_hex],
    ["RetailFeeAssessmentV1", encodeRetailFeeAssessmentV1(fixture.assessment), fixture.assessment_hex],
  ]) {
    const frame = validateNoritoFrame(encoded, {
      expectedTypeName: `iroha_data_model::validation_fee::${typeName}`,
      expectedPaddingLength: 0,
      requireNonEmptyPayload: true,
    });
    assert.equal(frame.schemaHash.length, 16);
    assert.equal(frame.flags, 2);
    assert.equal(encoded.length, 40 + frame.payload.length);
    assert.equal(encoded.toString("hex"), nativeHex);
  }
});

test("retail intent commits to exact amount and ordered payment legs", () => {
  assert.equal(encodeRetailFeeQuoteRequestV1(fixture.request).toString("hex"), fixture.request_hex);
  assert.equal(hash(fixture.request), fixture.intent_hash_hex);
  const first = fixture.request.transfers[0];
  const second = { ...first, amount_minor_units: 200 };
  assert.notEqual(hash({ ...fixture.request, transfers: [first, second] }), hash({ ...fixture.request, transfers: [second, first] }));
  assert.notEqual(hash(fixture.request), hash({ ...fixture.request, transfers: [second] }));
});

test("included payments retain a complete zero assessment and marker", () => {
  assert.equal(fixture.assessment.fee_minor, 0);
  assert.equal(retailFeeAssessmentMarkerMessage(fixture.assessment), fixture.marker);
  for (const key of ["fee_minor", "payments_used_before", "policy_revision", "expires_at_ms"]) {
    const changed = { ...fixture.assessment, [key]: fixture.assessment[key] + 1 };
    if (key === "fee_minor") assert.throws(() => retailFeeAssessmentMarkerMessage(changed));
    else assert.notEqual(retailFeeAssessmentMarkerMessage(changed), fixture.marker);
  }
  assert.notEqual(retailFeeAssessmentMarkerMessage({ ...fixture.assessment, retail_enrolled: false }), fixture.marker);
});

test("fee codecs reject hidden overrides, malformed commitments and lossy quantities", () => {
  assert.throws(() => encodeRetailFeeQuoteRequestV1({ ...fixture.request, exempt: true }));
  assert.throws(() => encodeRetailFeeAssessmentV1({ ...fixture.assessment, disabled: true }));
  assert.throws(() => encodeRetailFeeAssessmentV1({ ...fixture.assessment, intent_hash: [1] }));
  for (const amount of [-1, 0.1, Number.MAX_SAFE_INTEGER + 1, "18446744073709551616"]) {
    assert.throws(() => encodeRetailFeeQuoteRequestV1({ ...fixture.request, transfers: [{ ...fixture.request.transfers[0], amount_minor_units: amount }] }));
  }
});

test("review decodes exact marker and rejects trailing or noncanonical archives", () => {
  assert.deepEqual(decodeRetailFeeAssessmentMarkerMessage(fixture.marker), fixture.assessment);
  assert.throws(() => decodeRetailFeeAssessmentMarkerMessage(fixture.marker + "00"));
  assert.throws(() => decodeRetailFeeAssessmentMarkerMessage(fixture.marker.toUpperCase()));
});

test("retail codecs enforce positive legs, canonical hash markers and Native count bounds", () => {
  for (const amount of [0, 0n]) {
    assert.throws(() => encodeRetailFeeQuoteRequestV1({ ...fixture.request,
      transfers: [{ ...fixture.request.transfers[0], amount_minor_units: amount }] }));
  }
  assert.throws(() => encodeRetailFeeQuoteRequestV1({ ...fixture.request,
    transfers: Array.from({ length: 1_001 }, () => fixture.request.transfers[0]) }));
  assert.doesNotThrow(() => encodeRetailFeeQuoteRequestV1({ ...fixture.request,
    transfers: Array.from({ length: 1_000 }, () => fixture.request.transfers[0]) }));
  assert.throws(() => encodeRetailFeeAssessmentV1({ ...fixture.assessment, qualifying_payments: 1_001 }));
  for (const key of ["state_commitment", "intent_hash"]) {
    const evenHash = `${fixture.assessment[key].slice(0, 62)}02`;
    assert.throws(() => encodeRetailFeeAssessmentV1({ ...fixture.assessment, [key]: evenHash }));
  }
  assert.throws(() => decodeRetailFeeAssessmentMarkerMessage(
    `iroha:retail_fee:assessment:v1:${"00".repeat(2_034)}`));
});


test("retail assessment hash fields use exact raw Rust byte-array fields", () => {
  const canonical = Buffer.from(fixture.assessment_hex, "hex");
  const frame = validateNoritoFrame(canonical);
  const fields = [];
  let cursor = 0;
  while (cursor < frame.payload.length) {
    // Every field in this bounded canonical fixture fits one compact length byte.
    const length = frame.payload[cursor++];
    assert.ok(length < 128);
    assert.ok(cursor + length <= frame.payload.length);
    fields.push(frame.payload.subarray(cursor, cursor + length));
    cursor += length;
  }
  assert.equal(fields.length, 10);
  for (const [index, name] of [[7, "state_commitment"], [8, "intent_hash"]]) {
    assert.equal(fields[index].length, 32);
    assert.equal(fields[index].toString("hex"), fixture.assessment[name].toLowerCase());
    for (const length of [31, 33, 64]) {
      const changed = fields.map((value, i) => i === index
        ? length === 64
          ? Buffer.from(Array.from(value, (byte) => [1, byte]).flat())
          : Buffer.alloc(length, 1)
        : value);
      const payload = Buffer.concat(changed.flatMap((value) => [Buffer.from([value.length]), value]));
      const header = Buffer.from(canonical.subarray(0, 40));
      header.writeBigUInt64LE(BigInt(payload.length), 23);
      header.writeBigUInt64LE(crc64Xz(payload), 31);
      const bytes = Buffer.concat([header, payload]);
      assert.doesNotThrow(() => validateNoritoFrame(bytes), "the mutation keeps the outer archive valid");
      const marker = "iroha:retail_fee:assessment:v1:" + bytes.toString("hex");
      assert.throws(() => decodeRetailFeeAssessmentMarkerMessage(marker),
        new RegExp(`${name} must contain exactly 32 bytes`, "u"));
    }
  }
  assert.equal(encodeRetailFeeAssessmentV1(fixture.assessment).toString("hex"), fixture.assessment_hex);
  assert.deepEqual(decodeRetailFeeAssessmentMarkerMessage(fixture.marker), fixture.assessment);
});
