import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

import {
  PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1,
  PRIVACY_EXACT12_PROTOCOL_IDS_V1,
  noritoDecodePrivacyExact12FixtureBundleBase64V1,
  noritoDecodePrivacyExact12FixtureBundleV1,
  noritoEncodePrivacyExact12FixtureBundleV1,
  validateNoritoFrame,
} from "../src/norito.js";

const FIXTURE_URL = new URL(
  "../../../fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64",
  import.meta.url,
);
const MATRIX_URL = new URL(
  "../../../fixtures/privacy/exact12_v1.tsv",
  import.meta.url,
);
const BUNDLE_BASE64_FILE = fs.readFileSync(FIXTURE_URL, "utf8");
assert.equal(
  BUNDLE_BASE64_FILE.endsWith("\n"),
  true,
  "checked Exact12 fixture must end in exactly one LF",
);
const BUNDLE_BASE64 = BUNDLE_BASE64_FILE.slice(0, -1);
assert.equal(
  BUNDLE_BASE64.includes("\n"),
  false,
  "checked Exact12 fixture must contain exactly one line",
);
assert.match(
  BUNDLE_BASE64,
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u,
  "checked Exact12 fixture must contain one canonical standard-base64 line",
);
const BUNDLE_BYTES = Buffer.from(BUNDLE_BASE64, "base64");
const NORITO_CRC64_MASK = 0xffff_ffff_ffff_ffffn;
const NORITO_CRC64_POLY = 0xc96c_5795_d787_0f42n;

function protocolIdsFromMatrix() {
  return fs
    .readFileSync(MATRIX_URL, "utf8")
    .split("\n")
    .filter((line) => line.startsWith("protocol\t"))
    .map((line) => line.split("\t")[2]);
}

function cloneBundle(bundle) {
  return {
    version: bundle.version,
    rows: bundle.rows.map((row) => ({
      protocolId: row.protocolId,
      statementNorito: Uint8Array.from(row.statementNorito),
      envelopeNorito: Uint8Array.from(row.envelopeNorito),
      submitProofWireId: row.submitProofWireId,
      submitProofInstructionNorito: Uint8Array.from(
        row.submitProofInstructionNorito,
      ),
      transactionIntentProjectionNorito: Uint8Array.from(
        row.transactionIntentProjectionNorito,
      ),
      transactionIntentDigest: Uint8Array.from(row.transactionIntentDigest),
      unsignedTransactionPayloadNorito: Uint8Array.from(
        row.unsignedTransactionPayloadNorito,
      ),
      signedTransactionVersionedNorito: Uint8Array.from(
        row.signedTransactionVersionedNorito,
      ),
      signedTransactionHash: Uint8Array.from(row.signedTransactionHash),
    })),
  };
}

function noritoCrc64(payload) {
  let crc = NORITO_CRC64_MASK;
  for (const byte of payload) {
    let tableEntry = (crc ^ BigInt(byte)) & 0xffn;
    for (let bit = 0; bit < 8; bit += 1) {
      tableEntry =
        (tableEntry & 1n) === 0n
          ? tableEntry >> 1n
          : (tableEntry >> 1n) ^ NORITO_CRC64_POLY;
    }
    crc = tableEntry ^ (crc >> 8n);
  }
  return BigInt.asUintN(64, crc ^ NORITO_CRC64_MASK);
}

function rewriteOuterCrc(archive) {
  const payloadLength = Number(archive.readBigUInt64LE(23));
  const payload = archive.subarray(archive.length - payloadLength);
  archive.writeBigUInt64LE(noritoCrc64(payload), 31);
}

function readCompactLength(buffer, offset, context) {
  let value = 0;
  let multiplier = 1;
  for (let used = 0; used < 10 && offset + used < buffer.length; used += 1) {
    const byte = buffer[offset + used];
    value += (byte & 0x7f) * multiplier;
    if ((byte & 0x80) === 0) {
      assert.ok(Number.isSafeInteger(value), `${context} must fit a safe integer`);
      return { value, bytes: used + 1 };
    }
    multiplier *= 128;
  }
  assert.fail(`${context} has an invalid compact length`);
}

function readCompactField(buffer, offset, context) {
  const length = readCompactLength(buffer, offset, `${context}.length`);
  const payloadStart = offset + length.bytes;
  const end = payloadStart + length.value;
  assert.ok(end <= buffer.length, `${context} must fit its parent payload`);
  return { start: offset, payloadStart, end, next: end };
}

function outerRowsLayout(archive) {
  const frame = validateNoritoFrame(archive);
  const payloadStart = archive.length - frame.payload.length;
  const version = readCompactField(frame.payload, 0, "bundle.version");
  const rows = readCompactField(frame.payload, version.next, "bundle.rows");
  assert.equal(rows.next, frame.payload.length);
  const rowsPayload = frame.payload.subarray(rows.payloadStart, rows.end);
  assert.equal(rowsPayload.readBigUInt64LE(0), 12n);
  const rowFields = [];
  let cursor = 8;
  for (let index = 0; index < 12; index += 1) {
    const row = readCompactField(rowsPayload, cursor, `bundle.rows[${index}]`);
    rowFields.push(row);
    cursor = row.next;
  }
  assert.equal(cursor, rowsPayload.length);
  return { payloadStart, rows, rowsPayload, rowFields };
}

test("checked Exact12 base64 decodes all byte-complete rows and re-encodes identically", () => {
  assert.match(BUNDLE_BASE64, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
  assert.equal(BUNDLE_BYTES.toString("base64"), BUNDLE_BASE64);
  assert.ok(BUNDLE_BYTES.length <= PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1);

  const bundle = noritoDecodePrivacyExact12FixtureBundleBase64V1(BUNDLE_BASE64);
  assert.equal(bundle.version, 1);
  assert.deepEqual(
    bundle.rows.map((row) => row.protocolId),
    [...PRIVACY_EXACT12_PROTOCOL_IDS_V1],
  );
  assert.deepEqual(bundle.rows.map((row) => row.protocolId), protocolIdsFromMatrix());
  for (const row of bundle.rows) {
    assert.equal(row.submitProofWireId, "iroha.privacy.submit_proof.v1");
    for (const field of [
      "statementNorito",
      "envelopeNorito",
      "submitProofInstructionNorito",
      "transactionIntentProjectionNorito",
      "transactionIntentDigest",
      "unsignedTransactionPayloadNorito",
      "signedTransactionVersionedNorito",
      "signedTransactionHash",
    ]) {
      assert.ok(row[field] instanceof Uint8Array, field);
      assert.ok(row[field].byteLength > 0, field);
    }
    assert.equal(row.transactionIntentDigest.byteLength, 32);
    assert.equal(row.signedTransactionHash.byteLength, 32);
  }
  assert.deepEqual(
    Buffer.from(noritoEncodePrivacyExact12FixtureBundleV1(bundle)),
    BUNDLE_BYTES,
  );
  assert.deepEqual(
    noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES),
    bundle,
  );
});

test("Exact12 base64 and outer frame reject alternate encodings, bounds, and tails", () => {
  for (const alternate of [
    `${BUNDLE_BASE64}\n`,
    ` ${BUNDLE_BASE64}`,
    BUNDLE_BASE64.slice(0, -1),
  ]) {
    assert.throws(
      () => noritoDecodePrivacyExact12FixtureBundleBase64V1(alternate),
      /base64|archive|frame/i,
    );
  }
  assert.throws(
    () =>
      noritoDecodePrivacyExact12FixtureBundleBase64V1(
        "A".repeat(
          Math.ceil(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 / 3) * 4 + 1,
        ),
      ),
    /archive limit/,
  );
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES.subarray(0, -1)),
    /payload|CRC|frame|overran/i,
  );
  assert.throws(
    () =>
      noritoDecodePrivacyExact12FixtureBundleV1(
        Buffer.concat([BUNDLE_BYTES, Buffer.of(0)]),
      ),
    /padding|trailing|CRC/i,
  );
  assert.throws(
    () =>
      noritoDecodePrivacyExact12FixtureBundleV1(
        Buffer.alloc(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1),
      ),
    /exceeds/,
  );

  const wrongLayout = Buffer.from(BUNDLE_BYTES);
  wrongLayout[39] = 0;
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(wrongLayout),
    /canonical layout flags/,
  );
  const wrongSchema = Buffer.from(BUNDLE_BYTES);
  wrongSchema[6] ^= 0x80;
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(wrongSchema),
    /schema hash/,
  );
});

test("Exact12 decoder rejects adversarial declared counts and lengths before allocation", () => {
  const wrongCount = Buffer.from(BUNDLE_BYTES);
  const countLayout = outerRowsLayout(wrongCount);
  const rowsCountOffset = countLayout.payloadStart + countLayout.rows.payloadStart;
  wrongCount.writeBigUInt64LE(13n, rowsCountOffset);
  rewriteOuterCrc(wrongCount);
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(wrongCount),
    /exactly 12 rows/,
  );

  const oversizedNestedVector = Buffer.from(BUNDLE_BYTES);
  const statementFrameOffset = oversizedNestedVector.indexOf(
    Buffer.from("NRT0", "ascii"),
    40,
  );
  assert.ok(statementFrameOffset > 8, "first nested statement frame must exist");
  const statementLengthOffset = statementFrameOffset - 8;
  assert.ok(oversizedNestedVector.readBigUInt64LE(statementLengthOffset) > 40n);
  oversizedNestedVector.writeBigUInt64LE(
    BigInt(PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1),
    statementLengthOffset,
  );
  rewriteOuterCrc(oversizedNestedVector);
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(oversizedNestedVector),
    /decoding limit/,
  );

  const bundle = noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES);
  const sparseOversized = cloneBundle(bundle);
  sparseOversized.rows[0].statementNorito = new Array(
    PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1 + 1,
  );
  assert.throws(
    () => noritoEncodePrivacyExact12FixtureBundleV1(sparseOversized),
    /archive limit/,
  );
});

test("Exact12 protocol rows reject reorder, duplicate, unknown, and substitution", () => {
  const reordered = Buffer.from(BUNDLE_BYTES);
  const layout = outerRowsLayout(reordered);
  const first = Buffer.from(
    layout.rowsPayload.subarray(
      layout.rowFields[0].start,
      layout.rowFields[0].next,
    ),
  );
  const second = Buffer.from(
    layout.rowsPayload.subarray(
      layout.rowFields[1].start,
      layout.rowFields[1].next,
    ),
  );
  Buffer.concat([second, first]).copy(layout.rowsPayload, layout.rowFields[0].start);
  rewriteOuterCrc(reordered);
  assert.throws(
    () => noritoDecodePrivacyExact12FixtureBundleV1(reordered),
    /reordered protocol|substituted protocol/,
  );

  for (const [label, discriminant] of [
    ["duplicate", 0],
    ["unknown", 12],
  ]) {
    const mutated = Buffer.from(BUNDLE_BYTES);
    const mutatedLayout = outerRowsLayout(mutated);
    const row = mutatedLayout.rowFields[1];
    const rowPayload = mutatedLayout.rowsPayload.subarray(row.payloadStart, row.end);
    const protocol = readCompactField(rowPayload, 0, "row.protocol_id");
    assert.equal(protocol.end - protocol.payloadStart, 4);
    const absoluteProtocolOffset =
      mutatedLayout.payloadStart +
      mutatedLayout.rows.payloadStart +
      row.payloadStart +
      protocol.payloadStart;
    mutated.writeUInt32LE(discriminant, absoluteProtocolOffset);
    rewriteOuterCrc(mutated);
    assert.throws(
      () => noritoDecodePrivacyExact12FixtureBundleV1(mutated),
      new RegExp(label),
    );
  }

  const bundle = noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES);
  const substituted = cloneBundle(bundle);
  substituted.rows[0].statementNorito = Uint8Array.from(
    substituted.rows[1].statementNorito,
  );
  assert.throws(
    () => noritoEncodePrivacyExact12FixtureBundleV1(substituted),
    /substituted protocol/,
  );

  const unknownField = cloneBundle(bundle);
  unknownField.rows[0].legacy = true;
  assert.throws(
    () => noritoEncodePrivacyExact12FixtureBundleV1(unknownField),
    /unknown field legacy/,
  );
});

test("Exact12 encoder authenticates every byte-complete row field", () => {
  const bundle = noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES);
  for (const field of [
    "statementNorito",
    "envelopeNorito",
    "submitProofInstructionNorito",
    "transactionIntentProjectionNorito",
    "transactionIntentDigest",
    "unsignedTransactionPayloadNorito",
    "signedTransactionVersionedNorito",
    "signedTransactionHash",
  ]) {
    const mutated = cloneBundle(bundle);
    const bytes = mutated.rows[0][field];
    bytes[bytes.length - 1] ^= 0x80;
    assert.throws(
      () => noritoEncodePrivacyExact12FixtureBundleV1(mutated),
      undefined,
      field,
    );
  }
  const wrongWire = cloneBundle(bundle);
  wrongWire.rows[0].submitProofWireId += "x";
  assert.throws(
    () => noritoEncodePrivacyExact12FixtureBundleV1(wrongWire),
    /must be exactly/,
  );
});

test("Exact12 envelope requires the final marker and every native catalog byte", () => {
  const bundle = noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES);
  const original = Buffer.from(bundle.rows[0].envelopeNorito);
  const frame = validateNoritoFrame(original);
  const payloadStart = original.length - frame.payload.length;
  const marker = readCompactField(frame.payload, 0, "wire magic");
  const catalog = readCompactField(frame.payload, marker.next, "catalog commitment");
  assert.equal(marker.end - marker.payloadStart, 8);
  assert.equal(catalog.end - catalog.payloadStart, 32);
  assert.equal(frame.payload.subarray(catalog.payloadStart, catalog.end).toString("hex"),
    "5bcf366fb18d2e4361486c015da5b41a3fb00edf05611042ccc452120d176eb0");
  for (const [field, offsets, expected] of [
    [marker, [0, 7], /wire marker/],
    [catalog, Array.from({ length: 32 }, (_, index) => index), /catalog commitment/],
  ]) {
    for (const offset of offsets) {
      const mutated = cloneBundle(bundle);
      const envelope = Buffer.from(original);
      envelope[payloadStart + field.payloadStart + offset] ^= 1;
      rewriteOuterCrc(envelope);
      mutated.rows[0].envelopeNorito = envelope;
      assert.throws(() => noritoEncodePrivacyExact12FixtureBundleV1(mutated), expected);
    }
  }
  const canonicalCatalog = frame.payload.subarray(catalog.payloadStart, catalog.end);
  for (const hostile of [
    canonicalCatalog.subarray(0, 31), Buffer.concat([canonicalCatalog, Buffer.from([0])]),
    Buffer.concat([canonicalCatalog, Buffer.alloc(16)]),
    Buffer.from("e037f13904a0307c00db15d85cfb406bd79772d20144a949def0f3fda78e342e747f65787cbfbffac94f11c369e2bbff", "hex"),
  ]) {
    const payload = Buffer.concat([
      frame.payload.subarray(0, marker.next), Buffer.from([hostile.length]), hostile,
      frame.payload.subarray(catalog.next),
    ]);
    const malformed = Buffer.concat([original.subarray(0, payloadStart), payload]);
    malformed.writeBigUInt64LE(BigInt(payload.length), 23);
    rewriteOuterCrc(malformed);
    const mutated = cloneBundle(bundle);
    mutated.rows[0].envelopeNorito = malformed;
    assert.throws(() => noritoEncodePrivacyExact12FixtureBundleV1(mutated), /catalog commitment/);
  }
  const retired = cloneBundle(bundle);
  const envelope = Buffer.concat([
    original.subarray(0, payloadStart),
    frame.payload.subarray(catalog.next),
  ]);
  envelope.writeBigUInt64LE(BigInt(frame.payload.length - catalog.next), 23);
  rewriteOuterCrc(envelope);
  retired.rows[0].envelopeNorito = envelope;
  assert.throws(() => noritoEncodePrivacyExact12FixtureBundleV1(retired));
});

test("Exact12 envelope requires each protocol's final proof system and engine", () => {
  const bundle = noritoDecodePrivacyExact12FixtureBundleV1(BUNDLE_BYTES);
  for (let rowIndex = 0; rowIndex < 12; rowIndex += 1) {
    const original = Buffer.from(bundle.rows[rowIndex].envelopeNorito);
    const frame = validateNoritoFrame(original);
    const payloadStart = original.length - frame.payload.length;
    let offset = 0;
    for (let index = 0; index < 5; index += 1) {
      const field = readCompactField(frame.payload, offset, `envelope.field[${index}]`);
      offset = field.next;
      if (index < 3) continue;
      const mutated = cloneBundle(bundle);
      const envelope = Buffer.from(original);
      envelope.writeUInt32LE((envelope.readUInt32LE(payloadStart + field.payloadStart) + 1) % 9,
        payloadStart + field.payloadStart);
      rewriteOuterCrc(envelope);
      mutated.rows[rowIndex].envelopeNorito = envelope;
      assert.throws(() => noritoEncodePrivacyExact12FixtureBundleV1(mutated), /proof_system_id|engine_id/);
    }
  }
});

test("source, distribution, and browser-leaf Exact12 codecs stay byte-identical", async () => {
  const originalBuffer = globalThis.Buffer;
  const browserBuild = await build({
    entryPoints: [fileURLToPath(new URL("../dist/norito.js", import.meta.url))],
    bundle: true,
    format: "esm",
    logLevel: "silent",
    metafile: true,
    platform: "browser",
    write: false,
  });
  assert.equal(browserBuild.outputFiles.length, 1);
  assert.equal(
    Object.keys(browserBuild.metafile.inputs).some((input) => input.startsWith("node:")),
    false,
    "the Exact12 Norito leaf must retain a browser-only graph",
  );
  const browserModule = await import(
    `data:text/javascript;base64,${Buffer.from(browserBuild.outputFiles[0].contents).toString("base64")}`
  );
  assert.equal(
    globalThis.Buffer,
    originalBuffer,
    "the Exact12 Norito leaf must not install a global Buffer shim",
  );

  for (const [surface, module] of [
    ["source", await import(new URL("../src/norito.js", import.meta.url))],
    ["distribution", await import(new URL("../dist/norito.js", import.meta.url))],
    ["browser leaf", browserModule],
  ]) {
    const decoded = module.noritoDecodePrivacyExact12FixtureBundleBase64V1(
      BUNDLE_BASE64,
    );
    assert.equal(decoded.rows.length, 12, surface);
    assert.deepEqual(
      Buffer.from(module.noritoEncodePrivacyExact12FixtureBundleV1(decoded)),
      BUNDLE_BYTES,
      surface,
    );
    assert.throws(
      () =>
        module.noritoDecodePrivacyExact12FixtureBundleBase64V1(
          `${BUNDLE_BASE64}\n`,
        ),
      /base64/,
      surface,
    );
  }

  const browserFacade = await import(new URL("../dist/browser.js", import.meta.url));
  for (const fixtureOnlyExport of [
    "noritoDecodePrivacyExact12FixtureBundleBase64V1",
    "noritoDecodePrivacyExact12FixtureBundleV1",
    "noritoEncodePrivacyExact12FixtureBundleV1",
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_MAX_BYTES_V1",
    "PRIVACY_EXACT12_FIXTURE_BUNDLE_SCHEMA_NAME_V1",
    "PRIVACY_EXACT12_PROTOCOL_IDS_V1",
  ]) {
    assert.equal(
      Object.hasOwn(browserFacade, fixtureOnlyExport),
      false,
      `${fixtureOnlyExport} must stay on the root/Norito APIs, not the broad browser facade`,
    );
  }
});
