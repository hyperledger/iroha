import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  decodeContractMetadataValueV1,
  encodeContractMetadataValueV1,
} from "../src/noritoContractMetadata.js";
import { noritoEncodeContractManifestSignaturePayload } from "../src/norito.js";
import { readCompactField, visitEmbeddedVector } from "../src/kotodamaCompiler/embeddedNorito.js";

const fixtureUrl = new URL("./fixtures/contract_manifest_v1.json", import.meta.url);

function presentOption(bytes, label) {
  assert.equal(bytes[0], 1, `${label} must be present in the Rust fixture`);
  const state = { offset: 1 };
  const value = readCompactField(bytes, state, label);
  assert.equal(state.offset, bytes.length);
  return value;
}

test("shared metadata codecs match exact declaration bytes from the Rust manifest", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const bytes = Buffer.from(fixture.manifest_compact_hex, "hex");
  const state = { offset: 0 };
  const fields = Array.from({ length: 15 }, (_, index) => readCompactField(bytes, state, `manifest[${index}]`));
  assert.equal(state.offset, bytes.length);
  for (const [kind, index] of [["permissions", 6], ["events", 7], ["enum_types", 11]]) {
    assert.deepEqual(encodeContractMetadataValueV1(kind, fixture.manifest[kind]), fields[index]);
    assert.deepEqual(decodeContractMetadataValueV1(kind, fields[index]), fixture.manifest[kind]);
  }
  const errors = presentOption(fields[10], "error_types");
  assert.deepEqual(encodeContractMetadataValueV1("error_types", fixture.manifest.error_types), errors);
  assert.deepEqual(decodeContractMetadataValueV1("error_types", errors), fixture.manifest.error_types);
  let ordinal = 0;
  visitEmbeddedVector(presentOption(fields[8], "entrypoints"), "entrypoints", 256, (entry) => {
    assert.deepEqual(encodeContractMetadataValueV1("entrypoint", fixture.manifest.entrypoints[ordinal]), entry);
    assert.deepEqual(decodeContractMetadataValueV1("entrypoint", entry), fixture.manifest.entrypoints[ordinal]);
    ordinal += 1;
  });
  assert.equal(ordinal, fixture.manifest.entrypoints.length);
});

test("metadata rejection leaves subsequent manifest serialization byte-exact", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const expected = noritoEncodeContractManifestSignaturePayload(fixture.manifest);
  const entry = encodeContractMetadataValueV1("entrypoint", fixture.manifest.entrypoints[0]);
  for (const malformed of [entry.subarray(0, entry.length - 1), Buffer.concat([entry, Buffer.of(0)])]) {
    assert.throws(() => decodeContractMetadataValueV1("entrypoint", malformed));
    assert.deepEqual(noritoEncodeContractManifestSignaturePayload(fixture.manifest), expected);
    assert.deepEqual(encodeContractMetadataValueV1("entrypoint", fixture.manifest.entrypoints[0]), entry);
  }
});
