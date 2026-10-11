import { artifactReadContext, artifactReadOptions, withArtifactResponseIdentity } from "./contractArtifactReadTestHelpers.js";
import { universalArtifactInstruction } from "./contractArtifactTestHelpers.js";
import { universalArtifactInput } from "./contractArtifactTestHelpers.js";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { buildRegisterSmartContractCodeInstruction } from "../src/instructionBuilders.js";
import { ToriiClient } from "../src/toriiClient.js";
import { normalizeContractErrorMessagesV1, normalizeContractErrorTypeV1, normalizeContractErrorTypesV1, validateManifestErrorTypeBindingsV1 } from "../src/contractErrorTypes.js";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { isCanonicalKotodamaStateTypeName, isCanonicalKotodamaStructName } from "../src/kotodamaIdentifiers.js";
import { noritoEncodeInstruction, noritoDecodeInstruction } from "../src/norito.js";
import { encodeContractMetadataValueV1, decodeContractMetadataValueV1 } from "../src/noritoContractMetadata.js";

const error = { identity: "example/vault@1.0.0::金庫::拒否", variants: [{ name: "不足", code: 1 }, { name: "CapacityExceeded", code: 2 }] };
const returnSchema = { nodes: [{ kind: "Result", value: null }, { kind: "Unit", value: null }, { kind: "Error", value: error }] };

test("state-only nominal identities require the exact manifest catalog", async () => {
  const fixture = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/nominal_errors_v1.json", import.meta.url), "utf8"));
  const manifest = { ...fixture.manifest, entrypoints: [] };
  validateManifestErrorTypeBindingsV1(manifest);
  assert.throws(() => validateManifestErrorTypeBindingsV1({ ...manifest, error_types: [] }), /catalog/u);
  for (const typeName of [
    "missing/package@1::Vault::Failure",
    "Result<(), missing/package@1::Vault::Failure>",
    "StateMap<int, List<Option<missing/package@1::Vault::Failure>, 8>>",
    "Fixture::Record{status: missing/package@1::Vault::Failure}",
  ]) {
    assert.throws(() => validateManifestErrorTypeBindingsV1({
      ...manifest, states: [{ name: "status", type_name: typeName }],
    }), /catalog/u);
  }
});

test("shared SDK nominal fixture binds the same Japanese error and Unit schemas", async () => {
  const fixture = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/nominal_errors_v1.json", import.meta.url), "utf8"));
  validateManifestErrorTypeBindingsV1(fixture.manifest);
  assert.deepEqual(fixture.manifest.error_types[0], error);
  assert.deepEqual(fixture.manifest.entrypoints[0].return_schema, returnSchema);
  const cursor = fixture.manifest.entrypoints[1].return_schema;
  assert.equal(analyzeEntrypointValueTypeV1(cursor).canonicalName, "Option<StateCursor<int>>");
  assert.equal(analyzeEntrypointValueTypeV1(cursor).wordCount, 1);
  assert.equal(isCanonicalKotodamaStateTypeName("Option<StateCursor<int>>"), true);
  assert.equal(isCanonicalKotodamaStateTypeName("StateCursor<Json>"), false);
  const page = fixture.manifest.entrypoints[2].return_schema;
  assert.equal(analyzeEntrypointValueTypeV1(page).canonicalName, "StatePage<int, bool, 8>");
  assert.equal(analyzeEntrypointValueTypeV1(page).wordCount, 2);
  assert.equal(isCanonicalKotodamaStateTypeName(fixture.manifest.states[2].type_name), true);
  const forged = structuredClone(page);
  forged.nodes[6].value.nodes[0].value.kind = "Bool";
  assert.throws(() => analyzeEntrypointValueTypeV1(forged), /forged StatePage/u);
  assert.throws(() => analyzeEntrypointValueTypeV1({ nodes: [{ kind: "StateCursor", value: { nodes: [{ kind: "Leaf", value: { kind: "Json", value: null } }] } }] }), /scalar|Json/u);
});

test("nominal catalogs allow enum-local codes and reject malformed or duplicate schemas", () => {
  assert.deepEqual(normalizeContractErrorTypeV1(error), error);
  assert.equal(normalizeContractErrorTypesV1([error, { ...error, identity: "kotodama::ListError" }]).length, 2);
  for (const value of [
    { ...error, identity: "Injected<Error>" },
    { ...error, variants: [{ name: "Rejected", code: 0 }] },
    { ...error, variants: [...error.variants].reverse() },
    { ...error, variants: [{ name: "Duplicate", code: 1 }, { name: "Duplicate", code: 2 }] },
  ]) assert.throws(() => normalizeContractErrorTypeV1(value), TypeError);
  assert.throws(() => normalizeContractErrorTypesV1([error, error]), /duplicate error identity/u);
});

test("Unit and nominal errors compose into exact public and state types", () => {
  assert.equal(analyzeEntrypointValueTypeV1(returnSchema).canonicalName, `Result<(), ${error.identity}>`);
  assert.equal(analyzeEntrypointValueTypeV1(returnSchema).wordCount, 1);
  assert.equal(isCanonicalKotodamaStateTypeName(`Result<(), ${error.identity}>`), true);
  assert.equal(isCanonicalKotodamaStateTypeName(`StateMap<${error.identity}, bool>`), false);
  const manifest = { enum_types: [], events: [], error_types: [error], entrypoints: [{ return_schema: returnSchema }] };
  validateManifestErrorTypeBindingsV1(manifest);
  assert.throws(() => validateManifestErrorTypeBindingsV1({ ...manifest, error_types: [{ ...error, variants: [{ name: "Different", code: 1 }] }] }), /does not match/u);
});

test("native Norito manifest codecs roundtrip Unit and nominal error schemas", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"));
  const manifest = structuredClone(fixture.manifest);
  manifest.error_types = [error];
  manifest.error_messages = [{ error_type: error.identity, code: 1, message: "残高が不足しています" }];
  manifest.entrypoints[0].return_type = `Result<(), ${error.identity}>`;
  manifest.entrypoints[0].return_schema = returnSchema;
  const instruction = universalArtifactInstruction({ RegisterSmartContractCode: { manifest } });
  const encoded = noritoEncodeInstruction(instruction, 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.error_types, [error]);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.error_messages, manifest.error_messages);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.entrypoints[0].return_schema, returnSchema);
  assert.deepEqual(noritoEncodeInstruction(decoded, 753), encoded);
});

test("canonical Norito manifest codec preserves nominal state cursor key schemas", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"));
  const manifest = structuredClone(fixture.manifest);
  const schema = { nodes: [{ kind: "Option", value: null }, { kind: "StateCursor", value: { nodes: [{ kind: "Leaf", value: { kind: "Int", value: null } }] } }] };
  manifest.entrypoints[0].return_type = "Option<StateCursor<int>>";
  manifest.entrypoints[0].return_schema = schema;
  const encoded = noritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest } }), 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.entrypoints[0].return_schema, schema);
  assert.deepEqual(noritoEncodeInstruction(decoded, 753), encoded);
});


test("durable StatePage names enforce their exact fields and matching keys", () => {
  for (const typeName of [
    "StatePage{anything: int}",
    "StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<bool>>}",
    "StatePage{items: List<(Json, bool), 8>, next: Option<StateCursor<Json>>}",
  ]) assert.equal(isCanonicalKotodamaStateTypeName(typeName), false);
});


test("public Unit returns require an exact descriptor on JSON and Norito boundaries", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"));
  const manifest = structuredClone(fixture.manifest);
  manifest.entrypoints[0].return_type = "()";
  manifest.entrypoints[0].return_schema = { nodes: [{ kind: "Unit", value: null }] };
  const encoded = noritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest } }), 753);
  const decoded = noritoDecodeInstruction(encoded, 753).RegisterSmartContractCode.manifest;
  assert.deepEqual(decoded.entrypoints[0].return_schema, manifest.entrypoints[0].return_schema);
  buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest }));
  const fetchManifest = async (value) => new ToriiClient("https://localhost:8080", {
    localSigningContext: artifactReadContext,
    fetchImpl: async () => new Response(JSON.stringify(withArtifactResponseIdentity({ manifest: { ...value, code_hash: "hash:1111111111111111111111111111111111111111111111111111111111111111#4667" }, code_hash: "11".repeat(32), abi_hash: null }, "11".repeat(32))), {
      status: 200, headers: { "content-type": "application/json" },
    }),
  }).getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, artifactReadOptions());
  await fetchManifest(manifest);
  for (const fields of [["return_type"], ["return_schema"], ["return_type", "return_schema"]]) {
    for (const omitted of [false, true]) {
      const invalid = structuredClone(manifest);
      for (const field of fields) {
        if (omitted) delete invalid.entrypoints[0][field];
        else invalid.entrypoints[0][field] = null;
      }
      assert.throws(() => noritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest: invalid } }), 753), /return_type.*return_schema/u);
      assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest: invalid })), /return_type.*return_schema/u);
      await assert.rejects(fetchManifest(invalid), /return_type.*return_schema/u);
    }
  }
});


test("exported structs retain locked identity in public and durable schemas", async () => {
  const fixture = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/exported_structs_v1.json", import.meta.url), "utf8"));
  const vectors = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/exported_struct_names_v1.json", import.meta.url), "utf8"));
  const original = "std/math@1.0.0::Math::Receipt";
  for (const name of vectors.valid) {
    const manifest = JSON.parse(JSON.stringify(fixture.manifest).replaceAll(original, name));
    validateManifestErrorTypeBindingsV1(manifest);
    const entrypoint = manifest.entrypoints[0];
    assert.equal(analyzeEntrypointValueTypeV1(entrypoint.return_schema).canonicalName, `struct ${name}`);
    assert.equal(analyzeEntrypointValueTypeV1(entrypoint.argument_schema.fields[0].ty).wordCount, 3);
    assert.equal(isCanonicalKotodamaStructName(name), true, name);
    assert.equal(isCanonicalKotodamaStateTypeName(manifest.states[0].type_name), true, name);
  }
  for (const name of vectors.invalid) {
    const manifest = JSON.parse(JSON.stringify(fixture.manifest).replaceAll(original, name));
    assert.equal(isCanonicalKotodamaStructName(name), false, name);
    assert.throws(() => analyzeEntrypointValueTypeV1(manifest.entrypoints[0].return_schema), TypeError, name);
    assert.throws(() => validateManifestErrorTypeBindingsV1(manifest), TypeError, name);
  }
  const base = JSON.parse(await readFile(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"));
  const manifest = { ...base.manifest, error_messages: null, ...fixture.manifest };
  const encoded = noritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest } }), 753);
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.entrypoints[0].return_schema, fixture.manifest.entrypoints[0].return_schema);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.states, fixture.manifest.states);
  assert.deepEqual(noritoEncodeInstruction(decoded, 753), encoded);
  manifest.error_types = [];
  assert.throws(() => validateManifestErrorTypeBindingsV1(manifest), /catalog/u);
});


test("manifest instruction encoding and decoding reject unavailable native bindings", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"));
  const instruction = universalArtifactInstruction({ RegisterSmartContractCode: { manifest: fixture.manifest } });
  const encoded = noritoEncodeInstruction(instruction, 753);
  const directory = await mkdtemp(join(tmpdir(), "iroha-manifest-codec-native-absence-"));
  try {
    const script = `
      import assert from "node:assert/strict";
      import { noritoEncodeInstruction, noritoDecodeInstruction } from "./src/norito.js";
import { encodeContractMetadataValueV1, decodeContractMetadataValueV1 } from "./src/noritoContractMetadata.js";
      const instruction = ${JSON.stringify(instruction)};
      const encoded = Buffer.from(${JSON.stringify(encoded.toString("base64"))}, "base64");
      for (const operation of [
        () => noritoEncodeInstruction(instruction, 753),
        () => noritoEncodeInstruction(JSON.stringify(instruction), 753),
        () => noritoEncodeInstruction(encoded, 753),
        () => noritoDecodeInstruction(encoded, 753),
        () => noritoDecodeInstruction(encoded, 753, { parseJson: false }),
      ]) {
        assert.throws(operation, { code: "ERR_IROHA_NATIVE_BINDING", nativeStatus: "missing_file" });
      }
    `;
    const child = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      env: { ...process.env, IROHA_JS_NATIVE_DIR: join(directory, "absent-native") },
      encoding: "utf8",
    });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, 0, child.stderr || child.stdout);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("static error messages bind declared variants without changing nominal schemas", () => {
  const entry = { error_type: error.identity, code: 1, message: "残高が不足しています" };
  assert.deepEqual(normalizeContractErrorMessagesV1([entry], [error]), [entry]);
  assert.equal(normalizeContractErrorMessagesV1(null, [error]), null);
  for (const mutation of [
    { ...entry, error_type: "Other::Failure" }, { ...entry, code: 3 },
    { ...entry, message: " \n\t" }, { ...entry, message: "é".repeat(2049) },
  ]) assert.throws(() => normalizeContractErrorMessagesV1([mutation], [error]), TypeError);
  assert.throws(() => normalizeContractErrorMessagesV1([entry, entry], [error]), /sorted and unique/u);
  assert.deepEqual(normalizeContractErrorMessagesV1([{ ...entry, message: "é".repeat(2048) }], [error])[0].message.length, 2048);
  const manifest = { enum_types: [], events: [], error_types: [error], error_messages: [entry] };
  validateManifestErrorTypeBindingsV1(manifest);
  assert.deepEqual(manifest.error_types, [error]);
});

test("tuple cursors bind the exact full key schema and share the public node budget", () => {
  const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
  const key = { nodes: [{ kind: "Tuple", value: 2 }, leaf("AccountId"), { kind: "Tuple", value: 2 }, leaf("Int"), leaf("Name")] };
  const cursor = { kind: "StateCursor", value: key };
  const frame = encodeContractMetadataValueV1("value_type", { nodes: [cursor] });
  assert.deepEqual(decodeContractMetadataValueV1("value_type", frame), { nodes: [cursor] });
  assert.deepEqual(encodeContractMetadataValueV1("value_type", decodeContractMetadataValueV1("value_type", frame)), frame);
  assert.equal(analyzeEntrypointValueTypeV1({ nodes: [cursor] }).canonicalName, "StateCursor<(AccountId, (int, Name))>");
  const page = { nodes: [{ kind: "Struct", value: { name: "kotodama::StatePage", fields: ["items", "next"] } }, { kind: "List", value: { capacity: 8 } }, { kind: "Tuple", value: 2 }, ...key.nodes, leaf("Bool"), { kind: "Option", value: null }, cursor] };
  assert.equal(analyzeEntrypointValueTypeV1(page).canonicalName, "StatePage<(AccountId, (int, Name)), bool, 8>");
  const wrong = structuredClone(page); wrong.nodes.at(-1).value.nodes[3] = leaf("Bool");
  assert.throws(() => analyzeEntrypointValueTypeV1(wrong), /forged StatePage/u);
  for (const invalid of [{ kind: "Int", value: null }, { nodes: [{ kind: "StateCursor", value: key }] }, { nodes: [leaf("Json")] }]) assert.throws(() => analyzeEntrypointValueTypeV1({ nodes: [{ kind: "StateCursor", value: invalid }] }));
  for (const [arity, valid] of [[254, true], [255, false]]) {
    const schema = { nodes: [{ kind: "StateCursor", value: { nodes: [{ kind: "Tuple", value: arity }, ...Array.from({ length: arity }, () => leaf("Int"))] } }] };
    if (valid) assert.equal(analyzeEntrypointValueTypeV1(schema).nodeCount, 256);
    else assert.throws(() => analyzeEntrypointValueTypeV1(schema), /budget/u);
  }
});
