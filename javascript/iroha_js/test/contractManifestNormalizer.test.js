import { validateManifestFieldsV1 } from "../src/contractManifestRules.js";
import { canonicalHashLiteral, parseHashLiteralToBuffer } from "../src/instructionBuilderPrimitives.js";
import { universalArtifactInstruction } from "./contractArtifactTestHelpers.js";
import { universalArtifactInput } from "./contractArtifactTestHelpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildRegisterSmartContractCodeInstruction } from "../src/instructionBuilders.js";
import { noritoDecodeInstruction, noritoEncodeInstruction } from "../src/norito.js";

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/contract_manifest_v1.json", import.meta.url), "utf8"),
);

function manifestFixture() {
  return structuredClone(fixture.registration_manifest);
}

function observe(object, key, events, label = key, value = object[key]) {
  Object.defineProperty(object, key, {
    enumerable: true,
    configurable: true,
    get() {
      events.push(label);
      return value;
    },
  });
}

test("public manifest builder preserves the Rust fixture and canonical instruction bytes", () => {
  const manifest = manifestFixture();
  const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest }));
  assert.deepEqual(instruction, universalArtifactInstruction({
    RegisterSmartContractCode: { manifest: fixture.registration_manifest },
  }));
  assert.deepEqual(manifest, fixture.registration_manifest);
  assert.notEqual(instruction.RegisterSmartContractCode.manifest, manifest);
  assert.notEqual(instruction.RegisterSmartContractCode.manifest.entrypoints, manifest.entrypoints);

  const encoded = noritoEncodeInstruction(instruction, 753);
  const rustManifest = Buffer.from(fixture.registration_manifest_compact_hex, "hex");
  assert.notEqual(encoded.indexOf(rustManifest), -1, "instruction must contain exact Rust manifest bytes");
  const schemaManifest = Buffer.from(fixture.manifest_compact_hex, "hex");
  const schemaFixture = noritoEncodeInstruction(universalArtifactInstruction({ RegisterSmartContractCode: { manifest: fixture.manifest } }), 753);
  assert.notEqual(schemaFixture.indexOf(schemaManifest), -1, "scoped schema fixture must contain exact Rust manifest bytes");
  const decoded = noritoDecodeInstruction(encoded, 753);
  assert.deepEqual(decoded, instruction);
  assert.deepEqual(noritoEncodeInstruction(decoded, 753), encoded);
});

test("entrypoint getters retain their validation order", () => {
  const manifest = manifestFixture();
  const entrypoint = manifest.entrypoints[0];
  const events = [];
  const fields = [
    "name", "authorization", "kind", "params", "argument_schema", "return_type",
    "return_schema", "read_keys", "write_keys", "access_hints_complete",
    "access_hints_skipped", "triggers",
  ];
  for (const field of fields) observe(entrypoint, field, events);
  const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest }));
  assert.deepEqual(events, fields);
  assert.deepEqual(instruction.RegisterSmartContractCode.manifest, fixture.registration_manifest);
});

test("an entrypoint getter failure stops before later entrypoint fields", () => {
  const manifest = manifestFixture();
  const entrypoint = manifest.entrypoints[0];
  const events = [];
  const failure = new Error("authorization getter failed");
  observe(entrypoint, "name", events);
  Object.defineProperty(entrypoint, "authorization", {
    get() {
      events.push("authorization");
      throw failure;
    },
  });
  observe(entrypoint, "kind", events);
  observe(entrypoint, "params", events);
  assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest })), error => error === failure);
  assert.deepEqual(events, ["name", "authorization"]);
});

test("invalid trigger metadata fails after callback admission and before trigger fields", () => {
  const manifest = manifestFixture();
  const trigger = manifest.entrypoints[0].triggers[0];
  const events = [];
  observe(trigger, "callback", events);
  observe(trigger, "metadata", events, "metadata", []);
  observe(trigger, "id", events);
  observe(trigger, "repeats", events);
  assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest })), {
    code: "ERR_INVALID_OBJECT",
    path: "manifest.entrypoints[0].triggers[0].metadata",
    message: "manifest.entrypoints[0].triggers[0].metadata must be an object",
  });
  assert.deepEqual(events, ["callback", "metadata"]);
});

test("trigger metadata enumeration precedes value validation and callback field reads", () => {
  const manifest = manifestFixture();
  const trigger = manifest.entrypoints[0].triggers[0];
  const events = [];
  const metadata = {};
  observe(metadata, "first", events, "metadata.first", Number.NaN);
  observe(metadata, "second", events, "metadata.second", "read before first is validated");
  observe(trigger, "callback", events);
  observe(trigger, "metadata", events, "metadata", metadata);
  observe(trigger, "id", events);
  observe(trigger, "repeats", events);
  observe(trigger, "filter", events);
  observe(trigger, "authority", events);
  observe(trigger.callback, "namespace", events, "callback.namespace");
  observe(trigger.callback, "entrypoint", events, "callback.entrypoint");
  events.length = 0;
  assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest })), {
    code: "ERR_INVALID_JSON_VALUE",
    path: "manifest.entrypoints[0].triggers[0].metadata.first",
    message: "manifest.entrypoints[0].triggers[0].metadata.first must not contain non-finite numbers",
  });
  assert.deepEqual(events, [
    "callback", "metadata", "id", "repeats", "filter", "authority", "authority",
    "metadata.first", "metadata.second",
  ]);
});

for (const surface of ["provenance", "authority"]) {
  test(`valid manifest ${surface} requires the real native account owner`, () => {
    const directory = mkdtempSync(join(tmpdir(), "iroha-manifest-native-absence-"));
    try {
      const script = `
        import assert from 'node:assert/strict';
        import { readFileSync } from 'node:fs';
        import { buildRegisterSmartContractCodeInstruction } from './src/instructionBuilders.js';
        const fixture = JSON.parse(readFileSync('./test/fixtures/contract_manifest_v1.json', 'utf8'));
        const manifest = structuredClone(fixture.manifest);
        if (${JSON.stringify(surface)} === 'provenance') {
          manifest.provenance = fixture.signed_provenance;
        } else {
          const accounts = JSON.parse(readFileSync('../../fixtures/account/multisig_wire_v1.json', 'utf8'));
          const account = accounts.positive.find(entry => entry.policy !== null);
          assert(account, 'Rust fixture must contain a complete multisig controller');
          manifest.entrypoints[0].triggers[0].authority = account.i105;
        }
        assert.throws(() => buildRegisterSmartContractCodeInstruction({manifest}), {
          code: 'ERR_IROHA_NATIVE_BINDING', nativeStatus: 'missing_file',
        });
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
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("manifest fields reject retired and conflicting spellings before reading them", () => {
  for (const fields of [
    { contractName: "Ledger" },
    { seiyaku_name: "Ledger", seiyakuName: "Ledger" },
    { code_hash: null, codeHash: null },
  ]) {
    const manifest = { ...fields };
    for (const name of Object.keys(manifest)) {
      Object.defineProperty(manifest, name, { enumerable: true, get() {
        assert.fail("unsupported/conflicting manifest field was read");
      } });
    }
    assert.throws(() => buildRegisterSmartContractCodeInstruction({ manifest }),
      /manifest contains (?:unsupported fields|conflicting aliases):/u);
  }
});

test("manifest identity hashes reject a missing marker instead of changing content identity", () => {
  // CRC vectors are independently computed with Python binascii.crc_hqx(..., 0xffff).
  const unmarkedLiteral = `hash:${"AA".repeat(32)}#0E5B`;
  const markedLiteral = `hash:${"AA".repeat(31)}AB#3E38`;
  assert.deepEqual(parseHashLiteralToBuffer(unmarkedLiteral, "unmarked vector"), Buffer.alloc(32, 0xaa));
  assert.equal(parseHashLiteralToBuffer(markedLiteral, "marked vector")[31], 0xab);
  for (const field of ["codeHash", "abiHash"]) {
    for (const value of ["aa".repeat(32), Buffer.alloc(32, 0xaa), new Uint8Array(32).fill(0xaa), unmarkedLiteral]) {
      assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: { [field]: value },
      })), new RegExp(`${field} must set the Iroha Hash marker bit`, "u"));
    }
    const value = Buffer.alloc(32, 0xaa);
    value[31] |= 1;
    for (const admitted of [value, markedLiteral]) {
      const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({
        manifest: { permissions: [], events: [], enum_types: [], [field]: admitted },
      }));
      assert.equal(instruction.RegisterSmartContractCode.manifest[field === "codeHash" ? "code_hash" : "abi_hash"], canonicalHashLiteral(value));
    }
    assert.equal(value[31], 0xab);
  }
});

test("manifest entrypoint selectors reject padding and reserved names", () => {
  for (const name of [" run", "run ", "match", "__kotodama_link_forged"]) {
    assert.throws(() => buildRegisterSmartContractCodeInstruction(universalArtifactInput({
      manifest: { permissions: [], events: [], enum_types: [], entrypoints: [{ name, kind: "View", authorization: { kind: "Anyone", value: null } }] },
    })), /name must be a canonical Kotodama V1 identifier or branded lifecycle selector/u);
  }
});


test("manifest hash admission snapshots caller-owned byte arrays once", () => {
  const hash = Array(32).fill(0x11);
  let reads = 0;
  Object.defineProperty(hash, 31, { enumerable: true, get() {
    reads += 1;
    return reads === 1 ? 0xaa : 0xab;
  } });
  assert.throws(() => buildRegisterSmartContractCodeInstruction({
    manifest: { codeHash: hash },
  }), /codeHash must set the Iroha Hash marker bit/u);
  assert.equal(reads, 1);
});

test('shared field owner preserves builder error code/path and rejects response aliases before getters',()=>{
  assert.throws(()=>buildRegisterSmartContractCodeInstruction({manifest:{contractName:'Legacy'}}),{code:'ERR_INVALID_OBJECT',path:'manifest'});
  assert.throws(()=>buildRegisterSmartContractCodeInstruction({manifest:{codeHash:Buffer.alloc(32,0xaa)}}),{code:'ERR_INVALID_HEX',path:'manifest.codeHash'});
  const manifest={code_hash:null,codeHash:null};
  for(const key of Object.keys(manifest))Object.defineProperty(manifest,key,{enumerable:true,get(){assert.fail('conflicting field getter evaluated');}});
  assert.throws(()=>validateManifestFieldsV1(manifest,'response.manifest'),/response\.manifest contains conflicting aliases: code_hash, codeHash/);
});
