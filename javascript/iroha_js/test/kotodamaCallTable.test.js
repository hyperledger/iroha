import { artifactReadContext, artifactReadOptions, withArtifactResponseIdentity } from "./contractArtifactReadTestHelpers.js";
import { universalArtifactInput } from "./contractArtifactTestHelpers.js";
import test from "node:test";
import assert from "node:assert/strict";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { buildRegisterSmartContractCodeInstruction } from "../src/instructionBuilders.js";
import { noritoEncodeInstruction, noritoDecodeInstruction } from "../src/norito.js";
import { ToriiClient } from "../src/toriiClient.js";

const boolean = ["bool", [{ kind: "Leaf", value: { kind: "Bool", value: null } }]];
const unit = ["()", [{ kind: "Unit", value: null }]];
const codeHash = "hash:1111111111111111111111111111111111111111111111111111111111111111#4667";

function tuple(width) {
  return [
    `(${Array(width).fill("bool").join(", ")})`,
    [{ kind: "Tuple", value: width }, ...Array(width).fill(boolean[1][0])],
  ];
}

function manifest(fields, returns = unit) {
  return {
    code_hash: codeHash,
    permissions: [], events: [], enum_types: [],
    entrypoints: [{
      name: "inspect", kind: { kind: "View", value: null },
      authorization: { kind: "Anyone", value: null },
      params: fields.map(([typeName], index) => ({ name: `arg_${index}`, type_name: typeName })),
      argument_schema: fields.length === 0 ? null : {
        fields: fields.map(([, nodes], index) => ({ name: `arg_${index}`, ty: { nodes } })),
      },
      return_type: returns[0], return_schema: { nodes: returns[1] },
    }],
  };
}

function normalizeBuilder(value) {
  return buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest: value })).RegisterSmartContractCode.manifest;
}

async function normalizeTorii(value) {
  const client = new ToriiClient("https://localhost:8080", {
    localSigningContext: artifactReadContext,
    fetchImpl: async () => new Response(JSON.stringify(withArtifactResponseIdentity({
      manifest: value, code_hash: "11".repeat(32), abi_hash: null,
    }, "11".repeat(32))), { headers: { "content-type": "application/json" } }),
  });
  return (await client.getContractManifest({ dataspaceId: "0", codeHash: "11".repeat(32) }, artifactReadOptions())).manifest;
}

for (const [label, normalize] of [["builder", normalizeBuilder], ["Torii", normalizeTorii]]) {
  test(`${label} accepts wide argument and result tables`, async () => {
    const value = await normalize(manifest(Array(64).fill(boolean), tuple(64)));
    assert.equal(value.entrypoints[0].argument_schema.fields.length, 64);
    assert.equal(analyzeEntrypointValueTypeV1(value.entrypoints[0].return_schema, "result").wordCount, 64);
  });

  test(`${label} enforces the inclusive 8192-word table bound`, async () => {
    const value = await normalize(manifest(Array(8192).fill(boolean)));
    assert.equal(value.entrypoints[0].argument_schema.fields.length, 8192);
    await assert.rejects(async () => normalize(manifest(Array(8193).fill(boolean))), /8192/u);
    const flattened = Array(64).fill(tuple(128));
    await normalize(manifest(flattened));
    await assert.rejects(async () => normalize(manifest([...flattened, boolean])), /8192/u);
  });

  test(`${label} preserves schema limits with table calls`, async () => {
    await normalize(manifest([], tuple(255)));
    await assert.rejects(async () => normalize(manifest([], tuple(256))), /schema|nodes|bounds/u);
  });

  test(`${label} gives empty named products one word`, async () => {
    const empty = ["struct Fixture::Empty", [{ kind: "Struct", value: { name: "Fixture::Empty", fields: [] } }]];
    const list = ["List<struct Fixture::Empty, 2>", [{ kind: "List", value: { capacity: 2 } }, ...empty[1]]];
    const value = await normalize(manifest([empty], list));
    const argument = analyzeEntrypointValueTypeV1(value.entrypoints[0].argument_schema.fields[0].ty, "argument");
    assert.equal(argument.wordCount, 1);
    assert.equal(argument.canonicalName, "struct Fixture::Empty");
    assert.equal(analyzeEntrypointValueTypeV1(value.entrypoints[0].return_schema, "result").wordCount, 1);
  });
}

test("Norito contract records roundtrip wide and empty named return schemas", () => {
  const empty = ["struct Fixture::Empty", [{ kind: "Struct", value: { name: "Fixture::Empty", fields: [] } }]];
  for (const returns of [tuple(64), empty]) {
    const instruction = buildRegisterSmartContractCodeInstruction(universalArtifactInput({ manifest: manifest([empty], returns) }));
    const encoded = noritoEncodeInstruction(instruction, 753);
    assert.deepEqual(noritoDecodeInstruction(encoded, 753), instruction);
  }
});
