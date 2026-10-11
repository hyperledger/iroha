import assert from "node:assert/strict";
import test from "node:test";
import { buildRegisterSmartContractCodeInstruction } from "../src/instructionBuilders.js";
import { canonicalHashLiteral } from "../src/instructionBuilderPrimitives.js";
import { noritoEncodeInstruction, noritoDecodeInstruction, noritoEncodeContractManifestSignaturePayload } from "../src/norito.js";

const codeHash = "11".repeat(32);
const artifactId = { dataspaceId: "18446744073709551615", codeHash };
const unit = { returnType: "()", returnSchema: { nodes: [{ kind: "Unit", value: null }] } };
const anyone = { kind: "Anyone", value: null };
const lifecycle = { kind: "RuntimeLifecycle", value: null };
const declared = (name) => ({ kind: "Permission", value: name });
const permissions = [{ name: "Write", scope: { kind: "Instance", value: null } }];
const view = { name: "read", kind: "View", authorization: anyone, ...unit };
const call = { name: "write", kind: "Kotoage", authorization: declared("Write"), ...unit };
const trigger = {
  id: "update",
  repeats: { Indefinitely: null },
  filter: "AQ==",
  callback: { entrypoint: "write" },
};

function build(manifest) {
  return buildRegisterSmartContractCodeInstruction({ artifactId, manifest: { codeHash, permissions, events: [], enumTypes: [], ...manifest } });
}

for (const [name, manifest, error] of [
  ["unknown fields", { contractName: "Retired" }, /unsupported fields: contractName/u],
  ["conflicting aliases", { seiyakuName: "Ledger", seiyaku_name: "Other" }, /conflicting aliases/u],
  ["null aliases", { seiyakuName: "Ledger", seiyaku_name: null }, /conflicting aliases/u],
  ["unmarked code hash", { codeHash: "aa".repeat(32) }, /Hash marker bit/u],
  ["unmarked ABI hash", { abiHash: "aa".repeat(32) }, /Hash marker bit/u],
  ["wrong lifecycle kind", { entrypoints: [{ name: "hajimari", kind: "Kotoage", authorization: declared("Write"), ...unit }] }, /branded lifecycle selector/u],
  ["wrong lifecycle name", { entrypoints: [{ name: "setup", kind: "Hajimari", authorization: lifecycle, ...unit }] }, /branded lifecycle selector/u],
  ["lifecycle permission", { entrypoints: [{ name: "kaizen", kind: "Kaizen", authorization: declared("Write"), ...unit }] }, /RuntimeLifecycle exactly/u],
  ["missing call permission", { entrypoints: [{ ...call, authorization: null }] }, /requires exactly/u],
  ["reserved selector", { entrypoints: [{ ...view, name: "match" }] }, /canonical Kotodama V1 identifier/u],
  ["duplicate names", { entrypoints: [view, view] }, /duplicate name read/u],
  ["duplicate lifecycle", { entrypoints: [{ name: "hajimari", kind: "Hajimari", authorization: lifecycle, ...unit }, { name: "始まり", kind: "Hajimari", authorization: lifecycle, ...unit }] }, /duplicate Hajimari/u],
  ["duplicate triggers", { entrypoints: [{ ...call, triggers: [trigger, trigger] }] }, /duplicate trigger update/u],
  ["undeclared callback", { entrypoints: [{ ...call, triggers: [{ ...trigger, callback: { entrypoint: "absent" } }] }] }, /undeclared local entrypoint/u],
  ["view callback", { entrypoints: [view, { ...call, triggers: [{ ...trigger, callback: { entrypoint: "read" } }] }] }, /local callback must target kotoage/u],
  ["missing hint reason", { entrypoints: [{ ...view, accessHintsComplete: false }] }, /incomplete without a reason/u],
  ["inconsistent complete hints", { entrypoints: [{ ...view, accessHintsComplete: true, accessHintsSkipped: ["dynamic"] }] }, /complete but records skipped reasons/u],
  ["duplicate states", { states: [{ name: "balance", typeName: "quantity" }, { name: "balance", typeName: "quantity" }] }, /duplicate state name balance/u],
  ["duplicate message IDs", { kotoba: [{ msgId: "title", translations: [] }, { msgId: "title", translations: [] }] }, /duplicate msg_id title/u],
  ["duplicate languages", { kotoba: [{ msgId: "title", translations: [{ lang: "en", text: "Ledger" }, { lang: "en", text: "Other" }] }] }, /duplicate language en/u],
]) {
  test(`manifest instruction rejects ${name} before native encoding`, () => {
    assert.throws(() => build(manifest), error);
  });
}

test("manifest instruction retains valid lifecycle, callback, hints and full-width scope", () => {
  const manifest = {
    entrypoints: [
      { name: "hajimari", kind: "Hajimari", authorization: lifecycle, ...unit },
      { name: "改善", kind: "Kaizen", authorization: lifecycle, ...unit },
      view,
      { ...call, triggers: [trigger], accessHintsComplete: false, accessHintsSkipped: ["dynamic"] },
    ],
    states: [{ name: "balance", typeName: "quantity" }],
    kotoba: [{ msgId: "title", translations: [{ lang: "en", text: "Ledger" }] }],
  };
  const original = structuredClone(manifest);
  const result = build(manifest).RegisterSmartContractCode;
  assert.equal(result.artifact_id.dataspace_id, artifactId.dataspaceId);
  assert.equal(result.manifest.entrypoints[3].triggers[0].callback.entrypoint, "write");
  assert.deepEqual(manifest, original);
  assert.equal(build({ abiHash: codeHash }).RegisterSmartContractCode.manifest.abi_hash,
    canonicalHashLiteral(Buffer.from(codeHash, "hex")));
  assert.equal(build({ abiHash: canonicalHashLiteral(Buffer.from(codeHash, "hex")) }).RegisterSmartContractCode.manifest.abi_hash,
    canonicalHashLiteral(Buffer.from(codeHash, "hex")));
});

for (const [name, manifest, error] of [
  ["missing table", { permissions: undefined }, /required permission declaration array/u],
  ["undeclared role", { permissions: [], entrypoints: [call] }, /undeclared permission/u],
  ["duplicate roles", { permissions: [permissions[0], permissions[0]] }, /sorted and unique/u],
  ["unsorted roles", { permissions: [{ name: "Zulu", scope: { kind: "Instance", value: null } }, permissions[0]] }, /sorted and unique/u],
  ["retired string guard", { entrypoints: [{ ...call, permission: "Write" }] }, /permission is retired/u],
  ["lifecycle guard on view", { entrypoints: [{ ...view, authorization: lifecycle }] }, /RuntimeLifecycle exactly/u],
]) {
  test(`manifest authorization rejects ${name}`, () => assert.throws(() => build(manifest), error));
}

test("manifest authorization distinguishes public, instance, and explicit chain roles", () => {
  const shared = { name: "Operator", scope: { kind: "Chain", value: { permission_name: "SharedOperators" } } };
  const output = build({ permissions: [shared, ...permissions], entrypoints: [view, call, { ...view, name: "private_read", authorization: declared("Operator") }] }).RegisterSmartContractCode.manifest;
  assert.deepEqual(output.permissions, [shared, ...permissions]);
  assert.deepEqual(output.entrypoints[2].authorization, declared("Operator"));
});

test("manifest permission scopes roundtrip through Norito and bind the signed payload", () => {
  const shared = { name: "Operator", scope: { kind: "Chain", value: { permission_name: "SharedOperators" } } };
  const instruction = build({ permissions: [shared, ...permissions], entrypoints: [view, call] });
  const decoded = noritoDecodeInstruction(noritoEncodeInstruction(instruction, 753), 753);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.permissions, [shared, ...permissions]);
  assert.deepEqual(decoded.RegisterSmartContractCode.manifest.entrypoints[1].authorization, declared("Write"));
  const original = noritoEncodeContractManifestSignaturePayload(instruction.RegisterSmartContractCode.manifest);
  instruction.RegisterSmartContractCode.manifest.permissions[0].scope.value.permission_name = "OtherOperators";
  assert.notDeepEqual(noritoEncodeContractManifestSignaturePayload(instruction.RegisterSmartContractCode.manifest), original);
});
