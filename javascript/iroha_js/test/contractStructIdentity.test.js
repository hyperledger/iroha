import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { isCanonicalKotodamaStructName, isCanonicalKotodamaStateTypeName } from "../src/kotodamaIdentifiers.js";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { normalizeContractEventsV1 } from "../src/contractDeclarations.js";

test("qualified struct identity follows the canonical cross-SDK name vectors", async () => {
  const vectors = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/exported_struct_names_v1.json", import.meta.url), "utf8"));
  for (const name of vectors.valid) {
    assert.equal(isCanonicalKotodamaStructName(name), true, name);
    assert.equal(isCanonicalKotodamaStateTypeName(`${name}{}`), true, name);
  }
  for (const name of vectors.invalid) {
    assert.equal(isCanonicalKotodamaStructName(name), false, name);
    assert.equal(isCanonicalKotodamaStateTypeName(`${name}{}`), false, name);
  }
});

test("builtin identities retain friendly display while bare names and unknown owners reject", () => {
  const account = { nodes: [
    { kind: "Struct", value: { name: "kotodama::AccountView", fields: ["id", "metadata"] } },
    { kind: "Leaf", value: { kind: "AccountId", value: null } },
    { kind: "Leaf", value: { kind: "Json", value: null } },
  ] };
  assert.equal(analyzeEntrypointValueTypeV1(account).canonicalName, "AccountView");
  for (const name of ["AccountView", "Payload", "kotodama::Payload", "Unit::AccountView"]) {
    const bad = structuredClone(account);
    bad.nodes[0].value.name = name;
    assert.throws(() => analyzeEntrypointValueTypeV1(bad));
  }
  for (const name of ["Alpha::Payload", "Beta::Payload"]) {
    assert.equal(analyzeEntrypointValueTypeV1({ nodes: [{ kind: "Struct", value: { name, fields: [] } }] }).canonicalName, `struct ${name}`);
  }
});

test("native event payload roots require a qualified matching declaration name", () => {
  const event = (root) => ({ name: "Changed", payload_type: { nodes: [{ kind: "Struct", value: { name: root, fields: [] } }] } });
  assert.equal(normalizeContractEventsV1([event("Demo::Changed")])[0].payload_type.nodes[0].value.name, "Demo::Changed");
  for (const root of ["Changed", "Demo::Other", "kotodama::Changed"]) assert.throws(() => normalizeContractEventsV1([event(root)]));
});

test("durable builtin products enforce exact fields, child types, and page capacity", async () => {
  const vectors = JSON.parse(await readFile(new URL("../../../fixtures/kotodama/durable_builtin_shapes_v1.json", import.meta.url), "utf8"));
  for (const type of vectors.valid) assert.equal(isCanonicalKotodamaStateTypeName(type), true, type);
  for (const type of vectors.invalid) assert.equal(isCanonicalKotodamaStateTypeName(type), false, type);
});
