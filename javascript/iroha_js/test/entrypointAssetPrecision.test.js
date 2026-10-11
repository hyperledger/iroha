import assert from "node:assert/strict";
import test from "node:test";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";

const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
const option = () => ({ kind: "Option", value: null });
const fields = [
  "id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata",
];
function definitionNodes() {
  return [
    { kind: "Struct", value: { name: "kotodama::AssetDefinitionView", fields: [...fields] } },
    leaf("AssetDefinitionId"), leaf("String"), option(), leaf("String"),
    leaf("AccountId"), leaf("Quantity"), option(), leaf("Int"), leaf("Json"),
  ];
}
function pageNodes(nodes) {
  return [
    { kind: "Struct", value: { name: "kotodama::QueryPage", fields: ["items", "next_offset"] } },
    { kind: "List", value: { capacity: 64 } },
    ...nodes, option(), leaf("Int"),
  ];
}

test("asset-definition manifests bind optional numeric precision in views and pages", () => {
  const view = analyzeEntrypointValueTypeV1({ nodes: definitionNodes() });
  assert.equal(view.canonicalName, "AssetDefinitionView");
  assert.equal(view.nodeCount, 10);
  assert.equal(view.wordCount, 7);
  const page = analyzeEntrypointValueTypeV1({ nodes: pageNodes(definitionNodes()) });
  assert.equal(page.canonicalName, "QueryPage<AssetDefinitionView>");
  assert.equal(page.wordCount, 2);
});

for (const [label, mutate] of [
  ["retired six-field projection", (nodes) => {
    nodes[0].value.fields.splice(5, 1);
    nodes.splice(7, 2);
  }],
  ["required precision", (nodes) => { nodes.splice(7, 1); }],
  ["decimal precision", (nodes) => { nodes[8] = leaf("Decimal"); }],
  ["renamed precision", (nodes) => { nodes[0].value.fields[5] = "scale"; }],
  ["reordered precision", (nodes) => {
    [nodes[0].value.fields[5], nodes[0].value.fields[6]] = ["metadata", "numeric_scale"];
    nodes.splice(7, 3, leaf("Json"), option(), leaf("Int"));
  }],
]) {
  test(`asset-definition manifests reject ${label}`, () => {
    const nodes = definitionNodes();
    mutate(nodes);
    for (const candidate of [nodes, pageNodes(nodes)]) {
      assert.throws(
        () => analyzeEntrypointValueTypeV1({ nodes: candidate }),
        /forged reserved query-view schema/u,
      );
    }
  });
}
