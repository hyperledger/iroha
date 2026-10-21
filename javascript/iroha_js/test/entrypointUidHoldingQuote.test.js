import assert from "node:assert/strict";
import test from "node:test";
import { analyzeEntrypointValueTypeV1 } from "../src/entrypointSchema.js";
import { isCanonicalKotodamaStateTypeName } from "../src/kotodamaIdentifiers.js";
import { CORE_QUERY_VIEWS, UID_HOLDING_QUOTE, isExactDurableBuiltinProduct } from "../src/kotodamaProducts.js";

const leaf = (kind) => ({ kind: "Leaf", value: { kind, value: null } });
const option = () => ({ kind: "Option", value: null });
const list = (capacity) => ({ kind: "List", value: { capacity } });
const product = (name, fields) => ({ kind: "Struct", value: { name, fields } });
const fields = ["asset_definition_id", "account_id", "policy_revision", "beneficial_holdings", "holding_limit", "required_overflow"];
const types = ["AssetDefinitionId", "AccountId", "int", "quantity", "Option<quantity>", "quantity"];
const quote = () => [product("kotodama::AssetUidHoldingQuote", [...fields]), leaf("AssetDefinitionId"), leaf("AccountId"), leaf("Int"), leaf("Quantity"), option(), leaf("Quantity"), leaf("Quantity")];
const analyze = (nodes) => analyzeEntrypointValueTypeV1({ nodes });
const durable = (names = fields, children = types) => `kotodama::AssetUidHoldingQuote{${names.map((name, i) => `${name}: ${children[i]}`).join(", ")}}`;

test("UID holding quote is an exact six-word public product and remains outside QueryPage", () => {
  const schema = analyze(quote());
  assert.equal(schema.canonicalName, "AssetUidHoldingQuote");
  assert.equal(schema.nodeCount, 8);
  assert.equal(schema.wordCount, 6);
  assert.equal(analyze([option(), ...quote()]).canonicalName, "Option<AssetUidHoldingQuote>");
  assert.equal(analyze([list(2), ...quote()]).canonicalName, "List<AssetUidHoldingQuote, 2>");
  assert.equal(CORE_QUERY_VIEWS.size, 5);
  assert.equal(CORE_QUERY_VIEWS.has(UID_HOLDING_QUOTE.name), false);
  assert.throws(() => analyze([product("kotodama::QueryPage", ["items", "next_offset"]), list(64), ...quote(), option(), leaf("Int")]), /forged QueryPage/u);
});

test("UID holding quote boundary rejects field, order, identity and exact leaf substitutions", () => {
  for (let index = 0; index < fields.length; index += 1) {
    const nodes = quote(); nodes[0].value.fields[index] = `forged_${index}`;
    assert.throws(() => analyze(nodes), /forged/u);
  }
  for (const index of [1, 2, 3, 4, 6, 7]) {
    const nodes = quote(); nodes[index] = leaf("Bool");
    assert.throws(() => analyze(nodes), /forged/u);
  }
  const reordered = quote(); [reordered[0].value.fields[3], reordered[0].value.fields[5]] = [fields[5], fields[3]];
  assert.throws(() => analyze(reordered), /forged/u);
  const required = quote(); required.splice(5, 1);
  assert.throws(() => analyze(required), /forged/u);
  const forgedName = quote(); forgedName[0].value.name = "kotodama::ForgedQuote";
  assert.throws(() => analyze(forgedName), /noncanonical/u);
});

test("UID quote durable grammar enforces exact product without granting query row status", () => {
  assert.equal(isCanonicalKotodamaStateTypeName(durable()), true);
  assert.equal(isExactDurableBuiltinProduct(UID_HOLDING_QUOTE.name, fields, [...types, "quantity"]), false);
  assert.equal(isExactDurableBuiltinProduct(UID_HOLDING_QUOTE.name, fields, types.slice(0, -1)), false);
  assert.equal(isCanonicalKotodamaStateTypeName(`Option<${durable()}>`), true);
  assert.equal(isCanonicalKotodamaStateTypeName(`List<${durable()}, 2>`), true);
  for (let index = 0; index < fields.length; index += 1) {
    const names = [...fields]; names[index] = `forged_${index}`;
    assert.equal(isCanonicalKotodamaStateTypeName(durable(names)), false);
    const children = [...types]; children[index] = "bool";
    assert.equal(isCanonicalKotodamaStateTypeName(durable(fields, children)), false);
  }
  assert.equal(isCanonicalKotodamaStateTypeName(`kotodama::QueryPage{items: List<${durable()}, 64>, next_offset: Option<int>}`), false);
  assert.equal(isCanonicalKotodamaStateTypeName("kotodama::AssetUidHoldingQuote{}"), false);
});
