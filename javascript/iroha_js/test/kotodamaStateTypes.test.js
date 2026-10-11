import assert from "node:assert/strict";
import test from "node:test";
import { isCanonicalKotodamaStateTypeName } from "../src/kotodamaIdentifiers.js";

test("durable empty products preserve their nominal spelling at root and nested positions", () => {
  for (const type of [
    "Fixture::Empty{}",
    "Fixture::Other{}", "Fixture::Transfer{}",
    "List<Fixture::Empty{}, 2>",
    "List<List<Fixture::Empty{}, 2>, 2>",
    "Fixture::Envelope{empty: Fixture::Empty{}}",
    "StateMap<int, Fixture::Empty{}>",
    "std/math@1.0.0::Math::Empty{}",
  ]) assert.equal(isCanonicalKotodamaStateTypeName(type), true, type);
});

test("empty products do not relax canonical syntax or reserved type shapes", () => {
  for (const type of [
    "Empty{}", "Envelope{empty: Empty{}}",
    "{}", "Fixture::Empty{", "Fixture::Empty{ }", "Fixture::Empty{,}", "Fixture::Empty{: int}",
    "Fixture::Empty{field: int, }", "Fixture::Empty{}trailing", "List<Fixture::Empty{},2>",
    "List<Fixture::Empty{}, 0>", "Fixture::Envelope{empty: Fixture::Empty{}, empty: Fixture::Empty{}}",
    "StatePage{}", "Option{}", "int{}",
  ]) assert.equal(isCanonicalKotodamaStateTypeName(type), false, type);
});
