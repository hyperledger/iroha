import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalContractArguments,
  canonicalContractPayloadJson,
  contractPayloadDigestHex,
} from "../src/contractPayload.js";

const leaf = (kind) => ({ nodes: [{ kind: "Leaf", value: { kind, value: null } }] });

test("tagged Option payloads retain Unit and nested presence in their signed digest", () => {
  const values = [
    { some: null },
    { none: true },
    { some: { none: true } },
    { some: { some: null } },
  ];
  const digests = values.map((value) => {
    const payload = { value };
    assert.deepEqual(JSON.parse(canonicalContractPayloadJson(payload)), payload);
    return contractPayloadDigestHex(payload);
  });
  assert.equal(new Set(digests).size, values.length);
  assert.ok(!digests.includes(contractPayloadDigestHex({ value: null })));
});

test("contract payload digest matches Torii's absent-payload preimage", () => {
  const expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
  assert.equal(canonicalContractPayloadJson(undefined), null);
  assert.equal(canonicalContractPayloadJson(null), null);
  assert.equal(contractPayloadDigestHex(undefined), expected);
  assert.equal(contractPayloadDigestHex(null), expected);
});

test("contract payload canonicalization matches the Torii Norito JSON vector", () => {
  const payload = {
    z: "line\ncontrol\u000b😀",
    b: [true, false, null],
    a: 1,
  };
  const canonical = '{"a":1,"b":[true,false,null],"z":"line\\ncontrol\\u000b😀"}';
  assert.equal(canonicalContractPayloadJson(payload), canonical);
  assert.equal(
    contractPayloadDigestHex(payload),
    "f10ae09b778159dda1747afacbf679edb4b61690abd3714dbb387c42c436a2df",
  );
});

test("contract payload keys use Rust UTF-8 byte ordering rather than JavaScript UTF-16 ordering", () => {
  const payload = { "𐀀": 2, "": 1 };
  const canonical = '{"":1,"𐀀":2}';
  assert.equal(canonicalContractPayloadJson(payload), canonical);
  assert.equal(
    contractPayloadDigestHex(payload),
    "420a7bf67b19b06cff5cee796118b273c37afe53dd11200d233929b4f918f827",
  );
});

test("contract payload canonicalization rejects values without exact browser-to-Norito parity", () => {
  for (const value of [1e-6, Number.MAX_SAFE_INTEGER + 1, -0, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => canonicalContractPayloadJson({ value }), /safe integers/u);
  }
  assert.throws(() => canonicalContractPayloadJson({ value: undefined }), /unsupported undefined/u);
  assert.throws(() => canonicalContractPayloadJson({ value: "\ud800" }), /Unicode scalar/u);

  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalContractPayloadJson({ sparse }), /dense/u);

  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalContractPayloadJson(cyclic), /cycles/u);
});

test("schema-aware arguments stringify int, decimal and quantity numbers canonically", () => {
  const argumentSchema = {
    fields: [
      { name: "amount", ty: leaf("Int") },
      { name: "rate", ty: leaf("Decimal") },
      { name: "limit", ty: leaf("Quantity") },
      { name: "space", ty: leaf("DataSpaceId") },
      { name: "memo", ty: leaf("Json") },
      { name: "data", ty: leaf("Blob") },
    ],
  };
  const normalized = canonicalContractArguments(
    { amount: 5, rate: "1.25", limit: 10n, space: "7", memo: { n: 1 }, data: new Uint8Array([1, 171]) },
    { argumentSchema },
  );
  assert.deepEqual(normalized, {
    amount: "5",
    rate: "1.25",
    limit: "10",
    space: 7,
    memo: { n: 1 },
    data: "0x01ab",
  });
  assert.equal(
    canonicalContractPayloadJson({ amount: 5, rate: "1.25", limit: "10", space: 7, memo: { n: 1 }, data: "0x01ab" }, { argumentSchema }),
    '{"amount":"5","data":"0x01ab","limit":"10","memo":{"n":1},"rate":"1.25","space":7}',
  );
  assert.equal(
    contractPayloadDigestHex({ amount: 5, rate: "1.25", limit: "10", space: 7, memo: { n: 1 }, data: "0x01ab" }, { argumentSchema }),
    contractPayloadDigestHex(normalized),
  );
});

test("schema-aware arguments reject inexact values with the argument path", () => {
  const argumentSchema = {
    fields: [
      {
        name: "order",
        ty: {
          nodes: [
            { kind: "Struct", value: { name: "Fixture::Order", fields: ["lines", "memo"] } },
            { kind: "List", value: { capacity: 4 } },
            { kind: "Leaf", value: { kind: "Quantity", value: null } },
            { kind: "Option", value: null },
            { kind: "Leaf", value: { kind: "String", value: null } },
          ],
        },
      },
    ],
  };
  const reject = (payload, pattern) =>
    assert.throws(() => canonicalContractArguments(payload, { argumentSchema }), pattern);
  reject({ order: { lines: ["1", 2.5], memo: { none: true } } }, /argument `order\.lines\[1\]` expects quantity .* found the JSON number 2\.5/u);
  reject({ order: { lines: ["-1"], memo: { none: true } } }, /argument `order\.lines\[0\]` expects quantity/u);
  reject({ order: { lines: [], memo: { some: 7 } } }, /argument `order\.memo\.some` expects string/u);
  reject({ order: { lines: [] } }, /argument `order\.memo` expects a value for this declared field/u);
  reject({ order: { lines: [], memo: { none: true } }, extra: 1 }, /argument `extra` is not declared/u);
  reject({ order: { lines: ["1", "01"], memo: { none: true } } }, /argument `order\.lines\[1\]`/u);
  assert.deepEqual(
    canonicalContractArguments({ order: { lines: [3, "2.5"], memo: { some: "hi" } } }, { argumentSchema }),
    { order: { lines: ["3", "2.5"], memo: { some: "hi" } } },
  );
  assert.throws(
    () => canonicalContractArguments({ amount: 1.5 }, { argumentSchema: { fields: [{ name: "amount", ty: leaf("Int") }] } }),
    /argument `amount` expects int as a canonical decimal integer string such as "5", found the JSON number 1\.5/u,
  );
});

test("arguments without a schema reject JSON numbers instead of guessing their type", () => {
  assert.throws(
    () => canonicalContractArguments({ transfer: { amount: 5 } }),
    /argument `transfer\.amount` is the JSON number 5; without the entrypoint argument schema/u,
  );
  assert.throws(() => canonicalContractPayloadJson({ amount: 5 }, {}), /argument `amount`/u);
  assert.deepEqual(canonicalContractArguments({ amount: "5", tags: ["a"] }), { amount: "5", tags: ["a"] });
  assert.equal(canonicalContractArguments(undefined), null);
  assert.equal(canonicalContractArguments({}, { argumentSchema: null }), null);
  assert.throws(
    () => canonicalContractArguments({ amount: "5" }, { argumentSchema: null }),
    /expects no arguments for this zero-parameter entrypoint/u,
  );
});

test("schema counts accept every manifest number form and reject a missing list capacity", () => {
  const schemaWith = (tupleArity, listCapacity) => ({
    fields: [
      {
        name: "pair",
        ty: {
          nodes: [
            { kind: "Tuple", value: tupleArity },
            { kind: "Leaf", value: { kind: "Int", value: null } },
            { kind: "List", value: { capacity: listCapacity } },
            { kind: "Leaf", value: { kind: "Quantity", value: null } },
          ],
        },
      },
    ],
  });
  for (const [arity, capacity] of [[2, 2], [2n, 2n], ["2", "2"]]) {
    assert.deepEqual(
      canonicalContractArguments({ pair: [7, [1n, "2"]] }, { argumentSchema: schemaWith(arity, capacity) }),
      { pair: ["7", ["1", "2"]] },
    );
  }
  assert.throws(
    () => canonicalContractArguments({ pair: [7, [1, 2, 3]] }, { argumentSchema: schemaWith("2", "2") }),
    /argument `pair\[1\]` expects a list as a JSON array of at most 2 element\(s\)/u,
  );
  assert.throws(
    () => canonicalContractArguments({ pair: [7, [1]] }, { argumentSchema: schemaWith(2, undefined) }),
    /argument `pair\[1\]` has an invalid V1 argument schema node/u,
  );
  assert.throws(
    () => canonicalContractArguments({ pair: [7, [1]] }, { argumentSchema: schemaWith("02", 2) }),
    /argument `pair` has an invalid V1 argument schema node/u,
  );
});
