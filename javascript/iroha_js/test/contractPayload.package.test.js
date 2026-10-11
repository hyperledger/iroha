import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import * as distSubpath from "../dist/contractPayload.js";
import * as packageSubpath from "@iroha/iroha-js/contract-payload";

test("contract payload proof is exposed by the browser-safe package subpath", () => {
  for (const name of [
    "canonicalContractArguments",
    "canonicalContractPayloadJson",
    "contractPayloadDigestHex",
  ]) {
    assert.equal(typeof distSubpath[name], "function");
    assert.equal(packageSubpath[name], distSubpath[name]);
  }

  const packageJson = JSON.parse(
    fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(packageJson.exports["./contract-payload"], {
    browser: "./dist/contractPayload.js",
    import: "./dist/contractPayload.js",
    types: "./contract-payload.d.ts",
  });
  assert.deepEqual(packageJson.typesVersions["*"]["contract-payload"], [
    "./contract-payload.d.ts",
  ]);
  assert.ok(packageJson.files.includes("contract-payload.d.ts"));

  const declarations = fs.readFileSync(
    new URL("../contract-payload.d.ts", import.meta.url),
    "utf8",
  );
  assert.match(declarations, /canonicalContractPayloadJson/u);
  assert.match(declarations, /contractPayloadDigestHex/u);
  assert.match(declarations, /canonicalContractArguments/u);
  assert.match(declarations, /ContractArgumentSchema/u);
  assert.doesNotMatch(declarations, /reference types=["']node|from ["']node:/u);
});
