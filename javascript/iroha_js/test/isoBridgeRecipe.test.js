/** Recipe configuration retains business terms and uses existing operator authentication. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  nativeIntentFromEnvironment,
  parseConfiguredNativeIntent,
  createIsoOperatorClient,
} from "../recipes/iso_bridge_context.mjs";

const NETWORK_LITERAL = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0";
const ENVIRONMENT = Object.freeze({
  ISO_UETR: "123e4567-e89b-42d3-a456-426614174000",
  ISO_NETWORK_ID: NETWORK_LITERAL,
  ISO_EXPIRES_AT_HEIGHT: "18446744073709551615",
  ISO_SOURCE_ACCOUNT_ID: "payer-selected-source",
  ISO_TARGET_ACCOUNT_ID: "payer-selected-target",
  ISO_ASSET_DEFINITION_ID: "payer-selected-asset",
});

test("ISO recipe retains exact configured intent without synthesizing missing values", () => {
  const raw = nativeIntentFromEnvironment(ENVIRONMENT);
  assert.equal(raw.uetr, ENVIRONMENT.ISO_UETR);
  assert.deepEqual(raw.nexusSettlement, {
    networkId: NETWORK_LITERAL,
    expiresAtHeight: ENVIRONMENT.ISO_EXPIRES_AT_HEIGHT,
    sourceAccountId: ENVIRONMENT.ISO_SOURCE_ACCOUNT_ID,
    targetAccountId: ENVIRONMENT.ISO_TARGET_ACCOUNT_ID,
    assetDefinitionId: ENVIRONMENT.ISO_ASSET_DEFINITION_ID,
  });
  const missing = nativeIntentFromEnvironment({});
  assert.equal(missing.uetr, undefined);
  assert.ok(Object.values(missing.nexusSettlement).every((value) => value === undefined));
  const configured = parseConfiguredNativeIntent({ ...raw, supplementaryData: { memo: "retained" } });
  assert.equal(configured.nexusSettlement.networkId.toString(), NETWORK_LITERAL);
  assert.equal(configured.nexusSettlement.expiresAtHeight, ENVIRONMENT.ISO_EXPIRES_AT_HEIGHT);
  assert.deepEqual(configured.supplementaryData, { memo: "retained" });
});

test("ISO recipe requires the exact selected-network literal", () => {
  for (const networkId of [undefined, "testnet", " " + NETWORK_LITERAL, NETWORK_LITERAL.toLowerCase()]) {
    assert.throws(() => parseConfiguredNativeIntent({ nexusSettlement: { networkId } }), TypeError);
  }
});

test("ISO recipe binds the runtime operator signer to the selected network", async () => {
  const { nexusSettlement: { networkId } } = parseConfiguredNativeIntent(nativeIntentFromEnvironment(ENVIRONMENT));
  await assert.rejects(() => createIsoOperatorClient("https://localhost:8080", networkId, {}), /ISO_OPERATOR_SIGNER_MODULE/u);
  const directory = await mkdtemp(join(tmpdir(), "iroha-iso-signer-test-"));
  try {
    const modulePath = join(directory, "signer.mjs");
    // This fixture has no key and never submits a request.
    await writeFile(modulePath, 'export default { publicKey: "ed0120' + '11'.repeat(32) + '", sign: async () => new Uint8Array(64) };\n');
    const client = await createIsoOperatorClient("https://localhost:8080", networkId, { ISO_OPERATOR_SIGNER_MODULE: modulePath });
    assert.equal(client._operatorSigningContext.networkId, networkId);
    assert.equal(client._operatorSigningContext.publicKey, "ed0120" + "11".repeat(32));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
