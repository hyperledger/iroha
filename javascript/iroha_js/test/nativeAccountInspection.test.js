import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { build } from "esbuild";
import { inspectAccountViaNativeTransport } from "../src/nativeAccountInspection.js";
import { NetworkId } from "../src/networkId.js";

const contract = { responseSchema: "service.account-request-inspection.v1", inspectionSchema: "service.account-inspection.v1" };
const networkId = NetworkId.fromBytes(Uint8Array.from({ length: 32 }, () => 1));
const input = { networkId, requestId: "8a70f738-e08d-4d2c-bb07-f3eec382f441", nonce: "a1".repeat(32),
  accountId: "opaque-account-from-authenticated-service", publicKeyHex: "a2".repeat(32) };
const hash = (text) => createHash("sha256").update(text).digest("hex");
function response({ body, requestId }) {
  const { nonce, accountId, publicKeyHex } = JSON.parse(body);
  return { schema: contract.responseSchema, requestId, nonce, actorAccountId: accountId, actorPublicKeyHex: publicKeyHex,
    requestSha256: hash(body), intentSha256: hash(`${JSON.stringify({ accountId, networkId: networkId.toString(), operation: "account.admit", publicKeyHex })}\n`),
    inspection: { schema: contract.inspectionSchema, networkId: networkId.toString(), accountId, publicKeyHex,
      scope: "canonical-syntax-and-key-binding-only" } };
}
test("authenticates exact native response binding without implementing an account codec", async () => {
  let requests = 0;
  const value = await inspectAccountViaNativeTransport(input, async (request) => {
    requests++; assert.ok(Object.isFrozen(request));
    assert.deepEqual(JSON.parse(request.body), { requestId: input.requestId, nonce: input.nonce, accountId: input.accountId, publicKeyHex: input.publicKeyHex });
    return response(request);
  }, contract);
  assert.equal(requests, 1); assert.equal(value.accountId, input.accountId); assert.ok(Object.isFrozen(value));
});
test("every response binding is checked; unknown fields and getters are refused", async () => {
  for (const field of ["schema", "requestId", "nonce", "actorAccountId", "actorPublicKeyHex", "intentSha256", "requestSha256"]) {
    await assert.rejects(inspectAccountViaNativeTransport(input, async (request) => ({ ...response(request), [field]: "changed" }), contract));
  }
  for (const field of ["schema", "networkId", "accountId", "publicKeyHex", "scope"]) {
    await assert.rejects(inspectAccountViaNativeTransport(input, async (request) => {
      const value = response(request); value.inspection[field] = "changed"; return value;
    }, contract));
  }
  for (const edit of [value => { value.unknown = true; }, value => { value.inspection.unknown = true; },
    value => { delete value.nonce; }, value => { Object.defineProperty(value, "nonce", { get() { throw new Error("getter ran"); } }); }]) {
    await assert.rejects(inspectAccountViaNativeTransport(input, async (request) => { const value = response(request); edit(value); return value; }, contract));
  }
});
test("invalid input rejects before transport; transport errors propagate", async () => {
  for (const replacement of [{ requestId: "00000000-0000-0000-0000-000000000000" }, { requestId: input.requestId.toUpperCase() },
    { nonce: "0".repeat(64) }, { nonce: input.nonce.toUpperCase() }, { publicKeyHex: "a".repeat(63) },
    { accountId: " account " }, { accountId: "a\u0000b" }, { accountId: "a".repeat(2049) }, { networkId: networkId.toString() }]) {
    await assert.rejects(inspectAccountViaNativeTransport({ ...input, ...replacement }, () => { assert.fail("transport called"); }, contract));
  }
  const error = new Error("service unavailable");
  await assert.rejects(inspectAccountViaNativeTransport(input, async () => { throw error; }, contract), value => value === error);
});
test("transport edits, input races and replayed replies cannot substitute request authority", async () => {
  await assert.rejects(inspectAccountViaNativeTransport(input, async ({ body, requestId }) => response({ body: body + " ", requestId }), contract));
  const mutable = { ...input }, mutableContract = { ...contract };
  const result = await inspectAccountViaNativeTransport(mutable, async (request) => {
    mutable.accountId = "changed"; mutable.publicKeyHex = "b2".repeat(32); mutableContract.responseSchema = "changed";
    return response(request);
  }, mutableContract);
  assert.equal(result.accountId, input.accountId);
  const original = response({ body: JSON.stringify({ requestId: input.requestId, nonce: input.nonce, accountId: input.accountId, publicKeyHex: input.publicKeyHex }), requestId: input.requestId });
  await assert.rejects(inspectAccountViaNativeTransport({ ...input, nonce: "b1".repeat(32) }, async () => original, contract));
});
test("browser bundle has no native binding, filesystem, Node crypto or account codec", async () => {
  const result = await build({ entryPoints: ["src/nativeAccountInspection.js"], bundle: true, platform: "browser", format: "esm", write: false, metafile: true });
  const inputs = Object.keys(result.metafile.inputs);
  assert.ok(!inputs.some(path => /(?:native(?:\.browser)?\.js|address\.js|node:)/.test(path)), inputs.join("\n"));
  assert.ok(result.outputFiles[0].text.includes("canonical-syntax-and-key-binding-only"));
});
