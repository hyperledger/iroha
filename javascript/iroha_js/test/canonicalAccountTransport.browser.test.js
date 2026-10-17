import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { build } from "esbuild";
import { ed25519 } from "@noble/curves/ed25519";
import { AccountAddress } from "../src/address.js";

const PRIVATE_KEY = Buffer.alloc(32, 7);
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY);
const ADDRESS = AccountAddress.fromAccount({ publicKey: PUBLIC_KEY });
const ACCOUNT_ID = ADDRESS.toI105(369);
const VECTORS = JSON.parse(readFileSync(new URL("../../../fixtures/account/address_vectors.json", import.meta.url), "utf8"));
const bundle = await build({
  stdin: {
    contents: [
      'export { ToriiBrowserClient } from "@iroha/iroha-js/torii-browser";',
      'export { AccountAddress } from "@iroha/iroha-js/address";',
      'export { NetworkId, canonicalRequestSignatureMessage } from "@iroha/iroha-js/canonical-request";',
      'export { createConnectCanonicalRequestAuth } from "@iroha/iroha-js/connect-browser";',
    ].join("\n"),
    resolveDir: fileURLToPath(new URL("..", import.meta.url)),
  }, platform: "browser", format: "esm", bundle: true, write: false, metafile: true,
});
const browser = await import(`data:text/javascript;base64,${Buffer.from(`${bundle.outputFiles[0].text}\n//# sourceURL=iroha-browser-native-inspection-test.mjs`).toString("base64")}`);
const NETWORK = browser.NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const BASE = "https://localhost:8080/proxy";
function inspection(body, address = ADDRESS) {
  return { ...JSON.parse(body), canonical_hex: address.canonicalHex().toLowerCase(),
    controller: { kind: "single", algorithm: "ed25519", public_key_hex: Buffer.from(PUBLIC_KEY).toString("hex") } };
}
async function inspect(fetchImpl = async (_url, init) => new Response(JSON.stringify(inspection(init.body)), {
  headers: { "content-type": "application/json" },
})) {
  return new browser.ToriiBrowserClient(BASE, { networkId: NETWORK, fetchImpl }).inspectAccountIdentity(ACCOUNT_ID);
}

test("browser keeps native admission mandatory and authenticates reads with exact native-inspected identity", async () => {
  assert.ok(Object.keys(bundle.metafile.inputs).some((path) => /native\.browser\.js$/u.test(path)));
  assert.throws(() => browser.AccountAddress.fromI105(ACCOUNT_ID), {
    code: "ERR_IROHA_NATIVE_BINDING", nativeStatus: "browser_unavailable",
  });
  const nativeIdentity = await inspect();
  const approved = { accountId: ACCOUNT_ID, nativeIdentity };
  const signed = [];
  const connected = await browser.createConnectCanonicalRequestAuth({
    async waitForApproval() { return approved; },
    async signRaw(domain, message) {
      signed.push({ domain, message: Buffer.from(message) });
      return ed25519.sign(message, PRIVATE_KEY);
    },
  });
  approved.accountId = "other@example.public";
  assert.equal(connected.authAccountId, ACCOUNT_ID);
  assert.equal(connected.nativeIdentity, nativeIdentity);
  const captured = [];
  const client = new browser.ToriiBrowserClient(BASE, {
    networkId: NETWORK,
    canonicalRequestAuth: { accountId: connected.authAccountId, sign: connected.sign, nativeIdentity },
    fetchImpl: async (url, init) => {
      captured.push({ url, init });
      return new Response(String(url).endsWith("/query") ? '{"items":[],"next_cursor":null}' : "{}", { headers: { "content-type": "application/json" } });
    },
  });
  await client.getExplorerTransaction("transaction");
  await client.getExplorerTransaction("transaction");
  await client.transactions.list({ limit: 1 });
  await client.getMultisigSpec({ multisigAccountAlias: "council@example.public" }, {
    authAccountId: connected.authAccountId, sign: connected.sign, nativeIdentity,
  });
  for (const [index, { url, init }] of captured.entries()) {
    assert.equal(init.headers["X-Iroha-Account"], ADDRESS.canonicalHex().toLowerCase());
    const target = new URL(url);
    const message = browser.canonicalRequestSignatureMessage({
      networkId: NETWORK, method: init.method, path: target.pathname, query: target.search.slice(1), body: init.body ?? "",
      timestampMs: Number(init.headers["X-Iroha-Timestamp-Ms"]), nonce: init.headers["X-Iroha-Nonce"],
    });
    assert.deepEqual(signed[index].message, Buffer.from(message));
    assert.equal(ed25519.verify(Buffer.from(init.headers["X-Iroha-Signature"], "base64"), message, PUBLIC_KEY), true);
    assert.equal(init.redirect, "error");
  }
  assert.equal(captured.length, 4);
  assert.notEqual(captured[0].init.headers["X-Iroha-Nonce"], captured[1].init.headers["X-Iroha-Nonce"]);
});

test("browser identity inspection is unsigned, bounded, and fails closed on native refusal", async () => {
  const client = new browser.ToriiBrowserClient(BASE, {
    networkId: NETWORK, defaultHeaders: { Authorization: "secret" },
    canonicalRequestAuth: { accountId: "reader@example.public", sign() { assert.fail("inspection must not sign"); } },
    fetchImpl: async (url, init) => {
      assert.equal(String(url), `${BASE}/v1/accounts/inspect`);
      assert.equal(init.headers.Authorization, undefined);
      assert.equal(init.headers["X-Iroha-Account"], undefined);
      assert.equal(init.credentials, "omit");
      assert.equal(init.redirect, "error");
      assert.equal(init.cache, "no-store");
      return new Response("invalid identity", { status: 400 });
    },
  });
  await assert.rejects(client.inspectAccountIdentity(ACCOUNT_ID), error => error.status === 400);
  let canceled = false;
  await assert.rejects(inspect(async () => new Response(new ReadableStream({ cancel() { canceled = true; } }), {
    headers: { "content-type": "application/json", "content-length": String(8193) },
  })), /limit|exceed/u);
  assert.equal(canceled, true);
});

test("browser native inspection rejects changed bindings, malformed headers/controllers and unknown fields", async () => {
  for (const change of [
    value => { value.network_id = "wrong"; }, value => { value.account_id = "other"; },
    value => { value.request_id = "wrong"; }, value => { value.nonce = "b1".repeat(32); },
    value => { value.canonical_hex = "0xA1"; }, value => { value.canonical_hex = "0x01\r\nX-Injected: x"; },
    value => { value.controller.public_key_hex = "00".repeat(32); }, value => { value.controller.algorithm = "unknown"; },
    value => { value.controller.extra = true; }, value => { value.extra = true; },
  ]) {
    await assert.rejects(inspect(async (_url, init) => {
      const value = inspection(init.body); change(value);
      return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
    }));
  }
  await assert.rejects(inspect(async (_url, init) => new Response(JSON.stringify(inspection(init.body)).replace('"version":1', '"version":1,"version":1'), {
    headers: { "content-type": "application/json" },
  })), /duplicate/u);
});

test("native inspection bounds declared and streamed error bodies", async () => {
  for (const declaredLength of [true, false]) {
    let canceled = false;
    await assert.rejects(inspect(async () => {
      const response = new Response(new ReadableStream({
        pull(controller) {
          if (!declaredLength) controller.enqueue(new Uint8Array(8193));
        },
        cancel() { canceled = true; },
      }), { status: 503, headers: declaredLength ? { "content-length": "8193" } : {} });
      response.text = () => assert.fail("inspection errors must use the bounded reader");
      response.json = () => assert.fail("inspection errors must use the bounded reader");
      return response;
    }), /8192-byte response limit/u);
    assert.equal(canceled, true);
  }
});

test("native inspection abort cancels a stalled error body", async () => {
  const abort = new AbortController();
  const expected = new Error("inspection error body aborted");
  let canceled = false;
  const client = new browser.ToriiBrowserClient(BASE, {
    networkId: NETWORK,
    fetchImpl: async () => new Response(new ReadableStream({
      pull() { abort.abort(expected); },
      cancel() { canceled = true; },
    }), { status: 503 }),
  });
  await assert.rejects(client.inspectAccountIdentity(ACCOUNT_ID, { signal: abort.signal }), error => error === expected);
  assert.equal(canceled, true);
});

test("browser rejects forged or cross-context identity before signing and preserves approved-key binding", async () => {
  const nativeIdentity = await inspect();
  let signs = 0;
  for (const [baseUrl, networkId, accountId, identity] of [
    [BASE, NETWORK, ACCOUNT_ID, { ...nativeIdentity }],
    ["https://other.example", NETWORK, ACCOUNT_ID, nativeIdentity],
    [BASE, browser.NetworkId.fromBytes(Buffer.alloc(32, 0x33)), ACCOUNT_ID, nativeIdentity],
    [BASE, NETWORK, "other@example.public", nativeIdentity],
  ]) {
    assert.throws(() => new browser.ToriiBrowserClient(baseUrl, {
      networkId, canonicalRequestAuth: { accountId, nativeIdentity: identity, sign() { signs++; } },
    }), /exact account, network and Torii URL/u);
  }
  assert.equal(signs, 0);
  const connected = await browser.createConnectCanonicalRequestAuth({
    async waitForApproval() { return { accountId: ACCOUNT_ID, nativeIdentity }; },
    async signRaw(_domain, message) { return ed25519.sign(message, Buffer.alloc(32, 8)); },
  });
  await assert.rejects(connected.sign({ message: Uint8Array.of(1, 2, 3) }), /signature/iu);
  const multisig = VECTORS.cases.positive.find((row) => row.category === "multisig");
  const multiIdentity = await new browser.ToriiBrowserClient(BASE, {
    networkId: NETWORK, fetchImpl: async (_url, init) => new Response(JSON.stringify({
      ...JSON.parse(init.body), canonical_hex: multisig.encodings.canonical_hex.toLowerCase(), controller: { kind: "multisig" },
    }), { headers: { "content-type": "application/json" } }),
  }).inspectAccountIdentity(multisig.encodings.i105.string);
  await assert.rejects(browser.createConnectCanonicalRequestAuth({
    async waitForApproval() { return { accountId: multiIdentity.accountId, nativeIdentity: multiIdentity }; },
    async signRaw() { assert.fail("multisig must not reach the single-key signer"); },
  }), /single-key Ed25519/u);
});

test("native inspection rejects redirects, wrong media type, replay and canceled reads", async () => {
  await assert.rejects(inspect(async () => new Response("", { status: 302, headers: { Location: "https://other.example" } })), error => error.status === 302);
  let canceled = false;
  await assert.rejects(inspect(async () => new Response(new ReadableStream({ cancel() { canceled = true; } }), {
    headers: { "content-type": "text/html" },
  })), /application\/json/u);
  assert.equal(canceled, true);
  let prior;
  await inspect(async (_url, init) => {
    prior = inspection(init.body);
    return new Response(JSON.stringify(prior), { headers: { "content-type": "application/json" } });
  });
  await assert.rejects(inspect(async () => new Response(JSON.stringify(prior), {
    headers: { "content-type": "application/json" },
  })), /request binding/u);
  const abort = new AbortController();
  const expected = new Error("inspection aborted");
  const client = new browser.ToriiBrowserClient(BASE, {
    networkId: NETWORK,
    fetchImpl: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      abort.abort(expected);
    }),
  });
  await assert.rejects(client.inspectAccountIdentity(ACCOUNT_ID, { signal: abort.signal }), error => error === expected);
});
