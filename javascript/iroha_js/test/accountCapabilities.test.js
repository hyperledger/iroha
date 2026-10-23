import assert from "node:assert/strict";
import test from "node:test";
import { ToriiClient } from "../src/toriiClient.js";
import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";
import { NetworkId } from "../src/networkId.js";
import { normalizeAccountCapabilitiesV1 } from "../src/accountCapabilities.js";

const NETWORK_ID = NetworkId.fromBytes(new Uint8Array(32).fill(0xa5)).literal;
const CAPABILITIES = Object.freeze({
  schema_version: 1,
  network_id: NETWORK_ID,
  network_prefix: 369,
  allowed_signing: ["ed25519", "secp256k1"],
});
const json = (value) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
const CLIENTS = [["Node", ToriiClient], ["browser", ToriiBrowserClient]];

for (const [name, Client] of CLIENTS) {
  test(`${name}: account capabilities are credential-free and preserve exact advertised policy`, async () => {
    let calls = 0;
    const client = new Client("https://torii.example", {
      defaultHeaders: { Authorization: "Bearer parent-secret", Cookie: "parent-session=secret", "X-API-Token": "api-secret" },
      fetchImpl: async (url, init) => {
        calls += 1;
        assert.equal(String(url), "https://torii.example/v1/accounts/capabilities");
        assert.equal(init.method, "GET");
        assert.equal(init.credentials, "omit");
        assert.equal(init.redirect, "error");
        assert.equal(init.body, undefined);
        assert.deepEqual([...new Headers(init.headers).entries()], [["accept", "application/json"]]);
        return json(CAPABILITIES);
      },
    });
    const result = await client.getAccountCapabilities();
    assert.deepEqual(result, CAPABILITIES);
    assert.equal(calls, 1);
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.allowed_signing));
  });

  test(`${name}: account capabilities reject authentication and unexpected option fields before fetch`, async () => {
    let calls = 0;
    const client = new Client("https://torii.example", { fetchImpl: async () => { calls += 1; return json(CAPABILITIES); } });
    for (const input of [{ canonicalAuth: {} }, { accountId: "unregistered" }, { headers: {} }, { networkId: NETWORK_ID }]) {
      await assert.rejects(async () => client.getAccountCapabilities(input), /unsupported/u);
    }
    assert.equal(calls, 0);
  });

  test(`${name}: account capabilities reject retired, missing, and inconsistent wire shapes`, async () => {
    const invalid = [
      null, [], { ...CAPABILITIES, extra: true }, { ...CAPABILITIES, network_id: undefined },
      { ...CAPABILITIES, schema_version: 2 }, { ...CAPABILITIES, schema_version: "1" },
      { ...CAPABILITIES, network_id: "809574f5-fee7-5e69-bfcf-52451e42d50f" },
      { ...CAPABILITIES, network_id: NETWORK_ID.toLowerCase() },
      { ...CAPABILITIES, network_id: ` ${NETWORK_ID}` }, { ...CAPABILITIES, network_id: {} },
      { ...CAPABILITIES, network_prefix: "369" }, { ...CAPABILITIES, network_prefix: -1 },
      { ...CAPABILITIES, network_prefix: 65536 }, { ...CAPABILITIES, network_prefix: 0.5 },
      { ...CAPABILITIES, allowed_signing: [] }, { ...CAPABILITIES, allowed_signing: ["secp256k1", "ed25519"] },
      { ...CAPABILITIES, allowed_signing: ["ed25519", "ed25519"] },
      { ...CAPABILITIES, allowed_signing: ["ed25519", "Ed25519"] },
      { ...CAPABILITIES, allowed_signing: ["ed25519", "future-algorithm"] },
      { ...CAPABILITIES, default_signing: "secp256k1" },
      { ...CAPABILITIES, default_hash: "blake2b-256", default_signing: undefined },
    ];
    for (const value of invalid) {
      const client = new Client("https://torii.example", { fetchImpl: async () => json(value) });
      await assert.rejects(client.getAccountCapabilities(), undefined, JSON.stringify(value));
    }
  });

  test(`${name}: account capabilities reject duplicate JSON keys and invalid UTF-8`, async () => {
    for (const body of [
      JSON.stringify(CAPABILITIES).replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
      new Uint8Array([0xc0, 0xaf]),
    ]) {
      const client = new Client("https://torii.example", {
        fetchImpl: async () => new Response(body, { headers: { "content-type": "application/json" } }),
      });
      await assert.rejects(client.getAccountCapabilities());
    }
  });

  test(`${name}: account capabilities reject redirects and HTTP errors without reading their bodies`, async () => {
    for (const redirected of [false, true]) {
      let cancelled = false;
      let reads = 0;
      const response = {
        status: redirected ? 200 : 302,
        redirected,
        headers: new Headers({ "content-type": "application/json" }),
        body: { cancel() { cancelled = true; }, getReader() { reads += 1; throw new Error("must not read"); } },
      };
      const client = new Client("https://torii.example", { fetchImpl: async () => response });
      await assert.rejects(client.getAccountCapabilities(), /redirect|HTTP 200/u);
      assert.equal(cancelled, true);
      assert.equal(reads, 0);
    }
  });

  test(`${name}: account capabilities cancel an oversized or wrongly typed response before decoding`, async () => {
    for (const headers of [
      { "content-type": "application/json", "content-length": "4097" },
      { "content-type": "application/json", "content-length": "0003" },
      { "content-type": "text/html" },
    ]) {
      let cancelled = false;
      const stream = new ReadableStream({ cancel() { cancelled = true; } });
      const client = new Client("https://torii.example", {
        fetchImpl: async () => new Response(stream, { headers }),
      });
      await assert.rejects(client.getAccountCapabilities());
      assert.equal(cancelled, true);
    }
  });

  test(`${name}: account capabilities enforce the streaming limit without Content-Length`, async () => {
    let cancelled = false;
    const stream = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(4097)); },
      cancel() { cancelled = true; },
    });
    const client = new Client("https://torii.example", {
      fetchImpl: async () => new Response(stream, { headers: { "content-type": "application/json" } }),
    });
    await assert.rejects(client.getAccountCapabilities(), /4096-byte limit/u);
    assert.equal(cancelled, true);
  });

  test(`${name}: account capabilities abort a stalled body read`, { timeout: 1500 }, async () => {
    let cancelled = false;
    let beginFetch;
    const fetched = new Promise((resolve) => { beginFetch = resolve; });
    const controller = new AbortController();
    const reason = new Error("caller changed endpoint");
    const client = new Client("https://torii.example", {
      fetchImpl: async () => {
        beginFetch();
        return new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
          headers: { "content-type": "application/json" },
        });
      },
    });
    const pending = client.getAccountCapabilities({ signal: controller.signal });
    await fetched;
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort(reason);
    await assert.rejects(pending, (error) => error === reason);
    assert.equal(cancelled, true);
  });
}

test("account capability network prefixes include both valid u16 edges", () => {
  for (const network_prefix of [0, 65535]) {
    assert.equal(normalizeAccountCapabilitiesV1({ ...CAPABILITIES, network_prefix }).network_prefix, network_prefix);
  }
});

test("browser account capability timeout covers stalled response bodies", { timeout: 1500 }, async () => {
  let cancelled = false;
  const client = new ToriiBrowserClient("https://torii.example", {
    timeoutMs: 10,
    fetchImpl: async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
      headers: { "content-type": "application/json" },
    }),
  });
  await assert.rejects(client.getAccountCapabilities(), /timed out/u);
  assert.equal(cancelled, true);
});

test("account capabilities preserve canonical tag order without an implicit signer", () => {
  for (const allowed_signing of [["secp256k1"], ["bls_normal", "bls_small", "ml-dsa"]]) {
    assert.deepEqual(normalizeAccountCapabilitiesV1({ ...CAPABILITIES, allowed_signing }).allowed_signing, allowed_signing);
  }
  assert.throws(() => normalizeAccountCapabilitiesV1({ ...CAPABILITIES, allowed_signing: ["ml-dsa", "bls_normal"] }));
});
