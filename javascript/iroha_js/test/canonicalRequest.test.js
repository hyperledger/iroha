"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import {
  CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
  CANONICAL_REQUEST_MAX_METHOD_BYTES_V1,
  CANONICAL_REQUEST_MAX_PATH_BYTES_V1,
  CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1,
  CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1,
  CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
  canonicalQueryString,
  canonicalRequestMessage,
  canonicalRequestSignatureMessage,
  buildCanonicalRequestHeaders,
  buildCanonicalJsonRequest,
  signEd25519,
  verifyEd25519,
  NetworkId,
} from "../src/index.js";
import { AccountAddress } from "../src/address.js";

const TEST_NETWORK_ID = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const SHARED_I105_ACCOUNT =
  "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const SHARED_CANONICAL_ACCOUNT_HEX =
  "0x02000120ce7fa46c9dce7ea4b125e2e36bdb63ea33073e7590ac92816ae1e861b7048b03";

function deterministicKeyPair(seedByte) {
  const privateKey = Buffer.alloc(32, seedByte);
  return {
    privateKey,
    publicKey: Buffer.from(ed25519.getPublicKey(privateKey)),
  };
}

test("canonical request signing: canonical query sorts pairs", () => {
  const rendered = canonicalQueryString("b=2&a=3&b=1&space=a+b");
  assert.equal(rendered, "a=3&b=1&b=2&space=a+b");
});

test("canonical request signing: canonical query uses form encoding", () => {
  const rendered = canonicalQueryString("b=!*()~'&a=1");
  assert.equal(rendered, "a=1&b=%21*%28%29%7E%27");
  assert.equal(canonicalQueryString("x=%41%zz%FF"), "x=A%25zz%EF%BF%BD");
  assert.equal(
    canonicalQueryString("\u{10000}=supplementary&\uE000=bmp"),
    "%EE%80%80=bmp&%F0%90%80%80=supplementary",
  );
  assert.equal(
    canonicalQueryString("k=\u{10000}&k=\uE000"),
    "k=%EE%80%80&k=%F0%90%80%80",
  );
});

test("canonical request signing: canonical query enforces V1 pair and byte limits", () => {
  const exactPairs = Array.from(
    { length: CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1 },
    (_value, index) => `k${index}=v`,
  ).join("&");
  assert.doesNotThrow(() => canonicalQueryString(exactPairs));
  assert.throws(
    () => canonicalQueryString(`${exactPairs}&overflow=v`),
    /exceeds 64 pairs/u,
  );

  const exactBytes = `k=${"x".repeat(CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1 - 2)}`;
  assert.equal(Buffer.byteLength(exactBytes, "utf8"), 65_536);
  assert.doesNotThrow(() => canonicalQueryString(exactBytes));
  assert.throws(
    () => canonicalQueryString(`${exactBytes}x`),
    /exceeds 65536 raw UTF-8 bytes/u,
  );

  assert.equal(canonicalQueryString("&&b=2&&a=1&"), "a=1&b=2");
});

test("canonical request signing: enforces V1 account and nonce syntax", () => {
  const { privateKey } = deterministicKeyPair(12);
  const common = {
    networkId: TEST_NETWORK_ID,
    method: "get",
    path: "/v1/accounts",
    privateKey,
    timestampMs: 1_717_171_717_005,
  };
  for (const accountId of [
    "alice@universal",
    "alice_1@bank_a.paynet",
    "alice@xn--fa-hia",
    "alice@xn--ab-0ea",
    "alice@xn--alice",
    "alice@xn--a",
    "alice@xn--ab-uuba211bca8057b",
    "alice@xn--ab-j1t",
    "alice@xn--11b2er09f",
    "alice@xn--4u8c",
    "alice@xn--pq1d",
    "alice@xn--kx7e",
    "alice@xn--5h0f",
    "alice@xn--zo5h",
    "alice@xn--fi3d",
    "alice@xn--d4f",
    SHARED_I105_ACCOUNT,
  ]) {
    assert.doesNotThrow(() =>
      buildCanonicalRequestHeaders({ ...common, accountId, nonce: "valid-account" }),
    );
  }
  for (const accountId of [
    "alice",
    "alice.name@universal",
    "alice@a.b.c",
    "0xwallet@universal",
    "alice@ab--invalid",
    "alice@xn--",
    `${"a".repeat(64)}@universal`,
  ]) {
    assert.throws(
      () => buildCanonicalRequestHeaders({ ...common, accountId, nonce: "bad-account" }),
      /exact canonical I105 account or ASCII account alias/u,
    );
  }
  const oversizedAccount = `${"a".repeat(
    CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1 - 1,
  )}@a`;
  assert.throws(
    () =>
      buildCanonicalRequestHeaders({
        ...common,
        accountId: `a${oversizedAccount}`,
        nonce: "account-limit-plus-one",
      }),
    /exceeds 36864 UTF-8 bytes/u,
  );

  const exactNonce = "n".repeat(256);
  assert.doesNotThrow(() =>
    canonicalRequestSignatureMessage({
      ...common,
      accountId: undefined,
      privateKey: undefined,
      nonce: exactNonce,
    }),
  );
  for (const invalidNonce of [`${exactNonce}n`, "internal space", "control\u0001", "nönce"]) {
    assert.throws(
      () =>
        canonicalRequestSignatureMessage({
          ...common,
          accountId: undefined,
          privateKey: undefined,
          nonce: invalidNonce,
        }),
      /nonce must contain 1\.\.\.256 non-whitespace ASCII bytes/u,
    );
  }
});

test("canonical request signing: enforces the V1 method limit", () => {
  const common = { path: "/v1/test", body: Buffer.alloc(0) };
  assert.doesNotThrow(() =>
    canonicalRequestMessage({
      ...common,
      method: "A".repeat(CANONICAL_REQUEST_MAX_METHOD_BYTES_V1),
    }),
  );
  assert.throws(
    () =>
      canonicalRequestMessage({
        ...common,
        method: "A".repeat(CANONICAL_REQUEST_MAX_METHOD_BYTES_V1 + 1),
      }),
    /method exceeds 32 UTF-8 bytes/u,
  );
  for (const method of ["", "GET POST", "GÉT", "GET\n"]) {
    assert.throws(
      () => canonicalRequestMessage({ ...common, method }),
      /non-empty ASCII HTTP token/u,
    );
  }
});

test("canonical request signing: enforces the V1 path limit", () => {
  const common = { method: "GET", body: Buffer.alloc(0) };
  assert.doesNotThrow(() =>
    canonicalRequestMessage({
      ...common,
      path: `/${"x".repeat(CANONICAL_REQUEST_MAX_PATH_BYTES_V1 - 1)}`,
    }),
  );
  assert.throws(
    () =>
      canonicalRequestMessage({
        ...common,
        path: `/${"x".repeat(CANONICAL_REQUEST_MAX_PATH_BYTES_V1)}`,
      }),
    /path exceeds 65536 UTF-8 bytes/u,
  );
  for (const path of [
    "",
    "relative",
    "//evil/x",
    "///evil/x",
    "?x=1",
    "/raw space",
    "/raw\\slash",
    "/café",
    "/x?y",
    "/x#y",
    "/x%GG",
    "/v1/../admin",
    "/v1/%2e%2E/admin",
  ]) {
    assert.throws(
      () => canonicalRequestMessage({ ...common, path }),
      /exact root-relative ASCII path/u,
    );
  }
});

test("canonical request signing: rejects path spellings WHATWG URL would rewrite", () => {
  for (const [path, rewritten] of [
    ["/v1/../admin", "/admin"],
    ["/v1/%2e%2E/admin", "/admin"],
  ]) {
    assert.equal(new URL(path, "https://node.test").pathname, rewritten);
    assert.throws(
      () => canonicalRequestMessage({ method: "GET", path }),
      /exact root-relative ASCII path/u,
    );
  }
});

test("canonical request signing: requires a canonical u64-compatible timestamp", () => {
  const common = {
    networkId: TEST_NETWORK_ID,
    method: "GET",
    path: "/v1/test",
    nonce: "timestamp-limit",
  };
  assert.doesNotThrow(() =>
    canonicalRequestSignatureMessage({ ...common, timestampMs: 0 }),
  );
  for (const timestampMs of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => canonicalRequestSignatureMessage({ ...common, timestampMs }),
      /timestampMs must be a non-negative safe integer/u,
    );
  }
});

test("canonical JSON requests do not normalize non-canonical timestamps", async () => {
  await assert.rejects(
    buildCanonicalJsonRequest({
      accountId: "alice-1@wonderland",
      networkId: TEST_NETWORK_ID,
      method: "POST",
      path: "/v1/test",
      body: {},
      privateKey: Buffer.alloc(32, 7),
      timestampMs: 1.5,
      nonce: "fractional-timestamp",
    }),
    /timestampMs must be a non-negative safe integer/u,
  );
});

test("canonical JSON requests enforce the prepared wire-query byte cap", async () => {
  const rawQuery = `x=${"é".repeat(32_767)}`;
  assert.equal(Buffer.byteLength(rawQuery, "utf8"), 65_536);
  assert.doesNotThrow(() => canonicalQueryString(rawQuery));

  await assert.rejects(
    buildCanonicalJsonRequest({
      accountId: "alice@universal",
      networkId: TEST_NETWORK_ID,
      method: "GET",
      path: "/v1/test",
      query: rawQuery,
      body: {},
      privateKey: Buffer.alloc(32, 7),
      timestampMs: 1,
      nonce: "prepared-query-cap",
    }),
    /exceeds 65536 raw UTF-8 bytes/u,
  );
});

test("canonical JSON requests reject absolute paths before WHATWG normalization", async () => {
  for (const path of [
    "https://node.test/v1/../admin",
    "https://node.test/v1/%2e%2e/admin",
    "https://node.test/v1/a b",
  ]) {
    await assert.rejects(
      buildCanonicalJsonRequest({
        accountId: "alice@universal",
        networkId: TEST_NETWORK_ID,
        method: "GET",
        path,
        baseUrl: "https://node.test",
        body: {},
        privateKey: Buffer.alloc(32, 7),
        timestampMs: 1,
        nonce: "absolute-path-rejected",
      }),
      /path must be root-relative/u,
      path,
    );
  }
});

test("canonical header builders enforce the prepared wire-query byte cap", () => {
  const rawQuery = `x=${"é".repeat(32_767)}`;
  assert.equal(Buffer.byteLength(rawQuery, "utf8"), 65_536);
  assert.doesNotThrow(() => canonicalQueryString(rawQuery));

  assert.throws(
    () =>
      buildCanonicalRequestHeaders({
        accountId: "alice@universal",
        networkId: TEST_NETWORK_ID,
        method: "GET",
        path: "/v1/test",
        query: rawQuery,
        privateKey: Buffer.alloc(32, 7),
        timestampMs: 1,
        nonce: "prepared-header-query-cap",
      }),
    /exceeds 65536 raw UTF-8 bytes/u,
  );
});

test("canonical request signing: headers include a verifiable signature", () => {
  const { privateKey, publicKey } = deterministicKeyPair(7);
  const accountAddress = AccountAddress.fromAccount({ publicKey });
  const accountId = accountAddress.toI105();
  const accountAlias = "alice-1@wonderland";
  const body = Buffer.from('{"foo":1}');
  const path = `/v1/accounts/${encodeURIComponent(accountId)}/assets`;
  const timestampMs = 1_717_171_717_000;
  const nonce = "deterministic-nonce";
  const message = canonicalRequestSignatureMessage({
    networkId: TEST_NETWORK_ID,
    method: "get",
    path,
    query: "limit=10",
    body,
    timestampMs,
    nonce,
  });
  const headers = buildCanonicalRequestHeaders({
    accountId: accountAlias,
    networkId: TEST_NETWORK_ID,
    method: "get",
    path,
    query: "limit=10",
    body,
    privateKey,
    timestampMs,
    nonce,
  });
  const signature = Buffer.from(headers["X-Iroha-Signature"], "base64");
  assert.equal(headers["X-Iroha-Account"], accountAlias);
  assert.equal(headers["X-Iroha-Timestamp-Ms"], String(timestampMs));
  assert.equal(headers["X-Iroha-Nonce"], nonce);
  assert.equal(verifyEd25519(message, signature, publicKey), true);

  const i105Headers = buildCanonicalRequestHeaders({
    accountId,
    networkId: TEST_NETWORK_ID,
    method: "get",
    path,
    query: "limit=10",
    body,
    privateKey,
    timestampMs,
    nonce: `${nonce}-i105`,
  });
  assert.equal(i105Headers["X-Iroha-Account"], accountAddress.canonicalHex());
  assert.match(i105Headers["X-Iroha-Account"], /^0x[0-9a-f]+$/u);
});

test("canonical request signing: JSON helper renders I105 header identity as canonical hex", async () => {
  const { privateKey } = deterministicKeyPair(13);
  const request = await buildCanonicalJsonRequest({
    accountId: SHARED_I105_ACCOUNT,
    networkId: TEST_NETWORK_ID,
    method: "post",
    path: "/v1/test",
    body: {},
    privateKey,
    timestampMs: 1_717_171_717_006,
    nonce: "i105-header-hex",
  });

  assert.equal(request.headers["X-Iroha-Account"], SHARED_CANONICAL_ACCOUNT_HEX);
  assert.match(request.headers["X-Iroha-Account"], /^0x[0-9a-f]+$/u);
});

test("canonical request signing: exact NetworkId separates same-label deployments", () => {
  const networkId = NetworkId.fromBytes(Uint8Array.from({ length: 32 }, (_value, index) =>
    index === 31 ? 1 : 0,
  ));
  const foreignNetworkId = NetworkId.fromBytes(
    Uint8Array.from({ length: 32 }, (_value, index) => (index === 31 ? 3 : 0)),
  );
  const input = {
    method: "POST",
    path: "/v1/gov/ballots/plain",
    body: Buffer.from('{"network_id":"fixture"}'),
    timestampMs: 1_717_171_717_004,
    nonce: "exact-network-nonce",
  };
  const message = canonicalRequestSignatureMessage({ networkId, ...input });
  const foreignMessage = canonicalRequestSignatureMessage({
    networkId: foreignNetworkId,
    ...input,
  });
  assert.notDeepEqual(message, foreignMessage);
  assert.deepEqual(
    message.subarray(0, "iroha.app.request.network.v1\0".length),
    Buffer.from("iroha.app.request.network.v1\0", "utf8"),
  );
});

test("canonical request signing: rejects padded auth fields", async () => {
  const { privateKey, publicKey } = deterministicKeyPair(11);
  const accountId = AccountAddress.fromAccount({ publicKey }).toI105();
  const accountAlias = "alice-1@wonderland";
  const timestampMs = 1_717_171_717_003;

  assert.throws(
    () =>
      canonicalRequestSignatureMessage({
        networkId: TEST_NETWORK_ID,
        method: "get",
        path: "/v1/accounts",
        timestampMs,
        nonce: " nonce",
      }),
    /surrounding whitespace/,
  );
  assert.throws(
    () =>
      buildCanonicalRequestHeaders({
        accountId: ` ${accountAlias}`,
        networkId: TEST_NETWORK_ID,
        method: "get",
        path: "/v1/accounts",
        privateKey,
        timestampMs,
        nonce: "nonce",
      }),
    /exact canonical I105 account or ASCII account alias/,
  );
  assert.throws(
    () =>
      buildCanonicalRequestHeaders({
        accountId: accountAlias,
        networkId: TEST_NETWORK_ID,
        method: "get",
        path: "/v1/accounts",
        privateKey,
        timestampMs,
        nonce: "nonce\n",
      }),
    /surrounding whitespace/,
  );
  await assert.rejects(
    () =>
      buildCanonicalJsonRequest({
        accountId: `${accountAlias} `,
        networkId: TEST_NETWORK_ID,
        path: "/v1/accounts",
        body: {},
        privateKey,
        timestampMs,
        nonce: "nonce",
      }),
    /exact canonical I105 account or ASCII account alias/,
  );
  await assert.rejects(
    () =>
      buildCanonicalJsonRequest({
        accountId: accountAlias,
        networkId: TEST_NETWORK_ID,
        path: "/v1/accounts",
        body: {},
        privateKey,
        timestampMs,
        nonce: "\tnonce",
      }),
    /surrounding whitespace/,
  );

  for (const invalidAccountId of [
    "Alice-1@wonderland",
    "alice-1@Wonderland",
    "alíce-1@wonderland",
    "alice-1%40wonderland",
    Buffer.from(accountAlias, "utf8").toString("base64"),
  ]) {
    assert.throws(
      () =>
        buildCanonicalRequestHeaders({
          accountId: invalidAccountId,
          networkId: TEST_NETWORK_ID,
          method: "get",
          path: "/v1/accounts",
          privateKey,
          timestampMs,
          nonce: "nonce",
        }),
      /exact canonical I105 account or ASCII account alias/,
      invalidAccountId,
    );
    await assert.rejects(
      () =>
        buildCanonicalJsonRequest({
          accountId: invalidAccountId,
          networkId: TEST_NETWORK_ID,
          path: "/v1/accounts",
          body: {},
          privateKey,
          timestampMs,
          nonce: "nonce",
        }),
      /exact canonical I105 account or ASCII account alias/,
      invalidAccountId,
    );
  }
});

test("canonical request signing: JSON helper signs the exact request body with callback signers", async () => {
  const { privateKey, publicKey } = deterministicKeyPair(8);
  const accountId = "operator-1@mibank.paynet";
  const path = "/v1/aliases/resolve?b=2&a=1";
  const timestampMs = 1_717_171_717_001;
  const nonce = "browser-keystore-nonce";
  let signerInput = null;

  const request = await buildCanonicalJsonRequest({
    accountId,
    networkId: TEST_NETWORK_ID,
    method: "post",
    path,
    body: { alias: "tidal-river-4160@mibank.paynet" },
    headers: { "X-Request-Id": "req_1" },
    timestampMs,
    nonce,
    sign: async (input) => {
      signerInput = input;
      return signEd25519(input.message, privateKey).toString("base64");
    },
  });

  assert.equal(request.method, "POST");
  assert.equal(request.body, '{"alias":"tidal-river-4160@mibank.paynet"}');
  assert.equal(request.headers["Content-Type"], "application/json");
  assert.equal(request.headers.Accept, "application/json");
  assert.equal(request.headers["X-Request-Id"], "req_1");
  assert.equal(request.headers["X-Iroha-Account"], accountId);
  assert.equal(request.headers["X-Iroha-Timestamp-Ms"], String(timestampMs));
  assert.equal(request.headers["X-Iroha-Nonce"], nonce);
  assert.ok(signerInput);
  assert.equal(signerInput.messageBase64, signerInput.message.toString("base64"));
  assert.equal(signerInput.path, "/v1/aliases/resolve");
  assert.equal(signerInput.query, "b=2&a=1");
  assert.equal(signerInput.body, request.body);

  const message = canonicalRequestSignatureMessage({
    networkId: TEST_NETWORK_ID,
    method: request.method,
    path: "/v1/aliases/resolve",
    query: "b=2&a=1",
    body: request.body,
    timestampMs,
    nonce,
  });
  const signature = Buffer.from(request.headers["X-Iroha-Signature"], "base64");
  assert.equal(verifyEd25519(message, signature, publicKey), true);
});

test("canonical request signing: callback signatures are bounded canonical bytes", async () => {
  const common = {
    accountId: "operator@paynet",
    networkId: TEST_NETWORK_ID,
    method: "POST",
    path: "/v1/test",
    body: {},
    timestampMs: 1_717_171_717_007,
    nonce: "callback-signature-bounds",
  };
  const exact = Buffer.alloc(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1, 1);
  const accepted = await buildCanonicalJsonRequest({ ...common, sign: () => exact });
  assert.equal(
    Buffer.from(accepted.headers["X-Iroha-Signature"], "base64").length,
    CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
  );

  for (const signature of [
    Buffer.alloc(0),
    Buffer.alloc(64),
    Buffer.alloc(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 + 1, 1),
    "AQ",
    " AQ==",
    {},
  ]) {
    await assert.rejects(
      buildCanonicalJsonRequest({ ...common, sign: () => signature }),
      /signature|padded standard-base64/u,
    );
  }
});

test("canonical request signing: JSON helper includes reverse-proxy base paths", async () => {
  const { privateKey, publicKey } = deterministicKeyPair(9);
  const accountId = "operator-1@mibank.paynet";
  const timestampMs = 1_717_171_717_002;
  const nonce = "torii-prefix-nonce";
  let signerInput = null;

  const request = await buildCanonicalJsonRequest({
    accountId,
    networkId: TEST_NETWORK_ID,
    method: "post",
    baseUrl: "https://explorer.example/torii/",
    path: "/v1/aliases/resolve?alias_scope=paynet",
    body: { alias: "tidal-river-4160@mibank.paynet" },
    timestampMs,
    nonce,
    sign: async (input) => {
      signerInput = input;
      return signEd25519(input.message, privateKey);
    },
  });

  assert.ok(signerInput);
  assert.equal(signerInput.path, "/torii/v1/aliases/resolve");
  assert.equal(signerInput.query, "alias_scope=paynet");

  const message = canonicalRequestSignatureMessage({
    networkId: TEST_NETWORK_ID,
    method: request.method,
    path: "/torii/v1/aliases/resolve",
    query: "alias_scope=paynet",
    body: request.body,
    timestampMs,
    nonce,
  });
  const signature = Buffer.from(request.headers["X-Iroha-Signature"], "base64");
  assert.equal(verifyEd25519(message, signature, publicKey), true);
});

test("canonical request signing: explicit query overrides query strings in paths", async () => {
  const { privateKey } = deterministicKeyPair(10);
  let signerInput = null;

  await buildCanonicalJsonRequest({
    accountId: "operator@paynet",
    networkId: TEST_NETWORK_ID,
    baseUrl: "https://explorer.example/torii",
    path: "/v1/aliases/resolve?ignored=1",
    query: "alias_scope=paynet",
    body: { alias: "banking@paynet" },
    sign: (input) => {
      signerInput = input;
      return signEd25519(input.message, privateKey);
    },
  });

  assert.ok(signerInput);
  assert.equal(signerInput.path, "/torii/v1/aliases/resolve");
  assert.equal(signerInput.query, "alias_scope=paynet");
});

test("canonical request signing: retained JSON originals keep their exact bytes", async () => {
  const { privateKey, publicKey } = deterministicKeyPair(9);
  const bodyText = '{ "amount": 9007199254740993, "memo": "Kina ₭" }\n';
  const request = await buildCanonicalJsonRequest({
    accountId: "admin1@mibank.bpng", networkId: TEST_NETWORK_ID,
    path: "/v1/multisig/propose", baseUrl: "https://torii.example/gateway",
    bodyText, privateKey, timestampMs: 1717171717002, nonce: "retained-original",
  });
  assert.equal(request.body, bodyText);
  const signature = Buffer.from(request.headers["X-Iroha-Signature"], "base64");
  const message = (body) => canonicalRequestSignatureMessage({
    networkId: TEST_NETWORK_ID, method: "POST", path: "/gateway/v1/multisig/propose",
    body, timestampMs: 1717171717002, nonce: "retained-original",
  });
  assert.equal(verifyEd25519(message(bodyText), signature, publicKey), true);
  assert.equal(verifyEd25519(message(JSON.stringify(JSON.parse(bodyText))), signature, publicKey), false);
});

test("canonical request signing: retained JSON original cannot be replaced by another body", async () => {
  const { privateKey } = deterministicKeyPair(9);
  const common = {accountId: "admin1@mibank.bpng", networkId: TEST_NETWORK_ID,
    path: "/v1/multisig/propose", privateKey};
  await assert.rejects(buildCanonicalJsonRequest({...common, bodyText: "{}", body: {amount: 1}}), /cannot be combined/);
  await assert.rejects(buildCanonicalJsonRequest({...common, bodyText: new Uint8Array([123, 125])}), /pre-serialized JSON string/);
});
