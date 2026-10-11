import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha2";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import { blake2b256 } from "../src/blake2b.js";
import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";
import { ToriiHttpError, ToriiStreamGapError } from "../src/toriiErrors.js";
import {
  browserSignedTransactionHashHex,
  browserTransactionPayloadHashHex,
  buildBrowserTransferPayload,
  finalizeBrowserSignedTransaction,
} from "../src/transactionCodec.js";
import { NetworkId } from "../src/networkId.js";
import * as browserSdk from "../src/browser.js";
import * as browserDistSdk from "../dist/browser.js";


const BASE_URL = "https://localhost:8080";
const QUERY_NETWORK_ID = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const FOREIGN_QUERY_NETWORK_ID = NetworkId.fromBytes(Buffer.alloc(32, 0xa7));
const BROWSER_OPERATOR_CONTEXT = new browserSdk.OperatorSigningContext(
  QUERY_NETWORK_ID,
  {
    publicKey:
      "ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",
    sign: async () => Buffer.alloc(64, 0x22),
  },
);
const DIST_BROWSER_OPERATOR_CONTEXT = new browserDistSdk.OperatorSigningContext(
  browserDistSdk.NetworkId.fromBytes(Buffer.alloc(32, 0xa5)),
  {
    publicKey:
      "ed012066BE7E332C7A453332BD9D0A7F7DB055F5C5EF1A06ADA66D98B39FB6810C473A",
    sign: async () => Buffer.alloc(64, 0x22),
  },
);
const FIXTURE_ALICE_ID = AccountAddress.fromAccount({
  publicKey: Buffer.from(
    "68F4B6017D0F876A55C80A82B8388A54AAD264D367269E2DE8BE079C935B5F96",
    "hex",
  ),
}).toI105();
const FIXTURE_BOB_ID = AccountAddress.fromAccount({
  publicKey: Buffer.from(
    "EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245",
    "hex",
  ),
}).toI105();
const AUTHORITY_FEE_PAYMENT = Object.freeze({
  payer: "authority",
  value: Object.freeze({ charge_limits: Object.freeze([]), gas_limit: null }),
});

function canonicalReadOptions() {
  return {
    authAccountId: FIXTURE_ALICE_ID,
    timestampMs: 1_700_000_000_000,
    nonce: "browser-read-fixture",
    sign: async () => Buffer.alloc(64, 0x11),
  };
}

function jsonResponse(payload, init = {}) {
  return new Response(JSON.stringify(payload), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function compactHashSignedTransactionFixture() {
  const privateKey = Buffer.alloc(32, 7);
  const publicKey = Buffer.from(ed25519.getPublicKey(privateKey));
  const networkId = NetworkId.parse(
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
  );
  const authority = AccountAddress.fromAccount({ publicKey }).toI105();
  const payload = buildBrowserTransferPayload({
    networkPrefix: 753,
    networkId,
    authority,
    sourceAssetHoldingId: `62Fk4FPcMuLvW5QjDGNF2a4jAmjM#${authority}`,
    quantity: "1",
    destinationAccountId: FIXTURE_BOB_ID,
    feePayment: { payer: "authority", chargeLimits: [] },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 5_000,
    nonce: 42,
  });
  const payloadHashHex = browserTransactionPayloadHashHex(payload, 753);
  const signature = Buffer.from(
    ed25519.sign(Buffer.from(payloadHashHex, "hex"), privateKey),
  );
  return finalizeBrowserSignedTransaction(
    { networkPrefix: 753, networkId, payloadBytes: payload, payloadHashHex, authority, signingPublicKey: publicKey },
    { algorithm: "ed25519", signature },
    publicKey,
  ).signedTransaction;
}

function blockProofResponseFixture() {
  const u64 = (value) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64LE(BigInt(value));
    return bytes;
  };
  const compact = (value) => {
    const bytes = [];
    let remaining = value;
    do {
      const byte = remaining & 0x7f;
      remaining >>>= 7;
      bytes.push(remaining === 0 ? byte : byte | 0x80);
    } while (remaining !== 0);
    return Buffer.from(bytes);
  };
  const field = (payload) => Buffer.concat([compact(payload.length), payload]);
  const struct = (...fields) => Buffer.concat(fields.map(field));
  const entryHash = Buffer.alloc(32, 0x20);
  entryHash[31] |= 1;
  const resultHash = Buffer.alloc(32, 0x50);
  resultHash[31] |= 1;
  const blockHash = Buffer.alloc(32, 0x30);
  blockHash[31] |= 1;
  const executedBlockWireHash = Buffer.alloc(32, 0x40);
  executedBlockWireHash[31] |= 1;
  const entryRoot = Buffer.from(
    blake2b256(
      Buffer.concat([
        Buffer.from("iroha:merkle:leaf:v1\0", "utf8"),
        entryHash,
      ]),
    ),
  );
  entryRoot[31] |= 1;
  const resultRoot = Buffer.from(
    blake2b256(
      Buffer.concat([
        Buffer.from("iroha:merkle:leaf:v1\0", "utf8"),
        resultHash,
      ]),
    ),
  );
  resultRoot[31] |= 1;
  const leafIndex = Buffer.alloc(4);
  const entryCommitment = struct(entryRoot, u64(1));
  const receipt = struct(entryHash, struct(leafIndex, u64(0)));
  const resultCommitment = struct(resultRoot, u64(1));
  const resultReceipt = struct(resultHash, struct(leafIndex, u64(0)));
  const payload = struct(
    u64(7),
    blockHash,
    executedBlockWireHash,
    entryHash,
    entryCommitment,
    receipt,
    resultCommitment,
    resultReceipt,
    u64(0),
  );
  const schemaHash = Buffer.from(
    sha256(Buffer.from(
      "norito:v1:type-name\0iroha_data_model::block::proofs::BlockProofs",
      "utf8",
    )).subarray(0, 16),
  );
  let crc = 0xffff_ffff_ffff_ffffn;
  for (const byte of payload) {
    crc ^= BigInt(byte);
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1n) === 0n
        ? crc >> 1n
        : (crc >> 1n) ^ 0xc96c_5795_d787_0f42n;
    }
  }
  crc = BigInt.asUintN(64, crc ^ 0xffff_ffff_ffff_ffffn);
  return Buffer.concat([
    Buffer.from("NRT0", "ascii"),
    Buffer.of(0, 0),
    schemaHash,
    Buffer.of(0),
    u64(payload.length),
    u64(crc),
    Buffer.of(0x02),
    payload,
  ]);
}

function authenticatedBlockProofAnchorFixture() {
  const entryHash = Buffer.alloc(32, 0x20);
  entryHash[31] |= 1;
  const resultHash = Buffer.alloc(32, 0x50);
  resultHash[31] |= 1;
  const blockHash = Buffer.alloc(32, 0x30);
  blockHash[31] |= 1;
  const executedBlockWireHash = Buffer.alloc(32, 0x40);
  executedBlockWireHash[31] |= 1;
  const merkleLeafDomain = Buffer.from("iroha:merkle:leaf:v1\0", "utf8");
  const entryRoot = Buffer.from(
    blake2b256(Buffer.concat([merkleLeafDomain, entryHash])),
  );
  entryRoot[31] |= 1;
  const resultRoot = Buffer.from(
    blake2b256(Buffer.concat([merkleLeafDomain, resultHash])),
  );
  resultRoot[31] |= 1;
  return {
    block_height: "7",
    block_hash: blockHash.toString("hex"),
    executed_block_wire_hash: executedBlockWireHash.toString("hex"),
    entry_hash: entryHash.toString("hex"),
    entry_index: 0,
    entry_commitment: { root: entryRoot.toString("hex"), leaf_count: "1" },
    result_commitment: { root: resultRoot.toString("hex"), leaf_count: "1" },
    fastpq_transcripts: {},
  };
}

function sseResponse(chunks, { close = true, onCancel } = {}) {
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
        if (close) controller.close();
      },
      cancel() {
        onCancel?.();
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  );
}


test("ToriiBrowserClient keeps transport configuration private and immutable", async () => {
  let captured;
  const defaultHeaders = {
    Authorization: "Bearer browser-secret",
    "X-Trace": "trace-1",
  };
  const client = new ToriiBrowserClient("https://torii.example", {
    defaultHeaders,
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return jsonResponse({ status: "ok" });
    },
    timeoutMs: 5_000,
  });

  defaultHeaders.Authorization = "Bearer mutated";
  defaultHeaders["X-Trace"] = "trace-2";

  assert.deepEqual(Object.keys(client), []);
  assert.equal(JSON.stringify(client), "{}");
  assert.equal(client.defaultHeaders, undefined);
  assert.equal(client.fetchImpl, undefined);
  assert.equal(client.timeoutMs, undefined);
  assert.equal(client.baseUrl, "https://torii.example");
  assert.throws(() => {
    client.baseUrl = "http://attacker.example";
  }, TypeError);

  await client.getExplorerHealth();
  assert.equal(captured.url, "https://torii.example/v1/explorer/health");
  assert.equal(captured.init.headers.Authorization, "Bearer browser-secret");
  assert.equal(captured.init.headers["X-Trace"], "trace-1");
});

test("ToriiBrowserClient accepts only an exact credential-free HTTP root URL", () => {
  const fetchImpl = async () => jsonResponse({ status: "ok" });
  for (const baseUrl of [
    { toString: () => "https://coerced.example" },
    " ftp://torii.example",
    "ftp://torii.example",
    "https://user:password@torii.example",
    "https://torii.example?target=other",
    "https://torii.example#fragment",
    "https://torii.example/v1",
    "https://torii.example/v1/explorer",
  ]) {
    assert.throws(
      () => new ToriiBrowserClient(baseUrl, { fetchImpl }),
      /baseUrl/u,
    );
  }
  assert.equal(
    new ToriiBrowserClient(new URL("https://torii.example/proxy/"), { fetchImpl }).baseUrl,
    "https://torii.example/proxy",
  );
});

test("ToriiBrowserClient validates copied headers, timeouts, and option names", () => {
  const fetchImpl = async () => jsonResponse({ status: "ok" });
  for (const defaultHeaders of [
    new Headers({ Authorization: "Bearer secret" }),
    { Authorization: 1 },
    { Authorization: "Bearer secret\r\nX-Injected: yes" },
  ]) {
    assert.throws(
      () => new ToriiBrowserClient("https://torii.example", {
        defaultHeaders,
        fetchImpl,
      }),
      /defaultHeaders/u,
    );
  }
  for (const timeoutMs of [true, [25], -1, 1.5, "01", "not-a-timeout"]) {
    assert.throws(
      () => new ToriiBrowserClient("https://torii.example", { fetchImpl, timeoutMs }),
      /timeoutMs/u,
    );
  }
  assert.throws(
    () => new ToriiBrowserClient("https://torii.example", {
      config: { toriiClient: { timeoutMs: 5_000 } },
      fetchImpl,
    }),
    /unsupported option config/u,
  );
});

test("ToriiBrowserClient protects credential headers with an exact insecure opt-in", () => {
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("unexpected fetch");
  };
  for (const allowInsecure of ["false", "true", 0, 1, {}, []]) {
    assert.throws(
      () =>
        new ToriiBrowserClient("http://torii.example", {
          allowInsecure,
          defaultHeaders: { Authorization: "Bearer secret" },
          fetchImpl,
        }),
      /allowInsecure must be a boolean/u,
    );
  }
  assert.throws(
    () =>
      new ToriiBrowserClient("http://torii.example", {
        defaultHeaders: { Authorization: "Bearer secret" },
        fetchImpl,
      }),
    /credential headers require an https base URL/u,
  );
  assert.doesNotThrow(
    () =>
      new ToriiBrowserClient("http://torii.example", {
        allowInsecure: true,
        defaultHeaders: { Authorization: "Bearer secret" },
        fetchImpl,
      }),
  );
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient keeps its timeout when a caller signal is supplied", async () => {
  const fetchImpl = async (_url, init) =>
    new Promise((_, reject) => {
      init.signal.addEventListener(
        "abort",
        () => reject(new DOMException("Aborted", "AbortError")),
        { once: true },
      );
    });
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl,
    timeoutMs: 10,
  });
  const caller = new AbortController();
  await assert.rejects(
    () => client.explorerBlocks.list({}, { signal: caller.signal }),
    /AbortError|aborted/iu,
  );
});

test("ToriiBrowserClient applies a default bound to JSON response bodies", async () => {
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () =>
      new Response("{}", {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-length": String(8 * 1024 * 1024 + 1),
        },
      }),
  });
  await assert.rejects(
    () => client.explorerBlocks.list(),
    /exceeds its 8388608-byte response limit/u,
  );
});


test("ToriiBrowserClient signs every scoped Explorer and contract read over its final URL", async () => {
  const signed = [];
  const fetched = [];
  const snapshotHash = "ef".repeat(32);
  const cursorPage = {
    next_cursor: null,
    items: [],
  };
  const historyPage = {
    pagination: {
      limit: 25,
      snapshot_height: 1,
      snapshot_hash: snapshotHash,
      next_cursor: null,
      has_more: false,
    },
    items: [],
  };
  const responseFor = (url) => {
    const path = new URL(url).pathname.replace(/^\/proxy/u, "");
    if (path.endsWith("/query")) return jsonResponse({ items: [], next_cursor: null });
    if (path === "/v1/contracts/events/sse") {
      return sseResponse(["event: contract_event\ndata: {}\n\n"]);
    }
    if (path === "/v1/explorer/assets/asset-id") {
      return jsonResponse({ quantity: "0" });
    }
    if (path === "/v1/explorer/rwas/rwa-id") {
      return jsonResponse({ quantity: "0", held_quantity: "0" });
    }
    if (path.endsWith("/assets") && path.startsWith("/v1/accounts/")) {
      return jsonResponse({ items: [], total: 0 });
    }
    if (
      [
        "/v1/explorer/accounts",
        "/v1/explorer/domains",
        "/v1/explorer/assets",
        "/v1/explorer/asset-definitions",
        "/v1/explorer/nfts",
        "/v1/explorer/rwas",
      ].includes(path)
    ) {
      return jsonResponse(cursorPage);
    }
    if (
      path === "/v1/explorer/blocks"
      || path === "/v1/explorer/transactions"
      || path === "/v1/explorer/instructions"
    ) {
      return jsonResponse(historyPage);
    }
    if (
      path === "/v1/explorer/transactions/latest"
      || path === "/v1/explorer/instructions/latest"
    ) {
      return jsonResponse({ sampled_at: "2026-08-30T01:02:03Z", ...historyPage });
    }
    return jsonResponse({});
  };
  const client = new ToriiBrowserClient("https://localhost:8080/proxy", {
    networkId: QUERY_NETWORK_ID,
    canonicalRequestAuth: {
      accountId: FIXTURE_ALICE_ID,
      sign: async (input) => {
        signed.push(input);
        return Buffer.alloc(64, 0x31);
      },
    },
    fetchImpl: async (url, init) => {
      fetched.push({ url: new URL(url), init });
      assert.equal(init.method, new URL(url).pathname.endsWith("/query") ? "POST" : "GET");
      assert.equal(init.redirect, "error");
      assert.equal(init.credentials, "omit");
      assert.ok(init.headers["X-Iroha-Account"]);
      assert.ok(init.headers["X-Iroha-Signature"]);
      assert.ok(init.headers["X-Iroha-Timestamp-Ms"]);
      assert.ok(init.headers["X-Iroha-Nonce"]);
      return responseFor(url);
    },
  });

  const aborted = new AbortController();
  aborted.abort();
  const invocations = [
    () => client.explorerAccounts.list({ limit: 1, filter: 'domain = "wonderland"' }),
    () => client.getExplorerAccount(FIXTURE_ALICE_ID, { addressFormat: "i105" }),
    () => client.explorerDomains.list({ limit: 1, filter: `owned_by = "${FIXTURE_ALICE_ID}"` }),
    () => client.getExplorerDomain("wonderland"),
    () => client.explorerAssets.list({ limit: 1, filter: 'definition = "rose#wonderland"' }),
    () => client.getExplorerAsset("asset-id"),
    () => client.explorerAssetDefinitions.list({ limit: 1, filter: 'owning_domain = "wonderland"' }),
    () => client.getExplorerAssetDefinitionEconometrics("rose#wonderland"),
    () => client.getExplorerAssetDefinitionSnapshot("rose#wonderland"),
    () => client.explorerNfts.list({ limit: 1, filter: 'domain = "wonderland"' }),
    () => client.getExplorerNft("nft-id"),
    () => client.explorerRwas.list({ limit: 1, filter: 'domain = "wonderland"' }),
    () => client.getExplorerRwa("rwa-id"),
    () => client.explorerBlocks.list({ limit: 1 }),
    () => client.getExplorerBlock(1),
    () => client.getExplorerMetrics(),
    () => client.explorerTransactions.list({ limit: 1, filter: 'status = "committed"' }),
    () => client.explorerLatestTransactions.list({ limit: 1, filter: 'status = "rejected"' }),
    () => client.getExplorerTransaction("transaction-hash", { addressFormat: "i105" }),
    () => client.explorerInstructions.list({ limit: 1, filter: 'kind = "transfer"' }),
    () => client.explorerLatestInstructions.list({ limit: 1, filter: 'kind = "transfer"' }),
    () => client.getExplorerInstruction("transaction-hash", 0, { addressFormat: "i105" }),
    () => client.getExplorerInstructionContractView("transaction-hash", 0),
    () => client.getAccount(FIXTURE_ALICE_ID),
    () => client.accountPermissions(FIXTURE_ALICE_ID).list(),
    () => client.accountHistory(FIXTURE_ALICE_ID).list(),
    () => client.contractActivity.list({ limit: 1, filter: 'contract_alias = "demo::module"' }),
    () => client.contractEvents.list({ limit: 1, filter: 'event_kind = "filled"' }),
    async () => {
      for await (const _event of client.streamContractEvents({
        eventKind: "filled",
        signal: aborted.signal,
      })) {
        // Consume the one test frame; the pre-aborted signal makes EOF graceful.
      }
    },
  ];
  for (const invoke of invocations) await invoke();

  assert.equal(signed.length, invocations.length);
  assert.equal(fetched.length, invocations.length);
  for (let index = 0; index < signed.length; index += 1) {
    assert.equal(signed[index].method, fetched[index].init.method);
    assert.equal(signed[index].path, fetched[index].url.pathname);
    assert.equal(signed[index].query ?? "", fetched[index].url.search.slice(1));
    assert.equal(signed[index].body, fetched[index].init.body ?? "");
  }
});

test("ToriiBrowserClient leaves optional dataspace reads anonymous without a signer", async () => {
  const calls = [];
  const client = new ToriiBrowserClient("https://localhost:8080", {
    fetchImpl: async (url, init) => {
      calls.push({ url: new URL(url), init });
      if (new URL(url).pathname.endsWith("/events/sse")) {
        return sseResponse([]);
      }
      if (new URL(url).pathname.endsWith("/query")) {
        return jsonResponse({ items: [], next_cursor: null });
      }
      return jsonResponse({});
    },
  });
  await client.getExplorerDomain("wonderland");
  await client.getExplorerMetrics();
  await client.getAccount(FIXTURE_ALICE_ID);
  await client.accountAssets(FIXTURE_ALICE_ID).list();
  await client.accountPermissions(FIXTURE_ALICE_ID).list();
  await client.accountHistory(FIXTURE_ALICE_ID).list();
  await client.contractEvents.list();
  const aborted = new AbortController();
  aborted.abort();
  for await (const _event of client.streamContractEvents({ signal: aborted.signal })) {
    // No frames are expected.
  }
  assert.equal(calls.length, 8);
  for (const { init } of calls) {
    assert.equal(init.credentials, "omit");
    assert.equal(init.headers["X-Iroha-Account"], undefined);
    assert.equal(init.headers["X-Iroha-Signature"], undefined);
    assert.equal(init.headers["X-Iroha-Timestamp-Ms"], undefined);
    assert.equal(init.headers["X-Iroha-Nonce"], undefined);
  }
});

test("ToriiBrowserClient keeps Explorer health public when canonical read auth is configured", async () => {
  let signCalls = 0;
  let captured;
  const client = new ToriiBrowserClient("https://localhost:8080", {
    networkId: QUERY_NETWORK_ID,
    canonicalRequestAuth: {
      accountId: FIXTURE_ALICE_ID,
      sign: async () => {
        signCalls += 1;
        return Buffer.alloc(64, 0x32);
      },
    },
    fetchImpl: async (url, init) => {
      captured = { url: new URL(url), init };
      return jsonResponse({ status: "ok" });
    },
  });
  await client.getExplorerHealth();
  assert.equal(signCalls, 0);
  assert.equal(captured.url.pathname, "/v1/explorer/health");
  assert.equal(captured.init.headers["X-Iroha-Account"], undefined);
  assert.equal(captured.init.headers["X-Iroha-Signature"], undefined);
  assert.equal(captured.init.redirect, undefined);
});

test("ToriiBrowserClient rejects partial, precomputed, and redirected canonical read auth", async () => {
  const noFetch = async () => {
    throw new Error("must not fetch");
  };
  assert.throws(
    () => new ToriiBrowserClient("https://localhost:8080", {
      networkId: QUERY_NETWORK_ID,
      canonicalRequestAuth: { accountId: FIXTURE_ALICE_ID },
      fetchImpl: noFetch,
    }),
    /requires exactly accountId and sign/u,
  );
  assert.throws(
    () => new ToriiBrowserClient("https://localhost:8080", {
      canonicalRequestAuth: {
        accountId: FIXTURE_ALICE_ID,
        sign: async () => Buffer.alloc(64, 0x33),
      },
      fetchImpl: noFetch,
    }),
    /requires options.networkId/u,
  );
  assert.throws(
    () => new ToriiBrowserClient("https://localhost:8080", {
      defaultHeaders: { "X-Iroha-Nonce": "precomputed" },
      fetchImpl: noFetch,
    }),
    /cannot be precomputed/u,
  );

  const redirected = new ToriiBrowserClient("https://localhost:8080", {
    networkId: QUERY_NETWORK_ID,
    canonicalRequestAuth: {
      accountId: FIXTURE_ALICE_ID,
      sign: async () => Buffer.alloc(64, 0x34),
    },
    fetchImpl: async () => ({
      status: 200,
      redirected: true,
      text: async () => "{}",
    }),
  });
  await assert.rejects(
    redirected.getExplorerDomain("wonderland"),
    /must not accept a redirected response/u,
  );
});

test("ToriiBrowserClient rejects retired Explorer controls and page envelopes", async () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => { fetchCalls++; throw new Error("unexpected transport"); },
  });
  for (const collection of [client.explorerBlocks, client.explorerTransactions, client.explorerLatestInstructions]) {
    for (const query of [{ page: 2 }, { offset: 1 }, { per_page: 5 }, { limit: 0 }, { sort: "id" }, { includeTotal: true }]) {
      await assert.rejects(collection.list(query));
    }
  }
  assert.equal(fetchCalls, 0);
  for (const payload of [
    { items: [], pagination: { next_cursor: null, has_more: false } },
    { items: [], next_cursor: null, sampled_at: "today" },
  ]) {
    const reader = new ToriiBrowserClient("https://torii.example", { fetchImpl: async () => jsonResponse(payload) });
    await assert.rejects(reader.explorerTransactions.list(), error => error.code === "invalid_response");
  }
});


test("ToriiBrowserClient uses explicit asset-definition ownership fields", async () => {
  const item = {
    id: "11111111-1111-4111-8111-111111111111",
    owning_domain: null,
    owning_dataspace: null,
    mintable: "Infinitely",
    logo: null,
    metadata: {},
    owned_by: FIXTURE_ALICE_ID,
    assets: 0,
    total_quantity: "0",
    locked_quantity: null,
    circulating_quantity: null,
  };
  const client = new ToriiBrowserClient("https://localhost:8080", {
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      assert.equal(JSON.parse(init.body).filter, 'owning_domain = "treasury.universal"');
      assert.equal(parsed.searchParams.get("domain"), null);
      return jsonResponse({
        next_cursor: null,
        items: [item],
      });
    },
  });

  const page = await client.explorerAssetDefinitions.list({
    limit: 10,
    filter: 'owning_domain = "treasury.universal"',
  });
  assert.equal(page.items[0].owning_domain, null);
  assert.equal(page.items[0].owning_dataspace, null);

  const missingOwnership = { ...item };
  delete missingOwnership.owning_domain;
  const invalidClient = new ToriiBrowserClient("https://localhost:8080", {
    fetchImpl: async () =>
      jsonResponse({
        next_cursor: null,
        items: [missingOwnership],
      }),
  });
  await assert.rejects(
    invalidClient.explorerAssetDefinitions.list({ limit: 10 }),
    /missing or unsupported fields/u,
  );
});


test("ToriiBrowserClient preserves exact direct asset homes and rejects malformed ownership", async () => {
  const item = {
    id: "11111111-1111-4111-8111-111111111111",
    owning_domain: null,
    owning_dataspace: null,
    mintable: "Infinitely",
    logo: null,
    metadata: {},
    owned_by: FIXTURE_ALICE_ID,
    assets: 0,
    total_quantity: "0",
    locked_quantity: null,
    circulating_quantity: null,
  };
  const read = (row) => new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => jsonResponse({ next_cursor: null, items: [row] }),
  }).explorerAssetDefinitions.list({ limit: 1 });

  for (const home of ["1", "9007199254740993", "8648377547929788715", "18446744073709551615"]) {
    const page = await read({ ...item, owning_dataspace: home });
    assert.equal(page.items[0].owning_dataspace, home);
    assert.equal(typeof page.items[0].owning_dataspace, "string");
    assert.equal(page.items[0].owning_domain, null);
  }
  for (const owningDomain of [null, "treasury.bpng"]) {
    const page = await read({ ...item, owning_domain: owningDomain });
    assert.equal(page.items[0].owning_domain, owningDomain);
    assert.equal(page.items[0].owning_dataspace, null);
  }
  for (const home of [
    "0", "00", "01", "18446744073709551616", "184467440737095516150",
    "", "+1", "-1", "1.0", "1e0", " 1", "1 ", "1\n", "1\r\n", "１", 0, 7, 9007199254740992, true, {}, [],
  ]) {
    await assert.rejects(read({ ...item, owning_dataspace: home }), /owning_dataspace/u);
  }
  await assert.rejects(
    read({ ...item, owning_domain: "treasury.bpng", owning_dataspace: "7" }),
    /cannot carry both domain and dataspace homes/u,
  );
  for (const field of ["owning_domain", "owning_dataspace"]) {
    const missing = { ...item };
    delete missing[field];
    await assert.rejects(read(missing), /missing or unsupported fields/u);
  }
});

test("ToriiBrowserClient exposes exact JSON ledger windows, roots, and state proofs", async () => {
  const calls = [];
  const client = new ToriiBrowserClient(BASE_URL, {
    defaultHeaders: { "x-test-client": "ledger" },
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return jsonResponse({ ok: true });
    },
  });

  await client.listLedgerHeaders({ from: 9, limit: 3 });
  await client.getLedgerStateRoot(9);
  await client.getLedgerStateProof(9);

  assert.equal(
    calls[0].url,
    "https://localhost:8080/v1/ledger/headers?from=9&limit=3",
  );
  assert.equal(calls[1].url, "https://localhost:8080/v1/ledger/state/9");
  assert.equal(calls[2].url, "https://localhost:8080/v1/ledger/state-proof/9");
  for (const call of calls) {
    assert.equal(call.init.headers.Accept, "application/json");
    assert.equal(call.init.headers["x-test-client"], "ledger");
  }
});

test("ToriiBrowserClient fetches ledger BlockProofs only as canonical Norito", async () => {
  const entryHash = "AB".repeat(32);
  let captured;
  const client = new ToriiBrowserClient(BASE_URL, {
    defaultHeaders: { Accept: "application/json", "x-test-client": "ledger" },
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return new Response(blockProofResponseFixture(), {
        headers: { "content-type": "application/x-norito" },
      });
    },
  });

  const proof = await client.getLedgerBlockProof(7, `0x${entryHash}`);
  assert.equal(
    captured.url,
    `https://localhost:8080/v1/ledger/block/7/proof/${entryHash.toLowerCase()}`,
  );
  assert.equal(captured.init.headers.Accept, "application/x-norito");
  assert.equal(captured.init.headers["x-test-client"], "ledger");
  assert.deepEqual(Object.keys(proof), [
    "block_height",
    "block_hash",
    "executed_block_wire_hash",
    "entry_hash",
    "entry_commitment",
    "entry_proof",
    "result_commitment",
    "result_proof",
    "fastpq_transcripts",
  ]);
  assert.equal(proof.block_height, "7");
  assert.match(proof.block_hash, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
  assert.match(
    proof.executed_block_wire_hash,
    /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u,
  );
  assert.equal(proof.entry_proof.leaf, proof.entry_hash);
  assert.deepEqual(proof.entry_proof.proof, { leaf_index: 0, audit_path: [] });
  assert.equal(proof.entry_commitment.leaf_count, "1");
  assert.notEqual(proof.entry_commitment.root, proof.entry_hash);
  assert.equal(proof.result_commitment.leaf_count, "1");
  assert.equal(proof.result_proof.proof.leaf_index, 0);
  assert.notEqual(proof.result_commitment.root, proof.result_proof.leaf);
  assert.deepEqual(proof.fastpq_transcripts, {});

  assert.equal(
    browserSdk.verifyBlockProofs(
      proof,
      authenticatedBlockProofAnchorFixture(),
    ).valid,
    true,
  );
  assert.equal(browserSdk.verifyBlockProofs(proof).valid, false);
});

test("ToriiBrowserClient fetches the bounded exact executed block wire", async () => {
  const expectedWire = Buffer.from([1, 0x4e, 0x52, 0x54, 0x30, 0xaa]);
  let captured;
  const client = new ToriiBrowserClient(BASE_URL, {
    defaultHeaders: { Accept: "application/json", "x-test-client": "ledger" },
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return new Response(expectedWire, {
        headers: { "content-type": "application/x-norito" },
      });
    },
  });

  const actualWire = await client.getLedgerExecutedBlockWire(7);
  assert.equal(captured.url, "https://localhost:8080/v1/ledger/block/7");
  assert.equal(captured.init.headers.Accept, "application/x-norito");
  assert.equal(captured.init.headers["x-test-client"], "ledger");
  assert.deepEqual(actualWire, expectedWire);

  const maximumHeightWire = await client.getLedgerExecutedBlockWire(
    "18446744073709551615",
  );
  assert.equal(
    captured.url,
    "https://localhost:8080/v1/ledger/block/18446744073709551615",
  );
  assert.deepEqual(maximumHeightWire, expectedWire);
});

test("ToriiBrowserClient rejects malformed ledger selectors and representations locally", async () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse({});
    },
  });

  assert.throws(() => client.listLedgerHeaders({ from: 0 }), /positive decimal integer/u);
  assert.throws(() => client.listLedgerHeaders({ offset: 1 }), /unsupported option offset/u);
  assert.throws(() => client.getLedgerStateRoot(0), /positive decimal integer/u);
  await assert.rejects(
    client.getLedgerExecutedBlockWire(0),
    /positive decimal integer/u,
  );
  await assert.rejects(
    client.getLedgerExecutedBlockWire(1n << 64n),
    /must not exceed 18446744073709551615/u,
  );
  await assert.rejects(
    client.getLedgerExecutedBlockWire(1, { offset: 1 }),
    /unsupported option offset/u,
  );
  await assert.rejects(
    client.getLedgerBlockProof(1, "abc"),
    /exactly 32 bytes of hexadecimal/u,
  );
  assert.equal(fetchCalls, 0);

  const wrongContentTypeClient = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => jsonResponse({}),
  });
  await assert.rejects(
    wrongContentTypeClient.getLedgerBlockProof(1, "ab".repeat(32)),
    /must return application\/x-norito/u,
  );
  await assert.rejects(
    wrongContentTypeClient.getLedgerExecutedBlockWire(1),
    /must return application\/x-norito/u,
  );

  const emptyClient = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => new Response(new Uint8Array(), {
      headers: { "content-type": "application/x-norito" },
    }),
  });
  await assert.rejects(
    emptyClient.getLedgerExecutedBlockWire(1),
    /must not be empty/u,
  );

  const oversizedClient = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => new Response(Uint8Array.of(1), {
      headers: {
        "content-type": "application/x-norito",
        "content-length": String(
          browserSdk.AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1 + 1,
        ),
      },
    }),
  });
  await assert.rejects(
    oversizedClient.getLedgerExecutedBlockWire(1),
    /33554432-byte response limit/u,
  );

  const lengthMismatchClient = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => new Response(Uint8Array.of(1), {
      headers: {
        "content-type": "application/x-norito",
        "content-length": "2",
      },
    }),
  });
  await assert.rejects(
    lengthMismatchClient.getLedgerExecutedBlockWire(1),
    /Content-Length does not match/u,
  );

  const fragmentedClient = new ToriiBrowserClient(BASE_URL, {
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) {
        for (let index = 0; index <= 16_384; index += 1) {
          controller.enqueue(Uint8Array.of(index & 0xff));
        }
        controller.close();
      },
    }), {
      headers: { "content-type": "application/x-norito" },
    }),
  });
  await assert.rejects(
    fragmentedClient.getLedgerExecutedBlockWire(1),
    /too many fragmented response chunks/u,
  );
});

test("ToriiBrowserClient account and contract collections use shared queries", async () => {
  const calls = [];
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async (url, init) => {
      calls.push({ url: new URL(url), init });
      return jsonResponse({ items: [], next_cursor: null });
    },
  });
  const query = { filter: 'result_ok = true', limit: 5, cursor: "q1_next" };
  for (const collection of [client.accountPermissions("alice/account"), client.accountHistory("alice/account"), client.contractActivity, client.contractEvents]) {
    assert.deepEqual(await collection.list(query), { items: [], nextCursor: null, total: undefined });
  }
  assert.deepEqual(calls.map(call => call.url.pathname), [
    "/v1/accounts/alice%2Faccount/permissions/query",
    "/v1/accounts/alice%2Faccount/history/query",
    "/v1/contracts/activity/query",
    "/v1/contracts/events/query",
  ]);
  for (const call of calls) {
    assert.equal(call.init.method, "POST");
    assert.equal(call.url.search, "");
    assert.deepEqual(JSON.parse(call.init.body), query);
  }
});

test("ToriiBrowserClient rejects removed collection options before transport", async () => {
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => { throw new Error("unexpected transport"); },
  });
  for (const collection of [client.accountPermissions("alice"), client.accountHistory("alice"), client.contractActivity, client.contractEvents]) {
    await assert.rejects(collection.list({ offset: 1 }), /unknown|unsupported/u);
    await assert.rejects(collection.list({ countMode: "exact" }), /unknown|unsupported/u);
  }
  for (const collection of [client.accountHistory("alice"), client.contractActivity, client.contractEvents]) {
    await assert.rejects(collection.list({ sort: "-block_height" }), /cannot be sorted/u);
    await assert.rejects(collection.list({ includeTotal: true }), /no total/u);
  }
});

test("ToriiBrowserClient streams fragmented multiline CRLF contract events with fetch", async () => {
  const abortController = new AbortController();
  let capturedInit;
  let cancelled = false;
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    defaultHeaders: {
      Accept: "application/json",
      "Last-Event-ID": "must-not-be-sent",
      "x-test-client": "browser-sdk",
    },
    fetchImpl: async (url, init) => {
      fetchCalls += 1;
      capturedInit = init;
      assert.equal(
        String(url),
        "https://torii.example/v1/contracts/events/sse?contract_address=irohac1router&event_kind=fill",
      );
      return sseResponse(
        [
          ": heart",
          "beat\r",
          "\n\r\nevent: contract_event\r\nid: event-1\r\nretry: 1500\r\n",
          "data: {\"event_id\":\"event-1\",\r\n",
          "data: \"schema_version\":1}\r\n\r",
          "\n",
        ],
        { close: false, onCancel: () => { cancelled = true; } },
      );
    },
  });

  const iterator = client.streamContractEvents({
    contractAddress: "irohac1router",
    eventKind: "fill",
    signal: abortController.signal,
  });
  const first = await iterator.next();
  assert.equal(first.done, false);
  assert.equal(first.value.event, "contract_event");
  assert.equal(first.value.id, "event-1");
  assert.equal(first.value.retry, 1500);
  assert.deepEqual(first.value.data, { event_id: "event-1", schema_version: 1 });
  assert.equal(
    first.value.raw,
    "{\"event_id\":\"event-1\",\n\"schema_version\":1}",
  );
  assert.equal(capturedInit.signal, abortController.signal);
  const headers = new Headers(capturedInit.headers);
  assert.equal(headers.get("accept"), "text/event-stream");
  assert.equal(headers.get("x-test-client"), "browser-sdk");
  assert.equal(headers.get("last-event-id"), null);
  await iterator.return();
  assert.equal(cancelled, true);
  assert.equal(fetchCalls, 1);
});

test("ToriiBrowserClient forwards aborts into the contract event ReadableStream", async () => {
  const abortController = new AbortController();
  let requestStarted = false;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async (_url, init) => {
      requestStarted = true;
      return new Response(
        new ReadableStream({
          start(controller) {
            init.signal.addEventListener(
              "abort",
              () => controller.error(init.signal.reason),
              { once: true },
            );
          },
        }),
        { headers: { "content-type": "text/event-stream" } },
      );
    },
  });

  const pending = client.streamContractEvents({ signal: abortController.signal }).next();
  while (!requestStarted) await Promise.resolve();
  const reason = new DOMException("stop streaming", "AbortError");
  abortController.abort(reason);
  await assert.rejects(pending, (error) => error === reason);
});

test("ToriiBrowserClient turns contract stream_error events into typed gaps", async () => {
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => sseResponse([
      "event: stream_error\n",
      "data: {\"code\":\"stream_lagged\",\"message\":\"events were lost\",",
      "\"dropped_messages\":4,\"replay_available\":false}\n\n",
    ]),
  });

  await assert.rejects(
    client.streamContractEvents().next(),
    (error) => {
      assert(error instanceof ToriiStreamGapError);
      assert.equal(error.code, "stream_lagged");
      assert.equal(error.message, "events were lost");
      assert.equal(error.droppedMessages, 4);
      assert.equal(error.replayAvailable, false);
      assert.equal(error.payload.replay_available, false);
      return true;
    },
  );
});

test("ToriiBrowserClient treats contract stream EOF as a terminal non-replayable gap", async () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return sseResponse([]);
    },
  });

  await assert.rejects(
    client.streamContractEvents().next(),
    (error) => {
      assert(error instanceof ToriiStreamGapError);
      assert.equal(error.code, "stream_unexpected_eof");
      assert.equal(error.droppedMessages, null);
      assert.equal(error.replayAvailable, false);
      return true;
    },
  );
  assert.equal(fetchCalls, 1);
});

test("ToriiBrowserClient contract event stream accepts only committed emitted provenance", () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return sseResponse([]);
    },
  });

  assert.throws(
    () => client.streamContractEvents({ provenance: "derived" }),
    /streamContractEvents options\.provenance must be emitted/u,
  );
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient rejects adversarial query options before fetch", async () => {
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls += 1;
    throw new Error("fetch should not be called for invalid local options");
  };
  const client = new ToriiBrowserClient("https://torii.example", { fetchImpl });

  await assert.rejects(
    () => client.explorerBlocks.list({ page: 0 }),
    { name: "ListQueryError", message: /invalid `query`: unknown member `page`/u },
  );
  assert.throws(
    () => client.resolveAlias("  "),
    /alias must not be empty/,
  );
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient preserves error responses for callers", async () => {
  const fetchImpl = async () => new Response("not found", { status: 404 });
  const client = new ToriiBrowserClient("https://localhost:8080", { fetchImpl });
  await assert.rejects(
    () => client.getExplorerRwa("missing$domain"),
    (error) => {
      assert(error instanceof ToriiHttpError);
      assert.equal(error.status, 404);
      assert.equal(error.bodyText, "not found");
      return true;
    },
  );
});

test("browser aggregate exports reusable browser-safe SDK APIs", () => {
  assert.equal(typeof browserSdk.AccountAddress, "function");
  assert.equal(typeof browserSdk.ToriiBrowserClient, "function");
  assert.equal(typeof browserSdk.ToriiStreamGapError, "function");
  assert.equal(typeof browserDistSdk.ToriiStreamGapError, "function");
  assert.equal(typeof browserSdk.normalizeAccountAliasFqn, "function");
  assert.equal(typeof browserSdk.noritoEncodeMultisigProposeRequest, "function");
  assert.equal(typeof browserSdk.noritoDecodeBlockProofs, "function");
  assert.equal(typeof browserSdk.verifyBlockProofs, "function");
  assert.equal(typeof browserSdk.NumericV1?.decodeQuantityJson, "function");
  assert.equal(typeof browserSdk.KotodamaQuantity, "function");
  assert.equal(typeof browserDistSdk.NumericV1?.decodeQuantityJson, "function");
  assert.equal(typeof browserDistSdk.KotodamaQuantity, "function");
  assert.throws(() => browserSdk.NumericV1.decodeQuantityJson("1.0"), {
    code: "invalid_text",
  });
  assert.throws(() => browserDistSdk.NumericV1.decodeQuantityJson("1.0"), {
    code: "invalid_text",
  });
});

test("ToriiBrowserClient rejects noncanonical asset and RWA quantity readbacks", async () => {
  const cases = [
    {
      payload: {
        next_cursor: null,
        items: [{ id: "asset", value: "01" }],
      },
      invoke: (client) => client.explorerAssets.list(),
    },
    {
      payload: {
        next_cursor: null,
        items: [{ id: "rwa", quantity: "1", held_quantity: "0.0" }],
      },
      invoke: (client) => client.explorerRwas.list(),
    },
  ];
  for (const entry of cases) {
    const client = new ToriiBrowserClient("https://torii.example", {
      fetchImpl: async () => jsonResponse(entry.payload),
    });
    await assert.rejects(
      () => entry.invoke(client),
      /canonical (?:non-negative )?Kotodama V1 quantity/u,
    );
  }
});

test("ToriiBrowserClient statically imports only named browser-safe Norito APIs", () => {
  const source = readFileSync(
    new URL("../src/toriiBrowserClient.js", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /import\s*\{[^}]*noritoDecodeBlockProofs[^}]*noritoEncodeMultisigProposeRequest[^}]*\}\s*from\s*["']\.\/norito\.js["']/su,
  );
  assert.doesNotMatch(source, /import\s*\(\s*["']\.\/norito\.js["']\s*\)/u);
  assert.doesNotMatch(source, /import\s+\*\s+as\s+\w+\s+from\s+["']\.\/norito\.js["']/u);
});

test("ToriiBrowserClient source and dist use only first-release multisig proposal routes", () => {
  for (const relativePath of [
    "../src/toriiBrowserClient.js",
    "../dist/toriiBrowserClient.js",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(
      source,
      /["']\/v1\/multisig\/proposals\/(?:list|get|search|lookup)["']/,
      `${relativePath} must not retain retired multisig proposal paths`,
    );
    assert.doesNotMatch(
      source,
      /\b(?:listMultisigProposals|getMultisigProposal)\b/,
      `${relativePath} must not retain retired multisig proposal methods`,
    );
    assert.match(source, /["']\/v1\/multisig\/proposals\/query["']/);
    assert.match(source, /["']\/v1\/multisig\/proposals\/resolve["']/);
    assert.match(source, /\bqueryMultisigProposals\b/);
    assert.match(source, /\bresolveMultisigProposal\b/);
  }
});

test("ToriiBrowserClient resolves aliases with JSON body", async () => {
  const fetchImpl = async (url, init) => {
    assert.equal(String(url), "https://torii.example/v1/aliases/resolve");
    assert.equal(init.method, "POST");
    assert.deepEqual(JSON.parse(init.body), { alias: "treasury@boi.is2" });
    return jsonResponse({ resolved: true, account_id: "account" });
  };
  const client = new ToriiBrowserClient("https://torii.example", { fetchImpl });
  const payload = await client.resolveAlias("treasury@boi.is2");
  assert.deepEqual(payload, { resolved: true, account_id: "account" });
});

test("ToriiBrowserClient posts selector-explicit multisig proposal reads", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse(
      calls.length === 1
        ? { resolved_multisig_account_id: FIXTURE_ALICE_ID, proposals: [] }
        : {
            resolved_multisig_account_id: FIXTURE_ALICE_ID,
            proposal_id: "a".repeat(64),
            instructions_hash: "a".repeat(64),
            proposal: { approvals: [], proposed_at_ms: 1 },
          },
    );
  };
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl,
    networkId: QUERY_NETWORK_ID,
  });

  await client.queryMultisigProposals(
    {
      multisigAccountAlias: "cbdc@banka",
      status: ["collecting_signatures"],
      cursor: "page-1",
      limit: 25,
    },
    canonicalReadOptions(),
  );
  await client.resolveMultisigProposal(
    {
      multisigAccountAlias: "cbdc@banka",
      instructionsHash: "a".repeat(64),
    },
    canonicalReadOptions(),
  );

  assert.equal(calls[0].url, "https://torii.example/v1/multisig/proposals/query");
  assert.notEqual(calls[0].url, "https://torii.example/v1/multisig/proposals/list");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    multisig_account_alias: "cbdc@banka",
    status: ["COLLECTING_SIGNATURES"],
    cursor: "page-1",
    limit: 25,
  });
  assert.equal(calls[1].url, "https://torii.example/v1/multisig/proposals/resolve");
  assert.notEqual(calls[1].url, "https://torii.example/v1/multisig/proposals/get");
  assert.equal(calls[1].init.method, "POST");
  assert.equal(calls[1].init.redirect, "error");
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    multisig_account_alias: "cbdc@banka",
    instructions_hash: "a".repeat(64),
  });
});

test("ToriiBrowserClient rejects unsupported multisig proposal statuses before fetch", () => {
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      throw new Error("fetch should not be invoked");
    },
  });

  assert.throws(
    () =>
      client.queryMultisigProposals({
        multisigAccountAlias: "cbdc@banka",
        status: ["READY_TO_SUBMIT"],
      }),
    /must be one of COLLECTING_SIGNATURES, FINALIZED, CANCELED, EXPIRED/,
  );
});

test("ToriiBrowserClient rejects implicit and ambiguous multisig selectors before fetch", () => {
  let calls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      calls += 1;
      throw new Error("fetch should not be invoked");
    },
  });

  assert.throws(() => client.queryMultisigProposals({}), /requires exactly one/);
  assert.throws(
    () =>
      client.queryMultisigProposals({
        multisigAccountId: FIXTURE_ALICE_ID,
        multisigAccountAlias: "cbdc@banka",
      }),
    /requires exactly one/,
  );
  assert.throws(
    () => client.resolveMultisigProposal(FIXTURE_ALICE_ID, "b".repeat(64)),
    /must be an object/,
  );
  assert.throws(
    () =>
      client.resolveMultisigProposal({
        multisigAccountId: FIXTURE_ALICE_ID,
        proposalId: "b".repeat(64),
        instructionsHash: "b".repeat(64),
      }),
    /requires exactly one/,
  );
  assert.equal(calls, 0);
});

test("ToriiBrowserClient submits multisig Norito payloads to registered routes", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    return jsonResponse({
      ok: true,
      resolved_multisig_account_id: FIXTURE_ALICE_ID,
      submitted: false,
    });
  };
  const client = new ToriiBrowserClient("https://torii.example", { networkPrefix: 753, fetchImpl });

  await client.submitMultisigPropose({
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    feePayment: AUTHORITY_FEE_PAYMENT,
    instructions: [{ Custom: { payload: { probe: true } } }],
  });
  await client.submitMultisigContractCallPropose({
    multisigAccountAlias: "cbdc@banka",
    signerAccountId: FIXTURE_ALICE_ID,
    contractAlias: "apps_review::universal",
    entrypoint: "execute",
    payload: { probe: true },
    feePayment: AUTHORITY_FEE_PAYMENT,
  });
  await client.submitMultisigContractCallApprove({
    multisigAccountId: FIXTURE_ALICE_ID,
    signerAccountId: FIXTURE_BOB_ID,
    proposalId: "e".repeat(64),
    contract_alias: "apps_mint_request::sbp",
    entrypoint: "create_mint_request",
    payload: { amount: 111 },
    feePayment: AUTHORITY_FEE_PAYMENT,
  });

  assert.equal(calls[0].url, "https://torii.example/v1/multisig/propose");
  assert.equal(calls[0].init.headers["Content-Type"], "application/x-norito");
  assert.equal(calls[1].url, "https://torii.example/v1/contracts/call/multisig/propose");
  assert.equal(calls[1].init.headers["Content-Type"], "application/x-norito");
  assert.equal(calls[2].url, "https://torii.example/v1/contracts/call/multisig/approve");
  assert.equal(calls[2].init.headers["Content-Type"], "application/x-norito");
});

test("ToriiBrowserClient requires canonical raw lowercase receipt identities", async () => {
  const signedTransaction = compactHashSignedTransactionFixture();
  const entrypointHash = browserSignedTransactionHashHex(signedTransaction, 753);

  const correctHeaders = {
    "x-iroha-entrypoint-hash": entrypointHash,
    "x-iroha-signed-transaction-hash": entrypointHash,
  };
  let acceptedInit;
  const acceptedClient = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async (_url, init) => {
      acceptedInit = init;
      return jsonResponse(
        { accepted: true },
        { status: 202, headers: correctHeaders },
      );
    },
  });
  assert.deepEqual(await acceptedClient.submitTransaction(signedTransaction), {
    accepted: true,
  });
  assert.equal(acceptedInit.redirect, "error");

  const forgedHash = "01".repeat(32);
  for (const [label, override, expectedHeader, message] of [
    [
      "forged entrypoint hash",
      { "x-iroha-entrypoint-hash": forgedHash },
      "x-iroha-entrypoint-hash",
      "does not match",
    ],
    [
      "forged signed transaction hash",
      { "x-iroha-signed-transaction-hash": forgedHash },
      "x-iroha-signed-transaction-hash",
      "does not match",
    ],
    [
      "coalesced signed transaction hash",
      { "x-iroha-signed-transaction-hash": `${entrypointHash}, ${entrypointHash}` },
      "x-iroha-signed-transaction-hash",
      "exactly once",
    ],
    [
      "uppercase entrypoint hash",
      { "x-iroha-entrypoint-hash": entrypointHash.toUpperCase() },
      "x-iroha-entrypoint-hash",
      "exactly once",
    ],
  ]) {
    const client = new ToriiBrowserClient("https://torii.example", {
      networkPrefix: 753,
      fetchImpl: async () =>
        jsonResponse(
          { accepted: true },
          { status: 202, headers: { ...correctHeaders, ...override } },
        ),
    });
    await assert.rejects(
      client.submitTransaction(signedTransaction),
      new RegExp(`${expectedHeader}.*${message}`, "u"),
      label,
    );
  }

  for (const missing of Object.keys(correctHeaders)) {
    const headers = { ...correctHeaders };
    delete headers[missing];
    const client = new ToriiBrowserClient("https://torii.example", {
      networkPrefix: 753,
      fetchImpl: async () => jsonResponse({ accepted: true }, { status: 202, headers }),
    });
    await assert.rejects(
      client.submitTransaction(signedTransaction),
      new RegExp(`${missing}.*exactly once`, "u"),
    );
  }
});

for (const status of [200, 201, 204]) {
  test(`ToriiBrowserClient rejects noncanonical HTTP ${status} transaction admission`, async () => {
    const signedTransaction = compactHashSignedTransactionFixture();
    let attempts = 0;
    const client = new ToriiBrowserClient("https://torii.example", {
      networkPrefix: 753,
      fetchImpl: async () => {
        attempts += 1;
        return status === 204
          ? new Response(null, { status })
          : jsonResponse({ accepted: true }, { status });
      },
    });

    await assert.rejects(
      () => client.submitTransaction(signedTransaction),
      (error) => error instanceof ToriiHttpError && error.status === status,
    );
    assert.equal(attempts, 1);
  });
}

test("ToriiBrowserClient keeps transaction admission statuses immutable", () => {
  const signedTransaction = compactHashSignedTransactionFixture();
  let attempts = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async () => {
      attempts += 1;
      return jsonResponse({ accepted: true }, { status: 202 });
    },
  });

  for (const successStatuses of [[200], [202], [200, 202]]) {
    assert.throws(
      () => client.submitTransaction(signedTransaction, { successStatuses }),
      /submitTransaction options contains unsupported option successStatuses/u,
    );
  }
  assert.equal(attempts, 0);
});

for (const redirectStatus of [307, 308]) {
  test(`ToriiBrowserClient rejects transaction ${redirectStatus} without redirecting`, async () => {
    const signedTransaction = compactHashSignedTransactionFixture();
    let attempts = 0;
    const client = new ToriiBrowserClient("https://torii.example", {
      networkPrefix: 753,
      fetchImpl: async (_url, init) => {
        attempts += 1;
        assert.equal(init.redirect, "error");
        return jsonResponse(
          { redirect: true },
          {
            status: redirectStatus,
            headers: { location: "https://redirect.example/replayed" },
          },
        );
      },
    });

    await assert.rejects(
      () => client.submitTransaction(signedTransaction),
      (error) =>
        error instanceof ToriiHttpError &&
        error.status === redirectStatus,
    );
    assert.equal(attempts, 1);
  });
}

test("ToriiBrowserClient rejects redirects for caller-supplied nonce headers", async () => {
  let attempts = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async (_url, init) => {
      attempts += 1;
      assert.equal(init.redirect, "error");
      return jsonResponse(
        { redirect: true },
        {
          status: 307,
          headers: { location: "https://redirect.example/replayed-query" },
        },
      );
    },
  });

  await assert.rejects(
    () =>
      client._json("POST", "/query", {
        body: { query: "signed" },
        headers: { "X-Iroha-Nonce": "caller-generated-nonce" },
      }),
    (error) => error instanceof ToriiHttpError && error.status === 307,
  );
  assert.equal(attempts, 1);
});

test("ToriiBrowserClient waits for exact global state-resolved Applied finality", async () => {
  const hash = "ab".repeat(32);
  const payloads = [
    {
      hash,
      status: { kind: "Applied", block_height: 17 },
      scope: "global",
      resolved_from: "queue",
    },
    {
      hash,
      status: { kind: "Applied", block_height: 17 },
      scope: "global",
      resolved_from: "cache",
    },
    {
      hash,
      status: { kind: "Applied", block_height: 17 },
      scope: "global",
      resolved_from: "state",
    },
  ];
  const urls = [];
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async (url) => {
      urls.push(String(url));
      return jsonResponse(payloads.shift());
    },
  });

  const status = await client.waitForTransactionStatus(hash, {
    intervalMs: 0,
    maxAttempts: 3,
  });

  assert.equal(status.status.kind, "Applied");
  assert.equal(status.scope, "global");
  assert.equal(status.resolved_from, "state");
  assert.equal(urls.length, 3);
  for (const url of urls) {
    assert.equal(
      url,
      `https://torii.example/v1/pipeline/transactions/status?hash=${hash}&scope=global`,
    );
  }
});

test("ToriiBrowserClient treats Rejected and Expired as fixed failures", async () => {
  for (const kind of ["Rejected", "Expired"]) {
    for (const resolvedFrom of ["queue", "cache", "state"]) {
      const hash = kind === "Rejected" ? "ad".repeat(32) : "af".repeat(32);
      const client = new ToriiBrowserClient("https://torii.example", {
        fetchImpl: async () => jsonResponse({
          hash,
          status: { kind },
          scope: "global",
          resolved_from: resolvedFrom,
        }),
      });
      await assert.rejects(
        client.waitForTransactionStatus(hash, { intervalMs: 0, maxAttempts: 2 }),
        new RegExp(`fixed failure status ${kind}`, "u"),
      );
    }
  }
});

test("ToriiBrowserClient requires exact lowercase full transaction hashes", async () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return new Response("", { status: 404 });
    },
  });
  for (const hash of [
    "aa".repeat(32),
    "AB".repeat(32),
    `0x${"ab".repeat(32)}`,
    `${"ab".repeat(32)} `,
    "ab".repeat(31),
    new Uint8Array(32),
  ]) {
    await assert.rejects(
      client.getTransactionStatus(hash),
      /exact canonical lowercase 32-byte Iroha hash/u,
    );
    await assert.rejects(
      client.waitForTransactionStatus(hash, { intervalMs: 0, maxAttempts: 1 }),
      /exact canonical lowercase 32-byte Iroha hash/u,
    );
  }
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient rejects a noncanonical pipeline response hash", async () => {
  const hash = "cd".repeat(32);
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () =>
      jsonResponse({
        hash: hash.toUpperCase(),
        status: { kind: "Applied", block_height: 1 },
        scope: "global",
        resolved_from: "state",
      }),
  });

  await assert.rejects(
    client.getTransactionStatus(hash),
    /exact canonical lowercase 32-byte Iroha hash/u,
  );
});

test("ToriiBrowserClient rejects malformed Applied envelopes", async () => {
  const hash = "cd".repeat(32);
  for (const [payload, pattern] of [
    [
      {
        hash: "ef".repeat(32),
        status: { kind: "Applied", block_height: 1 },
        scope: "global",
        resolved_from: "state",
      },
      /does not match the requested transaction/u,
    ],
    [
      {
        hash,
        status: { kind: "Applied", block_height: 0 },
        scope: "global",
        resolved_from: "state",
      },
      /block_height must be a positive safe integer/u,
    ],
    [
      {
        hash,
        status: { kind: "Applied", block_height: 1 },
        scope: "auto",
        resolved_from: "state",
      },
      /scope is not a current status scope/u,
    ],
  ]) {
    const client = new ToriiBrowserClient("https://torii.example", {
      fetchImpl: async () => jsonResponse(payload),
    });
    await assert.rejects(
      client.waitForTransactionStatus(hash, { intervalMs: 0, maxAttempts: 1 }),
      pattern,
    );
  }
});

test("ToriiBrowserClient rejects retired nested status details", async () => {
  const hash = "13".repeat(32);
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () =>
      jsonResponse({
        hash,
        status: { kind: "Queued", content: { Committed: true } },
        scope: "global",
        resolved_from: "queue",
      }),
  });

  await assert.rejects(
    client.waitForTransactionStatus(hash, { intervalMs: 0, maxAttempts: 1 }),
    /retired or unsupported fields: content/u,
  );
});

test("ToriiBrowserClient keeps diagnostic scopes separate from global-only waits", async () => {
  const hash = "57".repeat(32);
  const urls = [];
  const client = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async (url) => {
      urls.push(String(url));
      return new Response("", { status: 404 });
    },
  });

  assert.equal(await client.getTransactionStatus(hash), null);
  assert.equal(
    await client.getTransactionStatus(hash, { scope: undefined }),
    null,
  );
  assert.equal(await client.getTransactionStatus(hash, { scope: "local" }), null);
  assert.deepEqual(urls, [
    `https://torii.example/v1/pipeline/transactions/status?hash=${hash}&scope=global`,
    `https://torii.example/v1/pipeline/transactions/status?hash=${hash}&scope=global`,
    `https://torii.example/v1/pipeline/transactions/status?hash=${hash}&scope=local`,
  ]);
  for (const scope of [null, "", "auto"]) {
    await assert.rejects(
      client.getTransactionStatus(hash, { scope }),
      /must be local or global/u,
    );
  }
  for (const scope of [undefined, null, "global"]) {
    await assert.rejects(
      client.waitForTransactionStatus(hash, { scope }),
      /scope is not supported/u,
    );
  }

  let submissions = 0;
  const submittingClient = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async () => {
      submissions += 1;
      return new Response("", { status: 204 });
    },
  });
  for (const scope of [undefined, null, "global"]) {
    await assert.rejects(
      submittingClient.submitTransactionAndWait(Uint8Array.from([1, 2]), {
        scope,
      }),
      /scope is not supported/u,
    );
  }
  assert.equal(submissions, 0);
});

test("ToriiBrowserClient transaction finality policy cannot be overridden", async () => {
  const hash = "57".repeat(32);
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async () => {
      fetchCalls += 1;
      return new Response(null, { status: 404 });
    },
  });

  for (const field of ["successStatuses", "failureStatuses", "terminalStatuses"]) {
    const options = { [field]: ["Committed"] };
    await assert.rejects(
      client.getTransactionStatus(hash, options),
      new RegExp(`unsupported option ${field}`, "u"),
    );
    await assert.rejects(
      client.waitForTransactionStatus(hash, options),
      new RegExp(`unsupported option ${field}`, "u"),
    );
    await assert.rejects(
      client.submitTransactionAndWait(Uint8Array.from([1, 2]), options),
      new RegExp(`unsupported option ${field}`, "u"),
    );
  }
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient route success statuses cannot be overridden", async () => {
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    networkPrefix: 753,
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse({ accepted: true }, { status: 500 });
    },
  });

  assert.throws(
    () => client.getAccount(FIXTURE_ALICE_ID, { successStatuses: [500] }),
    /unsupported option successStatuses/u,
  );
  await assert.rejects(
    client.submitMultisigPropose({}, { successStatuses: [500] }),
    /unsupported option successStatuses/u,
  );
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient polling controls reject coercive integers", async () => {
  const hash = "5b".repeat(32);
  let fetchCalls = 0;
  const client = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return new Response(null, { status: 404 });
    },
  });

  for (const options of [
    { intervalMs: true },
    { intervalMs: [1] },
    { timeoutMs: true },
    { timeoutMs: 1.5 },
    { maxAttempts: [1] },
  ]) {
    await assert.rejects(
      client.waitForTransactionStatus(hash, options),
      /safe integer/u,
    );
  }
  assert.equal(fetchCalls, 0);
});

test("ToriiBrowserClient status reads accept only exact HTTP 200 or 404", async () => {
  const hash = "59".repeat(32);
  for (const status of [202, 204]) {
    const client = new ToriiBrowserClient("https://torii.example", {
      fetchImpl: async () => new Response(null, { status }),
    });
    await assert.rejects(
      client.getTransactionStatus(hash),
      (error) => error instanceof ToriiHttpError && error.status === status,
    );
  }

  const empty = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => new Response("", {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  });
  await assert.rejects(empty.getTransactionStatus(hash));

  const missing = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => new Response(null, { status: 404 }),
  });
  assert.equal(await missing.getTransactionStatus(hash), null);
});

const typedSumeragiBrowserClients = Object.freeze([
  ["source", ToriiBrowserClient, BROWSER_OPERATOR_CONTEXT],
  ["dist", browserDistSdk.ToriiBrowserClient, DIST_BROWSER_OPERATOR_CONTEXT],
]);









test("ToriiBrowserClient Sumeragi reads require fresh operator auth before dispatch", async () => {
  let calls = 0;
  const missing = new ToriiBrowserClient("https://torii.example", {
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({});
    },
  });
  assert.throws(
    () => missing.getSumeragiStatus(),
    /requires an immutable OperatorSigningContext/u,
  );
  assert.equal(calls, 0);

  const signedCalls = [];
  const signed = new ToriiBrowserClient("https://torii.example", {
    operatorSigningContext: BROWSER_OPERATOR_CONTEXT,
    fetchImpl: async (url, init) => {
      signedCalls.push([String(url), init]);
      return jsonResponse({});
    },
  });
  await signed.getSumeragiStatus();
  assert.equal(signedCalls.length, 1);
  assert.equal(signedCalls[0][0], "https://torii.example/v1/sumeragi/status");
  assert.equal(signedCalls[0][1].redirect, "error");
  assert.equal(signedCalls[0][1].body, undefined);
  assert.ok(signedCalls[0][1].headers["X-Iroha-Operator-Signature"]);

  const fallback = new ToriiBrowserClient("https://torii.example", {
    operatorSigningContext: BROWSER_OPERATOR_CONTEXT,
    defaultHeaders: { Authorization: "Bearer retired" },
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({});
    },
  });
  await assert.rejects(
    fallback.getSumeragiStatus(),
    /generated signing/u,
  );
  assert.equal(calls, 0);
});
