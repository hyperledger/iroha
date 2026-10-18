import assert from "node:assert/strict";
import test from "node:test";
import { ed25519 } from "@noble/curves/ed25519";

import { ToriiBrowserClient } from "../src/toriiBrowserClient.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { NetworkId } from "../src/networkId.js";
import { ToriiHttpError } from "../src/toriiErrors.js";
import { canonicalRequestSignatureMessage } from "../src/canonicalRequest.js";
import {
  EXPLORER_TRANSACTION_PROOF_MAX_BYTES,
  decodeExplorerTransactionProof,
} from "../src/explorerTransactionProof.js";

const NETWORK = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const HASH = NetworkId.fromBytes(Buffer.alloc(32, 0x3b)).toString();
const OTHER_HASH = NetworkId.fromBytes(Buffer.alloc(32, 0x33)).toString();
const PRIVATE_KEY = Buffer.alloc(32, 7);
const ACCOUNT = "explorer@example.public";

function fixture() {
  return {
    version: 1,
    network_id: NETWORK.toString(),
    block_height: 73,
    block_header: {
      height: 73,
      prev_block_hash: OTHER_HASH,
      merkle_root: OTHER_HASH,
      da_proof_policies_hash: null,
      da_commitments_hash: null,
      da_pin_intents_hash: null,
      npos_effects_hash: null,
      creation_time_ms: 1_700_000_000_000,
      view_change_index: 0,
      confidential_features: null,
      execution_context_hash: null,
      global_beacon_pulse_hash: OTHER_HASH,
    },
    transaction: {
      block_hash: OTHER_HASH,
      entrypoint_hash: HASH,
      entrypoint_proof: { leaf_index: 1, audit_path: [OTHER_HASH, null] },
      entrypoint: { External: { metadata: { weight: 0.125, sequence: 9007199254740993n } } },
      output_hash: OTHER_HASH,
      output_proof: { leaf_index: 2, audit_path: [OTHER_HASH, OTHER_HASH] },
      output: { Network: { input_index: 1, result: { Ok: [] }, completions: [] } },
    },
    certificate: {
      consensus_header: "AQID",
      commit_qc: "BAU=",
      result_preimage: "Bg==",
    },
  };
}

function json(value) {
  return JSON.stringify(value, (_, item) => typeof item === "bigint" ? `${item}n` : item)
    .replace(/"(-?\d+)n"/gu, "$1");
}

function response(value = fixture(), headers = {}) {
  return new Response(typeof value === "string" ? value : json(value), {
    headers: { "content-type": "application/json", ...headers },
  });
}

for (const [label, construct] of [
  ["browser", (fetchImpl) => new ToriiBrowserClient("https://localhost:8080", {
    networkId: NETWORK, fetchImpl,
  })],
  ["Node", (fetchImpl) => new ToriiClient("https://localhost:8080", {
    localSigningContext: new LocalSigningContext(NETWORK, 753), fetchImpl,
  })],
]) {
  test(`${label} selective proof reads exact public route with lossless u64 and metadata`, async () => {
    const payload = fixture();
    payload.block_height = 9007199254740993n;
    payload.block_header.height = payload.block_height;
    payload.block_header.creation_time_ms = 18446744073709551615n;
    const captured = [];
    const client = construct(async (url, init) => {
      captured.push({ url: String(url), init });
      return response(payload);
    });
    const proof = await client.getExplorerTransactionProof(HASH);
    assert.equal(captured.length, 1);
    assert.equal(captured[0].url,
      `https://localhost:8080/v1/explorer/transactions/${HASH.slice(5, 69).toLowerCase()}/proof`);
    assert.equal(captured[0].init.method, "GET");
    assert.equal(captured[0].init.headers["X-Iroha-Signature"], undefined);
    assert.equal(proof.block_height, "9007199254740993");
    assert.equal(proof.block_header.height, "9007199254740993");
    assert.equal(proof.block_header.creation_time_ms, "18446744073709551615");
    assert.equal(proof.transaction.entrypoint.External.metadata.sequence, 9007199254740993n);
    assert.equal(proof.transaction.entrypoint.External.metadata.weight, 0.125);
    assert.equal(proof.transaction.entrypoint_proof.audit_path[0], OTHER_HASH);
    assert.deepEqual(proof.certificate, payload.certificate);
    assert.equal(Object.hasOwn(proof, "valid"), false);
  });

  test(`${label} proof rejects a different transaction or configured network`, async () => {
    for (const field of ["hash", "network"]) {
      const payload = fixture();
      if (field === "hash") payload.transaction.entrypoint_hash = OTHER_HASH;
      else payload.network_id = OTHER_HASH;
      const client = construct(async () => response(payload));
      await assert.rejects(client.getExplorerTransactionProof(HASH), /does not match/u);
    }
  });

  test(`${label} proof propagates hidden/private denial without fallback`, async () => {
    for (const status of [401, 403, 404]) {
      let calls = 0;
      const client = construct(async () => {
        calls += 1;
        return new Response("Access unavailable", { status });
      });
      await assert.rejects(client.getExplorerTransactionProof(HASH), (error) =>
        error instanceof ToriiHttpError && error.status === status);
      assert.equal(calls, 1);
    }
  });

  test(`${label} proof cancels an oversized response before consuming it`, async () => {
    let canceled = false;
    const client = construct(async () => new Response(new ReadableStream({
      cancel() { canceled = true; },
    }), {
      headers: {
        "content-type": "application/json",
        "content-length": String(EXPLORER_TRANSACTION_PROOF_MAX_BYTES + 1),
      },
    }));
    await assert.rejects(client.getExplorerTransactionProof(HASH), /limit|exceed/u);
    assert.equal(canceled, true);
  });

  test(`${label} proof bounds declared and streamed error bodies`, async () => {
    for (const declaredLength of [true, false]) {
      let canceled = false;
      const client = construct(async () => {
        const errorResponse = new Response(new ReadableStream({
          pull(controller) {
            if (!declaredLength) {
              controller.enqueue(new Uint8Array(EXPLORER_TRANSACTION_PROOF_MAX_BYTES + 1));
            }
          },
          cancel() { canceled = true; },
        }), {
          status: 503,
          headers: declaredLength
            ? { "content-length": String(EXPLORER_TRANSACTION_PROOF_MAX_BYTES + 1) } : {},
        });
        errorResponse.text = () => assert.fail("error bodies must use the bounded reader");
        errorResponse.json = () => assert.fail("error bodies must use the bounded reader");
        return errorResponse;
      });
      await assert.rejects(client.getExplorerTransactionProof(HASH), error => {
        if (label === "Node") {
          // Node already caps errors at 64 KiB and preserves the HTTP status.
          return error instanceof ToriiHttpError && error.status === 503 && error.bodyText === null;
        }
        return /limit|exceed/u.test(error.message);
      });
      assert.equal(canceled, true);
    }
  });

  test(`${label} proof rejects noncanonical hash before issuing a request`, async () => {
    let calls = 0;
    const client = construct(async () => { calls += 1; return response(); });
    for (const hash of [HASH.toLowerCase(), HASH.slice(0, -1) + (HASH.endsWith("0") ? "1" : "0"), "31".repeat(32)]) {
      await assert.rejects(async () => client.getExplorerTransactionProof(hash), /hash literal/u);
    }
    assert.equal(calls, 0);
  });
}

test("browser private proof signs freshly with default and per-request identities", async () => {
  const captured = [];
  const signed = [];
  const signer = (accountId) => ({ accountId, sign(input) {
    signed.push(input);
    return ed25519.sign(input.message, PRIVATE_KEY);
  } });
  const client = new ToriiBrowserClient("https://localhost:8080", {
    networkId: NETWORK,
    canonicalRequestAuth: signer(ACCOUNT),
    fetchImpl: async (url, init) => {
      captured.push({ url, init });
      return response();
    },
  });
  await client.getExplorerTransactionProof(HASH);
  await client.getExplorerTransactionProof(HASH);
  await client.getExplorerTransactionProof(HASH, {
    canonicalRequestAuth: signer("other@example.public"),
  });
  await client.getExplorerTransactionProof(HASH, { canonicalRequestAuth: null });
  assert.equal(signed.length, 3);
  assert.notEqual(signed[0].nonce, signed[1].nonce);
  assert.equal(captured[0].init.headers["X-Iroha-Account"], ACCOUNT);
  assert.equal(captured[2].init.headers["X-Iroha-Account"], "other@example.public");
  assert.equal(captured[3].init.headers["X-Iroha-Account"], undefined);
  for (const { init } of captured.slice(0, 3)) {
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
  }
  for (const input of signed) {
    assert.equal(input.networkId.equals(NETWORK), true);
    assert.equal(input.path, `/v1/explorer/transactions/${HASH.slice(5, 69).toLowerCase()}/proof`);
    assert.equal(input.method, "GET");
    assert.equal(input.body, "");
  }
});

test("Node private proof signs freshly for the configured network and supports per-call identity", async () => {
  const captured = [];
  const client = new ToriiClient("https://localhost:8080", {
    localSigningContext: new LocalSigningContext(NETWORK, 753),
    canonicalRequestAuth: { accountId: ACCOUNT, privateKey: PRIVATE_KEY },
    fetchImpl: async (url, init) => { captured.push({ url, init }); return response(); },
  });
  await client.getExplorerTransactionProof(HASH);
  await client.getExplorerTransactionProof(HASH);
  await client.getExplorerTransactionProof(HASH, {
    canonicalAuth: { accountId: "other@example.public", privateKey: PRIVATE_KEY },
  });
  await client.getExplorerTransactionProof(HASH, { canonicalAuth: null });
  assert.notEqual(captured[0].init.headers["X-Iroha-Nonce"], captured[1].init.headers["X-Iroha-Nonce"]);
  assert.equal(captured[0].init.headers["X-Iroha-Account"], ACCOUNT);
  assert.equal(captured[2].init.headers["X-Iroha-Account"], "other@example.public");
  assert.equal(captured[3].init.headers["X-Iroha-Account"], undefined);
  for (const { url, init } of captured.slice(0, 3)) {
    const parsed = new URL(url);
    const message = canonicalRequestSignatureMessage({
      networkId: NETWORK,
      method: "GET",
      path: parsed.pathname,
      query: parsed.search.slice(1),
      timestampMs: Number(init.headers["X-Iroha-Timestamp-Ms"]),
      nonce: init.headers["X-Iroha-Nonce"],
    });
    assert.equal(ed25519.verify(Buffer.from(init.headers["X-Iroha-Signature"], "base64"),
      message, ed25519.getPublicKey(PRIVATE_KEY)), true);
    assert.equal(init.redirect, "error");
  }
});

test("selective proof decoder rejects duplicate keys, fractional u64, malformed paths and certificates", () => {
  const mutations = [
    ["height mismatch", (value) => { value.block_header.height = 74; }, /height/u],
    ["unsigned overflow", (value) => { value.block_height = 1n << 64n; }, /range/u],
    ["fractional u64", (value) => { value.block_header.view_change_index = 0.5; }, /integer/u],
    ["long proof", (value) => { value.transaction.output_proof.audit_path = Array(33).fill(null); }, /32 siblings/u],
    ["negative index", (value) => { value.transaction.entrypoint_proof.leaf_index = -1; }, /range/u],
    ["unmarked hash", (value) => {
      value.transaction.output_hash = "hash:" + "22".repeat(32) + "#0000";
    }, /hash literal/u],
    ["wrong base64 padding", (value) => { value.certificate.commit_qc = "BAU"; }, /base64/u],
    ["noncanonical padding bits", (value) => { value.certificate.commit_qc = "BB=="; }, /base64/u],
    ["oversized QC", (value) => { value.certificate.commit_qc = Buffer.alloc(4097).toString("base64"); }, /base64/u],
    ["whole block leak", (value) => { value.block = { transactions: [] }; }, /exactly/u],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const value = fixture();
    mutate(value);
    assert.throws(() => decodeExplorerTransactionProof(json(value), HASH, NETWORK), pattern, label);
  }
  assert.throws(() => decodeExplorerTransactionProof(json(fixture()).replace('"version":1',
    '"version":1,"version":1'), HASH, NETWORK), /duplicate/u);
});
