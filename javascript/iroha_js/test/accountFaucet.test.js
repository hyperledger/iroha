import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { createHash, scryptSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";

import {
  claimFaucet,
  faucetLeadingZeroBits,
  faucetPowChallenge,
  faucetPowDigest,
  faucetPuzzleChallenge,
  solveFaucetPuzzle,
} from "../src/accountFaucet.js";
import { AccountAddress } from "../src/address.js";
import { NetworkId } from "../src/networkId.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { makeNativeTest, nativeBinding } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: ["accountFaucetBindingJson", "verifyAccountFaucetPreparedTransactionJson"],
});

const PREFIX = 369;
const NETWORK_ID = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
const ACCOUNT = AccountAddress.fromAccount({
  publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(0x41)),
  algorithm: "ed25519",
}).toI105(PREFIX);
const FAUCET = AccountAddress.fromAccount({
  publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(0x42)),
  algorithm: "ed25519",
}).toI105(PREFIX);
const XOR = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const ANCHOR_HASH = "a1".repeat(31) + "a3";

function puzzle(overrides = {}) {
  return {
    algorithm: "scrypt-leading-zero-bits-v1",
    network_id: NETWORK_ID.toString(),
    chain_discriminant: PREFIX,
    difficulty_bits: 3,
    anchor_height: 42,
    anchor_block_hash_hex: ANCHOR_HASH,
    challenge_salt_hex: null,
    scrypt_log_n: 4,
    scrypt_r: 8,
    scrypt_p: 1,
    max_anchor_age_blocks: 6,
    ...overrides,
  };
}

baseTest("faucet challenge binds the network, account, anchor and optional salt", () => {
  const height = Buffer.alloc(8);
  height.writeBigUInt64BE(42n);
  const expected = createHash("sha256")
    .update(Buffer.from("iroha:accounts:faucet:pow:v1"))
    .update(Buffer.from(NETWORK_ID.toBytes()))
    .update(Buffer.from(ACCOUNT, "utf8"))
    .update(height)
    .update(Buffer.from(ANCHOR_HASH, "hex"))
    .digest();
  const derived = faucetPuzzleChallenge(puzzle(), { accountId: ACCOUNT, networkId: NETWORK_ID });
  assert.deepEqual(derived.challenge, expected);
  assert.deepEqual(derived.scrypt, { N: 16, r: 8, p: 1 });
  const salted = faucetPuzzleChallenge(puzzle({ challenge_salt_hex: "07".repeat(32) }), {
    accountId: ACCOUNT,
    networkId: NETWORK_ID,
  });
  assert.notDeepEqual(salted.challenge, expected);
  assert.throws(
    () => faucetPuzzleChallenge(puzzle({ network_id: NetworkId.fromBytes(Buffer.alloc(32, 0x55)).toString() }), { accountId: ACCOUNT, networkId: NETWORK_ID }),
    /network_id/u,
  );
  assert.throws(
    () => faucetPuzzleChallenge(puzzle({ chain_discriminant: 753 }), { accountId: ACCOUNT, networkId: NETWORK_ID }),
    /chain_discriminant/u,
  );
  assert.throws(
    () => faucetPuzzleChallenge({ ...puzzle(), extra: 1 }, { accountId: ACCOUNT, networkId: NETWORK_ID }),
    /exactly the V1 fields/u,
  );
  assert.equal(faucetLeadingZeroBits(Buffer.from([0, 0x10, 0xff])), 11);
  assert.equal(faucetLeadingZeroBits(Buffer.from([0x80])), 0);
});

baseTest("faucet challenge and digest match the pinned Rust wallet vectors", async () => {
  // crates/iroha_wallet/src/faucet_pow.rs faucet_challenge_matches_v1_preimage_vector
  const challenge = faucetPowChallenge({
    networkId: NetworkId.fromBytes(
      Buffer.from("32c903e5b3497e34c2b844ebfe8a39c19e6cf8f95d44c1ffb8ba9dcb42f91149", "hex"),
    ),
    accountId: "sorau\uff9b1N\uff72\uff98\uff73dPBe\uff7cRo\uff78Q2\uff94g\uff7cQqe\uff76\uff8d\uff7d\uff81hRW2\uff7a\uff7fZ9\uff95\uff66U\uff85RX5NJYH53",
    anchorHeight: 68,
    anchorBlockHashHex: "d5c0016a6345e8ea379da42aab1fdc16ba82756e19e0b63c48c14735e8caf7ef",
  });
  assert.equal(challenge.toString("hex"), "21e547302359214b28f0d1e0b04b6aeaf62a0e597dbad018d93ab0ce6af81a05");
  // Salted challenge plus scrypt(nonce = u64 BE 1, N = 16, r = 1, p = 1) digest vector.
  const salted = faucetPowChallenge({
    networkId: NetworkId.parse("hash:77FB29D14745ADCCFDC14350E1A6FE6A10265798CC936A1DAFA7D2552AC3B9F7#EBDD"),
    accountId: "alice@test",
    anchorHeight: 42,
    anchorBlockHashHex: "4d7a5660c7f3f5fb9f0df1f6ee9ce4d2a0b8df4cb4aa9bb2f7cfbc4cb03e2b85",
    challengeSaltHex: "ab".repeat(32),
  });
  const digest = await faucetPowDigest(salted, "0000000000000001", { N: 16, r: 1, p: 1 });
  assert.equal(digest.toString("hex"), "651c3411aeadf70d44b6bffa97c40c667695c1e48b37c732e0c3f8e0db08a61b");
  assert.equal(faucetLeadingZeroBits(Uint8Array.from([0x00, 0x00, 0x10])), 19);
  assert.throws(
    () => faucetPowChallenge({ networkId: NETWORK_ID, accountId: ACCOUNT, anchorHeight: 1, anchorBlockHashHex: "AA".repeat(32) }),
    /lowercase/u,
  );
});

baseTest("faucet puzzles beyond the native proof-of-work budget are refused", () => {
  for (const overrides of [
    { scrypt_log_n: 20 },
    { scrypt_log_n: 16, scrypt_r: 8, scrypt_p: 8 },
    { difficulty_bits: 0 },
    { difficulty_bits: 257 },
    { algorithm: "scrypt-leading-zero-bits-v2" },
  ]) {
    assert.throws(
      () => faucetPuzzleChallenge(puzzle(overrides), { accountId: ACCOUNT, networkId: NETWORK_ID }),
      /budget|difficulty_bits|algorithm/u,
    );
  }
});

baseTest("faucet solver returns a big-endian nonce meeting the difficulty", async () => {
  const challenge = createHash("sha256").update("challenge").digest();
  const params = { difficultyBits: 6, scrypt: { N: 16, r: 8, p: 1 } };
  const nonceHex = await solveFaucetPuzzle(challenge, params, { concurrency: 3 });
  assert.match(nonceHex, /^[0-9a-f]{16}$/u);
  const digest = scryptSync(Buffer.from(nonceHex, "hex"), challenge, 32, params.scrypt);
  assert.ok(faucetLeadingZeroBits(digest) >= 6);
  await assert.rejects(
    solveFaucetPuzzle(challenge, { difficultyBits: 256, scrypt: params.scrypt }, { maxAttempts: 4 }),
    /exceeded 4 attempts/u,
  );
});

test("claimFaucet refetches stale puzzles and never submits an unauthenticated envelope", async () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json", import.meta.url),
      "utf8",
    ),
  ).vectors.find((vector) => vector.name === "faucet_prepared");
  const calls = [];
  let prepareCount = 0;
  const torii = new ToriiClient("https://taira.example", {
    localSigningContext: new LocalSigningContext(NETWORK_ID, PREFIX),
    fetchImpl: async (url, init) => {
      const path = new URL(url).pathname;
      calls.push({ path, method: init.method, body: init.body });
      const reply = (status, body) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      if (path === "/v1/accounts/faucet/policy") {
        return reply(200, {
          schema_version: 1,
          network_id: NETWORK_ID.toString(),
          network_prefix: PREFIX,
          authority: FAUCET,
          asset_definition_id: XOR,
          amount: "25000",
        });
      }
      if (path === "/v1/accounts/faucet/puzzle") {
        return reply(200, puzzle({ anchor_height: 42 + calls.length }));
      }
      if (path === "/v1/accounts/faucet/prepare") {
        prepareCount += 1;
        if (prepareCount === 1) {
          return reply(400, { code: "faucet_pow_anchor_stale", message: "stale" });
        }
        return reply(200, fixture.response);
      }
      return reply(500, { code: "unexpected", message: path });
    },
  });
  await assert.rejects(
    claimFaucet(torii, { accountId: ACCOUNT, networkId: NETWORK_ID }, { concurrency: 2 }),
    /prepared faucet|differs|substituted/u,
  );
  assert.deepEqual(
    calls.map(({ method, path }) => `${method} ${path}`),
    [
      "GET /v1/accounts/faucet/policy",
      "GET /v1/accounts/faucet/puzzle",
      "POST /v1/accounts/faucet/prepare",
      "GET /v1/accounts/faucet/puzzle",
      "POST /v1/accounts/faucet/prepare",
    ],
  );
  const prepare = JSON.parse(calls[4].body);
  assert.deepEqual(Object.keys(prepare), ["schema", "binding", "claim", "fee_payment"]);
  assert.equal(prepare.schema, "iroha.accounts.faucet.prepare.v1");
  assert.deepEqual(prepare.fee_payment, {
    payer: "authority",
    value: { charge_limits: [], gas_limit: null },
  });
  assert.equal(prepare.claim.account_id, ACCOUNT);
  assert.equal(prepare.claim.pow_anchor_height, 46);
  assert.match(prepare.claim.pow_nonce_hex, /^[0-9a-f]{16}$/u);
  const expectedBinding = JSON.parse(
    nativeBinding.accountFaucetBindingJson(
      JSON.stringify(prepare.claim),
      prepare.binding.request_id,
      prepare.binding.execution_expires_at_unix_ms,
    ),
  );
  assert.deepEqual(prepare.binding, expectedBinding);
  assert.equal(prepare.binding.kind, "faucet");
  assert.match(prepare.binding.semantic_hash_hex, /^[0-9a-f]{63}[13579bdf]$/u);
  assert.equal(
    JSON.parse(calls[2].body).binding.request_id,
    prepare.binding.request_id,
    "request identity is stable across puzzle retries",
  );
});

test("claimFaucet rejects a policy for another network and a non-canonical account", async () => {
  const torii = new ToriiClient("https://taira.example", {
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          schema_version: 1,
          network_id: NetworkId.fromBytes(Buffer.alloc(32, 0x55)).toString(),
          network_prefix: PREFIX,
          authority: FAUCET,
          asset_definition_id: XOR,
          amount: "1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  await assert.rejects(
    claimFaucet(torii, { accountId: ACCOUNT, networkId: NETWORK_ID }),
    /faucet policy network_id differs/u,
  );
  await assert.rejects(
    claimFaucet(torii, { accountId: ` ${ACCOUNT}`, networkId: NETWORK_ID }),
    /canonical I105/u,
  );
});
