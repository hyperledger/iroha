// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Node.js client for the public testnet faucet (`/v1/accounts/faucet*`, V1).
 *
 * Flow: read the faucet policy, fetch a proof-of-work puzzle, solve the scrypt
 * leading-zero-bits challenge, prepare the claim (Torii returns a faucet-signed
 * transaction envelope), authenticate that envelope natively against the trusted
 * policy, submit it verbatim, and wait for global state-resolved `Applied`.
 */

import { createHash, randomBytes, scrypt as scryptCallback } from "node:crypto";
import { Buffer } from "node:buffer";

import { AccountAddress } from "./address.js";
import { NetworkId } from "./networkId.js";
import { normalizeAccountId } from "./normalizers.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";
import { ToriiHttpError } from "./toriiErrors.js";

const POW_ALGORITHM = "scrypt-leading-zero-bits-v1";
const POW_DOMAIN = Buffer.from("iroha:accounts:faucet:pow:v1", "utf8");
const PREPARE_SCHEMA = "iroha.accounts.faucet.prepare.v1";
const AUTHORITY_FEE_PAYMENT = Object.freeze({
  payer: "authority",
  value: Object.freeze({ charge_limits: Object.freeze([]), gas_limit: null }),
});
const JSON_ACCEPT = Object.freeze({ Accept: "application/json" });
const JSON_REQUEST = Object.freeze({
  "Content-Type": "application/json",
  Accept: "application/json",
});
const RETRYABLE_PREPARE_CODES = new Set([
  "faucet_pow_anchor_stale",
  "faucet_pow_anchor_out_of_range",
  "faucet_pow_anchor_unknown",
  "faucet_pow_solution_invalid",
]);
const PUZZLE_FIELDS = [
  "algorithm",
  "anchor_block_hash_hex",
  "anchor_height",
  "chain_discriminant",
  "challenge_salt_hex",
  "difficulty_bits",
  "max_anchor_age_blocks",
  "network_id",
  "scrypt_log_n",
  "scrypt_p",
  "scrypt_r",
];

function scrypt(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

function exactHex(value, bytes, context) {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})+$/u.test(value) || value.length !== bytes * 2) {
    throw new TypeError(`${context} must be ${bytes} lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, "hex");
}

function safeInteger(value, context, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`${context} must be an integer in ${min}..=${max}`);
  }
  return value;
}

/** Count leading zero bits, most significant bit of byte 0 first. */
export function faucetLeadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

/**
 * Validate a `/v1/accounts/faucet/puzzle` response and derive its PoW challenge.
 *
 * challenge = SHA-256("iroha:accounts:faucet:pow:v1" || network id bytes ||
 * UTF-8 account id || u64 BE anchor height || anchor block hash [|| salt]).
 * @returns {{ challenge: Buffer, anchorHeight: number, difficultyBits: number, scrypt: { N: number, r: number, p: number } }}
 */
export function faucetPuzzleChallenge(puzzle, { accountId, networkId }) {
  if (puzzle === null || typeof puzzle !== "object" || Array.isArray(puzzle)) {
    throw new TypeError("faucet puzzle must be an object");
  }
  const keys = Object.keys(puzzle).sort();
  if (keys.length !== PUZZLE_FIELDS.length || keys.some((key, index) => key !== PUZZLE_FIELDS[index])) {
    throw new TypeError("faucet puzzle must contain exactly the V1 fields");
  }
  if (puzzle.algorithm !== POW_ALGORITHM) {
    throw new TypeError(`faucet puzzle algorithm must be ${POW_ALGORITHM}`);
  }
  if (puzzle.network_id !== networkId.toString()) {
    throw new Error("faucet puzzle network_id differs from the selected network");
  }
  const { chainDiscriminant } = AccountAddress.parseEncoded(accountId);
  if (puzzle.chain_discriminant !== chainDiscriminant) {
    throw new Error("faucet puzzle chain_discriminant differs from the account network prefix");
  }
  const anchorHeight = safeInteger(puzzle.anchor_height, "faucet puzzle anchor_height", { min: 1 });
  const difficultyBits = safeInteger(puzzle.difficulty_bits, "faucet puzzle difficulty_bits", { max: 256 });
  const logN = safeInteger(puzzle.scrypt_log_n, "faucet puzzle scrypt_log_n", { min: 1, max: 30 });
  const r = safeInteger(puzzle.scrypt_r, "faucet puzzle scrypt_r", { min: 1, max: 1024 });
  const p = safeInteger(puzzle.scrypt_p, "faucet puzzle scrypt_p", { min: 1, max: 1024 });
  safeInteger(puzzle.max_anchor_age_blocks, "faucet puzzle max_anchor_age_blocks");
  const height = Buffer.alloc(8);
  height.writeBigUInt64BE(BigInt(anchorHeight));
  const parts = [
    POW_DOMAIN,
    Buffer.from(networkId.toBytes()),
    Buffer.from(accountId, "utf8"),
    height,
    exactHex(puzzle.anchor_block_hash_hex, 32, "faucet puzzle anchor_block_hash_hex"),
  ];
  if (puzzle.challenge_salt_hex !== null) {
    parts.push(exactHex(puzzle.challenge_salt_hex, 32, "faucet puzzle challenge_salt_hex"));
  }
  return {
    challenge: createHash("sha256").update(Buffer.concat(parts)).digest(),
    anchorHeight,
    difficultyBits,
    scrypt: { N: 2 ** logN, r, p },
  };
}

/**
 * Find an 8-byte big-endian nonce whose scrypt digest meets the difficulty.
 * @returns {Promise<string>} lowercase nonce hex
 */
export async function solveFaucetPuzzle(challenge, { difficultyBits, scrypt: params }, options = {}) {
  const concurrency = options.concurrency ?? 4;
  const maxAttempts = options.maxAttempts ?? Math.min(2 ** Math.min(difficultyBits + 8, 40), Number.MAX_SAFE_INTEGER);
  const signal = options.signal;
  const scryptOptions = { ...params, maxmem: 256 * params.N * params.r + 1024 * 1024 };
  let next = 0n;
  let found = null;
  const worker = async () => {
    while (found === null) {
      if (signal?.aborted) throw signal.reason ?? new Error("faucet proof-of-work aborted");
      if (next >= BigInt(maxAttempts)) return;
      const nonce = Buffer.alloc(8);
      nonce.writeBigUInt64BE(next);
      next += 1n;
      const digest = await scrypt(nonce, challenge, 32, scryptOptions);
      if (found === null && faucetLeadingZeroBits(digest) >= difficultyBits) {
        found = nonce.toString("hex");
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  if (found === null) {
    throw new Error(`faucet proof-of-work exceeded ${maxAttempts} attempts`);
  }
  return found;
}

async function readJson(torii, response, context, signal) {
  const body = await torii._maybeJson(response, { context, signal });
  if (body === null || typeof body !== "object") {
    throw new Error(`${context} returned no JSON object`);
  }
  return body;
}

/**
 * Claim testnet funds for `accountId` through the V1 faucet.
 *
 * The prepared envelope is authenticated natively against the faucet policy
 * (`options.policy`, else the advertised policy of the selected network) before
 * it is submitted verbatim. A stale anchor or a solution invalidated by an
 * adaptive difficulty increase refetches the puzzle, up to `maxPuzzleAttempts`.
 *
 * @param {import("./toriiClient.js").ToriiClient} torii
 * @param {{ accountId: string, networkId: NetworkId | string }} request
 * @param {{ signal?: AbortSignal, maxPuzzleAttempts?: number, concurrency?: number, requestId?: string, executionTtlMs?: number, timeoutMs?: number, policy?: { authority: string, assetDefinitionId: string, amount: string } }} [options]
 * @returns {Promise<{ hash: string, blockHeight: number }>}
 */
export async function claimFaucet(torii, request, options = {}) {
  if (!torii || typeof torii._request !== "function" || typeof torii.waitForTransactionStatus !== "function") {
    throw new TypeError("torii must be a ToriiClient");
  }
  const accountId = normalizeAccountId(request?.accountId, "claimFaucet.accountId");
  if (accountId !== request.accountId) {
    throw new TypeError("claimFaucet.accountId must be the canonical I105 account literal");
  }
  const networkId = request.networkId instanceof NetworkId
    ? request.networkId
    : NetworkId.parse(request.networkId);
  const signal = options.signal;
  const requestId = options.requestId ?? randomBytes(32).toString("hex");
  if (!/^[0-9a-f]{64}$/u.test(requestId)) {
    throw new TypeError("claimFaucet options.requestId must be 64 lowercase hexadecimal characters");
  }
  const executionTtlMs = options.executionTtlMs ?? 10 * 60 * 1000;
  safeInteger(executionTtlMs, "claimFaucet options.executionTtlMs", { min: 1 });
  const maxPuzzleAttempts = options.maxPuzzleAttempts ?? 3;
  safeInteger(maxPuzzleAttempts, "claimFaucet options.maxPuzzleAttempts", { min: 1 });

  const policyResponse = await torii._request("GET", "/v1/accounts/faucet/policy", {
    headers: JSON_ACCEPT,
    signal,
  });
  await torii._expectStatus(policyResponse, [200]);
  const advertised = await readJson(torii, policyResponse, "faucet policy", signal);
  if (advertised.network_id !== networkId.toString()) {
    throw new Error("faucet policy network_id differs from the selected network");
  }
  const policy = options.policy ?? {
    authority: advertised.authority,
    assetDefinitionId: advertised.asset_definition_id,
    amount: advertised.amount,
  };
  const native = resolveNativeRuntimeBinding(defaultNativeRuntime);
  const expiresAt = Date.now() + executionTtlMs;

  for (let attempt = 1; ; attempt += 1) {
    const puzzleResponse = await torii._request("GET", "/v1/accounts/faucet/puzzle", {
      headers: JSON_ACCEPT,
      signal,
    });
    await torii._expectStatus(puzzleResponse, [200]);
    const puzzle = faucetPuzzleChallenge(
      await readJson(torii, puzzleResponse, "faucet puzzle", signal),
      { accountId, networkId },
    );
    const claim = {
      account_id: accountId,
      pow_anchor_height: puzzle.anchorHeight,
      pow_nonce_hex: await solveFaucetPuzzle(puzzle.challenge, puzzle, {
        concurrency: options.concurrency,
        signal,
      }),
    };
    const claimJson = JSON.stringify(claim);
    const bindingJson = native.accountFaucetBindingJson(claimJson, requestId, expiresAt);
    const prepareResponse = await torii._request("POST", "/v1/accounts/faucet/prepare", {
      headers: JSON_REQUEST,
      body: `{"schema":${JSON.stringify(PREPARE_SCHEMA)},"binding":${bindingJson},"claim":${claimJson},"fee_payment":${JSON.stringify(AUTHORITY_FEE_PAYMENT)}}`,
      signal,
    });
    try {
      await torii._expectStatus(prepareResponse, [200]);
    } catch (error) {
      if (
        error instanceof ToriiHttpError &&
        RETRYABLE_PREPARE_CODES.has(error.code) &&
        attempt < maxPuzzleAttempts
      ) {
        continue;
      }
      throw error;
    }
    const { bytes: preparedBytes } = await torii._readBoundedResponseBytes(
      prepareResponse,
      1024 * 1024,
      "faucet prepared transaction",
      { signal },
    );
    const preparedJson = Buffer.from(preparedBytes).toString("utf8");
    const hash = native.verifyAccountFaucetPreparedTransactionJson({
      networkId: Buffer.from(networkId.toBytes()),
      preparedJson,
      claimJson,
      bindingJson,
      policyAuthority: policy.authority,
      policyAssetDefinitionId: policy.assetDefinitionId,
      policyAmount: policy.amount,
    });
    const submitResponse = await torii._request("POST", "/v1/accounts/faucet", {
      headers: JSON_REQUEST,
      body: preparedJson,
      signal,
    });
    await torii._expectStatus(submitResponse, [200, 202]);
    const submitted = await readJson(torii, submitResponse, "faucet submit", signal);
    if (submitted.transaction_hash_hex !== hash) {
      throw new Error("faucet submit response names a different transaction");
    }
    if (submitted.outcome === "Rejected") {
      throw new Error(`faucet transaction ${hash} was rejected`);
    }
    const status = await torii.waitForTransactionStatus(hash, {
      signal,
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    });
    return { hash, blockHeight: status.status.block_height };
  }
}
