// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { setImmediate } from "node:timers/promises";
import { ed25519 } from "@noble/curves/ed25519";
import {
  buildCanonicalJsonRequest,
  NetworkId,
  withCanonicalReadRetry,
} from "../src/canonicalRequest.js";

const READ = { method: "POST", path: "/v1/multisig/proposals/query" };
const NOW = 1_800_000_000_000;
const refusal = (extra = {}) => Object.assign(new Error("capacity is busy"), {
  status: 429, code: "query_validation_failed", ...extra,
});

function mockClock(t) {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: NOW });
}

async function advance(t, milliseconds) {
  t.mock.timers.tick(milliseconds);
  await setImmediate();
}

test("capacity retries rebuild canonical signatures with fresh nonce and timestamp", async (t) => {
  mockClock(t);
  const requests = [];
  const attempts = [];
  const messages = [];
  const privateKey = new Uint8Array(32).fill(7);
  const publicKey = ed25519.getPublicKey(privateKey);
  const result = withCanonicalReadRetry({
    ...READ,
    operation: async (attempt) => {
      attempts.push(attempt);
      const request = await buildCanonicalJsonRequest({
        ...READ,
        accountId: "operator@wonderland",
        networkId: NetworkId.fromBytes(new Uint8Array(32).fill(0xa5)),
        body: { multisig_account_alias: "bank@wonderland" },
        sign: ({ message }) => {
          messages.push(message);
          return ed25519.sign(message, privateKey);
        },
      });
      requests.push(request);
      if (attempt < 2) throw refusal();
      return { proposals: [] };
    },
  });
  await setImmediate();
  assert.equal(requests.length, 1);
  await advance(t, 249);
  assert.equal(requests.length, 1);
  await advance(t, 1);
  assert.equal(requests.length, 2);
  await advance(t, 500);
  assert.deepEqual(await result, { proposals: [] });
  assert.deepEqual(attempts, [0, 1, 2]);
  assert.equal(new Set(requests.map(({ headers }) => headers["X-Iroha-Nonce"])).size, 3);
  assert.equal(new Set(requests.map(({ headers }) => headers["X-Iroha-Timestamp-Ms"])).size, 3);
  assert.equal(new Set(requests.map(({ body }) => body)).size, 1);
  requests.forEach(({ headers }, index) => {
    assert.ok(ed25519.verify(Buffer.from(headers["X-Iroha-Signature"], "base64"), messages[index], publicKey));
  });
});

test("supported GET and parameterized POST reads retry without widening route matching", async (t) => {
  mockClock(t);
  for (const [method, path] of [
    ["GET", "/v1/accounts?limit=100"],
    ["GET", "/v1/accounts/account%40bank/history?limit=100"],
    ["GET", `/v1/explorer/transactions/${"ab".repeat(32)}`],
    ["POST", "/v1/assets/asset%23bank/holders/query"],
    ["POST", "/v1/aliases/resolve"],
    ["POST", "/v1/assets/aliases/resolve"],
    ["POST", "/v1/controls/asset-transfer/query"],
  ]) {
    let calls = 0;
    const result = withCanonicalReadRetry({ method, path, operation: () => {
      if (++calls === 1) throw refusal({ code: "RATE_LIMITED" });
      return path;
    } });
    await advance(t, 250);
    assert.equal(await result, path);
    assert.equal(calls, 2);
  }
});

test("mutation and unknown targets execute once and preserve their failure", async () => {
  for (const [method, path] of [
    ["POST", "/v1/multisig/propose"],
    ["POST", "/v1/multisig/approve"],
    ["POST", "/v1/multisig/cancel"],
    ["POST", "/v1/transactions"],
    ["POST", "/v1/assets/transfer"],
    ["POST", "/v1/anything/query"],
    ["GET", "/v1/anything"],
    ["DELETE", "/v1/aliases/resolve"],
    ["POST", "https://torii.invalid/v1/aliases/resolve"],
    ["POST", "/v1/aliases/resolve#fragment"],
    ["GET", "/v1/accounts/../history"],
    ["GET", "/v1/accounts/%2e%2e/history"],
  ]) {
    let calls = 0;
    const error = refusal();
    await assert.rejects(withCanonicalReadRetry({ method, path, operation: () => {
      calls += 1;
      throw error;
    } }), (actual) => actual === error);
    assert.equal(calls, 1, `${method} ${path}`);
  }
});

test("authentication, validation, transport and untyped failures execute once", async () => {
  for (const error of [
    refusal({ status: 401 }), refusal({ status: 403 }), refusal({ status: 400 }),
    refusal({ status: 503 }), refusal({ code: "unrelated_error" }),
    refusal({ code: undefined }), refusal({ status: "429" }),
    new TypeError("Failed to fetch"),
  ]) {
    let calls = 0;
    await assert.rejects(withCanonicalReadRetry({ ...READ, operation: () => {
      calls += 1;
      throw error;
    } }), (actual) => actual === error);
    assert.equal(calls, 1);
  }
});

test("persistent refusal stops after three retries and preserves the last error", async (t) => {
  mockClock(t);
  const failures = [];
  const result = withCanonicalReadRetry({ ...READ, operation: () => {
    const error = refusal();
    failures.push(error);
    throw error;
  } });
  const rejected = assert.rejects(result, (error) => error === failures[3]);
  await advance(t, 250);
  await advance(t, 500);
  await advance(t, 1_000);
  await rejected;
  assert.equal(failures.length, 4);
});

test("Retry-After seconds, date and typed details delay the next fresh attempt", async (t) => {
  mockClock(t);
  for (const extra of [
    { retryAfter: "2" },
    { retryAfter: new Date(Date.now() + 2_000).toUTCString() },
    { retryAfterSeconds: 2 },
    { details: { retry_after_seconds: 2 } },
    { headers: new Headers({ "Retry-After": "2" }) },
  ]) {
    // Generate the HTTP date against this iteration's current clock.
    if (typeof extra.retryAfter === "string" && extra.retryAfter.includes(",")) {
      extra.retryAfter = new Date(Date.now() + 2_000).toUTCString();
    }
    let calls = 0;
    const result = withCanonicalReadRetry({ ...READ, operation: () => {
      if (++calls === 1) throw refusal(extra);
      return "ready";
    } });
    await advance(t, 1_999);
    assert.equal(calls, 1);
    await advance(t, 1);
    assert.equal(await result, "ready");
  }
});

test("Retry-After cannot exceed the remaining ten-second window or be shortened", async (t) => {
  mockClock(t);
  const tooLong = refusal({ retryAfter: "120" });
  let calls = 0;
  await assert.rejects(withCanonicalReadRetry({ ...READ, operation: () => {
    calls += 1;
    throw tooLong;
  } }), (error) => error === tooLong);
  assert.equal(calls, 1);

  const failures = [];
  const result = withCanonicalReadRetry({ ...READ, operation: () => {
    const error = refusal({ retryAfterSeconds: 4 });
    failures.push(error);
    throw error;
  } });
  const rejected = assert.rejects(result, (error) => error === failures[2]);
  await advance(t, 4_000);
  await advance(t, 4_000);
  await rejected;
  assert.equal(failures.length, 3);
});

test("invalid Retry-After falls back to finite exponential delays", async (t) => {
  mockClock(t);
  for (const retryAfter of ["-1", "not-a-date"]) {
    let calls = 0;
    const result = withCanonicalReadRetry({ ...READ, operation: () => {
      if (++calls === 1) throw refusal({ retryAfter });
      return "ready";
    } });
    await advance(t, 250);
    assert.equal(await result, "ready");
  }
});

test("abort before an attempt and during backoff preserves the abort reason", async (t) => {
  mockClock(t);
  for (const abortFirst of [true, false]) {
    const controller = new AbortController();
    const reason = new Error("session changed");
    let calls = 0;
    if (abortFirst) controller.abort(reason);
    const result = withCanonicalReadRetry({ ...READ, signal: controller.signal, operation: () => {
      calls += 1;
      throw refusal();
    } });
    const rejected = assert.rejects(result, (error) => error === reason);
    if (!abortFirst) controller.abort(reason);
    await rejected;
    await advance(t, 10_000);
    assert.equal(calls, abortFirst ? 0 : 1);
  }
});

test("abort during operation prevents accepting its late success", async () => {
  const controller = new AbortController();
  const reason = new Error("session changed");
  let finish;
  const result = withCanonicalReadRetry({ ...READ, signal: controller.signal,
    operation: () => new Promise((resolve) => { finish = resolve; }),
  });
  controller.abort(reason);
  finish("stale result");
  await assert.rejects(result, (error) => error === reason);
});
