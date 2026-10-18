// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

// These are read-only routes in iroha_torii_shared::route_catalog. Keep the
// allowlist explicit: a POST suffix or a caller-supplied method cannot establish
// that repeating a request is safe.
const READ_POST_PATHS = new Set([
  "/v1/multisig/spec",
  "/v1/multisig/proposals/query",
  "/v1/multisig/proposals/resolve",
  "/v1/aliases/resolve",
  "/v1/aliases/resolve-index",
  "/v1/aliases/by-account",
  "/v1/assets/aliases/resolve",
  "/v1/controls/asset-transfer/query",
  "/v1/accounts/query",
  "/v1/transactions/query",
]);
const READ_GET_PATHS = new Set([
  "/v1/accounts",
]);
const READ_POST_PATTERNS = [
  /^\/v1\/accounts\/[^/]+\/(?:history|transactions|assets|permissions)\/query$/u,
  /^\/v1\/assets\/[^/]+\/holders\/query$/u,
];
const READ_GET_PATTERNS = [
  /^\/v1\/accounts\/[^/]+(?:\/(?:history|transactions|assets|permissions|aliases))?$/u,
  /^\/v1\/assets\/[^/]+\/holders$/u,
  /^\/v1\/explorer\/transactions\/[0-9a-fA-F]{64}(?:\/proof)?$/u,
];
const RETRYABLE_CODES = new Set([
  "query_validation_failed",
  "query_capacity_exceeded",
  "capacity_limit",
  "authority_quota_exceeded",
  "request_rate_limited",
  "preauth_rate_limited",
  "rate_limited",
]);
const MAX_RETRIES = 3;
const MAX_RETRY_WAIT_MS = 10_000;
const INITIAL_RETRY_WAIT_MS = 250;

function isReadRoute(method, path) {
  if (typeof method !== "string" || typeof path !== "string" || path.includes("#")) {
    return false;
  }
  const pathname = path.split("?", 1)[0];
  if (!pathname.startsWith("/v1/") || /[\s\\]/u.test(pathname)) return false;
  // Fetch normalizes dot segments. Never classify one target then send another.
  if (new URL(pathname, "https://torii.invalid").pathname !== pathname) return false;
  if (method.toUpperCase() === "POST") {
    return READ_POST_PATHS.has(pathname) || READ_POST_PATTERNS.some((pattern) => pattern.test(pathname));
  }
  return method.toUpperCase() === "GET" && (
    READ_GET_PATHS.has(pathname) || READ_GET_PATTERNS.some((pattern) => pattern.test(pathname))
  );
}

function retryAfterMs(error) {
  const details = error.details;
  const seconds = error.retryAfterSeconds ?? details?.retry_after_seconds ?? details?.retryAfterSeconds;
  if (typeof seconds === "number" && Number.isFinite(seconds) && seconds >= 0) {
    return seconds * 1_000;
  }
  const raw = error.retryAfter ?? details?.retry_after ?? details?.retryAfter ??
    error.headers?.get?.("Retry-After");
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  const text = String(raw).trim();
  if (/^\d+(?:\.\d+)?$/u.test(text)) return Number(text) * 1_000;
  // Restrict date parsing to HTTP-date text; Date.parse also accepts negative
  // numbers and other strings that are not Retry-After dates.
  if (!/^[A-Za-z]{3}, /u.test(text)) return null;
  const date = Date.parse(text);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : null;
}

function checkAbort(signal) {
  if (!signal?.aborted) return;
  if (signal.reason !== undefined) throw signal.reason;
  const error = new Error("The request was aborted");
  error.name = "AbortError";
  throw error;
}

function waitForRetry(milliseconds, signal) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const cleanup = () => signal?.removeEventListener("abort", onAbort);
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      cleanup();
      try {
        checkAbort(signal);
      } catch (error) {
        reject(error);
      }
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

/**
 * Retry an allowlisted Torii read after an explicit HTTP 429 capacity refusal.
 * The operation must build and sign a fresh request on every invocation and
 * pass the signal to its transport. Attempts are zero-based, with at most three
 * retries and a ten-second retry window. Unknown routes and errors run once;
 * exhausted refusals retain the original error object. Successful responses,
 * writes, authentication failures and ambiguous transport failures are never
 * retried. Retry-After values beyond the remaining window return immediately.
 * @template T
 * @param {{method: string, path: string, signal?: AbortSignal, operation: (attempt: number) => T | Promise<T>}} options
 * @returns {Promise<T>}
 */
export async function withCanonicalReadRetry({ method, path, signal, operation }) {
  if (typeof operation !== "function") throw new TypeError("operation must be a function");
  const retryAllowed = isReadRoute(method, path);
  const startedAt = Date.now();
  let waitedMs = 0;
  for (let attempt = 0; ; attempt += 1) {
    checkAbort(signal);
    try {
      const result = await operation(attempt);
      checkAbort(signal);
      return result;
    } catch (error) {
      checkAbort(signal);
      if (!retryAllowed || attempt >= MAX_RETRIES || error?.status !== 429 ||
          typeof error.code !== "string" || !RETRYABLE_CODES.has(error.code.toLowerCase())) {
        throw error;
      }
      const elapsedMs = Math.max(waitedMs, Date.now() - startedAt);
      const delayMs = Math.max(INITIAL_RETRY_WAIT_MS * 2 ** attempt, retryAfterMs(error) ?? 0);
      if (!Number.isFinite(delayMs) || delayMs > MAX_RETRY_WAIT_MS - elapsedMs) throw error;
      await waitForRetry(delayMs, signal);
      waitedMs += delayMs;
      if (Math.max(waitedMs, Date.now() - startedAt) > MAX_RETRY_WAIT_MS) throw error;
    }
  }
}
