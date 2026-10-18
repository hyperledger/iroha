import { Buffer } from "buffer";
import {
  canonicalAuthAccountHeaderValue,
  requireCanonicalAuthAccount,
} from "./canonicalAccount.js";
import {
  canonicalRequestMessage,
  CANONICAL_REQUEST_MAX_METHOD_BYTES_V1,
  CANONICAL_REQUEST_MAX_PATH_BYTES_V1,
  CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1,
  CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1,
  canonicalQueryString,
} from "./canonicalMessage.js";
import {
  CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
  CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
  CANONICAL_REQUEST_MAX_WITNESS_BYTES_V1,
} from "./canonicalLimits.js";
import { preparedTransportQuery } from "./canonicalTransport.js";
import { randomBytes } from "./cryptoHash.js";
import { requireToriiNativeIdentity } from "./nativeAccountInspection.js";
import { signEd25519 } from "./crypto.js";
import { NetworkId, networkIdBytes } from "./networkId.js";

export { NetworkId };
export { withCanonicalReadRetry } from "./canonicalReadRetry.js";
export {
  canonicalRequestMessage,
  CANONICAL_REQUEST_MAX_METHOD_BYTES_V1,
  CANONICAL_REQUEST_MAX_PATH_BYTES_V1,
  CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1,
  CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1,
  canonicalQueryString,
};
export {
  CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
  CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
  CANONICAL_REQUEST_MAX_WITNESS_BYTES_V1,
};

const DEFAULT_JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json",
  Accept: "application/json",
});

const CANONICAL_REQUEST_NETWORK_DOMAIN = Buffer.from(
  "iroha.app.request.network.v1\0",
  "utf8",
);

function requireExactNonBlankString(value, field, context) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${field} is required for ${context}`);
  }
  if (value.trim() !== value) {
    throw new Error(`${field} must not contain surrounding whitespace for ${context}`);
  }
  if (
    field === "nonce" &&
    (Buffer.byteLength(value, "utf8") > 256 ||
      !Array.from(value).every((character) => {
        const code = character.codePointAt(0);
        return code >= 0x21 && code <= 0x7e;
      }))
  ) {
    throw new Error(`nonce must contain 1...256 non-whitespace ASCII bytes for ${context}`);
  }
  return value;
}

/**
 * Build canonical request bytes for signature verification, bound to one exact
 * genesis-derived network and freshness metadata.
 * @param {{networkId: import("./networkId.js").NetworkId, method: string, path: string, query?: string | URLSearchParams, body?: Buffer | ArrayBuffer | ArrayBufferView | string, timestampMs: number, nonce: string}} params
 * @returns {Buffer}
 */
export function canonicalRequestSignatureMessage({
  networkId,
  method,
  path,
  query,
  body,
  timestampMs,
  nonce,
}) {
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) {
    throw new RangeError("timestampMs must be a non-negative safe integer");
  }
  const checkedNonce = requireExactNonBlankString(
    nonce,
    "nonce",
    "canonical exact-network signatures",
  );
  const network = Buffer.from(networkIdBytes(networkId, "networkId"));
  const base = canonicalRequestMessage({ method, path, query, body });
  return Buffer.concat([
    CANONICAL_REQUEST_NETWORK_DOMAIN,
    network,
    base,
    Buffer.from(`\n${String(timestampMs)}\n${checkedNonce}`, "utf8"),
  ]);
}

/**
 * Build canonical signing headers for app-facing Torii endpoints.
 * `accountId` is an exact canonical I105 account or active canonical ASCII
 * alias. I105 is rendered as lowercase canonical hex in `X-Iroha-Account`;
 * ASCII aliases are carried unchanged.
 * @param {{accountId: string, networkId: import("./networkId.js").NetworkId, method: string, path: string, query?: string | URLSearchParams, body?: Buffer | ArrayBuffer | ArrayBufferView | string, privateKey: Buffer | ArrayBuffer | ArrayBufferView, timestampMs?: number, nonce?: string}} params
 * @returns {{ "X-Iroha-Account": string, "X-Iroha-Signature": string, "X-Iroha-Timestamp-Ms": string, "X-Iroha-Nonce": string }}
 */
export function buildCanonicalRequestHeaders({
  accountId,
  networkId,
  method,
  path,
  query,
  body,
  privateKey,
  timestampMs = Date.now(),
  nonce = randomBytes(16).toString("hex"),
}) {
  const checkedAccount = requireCanonicalAuthAccount(
    accountId,
    "accountId",
  );
  if (!privateKey) {
    throw new Error("privateKey is required for canonical headers");
  }
  const checkedNonce = requireExactNonBlankString(nonce, "nonce", "canonical headers");
  const signatureInput = {
    method,
    path,
    query: preparedTransportQuery(query),
    body,
    timestampMs,
    nonce: checkedNonce,
  };
  const message = canonicalRequestSignatureMessage({ networkId, ...signatureInput });
  const signature = signEd25519(message, privateKey);
  return {
    "X-Iroha-Account": canonicalAuthAccountHeaderValue(checkedAccount),
    "X-Iroha-Signature": Buffer.from(signature).toString("base64"),
    "X-Iroha-Timestamp-Ms": String(timestampMs),
    "X-Iroha-Nonce": checkedNonce,
  };
}

function normalizeHeadersInit(headers) {
  if (headers === undefined || headers === null) {
    return {};
  }
  const normalized = {};
  if (typeof Headers !== "undefined" && headers instanceof Headers) {
    for (const [key, value] of headers.entries()) {
      normalized[key] = value;
    }
    return normalized;
  }
  if (Array.isArray(headers)) {
    for (const [key, value] of headers) {
      normalized[String(key)] = String(value);
    }
    return normalized;
  }
  if (typeof headers[Symbol.iterator] === "function") {
    for (const [key, value] of headers) {
      normalized[String(key)] = String(value);
    }
    return normalized;
  }
  if (typeof headers === "object") {
    for (const [key, value] of Object.entries(headers)) {
      if (value !== undefined && value !== null) {
        normalized[key] = String(value);
      }
    }
    return normalized;
  }
  throw new Error("headers must be a Headers, iterable, or plain object");
}

function normalizeSignatureBase64(signature, context = "signature") {
  if (signature === undefined || signature === null) {
    throw new Error(`${context} must be returned by the canonical request signer`);
  }
  let payload;
  let canonical;
  if (typeof signature === "string") {
    if (
      !signature ||
      signature.length > 4 * Math.ceil(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 / 3) ||
      signature.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
        signature,
      )
    ) {
      throw new Error(`${context} must be exact padded standard-base64`);
    }
    payload = Buffer.from(signature, "base64");
    canonical = payload.toString("base64");
    if (canonical !== signature) {
      throw new Error(`${context} must be exact padded standard-base64`);
    }
  } else {
    const byteLength = ArrayBuffer.isView(signature)
      ? signature.byteLength
      : signature instanceof ArrayBuffer
        ? signature.byteLength
        : null;
    if (byteLength === null) {
      throw new TypeError(`${context} must be bytes or exact padded standard-base64`);
    }
    if (byteLength > CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1) {
      throw new RangeError(`${context} exceeds the canonical V1 signature limit`);
    }
    payload = ArrayBuffer.isView(signature)
      ? Buffer.from(signature.buffer, signature.byteOffset, signature.byteLength)
      : Buffer.from(signature);
    canonical = payload.toString("base64");
  }
  if (
    payload.length === 0 ||
    payload.length > CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 ||
    payload.every((byte) => byte === 0)
  ) {
    throw new RangeError(
      `${context} must contain 1...${CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1} non-zero signature bytes`,
    );
  }
  return canonical;
}

function splitPathAndQuery(path, query) {
  const pathText = String(path);
  if (pathText.includes("#")) {
    throw new TypeError("canonical request targets must not contain a URL fragment");
  }
  const queryIndex = pathText.indexOf("?");
  if (query !== undefined && query !== null) {
    return {
      path: queryIndex < 0 ? pathText : pathText.slice(0, queryIndex),
      query,
    };
  }
  if (queryIndex < 0) {
    return { path: pathText, query: undefined };
  }
  return {
    path: pathText.slice(0, queryIndex),
    query: pathText.slice(queryIndex + 1),
  };
}

function canonicalTargetFromPath({ path, query, baseUrl }) {
  const pathText = String(path);
  const absoluteUrlPattern = /^[a-z][a-z0-9+.-]*:\/\//i;
  if (absoluteUrlPattern.test(pathText)) {
    throw new TypeError(
      "canonical JSON request path must be root-relative; use baseUrl for the origin",
    );
  }
  if (!pathText.startsWith("/") || pathText.startsWith("//")) {
    throw new TypeError("canonical JSON request path must be exact root-relative text");
  }

  const target = splitPathAndQuery(pathText, query);
  if (!baseUrl) {
    return target;
  }

  const base = new URL(String(baseUrl));
  const basePath = base.pathname.replace(/\/+$/, "");
  const requestPath = String(target.path || "").replace(/^\/+/, "");
  const joinedPath = [basePath, requestPath].filter(Boolean).join("/");
  return {
    path: joinedPath ? `/${joinedPath}`.replace(/\/{2,}/g, "/") : "/",
    query: target.query,
  };
}

/**
 * Build fetch-compatible JSON request options signed with Torii canonical auth.
 *
 * The returned body string is the exact JSON payload covered by the signature.
 * Callers with private key bytes can pass `privateKey`; browser keystores can
 * pass an async `sign` callback and keep private keys out of application code.
 * `accountId` must be the exact canonical I105 account or active canonical
 * ASCII alias used as the auth header.
 *
 * @param {{accountId: string, networkId: import("./networkId.js").NetworkId, method?: string, path: string, baseUrl?: string, query?: string | URLSearchParams, body?: unknown, headers?: Headers | Array<[string, string]> | Record<string, string>, privateKey?: Buffer | ArrayBuffer | ArrayBufferView, sign?: (input: {message: Buffer, messageBase64: string, networkId: import("./networkId.js").NetworkId, method: string, path: string, query?: string | URLSearchParams, body: string, timestampMs: number, nonce: string}) => Promise<Buffer | ArrayBuffer | ArrayBufferView | string> | Buffer | ArrayBuffer | ArrayBufferView | string, timestampMs?: number, nonce?: string}} params
 * @returns {Promise<{method: string, headers: Record<string, string>, body: string}>}
 */
export async function buildCanonicalJsonRequest({
  accountId,
  nativeIdentity,
  networkId,
  method = "POST",
  path,
  baseUrl,
  query,
  body,
  bodyText,
  headers,
  privateKey,
  sign,
  timestampMs = Date.now(),
  nonce = randomBytes(16).toString("hex"),
}) {
  const inspected = nativeIdentity === undefined ? null : requireToriiNativeIdentity(
    nativeIdentity, { accountId, networkId, baseUrl },
  );
  const checkedAccount = inspected?.accountId ?? requireCanonicalAuthAccount(accountId, "accountId");
  if (!path) {
    throw new Error("path is required for canonical JSON requests");
  }
  const checkedNonce = requireExactNonBlankString(
    nonce,
    "nonce",
    "canonical JSON requests",
  );
  if (!privateKey && typeof sign !== "function") {
    throw new Error("privateKey or sign is required for canonical JSON requests");
  }
  const methodUpper = String(method).toUpperCase();
  const canonicalTarget = canonicalTargetFromPath({ path, query, baseUrl });
  canonicalTarget.query = preparedTransportQuery(canonicalTarget.query);
  if (bodyText !== undefined && (typeof bodyText !== "string" || body !== undefined)) {
    throw new TypeError("bodyText must be a pre-serialized JSON string and cannot be combined with body");
  }
  const bodyJson = bodyText ?? (body === undefined ? "" : JSON.stringify(body));
  const message = canonicalRequestSignatureMessage({
    networkId,
    method: methodUpper,
    path: canonicalTarget.path,
    query: canonicalTarget.query,
    body: bodyJson,
    timestampMs,
    nonce: checkedNonce,
  });
  const signatureBase64 = privateKey
    ? Buffer.from(signEd25519(message, privateKey)).toString("base64")
    : normalizeSignatureBase64(
        await sign({
          message,
          messageBase64: message.toString("base64"),
          networkId,
          method: methodUpper,
          path: canonicalTarget.path,
          query: canonicalTarget.query,
          body: bodyJson,
          timestampMs,
          nonce: checkedNonce,
        }),
      );
  return {
    method: methodUpper,
    headers: {
      ...DEFAULT_JSON_HEADERS,
      ...normalizeHeadersInit(headers),
      "X-Iroha-Account": inspected?.canonicalHex ?? canonicalAuthAccountHeaderValue(checkedAccount),
      "X-Iroha-Signature": signatureBase64,
      "X-Iroha-Timestamp-Ms": String(timestampMs),
      "X-Iroha-Nonce": checkedNonce,
    },
    body: bodyJson,
  };
}
