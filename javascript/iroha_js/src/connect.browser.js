import { x25519 } from "@noble/curves/ed25519";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { blake2b } from "@noble/hashes/blake2b";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { AccountAddress } from "./address.js";
import { crc64Xz } from "./crc64Xz.js";
import { verifyEd25519Strict } from "./ed25519Strict.js";
import { NetworkId, networkIdBytes } from "./networkId.js";

export { NetworkId };

/** Exact current binary FrameV1 + EnvelopeV1 + AEAD overhead for SignRequestTx. */
export const CONNECT_SIGN_REQUEST_TX_FRAME_OVERHEAD_V1 = 472;

/** Validate endpoint-reported WebSocket/buffer capacity; this is not wallet or finality authentication. */
export function validateConnectTransactionTransportStatus(status, payloadLength) {
  if (!Number.isSafeInteger(payloadLength) || payloadLength <= 0 || payloadLength > Number.MAX_SAFE_INTEGER - CONNECT_SIGN_REQUEST_TX_FRAME_OVERHEAD_V1) throw new RangeError("invalid Connect transaction payload length");
  const frameBytes = payloadLength + CONNECT_SIGN_REQUEST_TX_FRAME_OVERHEAD_V1;
  const frameMaxBytes = status?.policy?.frame_max_bytes;
  const sessionBufferMaxBytes = status?.policy?.session_buffer_max_bytes;
  if (status?.enabled !== true || !Number.isSafeInteger(frameMaxBytes) || !Number.isSafeInteger(sessionBufferMaxBytes) || frameMaxBytes < frameBytes || sessionBufferMaxBytes < frameBytes) throw new Error("Connect endpoint cannot carry this complete transaction; use an execution-qualified transport configuration.");
  return Object.freeze({ frameBytes, frameMaxBytes, sessionBufferMaxBytes });
}

const encoder = new TextEncoder();
const SID_PREFIX = encoder.encode("iroha-connect|sid|");
const CONNECT_SALT_PREFIX = encoder.encode("iroha-connect|salt|");
const CONNECT_AAD_PREFIX = encoder.encode("connect:v1");
const CONNECT_K_APP = encoder.encode("iroha-connect|k_app");
const CONNECT_K_WALLET = encoder.encode("iroha-connect|k_wallet");
const X25519_HKDF_SALT = encoder.encode("iroha:x25519:hkdf:v1");
const X25519_HKDF_INFO = encoder.encode("iroha:x25519:session-key");
const APPROVE_DOMAIN = encoder.encode("iroha-connect|approve|v1");
const RELAY_AUTH_DOMAIN = encoder.encode("iroha-connect|relay-auth|v1");
const CONNECT_ENVELOPE_TYPE_NAME = "iroha_torii_shared::connect::EnvelopeV1";
const CONNECT_URI_VERSION = "1";
const CONNECT_URI_SCHEME = "iroha://connect";
const CONNECT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CONNECT_RESPONSE_FIELDS = new Set([
  "sid", "network_id", "app_pk", "nonce", "wallet_uri", "app_uri",
  "token_app", "token_wallet", "token_management", "token_relay",
]);
const CONNECT_URI_FIELDS = new Set([
  "sid", "network_id", "app_pk", "nonce", "node", "v", "role", "token", "relay",
]);
const DEFAULT_CONNECT_LAUNCH_PROTOCOL = "irohaconnect";
const DEFAULT_TORII_BASE_URL = "https://taira.sora.org";

const FRAME_KIND_CONTROL = 0;
const FRAME_KIND_CIPHERTEXT = 1;
const DIR_APP_TO_WALLET = 0;
const DIR_WALLET_TO_APP = 1;
const ROLE_APP = 0;
const ROLE_WALLET = 1;
const CONTROL_OPEN = 0;
const CONTROL_APPROVE = 1;
const CONTROL_REJECT = 2;
const CONTROL_CLOSE = 3;
const CONTROL_PING = 4;
const CONTROL_PONG = 5;
const CONTROL_SERVER_EVENT = 6;
const PAYLOAD_CONTROL = 0;
const PAYLOAD_SIGN_REQUEST_RAW = 1;
const PAYLOAD_SIGN_REQUEST_TX = 2;
const PAYLOAD_SIGN_RESULT_OK = 3;
const PAYLOAD_SIGN_RESULT_ERR = 4;
const CONTROL_AFTER_KEY_CLOSE = 0;
const CONTROL_AFTER_KEY_REJECT = 1;
// Plain Connect frames use the native Norito layout the Torii relay decodes and
// re-encodes: `[u8; 32]` fields carry one u64-length-prefixed byte per element,
// and `sig_wallet` is a u32 algorithm plus an element-framed signature sequence.
const CONNECT_FIXED_ARRAY_BYTES = 32;
const CONNECT_ELEMENT_FRAME_BYTES = 9;
const ALGORITHM_ED25519 = 0;

export const TORII_CANONICAL_REQUEST_DOMAIN_TAG =
  "iroha:torii:canonical-request:v1";

export class ConnectApprovalRejectedError extends Error {
  constructor(codeId, reason, code = null) {
    super(reason || "wallet rejected the connect session");
    this.name = "ConnectApprovalRejectedError";
    this.code = code;
    this.codeId = codeId ?? null;
    this.reason = reason ?? null;
  }
}

export class ConnectSessionClosedError extends Error {
  constructor(reason, code = null, retryable = null, who = null) {
    super(reason || "connect session closed");
    this.name = "ConnectSessionClosedError";
    this.code = code;
    this.reason = reason ?? null;
    this.retryable = retryable;
    this.who = who;
  }
}

export class ConnectSignRequestError extends Error {
  constructor(code, message) {
    super(message || "wallet signature request failed");
    this.name = "ConnectSignRequestError";
    this.code = code ?? null;
  }
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new TypeError(`${name} must not be empty`);
  }
  return trimmed;
}

function requireExactNonEmptyString(value, name) {
  const normalized = requireNonEmptyString(value, name);
  if (normalized !== value) {
    throw new TypeError(`${name} must not contain surrounding whitespace`);
  }
  return normalized;
}

function toUint8Array(value, name) {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    const bytes = new Uint8Array(value.length);
    for (let index = 0; index < value.length; index += 1) {
      const entry = value[index];
      if (!Number.isInteger(entry) || entry < 0 || entry > 0xff) {
        throw new TypeError(`${name}[${index}] must be a byte`);
      }
      bytes[index] = entry;
    }
    return bytes;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    const hex = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
    if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
      const out = new Uint8Array(hex.length / 2);
      for (let index = 0; index < out.length; index += 1) {
        out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
      }
      return out;
    }
  }
  throw new TypeError(`${name} must be binary data`);
}

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function randomBytes(length) {
  const cryptoImpl = globalThis.crypto;
  if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== "function") {
    throw new Error("Web Crypto getRandomValues() is required");
  }
  const out = new Uint8Array(length);
  cryptoImpl.getRandomValues(out);
  return out;
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function toHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export function toBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function baseUrlFromLocation() {
  if (typeof window === "undefined") {
    return DEFAULT_TORII_BASE_URL;
  }
  return `${window.location.protocol}//${window.location.host}`;
}

function normalizeConnectRole(role, name = "role") {
  if (role === "app" || role === "wallet") {
    return role;
  }
  throw new TypeError(`${name} must be 'app' or 'wallet'`);
}

function normalizeOptionalString(value) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function normalizeConnectProtocol(value, name = "protocol") {
  const normalized = requireNonEmptyString(value, name);
  return normalized.endsWith(":") ? normalized.slice(0, -1) : normalized;
}

function buildConnectUri(sidBase64Url, networkId, appPublicKey, nonce, node, role, token = null) {
  const params = new URLSearchParams({
    sid: sidBase64Url,
    network_id: networkId.toString(),
    app_pk: toBase64Url(appPublicKey),
    nonce: toBase64Url(nonce),
    v: CONNECT_URI_VERSION,
    role: normalizeConnectRole(role),
  });
  if (node) {
    params.set("node", node);
  }
  if (token) {
    params.set("token", requireNonEmptyString(token, "token"));
  }
  return `${CONNECT_URI_SCHEME}?${params.toString()}`;
}

export function buildConnectWebSocketUrl(baseUrl, sid, role = "app") {
  const normalizedBaseUrl = requireNonEmptyString(baseUrl, "baseUrl");
  const normalizedSid = requireNonEmptyString(sid, "sid");
  const normalizedRole = normalizeConnectRole(role);
  const url = new URL("/v1/connect/ws", `${normalizedBaseUrl}/`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("sid", normalizedSid);
  url.searchParams.set("role", normalizedRole);
  return url.toString();
}

export function createConnectSessionPreview(options = {}) {
  if (!options || typeof options !== "object") {
    throw new TypeError("options must be an object");
  }
  const networkId = options.networkId;
  const exactNetworkId = networkIdBytes(networkId, "networkId");
  const node =
    options.node === undefined || options.node === null
      ? null
      : requireNonEmptyString(options.node, "node");
  const privateKey = options.appKeyPair?.privateKey
    ? toUint8Array(options.appKeyPair.privateKey, "appKeyPair.privateKey")
    : x25519.utils.randomPrivateKey();
  if (privateKey.length !== 32) {
    throw new RangeError(`appKeyPair.privateKey must be 32 bytes (received ${privateKey.length})`);
  }
  const publicKey = options.appKeyPair?.publicKey
    ? toUint8Array(options.appKeyPair.publicKey, "appKeyPair.publicKey")
    : x25519.getPublicKey(privateKey);
  if (publicKey.length !== 32) {
    throw new RangeError(`appKeyPair.publicKey must be 32 bytes (received ${publicKey.length})`);
  }
  const nonce =
    options.nonce === undefined || options.nonce === null
      ? randomBytes(16)
      : toUint8Array(options.nonce, "nonce");
  if (nonce.length !== 16) {
    throw new RangeError(`nonce must be 16 bytes (received ${nonce.length})`);
  }
  const sidBytes = blake2b(concatBytes(SID_PREFIX, exactNetworkId, publicKey, nonce), {
    dkLen: 32,
  });
  const sidBase64Url = toBase64Url(sidBytes);
  const toriiBaseUrl = node || baseUrlFromLocation();
  return {
    networkId,
    node,
    sidBytes,
    sidBase64Url,
    nonce,
    appKeyPair: {
      publicKey,
      privateKey,
    },
    walletUri: buildConnectUri(sidBase64Url, networkId, publicKey, nonce, node, "wallet"),
    appUri: buildConnectUri(sidBase64Url, networkId, publicKey, nonce, node, "app"),
    wsUrl: buildConnectWebSocketUrl(toriiBaseUrl, sidBase64Url, "app"),
    createdAt: Date.now(),
  };
}

function getFetch(fetchImpl) {
  const resolved = fetchImpl ?? globalThis.fetch;
  if (typeof resolved !== "function") {
    throw new Error("fetch implementation is required");
  }
  return resolved;
}

export async function registerConnectSession(baseUrl, preview, options = {}) {
  const normalized = normalizePreviewInput(preview);
  const payload = {
    sid: toBase64Url(normalized.sidBytes),
    network_id: normalized.networkId.toString(),
    app_pk: toBase64Url(normalized.appKeyPair.publicKey),
    nonce: toBase64Url(normalized.nonce),
  };
  if (options.node !== undefined && options.node !== null) {
    payload.node = requireNonEmptyString(options.node, "node");
  }
  const response = await getFetch(options.fetchImpl)(
    new URL("/v1/connect/session", `${requireNonEmptyString(baseUrl, "baseUrl")}/`),
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    },
  );
  if (!response.ok) {
    const message = await response.text().catch(() => response.statusText);
    throw new Error(`${response.status} ${response.statusText}: ${message || "unable to create connect session"}`);
  }
  const session = await response.json();
  validateRegisteredConnectSession(session, payload);
  return session;
}

function validateRegisteredConnectSession(session, expected) {
  if (!session || typeof session !== "object" || Array.isArray(session)) {
    throw new TypeError("Connect session response must be an object");
  }
  for (const field of Object.keys(session)) {
    if (!CONNECT_RESPONSE_FIELDS.has(field)) {
      throw new Error(`Connect session response contains unsupported field ${field}`);
    }
  }
  const identity = {
    sid: requireExactNonEmptyString(session.sid, "session.sid"),
    network_id: requireExactNonEmptyString(session.network_id, "session.network_id"),
    app_pk: requireExactNonEmptyString(session.app_pk, "session.app_pk"),
    nonce: requireExactNonEmptyString(session.nonce, "session.nonce"),
  };
  for (const field of ["sid", "network_id", "app_pk", "nonce"]) {
    if (identity[field] !== expected[field]) {
      throw new Error(`Torii substituted the canonical Connect session ${field}`);
    }
  }
  const tokens = {
    app: requireConnectToken(session.token_app, "session.token_app"),
    wallet: requireConnectToken(session.token_wallet, "session.token_wallet"),
    management: requireConnectToken(session.token_management, "session.token_management"),
    relay: requireConnectToken(session.token_relay, "session.token_relay"),
  };
  validateRegisteredConnectUri(session.wallet_uri, "wallet", identity, expected.node, tokens.wallet, tokens.relay);
  validateRegisteredConnectUri(session.app_uri, "app", identity, expected.node, tokens.app, tokens.relay);
}

function validateRegisteredConnectUri(value, role, identity, node, token, relay) {
  const literal = requireExactNonEmptyString(value, `session.${role}_uri`);
  let parsed;
  try {
    parsed = new URL(literal);
  } catch {
    throw new Error(`session.${role}_uri must be an absolute Connect URI`);
  }
  if (parsed.protocol !== "iroha:" || parsed.host !== "connect" || parsed.pathname || parsed.hash) {
    throw new Error(`session.${role}_uri must use iroha://connect without a path or fragment`);
  }
  const query = new Map();
  for (const [key, entry] of parsed.searchParams) {
    if (!CONNECT_URI_FIELDS.has(key)) {
      throw new Error(`session.${role}_uri contains unsupported parameter ${key}`);
    }
    if (query.has(key)) {
      throw new Error(`session.${role}_uri contains duplicate parameter ${key}`);
    }
    query.set(key, entry);
  }
  const expectedValues = {
    ...identity,
    node: node ?? "",
    v: CONNECT_URI_VERSION,
    role,
    token,
    relay,
  };
  for (const field of CONNECT_URI_FIELDS) {
    if (!query.has(field)) {
      throw new Error(`session.${role}_uri is missing required parameter ${field}`);
    }
    if (query.get(field) !== expectedValues[field]) {
      throw new Error(`session.${role}_uri substituted Connect parameter ${field}`);
    }
  }
}

function requireConnectToken(value, name) {
  const token = requireExactNonEmptyString(value, name);
  if (!CONNECT_TOKEN_PATTERN.test(token)) {
    throw new TypeError(`${name} must be a canonical 32-byte unpadded base64url token`);
  }
  return token;
}

export async function deleteConnectSession(baseUrl, sid, options = {}) {
  const tokenManagement = requireNonEmptyString(
    options.tokenManagement ?? options.token_management,
    "tokenManagement",
  );
  const headers = {
    Accept: "application/json",
    Authorization: `Bearer ${tokenManagement}`,
  };
  const response = await getFetch(options.fetchImpl)(
    new URL(
      `/v1/connect/session/${encodeURIComponent(requireNonEmptyString(sid, "sid"))}`,
      `${requireNonEmptyString(baseUrl, "baseUrl")}/`,
    ),
    {
      method: "DELETE",
      headers,
    },
  );
  if (!response.ok && response.status !== 404) {
    const message = await response.text().catch(() => response.statusText);
    throw new Error(`${response.status} ${response.statusText}: ${message || "unable to delete connect session"}`);
  }
}

export function buildConnectTokenProtocol(token) {
  const normalized = requireNonEmptyString(token, "token");
  return `iroha-connect.token.v1.${toBase64Url(encoder.encode(normalized))}`;
}

export function resolveConnectLaunchUri(role, preview = null, session = null) {
  const normalizedRole = normalizeConnectRole(role);
  const sessionUri =
    normalizedRole === "wallet"
      ? normalizeOptionalString(session?.wallet_uri)
      : normalizeOptionalString(session?.app_uri);
  if (sessionUri) {
    return sessionUri;
  }
  return normalizedRole === "wallet"
    ? normalizeOptionalString(preview?.walletUri) ?? ""
    : normalizeOptionalString(preview?.appUri) ?? "";
}

export function rewriteConnectUriProtocol(
  uri,
  protocol = DEFAULT_CONNECT_LAUNCH_PROTOCOL,
) {
  const parsed = new URL(requireNonEmptyString(uri, "uri"));
  parsed.protocol = `${normalizeConnectProtocol(protocol)}:`;
  return parsed.toString();
}

export function resolveConnectLaunchUriForProtocol(
  role,
  preview = null,
  session = null,
  protocol = DEFAULT_CONNECT_LAUNCH_PROTOCOL,
) {
  const launchUri = resolveConnectLaunchUri(role, preview, session);
  if (!launchUri) {
    return "";
  }
  return rewriteConnectUriProtocol(launchUri, protocol);
}

function mergeConnectProtocols(protocols, tokenProtocol) {
  if (protocols === undefined || protocols === null) {
    return [tokenProtocol];
  }
  if (typeof protocols === "string") {
    return protocols === tokenProtocol ? [protocols] : [tokenProtocol, protocols];
  }
  if (Array.isArray(protocols)) {
    const normalized = protocols.map((protocol, index) =>
      requireNonEmptyString(protocol, `protocols[${index}]`)
    );
    return normalized.includes(tokenProtocol)
      ? normalized
      : [tokenProtocol, ...normalized];
  }
  throw new TypeError("protocols must be a string or array");
}

function normalizeSocketOptions(baseUrl, sid, token, role, options) {
  if (baseUrl && typeof baseUrl === "object") {
    return {
      baseUrl: requireNonEmptyString(baseUrl.baseUrl, "baseUrl"),
      sid: requireNonEmptyString(baseUrl.sid, "sid"),
      token: requireNonEmptyString(baseUrl.token, "token"),
      role: normalizeConnectRole(baseUrl.role ?? "app"),
      options: baseUrl,
    };
  }
  return {
    baseUrl: requireNonEmptyString(baseUrl, "baseUrl"),
    sid: requireNonEmptyString(sid, "sid"),
    token: requireNonEmptyString(token, "token"),
    role: normalizeConnectRole(role),
    options: options ?? {},
  };
}

function assertSecureWebSocket(url, allowInsecure = false) {
  if (allowInsecure) {
    return;
  }
  if (new URL(url).protocol !== "wss:") {
    throw new Error("Connect WebSocket requires wss://; pass allowInsecure: true for local/dev use only");
  }
}

export function openConnectWebSocket(baseUrl, sid, token, role = "app", options = {}) {
  const normalized = normalizeSocketOptions(baseUrl, sid, token, role, options);
  const WebSocketImpl = normalized.options.webSocketImpl ?? globalThis.WebSocket;
  if (typeof WebSocketImpl !== "function") {
    throw new Error("WebSocket implementation is required");
  }
  const url = buildConnectWebSocketUrl(normalized.baseUrl, normalized.sid, normalized.role);
  assertSecureWebSocket(url, normalized.options.allowInsecure === true);
  return new WebSocketImpl(
    url,
    mergeConnectProtocols(normalized.options.protocols, buildConnectTokenProtocol(normalized.token)),
  );
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function u16ToBytes(value) {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, true);
  return out;
}

function u32ToBytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

function u64ToBytes(value) {
  const normalized = BigInt(value);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, normalized, true);
  return out;
}

function readU16(bytes, offset, label) {
  if (offset + 2 > bytes.length) {
    throw new Error(`${label} exceeded available bytes`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 2).getUint16(0, true);
}

function readU32(bytes, offset, label) {
  if (offset + 4 > bytes.length) {
    throw new Error(`${label} exceeded available bytes`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
}

function readU64(bytes, offset, label) {
  if (offset + 8 > bytes.length) {
    throw new Error(`${label} exceeded available bytes`);
  }
  const value = new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} exceeded Number.MAX_SAFE_INTEGER`);
  }
  return Number(value);
}

function encodeLengthPrefixed(payload) {
  return concatBytes(u64ToBytes(payload.length), payload);
}

function encodeNoritoString(value) {
  return encodeLengthPrefixed(encoder.encode(requireNonEmptyString(value, "string value")));
}

function encodeNoritoBytes(value) {
  return encodeLengthPrefixed(toUint8Array(value, "bytes"));
}

function encodeNoritoBool(value) {
  return Uint8Array.of(value ? 1 : 0);
}

function encodeNoritoOption(encoded) {
  if (encoded === null || encoded === undefined) {
    return Uint8Array.of(0);
  }
  return concatBytes(Uint8Array.of(1), encodeLengthPrefixed(encoded));
}

function encodeNoritoVec(values, encodeValue, name) {
  if (!Array.isArray(values)) {
    throw new TypeError(`${name} must be an array`);
  }
  const parts = [u64ToBytes(values.length)];
  values.forEach((value, index) => {
    parts.push(encodeLengthPrefixed(encodeValue(value, `${name}[${index}]`)));
  });
  return concatBytes(...parts);
}

function encodeNoritoStruct(fields) {
  return concatBytes(...fields.map((field) => encodeLengthPrefixed(field)));
}

/** Element-frame raw bytes: each byte is its own u64-length-prefixed element. */
function encodeElementFramedBytes(bytes) {
  const out = new Uint8Array(bytes.length * CONNECT_ELEMENT_FRAME_BYTES);
  bytes.forEach((byte, index) => {
    const offset = index * CONNECT_ELEMENT_FRAME_BYTES;
    out[offset] = 1;
    out[offset + 8] = byte;
  });
  return out;
}

function decodeElementFramedBytes(bytes, count, label) {
  if (bytes.length !== count * CONNECT_ELEMENT_FRAME_BYTES) {
    throw new Error(`${label} must contain ${count} element-framed bytes`);
  }
  const out = new Uint8Array(count);
  for (let index = 0; index < count; index += 1) {
    const offset = index * CONNECT_ELEMENT_FRAME_BYTES;
    if (readU64(bytes, offset, `${label}[${index}].length`) !== 1) {
      throw new Error(`${label}[${index}] must be exactly one byte`);
    }
    out[index] = bytes[offset + 8];
  }
  return out;
}

/** Encode a native `[u8; 32]` field. */
function encodeFixedByteArray(value, label) {
  const bytes = toUint8Array(value, label);
  if (bytes.length !== CONNECT_FIXED_ARRAY_BYTES) {
    throw new TypeError(`${label} must be ${CONNECT_FIXED_ARRAY_BYTES} bytes`);
  }
  return encodeElementFramedBytes(bytes);
}

/** Strictly decode a native `[u8; 32]` field. */
function decodeFixedByteArray(bytes, label) {
  return decodeElementFramedBytes(bytes, CONNECT_FIXED_ARRAY_BYTES, label);
}

function encodeDir(dir) {
  return u32ToBytes(dir === DIR_WALLET_TO_APP ? DIR_WALLET_TO_APP : DIR_APP_TO_WALLET);
}

function encodeRole(role) {
  return u32ToBytes(role === ROLE_WALLET ? ROLE_WALLET : ROLE_APP);
}

function normalizeAppMeta(appMeta) {
  if (appMeta === undefined || appMeta === null) {
    return null;
  }
  if (!appMeta || typeof appMeta !== "object") {
    throw new TypeError("appMeta must be an object when provided");
  }
  return {
    name: requireNonEmptyString(appMeta.name, "appMeta.name"),
    url: normalizeOptionalString(appMeta.url),
    iconHash: normalizeOptionalString(appMeta.iconHash ?? appMeta.icon_hash),
  };
}

function encodeAppMeta(appMeta) {
  const meta = normalizeAppMeta(appMeta);
  if (!meta) {
    return encodeNoritoOption(null);
  }
  return encodeNoritoOption(
    encodeNoritoStruct([
      encodeNoritoString(meta.name),
      encodeNoritoOption(meta.url ? encodeNoritoString(meta.url) : null),
      encodeNoritoOption(meta.iconHash ? encodeNoritoString(meta.iconHash) : null),
    ]),
  );
}

function normalizePermissions(permissions) {
  if (permissions === undefined || permissions === null) {
    return null;
  }
  if (!permissions || typeof permissions !== "object") {
    throw new TypeError("permissions must be an object when provided");
  }
  const methods = permissions.methods ?? [];
  const events = permissions.events ?? [];
  const resources = permissions.resources ?? null;
  return {
    methods: encodeNoritoVec(methods, (value, name) => encodeNoritoString(requireNonEmptyString(value, name)), "permissions.methods"),
    events: encodeNoritoVec(events, (value, name) => encodeNoritoString(requireNonEmptyString(value, name)), "permissions.events"),
    resources:
      resources === null || resources === undefined
        ? encodeNoritoOption(null)
        : encodeNoritoOption(
            encodeNoritoVec(
              resources,
              (value, name) => encodeNoritoString(requireNonEmptyString(value, name)),
              "permissions.resources",
            ),
          ),
  };
}

function encodePermissions(permissions) {
  const normalized = normalizePermissions(permissions);
  if (!normalized) {
    return encodeNoritoOption(null);
  }
  return encodeNoritoOption(
    encodeNoritoStruct([
      normalized.methods,
      normalized.events,
      normalized.resources,
    ]),
  );
}

function encodeOpenControl({ appPublicKey, networkId, appMeta, permissions }) {
  const body = encodeNoritoStruct([
    encodeFixedByteArray(appPublicKey, "appPublicKey"),
    encodeAppMeta(appMeta),
    encodeNoritoStruct([networkIdBytes(networkId, "networkId")]),
    encodePermissions(permissions),
  ]);
  return concatBytes(u32ToBytes(CONTROL_OPEN), u64ToBytes(body.length), body);
}

function encodePongControl(nonce) {
  const body = encodeNoritoStruct([u64ToBytes(nonce)]);
  return concatBytes(u32ToBytes(CONTROL_PONG), u64ToBytes(body.length), body);
}

function encodeEncryptedClosePayload(reason) {
  return concatBytes(
    u32ToBytes(PAYLOAD_CONTROL),
    encodeLengthPrefixed(
      concatBytes(
        u32ToBytes(CONTROL_AFTER_KEY_CLOSE),
        encodeLengthPrefixed(encodeRole(ROLE_APP)),
        encodeLengthPrefixed(u16ToBytes(1000)),
        encodeLengthPrefixed(encodeNoritoString(reason)),
        encodeLengthPrefixed(encodeNoritoBool(false)),
      ),
    ),
  );
}

function encodeSignRequestTxPayload(txBytes) {
  return concatBytes(
    u32ToBytes(PAYLOAD_SIGN_REQUEST_TX),
    encodeLengthPrefixed(encodeNoritoBytes(txBytes)),
  );
}

function encodeSignRequestRawPayload(domainTag, bytes) {
  return concatBytes(
    u32ToBytes(PAYLOAD_SIGN_REQUEST_RAW),
    encodeLengthPrefixed(encodeNoritoString(domainTag)),
    encodeLengthPrefixed(encodeNoritoBytes(bytes)),
  );
}

function encodeCiphertextFrame({ sidBytes, dir, seq, ciphertext }) {
  const ciphertextStruct = encodeNoritoStruct([
    encodeDir(dir),
    encodeNoritoBytes(ciphertext),
  ]);
  const kind = concatBytes(
    u32ToBytes(FRAME_KIND_CIPHERTEXT),
    u64ToBytes(ciphertextStruct.length),
    ciphertextStruct,
  );
  return encodeConnectFrame({
    sidBytes,
    dir,
    seq,
    kind,
  });
}

function encodeControlFrame({ sidBytes, dir, seq, control }) {
  const kind = concatBytes(
    u32ToBytes(FRAME_KIND_CONTROL),
    u64ToBytes(control.length),
    control,
  );
  return encodeConnectFrame({
    sidBytes,
    dir,
    seq,
    kind,
  });
}

function encodeConnectFrame({ sidBytes, dir, seq, kind }) {
  return encodeNoritoStruct([
    encodeFixedByteArray(sidBytes, "sidBytes"),
    encodeDir(dir),
    u64ToBytes(seq),
    kind,
  ]);
}

function readLengthPrefixedSlice(bytes, state, label) {
  const length = readU64(bytes, state.offset, `${label}.length`);
  state.offset += 8;
  if (state.offset + length > bytes.length) {
    throw new Error(`${label}.payload exceeded available bytes`);
  }
  const payload = bytes.subarray(state.offset, state.offset + length);
  state.offset += length;
  return payload;
}

function decodeDir(bytes, label) {
  if (bytes.length !== 4) {
    throw new Error(`${label} must be 4 bytes`);
  }
  return readU32(bytes, 0, label);
}

function decodeRole(bytes, label) {
  if (bytes.length !== 4) {
    throw new Error(`${label} must be 4 bytes`);
  }
  return readU32(bytes, 0, label);
}

function decodeNoritoString(bytes, label) {
  const state = { offset: 0 };
  const payload = readLengthPrefixedSlice(bytes, state, label);
  if (state.offset !== bytes.length) {
    throw new Error(`${label} length mismatch`);
  }
  return new TextDecoder().decode(payload);
}

function decodeNoritoBytes(bytes, label) {
  const state = { offset: 0 };
  const payload = readLengthPrefixedSlice(bytes, state, label);
  if (state.offset !== bytes.length) {
    throw new Error(`${label} length mismatch`);
  }
  return payload;
}

/**
 * Strictly decode a plain-frame `WalletSignatureV1`: a u32 algorithm field and a
 * u64 count followed by that many element-framed signature bytes.
 */
function decodeRelayWalletSignature(bytes, label) {
  const state = { offset: 0 };
  const algorithmBytes = readLengthPrefixedSlice(bytes, state, `${label}.algorithm`);
  if (algorithmBytes.length !== 4) {
    throw new Error(`${label}.algorithm must be a 4-byte discriminant`);
  }
  const sequence = readLengthPrefixedSlice(bytes, state, `${label}.signature`);
  if (state.offset !== bytes.length) {
    throw new Error(`${label} length mismatch`);
  }
  if (sequence.length < 8) {
    throw new Error(`${label}.signature is truncated`);
  }
  const count = readU64(sequence, 0, `${label}.signature.count`);
  return {
    algorithm: readU32(algorithmBytes, 0, `${label}.algorithm`),
    signature: decodeElementFramedBytes(sequence.subarray(8), count, `${label}.signature`),
  };
}

function decodeWalletSignature(bytes, label) {
  const state = { offset: 0 };
  const algorithmBytes = readLengthPrefixedSlice(bytes, state, `${label}.algorithm`);
  if (algorithmBytes.length !== 1) {
    throw new Error(`${label}.algorithm must be 1 byte`);
  }
  const signature = decodeNoritoBytes(
    readLengthPrefixedSlice(bytes, state, `${label}.signature`),
    `${label}.signature`,
  );
  if (state.offset !== bytes.length) {
    throw new Error(`${label} length mismatch`);
  }
  return {
    algorithm: algorithmBytes[0],
    signature,
  };
}

function decodeConnectControl(bytes) {
  if (bytes.length < 12) {
    throw new Error("control frame is truncated");
  }
  const tag = readU32(bytes, 0, "control.tag");
  const bodyLength = readU64(bytes, 4, "control.length");
  if (12 + bodyLength !== bytes.length) {
    throw new Error("control frame body length mismatch");
  }
  const body = bytes.subarray(12, 12 + bodyLength);
  const state = { offset: 0 };
  const requireConsumed = (label) => {
    if (state.offset !== body.length) {
      throw new Error(`${label} length mismatch`);
    }
  };
  if (tag === CONTROL_APPROVE) {
    const walletPk = decodeFixedByteArray(
      readLengthPrefixedSlice(body, state, "approve.wallet_pk"),
      "approve.wallet_pk",
    );
    const accountId = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "approve.account_id"),
      "approve.account_id",
    );
    const permissions = readLengthPrefixedSlice(body, state, "approve.permissions");
    const proof = readLengthPrefixedSlice(body, state, "approve.proof");
    const signature = decodeRelayWalletSignature(
      readLengthPrefixedSlice(body, state, "approve.sig_wallet"),
      "approve.sig_wallet",
    );
    requireConsumed("approve");
    return {
      kind: "approve",
      walletPublicKey: walletPk,
      accountId,
      permissions,
      proof,
      signature,
    };
  }
  if (tag === CONTROL_REJECT) {
    const codeBytes = readLengthPrefixedSlice(body, state, "reject.code");
    const code = readU16(codeBytes, 0, "reject.code");
    const codeId = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "reject.code_id"),
      "reject.code_id",
    );
    const reason = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "reject.reason"),
      "reject.reason",
    );
    requireConsumed("reject");
    return { kind: "reject", code, codeId, reason };
  }
  if (tag === CONTROL_CLOSE) {
    const who = decodeRole(
      readLengthPrefixedSlice(body, state, "close.who"),
      "close.who",
    );
    const code = readU16(
      readLengthPrefixedSlice(body, state, "close.code"),
      0,
      "close.code",
    );
    const reason = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "close.reason"),
      "close.reason",
    );
    const retryableBytes = readLengthPrefixedSlice(body, state, "close.retryable");
    requireConsumed("close");
    if (retryableBytes.length !== 1 || retryableBytes[0] > 1) {
      throw new Error("close.retryable must be one boolean byte");
    }
    return {
      kind: "close",
      who,
      code,
      reason,
      retryable: retryableBytes[0] === 1,
    };
  }
  if (tag === CONTROL_PING) {
    const nonce = readU64(
      readLengthPrefixedSlice(body, state, "ping.nonce"),
      0,
      "ping.nonce",
    );
    return { kind: "ping", nonce };
  }
  if (tag === CONTROL_PONG) {
    const nonce = readU64(
      readLengthPrefixedSlice(body, state, "pong.nonce"),
      0,
      "pong.nonce",
    );
    return { kind: "pong", nonce };
  }
  if (tag === CONTROL_SERVER_EVENT) {
    return { kind: "server_event", bytes: body };
  }
  return { kind: "unknown", tag };
}

function decodeConnectCiphertext(bytes) {
  const state = { offset: 0 };
  const dir = decodeDir(readLengthPrefixedSlice(bytes, state, "ciphertext.dir"), "ciphertext.dir");
  const aead = decodeNoritoBytes(
    readLengthPrefixedSlice(bytes, state, "ciphertext.aead"),
    "ciphertext.aead",
  );
  if (state.offset !== bytes.length) {
    throw new Error("ciphertext frame length mismatch");
  }
  return { dir, aead };
}

function decodeConnectFrame(bytes) {
  const state = { offset: 0 };
  const sidBytes = decodeFixedByteArray(
    readLengthPrefixedSlice(bytes, state, "frame.sid"),
    "frame.sid",
  );
  const dir = decodeDir(readLengthPrefixedSlice(bytes, state, "frame.dir"), "frame.dir");
  const seq = readU64(readLengthPrefixedSlice(bytes, state, "frame.seq"), 0, "frame.seq");
  const kindBytes = readLengthPrefixedSlice(bytes, state, "frame.kind");
  if (state.offset !== bytes.length) {
    throw new Error("connect frame length mismatch");
  }
  const tag = readU32(kindBytes, 0, "frame.kind.tag");
  const bodyLength = readU64(kindBytes, 4, "frame.kind.length");
  if (12 + bodyLength !== kindBytes.length) {
    throw new Error("connect frame kind body length mismatch");
  }
  const body = kindBytes.subarray(12, 12 + bodyLength);
  if (tag === FRAME_KIND_CONTROL) {
    return {
      sidBytes,
      dir,
      seq,
      kind: { type: "control", control: decodeConnectControl(body) },
    };
  }
  if (tag === FRAME_KIND_CIPHERTEXT) {
    return {
      sidBytes,
      dir,
      seq,
      kind: { type: "ciphertext", ciphertext: decodeConnectCiphertext(body) },
    };
  }
  throw new Error(`unsupported connect frame kind ${tag}`);
}

function noritoSchemaHash(typeName) {
  return sha256(concatBytes(encoder.encode("norito:v1:type-name\0"), encoder.encode(typeName))).subarray(0, 16);
}

function frameNoritoPayload(typeName, payload) {
  return concatBytes(
    encoder.encode("NRT0"),
    Uint8Array.of(0, 0),
    noritoSchemaHash(typeName),
    Uint8Array.of(0),
    u64ToBytes(payload.length),
    u64ToBytes(crc64Xz(payload)),
    Uint8Array.of(0),
    payload,
  );
}

function decodeNoritoFrame(bytes, label, typeName = CONNECT_ENVELOPE_TYPE_NAME) {
  if (bytes.length < 40) {
    throw new Error(`${label} is not a valid Norito frame`);
  }
  if (new TextDecoder().decode(bytes.subarray(0, 4)) !== "NRT0") {
    throw new Error(`${label} is not an NRT0 frame`);
  }
  if (bytes[4] !== 0 || bytes[5] !== 0) {
    throw new Error(`${label} uses an unsupported Norito version`);
  }
  const expectedSchema = noritoSchemaHash(typeName);
  const actualSchema = bytes.subarray(6, 22);
  if (toHex(actualSchema) !== toHex(expectedSchema)) {
    throw new Error(`${label} Norito schema mismatch`);
  }
  if (bytes[22] !== 0 || bytes[39] !== 0) {
    throw new Error(`${label} uses unsupported Norito layout flags`);
  }
  const payloadLength = readU64(bytes, 23, `${label}.payloadLength`);
  const checksum = new DataView(bytes.buffer, bytes.byteOffset + 31, 8).getBigUint64(0, true);
  const payload = bytes.subarray(40, 40 + payloadLength);
  if (payload.length !== payloadLength) {
    throw new Error(`${label} payload exceeded available bytes`);
  }
  if (crc64Xz(payload) !== checksum) {
    throw new Error(`${label} CRC64 mismatch`);
  }
  return payload;
}

function encodeEnvelope(seq, payload) {
  return frameNoritoPayload(
    CONNECT_ENVELOPE_TYPE_NAME,
    encodeNoritoStruct([u64ToBytes(seq), payload]),
  );
}

function decodeEnvelope(bytes) {
  const payload = decodeNoritoFrame(bytes, "Connect envelope");
  const state = { offset: 0 };
  const seq = readU64(readLengthPrefixedSlice(payload, state, "envelope.seq"), 0, "envelope.seq");
  const payloadBytes = readLengthPrefixedSlice(payload, state, "envelope.payload");
  if (state.offset !== payload.length) {
    throw new Error("Connect envelope length mismatch");
  }
  return {
    seq,
    payload: decodeConnectPayload(payloadBytes),
  };
}

function decodeConnectPayload(bytes) {
  const tag = readU32(bytes, 0, "payload.tag");
  const body = bytes.subarray(4);
  const state = { offset: 0 };
  if (tag === PAYLOAD_SIGN_RESULT_OK) {
    const signature = decodeWalletSignature(
      readLengthPrefixedSlice(body, state, "payload.signature"),
      "payload.signature",
    );
    return {
      kind: "sign_result_ok",
      signature,
    };
  }
  if (tag === PAYLOAD_SIGN_RESULT_ERR) {
    const code = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "payload.code"),
      "payload.code",
    );
    const message = decodeNoritoString(
      readLengthPrefixedSlice(body, state, "payload.message"),
      "payload.message",
    );
    return {
      kind: "sign_result_err",
      code,
      message,
    };
  }
  if (tag === PAYLOAD_CONTROL) {
    const controlBytes = readLengthPrefixedSlice(body, state, "payload.control");
    const controlTag = readU32(controlBytes, 0, "payload.control.tag");
    if (controlTag === CONTROL_AFTER_KEY_CLOSE) {
      const nested = { offset: 4 };
      const who = decodeRole(readLengthPrefixedSlice(controlBytes, nested, "payload.control.close.who"), "payload.control.close.who");
      const code = readU16(readLengthPrefixedSlice(controlBytes, nested, "payload.control.close.code"), 0, "payload.control.close.code");
      const reason = decodeNoritoString(readLengthPrefixedSlice(controlBytes, nested, "payload.control.close.reason"), "payload.control.close.reason");
      const retryableBytes = readLengthPrefixedSlice(controlBytes, nested, "payload.control.close.retryable");
      return {
        kind: "control_close",
        who,
        code,
        reason,
        retryable: retryableBytes[0] === 1,
      };
    }
    if (controlTag === CONTROL_AFTER_KEY_REJECT) {
      const nested = { offset: 4 };
      const code = readU16(readLengthPrefixedSlice(controlBytes, nested, "payload.control.reject.code"), 0, "payload.control.reject.code");
      const codeId = decodeNoritoString(readLengthPrefixedSlice(controlBytes, nested, "payload.control.reject.code_id"), "payload.control.reject.code_id");
      const reason = decodeNoritoString(readLengthPrefixedSlice(controlBytes, nested, "payload.control.reject.reason"), "payload.control.reject.reason");
      return {
        kind: "control_reject",
        code,
        codeId,
        reason,
      };
    }
  }
  return { kind: "unknown", tag };
}

function deriveDirectionKeys(sharedSecret, sidBytes) {
  const sessionKey = hkdf(sha256, sharedSecret, X25519_HKDF_SALT, X25519_HKDF_INFO, 32);
  const salt = blake2b(concatBytes(CONNECT_SALT_PREFIX, sidBytes), { dkLen: 32 });
  return {
    appKey: hkdf(sha256, sessionKey, salt, CONNECT_K_APP, 32),
    walletKey: hkdf(sha256, sessionKey, salt, CONNECT_K_WALLET, 32),
  };
}

function taggedApproveField(tag, value) {
  const tagBytes = encoder.encode(tag);
  return concatBytes(u16ToBytes(tagBytes.length), tagBytes, u64ToBytes(value.length), value);
}

function relayAuthHash(sidBytes, relayToken) {
  return sha256(concatBytes(RELAY_AUTH_DOMAIN, sidBytes, encoder.encode(relayToken)));
}

function isNoritoNoneOption(bytes) {
  if (bytes.length === 1 && bytes[0] === 0) {
    return true;
  }
  return bytes.length === 4 && readU32(bytes, 0, "option.tag") === 0;
}

function unwrapNoritoOption(bytes, context) {
  if (isNoritoNoneOption(bytes)) {
    return null;
  }
  if (bytes[0] !== 1) {
    throw new Error(`${context} has an invalid option tag`);
  }
  const state = { offset: 1 };
  const value = readLengthPrefixedSlice(bytes, state, context);
  if (state.offset !== bytes.length) {
    throw new Error(`${context} has trailing bytes`);
  }
  return value;
}

function accountEd25519PublicKey(accountId) {
  const address = AccountAddress.fromI105(accountId);
  const controller = address.controllerInfo();
  if (!controller || controller.tag !== 0 || controller.curve !== 1 || controller.publicKey.length !== 32) {
    throw new Error("Connect approval account id must be a canonical single-key Ed25519 I105 address");
  }
  return Uint8Array.from(controller.publicKey);
}

function requireValidEd25519Signature(signature, message, publicKey) {
  const normalizedSignature = toUint8Array(signature, "wallet signature");
  if (normalizedSignature.length !== 64) {
    throw new ConnectSignRequestError(
      "INVALID_SIGNATURE",
      `wallet Ed25519 signature must be 64 bytes (received ${normalizedSignature.length})`,
    );
  }
  let valid = false;
  try {
    valid = verifyEd25519Strict(message, normalizedSignature, publicKey);
  } catch {
    // Use one stable error for every malformed or mismatched wallet signature.
  }
  if (!valid) {
    throw new ConnectSignRequestError(
      "INVALID_SIGNATURE",
      "wallet signature does not match the approved account and requested bytes",
    );
  }
  return normalizedSignature;
}

function buildApprovalPreimage(preview, control, relayToken) {
  const permissions = unwrapNoritoOption(control.permissions, "approve.permissions");
  const proof = unwrapNoritoOption(control.proof, "approve.proof");
  const constraints = encodeNoritoStruct([networkIdBytes(preview.networkId, "preview.networkId")]);
  const fields = [
    taggedApproveField("domain", APPROVE_DOMAIN),
    taggedApproveField("network_id", networkIdBytes(preview.networkId, "preview.networkId")),
    taggedApproveField("constraints", blake2b(constraints, { dkLen: 32 })),
    taggedApproveField("sid", preview.sidBytes),
    taggedApproveField("app_pk", preview.appKeyPair.publicKey),
    taggedApproveField("wallet_pk", control.walletPublicKey),
    taggedApproveField("account_id", encoder.encode(control.accountId)),
  ];
  if (permissions !== null) {
    fields.push(taggedApproveField("permissions", blake2b(permissions, { dkLen: 32 })));
  }
  if (proof !== null) {
    fields.push(taggedApproveField("proof", blake2b(proof, { dkLen: 32 })));
  }
  fields.push(taggedApproveField("relay_auth", relayAuthHash(preview.sidBytes, relayToken)));
  return concatBytes(
    ...fields,
  );
}

function verifyApproval(preview, control, relayToken) {
  if (control.signature.algorithm !== ALGORITHM_ED25519) {
    throw new Error(`unsupported Connect approval signature algorithm ${control.signature.algorithm}`);
  }
  if (control.signature.signature.length !== 64) {
    throw new Error("Connect approval Ed25519 signature must be 64 bytes");
  }
  const publicKey = accountEd25519PublicKey(control.accountId);
  const preimage = buildApprovalPreimage(preview, control, relayToken);
  if (!verifyEd25519Strict(preimage, control.signature.signature, publicKey)) {
    throw new Error("Connect approval signature verification failed");
  }
  return publicKey;
}

function buildAad(sidBytes, dir, seq) {
  return concatBytes(
    CONNECT_AAD_PREFIX,
    sidBytes,
    Uint8Array.of(dir),
    u64ToBytes(seq),
    Uint8Array.of(1),
  );
}

function buildNonce(seq) {
  return concatBytes(new Uint8Array(4), u64ToBytes(seq));
}

function encryptEnvelope(keyBytes, sidBytes, dir, seq, payload) {
  const plaintext = encodeEnvelope(seq, payload);
  return chacha20poly1305(keyBytes, buildNonce(seq), buildAad(sidBytes, dir, seq)).encrypt(plaintext);
}

function decryptEnvelope(keyBytes, sidBytes, frame) {
  const plaintext = chacha20poly1305(
    keyBytes,
    buildNonce(frame.seq),
    buildAad(sidBytes, frame.dir, frame.seq),
  ).decrypt(frame.kind.ciphertext.aead);
  const envelope = decodeEnvelope(plaintext);
  if (envelope.seq !== frame.seq) {
    throw new Error("Connect envelope sequence mismatch");
  }
  return envelope;
}

async function bytesFromWebSocketMessage(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new TypeError("Connect WebSocket message must be binary");
}

function attachSocketHandler(socket, eventName, handler) {
  if (typeof socket.addEventListener === "function") {
    socket.addEventListener(eventName, handler);
    return;
  }
  socket[`on${eventName}`] = handler;
}

function normalizeSessionInput(session) {
  if (!session || typeof session !== "object") {
    throw new TypeError("session must be an object");
  }
  return {
    sid: requireNonEmptyString(session.sid, "session.sid"),
    tokenApp: requireNonEmptyString(session.token_app ?? session.tokenApp, "session.token_app"),
    tokenRelay: requireNonEmptyString(session.token_relay ?? session.tokenRelay, "session.token_relay"),
  };
}

function normalizePreviewInput(preview) {
  if (!preview || typeof preview !== "object") {
    throw new TypeError("preview must be an object");
  }
  const sidBytes = toUint8Array(preview.sidBytes, "preview.sidBytes");
  if (sidBytes.length !== 32) {
    throw new RangeError(`preview.sidBytes must be 32 bytes (received ${sidBytes.length})`);
  }
  const publicKey = toUint8Array(preview.appKeyPair?.publicKey, "preview.appKeyPair.publicKey");
  const privateKey = toUint8Array(preview.appKeyPair?.privateKey, "preview.appKeyPair.privateKey");
  if (publicKey.length !== 32 || privateKey.length !== 32) {
    throw new RangeError("preview.appKeyPair must contain 32-byte X25519 keys");
  }
  networkIdBytes(preview.networkId, "preview.networkId");
  const nonce = toUint8Array(preview.nonce, "preview.nonce");
  if (nonce.length !== 16) {
    throw new RangeError(`preview.nonce must be 16 bytes (received ${nonce.length})`);
  }
  return {
    sidBytes,
    networkId: preview.networkId,
    nonce,
    appKeyPair: {
      publicKey,
      privateKey,
    },
  };
}

function rejectDeferred(deferred, error) {
  if (deferred && typeof deferred.reject === "function") {
    deferred.reject(error);
  }
}

function copyConnectApproval(approval) {
  return Object.freeze({
    accountId: approval.accountId,
    signingPublicKey: Uint8Array.from(approval.signingPublicKey),
    walletPublicKey: Uint8Array.from(approval.walletPublicKey),
    signature: Uint8Array.from(approval.signature),
  });
}

export function createConnectAppSession(options = {}) {
  if (!options || typeof options !== "object") {
    throw new TypeError("options must be an object");
  }
  const baseUrl = requireNonEmptyString(options.baseUrl, "baseUrl");
  const preview = normalizePreviewInput(options.preview);
  const session = normalizeSessionInput(options.session);
  const socket = openConnectWebSocket(baseUrl, session.sid, session.tokenApp, "app", {
    webSocketImpl: options.webSocketImpl,
    protocols: options.protocols,
    allowInsecure: options.allowInsecure,
  });
  if ("binaryType" in socket) {
    socket.binaryType = "arraybuffer";
  }

  const approval = createDeferred();
  // Observe early socket failures so a session that fails before the caller
  // awaits waitForApproval() does not raise an unhandled rejection (which
  // terminates Node.js); waitForApproval() still rejects with that error.
  approval.promise.catch(() => {});
  let pendingSign = null;
  let appSeq = 1;
  let walletSeq = 1;
  let serverSeqWalletToApp = 1;
  let closed = false;
  let approved = null;
  let approvalFailure = null;
  let keys = null;

  function failSession(error) {
    if (closed) {
      return;
    }
    closed = true;
    rejectDeferred(approval, error);
    if (pendingSign) {
      pendingSign.reject(error);
      pendingSign = null;
    }
  }

  function sendFrame(bytes) {
    if (closed) {
      throw new ConnectSessionClosedError("connect session closed");
    }
    socket.send(bytes);
  }

  function sendControl(controlBytes) {
    sendFrame(
      encodeControlFrame({
        sidBytes: preview.sidBytes,
        dir: DIR_APP_TO_WALLET,
        seq: appSeq,
        control: controlBytes,
      }),
    );
    appSeq += 1;
  }

  function sendEncrypted(payloadBytes) {
    if (!keys) {
      throw new Error("connect session has not been approved");
    }
    sendFrame(
      encodeCiphertextFrame({
        sidBytes: preview.sidBytes,
        dir: DIR_APP_TO_WALLET,
        seq: appSeq,
        ciphertext: encryptEnvelope(keys.appKey, preview.sidBytes, DIR_APP_TO_WALLET, appSeq, payloadBytes),
      }),
    );
    appSeq += 1;
  }

  function requestSignature(payloadBytes, verificationBytes = null) {
    if (pendingSign) {
      throw new ConnectSignRequestError(
        "REQUEST_IN_FLIGHT",
        "a wallet signature request is already in flight",
      );
    }
    const request = {
      ...createDeferred(),
      verificationBytes,
    };
    pendingSign = request;
    void (async () => {
      try {
        await approval.promise;
        if (approvalFailure !== null) {
          throw approvalFailure;
        }
        if (pendingSign !== request) {
          return;
        }
        sendEncrypted(payloadBytes);
      } catch (error) {
        if (pendingSign === request) {
          pendingSign = null;
          request.reject(error);
        }
      }
    })();
    return request.promise;
  }

  async function handleMessage(event) {
    try {
      const bytes = await bytesFromWebSocketMessage(event.data);
      const frame = decodeConnectFrame(bytes);
      if (toHex(frame.sidBytes) !== toHex(preview.sidBytes)) {
        throw new Error("received a connect frame for a different session");
      }

      if (frame.kind.type === "control") {
        const control = frame.kind.control;
        if (control.kind === "server_event") {
          if (frame.seq !== serverSeqWalletToApp) {
            throw new Error(`unexpected server event sequence ${frame.seq}; expected ${serverSeqWalletToApp}`);
          }
          serverSeqWalletToApp += 1;
          return;
        }
        if (frame.seq !== walletSeq) {
          throw new Error(`unexpected wallet sequence ${frame.seq}; expected ${walletSeq}`);
        }
        walletSeq += 1;
        if (control.kind === "approve") {
          if (approved !== null) {
            const error = new ConnectSessionClosedError(
              "connect session received more than one wallet approval",
            );
            approvalFailure = error;
            failSession(error);
            try {
              socket.close();
            } catch {
              // The session is already closed locally; socket close is best-effort.
            }
            return;
          }
          const signingPublicKey = verifyApproval(preview, control, session.tokenRelay);
          keys = deriveDirectionKeys(
            x25519.getSharedSecret(preview.appKeyPair.privateKey, control.walletPublicKey),
            preview.sidBytes,
          );
          approved = Object.freeze({
            accountId: control.accountId,
            signingPublicKey: Uint8Array.from(signingPublicKey),
            walletPublicKey: Uint8Array.from(control.walletPublicKey),
            signature: Uint8Array.from(control.signature.signature),
          });
          approval.resolve();
          return;
        }
        if (control.kind === "reject") {
          failSession(new ConnectApprovalRejectedError(control.codeId, control.reason, control.code));
          return;
        }
        if (control.kind === "close") {
          failSession(new ConnectSessionClosedError(control.reason, control.code, control.retryable, control.who));
          return;
        }
        if (control.kind === "ping") {
          sendControl(encodePongControl(control.nonce));
        }
        return;
      }

      if (!keys) {
        throw new Error("received ciphertext before approval");
      }
      if (frame.seq !== walletSeq) {
        throw new Error(`unexpected wallet sequence ${frame.seq}; expected ${walletSeq}`);
      }
      walletSeq += 1;
      const envelope = decryptEnvelope(keys.walletKey, preview.sidBytes, frame);
      if (envelope.payload.kind === "sign_result_ok") {
        if (!pendingSign) {
          return;
        }
        if (envelope.payload.signature.algorithm !== ALGORITHM_ED25519) {
          pendingSign.reject(
            new ConnectSignRequestError(
              "UNSUPPORTED_ALGORITHM",
              `unsupported wallet signature algorithm ${envelope.payload.signature.algorithm}`,
            ),
          );
          pendingSign = null;
          return;
        }
        const request = pendingSign;
        let signature = envelope.payload.signature.signature;
        if (request.verificationBytes !== null) {
          try {
            signature = requireValidEd25519Signature(
              signature,
              request.verificationBytes,
              accountEd25519PublicKey(approved.accountId),
            );
          } catch (error) {
            request.reject(error);
            pendingSign = null;
            return;
          }
        }
        pendingSign = null;
        request.resolve(Uint8Array.from(signature));
        return;
      }
      if (envelope.payload.kind === "sign_result_err") {
        if (pendingSign) {
          pendingSign.reject(
            new ConnectSignRequestError(
              envelope.payload.code,
              envelope.payload.message,
            ),
          );
          pendingSign = null;
        }
        return;
      }
      if (envelope.payload.kind === "control_close") {
        failSession(
          new ConnectSessionClosedError(
            envelope.payload.reason,
            envelope.payload.code,
            envelope.payload.retryable,
            envelope.payload.who,
          ),
        );
        return;
      }
      if (envelope.payload.kind === "control_reject") {
        failSession(
          new ConnectApprovalRejectedError(
            envelope.payload.codeId,
            envelope.payload.reason,
            envelope.payload.code,
          ),
        );
      }
    } catch (error) {
      failSession(
        error instanceof Error ? error : new Error("failed to process connect message"),
      );
    }
  }

  attachSocketHandler(socket, "open", () => {
    try {
      sendControl(
        encodeOpenControl({
          appPublicKey: preview.appKeyPair.publicKey,
          networkId: preview.networkId,
          appMeta: options.appMeta ?? null,
          permissions: options.permissions ?? null,
        }),
      );
    } catch (error) {
      failSession(error instanceof Error ? error : new Error("failed to open connect session"));
    }
  });
  attachSocketHandler(socket, "message", (event) => {
    void handleMessage(event);
  });
  attachSocketHandler(socket, "error", () => {
    failSession(new ConnectSessionClosedError("connect socket errored"));
  });
  attachSocketHandler(socket, "close", () => {
    failSession(new ConnectSessionClosedError("connect socket closed"));
  });

  return {
    socket,
    async waitForApproval() {
      await approval.promise;
      if (approvalFailure !== null) {
        throw approvalFailure;
      }
      return copyConnectApproval(approved);
    },
    async signTransaction(unsignedTxBytes) {
      const txBytes = toUint8Array(unsignedTxBytes, "unsignedTxBytes");
      return requestSignature(encodeSignRequestTxPayload(txBytes));
    },
    async signRaw(domainTag, bytes) {
      const normalizedDomainTag = requireExactNonEmptyString(
        domainTag,
        "domainTag",
      );
      const message = Uint8Array.from(toUint8Array(bytes, "bytes"));
      return requestSignature(
        encodeSignRequestRawPayload(normalizedDomainTag, message),
        message,
      );
    },
    close(reason = "client closed session") {
      if (closed) {
        return;
      }
      if (keys) {
        try {
          sendEncrypted(encodeEncryptedClosePayload(reason));
        } catch {
          // Best-effort close only.
        }
      }
      closed = true;
      if (typeof socket.close === "function") {
        socket.close();
      }
      const error = new ConnectSessionClosedError(reason);
      rejectDeferred(approval, error);
      if (pendingSign) {
        pendingSign.reject(error);
        pendingSign = null;
      }
    },
    get approvedAccountId() {
      return approved?.accountId ?? null;
    },
  };
}

/**
 * Bind Torii canonical-request authentication to an approved Connect identity.
 * The signer sends the exact canonical message bytes to the wallet as a raw
 * request; no private key material is accepted or exposed by this adapter.
 *
 * @param {{waitForApproval: () => Promise<{accountId: string}>, signRaw: (domainTag: string, bytes: Uint8Array) => Promise<Uint8Array>}} session
 * @returns {Promise<{readonly authAccountId: string, readonly sign: (input: {message: ArrayBuffer | ArrayBufferView}) => Promise<Uint8Array>}>}
 */
export async function createConnectCanonicalRequestAuth(session) {
  if (!session || typeof session !== "object") {
    throw new TypeError("session must be an object");
  }
  if (typeof session.waitForApproval !== "function") {
    throw new TypeError("session.waitForApproval must be a function");
  }
  if (typeof session.signRaw !== "function") {
    throw new TypeError("session.signRaw must be a function");
  }
  const approved = await session.waitForApproval();
  if (!approved || typeof approved !== "object") {
    throw new TypeError("session approval must be an object");
  }
  const authAccountId = requireExactNonEmptyString(
    approved.accountId,
    "approval.accountId",
  );
  const approvedPublicKey = accountEd25519PublicKey(authAccountId);
  const sign = async (input) => {
    if (!input || typeof input !== "object") {
      throw new TypeError("canonical signer input must be an object");
    }
    const message = Uint8Array.from(
      toUint8Array(input.message, "canonical signer input.message"),
    );
    const signature = await session.signRaw(
      TORII_CANONICAL_REQUEST_DOMAIN_TAG,
      Uint8Array.from(message),
    );
    return requireValidEd25519Signature(
      signature,
      message,
      approvedPublicKey,
    );
  };
  return Object.freeze({ authAccountId, sign });
}
