import { sha256 as hashBytes } from "@noble/hashes/sha256";
import { networkIdBytes } from "./networkId.js";
import { getCurveEntryByAlgorithm } from "./curveRegistry.js";
import { assertValidEd25519PublicKey } from "./ed25519Strict.js";

const RESPONSE_KEYS = ["schema", "requestId", "nonce", "actorAccountId", "actorPublicKeyHex", "intentSha256", "requestSha256", "inspection"];
const INSPECTION_KEYS = ["schema", "networkId", "accountId", "publicKeyHex", "scope"];

function object(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${label} must be a plain closed record`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).length !== keys.length || keys.some((key) =>
    !descriptors[key] || !("value" in descriptors[key]))) {
    throw new TypeError(`${label} has unexpected fields`);
  }
  return value;
}

function text(value, maximum, label) {
  if (typeof value !== "string" || !value || value.trim() !== value ||
      new TextEncoder().encode(value).length > maximum || value.normalize("NFC") !== value ||
      /\s/u.test(value) || /[\p{Cc}\p{Cs}]/u.test(value)) {
    throw new TypeError(`${label} must be exact bounded text`);
  }
  return value;
}

function sha256(value) {
  return Array.from(hashBytes(new TextEncoder().encode(value)), byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Request canonical account/key inspection from an authenticated native service.
 *
 * The transport must deliver body verbatim with requestId as X-Request-Id, and
 * authenticate the service and caller independently. No secret key is sent.
 * This validates response binding, not account encoding: Rust owns that codec.
 * The result proves syntax and controller binding only, never ledger authority.
 */
export async function inspectAccountViaNativeTransport(input, transport, contract) {
  object(input, ["networkId", "requestId", "nonce", "accountId", "publicKeyHex"], "native account input");
  object(contract, ["responseSchema", "inspectionSchema"], "native account contract");
  networkIdBytes(input.networkId, "native account networkId");
  const networkId = input.networkId.toString();
  const requestId = text(input.requestId, 36, "requestId");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(requestId) ||
      requestId === "00000000-0000-0000-0000-000000000000") throw new TypeError("requestId must be a nonnil canonical UUID");
  const nonce = text(input.nonce, 64, "nonce");
  if (!/^[0-9a-f]{64}$/u.test(nonce) || /^0+$/u.test(nonce)) throw new TypeError("nonce must be nonzero 32-byte lowercase hex");
  const accountId = text(input.accountId, 2048, "accountId");
  const publicKeyHex = text(input.publicKeyHex, 64, "publicKeyHex");
  if (!/^[0-9a-f]{64}$/u.test(publicKeyHex)) throw new TypeError("publicKeyHex must be 32-byte lowercase hex");
  const responseSchema = text(contract.responseSchema, 128, "responseSchema");
  const inspectionSchema = text(contract.inspectionSchema, 128, "inspectionSchema");
  if (typeof transport !== "function") throw new TypeError("native account transport must be a function");
  const body = JSON.stringify({ requestId, nonce, accountId, publicKeyHex });
  const requestSha256 = sha256(body);
  const intentSha256 = sha256(`${JSON.stringify({ accountId, networkId, operation: "account.admit", publicKeyHex })}\n`);
  const response = object(await transport(Object.freeze({ requestId, body })), RESPONSE_KEYS, "native account response");
  const inspection = object(response.inspection, INSPECTION_KEYS, "native account inspection");
  if (response.schema !== responseSchema || response.requestId !== requestId || response.nonce !== nonce ||
      response.actorAccountId !== accountId || response.actorPublicKeyHex !== publicKeyHex ||
      response.requestSha256 !== requestSha256 || response.intentSha256 !== intentSha256 ||
      inspection.schema !== inspectionSchema || inspection.networkId !== networkId ||
      inspection.accountId !== accountId || inspection.publicKeyHex !== publicKeyHex ||
      inspection.scope !== "canonical-syntax-and-key-binding-only") {
    throw new TypeError("native account inspection differs from its exact request binding");
  }
  return Object.freeze({ schema: inspectionSchema, networkId, accountId, publicKeyHex,
    scope: "canonical-syntax-and-key-binding-only" });
}


function nativeInspectionRandomBytes(length) {
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new Error("Web Crypto getRandomValues() is required for native account inspection");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

const TORII_NATIVE_IDENTITIES = new WeakMap();
const TORII_INSPECTION_RESPONSE_KEYS = [
  "version", "network_id", "request_id", "nonce", "account_id", "canonical_hex", "controller",
];

/** @internal Exact transport origin binding; no account codec is implemented here. */
export function nativeInspectionBaseUrl(value) {
  const raw = value instanceof URL ? value.toString() : value;
  if (typeof raw !== "string" || raw.trim() !== raw) throw new TypeError("native inspection requires an exact base URL");
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new TypeError("native account inspection requires an authenticated HTTPS Torii base URL");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/u, "")}`;
}

/**
 * Consume a bounded response from the supplied Torii native inspection transport.
 * The transport must authenticate the configured HTTPS service; it receives no
 * secret and performs no ledger lookup. Only this function creates the opaque
 * identity used by browser Connect and canonical-request signing.
 */
export async function inspectToriiAccountIdentityViaNativeTransport(input, transport) {
  object(input, ["networkId", "baseUrl", "accountId"], "Torii native account input");
  networkIdBytes(input.networkId, "Torii native account networkId");
  const networkId = input.networkId.toString();
  const baseUrl = nativeInspectionBaseUrl(input.baseUrl);
  const accountId = text(input.accountId, 2048, "accountId");
  if (typeof transport !== "function") throw new TypeError("native account transport must be a function");
  const uuid = nativeInspectionRandomBytes(16);
  uuid[6] = (uuid[6] & 0x0f) | 0x40;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
  const hex = Array.from(uuid, byte => byte.toString(16).padStart(2, "0")).join("");
  const requestId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  const nonce = Array.from(nativeInspectionRandomBytes(32), byte => byte.toString(16).padStart(2, "0")).join("");
  if (/^0+$/u.test(nonce)) throw new Error("native inspection entropy must be nonzero");
  const body = JSON.stringify({ version: 1, network_id: networkId, request_id: requestId,
    nonce, account_id: accountId });
  const response = object(await transport(Object.freeze({ requestId, body })),
    TORII_INSPECTION_RESPONSE_KEYS, "Torii native account response");
  if (response.version !== 1 || response.network_id !== networkId || response.request_id !== requestId
      || response.nonce !== nonce || response.account_id !== accountId) {
    throw new TypeError("Torii native account inspection differs from its exact request binding");
  }
  // These are response-shape checks only. Rust owns the I105/controller codec.
  const canonicalHex = response.canonical_hex;
  if (typeof canonicalHex !== "string" || canonicalHex.length > 4098
      || !/^0x(?:[0-9a-f]{2})+$/u.test(canonicalHex)) {
    throw new TypeError("Torii native account canonical_hex must be bounded exact lowercase hex");
  }
  let controller;
  const controllerKind = Object.getOwnPropertyDescriptor(response.controller ?? {}, "kind")?.value;
  if (controllerKind === "multisig") {
    object(response.controller, ["kind"], "Torii native account controller");
    controller = Object.freeze({ kind: "multisig" });
  } else {
    const value = object(response.controller, ["kind", "algorithm", "public_key_hex"], "Torii native account controller");
    const entry = getCurveEntryByAlgorithm(value.algorithm);
    if (value.kind !== "single" || !entry || typeof value.public_key_hex !== "string"
        || value.public_key_hex.length !== entry.publicKeyLength * 2
        || !/^[0-9a-f]+$/u.test(value.public_key_hex)) {
      throw new TypeError("Torii native account controller has an invalid algorithm or public key");
    }
    if (entry.algorithm === "ed25519") {
      assertValidEd25519PublicKey(Uint8Array.from(value.public_key_hex.match(/../gu), byte => Number.parseInt(byte, 16)));
    }
    controller = Object.freeze({ kind: "single", algorithm: value.algorithm, publicKeyHex: value.public_key_hex });
  }
  const identity = Object.freeze({ accountId, networkId, baseUrl });
  TORII_NATIVE_IDENTITIES.set(identity, Object.freeze({ accountId, networkId, baseUrl, canonicalHex, controller }));
  return identity;
}

/** @internal Require a genuine, immutable identity bound to this exact transport. */
export function requireToriiNativeIdentity(identity, { accountId, networkId, baseUrl }) {
  const admitted = TORII_NATIVE_IDENTITIES.get(identity);
  networkIdBytes(networkId, "native identity networkId");
  if (!admitted || admitted.accountId !== accountId || admitted.networkId !== networkId.toString()
      || admitted.baseUrl !== nativeInspectionBaseUrl(baseUrl)) {
    throw new TypeError("native account identity must be inspected for this exact account, network and Torii URL");
  }
  return admitted;
}

/** @internal Extract only the native-inspected Connect Ed25519 controller. */
export function toriiNativeIdentityEd25519Key(identity, binding) {
  const { controller } = requireToriiNativeIdentity(identity, binding);
  if (controller.kind !== "single" || controller.algorithm !== "ed25519") {
    throw new TypeError("Connect approval account id must be a canonical single-key Ed25519 I105 address");
  }
  return Uint8Array.from(controller.publicKeyHex.match(/../gu), byte => Number.parseInt(byte, 16));
}
