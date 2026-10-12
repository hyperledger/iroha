import { sha256 as hashBytes } from "@noble/hashes/sha256";
import { networkIdBytes } from "./networkId.js";

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
