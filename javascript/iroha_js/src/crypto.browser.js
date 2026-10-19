import { Buffer } from "buffer";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { verifyEd25519Strict } from "./ed25519Strict.js";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist as englishWordlist } from "@scure/bip39/wordlists/english.js";
import {
  CRYPTO_ALGORITHMS,
  normalizeCryptoAlgorithm,
} from "./cryptoAlgorithms.js";

export {
  CRYPTO_ALGORITHMS,
  normalizeCryptoAlgorithm,
};

const ED25519_SEED_LENGTH = 32;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_PRIVATE_KEY_LENGTH = 64;
const RECOVERY_PHRASE_WORD_COUNTS = new Set([12, 24]);
const RECOVERY_PHRASE_STRENGTH_BITS = new Map([
  [12, 128],
  [24, 256],
]);
const RECOVERY_ENTROPY_LENGTH_TO_WORD_COUNT = new Map([
  [16, 12],
  [32, 24],
]);

export const SM2_PRIVATE_KEY_LENGTH = 32;
export const SM2_PUBLIC_KEY_LENGTH = 65;
export const SM2_SIGNATURE_LENGTH = 64;
export const SM2_DEFAULT_DISTINGUISHED_ID = "1234567812345678";
export const PRIVACY_FFI_VERSION_V1 = 1;
export const PRIVACY_REQUIRED_BRIDGE_ABI_VERSION = 31;
export const PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES = 256 * 1024;
export const PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1 = Object.freeze({
  VALID: 0,
  NULL_POINTER: 1,
  EMPTY: 2,
  ARCHIVE_TOO_LARGE: 3,
  DECODE_RESOURCE_LIMIT: 4,
  SCHEMA_MISMATCH: 5,
  NON_CANONICAL: 6,
  MALFORMED_ARCHIVE: 7,
  INVALID_CATALOG: 8,
});
export const PRIVACY_FFI_STATUS_ERROR = 1;
export const PRIVACY_FFI_ERROR_NULL_POINTER = 1;
export const PRIVACY_FFI_ERROR_MALFORMED_NORITO = 2;
export const PRIVACY_FFI_ERROR_UNSUPPORTED_ALGORITHM = 3;
export const PRIVACY_FFI_ERROR_PRODUCTION_DISABLED = 4;
export const PRIVACY_FFI_ERROR_INVALID_REQUEST = 5;
function normalizeSeed(seed) {
  const buffer = toBuffer(seed, "seed");
  if (buffer.length !== ED25519_SEED_LENGTH) {
    throw new Error("key-generation seed must be exactly 32 bytes");
  }
  return Buffer.from(buffer);
}

function normalizePublicKey(publicKey) {
  const buffer = toBuffer(publicKey, "publicKey");
  if (buffer.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error("ed25519 public key must be 32 bytes");
  }
  return Buffer.from(buffer);
}

function extractSeed(privateKey) {
  const buffer = toBuffer(privateKey, "privateKey");
  if (buffer.length === ED25519_SEED_LENGTH) {
    return Buffer.from(buffer);
  }
  if (buffer.length === ED25519_PRIVATE_KEY_LENGTH) {
    const seed = Buffer.from(buffer.subarray(0, ED25519_SEED_LENGTH));
    const publicKey = Buffer.from(buffer.subarray(ED25519_SEED_LENGTH));
    const derivedPublic = Buffer.from(ed25519.getPublicKey(seed));
    if (!derivedPublic.equals(publicKey)) {
      throw new Error("ed25519 private key payload has mismatched public key");
    }
    return seed;
  }
  throw new Error("ed25519 private key must be 32-byte seed or 64-byte seed+public");
}

function toBuffer(value, name) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  throw new TypeError(`${name} must be a Buffer, string, or ArrayBuffer view`);
}

function unsupported(operation) {
  throw new Error(`${operation} is unavailable in browser-only crypto builds.`);
}

export function supportedCryptoAlgorithms() {
  return [CRYPTO_ALGORITHMS.ED25519];
}

/**
 * Generate an Ed25519 key pair. Seed material is hashed to 32 bytes when needed.
 * @param {{seed?: ArrayBufferView | ArrayBuffer | Buffer, algorithm?: import("../index.js").CryptoAlgorithm}} [options]
 * @returns {{algorithm: "ed25519", publicKey: Buffer, privateKey: Buffer}}
 */
export function generateKeyPair(options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    return unsupported(`generateKeyPair(${algorithm})`);
  }
  const seed =
    options.seed === undefined
      ? Buffer.from(ed25519.utils.randomPrivateKey())
      : normalizeSeed(options.seed);
  return {
    algorithm: "ed25519",
    publicKey: Buffer.from(ed25519.getPublicKey(seed)),
    privateKey: Buffer.from(seed),
  };
}

/**
 * Derive the public key for a given private key (32-byte seed or 64-byte seed+public concatenation).
 * @param {ArrayBufferView | ArrayBuffer | Buffer} privateKey
 * @param {{algorithm?: import("../index.js").CryptoAlgorithm}} [options]
 * @returns {Buffer}
 */
export function publicKeyFromPrivate(privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    return unsupported(`publicKeyFromPrivate(${algorithm})`);
  }
  const seed = extractSeed(privateKey);
  return Buffer.from(ed25519.getPublicKey(seed));
}

export function loadKeyPair(privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    return unsupported(`loadKeyPair(${algorithm})`);
  }
  const privateKeyBuffer = toBuffer(privateKey, "privateKey");
  return {
    algorithm,
    publicKey: publicKeyFromPrivate(privateKeyBuffer),
    privateKey: extractSeed(privateKeyBuffer),
    distid: null,
  };
}

/**
 * Sign a message using an Ed25519 private key.
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
 * @param {ArrayBufferView | ArrayBuffer | Buffer} privateKey
 * @returns {Buffer}
 */
export function signEd25519(message, privateKey) {
  const messageBuffer = toBuffer(message, "message");
  const seed = extractSeed(privateKey);
  return Buffer.from(ed25519.sign(messageBuffer, seed));
}

/**
 * Verify an Ed25519 signature.
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
 * @param {ArrayBufferView | ArrayBuffer | Buffer} signature
 * @param {ArrayBufferView | ArrayBuffer | Buffer} publicKey
 * @returns {boolean}
 */
export function verifyEd25519(message, signature, publicKey) {
  const messageBuffer = toBuffer(message, "message");
  const signatureBuffer = toBuffer(signature, "signature");
  const publicKeyBuffer = normalizePublicKey(publicKey);
  return verifyEd25519Strict(messageBuffer, signatureBuffer, publicKeyBuffer);
}

function recoveryPhraseWords(phrase) {
  if (typeof phrase !== "string") {
    throw new TypeError("recovery phrase must be a string");
  }
  return phrase.normalize("NFKD").trim().toLowerCase().split(/\s+/).filter(Boolean);
}

export function normalizeRecoveryPhrase(phrase) {
  const words = recoveryPhraseWords(phrase);
  const wordCount = words.length;
  if (!RECOVERY_PHRASE_WORD_COUNTS.has(wordCount)) {
    throw new Error("recovery phrase must contain 12 or 24 words");
  }
  const normalizedPhrase = words.join(" ");
  if (!validateMnemonic(normalizedPhrase, englishWordlist)) {
    throw new Error("recovery phrase checksum or word list is invalid");
  }
  return { phrase: normalizedPhrase, words, wordCount };
}

export function validateRecoveryPhrase(phrase) {
  try {
    normalizeRecoveryPhrase(phrase);
    return true;
  } catch {
    return false;
  }
}

export function generateRecoveryPhrase(wordCount = 24) {
  const strength = RECOVERY_PHRASE_STRENGTH_BITS.get(wordCount);
  if (!strength) {
    throw new Error("recovery phrase word count must be 12 or 24");
  }
  return normalizeRecoveryPhrase(generateMnemonic(englishWordlist, strength));
}

export function entropyToRecoveryPhrase(entropy) {
  const buffer = toBuffer(entropy, "entropy");
  if (!RECOVERY_ENTROPY_LENGTH_TO_WORD_COUNT.has(buffer.length)) {
    throw new Error("recovery phrase entropy must be 16 or 32 bytes");
  }
  return normalizeRecoveryPhrase(entropyToMnemonic(buffer, englishWordlist));
}

export function recoveryPhraseToEntropy(phrase) {
  const recovery = normalizeRecoveryPhrase(phrase);
  return Buffer.from(mnemonicToEntropy(recovery.phrase, englishWordlist));
}

export function deriveEd25519SeedFromRecoveryPhrase(phrase) {
  const entropy = recoveryPhraseToEntropy(phrase);
  return entropy.length === ED25519_SEED_LENGTH
    ? entropy
    : Buffer.from(sha256(entropy));
}

export function ed25519SeedToRecoveryPhrase(privateKey) {
  return entropyToRecoveryPhrase(extractSeed(privateKey));
}

export function sign(message, privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    return unsupported(`sign(${algorithm})`);
  }
  return signEd25519(message, privateKey);
}

export function verify(message, signature, publicKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    return unsupported(`verify(${algorithm})`);
  }
  return verifyEd25519(message, signature, publicKey);
}

export function publicKeyMultihash(_publicKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  return unsupported(`publicKeyMultihash(${algorithm})`);
}

export function privateKeyMultihash(_privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  return unsupported(`privateKeyMultihash(${algorithm})`);
}

export function generateSm2KeyPair() {
  return unsupported("generateSm2KeyPair");
}

export function deriveSm2KeyPairFromSeed() {
  return unsupported("deriveSm2KeyPairFromSeed");
}

export function loadSm2KeyPair() {
  return unsupported("loadSm2KeyPair");
}

export function sm2PublicKeyMultihash() {
  return unsupported("sm2PublicKeyMultihash");
}

export function signSm2() {
  return unsupported("signSm2");
}

export function verifySm2() {
  return unsupported("verifySm2");
}

const clearKaigiBlindingV1 = Uint8Array.prototype.fill;

export function buildKaigiAuthorizationProofV1(options) {
  const blinding = options?.blinding;
  if (blinding instanceof Uint8Array) Reflect.apply(clearKaigiBlindingV1, blinding, [0]);
  return unsupported("buildKaigiAuthorizationProofV1");
}

export function buildKaigiUsageProofV1(options) {
  const blinding = options?.blinding;
  if (blinding instanceof Uint8Array) Reflect.apply(clearKaigiBlindingV1, blinding, [0]);
  return unsupported("buildKaigiUsageProofV1");
}

export function deriveConfidentialKeyset() {
  return unsupported("deriveConfidentialKeyset");
}

export function deriveConfidentialKeysetFromHex() {
  return unsupported("deriveConfidentialKeysetFromHex");
}

export function deriveConfidentialOwnerTagV2() {
  return unsupported("deriveConfidentialOwnerTagV2");
}

export function deriveConfidentialDiversifierV2() {
  return unsupported("deriveConfidentialDiversifierV2");
}

export function deriveConfidentialReceiveAddressV2() {
  return unsupported("deriveConfidentialReceiveAddressV2");
}

export function deriveConfidentialNoteV2() {
  return unsupported("deriveConfidentialNoteV2");
}

export function deriveConfidentialNullifierV2() {
  return unsupported("deriveConfidentialNullifierV2");
}

export function isPrivacyNativeAvailable() {
  return false;
}

export function privacyCompiledProfileCatalogV1() {
  return unsupported("privacyCompiledProfileCatalogV1");
}

export function sm2FixtureFromSeed() {
  return unsupported("sm2FixtureFromSeed");
}
