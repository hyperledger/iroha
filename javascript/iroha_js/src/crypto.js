import { Buffer } from "node:buffer";
import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist as englishWordlist } from "@scure/bip39/wordlists/english.js";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signRaw,
} from "node:crypto";
import { verifyEd25519Strict } from "./ed25519Strict.js";
import {
  defaultNativeRuntime,
  resolveNativeRuntimeBinding,
  resolveOptionalNativeRuntimeBinding,
} from "./nativeRuntime.js";
import { networkIdBytes } from "./networkId.js";
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
export const PRIVACY_REQUIRED_BRIDGE_ABI_VERSION = 29;
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
export const CONFIDENTIAL_MEMO_SUITES_V1 = Object.freeze({
  ML_KEM_768_XCHACHA20_POLY1305: "ml-kem-768-xchacha20-poly1305-v1",
  ML_KEM_1024_XCHACHA20_POLY1305: "ml-kem-1024-xchacha20-poly1305-v1",
});
const CONFIDENTIAL_MEMO_SUITE_PARAMETERS_V1 = Object.freeze({
  [CONFIDENTIAL_MEMO_SUITES_V1.ML_KEM_768_XCHACHA20_POLY1305]: Object.freeze({
    publicKeyBytes: 1184,
    secretKeyBytes: 2400,
  }),
  [CONFIDENTIAL_MEMO_SUITES_V1.ML_KEM_1024_XCHACHA20_POLY1305]: Object.freeze({
    publicKeyBytes: 1568,
    secretKeyBytes: 3168,
  }),
});
const CONFIDENTIAL_MEMO_MAX_RECIPIENTS_V1 = 8;
const CONFIDENTIAL_MEMO_KEYPAIR_ACCESS = Symbol("ConfidentialMemoKeypairV1.access");
const PRIVACY_MAX_BRIDGE_ABI_VERSION = 0xffff_ffff;
const SM2_FIXTURE_REFERENCE = Object.freeze({
  distid: "1234567812345678",
  seedHex: "1111111111111111111111111111111111111111111111111111111111111111",
  messageHex: "69726F686120736D2073646B2066697874757265",
  privateKeyHex: "A333F581EC034C1689B750A827E150240565B483DEB28294DDB2089AD925A569",
  publicKeySec1Hex:
    "04361255A512347E76EA947EBB416C12D4C07E30B150C0EC2047ECC5E142907499B8D99C4C5CF69BFF6527E7B67396B55E42EF98625B339696DBEF9A3AABBFC06F",
  publicKeyMultihash:
    "86265300103132333435363738313233343536373804361255A512347E76EA947EBB416C12D4C07E30B150C0EC2047ECC5E142907499B8D99C4C5CF69BFF6527E7B67396B55E42EF98625B339696DBEF9A3AABBFC06F",
  publicKeyPrefixed:
    "sm2:86265300103132333435363738313233343536373804361255A512347E76EA947EBB416C12D4C07E30B150C0EC2047ECC5E142907499B8D99C4C5CF69BFF6527E7B67396B55E42EF98625B339696DBEF9A3AABBFC06F",
  za: "E54EDEDE2A2FCC1C9DF868C56F8A2DD8C562F1AD3C78DC11DD7D91BB6F0EBD46",
  signature:
    "1877845D5FFE0305946EEA3046D0279BE886B866EF620B7325413602CAD17C7FF72EBF26C29E77AAAB2226EDFBEE2D6D6ABC0D6C9B2C9A2248E2BD9324A12268",
  r: "1877845D5FFE0305946EEA3046D0279BE886B866EF620B7325413602CAD17C7F",
  s: "F72EBF26C29E77AAAB2226EDFBEE2D6D6ABC0D6C9B2C9A2248E2BD9324A12268",
});

const SM2_FIXTURE_SEED = Buffer.from(SM2_FIXTURE_REFERENCE.seedHex, "hex");
const SM2_FIXTURE_MESSAGE = Buffer.from(SM2_FIXTURE_REFERENCE.messageHex, "hex");
export const SM2_DEFAULT_DISTINGUISHED_ID = SM2_FIXTURE_REFERENCE.distid;

const ED25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function supportedCryptoAlgorithmsWithRuntime(nativeRuntime) {
  const native = resolveOptionalNativeRuntimeBinding(nativeRuntime);
  if (typeof native?.supportedCryptoAlgorithms === "function") {
    return native.supportedCryptoAlgorithms().map((algorithm) =>
      normalizeCryptoAlgorithm(algorithm),
    );
  }
  return [CRYPTO_ALGORITHMS.ED25519];
}

function ensureGenericCryptoNative(native, operation) {
  if (!native || typeof native[operation] !== "function") {
    throw new Error(
      `${operation} requires the iroha_js_host native binding built with full crypto support`,
    );
  }
  return native;
}

function normalizeNativeKeyPair(result, algorithm) {
  return {
    algorithm: normalizeCryptoAlgorithm(result.algorithm ?? algorithm),
    publicKey: Buffer.from(result.publicKey),
    privateKey: Buffer.from(result.privateKey),
    distid: typeof result.distid === "string" ? result.distid : null,
  };
}

/**
 * Generate a key pair. Ed25519 remains available in all Node builds; other algorithms require the native binding.
 *
 * If supplied, `seed` must be a 32-byte secret generated with at least 256
 * bits of entropy. It is a deterministic key-generation seed, not a password.
 * Omit it for operating-system-random production keys.
 * @param {{seed?: ArrayBufferView | ArrayBuffer | Buffer, algorithm?: import("../index.js").CryptoAlgorithm}} [options]
 * @returns {{algorithm: string, publicKey: Buffer, privateKey: Buffer, distid?: string | null}}
 */
function generateKeyPairWithRuntime(nativeRuntime, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    const native = ensureGenericCryptoNative(
      resolveNativeRuntimeBinding(nativeRuntime),
      "cryptoKeypair",
    );
    const seed =
      options.seed === undefined ? undefined : normalizeSeed(options.seed);
    return normalizeNativeKeyPair(native.cryptoKeypair(algorithm, seed), algorithm);
  }
  const seed =
    options.seed === undefined ? undefined : normalizeSeed(options.seed);
  const native = resolveOptionalNativeRuntimeBinding(nativeRuntime);
  if (typeof native?.ed25519Keypair === "function") {
    const result = native.ed25519Keypair(seed);
    return {
      algorithm: result.algorithm,
      publicKey: Buffer.from(result.publicKey),
      privateKey: Buffer.from(result.privateKey),
    };
  }
  const privateKey = seed ?? randomBytes(ED25519_SEED_LENGTH);
  return {
    algorithm: CRYPTO_ALGORITHMS.ED25519,
    publicKey: exportPublicKey(privateKeyFromSeed(privateKey)),
    privateKey: Buffer.from(privateKey),
  };
}

/**
 * Derive the public key for a given private key (32-byte seed or 64-byte seed+public concatenation).
 * @param {ArrayBufferView | ArrayBuffer | Buffer} privateKey
 * @param {{algorithm?: import("../index.js").CryptoAlgorithm}} [options]
 * @returns {Buffer}
 */
function publicKeyFromPrivateWithRuntime(nativeRuntime, privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm !== CRYPTO_ALGORITHMS.ED25519) {
    const native = ensureGenericCryptoNative(
      resolveNativeRuntimeBinding(nativeRuntime),
      "cryptoPublicKeyFromPrivate",
    );
    return Buffer.from(
      native.cryptoPublicKeyFromPrivate(algorithm, toBuffer(privateKey, "privateKey")),
    );
  }
  const buffer = toBuffer(privateKey, "privateKey");
  const native = resolveOptionalNativeRuntimeBinding(nativeRuntime);
  if (typeof native?.ed25519PublicKeyFromPrivate === "function") {
    return Buffer.from(native.ed25519PublicKeyFromPrivate(buffer));
  }
  const seed = extractSeed(buffer);
  return exportPublicKey(privateKeyFromSeed(seed));
}

function loadKeyPairWithRuntime(nativeRuntime, privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm === CRYPTO_ALGORITHMS.ED25519) {
    const privateKeyBuffer = toBuffer(privateKey, "privateKey");
    return {
      algorithm,
      publicKey: publicKeyFromPrivateWithRuntime(
        nativeRuntime,
        privateKeyBuffer,
      ),
      privateKey: extractSeed(privateKeyBuffer),
      distid: null,
    };
  }
  const native = ensureGenericCryptoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "cryptoKeypairFromPrivate",
  );
  return normalizeNativeKeyPair(
    native.cryptoKeypairFromPrivate(algorithm, toBuffer(privateKey, "privateKey")),
    algorithm,
  );
}

/**
 * Sign a message using an Ed25519 private key.
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
 * @param {ArrayBufferView | ArrayBuffer | Buffer} privateKey
 * @returns {Buffer}
 */
export function signEd25519(message, privateKey) {
  const seed = extractSeed(privateKey);
  const privateKeyObject = privateKeyFromSeed(seed);
  const messageBuffer = toBuffer(message, "message");
  return Buffer.from(signRaw(null, messageBuffer, privateKeyObject));
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
  return normalizeRecoveryPhrase(
    entropyToMnemonic(randomBytes(strength / 8), englishWordlist),
  );
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
    : createHash("sha256").update(entropy).digest();
}

export function ed25519SeedToRecoveryPhrase(privateKey) {
  return entropyToRecoveryPhrase(extractSeed(privateKey));
}

function signWithRuntime(nativeRuntime, message, privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm === CRYPTO_ALGORITHMS.ED25519) {
    return signEd25519(message, privateKey);
  }
  const native = ensureGenericCryptoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "cryptoSign",
  );
  return Buffer.from(
    native.cryptoSign(
      algorithm,
      toBuffer(privateKey, "privateKey"),
      toBuffer(message, "message"),
    ),
  );
}

function verifyWithRuntime(
  nativeRuntime,
  message,
  signature,
  publicKey,
  options = {},
) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  if (algorithm === CRYPTO_ALGORITHMS.ED25519) {
    return verifyEd25519(message, signature, publicKey);
  }
  const native = ensureGenericCryptoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "cryptoVerify",
  );
  return Boolean(
    native.cryptoVerify(
      algorithm,
      toBuffer(publicKey, "publicKey"),
      toBuffer(message, "message"),
      toBuffer(signature, "signature"),
    ),
  );
}

function publicKeyMultihashWithRuntime(nativeRuntime, publicKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  const native = ensureGenericCryptoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "cryptoPublicKeyMultihash",
  );
  return native.cryptoPublicKeyMultihash(algorithm, toBuffer(publicKey, "publicKey"));
}

function privateKeyMultihashWithRuntime(nativeRuntime, privateKey, options = {}) {
  const algorithm = normalizeCryptoAlgorithm(options.algorithm);
  const native = ensureGenericCryptoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "cryptoPrivateKeyMultihash",
  );
  return native.cryptoPrivateKeyMultihash(algorithm, toBuffer(privateKey, "privateKey"));
}

function normalizeSm2Distid(distid, native) {
  if (distid === undefined || distid === null) {
    if (native && typeof native.sm2DefaultDistid === "function") {
      return native.sm2DefaultDistid();
    }
    return SM2_DEFAULT_DISTINGUISHED_ID;
  }
  if (typeof distid !== "string") {
    throw new TypeError("distid must be a string");
  }
  const cleaned = distid.trim();
  if (!cleaned) {
    throw new Error("distid must not be empty");
  }
  return cleaned;
}

function ensureSm2Native(native) {
  if (
    !native ||
    typeof native.sm2Keypair !== "function" ||
    typeof native.sm2KeypairFromSeed !== "function" ||
    typeof native.sm2KeypairFromPrivate !== "function" ||
    typeof native.sm2Sign !== "function" ||
    typeof native.sm2Verify !== "function" ||
    typeof native.sm2PublicKeyMultihash !== "function"
  ) {
    throw new Error(
      "SM2 operations require the iroha_js_host native binding built with SM support",
    );
  }
  return native;
}

function ensureConfidentialV2Native(native, operation) {
  if (!native || typeof native[operation] !== "function") {
    throw new Error(
      `confidential v2 helper '${operation}' is unavailable; build iroha_js_host with \`npm run build:native\` before using shielded transfer v2`,
    );
  }
  return native;
}

function ensureConfidentialMemoNative(native, operation) {
  if (!native || typeof native[operation] !== "function") {
    throw new Error(
      `confidential memo helper '${operation}' is unavailable; build iroha_js_host with \`npm run build:native\``,
    );
  }
  return native;
}

function normalizeConfidentialMemoSuiteV1(value, context = "suite") {
  if (!Object.prototype.hasOwnProperty.call(CONFIDENTIAL_MEMO_SUITE_PARAMETERS_V1, value)) {
    throw new Error(
      `${context} must be exactly ${Object.values(CONFIDENTIAL_MEMO_SUITES_V1).join(" or ")}`,
    );
  }
  return value;
}

function assertExactConfidentialMemoFields(value, fields, context) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  const expected = new Set(fields);
  for (const key of Object.keys(value)) {
    if (!expected.has(key)) {
      throw new TypeError(`${context} contains unknown field ${key}`);
    }
  }
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      throw new TypeError(`${context}.${field} is required`);
    }
  }
}

/**
 * Local, explicitly destroyable ML-KEM keypair for confidential memos.
 * The secret key is never exposed as a public property.
 */
export class ConfidentialMemoKeypairV1 {
  #suite;
  #publicKey;
  #secretKey;
  #nativeRuntime;
  #destroyed = false;

  constructor(access, nativeRuntime, suite, publicKey, secretKey) {
    if (access !== CONFIDENTIAL_MEMO_KEYPAIR_ACCESS) {
      throw new TypeError("ConfidentialMemoKeypairV1 instances must be generated by the SDK");
    }
    this.#nativeRuntime = nativeRuntime;
    this.#suite = suite;
    this.#publicKey = Buffer.from(publicKey);
    this.#secretKey = Buffer.from(secretKey);
  }

  get suite() {
    return this.#suite;
  }

  get publicKey() {
    this.#assertLive();
    return Buffer.from(this.#publicKey);
  }

  get destroyed() {
    return this.#destroyed;
  }

  destroy() {
    if (!this.#destroyed) {
      this.#publicKey.fill(0);
      this.#secretKey.fill(0);
      this.#destroyed = true;
    }
  }

  open(envelope) {
    return openConfidentialMemoV1WithRuntime(this.#nativeRuntime, {
      keypair: this,
      envelope,
    });
  }

  _borrowSecretKeyV1(access) {
    if (access !== CONFIDENTIAL_MEMO_KEYPAIR_ACCESS) {
      throw new TypeError("confidential memo secret-key access is private to the SDK");
    }
    this.#assertLive();
    return this.#secretKey;
  }

  #assertLive() {
    if (this.#destroyed) {
      throw new Error("ConfidentialMemoKeypairV1 has been destroyed");
    }
  }
}

/** Generate one local ML-KEM confidential-memo keypair. */
function generateConfidentialMemoKeypairV1WithRuntime(nativeRuntime, input) {
  assertExactConfidentialMemoFields(input, ["suite"], "generateConfidentialMemoKeypairV1 input");
  const suite = normalizeConfidentialMemoSuiteV1(input.suite);
  const native = ensureConfidentialMemoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "generateConfidentialMemoKeypairV1",
  );
  const generated = native.generateConfidentialMemoKeypairV1(suite);
  if (generated?.suite !== suite) {
    throw new Error("native confidential memo keypair returned a different suite");
  }
  const publicKey = toOwnedBuffer(generated.publicKey, "generated.publicKey");
  const nativeSecretKey = toBuffer(generated.secretKey, "generated.secretKey");
  const secretKey = Buffer.from(nativeSecretKey);
  const parameters = CONFIDENTIAL_MEMO_SUITE_PARAMETERS_V1[suite];
  try {
    if (
      publicKey.length !== parameters.publicKeyBytes ||
      secretKey.length !== parameters.secretKeyBytes
    ) {
      publicKey.fill(0);
      throw new Error("native confidential memo keypair returned malformed key material");
    }
    return new ConfidentialMemoKeypairV1(
      CONFIDENTIAL_MEMO_KEYPAIR_ACCESS,
      nativeRuntime,
      suite,
      publicKey,
      secretKey,
    );
  } finally {
    nativeSecretKey.fill(0);
    secretKey.fill(0);
  }
}

/** Seal a memo to one through eight suite-matched local recipient keys. */
function sealConfidentialMemoV1WithRuntime(nativeRuntime, input) {
  assertExactConfidentialMemoFields(
    input,
    ["suite", "recipients", "plaintext"],
    "sealConfidentialMemoV1 input",
  );
  const suite = normalizeConfidentialMemoSuiteV1(input.suite);
  if (!Array.isArray(input.recipients) || input.recipients.length < 1 || input.recipients.length > CONFIDENTIAL_MEMO_MAX_RECIPIENTS_V1) {
    throw new RangeError("recipients must contain between one and eight entries");
  }
  const parameters = CONFIDENTIAL_MEMO_SUITE_PARAMETERS_V1[suite];
  const recipients = input.recipients.map((recipient, index) => {
    let recipientSuite;
    let publicKey;
    if (recipient instanceof ConfidentialMemoKeypairV1) {
      recipientSuite = recipient.suite;
      publicKey = recipient.publicKey;
    } else {
      assertExactConfidentialMemoFields(
        recipient,
        ["suite", "publicKey"],
        `recipients[${index}]`,
      );
      recipientSuite = normalizeConfidentialMemoSuiteV1(
        recipient.suite,
        `recipients[${index}].suite`,
      );
      publicKey = toOwnedBuffer(recipient.publicKey, `recipients[${index}].publicKey`);
    }
    if (recipientSuite !== suite) {
      throw new Error(`recipients[${index}].suite does not match the memo suite`);
    }
    if (publicKey.length !== parameters.publicKeyBytes) {
      throw new RangeError(
        `recipients[${index}].publicKey must be exactly ${parameters.publicKeyBytes} bytes`,
      );
    }
    return publicKey;
  });
  if (typeof input.plaintext === "string") {
    throw new TypeError("plaintext must be an explicit byte buffer, not a string");
  }
  const plaintext = toOwnedBuffer(input.plaintext, "plaintext");
  const native = ensureConfidentialMemoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "sealConfidentialMemoV1",
  );
  try {
    return Buffer.from(native.sealConfidentialMemoV1(suite, recipients, plaintext));
  } finally {
    plaintext.fill(0);
  }
}

/** Open one exact-eight-slot memo without exposing the keypair's secret bytes. */
function openConfidentialMemoV1WithRuntime(nativeRuntime, input) {
  assertExactConfidentialMemoFields(
    input,
    ["keypair", "envelope"],
    "openConfidentialMemoV1 input",
  );
  if (!(input.keypair instanceof ConfidentialMemoKeypairV1)) {
    throw new TypeError("keypair must be a live ConfidentialMemoKeypairV1");
  }
  const envelope = toOwnedBuffer(input.envelope, "envelope");
  const native = ensureConfidentialMemoNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "openConfidentialMemoV1",
  );
  return Buffer.from(
    native.openConfidentialMemoV1(
      input.keypair.suite,
      input.keypair._borrowSecretKeyV1(CONFIDENTIAL_MEMO_KEYPAIR_ACCESS),
      envelope,
    ),
  );
}

function generateSm2KeyPairWithRuntime(nativeRuntime, options = {}) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const effectiveDistid = normalizeSm2Distid(options.distid, native);
  const result = native.sm2Keypair(effectiveDistid);
  const privateKey = Buffer.from(result.privateKey);
  const publicKey = Buffer.from(result.publicKey);
  if (privateKey.length !== SM2_PRIVATE_KEY_LENGTH) {
    throw new Error("native sm2Keypair returned invalid private key length");
  }
  if (publicKey.length !== SM2_PUBLIC_KEY_LENGTH) {
    throw new Error("native sm2Keypair returned invalid public key length");
  }
  return {
    algorithm: "sm2",
    distid: typeof result.distid === "string" ? result.distid : effectiveDistid,
    privateKey,
    publicKey,
  };
}

function deriveSm2KeyPairFromSeedWithRuntime(nativeRuntime, seed, distid) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const seedBuffer = toBuffer(seed, "seed");
  const effectiveDistid = normalizeSm2Distid(distid, native);
  const result = native.sm2KeypairFromSeed(effectiveDistid, seedBuffer);
  const privateKey = Buffer.from(result.privateKey);
  const publicKey = Buffer.from(result.publicKey);
  if (privateKey.length !== SM2_PRIVATE_KEY_LENGTH) {
    throw new Error("native sm2KeypairFromSeed returned invalid private key length");
  }
  if (publicKey.length !== SM2_PUBLIC_KEY_LENGTH) {
    throw new Error("native sm2KeypairFromSeed returned invalid public key length");
  }
  return {
    algorithm: "sm2",
    distid: typeof result.distid === "string" ? result.distid : effectiveDistid,
    privateKey,
    publicKey,
  };
}

function loadSm2KeyPairWithRuntime(nativeRuntime, privateKey, distid) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const privateKeyBuffer = toBuffer(privateKey, "privateKey");
  if (privateKeyBuffer.length !== SM2_PRIVATE_KEY_LENGTH) {
    throw new Error(`sm2 private key must be ${SM2_PRIVATE_KEY_LENGTH} bytes`);
  }
  const effectiveDistid = normalizeSm2Distid(distid, native);
  const result = native.sm2KeypairFromPrivate(effectiveDistid, privateKeyBuffer);
  return {
    algorithm: "sm2",
    distid: typeof result.distid === "string" ? result.distid : effectiveDistid,
    privateKey: Buffer.from(result.privateKey),
    publicKey: Buffer.from(result.publicKey),
  };
}

function sm2PublicKeyMultihashWithRuntime(nativeRuntime, publicKey, distid) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const buffer = toBuffer(publicKey, "publicKey");
  if (buffer.length !== SM2_PUBLIC_KEY_LENGTH) {
    throw new Error(`sm2 public key must be ${SM2_PUBLIC_KEY_LENGTH} bytes`);
  }
  const effectiveDistid = normalizeSm2Distid(distid, native);
  return native.sm2PublicKeyMultihash(buffer, effectiveDistid);
}

function signSm2WithRuntime(nativeRuntime, message, privateKey, distid) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const privateKeyBuffer = toBuffer(privateKey, "privateKey");
  if (privateKeyBuffer.length !== SM2_PRIVATE_KEY_LENGTH) {
    throw new Error(`sm2 private key must be ${SM2_PRIVATE_KEY_LENGTH} bytes`);
  }
  const messageBuffer = toBuffer(message, "message");
  const effectiveDistid = normalizeSm2Distid(distid, native);
  const signature = native.sm2Sign(privateKeyBuffer, messageBuffer, effectiveDistid);
  const buffer = Buffer.from(signature);
  if (buffer.length !== SM2_SIGNATURE_LENGTH) {
    throw new Error("native sm2Sign returned invalid signature length");
  }
  return buffer;
}

function verifySm2WithRuntime(
  nativeRuntime,
  message,
  signature,
  publicKey,
  distid,
) {
  const native = ensureSm2Native(resolveNativeRuntimeBinding(nativeRuntime));
  const publicKeyBuffer = toBuffer(publicKey, "publicKey");
  if (publicKeyBuffer.length !== SM2_PUBLIC_KEY_LENGTH) {
    throw new Error(`sm2 public key must be ${SM2_PUBLIC_KEY_LENGTH} bytes`);
  }
  const signatureBuffer = toBuffer(signature, "signature");
  if (signatureBuffer.length !== SM2_SIGNATURE_LENGTH) {
    throw new Error(`sm2 signature must be ${SM2_SIGNATURE_LENGTH} bytes`);
  }
  const messageBuffer = toBuffer(message, "message");
  const effectiveDistid = normalizeSm2Distid(distid, native);
  return Boolean(
    native.sm2Verify(publicKeyBuffer, messageBuffer, signatureBuffer, effectiveDistid),
  );
}

const KAIGI_AUTHORIZATION_ACTIONS_V1 = new Set(["hostCreate", "join", "leave", "hostEnd"]);
const KAIGI_AUTHORIZATION_OPTION_KEYS_V1 = new Set([
  "networkId", "callId", "hostId", "subjectId", "participationSequence", "action", "preRosterRoot", "blinding",
]);
const KAIGI_PASTA_FP_MODULUS_V1 = BigInt("0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001");
const clearKaigiBlindingV1 = Uint8Array.prototype.fill;
const kaigiTypedArrayPrototypeV1 = Object.getPrototypeOf(Uint8Array.prototype);
const kaigiBufferGetterV1 = Object.getOwnPropertyDescriptor(kaigiTypedArrayPrototypeV1, "buffer").get;
const kaigiByteLengthGetterV1 = Object.getOwnPropertyDescriptor(kaigiTypedArrayPrototypeV1, "byteLength").get;
const KaigiSharedArrayBufferV1 = globalThis.SharedArrayBuffer;


function kaigiBytesV1(value, name, length = 32) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new TypeError(`${name} must be a ${length}-byte Uint8Array`);
  }
  return Buffer.from(value);
}

function kaigiScalarV1(value, name) {
  const bytes = kaigiBytesV1(value, name);
  let scalar = 0n;
  for (let index = 31; index >= 0; index -= 1) scalar = (scalar << 8n) | BigInt(bytes[index]);
  if (scalar >= KAIGI_PASTA_FP_MODULUS_V1) {
    throw new TypeError(`${name} must be canonical Pasta Fp bytes`);
  }
  return bytes;
}

function buildKaigiAuthorizationProofV1WithRuntime(nativeRuntime, options) {
  const blinding = options?.blinding;
  if (!(blinding instanceof Uint8Array)) {
    throw new TypeError("blinding must be a mutable 32-byte Uint8Array");
  }
  try {
    if (!options || typeof options !== "object" || Array.isArray(options)) {
      throw new TypeError("buildKaigiAuthorizationProofV1 options must be an object");
    }
    for (const key of Object.keys(options)) {
      if (!KAIGI_AUTHORIZATION_OPTION_KEYS_V1.has(key)) throw new TypeError(`unknown Kaigi authorization option: ${key}`);
    }
    if (Reflect.apply(kaigiByteLengthGetterV1, blinding, []) !== 32 ||
        (KaigiSharedArrayBufferV1 !== undefined && Reflect.apply(kaigiBufferGetterV1, blinding, []) instanceof KaigiSharedArrayBufferV1)) {
      throw new TypeError("blinding must be a private mutable 32-byte Uint8Array");
    }
    const network = networkIdBytes(options.networkId);
    const call = options.callId;
    if (!call || typeof call !== "object" || Array.isArray(call) ||
        Object.keys(call).some((key) => key !== "domainId" && key !== "callName")) {
      throw new TypeError("callId must contain exactly domainId and callName");
    }
    const domainId = call.domainId;
    const callName = call.callName;
    const hostId = options.hostId;
    const subjectId = options.subjectId;
    const action = options.action;
    for (const [name, value] of [["callId.domainId", domainId], ["callId.callName", callName], ["hostId", hostId], ["subjectId", subjectId]]) {
      if (typeof value !== "string" || value.length === 0 || value.trim() !== value) throw new TypeError(`${name} must be canonical nonempty text`);
    }
    const sequence = options.participationSequence;
    if (typeof sequence !== "bigint" || sequence < 0n || sequence > 0xffff_ffff_ffff_ffffn) {
      throw new TypeError("participationSequence must be an unsigned 64-bit bigint");
    }
    if (!KAIGI_AUTHORIZATION_ACTIONS_V1.has(action)) throw new TypeError("unknown Kaigi authorization action");
    const root = kaigiBytesV1(options.preRosterRoot, "preRosterRoot");
    const native = resolveNativeRuntimeBinding(nativeRuntime);
    if (typeof native.buildKaigiAuthorizationProofV1 !== "function") throw new Error("Native binding does not expose buildKaigiAuthorizationProofV1");
    const raw = native.buildKaigiAuthorizationProofV1(network, domainId, callName, hostId,
      subjectId, sequence, action, root, blinding);
    const proofBytes = raw.proof;
    const result = {
      commitment: kaigiScalarV1(raw.commitment, "commitment"),
      nullifier: kaigiScalarV1(raw.nullifier, "nullifier"),
      authorization: kaigiScalarV1(raw.authorization, "authorization"),
      preRosterRoot: kaigiBytesV1(raw.preRosterRoot, "preRosterRoot"),
      proof: kaigiBytesV1(proofBytes, "proof", proofBytes?.byteLength),
    };
    if (result.proof.length === 0 || !result.preRosterRoot.equals(root)) throw new Error("Native Kaigi proof returned an empty proof or different pre-state root");
    return Object.freeze(result);
  } finally {
    Reflect.apply(clearKaigiBlindingV1, blinding, [0]);
  }
}

/**
 * Prove one final Kaigi V1 action against its exact network, identities and pre-state.
 * The supplied mutable blinding is consumed and cleared on success or failure.
 */
export function buildKaigiAuthorizationProofV1(options) {
  return buildKaigiAuthorizationProofV1WithRuntime(defaultNativeRuntime, options);
}

const KAIGI_USAGE_OPTION_KEYS_V1 = new Set([
  "networkId", "callId", "hostId", "preRosterRoot", "segmentIndex", "durationMs", "billedGas", "hostCommitment", "blinding",
]);

function buildKaigiUsageProofV1WithRuntime(nativeRuntime, options) {
  const blinding = options?.blinding;
  if (!(blinding instanceof Uint8Array)) throw new TypeError("blinding must be a mutable 32-byte Uint8Array");
  try {
    if (!options || typeof options !== "object" || Array.isArray(options)) throw new TypeError("buildKaigiUsageProofV1 options must be an object");
    for (const key of Object.keys(options)) {
      if (!KAIGI_USAGE_OPTION_KEYS_V1.has(key)) throw new TypeError(`unknown Kaigi usage option: ${key}`);
    }
    if (Reflect.apply(kaigiByteLengthGetterV1, blinding, []) !== 32 ||
        (KaigiSharedArrayBufferV1 !== undefined && Reflect.apply(kaigiBufferGetterV1, blinding, []) instanceof KaigiSharedArrayBufferV1)) {
      throw new TypeError("blinding must be a private mutable 32-byte Uint8Array");
    }
    const network = networkIdBytes(options.networkId);
    const call = options.callId;
    if (!call || typeof call !== "object" || Array.isArray(call) ||
        Object.keys(call).some((key) => key !== "domainId" && key !== "callName")) {
      throw new TypeError("callId must contain exactly domainId and callName");
    }
    const { domainId, callName } = call;
    const hostId = options.hostId;
    for (const [name, value] of [["callId.domainId", domainId], ["callId.callName", callName], ["hostId", hostId]]) {
      if (typeof value !== "string" || value.length === 0 || value.trim() !== value) throw new TypeError(`${name} must be canonical nonempty text`);
    }
    const segment = options.segmentIndex;
    if (!Number.isInteger(segment) || segment < 0 || segment > 0xffff_ffff) throw new TypeError("segmentIndex must be an unsigned 32-bit integer");
    const duration = options.durationMs;
    const gas = options.billedGas;
    for (const [name, value] of [["durationMs", duration], ["billedGas", gas]]) {
      if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new TypeError(`${name} must be an unsigned 64-bit bigint`);
    }
    if (duration === 0n) throw new TypeError("durationMs must be positive");
    const root = kaigiBytesV1(options.preRosterRoot, "preRosterRoot");
    const hostCommitment = kaigiScalarV1(options.hostCommitment, "hostCommitment");
    const native = resolveNativeRuntimeBinding(nativeRuntime);
    if (typeof native.buildKaigiUsageProofV1 !== "function") throw new Error("Native binding does not expose buildKaigiUsageProofV1");
    const raw = native.buildKaigiUsageProofV1(network, domainId, callName, hostId, root,
      segment, duration, gas, hostCommitment, blinding);
    const proofBytes = raw.proof;
    const result = {
      hostCommitment: kaigiScalarV1(raw.hostCommitment, "hostCommitment"),
      usageCommitment: kaigiScalarV1(raw.usageCommitment, "usageCommitment"),
      preRosterRoot: kaigiBytesV1(raw.preRosterRoot, "preRosterRoot"),
      proof: kaigiBytesV1(proofBytes, "proof", proofBytes?.byteLength),
    };
    if (result.proof.length === 0 || !result.preRosterRoot.equals(root) || !result.hostCommitment.equals(hostCommitment)) {
      throw new Error("Native Kaigi usage proof returned an empty proof, different pre-state root or different host commitment");
    }
    return Object.freeze(result);
  } finally {
    Reflect.apply(clearKaigiBlindingV1, blinding, [0]);
  }
}

/** Prove a usage segment with the opening of stored host C; consume and clear blinding. */
export function buildKaigiUsageProofV1(options) {
  return buildKaigiUsageProofV1WithRuntime(defaultNativeRuntime, options);
}

/**
 * Derive the confidential key hierarchy from a 32-byte spend key.
 * @param {ArrayBufferView | ArrayBuffer | Buffer} spendKey
 * @returns {{skSpend: Buffer, nk: Buffer, ivk: Buffer, ovk: Buffer, fvk: Buffer, skSpendHex: string, nkHex: string, ivkHex: string, ovkHex: string, fvkHex: string, asHex(): Record<string, string>}}
 */
function deriveConfidentialKeysetWithRuntime(nativeRuntime, spendKey) {
  const seed = toBuffer(spendKey, "spendKey");
  if (seed.length !== 32) {
    throw new Error("confidential spend key must be 32 bytes");
  }

  const native = resolveNativeRuntimeBinding(nativeRuntime);
  if (typeof native.deriveConfidentialKeyset !== "function") {
    throw new Error("Native binding does not expose deriveConfidentialKeyset");
  }
  const raw = native.deriveConfidentialKeyset(seed);

  const keyset = {
    skSpend: toBufferField(raw, "sk_spend", "skSpend"),
    nk: toBufferField(raw, "nk"),
    ivk: toBufferField(raw, "ivk"),
    ovk: toBufferField(raw, "ovk"),
    fvk: toBufferField(raw, "fvk"),
  };
  return wrapConfidentialKeyset(keyset);
}

/**
 * Derive the confidential key hierarchy from a hex-encoded spend key.
 * @param {string} spendKeyHex
 * @returns {ReturnType<typeof deriveConfidentialKeyset>}
 */
function deriveConfidentialKeysetFromHexWithRuntime(nativeRuntime, spendKeyHex) {
  if (typeof spendKeyHex !== "string") {
    throw new TypeError("spendKeyHex must be a string");
  }
  if (spendKeyHex.trim() !== spendKeyHex) {
    throw new Error("spendKeyHex must not contain surrounding whitespace");
  }
  const cleaned = spendKeyHex;
  if (cleaned.length !== 64) {
    throw new Error("confidential spend key must be 64 hex characters (32 bytes)");
  }
  const seed = Buffer.from(cleaned, "hex");
  if (seed.length !== 32) {
    throw new Error("confidential spend key must be valid hex");
  }
  return deriveConfidentialKeysetWithRuntime(nativeRuntime, seed);
}

/**
 * Derive the confidential v2 owner tag from a 32-byte spend key.
 * @param {ArrayBufferView | ArrayBuffer | Buffer} spendKey
 * @param {{diversifierHex: string}} options
 * @returns {Buffer}
 */
function deriveConfidentialOwnerTagV2WithRuntime(
  nativeRuntime,
  spendKey,
  options,
) {
  const native = ensureConfidentialV2Native(
    resolveNativeRuntimeBinding(nativeRuntime),
    "deriveConfidentialOwnerTagV2",
  );
  const spendKeyBuffer = toBuffer(spendKey, "spendKey");
  if (spendKeyBuffer.length !== 32) {
    throw new Error("confidential spend key must be 32 bytes");
  }
  if (options?.diversifier !== undefined) {
    throw new Error("diversifier must use canonical diversifierHex");
  }
  if (options?.diversifierHex === undefined) {
    throw new Error("diversifier is required");
  }
  const diversifierHex = normalizeFixed32HexInput(options.diversifierHex, "diversifier");
  return Buffer.from(native.deriveConfidentialOwnerTagV2(spendKeyBuffer, diversifierHex));
}

/**
 * Derive a canonical confidential v2 diversifier from seed material.
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} seed
 * @returns {{diversifier: Buffer, diversifierHex: string}}
 */
function deriveConfidentialDiversifierV2WithRuntime(nativeRuntime, seed) {
  const native = ensureConfidentialV2Native(
    resolveNativeRuntimeBinding(nativeRuntime),
    "deriveConfidentialDiversifierV2",
  );
  const seedBuffer = toBuffer(seed, "seed");
  if (seedBuffer.length === 0) {
    throw new Error("seed must not be empty");
  }
  const diversifier = Buffer.from(native.deriveConfidentialDiversifierV2(seedBuffer));
  return {
    diversifier,
    diversifierHex: diversifier.toString("hex"),
  };
}

/**
 * Derive diversified confidential v2 receive-address material.
 * @param {{spendKey: ArrayBufferView | ArrayBuffer | Buffer, diversifierSeed: ArrayBufferView | ArrayBuffer | Buffer | string}} input
 * @returns {{ownerTag: Buffer, ownerTagHex: string, diversifier: Buffer, diversifierHex: string}}
 */
function deriveConfidentialReceiveAddressV2WithRuntime(nativeRuntime, input) {
  const native = ensureConfidentialV2Native(
    resolveNativeRuntimeBinding(nativeRuntime),
    "deriveConfidentialReceiveAddressV2",
  );
  const spendKeyBuffer = toBuffer(input?.spendKey, "spendKey");
  if (spendKeyBuffer.length !== 32) {
    throw new Error("confidential spend key must be 32 bytes");
  }
  const diversifierSeed = toBuffer(input?.diversifierSeed, "diversifierSeed");
  if (diversifierSeed.length === 0) {
    throw new Error("diversifierSeed must not be empty");
  }
  const raw = native.deriveConfidentialReceiveAddressV2(spendKeyBuffer, diversifierSeed);
  const ownerTagHex = String(raw.ownerTagHex ?? raw.owner_tag_hex ?? "");
  const diversifierHex = String(raw.diversifierHex ?? raw.diversifier_hex ?? "");
  return {
    ownerTag: Buffer.from(normalizeFixed32HexInput(ownerTagHex, "ownerTag"), "hex"),
    ownerTagHex: normalizeFixed32HexInput(ownerTagHex, "ownerTag"),
    diversifier: Buffer.from(normalizeFixed32HexInput(diversifierHex, "diversifier"), "hex"),
    diversifierHex: normalizeFixed32HexInput(diversifierHex, "diversifier"),
  };
}

/**
 * Derive a confidential v2 note commitment from note material.
 * @param {{assetDefinitionId: string, amount: string | number | bigint, rhoHex?: string, rho?: ArrayBufferView | ArrayBuffer | Buffer, ownerTagHex?: string, ownerTag?: ArrayBufferView | ArrayBuffer | Buffer}} input
 * @returns {{commitment: Buffer, commitmentHex: string}}
 */
function deriveConfidentialNoteV2WithRuntime(nativeRuntime, input) {
  const native = ensureConfidentialV2Native(
    resolveNativeRuntimeBinding(nativeRuntime),
    "deriveConfidentialNoteV2",
  );
  const assetDefinitionId = normalizeConfidentialV2ExactString(
    input?.assetDefinitionId,
    "assetDefinitionId",
  );
  const amount = normalizeWholeNumberLiteral(input?.amount, "amount");
  const rhoHex = normalizeFixed32HexInput(input?.rhoHex ?? input?.rho, "rho");
  const ownerTagHex = normalizeFixed32HexInput(
    input?.ownerTagHex ?? input?.ownerTag,
    "ownerTag",
  );
  const commitment = Buffer.from(
    native.deriveConfidentialNoteV2(
      assetDefinitionId,
      amount,
      rhoHex,
      ownerTagHex,
    ),
  );
  return {
    commitment,
    commitmentHex: commitment.toString("hex"),
  };
}

/**
 * Derive a confidential v2 nullifier from note material.
 * @param {{networkId: import("./networkId.js").NetworkId, assetDefinitionId: string, spendKey: ArrayBufferView | ArrayBuffer | Buffer, rhoHex?: string, rho?: ArrayBufferView | ArrayBuffer | Buffer}} input
 * @returns {{nullifier: Buffer, nullifierHex: string}}
 */
function deriveConfidentialNullifierV2WithRuntime(nativeRuntime, input) {
  const native = ensureConfidentialV2Native(
    resolveNativeRuntimeBinding(nativeRuntime),
    "deriveConfidentialNullifierV2",
  );
  const networkId = Buffer.from(
    networkIdBytes(input?.networkId, "networkId"),
  );
  const assetDefinitionId = normalizeConfidentialV2ExactString(
    input?.assetDefinitionId,
    "assetDefinitionId",
  );
  const spendKey = toBuffer(input?.spendKey, "spendKey");
  if (spendKey.length !== 32) {
    throw new Error("confidential spend key must be 32 bytes");
  }
  const rhoHex = normalizeFixed32HexInput(input?.rhoHex ?? input?.rho, "rho");
  const nullifier = Buffer.from(
    native.deriveConfidentialNullifierV2(
      networkId,
      assetDefinitionId,
      spendKey,
      rhoHex,
    ),
  );
  return {
    nullifier,
    nullifierHex: nullifier.toString("hex"),
  };
}

function hasPrivacyNativeSurface(native) {
  const abiVersion = privacyBridgeAbiVersion(native);
  return (
    native &&
    Number.isInteger(abiVersion) &&
    abiVersion === PRIVACY_REQUIRED_BRIDGE_ABI_VERSION &&
    typeof native.privacyCompiledProfileCatalogV1 === "function" &&
    typeof native.privacyValidateCompiledProfileCatalogV1 === "function"
  );
}

function hasPrivacyNative(native) {
  return (
    hasPrivacyNativeSurface(native) &&
    privacyNativeProbeReturnsBytes(native, "privacyCompiledProfileCatalogV1")
  );
}

function privacyNativeProbeReturnsBytes(native, operation) {
  let result;
  try {
    result = native[operation]();
    privacyNativeOutputToBuffer(native, result, operation, { clearSource: true });
    return true;
  } catch {
    return false;
  }
}

function privacyBridgeAbiVersion(native) {
  if (typeof native?.connectNoritoBridgeAbiVersion !== "function") {
    return 0;
  }
  try {
    const version = native.connectNoritoBridgeAbiVersion();
    return typeof version === "number" &&
      Number.isSafeInteger(version) &&
      version >= 0 &&
      version <= PRIVACY_MAX_BRIDGE_ABI_VERSION
      ? version
      : 0;
  } catch {
    return 0;
  }
}

function ensurePrivacyNative(native, operation) {
  if (!hasPrivacyNativeSurface(native)) {
    throw new Error(
      `${operation} requires the iroha_js_host native binding built with privacy FFI support`,
    );
  }
  return native;
}

function toPrivacyArchiveBuffer(value, name) {
  if (typeof value === "string") {
    throw new TypeError(`${name} must be Norito V1 bytes, not a string`);
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array || value instanceof DataView) {
    if (!(value.buffer instanceof ArrayBuffer)) {
      throw new TypeError(`${name} must not use shared memory`);
    }
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  throw new TypeError(
    `${name} must be Norito V1 bytes as a Buffer, Uint8Array, DataView, or ArrayBuffer`,
  );
}

function privacyNativeOutputToBuffer(native, result, operation, options = {}) {
  let output;
  if (result === undefined || result === null) {
    throw new Error(`native ${operation} returned no output`);
  }
  if (typeof result === "string") {
    throw new Error(`native ${operation} returned text instead of Norito V1 bytes`);
  }
  try {
    output = toPrivacyArchiveBuffer(result, `native ${operation} output`);
    if (output.length === 0) {
      throw new Error(`native ${operation} returned empty output`);
    }
    if (output.length > PRIVACY_COMPILED_PROFILE_CATALOG_ARCHIVE_MAX_BYTES) {
      throw new Error(`native ${operation} returned oversized output`);
    }
    const validationStatus = invokePrivacyNative(
      native,
      "privacyValidateCompiledProfileCatalogV1",
      output,
    );
    if (
      validationStatus !==
      PRIVACY_COMPILED_PROFILE_CATALOG_VALIDATION_STATUS_V1.VALID
    ) {
      throw new Error(
        `native ${operation} returned an invalid typed privacy compiled-profile catalog`,
      );
    }
    return Buffer.from(output);
  } finally {
    if (options.clearSource === true && output) {
      output.fill(0);
    }
  }
}

function invokePrivacyNative(native, operation, ...args) {
  try {
    return native[operation](...args);
  } catch {
    throw new Error(`native ${operation} failed`);
  }
}

function isPrivacyNativeAvailableWithRuntime(nativeRuntime) {
  return hasPrivacyNative(resolveOptionalNativeRuntimeBinding(nativeRuntime));
}

/**
 * Return this native binary's canonical local compiled-profile catalog.
 *
 * The catalog contains no committed height, governance activation, or network
 * readiness. Use `getPrivacyExact12CapabilityManifestV1` with the Node/N-API
 * Torii client for the authoritative committed manifest.
 * @returns {Buffer}
 */
function privacyCompiledProfileCatalogV1WithRuntime(nativeRuntime) {
  const native = ensurePrivacyNative(
    resolveNativeRuntimeBinding(nativeRuntime),
    "privacyCompiledProfileCatalogV1",
  );
  const result = invokePrivacyNative(native, "privacyCompiledProfileCatalogV1");
  return privacyNativeOutputToBuffer(
    native,
    result,
    "privacyCompiledProfileCatalogV1",
  );
}

/**
 * Return the canonical SM2 signing fixture values for the given seed and message.
 * @param {string} distid
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} seed
 * @param {ArrayBufferView | ArrayBuffer | Buffer | string} message
 * @returns {{distid: string, seedHex: string, messageHex: string, privateKeyHex: string, publicKeySec1Hex: string, publicKeyMultihash: string, publicKeyPrefixed: string, za: string, signature: string, r: string, s: string}}
 */
function sm2FixtureFromSeedWithRuntime(nativeRuntime, distid, seed, message) {
  if (typeof distid !== "string") {
    throw new TypeError("distid must be a string");
  }
  const native = resolveNativeRuntimeBinding(nativeRuntime);
  const seedBuffer = toBuffer(seed, "seed");
  const messageBuffer = toBuffer(message, "message");
  if (!native?.sm2FixtureFromSeed) {
    if (
      distid === SM2_FIXTURE_REFERENCE.distid &&
      seedBuffer.equals(SM2_FIXTURE_SEED) &&
      messageBuffer.equals(SM2_FIXTURE_MESSAGE)
    ) {
      return { ...SM2_FIXTURE_REFERENCE };
    }
    throw new Error("SM2 fixture helper unavailable; build iroha_js_host with SM support");
  }
  const fixture = native.sm2FixtureFromSeed(distid, seedBuffer, messageBuffer);
  return {
    distid: fixture.distid,
    seedHex: fixture.seedHex,
    messageHex: fixture.messageHex,
    privateKeyHex: fixture.privateKeyHex,
    publicKeySec1Hex: fixture.publicKeySec1Hex,
    publicKeyMultihash: fixture.publicKeyMultihash,
    publicKeyPrefixed: fixture.publicKeyPrefixed,
    za: fixture.za,
    signature: fixture.signature,
    r: fixture.r,
    s: fixture.s,
  };
}

/** @internal Source-level runtime facade; intentionally absent from package exports. */
export function _createCryptoApi(nativeRuntime) {
  return Object.freeze({
    buildKaigiAuthorizationProofV1: (options) => buildKaigiAuthorizationProofV1WithRuntime(nativeRuntime, options),
    buildKaigiUsageProofV1: (options) => buildKaigiUsageProofV1WithRuntime(nativeRuntime, options),
    supportedCryptoAlgorithms: () =>
      supportedCryptoAlgorithmsWithRuntime(nativeRuntime),
    generateKeyPair: (options = {}) =>
      generateKeyPairWithRuntime(nativeRuntime, options),
    publicKeyFromPrivate: (privateKey, options = {}) =>
      publicKeyFromPrivateWithRuntime(nativeRuntime, privateKey, options),
    loadKeyPair: (privateKey, options = {}) =>
      loadKeyPairWithRuntime(nativeRuntime, privateKey, options),
    sign: (message, privateKey, options = {}) =>
      signWithRuntime(nativeRuntime, message, privateKey, options),
    verify: (message, signature, publicKey, options = {}) =>
      verifyWithRuntime(
        nativeRuntime,
        message,
        signature,
        publicKey,
        options,
      ),
    publicKeyMultihash: (publicKey, options = {}) =>
      publicKeyMultihashWithRuntime(nativeRuntime, publicKey, options),
    privateKeyMultihash: (privateKey, options = {}) =>
      privateKeyMultihashWithRuntime(nativeRuntime, privateKey, options),
    generateConfidentialMemoKeypairV1: (input) =>
      generateConfidentialMemoKeypairV1WithRuntime(nativeRuntime, input),
    sealConfidentialMemoV1: (input) =>
      sealConfidentialMemoV1WithRuntime(nativeRuntime, input),
    openConfidentialMemoV1: (input) =>
      openConfidentialMemoV1WithRuntime(nativeRuntime, input),
    generateSm2KeyPair: (options = {}) =>
      generateSm2KeyPairWithRuntime(nativeRuntime, options),
    deriveSm2KeyPairFromSeed: (seed, distid) =>
      deriveSm2KeyPairFromSeedWithRuntime(nativeRuntime, seed, distid),
    loadSm2KeyPair: (privateKey, distid) =>
      loadSm2KeyPairWithRuntime(nativeRuntime, privateKey, distid),
    sm2PublicKeyMultihash: (publicKey, distid) =>
      sm2PublicKeyMultihashWithRuntime(nativeRuntime, publicKey, distid),
    signSm2: (message, privateKey, distid) =>
      signSm2WithRuntime(nativeRuntime, message, privateKey, distid),
    verifySm2: (message, signature, publicKey, distid) =>
      verifySm2WithRuntime(
        nativeRuntime,
        message,
        signature,
        publicKey,
        distid,
      ),
    deriveConfidentialKeyset: (spendKey) =>
      deriveConfidentialKeysetWithRuntime(nativeRuntime, spendKey),
    deriveConfidentialKeysetFromHex: (spendKeyHex) =>
      deriveConfidentialKeysetFromHexWithRuntime(nativeRuntime, spendKeyHex),
    deriveConfidentialOwnerTagV2: (spendKey, options) =>
      deriveConfidentialOwnerTagV2WithRuntime(
        nativeRuntime,
        spendKey,
        options,
      ),
    deriveConfidentialDiversifierV2: (seed) =>
      deriveConfidentialDiversifierV2WithRuntime(nativeRuntime, seed),
    deriveConfidentialReceiveAddressV2: (input) =>
      deriveConfidentialReceiveAddressV2WithRuntime(nativeRuntime, input),
    deriveConfidentialNoteV2: (input) =>
      deriveConfidentialNoteV2WithRuntime(nativeRuntime, input),
    deriveConfidentialNullifierV2: (input) =>
      deriveConfidentialNullifierV2WithRuntime(nativeRuntime, input),
    isPrivacyNativeAvailable: () =>
      isPrivacyNativeAvailableWithRuntime(nativeRuntime),
    privacyCompiledProfileCatalogV1: () =>
      privacyCompiledProfileCatalogV1WithRuntime(nativeRuntime),
    sm2FixtureFromSeed: (distid, seed, message) =>
      sm2FixtureFromSeedWithRuntime(nativeRuntime, distid, seed, message),
  });
}

export function supportedCryptoAlgorithms() {
  return supportedCryptoAlgorithmsWithRuntime(defaultNativeRuntime);
}

export function generateKeyPair(options = {}) {
  return generateKeyPairWithRuntime(defaultNativeRuntime, options);
}

export function publicKeyFromPrivate(privateKey, options = {}) {
  return publicKeyFromPrivateWithRuntime(
    defaultNativeRuntime,
    privateKey,
    options,
  );
}

export function loadKeyPair(privateKey, options = {}) {
  return loadKeyPairWithRuntime(defaultNativeRuntime, privateKey, options);
}

export function sign(message, privateKey, options = {}) {
  return signWithRuntime(defaultNativeRuntime, message, privateKey, options);
}

export function verify(message, signature, publicKey, options = {}) {
  return verifyWithRuntime(
    defaultNativeRuntime,
    message,
    signature,
    publicKey,
    options,
  );
}

export function publicKeyMultihash(publicKey, options = {}) {
  return publicKeyMultihashWithRuntime(
    defaultNativeRuntime,
    publicKey,
    options,
  );
}

export function privateKeyMultihash(privateKey, options = {}) {
  return privateKeyMultihashWithRuntime(
    defaultNativeRuntime,
    privateKey,
    options,
  );
}

export function generateConfidentialMemoKeypairV1(input) {
  return generateConfidentialMemoKeypairV1WithRuntime(
    defaultNativeRuntime,
    input,
  );
}

export function sealConfidentialMemoV1(input) {
  return sealConfidentialMemoV1WithRuntime(defaultNativeRuntime, input);
}

export function openConfidentialMemoV1(input) {
  return openConfidentialMemoV1WithRuntime(defaultNativeRuntime, input);
}

export function generateSm2KeyPair(options = {}) {
  return generateSm2KeyPairWithRuntime(defaultNativeRuntime, options);
}

export function deriveSm2KeyPairFromSeed(seed, distid) {
  return deriveSm2KeyPairFromSeedWithRuntime(
    defaultNativeRuntime,
    seed,
    distid,
  );
}

export function loadSm2KeyPair(privateKey, distid) {
  return loadSm2KeyPairWithRuntime(defaultNativeRuntime, privateKey, distid);
}

export function sm2PublicKeyMultihash(publicKey, distid) {
  return sm2PublicKeyMultihashWithRuntime(
    defaultNativeRuntime,
    publicKey,
    distid,
  );
}

export function signSm2(message, privateKey, distid) {
  return signSm2WithRuntime(
    defaultNativeRuntime,
    message,
    privateKey,
    distid,
  );
}

export function verifySm2(message, signature, publicKey, distid) {
  return verifySm2WithRuntime(
    defaultNativeRuntime,
    message,
    signature,
    publicKey,
    distid,
  );
}

export function deriveConfidentialKeyset(spendKey) {
  return deriveConfidentialKeysetWithRuntime(defaultNativeRuntime, spendKey);
}

export function deriveConfidentialKeysetFromHex(spendKeyHex) {
  return deriveConfidentialKeysetFromHexWithRuntime(
    defaultNativeRuntime,
    spendKeyHex,
  );
}

export function deriveConfidentialOwnerTagV2(spendKey, options) {
  return deriveConfidentialOwnerTagV2WithRuntime(
    defaultNativeRuntime,
    spendKey,
    options,
  );
}

export function deriveConfidentialDiversifierV2(seed) {
  return deriveConfidentialDiversifierV2WithRuntime(defaultNativeRuntime, seed);
}

export function deriveConfidentialReceiveAddressV2(input) {
  return deriveConfidentialReceiveAddressV2WithRuntime(
    defaultNativeRuntime,
    input,
  );
}

export function deriveConfidentialNoteV2(input) {
  return deriveConfidentialNoteV2WithRuntime(defaultNativeRuntime, input);
}

export function deriveConfidentialNullifierV2(input) {
  return deriveConfidentialNullifierV2WithRuntime(defaultNativeRuntime, input);
}

export function isPrivacyNativeAvailable() {
  return isPrivacyNativeAvailableWithRuntime(defaultNativeRuntime);
}

export function privacyCompiledProfileCatalogV1() {
  return privacyCompiledProfileCatalogV1WithRuntime(defaultNativeRuntime);
}

export function sm2FixtureFromSeed(distid, seed, message) {
  return sm2FixtureFromSeedWithRuntime(
    defaultNativeRuntime,
    distid,
    seed,
    message,
  );
}

function privateKeyFromSeed(seed) {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function exportPublicKey(privateKeyObject) {
  const publicKeyObject = createPublicKey(privateKeyObject);
  const spki = publicKeyObject.export({ type: "spki", format: "der" });
  return Buffer.from(spki).subarray(ED25519_SPKI_PREFIX.length);
}

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
    const publicKey = buffer.subarray(ED25519_SEED_LENGTH);
    const derivedPublic = exportPublicKey(privateKeyFromSeed(seed));
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

function toOwnedBuffer(value, name) {
  return Buffer.from(toBuffer(value, name));
}

function normalizeConfidentialV2ExactString(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  if (value.trim() !== value) {
    throw new Error(`${name} must not contain surrounding whitespace`);
  }
  return value;
}

function normalizeFixed32HexInput(value, name) {
  if (typeof value === "string") {
    if (value.trim() !== value) {
      throw new Error(`${name} must not contain surrounding whitespace`);
    }
    const normalized = value.replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
      throw new Error(`${name} must be a 32-byte hex string`);
    }
    return normalized;
  }
  const buffer = toBuffer(value, name);
  if (buffer.length !== 32) {
    throw new Error(`${name} must be 32 bytes`);
  }
  return Buffer.from(buffer).toString("hex");
}

function normalizeWholeNumberLiteral(value, name) {
  const normalized = String(value ?? "").trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${name} must be a whole-number string`);
  }
  return normalized;
}

function toBufferField(payload, ...fieldNames) {
  for (const fieldName of fieldNames) {
    if (!payload || !fieldName) {
      continue;
    }
    const value = payload[fieldName];
    if (value !== null && value !== undefined) {
      return toBuffer(value, String(fieldName));
    }
  }
  const rendered = fieldNames.map((fieldName) => `\`${fieldName}\``).join(" or ");
  throw new Error(`native binding returned missing ${rendered}`);
}

function wrapConfidentialKeyset(keys) {
  const result = {
    skSpend: Buffer.from(keys.skSpend),
    nk: Buffer.from(keys.nk),
    ivk: Buffer.from(keys.ivk),
    ovk: Buffer.from(keys.ovk),
    fvk: Buffer.from(keys.fvk),
    asHex() {
      return {
        skSpend: result.skSpendHex,
        nk: result.nkHex,
        ivk: result.ivkHex,
        ovk: result.ovkHex,
        fvk: result.fvkHex,
      };
    },
  };

  Object.defineProperties(result, {
    skSpendHex: {
      enumerable: true,
      get() {
        return result.skSpend.toString("hex");
      },
    },
    nkHex: {
      enumerable: true,
      get() {
        return result.nk.toString("hex");
      },
    },
    ivkHex: {
      enumerable: true,
      get() {
        return result.ivk.toString("hex");
      },
    },
    ovkHex: {
      enumerable: true,
      get() {
        return result.ovk.toString("hex");
      },
    },
    fvkHex: {
      enumerable: true,
      get() {
        return result.fvk.toString("hex");
      },
    },
  });

  return result;
}
