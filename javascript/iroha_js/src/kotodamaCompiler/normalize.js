import { validateEmbeddedStates } from "./embeddedStateSchema.js";
import { encodeContractMetadataValueV1, decodeContractMetadataValueV1 } from "../noritoContractMetadata.js";
import { normalizeContractEventsV1 } from "../contractDeclarations.js";
import { normalizeEntrypointAuthorizationV1, normalizeContractPermissionsV1, validateManifestDeclarationsV1, validateManifestEntrypointIdentityV1 } from "../contractManifestRules.js";
import { readU32Le, readU64Le, readCompactField, decodeEmbeddedString, visitEmbeddedVector } from "./embeddedNorito.js";
import { validateEmbeddedCallables } from "./embeddedCallSchema.js";
const propertyDescriptor = Object.getOwnPropertyDescriptor.bind(Object);
const ownKeys = Reflect.ownKeys.bind(Reflect);
const isSafeInteger = Number.isSafeInteger.bind(Number);
const isArray = Array.isArray.bind(Array);
const stringify = JSON.stringify.bind(JSON);
const TEXT_MUST_BE_SHARED = "must be ";
const TEXT_KOTODAMA_SHARED = "Kotodama ";
const TEXT_CANONICAL = "canonical ";
const TEXT_MANIFEST = "manifest ";
const TEXT_MUST_USE_SHARED = "must use ";
const TEXT_DO_NOT_MATCH_THE_EMBEDDED = "do not match the embedded ";
const TEXT_CONTAINS_SHARED = "contains ";
const TEXT_PLAIN_DATA_ONLY_OBJECT = "plain data-only object";
const TEXT_DENSE_DATA_ONLY_ARRAY = "dense data-only array";
const TEXT_LENGTH = "length";
const TEXT_IS_NOT = "is not ";
const TEXT_POINTER_TLV = "pointer TLV ";
const TEXT_CONTAIN_SHARED = "contain ";
const TEXT_COMPILER_FINGERPRINT = "compiler_fingerprint";
const TEXT_ERROR_MESSAGES = "error_messages";
const TEXT_ARTIFACTBYTES = "artifactBytes";
const TEXT_SEIYAKU_NAME = "seiyaku_name";
const TEXT_STRING = "string";
const TEXT_IS_MISSING = "is missing ";
const TEXT_INTERFACE = "interface";
const TEXT_FEATURES_BITMAP = "features_bitmap";
const TEXT_ENTRYPOINTS = "entrypoints";
const TEXT_CODE_HASH = "code_hash";
const TEXT_DYNAMIC_WRITES = "dynamic_writes";
const TEXT_BYTE_START = "byte_start";
const TEXT_WRITE_KEYS = "write_keys";
const TEXT_HAJIMARI = "Hajimari";
const TEXT_MESSAGE = "message";
const TEXT_ABIHASH = "abiHash";
const TEXT_MANIFEST_SHARED = "manifest";
const TEXT_ABI_HASH = "abi_hash";
const TEXT_ACCESS_HINT_DIAGNOSTICS = "access_hint_diagnostics";
const TEXT_DYNAMIC_READS = "dynamic_reads";
const TEXT_RETURN_SCHEMA = "return_schema";
const TEXT_DECLARATION_IDENTIFIER = "declaration identifier";
const TEXT_EXCEEDS_THE_SHARED = "exceeds the ";
const TEXT_FIELDS = "fields";
const TEXT_READ_KEYS = "read_keys";
const TEXT_ACCESS_HINTS_COMPLETE = "access_hints_complete";
const TEXT_TRANSLATIONS = "translations";
const TEXT_ACCESS_HINTS_SKIPPED = "access_hints_skipped";
const TEXT_BOOLEAN = "boolean";
import { normalizeContractErrorMessagesV1, normalizeContractErrorTypesV1, normalizeContractEnumTypesV1, validateManifestErrorTypeBindingsV1 } from "../contractErrorTypes.js";
import { crc64Xz as noritoCrc64 } from "../crc64Xz.js";
import { blake2b256 } from "../blake2b.js";
import {
  KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS,
  isCanonicalKotodamaDynamicAccessBaseKey,
  isCanonicalKotodamaEntrypoint as isCanonicalEntrypointName,
  isCanonicalKotodamaIdentifier as isCanonicalIdentifier,
  isCanonicalKotodamaStateTypeName as isCanonicalStateTypeName,
  isKotodamaV1DynamicAccessBoundKind,
  isKotodamaV1StateMapKeyTypeName,
  kotodamaV1StateMapKeyTypeName,
} from "../kotodamaIdentifiers.js";
import {
  analyzeEntrypointValueTypeV1,
  MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1,
} from "../entrypointSchema.js";

const TEXT_DOES_NOT_MATCH = " does not match ";
const TEXT_RESPONSE_CONTAINS_AN_INVALID = ("response " + TEXT_CONTAINS_SHARED + "an invalid ");
const TEXT_CONTAINS_DUPLICATE = (TEXT_CONTAINS_SHARED + "duplicate ");
const TEXT_IS_TRUNCATED = " is truncated";
const TEXT_MUST_BE_A = (" " + TEXT_MUST_BE_SHARED + "a ");
const TEXT_MUST_BE_UNIQUE_AND_CANONICAL = (" " + TEXT_MUST_BE_SHARED + "unique and canonical");
const TEXT_DESCRIPTOR = " descriptor ";
const TEXT_ARTIFACT_BYTES_MUST_CONTAIN = (TEXT_ARTIFACTBYTES + " must " + TEXT_CONTAIN_SHARED);
const TEXT_ACCESS_SET_HINTS = "access_set_hints";
const TEXT_ARTIFACT_BYTES_DO_NOT_MATCH_CODE_HASH = "artifact bytes do not match codeHash";


const TEXT_KOTODAMA_COMPILER = (TEXT_KOTODAMA_SHARED + "compiler ");
const TEXT_KOTODAMA_MANIFEST = (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST);
const TEXT_EXCEEDS_THE = (" " + TEXT_EXCEEDS_THE_SHARED);
const TEXT_FAILED_KOTODAMA_COMPILATION_MUST = ("failed " + TEXT_KOTODAMA_SHARED + "compilation must ");
const TEXT_MUST_BE_A_DENSE_ARRAY_WITHOUT_EXTRA_FIELDS = (TEXT_MUST_BE_A + ("dense array without extra " + TEXT_FIELDS));
const TEXT_MUST_CONTAIN = (" must " + TEXT_CONTAIN_SHARED);
const TEXT_MUST_BE_A_STABLE_PLAIN_DATA_ONLY_OBJECT = (TEXT_MUST_BE_A + ("stable " + TEXT_PLAIN_DATA_ONLY_OBJECT));
const TEXT_MUST_BE_A_STABLE_DENSE_DATA_ONLY_ARRAY = (TEXT_MUST_BE_A + ("stable " + TEXT_DENSE_DATA_ONLY_ARRAY));
const TEXT_MUST_USE_CANONICAL_BASE64_PADDING_BITS = (" " + TEXT_MUST_USE_SHARED + TEXT_CANONICAL + "base64 padding bits");
const TEXT_KOTODAMA_EMBEDDED_CONTRACT = (TEXT_KOTODAMA_SHARED + "embedded contract ");
const TEXT_LITERAL_TRIGGER_SPEC_DECODE_FAILURES = "literal_trigger_spec_decode_failures";


const CONTRACT_HASH_DOMAIN = new TextEncoder().encode("iroha:ivm:contract-artifact:v1\0");
const DIAGNOSTIC_PHASES = new Set([
  "lex",
  "parse",
  "resolve",
  "semantic",
  "lowering",
  "artifact",
]);
const DIAGNOSTIC_SEVERITIES = new Set(["error", "warning"]);
const MANIFEST_ENTRYPOINT_KINDS = new Set([
  "Kotoage",
  "View",
  (TEXT_HAJIMARI),
  "Kaizen",
]);
const MAX_DIAGNOSTICS = 64;
// Keep the allocation boundary independent from ledger admission. The exact
// deployable image limit is checked after the fixed IVM header is available.
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_IVM_CODE_REGION_BYTES = 0x0010_0000;
const MAX_WIRE_JSON_BYTES = 16 * 1024 * 1024;
const MAX_MANIFEST_ITEMS = 65_536;
const MAX_ENTRYPOINT_PARAMETERS = MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1;
const MAX_ENTRYPOINT_WORDS = MAX_ENTRYPOINT_CALL_TABLE_WORDS_V1;
const MAX_STRING_BYTES = 1024 * 1024;
const MAX_SOURCE_PATH_BYTES = 4096;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 65_536;
const U32_MAX = 0xffff_ffff;
const UTF8_ENCODER = new TextEncoder();
// IVM ABI v1 authenticates the syscall descriptor directly in the fixed
// header: 17 execution bytes followed by the canonical 32-byte ABI hash.
const IVM_EXECUTION_HEADER_BYTES = 17;
const IVM_ABI_HASH_BYTES = 32;
const IVM_HEADER_BYTES = IVM_EXECUTION_HEADER_BYTES + IVM_ABI_HASH_BYTES;
const NORITO_FRAME_HEADER_BYTES = 40;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const [TYPED_ARRAY_TAG_GETTER, TYPED_ARRAY_BUFFER_GETTER, TYPED_ARRAY_BYTE_OFFSET_GETTER, TYPED_ARRAY_BYTE_LENGTH_GETTER] =
  [Symbol.toStringTag, "buffer", "byteOffset", "byteLength"].map((name) =>
    Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, name)?.get);
// `Archived<EmbeddedContractInterfaceV1>` is at most 8-byte aligned, and the
// 40-byte NRT0 header is already aligned. The Rust decoder requires this exact
// schema padding rather than the looser unknown-schema 64-byte fallback.
const NORITO_EMBEDDED_INTERFACE_PADDING_BYTES = 0;
const NORITO_COMPACT_LENGTHS_FLAG = 0x02;
const EMBEDDED_INTERFACE_SCHEMA_HASH = Uint8Array.from([
  0x42, 0x78, 0xc4, 0x14, 0x19, 0x7d, 0x68, 0xd9,
  0xcb, 0xb2, 0xda, 0xde, 0xa7, 0x40, 0x23, 0x87,
]);


// Keep the fail-closed boundary's exact diagnostics while avoiding 145
// repeated `throw new TypeError(...)` constructor sequences in the minified
// browser compiler. A single throwing helper preserves the public error class
// and message byte-for-byte.
function rejectType(message) {
  throw new TypeError(message);
}

// Attach the exact field context only on failure; all public diagnostics remain unchanged.
function rejectAt(context, suffix) {
  rejectType(context + suffix);
}

function rejectRange(message) {
  throw new RangeError(message);
}

function isRecord(value) {
  if (value === null || typeof value !== "object" || isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireRecord(value, label) {
  let record;
  try {
    record = isRecord(value);
  } catch {
    rejectAt(label, `${TEXT_MUST_BE_A}plain data-only object`);
  }
  if (!record) {
    rejectAt(label, " must be an object");
  }
  let keys;
  try {
    keys = ownKeys(value);
  } catch {
    rejectAt(label, `${TEXT_MUST_BE_A}plain data-only object`);
  }
  for (const key of keys) {
    if (typeof key !== "string") {
      rejectAt(label, " must not contain symbol fields");
    }
    const descriptor = propertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      rejectAt(label, `.${key} must be an enumerable data property`);
    }
  }
  return value;
}

function snapshotRecord(value, label) {
  requireRecord(value, label);
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    rejectAt(label, `${TEXT_MUST_BE_A_STABLE_PLAIN_DATA_ONLY_OBJECT}`);
  }
  const snapshot = Object.create(null);
  for (const key of ownKeys(descriptors)) {
    const descriptor = descriptors[key];
    if (typeof key !== "string" || !("value" in descriptor) || !descriptor.enumerable) {
      rejectAt(label, `${TEXT_MUST_BE_A_STABLE_PLAIN_DATA_ONLY_OBJECT}`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function requireExactKeys(value, keys, label) {
  requireRecord(value, label);
  const actual = ownKeys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    rejectAt(label, " has an invalid field set");
  }
}

function requireDenseArray(value, label, maximum = MAX_MANIFEST_ITEMS) {
  if (!Array.isArray(value)) {
    rejectAt(label, " must be an array");
  }
  let length;
  let keys;
  try {
    const lengthDescriptor = propertyDescriptor(value, (TEXT_LENGTH));
    length = lengthDescriptor?.value;
    keys = ownKeys(value);
  } catch {
    rejectAt(label, `${TEXT_MUST_BE_A}dense data-only array`);
  }
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) {
    rejectRange(`${label}${TEXT_MUST_CONTAIN}at most ${maximum} items`);
  }
  if (keys.some((key) => typeof key !== "string")) {
    rejectAt(label, " must not contain symbol fields");
  }
  const elementKeys = keys.filter((key) => key !== (TEXT_LENGTH));
  if (elementKeys.length !== length) {
    rejectAt(label, `${TEXT_MUST_BE_A_DENSE_ARRAY_WITHOUT_EXTRA_FIELDS}`);
  }
  for (let index = 0; index < length; index += 1) {
    const descriptor = propertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      rejectAt(label, `${TEXT_MUST_BE_A}dense data-only array`);
    }
  }
  return value;
}

function snapshotDenseArray(value, label, maximum = MAX_MANIFEST_ITEMS) {
  if (!Array.isArray(value)) {
    rejectAt(label, " must be an array");
  }
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    rejectAt(label, `${TEXT_MUST_BE_A_STABLE_DENSE_DATA_ONLY_ARRAY}`);
  }
  const length = descriptors.length?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) {
    rejectRange(`${label}${TEXT_MUST_CONTAIN}at most ${maximum} items`);
  }
  if (Reflect.ownKeys(descriptors).length !== length + 1) {
    rejectAt(label, `${TEXT_MUST_BE_A_DENSE_ARRAY_WITHOUT_EXTRA_FIELDS}`);
  }
  const snapshot = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      rejectAt(label, `${TEXT_MUST_BE_A_STABLE_DENSE_DATA_ONLY_ARRAY}`);
    }
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

export function validateUnicodeScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function requireString(value, label, { allowEmpty = false, maximum = MAX_STRING_BYTES } = {}) {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    rejectAt(label, ` must be ${allowEmpty ? "a" : "a non-empty"} string`);
  }
  if (!validateUnicodeScalarString(value)) {
    rejectAt(label, `${TEXT_MUST_CONTAIN}valid Unicode scalar values`);
  }
  if (UTF8_ENCODER.encode(value).length > maximum) {
    rejectRange(`${label}${TEXT_EXCEEDS_THE}${maximum}-byte limit`);
  }
  return value;
}

function requireUnsignedInteger(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    rejectAt(label, ` must be an unsigned safe integer in 0..${maximum}`);
  }
  return value;
}

function requireNullableString(value, label, options) {
  return value === null ? null : requireString(value, label, options);
}

function requireStringArray(value, label, maximum = MAX_MANIFEST_ITEMS) {
  requireDenseArray(value, label, maximum);
  return value.map((entry, index) => requireString(entry, `${label}[${index}]`));
}

function validateBoundedJson(value, label) {
  const stack = [{ value, depth: 0, label }];
  let nodes = 0;
  while (stack.length !== 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > MAX_JSON_NODES) {
      rejectRange(`${label}${TEXT_EXCEEDS_THE}${MAX_JSON_NODES}-node JSON limit`);
    }
    if (current.depth > MAX_JSON_DEPTH) {
      rejectRange(`${label}${TEXT_EXCEEDS_THE}${MAX_JSON_DEPTH}-level JSON depth limit`);
    }
    const item = current.value;
    if (item === null || typeof item === (TEXT_BOOLEAN)) continue;
    if (typeof item === (TEXT_STRING)) {
      requireString(item, current.label, { allowEmpty: true });
      continue;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) {
        rejectType(`${current.label}${TEXT_MUST_CONTAIN}only finite JSON numbers`);
      }
      continue;
    }
    if (isArray(item)) {
      requireDenseArray(item, current.label);
      for (let index = item.length - 1; index >= 0; index -= 1) {
        stack.push({
          value: item[index],
          depth: current.depth + 1,
          label: `${current.label}[${index}]`,
        });
      }
      continue;
    }
    requireRecord(item, current.label);
    for (const key of ownKeys(item)) {
      requireString(key, `${current.label} key`, { maximum: MAX_SOURCE_PATH_BYTES });
      stack.push({
        value: item[key],
        depth: current.depth + 1,
        label: `${current.label}.${key}`,
      });
    }
  }
  return value;
}

function parseJson(raw, label) {
  requireString(raw, label, { allowEmpty: true, maximum: MAX_WIRE_JSON_BYTES });
  try {
    return JSON.parse(raw);
  } catch {
    rejectAt(label, " is not valid JSON");
  }
}

function normalizeHashHex(value, label) {
  if (typeof value !== "string") {
    rejectAt(TEXT_KOTODAMA_COMPILER, `response is missing ${label}`);
  }
  if (/^[0-9a-fA-F]{64}$/u.test(value)) {
    return requireIrohaHashMarker(value.toLowerCase(), label);
  }
  const literal = /^hash:([0-9A-F]{64})#([0-9A-F]{4})$/u.exec(value);
  if (literal === null) {
    rejectAt(TEXT_KOTODAMA_COMPILER, `${TEXT_RESPONSE_CONTAINS_AN_INVALID}or noncanonical ${label}`);
  }
  const [, body, checksum] = literal;
  const expected = crc16Literal("hash", body);
  if (checksum !== expected) {
    rejectAt(TEXT_KOTODAMA_COMPILER, `${TEXT_RESPONSE_CONTAINS_AN_INVALID}${label} checksum; expected ${expected}`);
  }
  return requireIrohaHashMarker(body.toLowerCase(), label);
}

function requireIrohaHashMarker(hex, label) {
  if ((Number.parseInt(hex.slice(-2), 16) & 1) !== 1) {
    rejectAt(TEXT_KOTODAMA_COMPILER, `${TEXT_RESPONSE_CONTAINS_AN_INVALID}${label} marker bit`);
  }
  return hex;
}

function crc16Literal(tag, body) {
  let crc = 0xffff;
  const processByte = (byte) => {
    crc ^= (byte & 0xff) << 8;
    for (let index = 0; index < 8; index += 1) {
      crc =
        (crc & 0x8000) !== 0
          ? ((crc << 1) ^ 0x1021) & 0xffff
          : (crc << 1) & 0xffff;
    }
  };
  for (const byte of UTF8_ENCODER.encode(tag)) {
    processByte(byte);
  }
  processByte(0x3a);
  for (const byte of UTF8_ENCODER.encode(body)) {
    processByte(byte);
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function snapshotUint8Array(value) {
  if (!ArrayBuffer.isView(value)) return null;
  try {
    if (TYPED_ARRAY_TAG_GETTER.call(value) !== "Uint8Array") return null;
    const buffer = TYPED_ARRAY_BUFFER_GETTER.call(value);
    const byteOffset = TYPED_ARRAY_BYTE_OFFSET_GETTER.call(value);
    const byteLength = TYPED_ARRAY_BYTE_LENGTH_GETTER.call(value);
    if (byteLength > MAX_ARTIFACT_BYTES) {
      rejectRange(
        `${TEXT_KOTODAMA_COMPILER}${TEXT_ARTIFACT_BYTES_MUST_CONTAIN}1..${MAX_ARTIFACT_BYTES} bytes`,
      );
    }
    return new Uint8Array(buffer, byteOffset, byteLength).slice();
  } catch (error) {
    if (error instanceof RangeError) throw error;
    rejectType((TEXT_KOTODAMA_COMPILER + (TEXT_ARTIFACTBYTES) + TEXT_MUST_BE_A + "readable Uint8Array"));
  }
}

function normalizeArtifactBytes(value) {
  let bytes;
  const byteView = snapshotUint8Array(value);
  if (byteView !== null) {
    bytes = byteView;
  } else if (isArray(value)) {
    const snapshot = snapshotDenseArray(
      value,
      (TEXT_KOTODAMA_COMPILER + (TEXT_ARTIFACTBYTES)),
      MAX_ARTIFACT_BYTES,
    );
    if (snapshot.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
      rejectType((TEXT_KOTODAMA_COMPILER + TEXT_ARTIFACT_BYTES_MUST_CONTAIN + "only bytes"));
    }
    bytes = Uint8Array.from(snapshot);
  } else {
    rejectType((TEXT_KOTODAMA_COMPILER + ("response " + TEXT_IS_MISSING + TEXT_ARTIFACTBYTES)));
  }
  if (bytes.length === 0 || bytes.length > MAX_ARTIFACT_BYTES) {
    rejectAt(TEXT_KOTODAMA_COMPILER, `${TEXT_ARTIFACT_BYTES_MUST_CONTAIN}1..${MAX_ARTIFACT_BYTES} bytes`);
  }
  return bytes;
}

function readU32Be(bytes, offset, label) {
  if (offset < 0 || offset + 4 > bytes.length) {
    rejectAt(label, `${TEXT_IS_TRUNCATED}`);
  }
  return (
    bytes[offset] * 0x1000000 +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  ) >>> 0;
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// Fixed ASCII section tags are compared without temporary byte arrays.
function hasMagic(bytes, offset, magic) {
  for (let index = 0; index < magic.length; index += 1) {
    if (bytes[offset + index] !== magic.charCodeAt(index)) return false;
  }
  return true;
}

function validateEmbeddedInterfaceFrame(frame, manifest, headerMode, abiHashHex) {
  const label = (TEXT_KOTODAMA_EMBEDDED_CONTRACT + (TEXT_INTERFACE));
  if (frame.length < NORITO_FRAME_HEADER_BYTES) {
    rejectAt(label, " is shorter than its Norito frame header");
  }
  if (!hasMagic(frame, 0, "NRT0")) {
    rejectAt(label, " is not an NRT0 frame");
  }
  if (frame[4] !== 0 || frame[5] !== 0) {
    rejectAt(label, " uses an unsupported Norito version");
  }
  if (!equalBytes(frame.subarray(6, 22), EMBEDDED_INTERFACE_SCHEMA_HASH)) {
    rejectAt(label, " has the wrong Norito schema hash");
  }
  if (frame[22] !== 0 || frame[39] !== NORITO_COMPACT_LENGTHS_FLAG) {
    rejectAt(label, " must use canonical uncompressed compact-length framing");
  }
  const payloadLength = readU64Le(frame, 23, `${label} payload ${TEXT_LENGTH}`);
  if (payloadLength === 0n || payloadLength > BigInt(Number.MAX_SAFE_INTEGER)) {
    rejectAt(label, " has an invalid payload length");
  }
  const safePayloadLength = Number(payloadLength);
  const paddingLength = frame.length - NORITO_FRAME_HEADER_BYTES - safePayloadLength;
  if (paddingLength !== NORITO_EMBEDDED_INTERFACE_PADDING_BYTES) {
    rejectAt(label, " has a noncanonical alignment padding length");
  }
  const payloadOffset = NORITO_FRAME_HEADER_BYTES + paddingLength;
  if (frame.subarray(NORITO_FRAME_HEADER_BYTES, payloadOffset).some((byte) => byte !== 0)) {
    rejectAt(label, " contains non-zero alignment padding");
  }
  const payload = frame.subarray(payloadOffset);
  if (payload.length !== safePayloadLength) {
    rejectAt(label, ` payload${TEXT_IS_TRUNCATED}`);
  }
  if (noritoCrc64(payload) !== readU64Le(frame, 31, `${label} CRC64`)) {
    rejectAt(label, " has an invalid CRC64");
  }

  const state = { offset: 0 };
  const fields = Array.from({ length: 14 }, (_, index) =>
    readCompactField(payload, state, `${label}.field${index}`));
  if (state.offset !== payload.length) {
    rejectAt(label, " contains trailing or unknown fields");
  }
  const embeddedName = decodeEmbeddedString(fields[0], `${label}.${TEXT_SEIYAKU_NAME}`);
  const embeddedFingerprint = decodeEmbeddedString(
    fields[1],
    `${label}.${TEXT_COMPILER_FINGERPRINT}`,
  );
  if (fields[2].length !== IVM_ABI_HASH_BYTES || toHex(fields[2]) !== abiHashHex) {
    rejectType(
      (TEXT_KOTODAMA_EMBEDDED_CONTRACT + (TEXT_INTERFACE + " ABI hash") + TEXT_DOES_NOT_MATCH + "the compiler response"),
    );
  }
  const embeddedFeatures = readU64Le(fields[3], 0, `${label}.${TEXT_FEATURES_BITMAP}`);
  if (fields[3].length !== 8 || embeddedFeatures > BigInt(Number.MAX_SAFE_INTEGER)) {
    rejectAt(label, ".features_bitmap is not a canonical safe u64");
  }
  if (
    embeddedName !== manifest.seiyaku_name ||
    embeddedFingerprint !== manifest.compiler_fingerprint ||
    Number(embeddedFeatures) !== manifest.features_bitmap
  ) {
    rejectType(
      (TEXT_KOTODAMA_MANIFEST + ("identity/capabilities " + TEXT_DO_NOT_MATCH_THE_EMBEDDED + "contract " + TEXT_INTERFACE)),
    );
  }
  if (Number(embeddedFeatures) !== (headerMode & 0x03)) {
    rejectType(
      (TEXT_KOTODAMA_EMBEDDED_CONTRACT + "capabilities do not match the IVM execution header"),
    );
  }

  const optionPresent = (field, optionLabel) => {
    if (field.length === 1 && field[0] === 0) return false;
    if (field.length >= 3 && field[0] === 1) {
      const optionState = { offset: 1 };
      readCompactField(field, optionState, `${optionLabel}.value`);
      if (optionState.offset === field.length) return true;
    }
    rejectAt(optionLabel, " has a noncanonical option envelope");
  };
  const expectedAccessHints = manifest.access_set_hints !== null;
  if (optionPresent(fields[4], `${label}.${TEXT_ACCESS_SET_HINTS}`) !== expectedAccessHints) {
    rejectType((TEXT_KOTODAMA_MANIFEST + ("access hints " + TEXT_DO_NOT_MATCH_THE_EMBEDDED + TEXT_INTERFACE)));
  }
  for (const [fieldIndex, manifestValue, fieldLabel] of [
    [7, manifest.kotoba ?? [], "kotoba"],
    [8, manifest.entrypoints, (TEXT_ENTRYPOINTS)],
    [10, manifest.states, "states"],
    [11, manifest.error_types ?? [], "error_types"],
    [13, manifest.error_messages ?? [], (TEXT_ERROR_MESSAGES)],
  ]) {
    if (visitEmbeddedVector(fields[fieldIndex], `${label}.${fieldLabel}`, MAX_MANIFEST_ITEMS) !== manifestValue.length) {
      rejectAt(TEXT_KOTODAMA_MANIFEST, `${fieldLabel} count${TEXT_DOES_NOT_MATCH}the embedded interface`);
    }
  }
  const messages = [];
  visitEmbeddedVector(fields[13], `${label}.${TEXT_ERROR_MESSAGES}`, MAX_MANIFEST_ITEMS, (entry, entryLabel) => {
    const cursor = { offset: 0 };
    const identity = readCompactField(entry, cursor, `${entryLabel}.error_type`);
    const code = readCompactField(entry, cursor, `${entryLabel}.code`);
    const message = readCompactField(entry, cursor, `${entryLabel}.message`);
    if (cursor.offset !== entry.length || code.length !== 4) rejectAt(entryLabel, " has an invalid error message record");
    messages.push({ error_type: decodeEmbeddedString(identity, `${entryLabel}.error_type`),
      code: readU32Le(code, 0, `${entryLabel}.code`), message: decodeEmbeddedString(message, `${entryLabel}.${TEXT_MESSAGE}`) });
  });
  const normalizedMessages = normalizeContractErrorMessagesV1(messages, manifest.error_types, `${label}.error_messages`);
  if (JSON.stringify(normalizedMessages) !== JSON.stringify(manifest.error_messages ?? [])) {
    rejectAt(TEXT_KOTODAMA_MANIFEST, "error_messages do not match the embedded contract interface");
  }
  for (const [index, kind, expected] of [
    [5, "permissions", normalizeContractPermissionsV1(manifest.permissions, "manifest.permissions")],
    [6, "events", normalizeContractEventsV1(manifest.events, "manifest.events")],
    [11, "error_types", normalizeContractErrorTypesV1(manifest.error_types) ?? []],
    [12, "enum_types", normalizeContractEnumTypesV1(manifest.enum_types)],
  ]) {
    const actual = decodeContractMetadataValueV1(kind, fields[index]);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) rejectAt(label, `.${kind} does not exactly match the manifest declaration table`);
  }
  let entryIndex = 0;
  visitEmbeddedVector(fields[8], `${label}.entrypoints`, MAX_MANIFEST_ITEMS, (entry, entryLabel) => {
    const cursor = { offset: 0 };
    for (let index = 0; index < 12; index += 1) readCompactField(entry, cursor, entryLabel);
    const declaration = entry.subarray(0, cursor.offset);
    const pc = readCompactField(entry, cursor, `${entryLabel}.entry_pc`);
    if (cursor.offset !== entry.length || pc.length !== 8 || readU64Le(pc, 0, entryLabel) % 4n !== 0n) rejectAt(entryLabel, " has an invalid entrypoint PC");
    const expected = encodeContractMetadataValueV1("entrypoint", manifest.entrypoints[entryIndex++]);
    if (!equalBytes(declaration, expected)) rejectAt(entryLabel, " does not exactly match the manifest entrypoint descriptor");
  });
  validateEmbeddedStates(fields[10], manifest.states, manifest.error_types ?? [], manifest.enum_types, `${label}.states`);
  return validateEmbeddedCallables(fields[9], headerMode, manifest.entrypoints.length, `${label}.callables`, manifest.error_types ?? [], manifest.enum_types);
}

function validateLiteralSection(bytes, start) {
  const label = "Kotodama IVM literal section";
  if (start + 16 > bytes.length) rejectAt(label, `${TEXT_IS_TRUNCATED}`);
  const count = readU32Le(bytes, start + 4, `${label} count`);
  const padding = readU32Le(bytes, start + 8, `${label} padding`);
  const dataLength = readU32Le(bytes, start + 12, `${label} data ${TEXT_LENGTH}`);
  if (count > 0x1_0000 || padding > 3) {
    rejectAt(label, " has invalid bounds");
  }
  const entriesLength = count * 8;
  const dataStart = start + 16 + entriesLength;
  const dataEnd = dataStart + dataLength;
  const codeOffset = dataEnd + padding;
  if (dataEnd < dataStart || codeOffset > bytes.length) {
    rejectAt(label, `${TEXT_EXCEEDS_THE}artifact bounds`);
  }
  const expectedPadding = (4 - ((start - IVM_HEADER_BYTES + 16 + entriesLength + dataLength) % 4)) % 4;
  if (
    padding !== expectedPadding ||
    bytes.subarray(dataEnd, codeOffset).some((byte) => byte !== 0)
  ) {
    rejectAt(label, " uses noncanonical alignment padding");
  }
  const descriptors = [];
  for (let index = 0; index < count; index += 1) {
    const descriptor = readU64Le(
      bytes,
      start + 16 + index * 8,
      `${label}${TEXT_DESCRIPTOR}${index}`,
    );
    const kind = Number(descriptor >> 56n);
    const relativeOffsetBigInt = descriptor & 0x00ff_ffff_ffff_ffffn;
    if (relativeOffsetBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
      rejectAt(label, `${TEXT_DESCRIPTOR}${index} offset is invalid`);
    }
    const relativeOffset = Number(relativeOffsetBigInt);
    const absoluteOffset = start + relativeOffset;
    if (
      (kind !== 0 && kind !== 1) ||
      relativeOffset < 16 + entriesLength ||
      absoluteOffset < dataStart ||
      absoluteOffset >= dataEnd
    ) {
      rejectAt(label, `${TEXT_DESCRIPTOR}${index} is invalid`);
    }
    if (
      descriptors.length !== 0 &&
      absoluteOffset <= descriptors[descriptors.length - 1].absoluteOffset
    ) {
      rejectAt(label, `${TEXT_DESCRIPTOR}targets must be strictly increasing`);
    }
    descriptors.push({ kind, absoluteOffset });
  }
  if (descriptors.length === 0) {
    if (dataLength !== 0) {
      rejectAt(label, " cannot contain unindexed literal data");
    }
  } else if (descriptors[0].absoluteOffset !== dataStart) {
    rejectAt(label, ` first${TEXT_DESCRIPTOR}must target the first data byte`);
  }
  for (let index = 0; index < descriptors.length; index += 1) {
    const { kind, absoluteOffset } = descriptors[index];
    const end = descriptors[index + 1]?.absoluteOffset ?? dataEnd;
    const literal = bytes.subarray(absoluteOffset, end);
    if (kind === 0) {
      validatePointerLiteralV1(literal, `${label}${TEXT_DESCRIPTOR}${index}`);
    } else if (literal.length !== 8) {
      rejectAt(label, ` i64${TEXT_DESCRIPTOR}${index}${TEXT_MUST_CONTAIN}exactly 8 bytes`);
    }
  }
  return codeOffset;
}

function validatePointerLiteralV1(bytes, label) {
  if (bytes.length < 39) {
    rejectAt(label, ` pointer TLV${TEXT_IS_TRUNCATED}`);
  }
  const typeId = (bytes[0] << 8) | bytes[1];
  const allowedType = typeId >= 0x0001 && typeId <= 0x0012;
  if (!allowedType) {
    rejectAt(label, " pointer TLV type is not allowed by ABI v1");
  }
  if (bytes[2] !== 1) {
    rejectAt(label, " pointer TLV must use version 1");
  }
  const payloadLength = readU32Be(bytes, 3, `${label} ${TEXT_POINTER_TLV}${TEXT_LENGTH}`);
  const expectedLength = 7 + payloadLength + 32;
  if (bytes.length !== expectedLength) {
    rejectAt(label, ` pointer TLV length${TEXT_DOES_NOT_MATCH}its envelope`);
  }
  const payload = bytes.subarray(7, 7 + payloadLength);
  const expectedHash = blake2b256(payload);
  expectedHash[expectedHash.length - 1] |= 1;
  if (!equalBytes(bytes.subarray(7 + payloadLength), expectedHash)) {
    rejectAt(label, " pointer TLV payload hash is invalid");
  }
}

function validateCompiledArtifactV1(bytes, manifest, abiHashHex) {
  const label = (TEXT_KOTODAMA_COMPILER + "artifact");
  if (bytes.length < IVM_HEADER_BYTES + 8 + NORITO_FRAME_HEADER_BYTES + 4) {
    rejectAt(label, " is too short to be a deployable IVM contract");
  }
  if (bytes.length - IVM_HEADER_BYTES > MAX_IVM_CODE_REGION_BYTES) {
    rejectRange(
      `${label} post-header image exceeds the ${MAX_IVM_CODE_REGION_BYTES}-byte IVM code-memory limit`,
    );
  }
  if (!hasMagic(bytes, 0, "IVM\0")) {
    rejectAt(label, " has invalid IVM header magic");
  }
  if (bytes[4] !== 1 || bytes[5] !== 1 || (bytes[6] & ~0x03) !== 0 || bytes[7] > 64) {
    rejectAt(label, " has unsupported IVM execution metadata");
  }
  if (bytes[16] !== 1) {
    rejectAt(label, " must use IVM ABI version 1");
  }
  if (toHex(bytes.subarray(IVM_EXECUTION_HEADER_BYTES, IVM_HEADER_BYTES)) !== abiHashHex) {
    rejectAt(label, ` authenticated ABI hash${TEXT_DOES_NOT_MATCH}abiHash`);
  }
  if (!hasMagic(bytes, IVM_HEADER_BYTES, "CNTR")) {
    rejectAt(label, " is missing its required CNTR interface section");
  }
  const interfaceLength = readU32Le(
    bytes,
    IVM_HEADER_BYTES + 4,
    `${label} CNTR ${TEXT_LENGTH}`,
  );
  const interfaceStart = IVM_HEADER_BYTES + 8;
  const interfaceEnd = interfaceStart + interfaceLength;
  if (interfaceLength === 0 || interfaceEnd < interfaceStart || interfaceEnd > bytes.length) {
    rejectAt(label, " has an invalid CNTR interface length");
  }
  const lastCallablePc = validateEmbeddedInterfaceFrame(
    bytes.subarray(interfaceStart, interfaceEnd),
    manifest,
    bytes[6],
    abiHashHex,
  );
  let codeOffset = interfaceEnd;
  if (hasMagic(bytes, codeOffset, "DBG1")) {
    rejectAt(label, " must keep DBG1 metadata in authenticated sidecars");
  }
  if (hasMagic(bytes, codeOffset, "LTLB")) {
    codeOffset = validateLiteralSection(bytes, codeOffset);
  }
  const codeLength = bytes.length - codeOffset;
  if (codeLength <= 0 || codeLength % 4 !== 0) {
    rejectAt(label, `${TEXT_MUST_CONTAIN}a non-empty word-aligned instruction stream`);
  }
  if (lastCallablePc >= BigInt(codeLength)) {
    rejectAt(label, " callable root is outside the instruction stream");
  }
}

function artifactHashHex(artifactBytes) {
  const input = new Uint8Array(CONTRACT_HASH_DOMAIN.length + artifactBytes.length);
  input.set(CONTRACT_HASH_DOMAIN);
  input.set(artifactBytes, CONTRACT_HASH_DOMAIN.length);
  const digest = blake2b256(input);
  // `iroha_crypto::Hash::prehashed` reserves the low bit of the final byte.
  digest[digest.length - 1] |= 1;
  return toHex(digest);
}

/**
 * Verify a detached compiler artifact and manifest at a deployment boundary.
 *
 * This intentionally reuses the same strict V1 checks as the compiler-client
 * response normalizer: the complete domain-separated code identity, canonical
 * manifest fields, authenticated ABI header, CNTR frame and callable tables,
 * literal section, and word-aligned executable stream must all agree before
 * upload instructions are built. Native admission owns executable policy and
 * exact callable-to-entrypoint schema binding.
 */
export function verifyCompiledContractArtifact(
  artifactBytes,
  manifest,
  codeHash,
  abiHash,
) {
  const normalizedArtifact = normalizeArtifactBytes(artifactBytes);
  const normalizedManifest = snapshotRecord(
    manifest,
    (TEXT_KOTODAMA_SHARED + "deployment " + TEXT_MANIFEST_SHARED),
  );
  const codeHashHex = normalizeHashHex(codeHash, "codeHash");
  const abiHashHex = normalizeHashHex(abiHash, (TEXT_ABIHASH));
  if (artifactHashHex(normalizedArtifact) !== codeHashHex) {
    throw new Error((TEXT_KOTODAMA_COMPILER + TEXT_ARTIFACT_BYTES_DO_NOT_MATCH_CODE_HASH));
  }
  validateArtifactManifest(normalizedArtifact, normalizedManifest, codeHashHex, abiHashHex);
  return Object.freeze({
    artifactBytes: normalizedArtifact,
    manifest: normalizedManifest,
    codeHashHex,
    abiHashHex,
  });
}

// Both detached deployment and compiler results require the same authenticated
// manifest identity and complete artifact layout before exposing the output.
function validateArtifactManifest(artifactBytes, manifest, codeHashHex, abiHashHex) {
  if (normalizeHashHex(manifest.code_hash, "manifest code_hash") !== codeHashHex) {
    throw new Error((TEXT_KOTODAMA_COMPILER + "manifest code_hash" + TEXT_DOES_NOT_MATCH + "the artifact"));
  }
  if (normalizeHashHex(manifest.abi_hash, "manifest abi_hash") !== abiHashHex) {
    throw new Error((TEXT_KOTODAMA_COMPILER + "manifest abi_hash" + TEXT_DOES_NOT_MATCH + "abiHash"));
  }
  validateCompilerManifest(manifest);
  validateCompiledArtifactV1(artifactBytes, manifest, abiHashHex);

}

function requireCanonicalBase64(value, label) {
  requireString(value, label);
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    rejectAt(label, " must be exact standard-base64");
  }
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (value.endsWith("==") && (alphabet.indexOf(value.at(-3)) & 0x0f) !== 0) {
    rejectAt(label, `${TEXT_MUST_USE_CANONICAL_BASE64_PADDING_BITS}`);
  }
  if (value.endsWith("=") && !value.endsWith("==") && (alphabet.indexOf(value.at(-2)) & 0x03) !== 0) {
    rejectAt(label, `${TEXT_MUST_USE_CANONICAL_BASE64_PADDING_BITS}`);
  }
  return value;
}

function validateSourceLocation(value, label, { nullable = false } = {}) {
  if (nullable && value.source_id === null) {
    for (const key of [(TEXT_BYTE_START), "byte_end", "line", "column"]) {
      if (value[key] !== null) {
        rejectAt(label, " must use one consistent nullable source location");
      }
    }
    if (value.source_path !== null) {
      rejectAt(label, ".source_path must be null without a source location");
    }
    return;
  }
  requireNullableString(value.source_path, `${label}.source_path`, {
    maximum: MAX_SOURCE_PATH_BYTES,
  });
  for (const key of ["source_id", "byte_start", "byte_end", "line", "column"]) {
    requireUnsignedInteger(value[key], U32_MAX, `${label}.${key}`);
  }
  if (value.byte_start > value.byte_end) {
    rejectAt(label, " must use a forward UTF-8 byte range");
  }
}

const SOURCE_LOCATION_FIELDS = ["source_path", "source_id", "byte_start", "byte_end", "line", "column"];
const FUNCTION_LOCATION_FIELDS = ["function_name", "pc_start", "pc_end"];
const BUDGET_FIELDS = ["bytecode_bytes", "bytecode_words", "frame_bytes", "jump_span_words"];

function validateSidecarEntry(value, index, kind) {
  const label = `${kind} sidecar entry ${index}`;
  const budget = kind === "budget";
  requireExactKeys(value, [
    ...FUNCTION_LOCATION_FIELDS,
    ...(budget ? [...BUDGET_FIELDS, "jump_range_risk"] : ["source_kind"]),
    ...SOURCE_LOCATION_FIELDS,
  ], label);
  if (!budget && value.source_kind !== "function" && value.source_kind !== "statement") {
    rejectAt(label, ".source_kind must be function or statement");
  }
  requireString(value.function_name, `${label}.function_name`);
  requireUnsignedInteger(value.pc_start, Number.MAX_SAFE_INTEGER, `${label}.pc_start`);
  requireUnsignedInteger(value.pc_end, Number.MAX_SAFE_INTEGER, `${label}.pc_end`);
  if (budget) {
    for (const key of BUDGET_FIELDS) {
      requireUnsignedInteger(value[key], U32_MAX, `${label}.${key}`);
    }
    if (typeof value.jump_range_risk !== "boolean") {
      rejectAt(label, `.jump_range_risk${TEXT_MUST_BE_A}boolean`);
    }
  }
  if (value.pc_start > value.pc_end) {
    rejectAt(label, " must use a forward PC range");
  }
  validateSourceLocation(value, label, { nullable: budget });
}

function parseSidecar(raw, kind, artifactHash) {
  const label = `${kind} sidecar`;
  const sidecar = requireRecord(parseJson(raw, label), label);
  const expectedKeys = kind === "budget"
    ? ["sidecar_version", "kind", "artifact_hash", "entries", (TEXT_ACCESS_HINT_DIAGNOSTICS)]
    : ["sidecar_version", "kind", "artifact_hash", "entries"];
  requireExactKeys(sidecar, expectedKeys, label);
  if (
    sidecar.sidecar_version !== 1 ||
    sidecar.kind !== kind ||
    normalizeHashHex(sidecar.artifact_hash, `${kind} artifact hash`) !== artifactHash
  ) {
    throw new Error(`${TEXT_KOTODAMA_COMPILER}returned an invalid or mismatched ${kind} sidecar`);
  }
  requireDenseArray(sidecar.entries, `${label}.entries`);
  sidecar.entries.forEach((entry, index) => validateSidecarEntry(entry, index, kind));
  if (kind === "budget") {
    requireExactKeys(
      sidecar.access_hint_diagnostics,
      ["state_wildcards", "isi_wildcards", TEXT_LITERAL_TRIGGER_SPEC_DECODE_FAILURES],
      `${label}.${TEXT_ACCESS_HINT_DIAGNOSTICS}`,
    );
    for (const key of [
      "state_wildcards",
      "isi_wildcards",
      TEXT_LITERAL_TRIGGER_SPEC_DECODE_FAILURES,
    ]) {
      requireUnsignedInteger(
        sidecar.access_hint_diagnostics[key],
        Number.MAX_SAFE_INTEGER,
        `${label}.${TEXT_ACCESS_HINT_DIAGNOSTICS}.${key}`,
      );
    }
  }
  return sidecar.entries;
}

function validateEntrypointType(value, label, maximumWords = MAX_ENTRYPOINT_WORDS) {
  validateBoundedJson(value, label);
  const analysis = analyzeEntrypointValueTypeV1(value, label);
  if (analysis.wordCount > maximumWords) {
    rejectAt(label, `${TEXT_EXCEEDS_THE}${maximumWords}-word V1 ABI limit`);
  }
  return analysis;
}

function validateArgumentSchema(value, params, label) {
  requireExactKeys(value, [(TEXT_FIELDS)], label);
  requireDenseArray(value.fields, `${label}.${TEXT_FIELDS}`, MAX_ENTRYPOINT_PARAMETERS);
  if (value.fields.length === 0 || value.fields.length !== params.length) {
    rejectAt(label, ".fields must exactly match the declared parameters");
  }
  const names = new Set();
  let words = 0;
  value.fields.forEach((field, index) => {
    const fieldLabel = `${label}.${TEXT_FIELDS}[${index}]`;
    requireExactKeys(field, ["name", "ty"], fieldLabel);
    if (!isCanonicalIdentifier(field.name) || names.has(field.name)) {
      rejectAt(fieldLabel, `.name${TEXT_MUST_BE_UNIQUE_AND_CANONICAL}`);
    }
    names.add(field.name);
    const analysis = validateEntrypointType(field.ty, `${fieldLabel}.ty`);
    words += analysis.wordCount;
    if (field.name !== params[index].name || analysis.canonicalName !== params[index].type_name) {
      rejectAt(fieldLabel, `${TEXT_DOES_NOT_MATCH}its declared parameter`);
    }
  });
  if (words > MAX_ENTRYPOINT_WORDS) {
    rejectAt(label, `${TEXT_EXCEEDS_THE}${MAX_ENTRYPOINT_WORDS}-word V1 ABI limit`);
  }
}

function validateDynamicAccessHints(value, label) {
  requireDenseArray(value, label);
  value.forEach((hint, index) => {
    const hintLabel = `${label}[${index}]`;
    requireExactKeys(hint, ["base_key", "key_type", "bound_kind", "max_keys"], hintLabel);
    requireString(hint.base_key, `${hintLabel}.base_key`);
    if (!isCanonicalKotodamaDynamicAccessBaseKey(hint.base_key)) {
      rejectAt(hintLabel, ".base_key must be state: plus one canonical state declaration identifier");
    }
    requireString(hint.key_type, `${hintLabel}.key_type`);
    if (!isKotodamaV1StateMapKeyTypeName(hint.key_type)) {
      rejectAt(hintLabel, ".key_type must be an exact Kotodama V1 StateMap key scalar");
    }
    requireString(hint.bound_kind, `${hintLabel}.bound_kind`);
    if (!isKotodamaV1DynamicAccessBoundKind(hint.bound_kind)) {
      rejectAt(hintLabel, ".bound_kind must be exactly take or page");
    }
    requireUnsignedInteger(
      hint.max_keys,
      KOTODAMA_V1_DYNAMIC_ACCESS_MAX_KEYS,
      `${hintLabel}.max_keys`,
    );
    if (hint.max_keys === 0) {
      rejectAt(hintLabel, ".max_keys must be in the V1 range 1..64");
    }
  });
}

function validateAccessSetHints(value, label) {
  if (value === null) return;
  requireExactKeys(
    value,
    [(TEXT_READ_KEYS), (TEXT_WRITE_KEYS), (TEXT_DYNAMIC_READS), (TEXT_DYNAMIC_WRITES)],
    label,
  );
  requireStringArray(value.read_keys, `${label}.${TEXT_READ_KEYS}`);
  requireStringArray(value.write_keys, `${label}.${TEXT_WRITE_KEYS}`);
  validateDynamicAccessHints(value.dynamic_reads, `${label}.${TEXT_DYNAMIC_READS}`);
  validateDynamicAccessHints(value.dynamic_writes, `${label}.${TEXT_DYNAMIC_WRITES}`);
}

function validateDynamicAccessHintStateMaps(accessSetHints, states, label) {
  if (accessSetHints === null) return;
  const stateMaps = new Map();
  for (const state of states) {
    const keyType = kotodamaV1StateMapKeyTypeName(state.type_name);
    if (keyType !== null) {
      stateMaps.set(state.name, keyType);
    }
  }
  for (const field of [(TEXT_DYNAMIC_READS), (TEXT_DYNAMIC_WRITES)]) {
    const seen = new Set();
    accessSetHints[field].forEach((hint, index) => {
      const hintLabel = `${label}.${field}[${index}]`;
      const identity = stringify([
        hint.base_key,
        hint.key_type,
        hint.bound_kind,
        hint.max_keys,
      ]);
      if (seen.has(identity)) {
        rejectAt(label, `.${field} contains a duplicate dynamic access hint`);
      }
      seen.add(identity);
      const stateName = hint.base_key.slice("state:".length);
      const expectedKeyType = stateMaps.get(stateName);
      if (expectedKeyType === undefined) {
        rejectAt(hintLabel, ".base_key must reference a declared top-level StateMap");
      }
      if (hint.key_type !== expectedKeyType) {
        rejectAt(hintLabel, `.key_type ${hint.key_type}${TEXT_DOES_NOT_MATCH}declared StateMap key type ${expectedKeyType}`);
      }
    });
  }
}

function validateTriggerRepeats(value, label) {
  requireRecord(value, label);
  const keys = ownKeys(value);
  if (keys.length !== 1 || !["Indefinitely", "Exactly"].includes(keys[0])) {
    rejectAt(label, `${TEXT_MUST_CONTAIN}exactly one canonical repeat policy`);
  }
  if (keys[0] === "Indefinitely") {
    if (value.Indefinitely !== null) {
      rejectAt(label, ".Indefinitely must be null");
    }
  } else {
    requireUnsignedInteger(value.Exactly, U32_MAX, `${label}.Exactly`);
  }
}

function validateTriggers(value, entrypointName, label) {
  requireDenseArray(value, label);
  const ids = new Set();
  value.forEach((trigger, index) => {
    const triggerLabel = `${label}[${index}]`;
    requireExactKeys(
      trigger,
      ["id", "repeats", "filter", "authority", "metadata", "callback"],
      triggerLabel,
    );
    if (!isCanonicalIdentifier(trigger.id, { declaration: true }) || ids.has(trigger.id)) {
      rejectAt(triggerLabel, `.id${TEXT_MUST_BE_UNIQUE_AND_CANONICAL}`);
    }
    ids.add(trigger.id);
    validateTriggerRepeats(trigger.repeats, `${triggerLabel}.repeats`);
    requireCanonicalBase64(trigger.filter, `${triggerLabel}.filter`);
    requireNullableString(trigger.authority, `${triggerLabel}.authority`);
    requireRecord(trigger.metadata, `${triggerLabel}.metadata`);
    validateBoundedJson(trigger.metadata, `${triggerLabel}.metadata`);
    requireExactKeys(trigger.callback, ["namespace", "entrypoint"], `${triggerLabel}.callback`);
    requireNullableString(trigger.callback.namespace, `${triggerLabel}.callback.namespace`);
    if (
      trigger.callback.namespace !== null
      && !isCanonicalIdentifier(trigger.callback.namespace, { typeDeclaration: true })
    ) {
      rejectAt(triggerLabel, `.callback.namespace${TEXT_MUST_BE_A}canonical type declaration`);
    }
    if (!isCanonicalEntrypointName(trigger.callback.entrypoint)) {
      rejectAt(triggerLabel, ".callback.entrypoint must be canonical");
    }
    if (trigger.callback.namespace === null && trigger.callback.entrypoint !== entrypointName) {
      rejectAt(triggerLabel, ".callback must target its declaring entrypoint");
    }
  });
}

function validateCompilerEntrypoint(entry, index, names, lifecycleKinds) {
  const label = `${TEXT_KOTODAMA_MANIFEST}entrypoint ${index}`;
  requireExactKeys(
    entry,
    [
      "name",
      "kind",
      "params",
      "argument_schema",
      "return_type",
      (TEXT_RETURN_SCHEMA),
      "authorization",
      (TEXT_READ_KEYS),
      (TEXT_WRITE_KEYS),
      (TEXT_ACCESS_HINTS_COMPLETE),
      (TEXT_ACCESS_HINTS_SKIPPED),
      "triggers",
    ],
    label,
  );
  requireExactKeys(entry.kind, ["kind", "value"], `${label}.kind`);
  if (!isCanonicalEntrypointName(entry.name)) {
    rejectAt(label, ".name is not a canonical V1 identifier or branded lifecycle selector");
  }
  if (names.has(entry.name)) {
    rejectAt(TEXT_KOTODAMA_MANIFEST, `${TEXT_CONTAINS_DUPLICATE}entrypoint ${entry.name}`);
  }
  names.add(entry.name);
  if (!MANIFEST_ENTRYPOINT_KINDS.has(entry.kind.kind)) {
    rejectAt(label, ".kind must be Kotoage, View, Hajimari, or Kaizen");
  }
  if (entry.kind.value !== null) {
    rejectAt(label, ".kind.value must be null");
  }
  const lifecycleKind =
    entry.name === "hajimari" || entry.name === "始まり"
      ? (TEXT_HAJIMARI)
      : entry.name === "kaizen" || entry.name === "改善"
        ? "Kaizen"
        : null;
  if (
    (lifecycleKind === null && [(TEXT_HAJIMARI), "Kaizen"].includes(entry.kind.kind)) ||
    (lifecycleKind !== null && entry.kind.kind !== lifecycleKind)
  ) {
    rejectAt(label, `.kind${TEXT_DOES_NOT_MATCH}its branded lifecycle selector`);
  }
  const authorization = normalizeEntrypointAuthorizationV1(entry.authorization, `${label}.authorization`);
  validateManifestEntrypointIdentityV1(entry.name, entry.kind.kind, authorization, label);
  if (lifecycleKind !== null) {
    if (lifecycleKinds.has(lifecycleKind)) {
      rejectAt(TEXT_KOTODAMA_MANIFEST, `${TEXT_CONTAINS_DUPLICATE}${lifecycleKind} entrypoints`);
    }
    lifecycleKinds.add(lifecycleKind);
  }

  requireDenseArray(entry.params, `${label}.params`, MAX_ENTRYPOINT_PARAMETERS);
  const paramNames = new Set();
  entry.params.forEach((param, paramIndex) => {
    const paramLabel = `${label}.params[${paramIndex}]`;
    requireExactKeys(param, ["name", "type_name"], paramLabel);
    if (!isCanonicalIdentifier(param.name) || paramNames.has(param.name)) {
      rejectAt(paramLabel, `.name${TEXT_MUST_BE_UNIQUE_AND_CANONICAL}`);
    }
    paramNames.add(param.name);
    requireString(param.type_name, `${paramLabel}.type_name`);
  });
  if (entry.params.length === 0) {
    if (entry.argument_schema !== null) {
      rejectAt(label, ".argument_schema must be null without parameters");
    }
  } else {
    if (entry.argument_schema === null) {
      rejectAt(label, ".argument_schema is required for declared parameters");
    }
    validateArgumentSchema(entry.argument_schema, entry.params, `${label}.argument_schema`);
  }
  if (entry.return_type === null || entry.return_schema === null) {
    rejectAt(label, " return_type and return_schema must be present together");
  }
  if (entry.return_schema !== null) {
    requireString(entry.return_type, `${label}.return_type`);
    const analysis = validateEntrypointType(entry.return_schema, `${label}.${TEXT_RETURN_SCHEMA}`);
    if (analysis.canonicalName !== entry.return_type) {
      rejectAt(label, `.return_type${TEXT_DOES_NOT_MATCH}return_schema`);
    }
  }
  requireStringArray(entry.read_keys, `${label}.read_keys`);
  requireStringArray(entry.write_keys, `${label}.write_keys`);
  if (entry.access_hints_complete !== null && typeof entry.access_hints_complete !== "boolean") {
    rejectAt(label, `.access_hints_complete${TEXT_MUST_BE_A}boolean or null`);
  }
  requireStringArray(entry.access_hints_skipped, `${label}.${TEXT_ACCESS_HINTS_SKIPPED}`);
  validateTriggers(entry.triggers, entry.name, `${label}.triggers`);
}

function validateCompilerManifestStates(states) {
  requireDenseArray(states, (TEXT_KOTODAMA_MANIFEST + "states"));
  const names = new Set();
  states.forEach((state, index) => {
    const label = `${TEXT_KOTODAMA_MANIFEST}state ${index}`;
    requireExactKeys(state, ["name", "type_name"], label);
    if (!isCanonicalIdentifier(state.name, { declaration: true })) {
      rejectAt(label, ".name is not canonical");
    }
    if (names.has(state.name)) {
      rejectAt(TEXT_KOTODAMA_MANIFEST, `${TEXT_CONTAINS_DUPLICATE}state ${state.name}`);
    }
    names.add(state.name);
    if (!isCanonicalStateTypeName(state.type_name)) {
      rejectAt(label, ".type_name is not a canonical V1 state type");
    }
  });
}

function validateCompilerManifestErrorTypes(value) {
  normalizeContractErrorTypesV1(value, (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST + "error_types"));
}

function validateKotoba(value) {
  if (value === null) return;
  requireDenseArray(value, (TEXT_KOTODAMA_MANIFEST + "kotoba"));
  const messageIds = new Set();
  value.forEach((entry, index) => {
    const label = `${TEXT_KOTODAMA_MANIFEST}kotoba[${index}]`;
    requireExactKeys(entry, ["msg_id", (TEXT_TRANSLATIONS)], label);
    requireString(entry.msg_id, `${label}.msg_id`);
    if (messageIds.has(entry.msg_id)) {
      rejectAt(TEXT_KOTODAMA_MANIFEST, `kotoba ${TEXT_CONTAINS_DUPLICATE}msg_id ${entry.msg_id}`);
    }
    messageIds.add(entry.msg_id);
    requireDenseArray(entry.translations, `${label}.${TEXT_TRANSLATIONS}`);
    const languages = new Set();
    entry.translations.forEach((translation, translationIndex) => {
      const translationLabel = `${label}.${TEXT_TRANSLATIONS}[${translationIndex}]`;
      requireExactKeys(translation, ["lang", "text"], translationLabel);
      requireString(translation.lang, `${translationLabel}.lang`);
      requireString(translation.text, `${translationLabel}.text`, { allowEmpty: true });
      if (languages.has(translation.lang)) {
        rejectAt(label, ` ${TEXT_CONTAINS_DUPLICATE}language ${translation.lang}`);
      }
      languages.add(translation.lang);
    });
  });
}

function validateProvenance(value) {
  if (value === null) return;
  // The canonical compiler currently emits no provenance. Accepting a
  // syntactically plausible signer/signature pair without verifying the exact
  // signed message and public-key algorithm would turn untrusted metadata into
  // a false authenticity claim. A later signed-manifest version must add full
  // cryptographic verification before this boundary accepts it.
  rejectType(
    (TEXT_KOTODAMA_MANIFEST + ("provenance " + TEXT_MUST_BE_SHARED + "null until signed provenance is verifiable")),
  );
}

function validateCompilerManifest(manifest) {
  requireRecord(manifest, (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST_SHARED));
  if (Object.hasOwn(manifest, "contract_name")) {
    rejectType(
      (TEXT_KOTODAMA_MANIFEST + (TEXT_MUST_USE_SHARED + TEXT_SEIYAKU_NAME + "; contract_name " + TEXT_IS_NOT + "a V1 field")),
    );
  }
  requireExactKeys(
    manifest,
    [
      (TEXT_SEIYAKU_NAME),
      (TEXT_CODE_HASH),
      (TEXT_ABI_HASH),
      (TEXT_COMPILER_FINGERPRINT),
      (TEXT_FEATURES_BITMAP),
      TEXT_ACCESS_SET_HINTS,
      "permissions",
      "events",
      (TEXT_ENTRYPOINTS),
      "states",
      "error_types",
      "enum_types",
      (TEXT_ERROR_MESSAGES),
      "kotoba",
      "provenance",
    ],
    (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST_SHARED),
  );
  if (!isCanonicalIdentifier(manifest.seiyaku_name, { typeDeclaration: true })) {
    rejectType(
      (TEXT_KOTODAMA_MANIFEST + (TEXT_SEIYAKU_NAME) + TEXT_MUST_BE_A + (TEXT_CANONICAL + "V1 type " + TEXT_DECLARATION_IDENTIFIER)),
    );
  }
  requireString(manifest.compiler_fingerprint, (TEXT_KOTODAMA_MANIFEST + (TEXT_COMPILER_FINGERPRINT)));
  requireUnsignedInteger(
    manifest.features_bitmap,
    3,
    (TEXT_KOTODAMA_MANIFEST + (TEXT_FEATURES_BITMAP)),
  );
  validateAccessSetHints(manifest.access_set_hints, (TEXT_KOTODAMA_MANIFEST + TEXT_ACCESS_SET_HINTS));
  requireDenseArray(manifest.entrypoints, (TEXT_KOTODAMA_MANIFEST + (TEXT_ENTRYPOINTS)));
  const names = new Set();
  const lifecycleKinds = new Set();
  manifest.entrypoints.forEach((entry, index) =>
    validateCompilerEntrypoint(entry, index, names, lifecycleKinds));
  validateCompilerManifestStates(manifest.states);
  validateDynamicAccessHintStateMaps(
    manifest.access_set_hints,
    manifest.states,
    (TEXT_KOTODAMA_MANIFEST + TEXT_ACCESS_SET_HINTS),
  );
  normalizeContractPermissionsV1(manifest.permissions, "manifest.permissions");
  normalizeContractEventsV1(manifest.events, "manifest.events");
  normalizeContractEnumTypesV1(manifest.enum_types, "manifest.enum_types");
  validateManifestDeclarationsV1(manifest, "manifest");
  validateCompilerManifestErrorTypes(manifest.error_types);
  validateManifestErrorTypeBindingsV1(manifest, (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST_SHARED));
  validateKotoba(manifest.kotoba);
  validateProvenance(manifest.provenance);
}

function validatePosition(value, label) {
  requireExactKeys(value, ["line", "column"], label);
  if (
    !isSafeInteger(value.line) ||
    value.line < 1 ||
    !isSafeInteger(value.column) ||
    value.column < 1
  ) {
    rejectAt(label, `${TEXT_MUST_CONTAIN}one-based safe-integer line and column values`);
  }
}

function validateSpan(value, label) {
  requireExactKeys(
    value,
    ["package_identity", "source", "start", "end", "byte_range"],
    label,
  );
  requireNullableString(value.package_identity, `${label}.package_identity`, {
    maximum: MAX_SOURCE_PATH_BYTES,
  });
  requireNullableString(value.source, `${label}.source`, { maximum: MAX_SOURCE_PATH_BYTES });
  validatePosition(value.start, `${label}.start`);
  validatePosition(value.end, `${label}.end`);
  const startsAfterEnd =
    value.start.line > value.end.line ||
    (value.start.line === value.end.line && value.start.column > value.end.column);
  if (startsAfterEnd) {
    rejectAt(label, `${TEXT_MUST_BE_A}forward half-open range`);
  }
  if (value.byte_range !== null) {
    requireExactKeys(value.byte_range, ["start", "end"], `${label}.byte_range`);
    if (
      !isSafeInteger(value.byte_range.start) ||
      value.byte_range.start < 0 ||
      !isSafeInteger(value.byte_range.end) ||
      value.byte_range.end < value.byte_range.start
    ) {
      rejectAt(label, `.byte_range${TEXT_MUST_BE_A}forward safe-integer byte range`);
    }
  }
}

function validateDiagnosticFix(value, label) {
  requireExactKeys(value, ["span", "replacement"], label);
  validateSpan(value.span, `${label}.span`);
  requireString(value.replacement, `${label}.replacement`, { allowEmpty: true });
}

function validateDiagnostic(value, index) {
  const label = `${TEXT_KOTODAMA_SHARED}diagnostic ${index}`;
  requireExactKeys(
    value,
    ["code", "severity", "phase", (TEXT_MESSAGE), "primary_span", "labels", "notes", "help", "fix", "alternative_fixes", "localized"],
    label,
  );
  if (typeof value.code !== "string" || !/^[EKW][A-Z0-9_]+$/.test(value.code)) {
    rejectAt(label, ".code is not a stable Kotodama diagnostic code");
  }
  if (!DIAGNOSTIC_SEVERITIES.has(value.severity)) {
    rejectAt(label, ".severity is invalid");
  }
  if (!DIAGNOSTIC_PHASES.has(value.phase)) {
    rejectAt(label, ".phase is invalid");
  }
  requireString(value.message, `${label}.${TEXT_MESSAGE}`);
  if (value.primary_span !== null) {
    validateSpan(value.primary_span, `${label}.primary_span`);
  }
  requireDenseArray(value.labels, `${label}.labels`);
  value.labels.forEach((entry, labelIndex) => {
    const entryLabel = `${label}.labels[${labelIndex}]`;
    requireExactKeys(entry, ["span", (TEXT_MESSAGE)], entryLabel);
    validateSpan(entry.span, `${entryLabel}.span`);
    requireString(entry.message, `${entryLabel}.${TEXT_MESSAGE}`, { allowEmpty: true });
  });
  requireStringArray(value.notes, `${label}.notes`);
  requireNullableString(value.help, `${label}.help`, { allowEmpty: true });
  if (value.fix !== null) {
    validateDiagnosticFix(value.fix, `${label}.fix`);
  }
  requireDenseArray(value.alternative_fixes, `${label}.alternative_fixes`);
  value.alternative_fixes.forEach((fix, fixIndex) => {
    validateDiagnosticFix(fix, `${label}.alternative_fixes[${fixIndex}]`);
  });
  if (value.localized !== null) {
    const localizedLabel = `${label}.localized`;
    requireExactKeys(value.localized, ["language", "message", "help"], localizedLabel);
    requireString(value.localized.language, `${localizedLabel}.language`);
    requireString(value.localized.message, `${localizedLabel}.message`);
    requireNullableString(value.localized.help, `${localizedLabel}.help`, { allowEmpty: true });
  }
}

function parseDiagnostics(raw) {
  const diagnostics = parseJson(raw, (TEXT_KOTODAMA_SHARED + "diagnosticsJson"));
  requireDenseArray(diagnostics, (TEXT_KOTODAMA_SHARED + "diagnostics"), MAX_DIAGNOSTICS);
  if (diagnostics.length === 0) {
    rejectType((TEXT_FAILED_KOTODAMA_COMPILATION_MUST + "return a non-empty diagnostic array"));
  }
  diagnostics.forEach(validateDiagnostic);
  if (!diagnostics.some((diagnostic) => diagnostic.severity === "error")) {
    rejectType((TEXT_FAILED_KOTODAMA_COMPILATION_MUST + (TEXT_CONTAIN_SHARED + "at least one error diagnostic")));
  }
  return diagnostics;
}

/** Validate and normalize one successful canonical Rust compiler wire output. */
export function normalizeCompilerOutput(output) {
  output = snapshotRecord(output, (TEXT_KOTODAMA_COMPILER + "output"));
  requireExactKeys(
    output,
    [
      (TEXT_ARTIFACTBYTES),
      (TEXT_MANIFEST_SHARED + "Json"),
      "codeHash",
      (TEXT_ABIHASH),
      "sourceMapJson",
      "budgetReportJson",
    ],
    (TEXT_KOTODAMA_COMPILER + "output"),
  );
  const artifactBytes = normalizeArtifactBytes(output.artifactBytes);
  const codeHashHex = normalizeHashHex(output.codeHash, "codeHash");
  const abiHashHex = normalizeHashHex(output.abiHash, (TEXT_ABIHASH));
  const actualCodeHash = artifactHashHex(artifactBytes);
  if (actualCodeHash !== codeHashHex) {
    throw new Error((TEXT_KOTODAMA_COMPILER + TEXT_ARTIFACT_BYTES_DO_NOT_MATCH_CODE_HASH));
  }

  const manifest = requireRecord(
    parseJson(output.manifestJson, (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST_SHARED + "Json")),
    (TEXT_KOTODAMA_SHARED + TEXT_MANIFEST_SHARED),
  );
  validateArtifactManifest(artifactBytes, manifest, codeHashHex, abiHashHex);

  const sourceMap = parseSidecar(output.sourceMapJson, "source-map", codeHashHex);
  const budgetReport = parseSidecar(output.budgetReportJson, "budget", codeHashHex);
  // The source map partitions each physical function into statement intervals
  // and generated-code gaps. An inlined statement retains its original helper
  // name, while the budget remains attached to the physical function.
  let sourceIndex = 0;
  let previousEnd = 0;
  for (const budgetEntry of budgetReport) {
    if (budgetEntry.pc_start < previousEnd) {
      rejectType((TEXT_KOTODAMA_COMPILER + "budget functions must be ordered without overlap"));
    }
    let cursor = budgetEntry.pc_start;
    while (cursor < budgetEntry.pc_end) {
      const sourceEntry = sourceMap[sourceIndex];
      if (!sourceEntry || sourceEntry.pc_start !== cursor ||
          sourceEntry.pc_end <= cursor || sourceEntry.pc_end > budgetEntry.pc_end) {
        rejectType((TEXT_KOTODAMA_COMPILER + "source-map intervals must exactly partition budget functions"));
      }
      if (sourceEntry.source_kind === "function" &&
          sourceEntry.function_name !== budgetEntry.function_name) {
        rejectAt(TEXT_KOTODAMA_COMPILER, `sidecar entry ${sourceIndex} function identity does not match`);
      }
      cursor = sourceEntry.pc_end;
      sourceIndex += 1;
    }
    previousEnd = budgetEntry.pc_end;
  }
  if (sourceIndex !== sourceMap.length) {
    rejectType((TEXT_KOTODAMA_COMPILER + "source-map intervals must exactly partition budget functions"));
  }
  return {
    artifactBytes,
    codeHashHex,
    abiHashHex,
    compilerFingerprint: manifest.compiler_fingerprint ?? "kotodama_lang",
    manifest,
    sourceMap,
    budgetReport,
  };
}

/**
 * Normalize the canonical Rust `Result<CompileOutput, DiagnosticBundle>` envelope.
 * Compiler failures remain structured data; malformed/internal failures throw.
 */
export function normalizeCompilerResult(result) {
  result = snapshotRecord(result, (TEXT_KOTODAMA_COMPILER + "result"));
  requireExactKeys(
    result,
    ["ok", "output", "diagnosticsJson"],
    (TEXT_KOTODAMA_COMPILER + "result"),
  );
  if (result.ok === true) {
    if (result.diagnosticsJson !== null) {
      rejectType(
        ("successful " + TEXT_KOTODAMA_SHARED + "compilation must " + TEXT_CONTAIN_SHARED + "an exact null diagnosticsJson sentinel"),
      );
    }
    return { ok: true, output: normalizeCompilerOutput(result.output) };
  }
  if (result.ok === false) {
    if (result.output !== null) {
      rejectType(
        (TEXT_FAILED_KOTODAMA_COMPILATION_MUST + (TEXT_CONTAIN_SHARED + "an exact null output sentinel")),
      );
    }
    return { ok: false, diagnostics: parseDiagnostics(result.diagnosticsJson) };
  }
  rejectType((TEXT_KOTODAMA_COMPILER + "result.ok" + TEXT_MUST_BE_A + (TEXT_BOOLEAN)));
}
