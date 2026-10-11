/** Canonical Norito value and frame primitives shared by metadata and ledger codecs. */
import { rejectError, rejectRange, rejectType } from "./validationThrow.js";
import {
  parseStrictLosslessJson,
  stringifyStrictLosslessIntegerJson,
} from "./strictLosslessJson.js";
import { Buffer } from "buffer";
import {
  BASE64_ENCODING,
  ED25519_ALGORITHM,
  JS_TYPE_BIGINT,
  JS_TYPE_FUNCTION,
  JS_TYPE_NUMBER,
  JS_TYPE_STRING,
  UTF8_ENCODING,
} from "./commonLiterals.js";
import { sha256 } from "@noble/hashes/sha2";
import { crc64Xz } from "./crc64Xz.js";
import {
  AccountAddress,
  curveIdFromAlgorithm,
  curveIdToAlgorithm,
  ensureCurveIdEnabled,
  normalizeBytes,
  validatePublicKeyForCurve,
} from "./address.js";
import { MultisigSpec } from "./multisig.js";
import { normalizeAccountId } from "./normalizers.js";
import { parseStrictGovernanceInstructionJson } from "./noritoGovernanceBoundary.js";

const TEXT_MUST_BE_AN_OBJECT_2 = " must be an object";

const TEXT_MUST_CONTAIN = " must contain ";

const TEXT_MUST_BE = " must be ";

const TEXT_EXCEEDS_THE = " exceeds the ";

const TEXT_IROHA_DATA_MODEL = "iroha_data_model::";

const TEXT_UNSUPPORTED = "unsupported ";

const TEXT_MUST_BE_AN_OBJECT = TEXT_MUST_BE_AN_OBJECT_2;

const TEXT_USES_UNSUPPORTED = (" uses " + TEXT_UNSUPPORTED);

const TEXT_MUST_CONTAIN_EXACTLY = (TEXT_MUST_CONTAIN + "exactly ");

const TEXT_MUST_BE_EXACT_STANDARD_BASE64 = (TEXT_MUST_BE + "exact standard-base64");

const TEXT_MUST_BE_A = (TEXT_MUST_BE + "a ");

const TEXT_MUST_NOT_CONTAIN = " must not contain ";

const TEXT_VARINT_EXCEEDS_AN_UNSIGNED_64_BIT_INTEGER = " varint exceeds an unsigned 64-bit integer";

const TEXT_EXCEEDS_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE = " exceeds JavaScript's safe integer range";

const TEXT_MUST_FIT_IN_AN_UNSIGNED_64_BIT_INTEGER = " must fit in an unsigned 64-bit integer";

const COMPACT_LEN_FLAG = 0x02;

const NORITO_FRAME_HEADER_LENGTH = 40;

const NORITO_MAX_HEADER_PADDING = 64;

const NORITO_SUPPORTED_HEADER_FLAGS = COMPACT_LEN_FLAG;

const UINT64_MASK = 0xffff_ffff_ffff_ffffn;

const EVENT_FILTER_BOX_SCHEMA_HASH = /* @__PURE__ */ schemaHashForTypeName(
  (TEXT_IROHA_DATA_MODEL + "events::model::EventFilterBox"),
);

let noritoLengthFlags = 0;

class BufferReader {
  constructor(buffer, context, lengthFlags = noritoLengthFlags) {
    this.buffer = buffer;
    this.context = context;
    this.lengthFlags = lengthFlags;
    this.offset = 0;
  }
  readU8(name) {
    this.#ensureAvailable(1, name);
    const value = this.buffer[this.offset];
    this.offset += 1;
    return value;
  }
  readU16LE(name) {
    this.#ensureAvailable(2, name);
    const value = this.buffer.readUInt16LE(this.offset);
    this.offset += 2;
    return value;
  }
  readU32LE(name) {
    this.#ensureAvailable(4, name);
    const value = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return value;
  }
  readU64LE(name) {
    this.#ensureAvailable(8, name);
    const value = this.buffer.readBigUInt64LE(this.offset);
    this.offset += 8;
    return value;
  }
  readLength(name) {
    if ((this.lengthFlags & COMPACT_LEN_FLAG) !== 0) {
      const [value, bytesRead] = decodeUnsignedLeb128(
        this.buffer,
        this.offset,
        `${this.context}.${name}`,
      );
      this.offset += bytesRead;
      return value;
    }
    return bigintToSafeNumber(this.readU64LE(name), `${this.context}.${name}`);
  }
  readBytes(length, name) {
    const safeLength = Number(length);
    this.#ensureAvailable(safeLength, name);
    const value = this.buffer.subarray(this.offset, this.offset + safeLength);
    this.offset += safeLength;
    return value;
  }

  assertEof() {
    if (this.offset !== this.buffer.length) {
      rejectError(`${this.context} has ${this.buffer.length - this.offset} trailing bytes`);
    }
  }

  #ensureAvailable(length, name) {
    if (this.offset + length > this.buffer.length) {
      rejectError(`${this.context}.${name} overran payload (${length} bytes requested, ${this.buffer.length - this.offset} remaining)`);
    }
  }
}

function cloneJson(value) {
  const directDataspace = exactRegisterDataspaceAssetDefinitionJson(value);
  if (directDataspace !== null) {
    return parseRegisterDataspaceAssetDefinitionJson(directDataspace, "direct-dataspace instruction");
  }
  if (isPublicPlainBallotInstruction(value)) {
    return parseStrictGovernanceInstructionJson(
      stringifyStrictLosslessIntegerJson(value, "standalone public ballot"),
      "standalone public ballot",
    );
  }
  if (typeof structuredClone === JS_TYPE_FUNCTION) {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}

function normalizeInstructionJsonValue(value) {
  if (value instanceof MultisigSpec) {
    return normalizeInstructionJsonValue(value.toPayload());
  }
  if (
    isPlainObject(value) &&
    value.quorum !== undefined &&
    value.signatories !== undefined &&
    (value.transaction_ttl_ms !== undefined || value.transactionTtlMs !== undefined)
  ) {
    return {
      quorum: normalizeInstructionJsonValue(value.quorum),
      signatories: normalizeInstructionJsonValue(value.signatories),
      transaction_ttl_ms: normalizeInstructionJsonValue(
        value.transaction_ttl_ms ?? value.transactionTtlMs,
      ),
    };
  }
  if (value instanceof Map) {
    return Object.fromEntries(
      Array.from(value.entries())
        .sort(([left], [right]) => String(left).localeCompare(String(right)))
        .map(([key, entryValue]) => [String(key), normalizeInstructionJsonValue(entryValue)]),
    );
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeInstructionJsonValue(entry));
  }
  if (isPlainObject(value)) {
    const normalized = Object.create(null);
    for (const [key, entryValue] of Object.entries(value)) {
      normalized[key] = normalizeInstructionJsonValue(entryValue);
    }
    return normalized;
  }
  return value;
}

function isPublicPlainBallotInstruction(value) {
  return isPlainObject(value) && (
    Object.prototype.hasOwnProperty.call(value, "CastPlainBallot")
    || Object.prototype.hasOwnProperty.call(value, "UpdatePlainConviction")
  );
}

/** Serialize the direct-dataspace namespace as an exact native u64 JSON token. */
export function exactRegisterDataspaceAssetDefinitionJson(instruction) {
  if (!isPlainObject(instruction) || !Object.prototype.hasOwnProperty.call(
    instruction, "RegisterDataspaceAssetDefinition",
  )) {
    return null;
  }
  const payload = instruction.RegisterDataspaceAssetDefinition;
  if (Object.keys(instruction).length !== 1 || !isPlainObject(payload) ||
      Object.keys(payload).length !== 2 ||
      !Object.prototype.hasOwnProperty.call(payload, "dataspace_id") ||
      !Object.prototype.hasOwnProperty.call(payload, "object") ||
      !isPlainObject(payload.object)) {
    rejectType("RegisterDataspaceAssetDefinition must contain exactly dataspace_id and object");
  }
  const value = payload.dataspace_id;
  if (typeof value !== "bigint" &&
      (typeof value !== "number" || !Number.isSafeInteger(value))) {
    rejectType("RegisterDataspaceAssetDefinition.dataspace_id must be an exact unsigned integer");
  }
  const dataspaceId = BigInt(value);
  if (dataspaceId <= 0n || dataspaceId > 0xffff_ffff_ffff_ffffn) {
    rejectRange("RegisterDataspaceAssetDefinition.dataspace_id must be a nonzero u64");
  }
  // Only the namespace needs a raw integer token. The unchanged definition
  // keeps ordinary JSON metadata, including finite fractions and signed zero.
  // Native still validates the complete definition and instruction schema.
  validateInstructionObjectNumbers(payload.object);
  const objectJson = JSON.stringify(payload.object);
  return `{"RegisterDataspaceAssetDefinition":{"dataspace_id":${dataspaceId},"object":${objectJson}}}`;
}

function parseRegisterDataspaceAssetDefinitionJson(json, context) {
  return parseStrictLosslessJson(json, context, {
    floatingPointPaths: [["RegisterDataspaceAssetDefinition", "object", "metadata"]],
  });
}

function validateInstructionObjectNumbers(value) {
  if (typeof value === "bigint") {
    rejectType("instruction object bigint values require exact JSON text");
  }
  if (typeof value === "number" && (
    !Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))
  )) {
    rejectType("instruction object numbers must be finite and integer values must be safe; use exact JSON text for larger integers");
  }
  if (Array.isArray(value)) {
    for (const entry of value) validateInstructionObjectNumbers(entry);
  } else if (isPlainObject(value)) {
    for (const entry of Object.values(value)) validateInstructionObjectNumbers(entry);
  }
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }
  rejectType(("bytes" + TEXT_MUST_BE + "a Buffer, ArrayBuffer, or typed array"));
}

function encodeStructValue(fields) {
  const parts = [];
  for (const payloads of fields) {
    for (const payload of payloads) {
      parts.push(encodeNoritoField(payload));
    }
  }
  return Buffer.concat(parts);
}

function decodeStructFields(payload, context, names) {
  const reader = new BufferReader(payload, context);
  const result = {};
  for (const name of names) {
    result[name] = readNoritoField(reader, name);
  }
  reader.assertEof();
  return result;
}

function encodeTupleValue(payloads) {
  return encodeStructValue(payloads.map((payload) => [payload]));
}

function decodeTupleFields(payload, context, names) {
  return decodeStructFields(payload, context, names);
}

function encodeOptionValue(value, encode, context) {
  if (value === undefined || value === null) {
    return Buffer.of(0);
  }
  return Buffer.concat([Buffer.of(1), encodeNoritoField(encode(value, context))]);
}

function decodeOptionValue(payload, decode, context) {
  if (payload.length === 0) {
    rejectError(`${context} option payload is empty`);
  }
  const tag = payload[0];
  if (tag === 0) {
    if (payload.length !== 1) {
      rejectError(`${context} None option contained trailing bytes`);
    }
    return null;
  }
  if (tag !== 1) {
    rejectError(`${context} option tag ${tag} is invalid`);
  }
  const reader = new BufferReader(payload.subarray(1), `${context}.some`);
  const inner = readNoritoField(reader, "value");
  reader.assertEof();
  return decode(inner, `${context}.value`);
}

function encodeBoolValue(value, context) {
  if (typeof value !== "boolean") {
    rejectType(`${context}${TEXT_MUST_BE_A}boolean`);
  }
  return Buffer.of(value ? 1 : 0);
}

function decodeBoolValue(payload, context) {
  if (payload.length !== 1 || (payload[0] !== 0 && payload[0] !== 1)) {
    rejectError(`${context}${TEXT_MUST_CONTAIN}a canonical boolean byte`);
  }
  return payload[0] === 1;
}

function normalizeFlexibleBytes(value) {
  if (typeof value === JS_TYPE_STRING) {
    const base64 = tryDecodeBase64(value.trim());
    if (base64) {
      return Array.from(base64);
    }
  }
  return Array.from(normalizeBytes(value));
}

function encodeNameValue(value, context) {
  const literal = assertExactNonEmptyString(value, context);
  if (/\p{White_Space}/u.test(literal)) {
    rejectType(`${context}${TEXT_MUST_NOT_CONTAIN}whitespace`);
  }
  if (/[@#$]/u.test(literal)) {
    rejectType(`${context} contains a reserved Name character`);
  }
  return encodeNoritoStringValue(literal.normalize("NFC"));
}

function decodeNameValue(payload, context) {
  const literal = decodeStringValue(payload, context);
  if (literal.length === 0 || /\p{White_Space}/u.test(literal)) {
    rejectType(`${context}${TEXT_MUST_BE_A}non-empty Name without whitespace`);
  }
  if (/[@#$]/u.test(literal)) {
    rejectType(`${context} contains a reserved Name character`);
  }
  return literal.normalize("NFC");
}

function encodeMetadataValue(value, context) {
  if (!isPlainObject(value)) {
    rejectType(`${context}${TEXT_MUST_BE_AN_OBJECT}`);
  }
  const entries = Object.keys(value)
    .sort()
    .map((key) => [key, value[key]]);
  return encodeNoritoVec(entries, ([key, json]) =>
    encodeTupleValue([
      encodeNameValue(key, `${context}.${key}`),
      encodeNoritoJsonValue(json),
    ]),
  );
}

function decodeMetadataValue(payload, context) {
  const entries = decodeNoritoVec(
    payload,
    (entry, index) => {
      const fields = decodeTupleFields(entry, `${context}[${index}]`, ["key", "value"]);
      return [
        decodeNameValue(fields.key, `${context}[${index}].key`),
        decodeJsonValue(fields.value, `${context}[${index}].value`),
      ];
    },
    context,
  );
  return Object.fromEntries(entries);
}

function encodeAccountIdValue(value, context) {
  const literal = normalizeAccountId(value, context);
  const address = AccountAddress.fromI105(literal);
  const controller = address.controllerInfo();
  if (!controller || typeof controller.tag !== JS_TYPE_NUMBER) {
    rejectError(`${context} could not resolve account controller information`);
  }
  switch (controller.tag) {
    case 0:
      return Buffer.concat([
        u32ToLittleEndianBuffer(0),
        encodeNoritoField(encodePublicKeyValue(controller, context)),
      ]);
    case 1:
      return Buffer.concat([
        u32ToLittleEndianBuffer(1),
        encodeNoritoField(encodeMultisigPolicyPayload(controller, context)),
      ]);
    default:
      rejectError(`${context}${TEXT_USES_UNSUPPORTED}account controller tag ${controller.tag}`);
  }
}

function decodeAccountIdValue(payload, context) {
  const reader = new BufferReader(payload, context);
  const kind = reader.readU32LE("kind");
  const controllerPayload = readNoritoField(reader, "payload");
  reader.assertEof();
  let header;
  let controller;
  if (kind === 0) {
    const { curve, publicKey } = decodePublicKeyValue(controllerPayload, context);
    header = { version: 0, classId: 0, normVersion: 1, extFlag: false };
    controller = { tag: 0, curve, publicKey };
  } else if (kind === 1) {
    const policy = decodeMultisigPolicyPayload(controllerPayload, context);
    header = { version: 0, classId: 1, normVersion: 1, extFlag: false };
    controller = { tag: 1, ...policy };
  } else {
    rejectError(`${context}${TEXT_USES_UNSUPPORTED}account controller variant ${kind}`);
  }
  return new AccountAddress(header, controller).toI105();
}

function encodePublicKeyValue(controller, context) {
  ensureCurveIdEnabled(controller.curve, context);
  const publicKey = Buffer.from(normalizeBytes(controller.publicKey));
  validatePublicKeyForCurve(controller.curve, publicKey, context);
  return encodeConstVecU8Value(
    Buffer.concat([Buffer.of(algorithmTagForCurveId(controller.curve, context)), publicKey]),
  );
}

function decodePublicKeyValue(payload, context) {
  const bytes = decodeConstVecU8Value(payload, `${context}.publicKey`);
  if (bytes.length === 0) {
    rejectError(`${context}.publicKey payload is empty`);
  }
  const curve = curveIdForAlgorithmTag(bytes[0], `${context}.publicKey.algorithm`);
  const publicKey = bytes.subarray(1);
  validatePublicKeyForCurve(curve, publicKey, `${context}.publicKey.payload`);
  return { curve, publicKey: Buffer.from(publicKey) };
}

function encodeConstVecU8Value(bytes) {
  const normalized = Buffer.from(normalizeFlexibleBytes(bytes, "ConstVec<u8>"));
  const parts = [u64ToLittleEndianBuffer(normalized.length)];
  for (const byte of normalized) {
    parts.push(encodeNoritoLength(1), Buffer.of(byte));
  }
  return Buffer.concat(parts);
}

function decodeConstVecU8Value(payload, context) {
  const reader = new BufferReader(payload, context, noritoLengthFlags);
  const count = bigintToSafeNumber(reader.readU64LE("count"), `${context}.count`);
  // Every element needs its field length and one byte. Reject impossible
  // source geometry before reserving from an attacker-controlled count.
  const minimumElementBytes = (noritoLengthFlags & COMPACT_LEN_FLAG) !== 0 ? 2 : 9;
  if (count > Math.floor((reader.buffer.length - reader.offset) / minimumElementBytes)) {
    rejectError(`${context} count exceeds its encoded byte geometry`);
  }
  const bytes = Buffer.allocUnsafe(count);
  for (let index = 0; index < count; index += 1) {
    const item = readNoritoField(reader, `item${index}`);
    if (item.length !== 1) {
      rejectError(`${context}[${index}]${TEXT_MUST_CONTAIN}exactly one byte`);
    }
    bytes[index] = item[0];
  }
  reader.assertEof();
  return bytes;
}

function algorithmTagForCurveId(curve, context) {
  const algorithm = curveIdToAlgorithm(curve);
  switch (algorithm) {
    case ED25519_ALGORITHM:
      return 0;
    case "secp256k1":
      return 1;
    case "bls_normal":
      return 2;
    case "bls_small":
      return 3;
    case "ml-dsa":
      return 4;
    case "gost3410-2012-256-paramset-a":
      return 5;
    case "gost3410-2012-256-paramset-b":
      return 6;
    case "gost3410-2012-256-paramset-c":
      return 7;
    case "gost3410-2012-512-paramset-a":
      return 8;
    case "gost3410-2012-512-paramset-b":
      return 9;
    case "sm2":
      return 10;
    default:
      rejectError(`${context}${TEXT_USES_UNSUPPORTED}public-key algorithm ${algorithm}`);
  }
}

function curveIdForAlgorithmTag(tag, context) {
  switch (tag) {
    case 0:
      return curveIdFromAlgorithm(ED25519_ALGORITHM);
    case 1:
      return curveIdFromAlgorithm("secp256k1");
    case 2:
      return curveIdFromAlgorithm("bls_normal");
    case 3:
      return curveIdFromAlgorithm("bls_small");
    case 4:
      return curveIdFromAlgorithm("ml-dsa");
    case 5:
      return curveIdFromAlgorithm("gost3410-2012-256-paramset-a");
    case 6:
      return curveIdFromAlgorithm("gost3410-2012-256-paramset-b");
    case 7:
      return curveIdFromAlgorithm("gost3410-2012-256-paramset-c");
    case 8:
      return curveIdFromAlgorithm("gost3410-2012-512-paramset-a");
    case 9:
      return curveIdFromAlgorithm("gost3410-2012-512-paramset-b");
    case 10:
      return curveIdFromAlgorithm("sm2");
    default:
      rejectError(`${context}${TEXT_USES_UNSUPPORTED}public-key algorithm tag ${tag}`);
  }
}

function encodeMultisigPolicyPayload(policy, context) {
  if (!Array.isArray(policy.members) || policy.members.length === 0) {
    rejectError(`${context} multisig policy${TEXT_MUST_CONTAIN}at least one member`);
  }
  return Buffer.concat([
    encodeNoritoField(encodeU8Value(policy.version, `${context}.version`)),
    encodeNoritoField(encodeU16Value(policy.threshold, `${context}.threshold`)),
    encodeNoritoField(
      encodeNoritoVec(policy.members, (member, index) =>
        encodeMultisigMemberPayload(member, `${context}.members[${index}]`),
      ),
    ),
  ]);
}

function decodeMultisigPolicyPayload(payload, context) {
  const reader = new BufferReader(payload, context);
  const version = decodeU8Value(readNoritoField(reader, "version"), `${context}.version`);
  const threshold = decodeU16Value(readNoritoField(reader, "threshold"), `${context}.threshold`);
  const members = decodeNoritoVec(
    readNoritoField(reader, "members"),
    (memberPayload, index) =>
      decodeMultisigMemberPayload(memberPayload, `${context}.members[${index}]`),
    `${context}.members`,
  );
  reader.assertEof();
  return { version, threshold, members };
}

function encodeMultisigMemberPayload(member, context) {
  return Buffer.concat([
    encodeNoritoField(encodePublicKeyValue(member, `${context}.public_key`)),
    encodeNoritoField(encodeU16Value(member.weight, `${context}.weight`)),
  ]);
}

function decodeMultisigMemberPayload(payload, context) {
  const reader = new BufferReader(payload, context);
  const { curve, publicKey } = decodePublicKeyValue(
    readNoritoField(reader, "publicKey"),
    `${context}.publicKey`,
  );
  const weight = decodeU16Value(readNoritoField(reader, "weight"), `${context}.weight`);
  reader.assertEof();
  return { curve, publicKey, weight };
}

function encodeEnumTagValue(index, encodePayload) {
  const payload = encodePayload ? encodeNoritoField(encodePayload()) : Buffer.alloc(0);
  return Buffer.concat([u32ToLittleEndianBuffer(index), payload]);
}

function encodeEventFilterBoxFramePayload(value, context) {
  const frameBytes = decodeExactStandardBase64(value, context);
  const frame = decodeNoritoFrame(frameBytes, context, EVENT_FILTER_BOX_SCHEMA_HASH);
  const expectedFlags = noritoLengthFlags & COMPACT_LEN_FLAG;
  if (frame.flags !== expectedFlags) {
    rejectError(`${context} uses Norito layout flags ${frame.flags}; expected ${expectedFlags}`);
  }
  const canonical = frameNoritoPayload(
    frame.payload,
    EVENT_FILTER_BOX_SCHEMA_HASH,
    frame.flags,
  );
  if (!canonical.equals(frameBytes)) {
    rejectError(`${context}${TEXT_MUST_BE_A}canonical unpadded EventFilterBox frame`);
  }
  return frame.payload;
}

function decodeEventFilterBoxFramePayload(payload, _context) {
  return frameNoritoPayload(
    payload,
    EVENT_FILTER_BOX_SCHEMA_HASH,
    noritoLengthFlags & COMPACT_LEN_FLAG,
  ).toString(BASE64_ENCODING);
}

function decodeExactStandardBase64(value, context) {
  if (
    typeof value !== JS_TYPE_STRING ||
    value.length === 0 ||
    value.trim() !== value ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)
  ) {
    rejectType(`${context}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`);
  }
  const bytes = Buffer.from(value, BASE64_ENCODING);
  if (bytes.length === 0 || bytes.toString(BASE64_ENCODING) !== value) {
    rejectType(`${context}${TEXT_MUST_BE_EXACT_STANDARD_BASE64}`);
  }
  return bytes;
}

function assertOnlyObjectKeys(value, allowedKeys, context) {
  const allowed = new Set(allowedKeys);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown !== undefined) {
    rejectType(`${context} contains unknown field ${unknown}`);
  }
}

function encodeU8Value(value, context) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 0xff) {
    rejectType(`${context}${TEXT_MUST_BE}an unsigned 8-bit integer`);
  }
  return Buffer.of(normalized);
}

function decodeU8Value(payload, context) {
  if (payload.length !== 1) {
    rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}one byte`);
  }
  return payload[0];
}

function encodeU16Value(value, context) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 0xffff) {
    rejectType(`${context}${TEXT_MUST_BE}an unsigned 16-bit integer`);
  }
  return u16ToLittleEndianBuffer(normalized);
}

function decodeU16Value(payload, context) {
  if (payload.length !== 2) {
    rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}two bytes`);
  }
  return payload.readUInt16LE(0);
}

function encodeU32Value(value, context) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 0xffff_ffff) {
    rejectType(`${context}${TEXT_MUST_BE}an unsigned 32-bit integer`);
  }
  return u32ToLittleEndianBuffer(normalized);
}

function decodeU32Value(payload, context) {
  if (payload.length !== 4) {
    rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}four bytes`);
  }
  return payload.readUInt32LE(0);
}

function encodeNoritoStringValue(value) {
  return encodeNoritoField(Buffer.from(value, UTF8_ENCODING));
}

function decodeStringValue(payload, context, lengthFlags = noritoLengthFlags) {
  const reader = new BufferReader(payload, context, lengthFlags);
  const stringBytes = readNoritoField(reader, "value");
  reader.assertEof();
  return stringBytes.toString(UTF8_ENCODING);
}

function encodeNoritoJsonValue(value) {
  return encodeStructValue([
    [encodeNoritoStringValue(canonicalJsonStringify(value))],
  ]);
}

function decodeJsonValue(payload, context) {
  const fields = decodeTupleFields(payload, context, ["value"]);
  return JSON.parse(decodeStringValue(fields.value, `${context}.value`));
}

function readNoritoField(reader, name) {
  const length = reader.readLength(`${name}.length`);
  return reader.readBytes(length, `${name}.payload`);
}

function encodeNoritoField(payload) {
  return Buffer.concat([encodeNoritoLength(payload.length), payload]);
}

function encodeNoritoVec(values, encode) {
  const payloads = values.map(encode);
  const parts = [u64ToLittleEndianBuffer(payloads.length)];
  for (const payload of payloads) {
    parts.push(encodeNoritoLength(payload.length), payload);
  }
  return Buffer.concat(parts);
}

function withNoritoCompactLengths(fn) {
  return withNoritoLengthFlags(COMPACT_LEN_FLAG, fn);
}

function withNoritoLengthFlags(flags, fn) {
  const previous = noritoLengthFlags;
  noritoLengthFlags = flags;
  try {
    return fn();
  } finally {
    noritoLengthFlags = previous;
  }
}

function encodeNoritoLength(value) {
  if ((noritoLengthFlags & COMPACT_LEN_FLAG) !== 0) {
    return encodeUnsignedLeb128(value);
  }
  return u64ToLittleEndianBuffer(value);
}

function decodeNoritoVec(payload, decode, context, maxCount = null) {
  const reader = new BufferReader(payload, context, noritoLengthFlags);
  const count = bigintToSafeNumber(reader.readU64LE("count"), `${context}.count`);
  if (maxCount !== null && count > maxCount) {
    rejectRange(`${context}${TEXT_EXCEEDS_THE}${maxCount}-item limit`);
  }
  const values = [];
  for (let index = 0; index < count; index += 1) {
    const itemPayload = readNoritoField(reader, `item${index}`);
    values.push(decode(itemPayload, index));
  }
  reader.assertEof();
  return values;
}

function schemaHashForTypeName(typeName) {
  const input = Uint8Array.from(
    Buffer.concat([
      Buffer.from("norito:v1:type-name\0", UTF8_ENCODING),
      Buffer.from(typeName, UTF8_ENCODING),
    ]),
  );
  const digest = sha256(
    input,
  );
  return Buffer.from(digest.subarray(0, 16));
}

/**
 * Validate one canonical, uncompressed Norito v1 frame without decoding its payload.
 *
 * The schema can be bound either by its exact hash or by the Rust type name from
 * which Norito derives that hash. The returned payload is a view over the input.
 *
 * @param {ArrayBufferView | ArrayBuffer | Buffer} bytes
 * @param {{
 *   context?: string,
 *   expectedSchemaHash?: ArrayBufferView | ArrayBuffer | Buffer,
 *   expectedTypeName?: string,
 *   expectedPaddingLength?: number,
 *   requireNonEmptyPayload?: boolean,
 * }} [options]
 * @returns {{payload: Buffer, schemaHash: Buffer, flags: number}}
 */
export function validateNoritoFrame(bytes, options = {}) {
  const context = options.context ?? "Norito frame";
  const buffer = toBuffer(bytes);
  if (buffer.length < NORITO_FRAME_HEADER_LENGTH) {
    rejectError(`${context} is shorter than the ${NORITO_FRAME_HEADER_LENGTH}-byte Norito header`);
  }
  if (buffer.subarray(0, 4).toString("ascii") !== "NRT0") {
    rejectError(`${context} is not an NRT0 frame`);
  }
  const major = buffer[4];
  const minor = buffer[5];
  if (major !== 0 || minor !== 0) {
    rejectError(`${context}${TEXT_USES_UNSUPPORTED}NRT0 version ${major}.${minor}`);
  }

  const schemaHash = buffer.subarray(6, 22);
  if (schemaHash.every((byte) => byte === 0)) {
    rejectError(`${context} uses the reserved all-zero schema hash`);
  }
  let expectedSchemaHash = null;
  if (options.expectedSchemaHash !== undefined) {
    expectedSchemaHash = toBuffer(options.expectedSchemaHash);
    if (expectedSchemaHash.length !== 16) {
      rejectType(`${context} expected schema hash${TEXT_MUST_CONTAIN}exactly 16 bytes`);
    }
  }
  if (options.expectedTypeName !== undefined) {
    if (
      typeof options.expectedTypeName !== JS_TYPE_STRING ||
      options.expectedTypeName.length === 0
    ) {
      rejectType(`${context} expected Rust type name${TEXT_MUST_BE}non-empty`);
    }
    const fromTypeName = /* @__PURE__ */ schemaHashForTypeName(options.expectedTypeName);
    if (expectedSchemaHash !== null && !expectedSchemaHash.equals(fromTypeName)) {
      rejectType(`${context} expected schema constraints contradict each other`);
    }
    expectedSchemaHash = fromTypeName;
  }
  if (expectedSchemaHash !== null && !schemaHash.equals(expectedSchemaHash)) {
    rejectError(`${context} schema hash did not match the expected type`);
  }

  const compression = buffer[22];
  if (compression !== 0) {
    rejectError(`${context} must use uncompressed Norito payload encoding`);
  }
  const payloadLength = bigintToSafeNumber(
    buffer.readBigUInt64LE(23),
    `${context}.payloadLength`,
  );
  if (options.requireNonEmptyPayload === true && payloadLength === 0) {
    rejectError(`${context}${TEXT_MUST_CONTAIN}a non-empty Norito payload`);
  }
  const expectedCrc = buffer.readBigUInt64LE(31);
  const flags = buffer[39];
  if ((flags & ~NORITO_SUPPORTED_HEADER_FLAGS) !== 0) {
    rejectError(`${context}${TEXT_USES_UNSUPPORTED}Norito header flags 0x${flags.toString(16)}`);
  }

  const paddingLength = buffer.length - NORITO_FRAME_HEADER_LENGTH - payloadLength;
  if (paddingLength < 0) {
    rejectError(`${context} payload length${TEXT_EXCEEDS_THE}available frame bytes`);
  }
  if (paddingLength > NORITO_MAX_HEADER_PADDING) {
    rejectError(`${context}${TEXT_EXCEEDS_THE}${NORITO_MAX_HEADER_PADDING}-byte Norito header-padding bound`);
  }
  if (options.expectedPaddingLength !== undefined) {
    if (
      !Number.isInteger(options.expectedPaddingLength) ||
      options.expectedPaddingLength < 0 ||
      options.expectedPaddingLength > NORITO_MAX_HEADER_PADDING
    ) {
      rejectType(`${context} expected padding length${TEXT_MUST_BE}an integer from 0 through ${NORITO_MAX_HEADER_PADDING}`);
    }
    if (paddingLength !== options.expectedPaddingLength) {
      rejectError(`${context}${TEXT_MUST_CONTAIN_EXACTLY}${options.expectedPaddingLength} bytes of header padding`);
    }
  }
  const payloadStart = NORITO_FRAME_HEADER_LENGTH + paddingLength;
  const padding = buffer.subarray(NORITO_FRAME_HEADER_LENGTH, payloadStart);
  if (padding.some((byte) => byte !== 0)) {
    rejectError(`${context} contains non-zero alignment padding or trailing bytes`);
  }
  const payload = buffer.subarray(payloadStart, payloadStart + payloadLength);
  if (payload.length !== payloadLength || payloadStart + payload.length !== buffer.length) {
    rejectError(`${context} contains trailing bytes outside the declared payload`);
  }
  const actualCrc = crc64Xz(payload);
  if (actualCrc !== expectedCrc) {
    rejectError(`${context} CRC64 mismatch`);
  }
  return { payload, schemaHash, flags };
}

function decodeNoritoFrame(buffer, context, expectedSchemaHash) {
  if (buffer.length < NORITO_FRAME_HEADER_LENGTH) {
    // Preserve the established decoder diagnostic while the exported preflight
    // helper reports the more specific short-header error.
    rejectError(`${context} reader overran payload while reading Norito header`);
  }
  return validateNoritoFrame(buffer, {
    context,
    ...(expectedSchemaHash == null ? {} : { expectedSchemaHash }),
  });
}

function frameNoritoPayload(payload, schemaHash, flags = 0, padding = 0) {
  const header = Buffer.concat([
    Buffer.from("NRT0", "ascii"),
    Buffer.from([0, 0]),
    schemaHash,
    Buffer.from([0]),
    u64ToLittleEndianBuffer(payload.length),
    u64ToLittleEndianBuffer(crc64Xz(payload)),
    Buffer.from([flags & 0xff]),
  ]);
  return Buffer.concat([header, Buffer.alloc(padding), payload]);
}

function u16ToLittleEndianBuffer(value) {
  const buffer = Buffer.allocUnsafe(2);
  buffer.writeUInt16LE(value, 0);
  return buffer;
}

function u32ToLittleEndianBuffer(value) {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value, 0);
  return buffer;
}

function u64ToLittleEndianBuffer(value) {
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeBigUInt64LE(normalizeU64Input(value, "u64"), 0);
  return buffer;
}

function normalizeU64Input(value, context) {
  if (typeof value === JS_TYPE_BIGINT) {
    if (value < 0n || value > UINT64_MASK) {
      rejectRange(`${context}${TEXT_MUST_FIT_IN_AN_UNSIGNED_64_BIT_INTEGER}`);
    }
    return value;
  }
  if (typeof value === JS_TYPE_NUMBER) {
    if (!Number.isInteger(value) || value < 0 || !Number.isSafeInteger(value)) {
      rejectType(`${context}${TEXT_MUST_BE_A}non-negative safe integer or bigint`);
    }
    return BigInt(value);
  }
  if (typeof value === JS_TYPE_STRING && /^\d+$/.test(value.trim())) {
    const parsed = BigInt(value.trim());
    if (parsed > UINT64_MASK) {
      rejectRange(`${context}${TEXT_MUST_FIT_IN_AN_UNSIGNED_64_BIT_INTEGER}`);
    }
    return parsed;
  }
  rejectType(`${context}${TEXT_MUST_BE_A}bigint, integer number, or decimal string`);
}

function bigintToSafeNumber(value, context) {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    rejectRange(`${context}${TEXT_EXCEEDS_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`);
  }
  return Number(value);
}

function encodeUnsignedLeb128(value) {
  let remaining = BigInt(value);
  const bytes = [];
  while (remaining >= 0x80n) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  return Buffer.from(bytes);
}

function decodeUnsignedLeb128(buffer, offset, context) {
  let value = 0n;
  let shift = 0n;
  let cursor = offset;
  for (let used = 0; used < 10 && cursor < buffer.length; used += 1) {
    const byte = BigInt(buffer[cursor]);
    cursor += 1;
    if (used === 9 && (byte & 0xfen) !== 0n) {
      rejectRange(`${context}${TEXT_VARINT_EXCEEDS_AN_UNSIGNED_64_BIT_INTEGER}`);
    }
    value |= (byte & 0x7fn) << shift;
    if ((byte & 0x80n) === 0n) {
      if (used > 0 && byte === 0n) {
        rejectError(`${context} varint is not minimally encoded`);
      }
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        rejectRange(`${context}${TEXT_EXCEEDS_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE}`);
      }
      return [Number(value), cursor - offset];
    }
    shift += 7n;
  }
  if (cursor >= buffer.length) {
    rejectError(`${context} varint is truncated`);
  }
  rejectRange(`${context}${TEXT_VARINT_EXCEEDS_AN_UNSIGNED_64_BIT_INTEGER}`);
}

function canonicalJsonStringify(value) {
  return JSON.stringify(canonicalizeJsonValue(normalizeInstructionJsonValue(cloneJson(value))));
}

function canonicalizeJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeJsonValue);
  }
  if (isPlainObject(value)) {
    const out = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeJsonValue(value[key]);
    }
    return out;
  }
  return value;
}

function assertNonEmptyString(value, context) {
  if (typeof value !== JS_TYPE_STRING || value.trim().length === 0) {
    rejectType(`${context}${TEXT_MUST_BE_A}non-empty string`);
  }
  return value.trim();
}

function assertExactNonEmptyString(value, context) {
  if (typeof value !== JS_TYPE_STRING || value.length === 0) {
    rejectType(`${context}${TEXT_MUST_BE_A}non-empty string`);
  }
  return value;
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function tryDecodeBase64(value) {
  if (!value) {
    return null;
  }
  const compact = value.replace(/\s+/g, "");
  if (compact.length === 0 || compact.length % 4 !== 0) {
    return null;
  }
  const paddingIndex = compact.indexOf("=");
  if (paddingIndex !== -1) {
    const head = compact.slice(0, paddingIndex);
    const padding = compact.slice(paddingIndex);
    if (!/^[0-9A-Za-z+/]*$/.test(head) || !/^={1,2}$/.test(padding)) {
      return null;
    }
  } else if (!/^[0-9A-Za-z+/]+$/.test(compact)) {
    return null;
  }
  try {
    const decoded = Buffer.from(compact, BASE64_ENCODING);
    if (decoded.length === 0) {
      return null;
    }
    if (decoded.toString(BASE64_ENCODING) !== compact) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export {
  TEXT_MUST_BE_AN_OBJECT_2,
  TEXT_MUST_CONTAIN,
  TEXT_MUST_BE,
  TEXT_EXCEEDS_THE,
  TEXT_IROHA_DATA_MODEL,
  TEXT_UNSUPPORTED,
  TEXT_MUST_BE_AN_OBJECT,
  TEXT_USES_UNSUPPORTED,
  TEXT_MUST_CONTAIN_EXACTLY,
  TEXT_MUST_BE_EXACT_STANDARD_BASE64,
  TEXT_MUST_BE_A,
  TEXT_MUST_NOT_CONTAIN,
  TEXT_VARINT_EXCEEDS_AN_UNSIGNED_64_BIT_INTEGER,
  TEXT_EXCEEDS_JAVA_SCRIPT_S_SAFE_INTEGER_RANGE,
  TEXT_MUST_FIT_IN_AN_UNSIGNED_64_BIT_INTEGER,
  COMPACT_LEN_FLAG,
  NORITO_FRAME_HEADER_LENGTH,
  NORITO_MAX_HEADER_PADDING,
  NORITO_SUPPORTED_HEADER_FLAGS,
  UINT64_MASK,
  EVENT_FILTER_BOX_SCHEMA_HASH,
  noritoLengthFlags,
  BufferReader,
  cloneJson,
  normalizeInstructionJsonValue,
  isPublicPlainBallotInstruction,
  parseRegisterDataspaceAssetDefinitionJson,
  validateInstructionObjectNumbers,
  toBuffer,
  encodeStructValue,
  decodeStructFields,
  encodeTupleValue,
  decodeTupleFields,
  encodeOptionValue,
  decodeOptionValue,
  encodeBoolValue,
  decodeBoolValue,
  normalizeFlexibleBytes,
  encodeNameValue,
  decodeNameValue,
  encodeMetadataValue,
  decodeMetadataValue,
  encodeAccountIdValue,
  decodeAccountIdValue,
  encodePublicKeyValue,
  decodePublicKeyValue,
  encodeConstVecU8Value,
  decodeConstVecU8Value,
  algorithmTagForCurveId,
  curveIdForAlgorithmTag,
  encodeMultisigPolicyPayload,
  decodeMultisigPolicyPayload,
  encodeMultisigMemberPayload,
  decodeMultisigMemberPayload,
  encodeEnumTagValue,
  encodeEventFilterBoxFramePayload,
  decodeEventFilterBoxFramePayload,
  decodeExactStandardBase64,
  assertOnlyObjectKeys,
  encodeU8Value,
  decodeU8Value,
  encodeU16Value,
  decodeU16Value,
  encodeU32Value,
  decodeU32Value,
  encodeNoritoStringValue,
  decodeStringValue,
  encodeNoritoJsonValue,
  decodeJsonValue,
  readNoritoField,
  encodeNoritoField,
  encodeNoritoVec,
  withNoritoCompactLengths,
  withNoritoLengthFlags,
  encodeNoritoLength,
  decodeNoritoVec,
  schemaHashForTypeName,
  decodeNoritoFrame,
  frameNoritoPayload,
  u16ToLittleEndianBuffer,
  u32ToLittleEndianBuffer,
  u64ToLittleEndianBuffer,
  normalizeU64Input,
  bigintToSafeNumber,
  encodeUnsignedLeb128,
  decodeUnsignedLeb128,
  canonicalJsonStringify,
  canonicalizeJsonValue,
  assertNonEmptyString,
  assertExactNonEmptyString,
  isPlainObject,
  tryDecodeBase64,
};
