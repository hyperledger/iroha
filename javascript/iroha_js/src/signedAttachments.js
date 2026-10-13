/** Canonical bounded signed attachment descriptors, separate from transaction admission. */
import { Buffer } from "buffer";
import { blake3 } from "@noble/hashes/blake3";
import {
  BufferReader, decodeAccountIdValue, encodeAccountIdValue,
  decodeExactStandardBase64, decodeNoritoVec, decodeStructFields, decodeU32Value,
  encodeNoritoField, encodeNoritoVec, encodeUnsignedLeb128, frameNoritoPayload,
  readNoritoField, schemaHashForTypeName, u32ToLittleEndianBuffer,
  u64ToLittleEndianBuffer, validateNoritoFrame, withNoritoCompactLengths,
} from "./noritoValueCodecs.js";

const SCHEMA = "iroha_data_model::transaction::signed_attachments::SignedAttachmentsV1";
const STATEMENT_SCHEMA = "iroha_data_model::transaction::signed_attachments::ActionStatementV1";
const STATEMENT_DOMAIN = "iroha.transaction.action-statement-digest.v1";
const KINDS = ["Proof", "KeyMaterial"];
const ROLES = ["ActionProof", "VerifyingKey", "LanePrivacyProof", "ExecutionProof"];
const ACTION_ROLES = ["ProofEffect", "ProofVerification", "Administrative", "Effect"];
const ZERO = Buffer.alloc(32);
const ACTION_FIELDS = ["actionIndex", "operation", "role", "authority", "invocation", "publicInputsDigest", "statementDigest", "attachments"];
const REFERENCE_FIELDS = ["index", "kind", "role", "length", "contentHash"];
const OCCURRENCE_FIELDS = ["index", "kind", "length", "contentHash", "bytes"];

/** Independent cardinality and total-frame limits; sixteen maximum-size occurrences cannot fit. */
export const SIGNED_ATTACHMENT_LIMITS_V1 = Object.freeze({
  maxActions: 16, maxOccurrences: 16, maxOccurrenceBytes: 9 * 1024 * 1024,
  maxFrameBytes: 9 * 1024 * 1024 + 64 * 1024, maxCallPath: 32, maxWireIdBytes: 128,
});

function requireValue(condition, message) {
  if (!condition) throw new TypeError(`signed attachments: ${message}`);
}
function object(value, keys, name) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value), `${name} must be an object`);
  requireValue(Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)), `${name} has noncanonical fields`);
  return value;
}
function bytes(value, maximum, name) {
  requireValue(value instanceof Uint8Array, `${name} must be Uint8Array`);
  requireValue(value.byteLength <= maximum, `${name} exceeds its byte bound`);
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}
function digest(value, name) {
  const result = bytes(value, 32, name);
  requireValue(result.length === 32, `${name} must contain 32 bytes`);
  return result;
}
function u32(value, name) {
  requireValue(Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff, `${name} must be u32`);
  return u32ToLittleEndianBuffer(value);
}
function boundedLength(value) {
  requireValue(Number.isSafeInteger(value) && value >= 0 && value <= SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes, "occurrence length exceeds its bound");
  return u64ToLittleEndianBuffer(value);
}
function list(value, maximum, name) {
  requireValue(Array.isArray(value) && value.length <= maximum, `${name} exceeds its count bound`);
  return value;
}
function tag(value, variants) {
  const index = variants.indexOf(value);
  requireValue(index >= 0, "unknown enum variant");
  return u32ToLittleEndianBuffer(index);
}
function struct(values) { return Buffer.concat(values.map(encodeNoritoField)); }
function digestValue(value) { return encodeNoritoField(digest(value, "digest")); }
function readTag(payload, variants) {
  const value = variants[decodeU32Value(payload, "enum tag")];
  requireValue(value !== undefined, "unknown enum tag");
  return value;
}
function readDigest(payload) {
  const fields = decodeStructFields(payload, "digest", ["bytes"]);
  return Buffer.from(digest(fields.bytes, "digest"));
}
function readLength(payload) {
  requireValue(payload.length === 8, "length requires eight bytes");
  const value = payload.readBigUInt64LE();
  requireValue(value <= BigInt(SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes), "occurrence length exceeds its bound");
  return Number(value);
}
function encodeOperation(value) {
  if (value.type === "NativeInstruction") {
    object(value, ["type", "wireId"], "operation");
    requireValue(typeof value.wireId === "string" && /^[!-~]{1,128}$/u.test(value.wireId), "operation wire ID must be bounded graphic ASCII");
    return Buffer.concat([u32(0), encodeNoritoField(encodeNoritoField(Buffer.from(value.wireId, "ascii")))]);
  }
  object(value, ["type"], "operation");
  return tag(value.type, ["NativeInstruction", "TransactionProof", "IvmProvedExecution"]);
}
function decodeOperation(payload) {
  const reader = new BufferReader(payload, "operation");
  const index = reader.readU32LE("tag");
  let result;
  if (index === 0) {
    const field = readNoritoField(reader, "wireId");
    requireValue(field.length <= 130, "operation wire ID exceeds its bound");
    const child = new BufferReader(field, "wireId");
    const wire = readNoritoField(child, "value");
    requireValue(wire.length >= 1 && wire.length <= 128 && wire.every((byte) => byte >= 33 && byte <= 126), "operation wire ID must be bounded graphic ASCII");
    child.assertEof();
    result = { type: "NativeInstruction", wireId: wire.toString("ascii") };
  } else {
    requireValue(index === 1 || index === 2, "unknown operation tag");
    result = { type: index === 1 ? "TransactionProof" : "IvmProvedExecution" };
  }
  reader.assertEof();
  return result;
}
function encodeAuthority(value) {
  if (value.type === "TransactionAuthority") {
    object(value, ["type"], "authority"); return u32(0);
  }
  object(value, ["type", "accountId"], "authority");
  requireValue(value.type === "ContractSubject" || value.type === "Account", "unknown authority");
  return Buffer.concat([u32(value.type === "ContractSubject" ? 1 : 2), encodeNoritoField(encodeAccountIdValue(value.accountId, "action authority"))]);
}
function decodeAuthority(payload) {
  const reader = new BufferReader(payload, "authority");
  const index = reader.readU32LE("tag");
  requireValue(index <= 2, "unknown authority tag");
  const value = index === 0 ? { type: "TransactionAuthority" } : {
    type: index === 1 ? "ContractSubject" : "Account",
    accountId: decodeAccountIdValue(readNoritoField(reader, "account"), "action authority"),
  };
  reader.assertEof(); return value;
}
function encodeInvocation(value) {
  if (value.type === "Transaction") { object(value, ["type"], "invocation"); return u32(0); }
  if (value.type === "Direct") {
    object(value, ["type", "instructionIndex"], "invocation");
    return Buffer.concat([u32(1), encodeNoritoField(u32(value.instructionIndex, "instruction index"))]);
  }
  object(value, ["type", "rootIndex", "callPath"], "invocation");
  requireValue(value.type === "Contract", "unknown invocation");
  list(value.callPath, 32, "call path");
  return Buffer.concat([u32(2), struct([u32(value.rootIndex, "root index"), encodeNoritoVec(value.callPath, (index) => u32(index, "call path index"))])]);
}
function decodeInvocation(payload) {
  const reader = new BufferReader(payload, "invocation");
  const index = reader.readU32LE("tag");
  requireValue(index <= 2, "unknown invocation tag");
  let result = { type: "Transaction" };
  if (index === 1) result = { type: "Direct", instructionIndex: decodeU32Value(readNoritoField(reader, "instructionIndex"), "instruction index") };
  if (index === 2) result = {
    type: "Contract", rootIndex: decodeU32Value(readNoritoField(reader, "rootIndex"), "root index"),
    callPath: decodeNoritoVec(readNoritoField(reader, "callPath"), (item) => decodeU32Value(item, "call path index"), "call path", 32),
  };
  reader.assertEof(); return result;
}
function actionHeader(action) {
  object(action, ACTION_FIELDS, "action");
  return [u32(action.actionIndex, "action index"), encodeOperation(action.operation), tag(action.role, ACTION_ROLES),
    encodeAuthority(action.authority), encodeInvocation(action.invocation), digestValue(action.publicInputsDigest)];
}
function encodeReference(reference, normalized) {
  object(reference, REFERENCE_FIELDS, "reference");
  const generated = normalized && reference.kind === "Proof";
  return struct([u32(reference.index, "reference index"), tag(reference.kind, KINDS), tag(reference.role, ROLES),
    boundedLength(generated ? 0 : reference.length), digestValue(generated ? ZERO : reference.contentHash)]);
}
function encodeAction(action, normalized) {
  list(action.attachments, 16, "references");
  return struct([...actionHeader(action), digestValue(normalized ? ZERO : action.statementDigest),
    encodeNoritoVec(action.attachments, (reference) => encodeReference(reference, normalized))]);
}
function decodeReference(payload) {
  const f = decodeStructFields(payload, "reference", REFERENCE_FIELDS);
  return { index: decodeU32Value(f.index, "index"), kind: readTag(f.kind, KINDS), role: readTag(f.role, ROLES), length: readLength(f.length), contentHash: readDigest(f.contentHash) };
}
function decodeAction(payload) {
  const f = decodeStructFields(payload, "action", ACTION_FIELDS);
  return { actionIndex: decodeU32Value(f.actionIndex, "action index"), operation: decodeOperation(f.operation),
    role: readTag(f.role, ACTION_ROLES), authority: decodeAuthority(f.authority), invocation: decodeInvocation(f.invocation),
    publicInputsDigest: readDigest(f.publicInputsDigest), statementDigest: readDigest(f.statementDigest),
    attachments: decodeNoritoVec(f.attachments, decodeReference, "references", 16) };
}
function decodeOccurrence(payload) {
  const f = decodeStructFields(payload, "occurrence", OCCURRENCE_FIELDS);
  const reader = new BufferReader(f.bytes, "occurrence bytes");
  const count = reader.readU64LE("count");
  requireValue(count <= BigInt(SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes), "occurrence bytes exceed their bound");
  const value = reader.readBytes(Number(count), "bytes"); reader.assertEof();
  return { index: decodeU32Value(f.index, "index"), kind: readTag(f.kind, KINDS), length: readLength(f.length), contentHash: readDigest(f.contentHash), bytes: value };
}

function validateStructure(value) {
  object(value, ["actions", "occurrences"], "descriptor");
  list(value.actions, 16, "actions"); list(value.occurrences, 16, "occurrences");
  requireValue(value.actions.length > 0, "descriptor has no actions");
  // Reject aggregate bytes before hashing or copying any occurrence.
  let total = 40;
  for (const occurrence of value.occurrences) {
    object(occurrence, OCCURRENCE_FIELDS, "occurrence");
    total += bytes(occurrence.bytes, SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes, "occurrence").length;
  }
  requireValue(total <= SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes, "aggregate frame exceeds its bound");
  const hashes = new Set();
  value.occurrences.forEach((occurrence, position) => {
    requireValue(occurrence.index === position, "occurrence index is out of order");
    tag(occurrence.kind, KINDS); boundedLength(occurrence.length);
    const data = bytes(occurrence.bytes, SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes, "occurrence");
    requireValue(data.length > 0 && occurrence.length === data.length, "occurrence length mismatch");
    requireValue(digest(occurrence.contentHash, "content hash").equals(Buffer.from(blake3(data))), "occurrence content hash mismatch");
    if (occurrence.kind === "Proof") {
      const hash = digest(occurrence.contentHash).toString("hex");
      requireValue(!hashes.has(hash), "duplicate proof content"); hashes.add(hash);
    }
  });
  let next = 0;
  value.actions.forEach((action, position) => {
    actionHeader(action); list(action.attachments, 16, "references");
    requireValue(action.actionIndex === position, "action index is out of order");
    requireValue(digest(action.publicInputsDigest).some(Boolean) && digest(action.statementDigest).some(Boolean), "zero derived digest");
    for (const reference of action.attachments) {
      encodeReference(reference, false);
      requireValue(reference.index === next, "reference index is duplicated or out of order");
      const occurrence = value.occurrences[next++];
      requireValue(occurrence !== undefined, "missing occurrence");
      requireValue(reference.kind === occurrence.kind && ((reference.role === "VerifyingKey") === (reference.kind === "KeyMaterial")), "reference kind or role mismatch");
      requireValue(reference.length === occurrence.length && digest(reference.contentHash).equals(digest(occurrence.contentHash)), "reference length or content hash mismatch");
    }
    if (action.operation.type === "NativeInstruction") {
      const authority = action.authority.type, invocation = action.invocation.type;
      requireValue((invocation === "Direct" && (authority === "TransactionAuthority" || authority === "Account")) ||
        (invocation === "Contract" && (authority === "ContractSubject" || authority === "Account")), "native authority or invocation mismatch");
      requireValue(action.attachments.every((r) => r.role === "ActionProof" || r.role === "VerifyingKey"), "native attachment role mismatch");
    } else {
      const execution = action.operation.type === "IvmProvedExecution";
      requireValue(action.role === (execution ? "ProofEffect" : "ProofVerification") && action.authority.type === "TransactionAuthority" && action.invocation.type === "Transaction", "carrier action binding mismatch");
      requireValue(action.attachments.length === 1 && (execution ? action.attachments[0].role === "ExecutionProof" : ["ActionProof", "LanePrivacyProof"].includes(action.attachments[0].role)), "carrier attachment role mismatch");
    }
  });
  requireValue(next === value.occurrences.length, "unused occurrence");
}

function encodePayload(value, normalized) {
  const actions = encodeNoritoVec(value.actions, (action) => encodeAction(action, normalized));
  const heads = value.occurrences.map((o) => struct([u32(o.index), tag(o.kind, KINDS),
    boundedLength(normalized && o.kind === "Proof" ? 0 : o.length), digestValue(normalized && o.kind === "Proof" ? ZERO : o.contentHash)]));
  const fieldSize = (length) => encodeUnsignedLeb128(length).length + length;
  let occurrencesSize = 8;
  value.occurrences.forEach((o, i) => { occurrencesSize += fieldSize(heads[i].length + fieldSize(8 + (normalized ? 0 : o.bytes.byteLength))); });
  requireValue(40 + fieldSize(actions.length) + fieldSize(occurrencesSize) <= SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes, "aggregate frame exceeds its bound");
  // Only after exact total framing is admitted do we concatenate large inline bytes.
  const occurrences = encodeNoritoVec(value.occurrences, (o, i) => {
    const content = normalized ? Buffer.alloc(0) : bytes(o.bytes, SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes, "occurrence");
    return Buffer.concat([heads[i], encodeNoritoField(Buffer.concat([u64ToLittleEndianBuffer(content.length), content]))]);
  });
  return struct([actions, occurrences]);
}

/** Encode the descriptor's canonical frame after structural validation; does not admit a transaction or verify proofs. */
export function encodeSignedAttachmentsV1(value) {
  return withNoritoCompactLengths(() => {
    validateStructure(value);
    return Uint8Array.from(frameNoritoPayload(encodePayload(value, false), schemaHashForTypeName(SCHEMA), 2));
  });
}

/** Decode an exact bounded canonical descriptor. Returned bytes are independent copies.
 * TODO: Transaction admission also requires carrier decoding, registered operation and invocation checks,
 * recomputed public-input/statement bindings and canonical executable/privacy normalization.
 */
export function decodeSignedAttachmentsV1(encoded) {
  const input = bytes(encoded, SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes, "frame");
  return withNoritoCompactLengths(() => {
    const frame = validateNoritoFrame(input, { expectedTypeName: SCHEMA, expectedPaddingLength: 0 });
    requireValue(frame.flags === 2, "frame must use canonical compact lengths");
    const fields = decodeStructFields(frame.payload, "descriptor", ["actions", "occurrences"]);
    // Inspect both counts before visiting an action or allocating an occurrence.
    for (const [name, minimum] of [["actions", 1], ["occurrences", 0]]) {
      requireValue(fields[name].length >= 8, "truncated sequence count");
      const count = fields[name].readBigUInt64LE();
      requireValue(count >= BigInt(minimum) && count <= 16n, `${name} exceeds its count bound`);
    }
    const value = { actions: decodeNoritoVec(fields.actions, decodeAction, "actions", 16),
      occurrences: decodeNoritoVec(fields.occurrences, decodeOccurrence, "occurrences", 16) };
    validateStructure(value);
    requireValue(encodePayload(value, false).equals(frame.payload), "descriptor is not canonically encoded");
    value.occurrences.forEach((o) => { o.bytes = Uint8Array.from(o.bytes); });
    return value;
  });
}

/** Canonical JSON value: padded standard base64 of the complete uncompressed descriptor frame. */
export function signedAttachmentsToJsonV1(value) { return Buffer.from(encodeSignedAttachmentsV1(value)).toString("base64"); }
/** Decode the canonical JSON string value, bounding text before base64 allocation. */
export function signedAttachmentsFromJsonV1(value) {
  requireValue(typeof value === "string" && value.length <= 4 * Math.ceil(SIGNED_ATTACHMENT_LIMITS_V1.maxFrameBytes / 3), "JSON frame exceeds its bound");
  return decodeSignedAttachmentsV1(decodeExactStandardBase64(value, "signed attachments"));
}

/** Compute the exact statement digest from a caller-supplied ordered intent; does not verify that intent or any proof. */
export function actionStatementDigestV1(action, orderedIntentDigest) {
  return withNoritoCompactLengths(() => {
    const payload = struct([digestValue(orderedIntentDigest), ...actionHeader(action)]);
    const frame = frameNoritoPayload(payload, schemaHashForTypeName(STATEMENT_SCHEMA), 2);
    return Uint8Array.from(blake3(Buffer.concat([Buffer.from(STATEMENT_DOMAIN, "ascii"), u64ToLittleEndianBuffer(frame.length), frame])));
  });
}

/** Proof-free descriptor projection for hashing only. It is deliberately not an admissible descriptor. */
export function signedAttachmentsIntentProjectionV1(value) {
  return withNoritoCompactLengths(() => {
    validateStructure(value);
    return Uint8Array.from(frameNoritoPayload(encodePayload(value, true), schemaHashForTypeName(SCHEMA), 2));
  });
}
