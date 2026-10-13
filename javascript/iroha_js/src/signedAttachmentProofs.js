/** Canonical proof-carrier metadata checks. These do not verify proofs or admit transactions. */
import { Buffer } from "buffer";
import { blake3 } from "@noble/hashes/blake3";
import { blake2b } from "@noble/hashes/blake2b";
import {
  BufferReader, decodeNoritoVec, decodeStructFields, decodeU32Value,
  encodeNoritoField, encodeNoritoVec, frameNoritoPayload, readNoritoField,
  schemaHashForTypeName, u32ToLittleEndianBuffer, u64ToLittleEndianBuffer,
  validateNoritoFrame, withNoritoCompactLengths,
} from "./noritoValueCodecs.js";
import {
  SIGNED_ATTACHMENT_LIMITS_V1, actionStatementDigestV1,
  decodeSignedAttachmentsV1, encodeSignedAttachmentsV1,
} from "./signedAttachments.js";

const SCHEMA = "iroha_data_model::proof::ProofAttachment";
const DOMAIN = "iroha.transaction.proof-carrier-public-inputs-digest.v1";
const MAX_FRAME = SIGNED_ATTACHMENT_LIMITS_V1.maxOccurrenceBytes;
const MAX_DEPTH = 255;
const FIELDS = ["backend", "proofBytes", "verifyingKey", "verifyingKeyCommitment", "envelopeHash", "lanePrivacy"];
const struct = (values) => Buffer.concat(values.map(encodeNoritoField));
function requireValue(condition, message) {
  if (!condition) throw new TypeError(`proof carrier: ${message}`);
}
function exactObject(value, keys, name) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value), `${name} must be an object`);
  requireValue(Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)), `${name} has noncanonical fields`);
}
function bytes(value, max, name) {
  requireValue(value instanceof Uint8Array && value.byteLength <= max, `${name} exceeds its byte bound or is not Uint8Array`);
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}
function fixed(value, name) {
  const result = bytes(value, 32, name);
  requireValue(result.length === 32, `${name} must contain 32 bytes`);
  return result;
}
function identifier(value) {
  requireValue(typeof value === "string" && value.length <= 256 && /^[a-z0-9](?:[a-z0-9_/:.-]*[a-z0-9])?$/u.test(value)
    && !["..", "//", ":::", "/:", ":/", "/.", "./", ":.", ".:"].some((part) => value.includes(part)), "identifier must use bounded portable registry syntax");
  return value;
}
function encodeString(value) { return encodeNoritoField(Buffer.from(identifier(value), "ascii")); }
function decodeString(payload) {
  const reader = new BufferReader(payload, "proof identifier");
  const value = readNoritoField(reader, "utf8"); reader.assertEof();
  requireValue(value.length <= 256 && value.every((b) => b < 128), "identifier must use bounded portable registry syntax");
  return identifier(value.toString("ascii"));
}
function u32(value, name) {
  requireValue(Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff, `${name} must be u32`);
  return u32ToLittleEndianBuffer(value);
}
function option(value, encode) {
  return value === null ? Buffer.of(0) : Buffer.concat([Buffer.of(1), encodeNoritoField(encode(value))]);
}
function readOption(payload, decode) {
  const reader = new BufferReader(payload, "proof option");
  const tag = reader.readU8("tag");
  requireValue(tag === 0 || tag === 1, "unknown option tag");
  const value = tag === 0 ? null : decode(readNoritoField(reader, "value"));
  reader.assertEof(); return value;
}
// Norito's ordinary fixed array is 32 individually delimited bytes. The lane
// leaf instead uses the schema's fixed_bytes annotation and stays raw32.
function encodeHash(value) { return struct([...fixed(value, "hash")].map((byte) => Buffer.of(byte))); }
function decodeHash(payload) {
  const reader = new BufferReader(payload, "fixed hash");
  const result = Buffer.alloc(32);
  for (let i = 0; i < 32; i += 1) {
    const item = readNoritoField(reader, `byte${i}`);
    requireValue(item.length === 1, "hash element must contain one byte"); result[i] = item[0];
  }
  reader.assertEof(); return result;
}
function validateLane(value) {
  exactObject(value, ["commitmentId", "leaf", "leafIndex", "auditPath"], "lane privacy");
  requireValue(Number.isInteger(value.commitmentId) && value.commitmentId >= 0 && value.commitmentId <= 65535, "commitment ID must be u16");
  fixed(value.leaf, "lane leaf"); u32(value.leafIndex, "leaf index");
  requireValue(Array.isArray(value.auditPath) && value.auditPath.length >= 1 && value.auditPath.length <= MAX_DEPTH, "lane path depth must be 1..255");
  requireValue(value.auditPath.length >= 32 || BigInt(value.leafIndex) < (1n << BigInt(value.auditPath.length)), "lane leaf index is out of range");
  for (const sibling of value.auditPath) requireValue((fixed(sibling, "lane sibling")[31] & 1) === 1, "lane sibling lacks canonical prehashed marker");
}
function encodeLane(value) {
  validateLane(value);
  const commitment = Buffer.alloc(2); commitment.writeUInt16LE(value.commitmentId);
  const path = encodeNoritoVec(value.auditPath, (sibling) => option(sibling, (value) => fixed(value, "lane sibling")));
  const merkle = struct([fixed(value.leaf, "lane leaf"), struct([u32(value.leafIndex), path])]);
  return struct([encodeNoritoField(commitment), Buffer.concat([u32(0), encodeNoritoField(merkle)])]);
}
function decodeLane(payload) {
  const f = decodeStructFields(payload, "lane privacy", ["commitment", "witness"]);
  const id = decodeStructFields(f.commitment, "commitment ID", ["value"]).value;
  requireValue(id.length === 2, "commitment ID must contain two bytes");
  const witness = new BufferReader(f.witness, "lane witness");
  requireValue(witness.readU32LE("tag") === 0, "unknown lane witness tag");
  const merkle = decodeStructFields(readNoritoField(witness, "merkle"), "merkle witness", ["leaf", "proof"]);
  witness.assertEof();
  const proof = decodeStructFields(merkle.proof, "merkle proof", ["index", "path"]);
  const value = { commitmentId: id.readUInt16LE(), leaf: Uint8Array.from(fixed(merkle.leaf, "lane leaf")),
    leafIndex: decodeU32Value(proof.index, "leaf index"),
    auditPath: decodeNoritoVec(proof.path, (item) => {
      const sibling = readOption(item, (value) => Buffer.from(fixed(value, "lane sibling")));
      requireValue(sibling !== null, "lane sibling must be present"); return Uint8Array.from(sibling);
    }, "lane audit path", MAX_DEPTH) };
  validateLane(value); return value;
}
function validateMetadata(value) {
  exactObject(value, FIELDS, "attachment"); identifier(value.backend);
  exactObject(value.verifyingKey, ["backend", "name"], "verifier key");
  identifier(value.verifyingKey.backend); identifier(value.verifyingKey.name);
  requireValue(value.verifyingKey.backend === value.backend, "verifier backend mismatch");
  const proof = bytes(value.proofBytes, MAX_FRAME, "proof");
  if (value.verifyingKeyCommitment !== null) requireValue(fixed(value.verifyingKeyCommitment, "commitment").some(Boolean), "commitment must be nonzero");
  // Generated proof/envelope values are not part of proof-free metadata. Keep
  // their type/size shape, but allow an empty proof and an unbound envelope so
  // planning never needs fabricated proof bytes.
  if (value.envelopeHash !== null) fixed(value.envelopeHash, "envelope hash");
  if (value.lanePrivacy !== null) validateLane(value.lanePrivacy);
  return proof;
}
function validate(value) {
  const proof = validateMetadata(value);
  requireValue(proof.length > 0, "proof bytes must be nonempty");
  if (value.envelopeHash !== null) {
    const expected = Buffer.from(blake2b(proof, { dkLen: 32 })); expected[31] |= 1;
    requireValue(expected.equals(fixed(value.envelopeHash, "envelope hash")), "envelope hash must match proof bytes");
  }
}
function payload(value, normalized) {
  const proof = normalized ? Buffer.alloc(0) : bytes(value.proofBytes, MAX_FRAME, "proof");
  const envelope = normalized ? null : value.envelopeHash;
  const fields = [encodeString(value.backend), struct([encodeString(value.backend), Buffer.concat([u64ToLittleEndianBuffer(proof.length), proof])]),
    struct([encodeString(value.verifyingKey.backend), encodeString(value.verifyingKey.name)])];
  if (value.verifyingKeyCommitment !== null || envelope !== null || value.lanePrivacy !== null) fields.push(option(value.verifyingKeyCommitment, encodeHash));
  if (envelope !== null || value.lanePrivacy !== null) fields.push(option(envelope, encodeHash));
  if (value.lanePrivacy !== null) fields.push(option(value.lanePrivacy, encodeLane));
  return struct(fields);
}
function frame(payload) { return frameNoritoPayload(payload, schemaHashForTypeName(SCHEMA), 2); }

/** Encode a complete canonical ProofAttachment within the signed occurrence's 9 MiB bound. */
export function encodeProofCarrierV1(value) {
  return withNoritoCompactLengths(() => {
    validate(value); const result = frame(payload(value, false));
    requireValue(result.length <= MAX_FRAME, "complete carrier exceeds signed occurrence bound");
    return Uint8Array.from(result);
  });
}

/** Decode one complete canonical carrier and check its actual structural metadata. No proof verification. */
export function decodeProofCarrierV1(encoded) {
  return withNoritoCompactLengths(() => {
    const input = bytes(encoded, MAX_FRAME, "frame");
    const decoded = validateNoritoFrame(input, { expectedTypeName: SCHEMA, expectedPaddingLength: 0 });
    requireValue(decoded.flags === 2, "frame must use canonical compact lengths");
    const reader = new BufferReader(decoded.payload, "proof attachment");
    const backend = decodeString(readNoritoField(reader, "backend"));
    const box = decodeStructFields(readNoritoField(reader, "proof"), "proof box", ["backend", "bytes"]);
    requireValue(decodeString(box.backend) === backend, "proof backend mismatch");
    const proof = new BufferReader(box.bytes, "proof bytes");
    const count = proof.readU64LE("count");
    requireValue(count > 0n && count <= BigInt(MAX_FRAME), "proof bytes count exceeds bound or is empty");
    const proofBytes = Uint8Array.from(proof.readBytes(Number(count), "bytes")); proof.assertEof();
    const key = decodeStructFields(readNoritoField(reader, "key"), "verifier key", ["backend", "name"]);
    const value = { backend, proofBytes, verifyingKey: { backend: decodeString(key.backend), name: decodeString(key.name) },
      verifyingKeyCommitment: null, envelopeHash: null, lanePrivacy: null };
    if (reader.offset < reader.buffer.length) value.verifyingKeyCommitment = readOption(readNoritoField(reader, "commitment"), decodeHash);
    if (reader.offset < reader.buffer.length) value.envelopeHash = readOption(readNoritoField(reader, "envelope hash"), decodeHash);
    if (reader.offset < reader.buffer.length) value.lanePrivacy = readOption(readNoritoField(reader, "lane"), decodeLane);
    reader.assertEof(); validate(value);
    requireValue(payload(value, false).equals(decoded.payload), "noncanonical carrier or redundant optional tail");
    return value;
  });
}

/** Exact proof-free carrier metadata digest, preserving verifier commitment and lane witness.
 * Accepts an empty generated proof and discards the generated envelope hash, so
 * callers can derive the statement before proving. Retained metadata stays validated.
 * This is not completed-carrier admission; encode/decode/inspection require a real nonempty proof.
 */
export function proofCarrierPublicInputsDigestV1(value) {
  return withNoritoCompactLengths(() => {
    validateMetadata(value); const encoded = frame(payload(value, true));
    return Uint8Array.from(blake3(Buffer.concat([Buffer.from(DOMAIN, "ascii"), u64ToLittleEndianBuffer(encoded.length), encoded])));
  });
}

/** Check every actual carrier and statement against a caller-supplied intent digest.
 * This is a binding layer, not transaction admission: the caller must derive that
 * digest from canonical payload/executable/privacy normalization and separately
 * validate registered native operations and executable invocation targets.
 * TODO: Integrate only after the complete canonical transaction context is available.
 * Returns independent decoded proof carriers in action order; native action bytes are not interpreted here.
 */
export function inspectSignedAttachmentProofBindingsV1(descriptor, orderedIntentDigest) {
  const intent = fixed(orderedIntentDigest, "ordered intent digest");
  const value = decodeSignedAttachmentsV1(encodeSignedAttachmentsV1(descriptor));
  const result = [];
  for (const action of value.actions) {
    if (action.operation.type !== "NativeInstruction") {
      const reference = action.attachments[0];
      const carrier = decodeProofCarrierV1(value.occurrences[reference.index].bytes);
      requireValue((reference.role === "LanePrivacyProof") === (carrier.lanePrivacy !== null), "carrier role and lane witness mismatch");
      requireValue(Buffer.from(proofCarrierPublicInputsDigestV1(carrier)).equals(Buffer.from(action.publicInputsDigest)), "carrier public inputs mismatch");
      result.push({ actionIndex: action.actionIndex, attachment: carrier });
    }
    requireValue(Buffer.from(actionStatementDigestV1(action, intent)).equals(Buffer.from(action.statementDigest)), "statement digest mismatch");
  }
  return result;
}
