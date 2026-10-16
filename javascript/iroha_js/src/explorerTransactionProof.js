import { Buffer } from "buffer";
import { computeHashLiteralCrc } from "./hashLiteralCrc.js";
import { NetworkId } from "./networkId.js";
import { parseStrictLosslessJson } from "./strictLosslessJson.js";

export const EXPLORER_TRANSACTION_PROOF_MAX_BYTES = 16 * 1024 * 1024;
export const EXPLORER_TRANSACTION_PROOF_FLOAT_PATHS = Object.freeze([
  Object.freeze(["transaction", "entrypoint"]),
  Object.freeze(["transaction", "output"]),
]);

const CONTEXT = "explorer transaction proof response";
const MAX_U64 = (1n << 64n) - 1n;
const HEADER_HASH_FIELDS = Object.freeze([
  "prev_block_hash", "merkle_root", "da_proof_policies_hash", "da_commitments_hash",
  "da_pin_intents_hash", "npos_effects_hash", "execution_context_hash",
  "global_beacon_pulse_hash",
]);

function record(value, fields, context) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${context} must be an object`);
  }
  if (fields && (Object.keys(value).length !== fields.length
      || fields.some((field) => !Object.hasOwn(value, field)))) {
    throw new TypeError(`${context} must contain exactly ${fields.join(", ")}`);
  }
  return value;
}

/** Validate the current checksummed marked hash literal without changing its identity. */
export function explorerTransactionProofHash(value, context = "transaction hash") {
  const match = typeof value === "string"
    ? /^hash:([0-9A-F]{64})#([0-9A-F]{4})$/u.exec(value) : null;
  if (!match || computeHashLiteralCrc("hash", match[1]) !== match[2]
      || (Number.parseInt(match[1].slice(-2), 16) & 1) !== 1) {
    throw new TypeError(`${context} must be a canonical checksummed marked hash literal`);
  }
  return value;
}

function unsigned(value, context, maximum, positive = false) {
  if (!(typeof value === "bigint" || (typeof value === "number"
      && Number.isSafeInteger(value) && !Object.is(value, -0)))) {
    throw new TypeError(`${context} must be an exact unsigned integer token`);
  }
  const integer = BigInt(value);
  if (integer < (positive ? 1n : 0n) || integer > maximum) {
    throw new RangeError(`${context} is outside its unsigned integer range`);
  }
  return integer;
}

function merkleProof(value, context) {
  const proof = record(value, ["leaf_index", "audit_path"], context);
  const leafIndex = Number(unsigned(proof.leaf_index, `${context}.leaf_index`, 0xffff_ffffn));
  if (!Array.isArray(proof.audit_path) || proof.audit_path.length > 32) {
    throw new TypeError(`${context}.audit_path must contain at most 32 siblings`);
  }
  return Object.freeze({
    leaf_index: leafIndex,
    audit_path: Object.freeze(proof.audit_path.map((hash, index) => hash === null ? null
      : explorerTransactionProofHash(hash, `${context}.audit_path[${index}]`))),
  });
}

function certificateBytes(value, context, maximumBytes) {
  if (typeof value !== "string" || value.length === 0
      || value.length > Math.ceil(maximumBytes / 3) * 4
      || value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/u.test(value)) {
    throw new TypeError(`${context} must be bounded canonical padded base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length > maximumBytes || decoded.toString("base64") !== value) {
    throw new TypeError(`${context} must be canonical padded base64`);
  }
  return value;
}

/** Structural/request binding only: this does not authenticate finality or native proof bytes. */
export function normalizeExplorerTransactionProof(value, expectedHash, expectedNetworkId = null) {
  const proof = record(value, [
    "version", "network_id", "block_height", "block_header", "transaction", "certificate",
  ], CONTEXT);
  if (proof.version !== 1) throw new TypeError(`${CONTEXT}.version must be 1`);
  const networkId = NetworkId.parse(proof.network_id);
  if (expectedNetworkId !== null && !networkId.equals(expectedNetworkId)) {
    throw new TypeError(`${CONTEXT}.network_id does not match the configured network`);
  }
  const blockHeight = unsigned(proof.block_height, `${CONTEXT}.block_height`, MAX_U64, true)
    .toString(10);
  const header = record(proof.block_header, [
    "height", ...HEADER_HASH_FIELDS, "creation_time_ms", "view_change_index", "confidential_features",
  ], `${CONTEXT}.block_header`);
  const normalizedHeader = {
    ...header,
    height: unsigned(header.height, `${CONTEXT}.block_header.height`, MAX_U64, true).toString(10),
    creation_time_ms: unsigned(header.creation_time_ms, `${CONTEXT}.block_header.creation_time_ms`, MAX_U64).toString(10),
    view_change_index: unsigned(header.view_change_index, `${CONTEXT}.block_header.view_change_index`, MAX_U64).toString(10),
  };
  if (normalizedHeader.height !== blockHeight) {
    throw new TypeError(`${CONTEXT}.block_height does not match block_header.height`);
  }
  for (const field of HEADER_HASH_FIELDS) {
    if (header[field] !== null) {
      explorerTransactionProofHash(header[field], `${CONTEXT}.block_header.${field}`);
    }
  }
  if (header.confidential_features !== null) {
    record(header.confidential_features, null, `${CONTEXT}.block_header.confidential_features`);
  }
  const transaction = record(proof.transaction, [
    "block_hash", "entrypoint_hash", "entrypoint_proof", "entrypoint", "output_hash", "output_proof", "output",
  ], `${CONTEXT}.transaction`);
  for (const field of ["block_hash", "entrypoint_hash", "output_hash"]) {
    explorerTransactionProofHash(transaction[field], `${CONTEXT}.transaction.${field}`);
  }
  if (transaction.entrypoint_hash !== expectedHash) {
    throw new TypeError(`${CONTEXT}.transaction.entrypoint_hash does not match the requested transaction`);
  }
  record(transaction.entrypoint, null, `${CONTEXT}.transaction.entrypoint`);
  record(transaction.output, null, `${CONTEXT}.transaction.output`);
  const certificate = record(proof.certificate, [
    "consensus_header", "commit_qc", "result_preimage",
  ], `${CONTEXT}.certificate`);
  return Object.freeze({
    version: 1,
    network_id: proof.network_id,
    block_height: blockHeight,
    block_header: Object.freeze(normalizedHeader),
    transaction: Object.freeze({
      ...transaction,
      entrypoint_proof: merkleProof(transaction.entrypoint_proof, `${CONTEXT}.transaction.entrypoint_proof`),
      output_proof: merkleProof(transaction.output_proof, `${CONTEXT}.transaction.output_proof`),
    }),
    certificate: Object.freeze(Object.fromEntries(Object.entries(certificate).map(([field, bytes]) => [
      field, certificateBytes(bytes, `${CONTEXT}.certificate.${field}`, field === "commit_qc" ? 4096 : 65536),
    ]))),
  });
}

export function decodeExplorerTransactionProof(text, expectedHash, expectedNetworkId = null) {
  return normalizeExplorerTransactionProof(parseStrictLosslessJson(text, CONTEXT, {
    floatingPointPaths: EXPLORER_TRANSACTION_PROOF_FLOAT_PATHS,
  }), expectedHash, expectedNetworkId);
}
