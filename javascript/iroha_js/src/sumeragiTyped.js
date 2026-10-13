import { Buffer } from "buffer";
import { parseStrictLosslessIntegerJson } from "./strictLosslessJson.js";
import { computeHashLiteralCrc } from "./hashLiteralCrc.js";
import { getCurveEntryByPublicKeyMulticodec } from "./curveRegistry.js";
import { AccountAddress } from "./address.js";
import { SUMERAGI_LANES_TYPED_JSON_MAX_BYTES, SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES } from "./sumeragiTypedLimits.js";

export { SUMERAGI_LANES_TYPED_JSON_MAX_BYTES, SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES };
const FIELDS = "protocol_version config_fingerprint beacon_horizon instance height view stage leader proxy_tail high_qc_view level start_level t_retx_ms committed_height applied_height awaiting signer unanchored abstaining halted footprint".split(" ");
const FOOTPRINT = "votes timeouts blocks exec_entries wants pending_apply sync_entries sync_bytes peers recent_headers configs cert_cache evidence_keys probe".split(" ");
const HORIZON = "epoch_length_blocks next_required_pulse_height active_session_id session_covers_next_pulse local_provider_ready".split(" ");
const HEIGHT_REASONS = new Set(["safety_violation", "apply_diverged", "publication_recovery_required"]);
const UNIT_REASONS = new Set(["safety_record_corrupt", "safety_record_inconsistent", "driver_anomaly"]);

function record(value, fields, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) {
    throw new TypeError(`${label} requires exactly its native fields`);
  }
  return value;
}
function uint(value, bits = 64) {
  if ((typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0)) && typeof value !== "bigint") {
    throw new TypeError("native status requires exact unsigned integers");
  }
  const integer = BigInt(value);
  if (integer < 0n || integer >= (1n << BigInt(bits))) throw new RangeError("native status integer exceeds its bound");
  return bits < 64 ? Number(integer) : value;
}
function optionalUint(value) { return value === null ? null : uint(value); }
function bool(value) {
  if (typeof value !== "boolean") throw new TypeError("native status requires booleans");
  return value;
}
function hash(value) {
  if (typeof value !== "string" || !/^hash:[0-9A-F]{64}#[0-9A-F]{4}$/.test(value)) throw new TypeError("native fingerprint must be a canonical hash");
  const body = value.slice(5, 69);
  if ((Number.parseInt(body.slice(-2), 16) & 1) !== 1 || computeHashLiteralCrc("hash", body) !== value.slice(70)) {
    throw new TypeError("native fingerprint marker or checksum is invalid");
  }
  return value;
}
function publicKey(value) {
  if (value === null) return null;
  if (typeof value !== "string" || value.length % 2 || !/^[0-9a-fA-F]+$/.test(value)) throw new TypeError("native status requires canonical public keys");
  const bytes = Buffer.from(value, "hex");
  let cursor = 0;
  function varint() {
    let result = 0n;
    for (let used = 0; used < 10 && cursor < bytes.length; used += 1) {
      const byte = bytes[cursor++];
      if (used === 9 && (byte & 0xfe) !== 0) throw new TypeError("public-key varint overflows");
      result |= BigInt(byte & 0x7f) << BigInt(used * 7);
      if ((byte & 0x80) === 0) {
        if ((used !== 0 && byte === 0) || result > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError("public-key varint is not canonical");
        return Number(result);
      }
    }
    throw new TypeError("public-key varint is truncated");
  }
  const code = varint();
  const length = varint();
  const key = bytes.subarray(cursor);
  const curve = getCurveEntryByPublicKeyMulticodec(code);
  if (!curve || length !== key.length || value !== bytes.subarray(0, cursor).toString("hex") + key.toString("hex").toUpperCase()) throw new TypeError("public key has wrong algorithm, length or canonical spelling");
  // Reuse the SDK's actual controller/public-key admission boundary.
  AccountAddress.fromAccount({ publicKey: key, algorithm: curve.algorithm });
  return value;
}
function horizon(value) {
  if (value === null) return null;
  const r = record(value, HORIZON, "native beacon horizon");
  const session = r.active_session_id;
  if (session !== null && (typeof session !== "string" || !/^[0-9A-F]{64}$/.test(session))) throw new TypeError("native beacon session must be uppercase 32-byte hex");
  const next = optionalUint(r.next_required_pulse_height);
  const covers = bool(r.session_covers_next_pulse);
  const ready = bool(r.local_provider_ready);
  if ((covers && (session === null || next === null)) || (ready && session === null)) throw new TypeError("native beacon readiness requires its exact session and demand");
  return Object.freeze({ epoch_length_blocks: uint(r.epoch_length_blocks), next_required_pulse_height: next, active_session_id: session, session_covers_next_pulse: covers, local_provider_ready: ready });
}
function halt(value) {
  if (value === null) return null;
  const r = record(value, ["reason", "details"], "native halt reason");
  if (HEIGHT_REASONS.has(r.reason)) return Object.freeze({ reason: r.reason, details: uint(r.details) });
  if (UNIT_REASONS.has(r.reason) && r.details === null) return Object.freeze({ reason: r.reason, details: null });
  throw new TypeError("invalid native halt reason or details");
}
/** Validate an immutable protocol-1 observation, never a finality proof. */
export function parseSumeragiStatusPayload(payload) {
  const r = record(payload, FIELDS, "native status");
  if (uint(r.protocol_version, 16) !== 1 || uint(r.stage, 16) > 2) throw new TypeError("unsupported native status protocol or stage");
  if (typeof r.instance !== "string" || !/^[0-9a-f]{64}$/.test(r.instance)) throw new TypeError("native instance must be lowercase 32-byte hex");
  const f = record(r.footprint, FOOTPRINT, "native footprint");
  return Object.freeze({
    protocol_version: 1, config_fingerprint: hash(r.config_fingerprint), beacon_horizon: horizon(r.beacon_horizon),
    instance: r.instance, height: uint(r.height), view: uint(r.view), stage: Number(r.stage),
    leader: publicKey(r.leader), proxy_tail: publicKey(r.proxy_tail), high_qc_view: optionalUint(r.high_qc_view),
    level: uint(r.level, 32), start_level: uint(r.start_level, 32), t_retx_ms: uint(r.t_retx_ms),
    committed_height: uint(r.committed_height), applied_height: uint(r.applied_height), awaiting: bool(r.awaiting),
    signer: publicKey(r.signer), unanchored: bool(r.unanchored), abstaining: bool(r.abstaining), halted: halt(r.halted),
    footprint: Object.freeze(Object.fromEntries(FOOTPRINT.map((field) => [field, uint(f[field])]))),
  });
}
/** Bounded strict JSON preserves all unsigned bits and rejects duplicate/numeric-token drift. */
export function parseSumeragiStatusJson(text, context = "native status") {
  if (typeof text !== "string" || !text.length || Buffer.byteLength(text, "utf8") > SUMERAGI_STATUS_TYPED_JSON_MAX_BYTES) throw new TypeError(`${context} is empty or exceeds its byte bound`);
  return parseSumeragiStatusPayload(parseStrictLosslessIntegerJson(text, context));
}
const LANE_STATUS = ["record", "instance"];
const LANE_RECORD = "da_layout lane dataspace incarnation params committee created_at active_from closing anchor_freshness merged merged_at rescued".split(" ");
const LANE_DA_LAYOUT = "encoding chunk_size_bytes data_shards parity_shards max_payload_size_bytes max_chunk_count".split(" ");
const LANE_PARAMS = "block_cadence_ms max_clock_drift_ms due_work_max_lag_ms key_activation_lead_blocks key_overlap_grace_blocks key_expiry_grace_blocks key_allowed_algorithms payload_retry_interval_ms exec_budget_ms apply_budget_ms max_block_bytes epoch_length_blocks demotion_window".split(" ");
const LANE_NONZERO_PARAMS = new Set(["block_cadence_ms", "due_work_max_lag_ms", "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms", "max_block_bytes", "epoch_length_blocks", "demotion_window"]);
const LANE_FRONTIER = ["height", "block_hash", "result"];
const LANE_MEMBER = ["peer", "pop"];
const KEY_ALGORITHMS = new Set(["ed25519", "secp256k1", "ml-dsa", "bls_normal", "bls_small", "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b", "gost3410-2012-256-paramset-c", "gost3410-2012-512-paramset-a", "gost3410-2012-512-paramset-b", "sm2"]);
const BLS_NORMAL_POP_BYTES = 96;

function byte32(value, label) {
  if (typeof value !== "string" || !/^[0-9A-F]{64}$/.test(value)) throw new TypeError(`${label} must be exactly 32 uppercase hex bytes`);
  return value;
}
function laneParams(value) {
  const r = record(value, LANE_PARAMS, "native lane parameters");
  const algorithms = r.key_allowed_algorithms;
  if (!Array.isArray(algorithms) || algorithms.some((name) => typeof name !== "string" || !KEY_ALGORITHMS.has(name))) {
    throw new TypeError("native lane key_allowed_algorithms must list admitted algorithm names");
  }
  return Object.freeze(Object.fromEntries(LANE_PARAMS.map((field) => {
    if (field === "key_allowed_algorithms") return [field, Object.freeze([...algorithms])];
    const parsed = uint(r[field], field === "max_block_bytes" ? 32 : 64);
    if (LANE_NONZERO_PARAMS.has(field) && BigInt(parsed) === 0n) throw new RangeError(`native lane ${field} must be nonzero`);
    return [field, parsed];
  })));
}
function laneMember(value) {
  const r = record(value, LANE_MEMBER, "native lane committee member");
  if (typeof r.peer !== "string" || !r.peer.startsWith("ea0130")) throw new TypeError("native lane committee peer must be a BLS-normal key");
  const peer = publicKey(r.peer);
  if (typeof r.pop !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(r.pop)) throw new TypeError("native lane committee pop must be standard base64");
  const pop = Buffer.from(r.pop, "base64");
  if (pop.toString("base64") !== r.pop || pop.length !== BLS_NORMAL_POP_BYTES) throw new TypeError("native lane committee pop must be a canonical 96-byte proof");
  return Object.freeze({ peer, pop: r.pop });
}
function laneFrontier(value) {
  const r = record(value, LANE_FRONTIER, "native lane frontier");
  return Object.freeze({ height: uint(r.height), block_hash: byte32(r.block_hash, "native lane block_hash"), result: byte32(r.result, "native lane result") });
}
function laneDataAvailabilityLayout(value) {
  const r = record(value, LANE_DA_LAYOUT, "native lane data-availability layout");
  const encoding = record(r.encoding, ["encoding", "details"], "native lane payload encoding");
  if (encoding.encoding !== "reed_solomon16" || encoding.details !== null) {
    throw new TypeError("native lane payload encoding must be Reed-Solomon16");
  }
  const chunk = uint(r.chunk_size_bytes, 32);
  const data = uint(r.data_shards, 16);
  const parity = uint(r.parity_shards, 16);
  const payload = uint(r.max_payload_size_bytes);
  const chunks = uint(r.max_chunk_count, 32);
  if (chunk < 2 || chunk > 256 * 1024 || chunk % 2 || data < 1 || data > 16 ||
      parity < 1 || parity > 16 || BigInt(payload) < 1n || BigInt(payload) > 16n * 1024n * 1024n ||
      chunks < 1 || chunks > 1024) throw new RangeError("native lane data-availability layout exceeds protocol bounds");
  const maximum = Number(payload);
  const full = Math.floor(maximum / (data * chunk));
  const remainder = maximum % (data * chunk);
  const stripes = full + (remainder > 0 ? 1 : 0);
  const terminalRow = 2 * Math.ceil(remainder / (2 * data));
  if (stripes * (data + parity) > chunks || (full * chunk + terminalRow) * (data + parity) > 32 * 1024 * 1024) {
    throw new RangeError("native lane data-availability geometry exceeds protocol bounds");
  }
  return Object.freeze({ encoding: Object.freeze({ encoding: "reed_solomon16", details: null }),
    chunk_size_bytes: chunk, data_shards: data, parity_shards: parity,
    max_payload_size_bytes: payload, max_chunk_count: chunks });
}
function laneRecord(value) {
  const r = record(value, LANE_RECORD, "native lane record");
  if (!Array.isArray(r.committee)) throw new TypeError("native lane committee must be an array");
  const params = laneParams(r.params);
  const layout = laneDataAvailabilityLayout(r.da_layout);
  if (BigInt(params.max_block_bytes) > BigInt(layout.max_payload_size_bytes)) {
    throw new RangeError("native lane block limit exceeds its data-availability payload limit");
  }
  return Object.freeze({
    da_layout: layout, lane: uint(r.lane, 32), dataspace: uint(r.dataspace), incarnation: byte32(r.incarnation, "native lane incarnation"),
    params, committee: Object.freeze(r.committee.map(laneMember)),
    created_at: uint(r.created_at), active_from: uint(r.active_from), closing: optionalUint(r.closing),
    anchor_freshness: uint(r.anchor_freshness), merged: laneFrontier(r.merged), merged_at: uint(r.merged_at), rescued: uint(r.rescued),
  });
}
/** Validate the exact native lane list; lane instance statuses are observations, never finality proofs. */
export function parseSumeragiLanesPayload(payload) {
  if (!Array.isArray(payload)) throw new TypeError("native lanes must be a JSON array");
  return Object.freeze(payload.map((lane) => {
    const r = record(lane, LANE_STATUS, "native lane status");
    return Object.freeze({ record: laneRecord(r.record), instance: r.instance === null ? null : parseSumeragiStatusPayload(r.instance) });
  }));
}
/** Bounded strict JSON for `GET /v1/sumeragi/lanes`; preserves all unsigned bits. */
export function parseSumeragiLanesJson(text, context = "native lanes") {
  if (typeof text !== "string" || !text.length || Buffer.byteLength(text, "utf8") > SUMERAGI_LANES_TYPED_JSON_MAX_BYTES) throw new TypeError(`${context} is empty or exceeds its byte bound`);
  return parseSumeragiLanesPayload(parseStrictLosslessIntegerJson(text, context));
}
