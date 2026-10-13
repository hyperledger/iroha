"""Closed protocol-1 native status observations; these values are not finality proofs."""
from __future__ import annotations

import base64
import binascii
from binascii import crc_hqx
from dataclasses import dataclass
import json
import re
from typing import Any, Mapping
from ._public_key_multihash import decode_canonical_public_key_multihash
from .bls_public_key import decode_bls_normal_peer_id

STATUS_MAX_BYTES = 1024 * 1024
_STATUS = frozenset("protocol_version config_fingerprint beacon_horizon instance height view stage leader proxy_tail high_qc_view level start_level t_retx_ms committed_height applied_height awaiting signer unanchored abstaining halted footprint".split())
_FOOTPRINT = tuple("votes timeouts blocks exec_entries wants pending_apply sync_entries sync_bytes peers recent_headers configs cert_cache evidence_keys probe".split())
_HORIZON = frozenset("epoch_length_blocks next_required_pulse_height active_session_id session_covers_next_pulse local_provider_ready".split())
_HEIGHT_REASONS = frozenset(("safety_violation", "apply_diverged", "publication_recovery_required"))
_UNIT_REASONS = frozenset(("safety_record_corrupt", "safety_record_inconsistent", "driver_anomaly"))

def _record(value: Any, fields: frozenset[str] | tuple[str, ...], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ValueError(f"{label} requires exactly its native fields")
    return value

def _uint(value: Any, bits: int = 64) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"native status value must be an unsigned {bits}-bit integer")
    return value

def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise ValueError("native status value must be a boolean")
    return value

def _optional_uint(value: Any) -> int | None:
    return None if value is None else _uint(value)

def _public_key(value: Any) -> str | None:
    if value is None:
        return None
    literal, (algorithm, _payload) = decode_canonical_public_key_multihash(value, "native status public key")
    if literal.startswith("ea0130"):
        decode_bls_normal_peer_id(literal, "native status public key")
    return literal

def _hash(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"hash:[0-9A-F]{64}#[0-9A-F]{4}", value) is None:
        raise ValueError("native status fingerprint must be a canonical hash")
    raw = bytes.fromhex(value[5:69])
    if not raw[-1] & 1 or int(value[70:], 16) != crc_hqx(value[:69].encode("ascii"), 0xFFFF):
        raise ValueError("native status fingerprint has invalid marker or checksum")
    return value

@dataclass(frozen=True)
class SumeragiFootprint:
    """Unsigned native core memory counters observed at this cut."""
    votes: int
    timeouts: int
    blocks: int
    exec_entries: int
    wants: int
    pending_apply: int
    sync_entries: int
    sync_bytes: int
    peers: int
    recent_headers: int
    configs: int
    cert_cache: int
    evidence_keys: int
    probe: int

@dataclass(frozen=True)
class SumeragiBeaconHorizon:
    """Readiness observed by the actual beacon owner at the same applied cut."""
    epoch_length_blocks: int
    next_required_pulse_height: int | None
    active_session_id: str | None
    session_covers_next_pulse: bool
    local_provider_ready: bool

@dataclass(frozen=True)
class SumeragiHaltReason:
    """Closed native halt reason with explicit unit or height details."""
    reason: str
    details: int | None

@dataclass(frozen=True)
class SumeragiStatus:
    """Immutable protocol-1 observation with required nullable fields."""
    protocol_version: int
    config_fingerprint: str
    beacon_horizon: SumeragiBeaconHorizon | None
    instance: str
    height: int
    view: int
    stage: int
    leader: str | None
    proxy_tail: str | None
    high_qc_view: int | None
    level: int
    start_level: int
    t_retx_ms: int
    committed_height: int
    applied_height: int
    awaiting: bool
    signer: str | None
    unanchored: bool
    abstaining: bool
    halted: SumeragiHaltReason | None
    footprint: SumeragiFootprint

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiStatus":
        """Validate every field against the current native observation schema."""
        r = _record(payload, _STATUS, "native status")
        if _uint(r["protocol_version"], 16) != 1 or _uint(r["stage"], 16) > 2:
            raise ValueError("unsupported native status protocol or stage")
        if not isinstance(r["instance"], str) or re.fullmatch(r"[0-9a-f]{64}", r["instance"]) is None:
            raise ValueError("native instance must be exact lowercase 32-byte hex")
        f = _record(r["footprint"], _FOOTPRINT, "native footprint")
        horizon = None
        if r["beacon_horizon"] is not None:
            h = _record(r["beacon_horizon"], _HORIZON, "native beacon horizon")
            session = h["active_session_id"]
            if session is not None and (not isinstance(session, str) or re.fullmatch(r"[0-9A-F]{64}", session) is None):
                raise ValueError("native beacon session must be exact uppercase 32-byte hex")
            next_height = _optional_uint(h["next_required_pulse_height"])
            covers = _boolean(h["session_covers_next_pulse"])
            ready = _boolean(h["local_provider_ready"])
            if (covers and (session is None or next_height is None)) or (ready and session is None):
                raise ValueError("native beacon readiness requires the exact session and demand")
            horizon = SumeragiBeaconHorizon(_uint(h["epoch_length_blocks"]), next_height, session, covers, ready)
        halted = None
        if r["halted"] is not None:
            h = _record(r["halted"], ("reason", "details"), "native halt reason")
            if h["reason"] in _HEIGHT_REASONS:
                detail = _uint(h["details"])
            elif h["reason"] in _UNIT_REASONS and h["details"] is None:
                detail = None
            else:
                raise ValueError("invalid native halt reason or details")
            halted = SumeragiHaltReason(h["reason"], detail)
        return cls(1, _hash(r["config_fingerprint"]), horizon, r["instance"],
                   _uint(r["height"]), _uint(r["view"]), r["stage"],
                   _public_key(r["leader"]), _public_key(r["proxy_tail"]),
                   _optional_uint(r["high_qc_view"]), _uint(r["level"], 32),
                   _uint(r["start_level"], 32), _uint(r["t_retx_ms"]),
                   _uint(r["committed_height"]), _uint(r["applied_height"]),
                   _boolean(r["awaiting"]), _public_key(r["signer"]),
                   _boolean(r["unanchored"]), _boolean(r["abstaining"]), halted,
                   SumeragiFootprint(**{name: _uint(f[name]) for name in _FOOTPRINT}))

def _parse_strict_json(payload: bytes, label: str, maximum_bytes: int) -> Any:
    """Bounded strict JSON tokenizer; preserve every unsigned bit and reject signed zero."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= maximum_bytes:
        raise ValueError(f"{label} is empty or exceeds its byte bound")
    def integer(token: str) -> int:
        if token.startswith("-"):
            raise ValueError(f"{label} requires unsigned integer tokens")
        return int(token)
    def reject(token: str) -> None:
        raise ValueError(f"{label} contains a non-integer numeric token {token}")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate field {key}")
            result[key] = value
        return result
    try:
        value = json.loads(payload.decode("utf-8", "strict"), parse_int=integer,
                           parse_float=reject, parse_constant=reject, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} must be strict UTF-8 JSON") from error
    return value

def parse_native_status_json(payload: bytes, label: str = "native status") -> dict[str, Any]:
    """Strict bounded status JSON: exactly the native status fields at the root."""
    value = _parse_strict_json(payload, label, STATUS_MAX_BYTES)
    _record(value, _STATUS, label)
    return value

LANES_MAX_BYTES = 16 * 1024 * 1024
_LANE_STATUS = frozenset(("record", "instance"))
_LANE_RECORD = frozenset("lane dataspace incarnation params da_layout committee created_at active_from closing anchor_freshness merged merged_at rescued".split())
_LANE_DA_LAYOUT = frozenset("encoding chunk_size_bytes data_shards parity_shards max_payload_size_bytes max_chunk_count".split())
_LANE_PARAMS = tuple("block_cadence_ms max_clock_drift_ms due_work_max_lag_ms key_activation_lead_blocks key_overlap_grace_blocks key_expiry_grace_blocks key_allowed_algorithms payload_retry_interval_ms exec_budget_ms apply_budget_ms max_block_bytes epoch_length_blocks demotion_window".split())
_LANE_NONZERO_PARAMS = frozenset(("block_cadence_ms", "due_work_max_lag_ms", "payload_retry_interval_ms", "exec_budget_ms", "apply_budget_ms", "max_block_bytes", "epoch_length_blocks", "demotion_window"))
_LANE_FRONTIER = frozenset(("height", "block_hash", "result"))
_LANE_MEMBER = frozenset(("peer", "pop"))
_KEY_ALGORITHMS = frozenset(("ed25519", "secp256k1", "ml-dsa", "bls_normal", "bls_small", "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b", "gost3410-2012-256-paramset-c", "gost3410-2012-512-paramset-a", "gost3410-2012-512-paramset-b", "sm2"))
_BLS_NORMAL_POP_BYTES = 96

def _byte32(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9A-F]{64}", value) is None:
        raise ValueError(f"{label} must be exactly 32 uppercase hex bytes")
    return value

@dataclass(frozen=True)
class SumeragiParameters:
    """Chain parameters pinned into one lane incarnation (Rust `SumeragiParameters`)."""
    block_cadence_ms: int
    max_clock_drift_ms: int
    due_work_max_lag_ms: int
    key_activation_lead_blocks: int
    key_overlap_grace_blocks: int
    key_expiry_grace_blocks: int
    key_allowed_algorithms: tuple[str, ...]
    payload_retry_interval_ms: int
    exec_budget_ms: int
    apply_budget_ms: int
    max_block_bytes: int
    epoch_length_blocks: int
    demotion_window: int

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiParameters":
        """Validate every served parameter; nonzero Rust fields must stay nonzero."""
        r = _record(payload, _LANE_PARAMS, "native lane parameters")
        algorithms = r["key_allowed_algorithms"]
        if not isinstance(algorithms, list) or any(not isinstance(name, str) or name not in _KEY_ALGORITHMS for name in algorithms):
            raise ValueError("native lane key_allowed_algorithms must list admitted algorithm names")
        values: dict[str, Any] = {"key_allowed_algorithms": tuple(algorithms)}
        for name in _LANE_PARAMS:
            if name == "key_allowed_algorithms":
                continue
            value = _uint(r[name], 32 if name == "max_block_bytes" else 64)
            if name in _LANE_NONZERO_PARAMS and value == 0:
                raise ValueError(f"native lane {name} must be nonzero")
            values[name] = value
        return cls(**values)

@dataclass(frozen=True)
class SumeragiLaneMember:
    """One pinned lane committee member: BLS-normal peer key and its possession proof."""
    peer: str
    pop: bytes

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiLaneMember":
        """Validate the canonical BLS-normal key and canonical base64 96-byte proof."""
        r = _record(payload, _LANE_MEMBER, "native lane committee member")
        peer = r["peer"]
        if not isinstance(peer, str) or not peer.startswith("ea0130"):
            raise ValueError("native lane committee peer must be a canonical BLS-normal key")
        _public_key(peer)
        pop = r["pop"]
        if not isinstance(pop, str):
            raise ValueError("native lane committee pop must be standard base64")
        try:
            raw = base64.b64decode(pop, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("native lane committee pop must be standard base64") from error
        if base64.b64encode(raw).decode("ascii") != pop or len(raw) != _BLS_NORMAL_POP_BYTES:
            raise ValueError("native lane committee pop must be a canonical 96-byte proof")
        return cls(peer, raw)

@dataclass(frozen=True)
class SumeragiLaneFrontier:
    """Highest merged lane block; height 0 means nothing merged yet."""
    height: int
    block_hash: str
    result: str

@dataclass(frozen=True)
class SumeragiDataAvailabilityLayout:
    """Mandatory signed RS16 geometry pinned into one lane incarnation."""
    encoding: str
    chunk_size_bytes: int
    data_shards: int
    parity_shards: int
    max_payload_size_bytes: int
    max_chunk_count: int

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiDataAvailabilityLayout":
        """Require canonical RS16 encoding and the native protocol resource bounds."""
        r = _record(payload, _LANE_DA_LAYOUT, "native lane data-availability layout")
        encoding = _record(r["encoding"], ("encoding", "details"), "native lane payload encoding")
        if encoding["encoding"] != "reed_solomon16" or encoding["details"] is not None:
            raise ValueError("native lane payload encoding must be Reed-Solomon16")
        chunk = _uint(r["chunk_size_bytes"], 32)
        data = _uint(r["data_shards"], 16)
        parity = _uint(r["parity_shards"], 16)
        maximum = _uint(r["max_payload_size_bytes"])
        chunks = _uint(r["max_chunk_count"], 32)
        if not (2 <= chunk <= 256 * 1024 and chunk % 2 == 0 and 1 <= data <= 16 and
                1 <= parity <= 16 and 1 <= maximum <= 16 * 1024 * 1024 and 1 <= chunks <= 1024):
            raise ValueError("native lane data-availability layout exceeds protocol bounds")
        full, remainder = divmod(maximum, data * chunk)
        stripes = full + (remainder > 0)
        terminal_row = 2 * ((remainder + 2 * data - 1) // (2 * data))
        if stripes * (data + parity) > chunks or (full * chunk + terminal_row) * (data + parity) > 32 * 1024 * 1024:
            raise ValueError("native lane data-availability geometry exceeds protocol bounds")
        return cls("reed_solomon16", chunk, data, parity, maximum, chunks)

@dataclass(frozen=True)
class SumeragiLaneRecord:
    """Committed lifecycle record of one lane incarnation (`specs/sumeragi_lanes.md` §2.1)."""
    lane: int
    dataspace: int
    incarnation: str
    params: SumeragiParameters
    da_layout: SumeragiDataAvailabilityLayout
    committee: tuple[SumeragiLaneMember, ...]
    created_at: int
    active_from: int
    closing: int | None
    anchor_freshness: int
    merged: SumeragiLaneFrontier
    merged_at: int
    rescued: int

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiLaneRecord":
        """Validate every record field, including the nested parameters and committee."""
        r = _record(payload, _LANE_RECORD, "native lane record")
        committee = r["committee"]
        if not isinstance(committee, list):
            raise ValueError("native lane committee must be an array")
        f = _record(r["merged"], _LANE_FRONTIER, "native lane frontier")
        merged = SumeragiLaneFrontier(_uint(f["height"]), _byte32(f["block_hash"], "native lane block_hash"), _byte32(f["result"], "native lane result"))
        params = SumeragiParameters.from_payload(r["params"])
        layout = SumeragiDataAvailabilityLayout.from_payload(r["da_layout"])
        if params.max_block_bytes > layout.max_payload_size_bytes:
            raise ValueError("native lane block limit exceeds its data-availability payload limit")
        return cls(_uint(r["lane"], 32), _uint(r["dataspace"]), _byte32(r["incarnation"], "native lane incarnation"),
                   params, layout,
                   tuple(SumeragiLaneMember.from_payload(member) for member in committee),
                   _uint(r["created_at"]), _uint(r["active_from"]), _optional_uint(r["closing"]),
                   _uint(r["anchor_freshness"]), merged, _uint(r["merged_at"]), _uint(r["rescued"]))

@dataclass(frozen=True)
class SumeragiLaneStatus:
    """One served lane with this node's instance status (None while it runs none); not finality."""
    record: SumeragiLaneRecord
    instance: SumeragiStatus | None

    @classmethod
    def from_payload(cls, payload: Any) -> "SumeragiLaneStatus":
        """Validate the committed record and the nullable native instance status."""
        r = _record(payload, _LANE_STATUS, "native lane status")
        instance = None if r["instance"] is None else SumeragiStatus.from_payload(r["instance"])
        return cls(SumeragiLaneRecord.from_payload(r["record"]), instance)

def parse_native_lanes(payload: Any) -> list[SumeragiLaneStatus]:
    """Validate an already-decoded `GET /v1/sumeragi/lanes` list."""
    if not isinstance(payload, list):
        raise ValueError("native lanes must be a JSON array")
    return [SumeragiLaneStatus.from_payload(lane) for lane in payload]

def parse_native_lanes_json(payload: bytes, label: str = "native lanes") -> list[SumeragiLaneStatus]:
    """Strict bounded lane list JSON; every unsigned value keeps all its bits."""
    return parse_native_lanes(_parse_strict_json(payload, label, LANES_MAX_BYTES))
