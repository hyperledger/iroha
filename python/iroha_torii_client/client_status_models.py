"""Connect, Kaigi, and Sumeragi status models exposed by the Torii client."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple, Union


@dataclass(frozen=True)
class ConnectPerIpSessions:
    """Per-IP session counter inside a Connect status snapshot."""

    ip: str
    sessions: int


@dataclass(frozen=True)
class ConnectStatusPolicy:
    """Policy knobs currently enforced by the Connect service."""

    relay_enabled: Optional[bool]
    ws_max_sessions: Optional[int]
    ws_per_ip_max_sessions: Optional[int]
    ws_rate_per_ip_per_min: Optional[int]
    session_ttl_ms: Optional[int]
    frame_max_bytes: Optional[int]
    session_buffer_max_bytes: Optional[int]
    relay_strategy: Optional[str]
    relay_effective_strategy: Optional[str]
    relay_p2p_attached: Optional[bool]
    p2p_ttl_hops: Optional[int]
    heartbeat_interval_ms: Optional[int]
    heartbeat_miss_tolerance: Optional[int]
    heartbeat_min_interval_ms: Optional[int]
    extra: Dict[str, Any]


@dataclass(frozen=True)
class ConnectStatusSnapshot:
    """Aggregate Connect status metrics."""

    enabled: bool
    sessions_total: int
    sessions_active: int
    per_ip_sessions: List[ConnectPerIpSessions]
    buffered_sessions: int
    total_buffer_bytes: int
    dedupe_size: int
    frames_in_total: int
    frames_out_total: int
    ciphertext_total: int
    dedupe_drops_total: int
    buffer_drops_total: int
    plaintext_control_drops_total: int
    monotonic_drops_total: int
    sequence_violation_closes_total: int
    role_direction_mismatch_total: int
    ping_miss_total: int
    p2p_rebroadcasts_total: int
    p2p_rebroadcast_skipped_total: int
    p2p_auth_failures_total: int
    p2p_ttl_drops_total: int
    p2p_unknown_session_drops_total: int
    p2p_session_claims_in_total: int
    p2p_session_claims_installed_total: int
    p2p_session_claim_conflicts_total: int
    p2p_role_consumed_total: int
    p2p_session_terminated_total: int
    policy: Optional[ConnectStatusPolicy]


@dataclass(frozen=True)
class ConnectSessionInfo:
    """Session tokens returned by ``POST /v1/connect/session``."""

    sid: str
    network_id: str
    app_pk: str
    nonce: str
    wallet_uri: str
    app_uri: str
    token_app: str
    token_wallet: str
    token_management: str
    token_relay: str


@dataclass(frozen=True)
class ConnectAppRecord:
    """Registered Connect application descriptor."""

    app_id: str
    display_name: Optional[str]
    description: Optional[str]
    icon_url: Optional[str]
    namespaces: List[str]
    metadata: Dict[str, Any]
    policy: Dict[str, Any]
    extra: Dict[str, Any]


@dataclass(frozen=True)
class ConnectAppRegistryPage:
    """Paginated Connect app registry response."""

    items: List[ConnectAppRecord]
    total: Optional[int]
    next_cursor: Optional[str]
    extra: Dict[str, Any]


@dataclass(frozen=True)
class ConnectAppPolicyControls:
    """Mutable Connect app policy toggles."""

    relay_enabled: Optional[bool]
    ws_max_sessions: Optional[int]
    ws_per_ip_max_sessions: Optional[int]
    ws_rate_per_ip_per_min: Optional[int]
    session_ttl_ms: Optional[int]
    frame_max_bytes: Optional[int]
    session_buffer_max_bytes: Optional[int]
    heartbeat_interval_ms: Optional[int]
    heartbeat_miss_tolerance: Optional[int]
    heartbeat_min_interval_ms: Optional[int]
    extra: Dict[str, Any]


@dataclass(frozen=True)
class ConnectAdmissionManifestEntry:
    """Admission manifest entry describing permitted Connect apps."""

    app_id: str
    namespaces: List[str]
    metadata: Dict[str, Any]
    policy: Dict[str, Any]
    extra: Dict[str, Any]


@dataclass(frozen=True)
class ConnectAdmissionManifest:
    """Admission manifest contents returned by Connect governance endpoints."""

    version: Optional[int]
    manifest_hash: Optional[str]
    updated_at: Optional[str]
    entries: List[ConnectAdmissionManifestEntry]
    extra: Dict[str, Any]


SUMERAGI_EVIDENCE_KIND = "NativeSumeragiEvidence"
SUMERAGI_EVIDENCE_CLASSES = {
    "proposal",
    "phase_vote",
    "timeout_vote",
    "invalid_proposal",
    "conflicting_certificates",
}


@dataclass(frozen=True)
class SumeragiEvidencePenaltyDetails:
    """Canonical block height that applied the consensus penalty."""

    height: int


@dataclass(frozen=True)
class SumeragiEvidencePendingPenaltyStatus:
    """Penalty lifecycle state for evidence awaiting a committed outcome."""

    status: Literal["pending"]
    details: None


@dataclass(frozen=True)
class SumeragiEvidenceAppliedPenaltyStatus:
    """Penalty lifecycle state for evidence applied in a committed block."""

    status: Literal["applied"]
    details: SumeragiEvidencePenaltyDetails


SumeragiEvidencePenaltyStatus = Union[
    SumeragiEvidencePendingPenaltyStatus,
    SumeragiEvidenceAppliedPenaltyStatus,
]


@dataclass(frozen=True)
class SumeragiEvidenceOffender:
    """Original signer index and peer resolved from authenticated historical state."""

    signer: int
    peer_id: str


@dataclass(frozen=True)
class SumeragiEvidenceRecord:
    """Exact native evidence audit projection returned by `/v1/sumeragi/evidence`."""

    kind: Literal["NativeSumeragiEvidence"]
    class_: Literal["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"]
    instance: str
    height: int
    epoch: int
    context_id: str
    authority_generation: str
    offenders: Tuple[SumeragiEvidenceOffender, ...]
    safety_violation: bool
    native_frame_hash: str
    recorded_height: int
    recorded_view: int
    recorded_ms: int
    consensus_admitted_height: int
    penalty_status: SumeragiEvidencePenaltyStatus

@dataclass(frozen=True)
class SumeragiEvidenceListPage:
    """Paginated evidence listing."""

    items: List[SumeragiEvidenceRecord]
    total: int


_KAIGI_HEALTH_STATUSES = {"healthy", "degraded", "unavailable"}


@dataclass(frozen=True)
class KaigiRelaySummary:
    """Summary entry returned by ``GET /v1/kaigi/relays``."""

    relay_id: str
    domain: str
    bandwidth_class: int
    hpke_fingerprint_hex: str
    status: Optional[str]
    reported_at_ms: Optional[int]


@dataclass(frozen=True)
class KaigiRelaySummaryList:
    """Response envelope for ``GET /v1/kaigi/relays``."""

    total: int
    items: List[KaigiRelaySummary]


@dataclass(frozen=True)
class KaigiRelayReportedCall:
    """Call metadata reported alongside Kaigi relay health snapshots."""

    domain_id: str
    call_name: str


@dataclass(frozen=True)
class KaigiRelayDomainMetrics:
    """Per-domain metrics emitted by Kaigi relay endpoints."""

    domain: str
    registrations_total: int
    manifest_updates_total: int
    failovers_total: int
    health_reports_total: int


@dataclass(frozen=True)
class KaigiRelayDetail:
    """Detailed relay metadata returned by ``GET /v1/kaigi/relays/{relay_id}``."""

    relay: KaigiRelaySummary
    hpke_public_key_b64: str
    reported_call: Optional[KaigiRelayReportedCall]
    reported_by: Optional[str]
    notes: Optional[str]
    metrics: Optional[KaigiRelayDomainMetrics]


@dataclass(frozen=True)
class KaigiRelayHealthSnapshot:
    """Aggregated relay health counters returned by ``GET /v1/kaigi/relays/health``."""

    healthy_total: int
    degraded_total: int
    unavailable_total: int
    reports_total: int
    registrations_total: int
    failovers_total: int
    domains: List[KaigiRelayDomainMetrics]


@dataclass(frozen=True)
class SumeragiParamsSnapshot:
    """Consensus parameter snapshot returned by ``GET /v1/sumeragi/params``."""

    block_cadence_ms: int
    max_clock_drift_ms: int
    chain_height: int


def parse_sumeragi_json_object(payload: bytes, label: str) -> Dict[str, Any]:
    """Decode strict UTF-8 JSON while retaining typed-parser numeric diagnostics."""

    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be UTF-8 JSON") from error

    def unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate field `{key}`")
            result[key] = value
        return result

    def reject_constant(token: str) -> Any:
        raise ValueError(f"{label} contains a non-finite numeric value `{token}`")

    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_float=Decimal,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} must be valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value

@dataclass(frozen=True)
class PeerInfo:
    """Online peer descriptor returned by ``GET /v1/peers``."""

    address: str
    public_key_hex: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PeerInfo":
        if not isinstance(payload, Mapping):
            raise RuntimeError("peer payload must be an object")
        address = payload.get("address")
        if not isinstance(address, str) or not address:
            raise RuntimeError("peer payload missing `address`")
        identity = payload.get("id")
        if not isinstance(identity, Mapping):
            raise RuntimeError("peer payload missing `id` object")
        public_key = identity.get("public_key")
        if not isinstance(public_key, str) or not public_key:
            raise RuntimeError("peer payload missing `id.public_key`")
        return cls(address=address, public_key_hex=public_key)


@dataclass(frozen=True)
class PeerTelemetryConfig:
    """Configuration snapshot attached to a telemetry peer entry."""

    public_key_hex: str
    queue_capacity: Optional[int]
    network_block_gossip_size: Optional[int]
    network_block_gossip_period_ms: Optional[int]
    network_tx_gossip_size: Optional[int]
    network_tx_gossip_period_ms: Optional[int]


@dataclass(frozen=True)
class PeerTelemetryLocation:
    """Geolocation metadata for a telemetry peer."""

    lat: float
    lon: float
    country: str
    city: str


@dataclass(frozen=True)
class PeerTelemetryInfo:
    """Entry returned by ``GET /v1/telemetry/peers-info``."""

    url: str
    connected: bool
    telemetry_unsupported: bool
    config: Optional[PeerTelemetryConfig]
    location: Optional[PeerTelemetryLocation]
    connected_peers: Optional[List[str]]


@dataclass(frozen=True)
class LoggerConfig:
    """Logger configuration fragment exposed via ``/v1/configuration``."""

    level: str
    filter: Optional[str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "LoggerConfig":
        if not isinstance(payload, Mapping):
            raise RuntimeError("logger section must be an object")
        level = payload.get("level")
        if not isinstance(level, str) or not level:
            raise RuntimeError("logger section missing `level`")
        filter_value = payload.get("filter")
        if filter_value is None:
            filter_str = None
        elif isinstance(filter_value, str):
            filter_str = filter_value
        else:
            raise RuntimeError("logger section `filter` must be a string when present")
        return cls(level=level, filter=filter_str)

    def to_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"level": self.level}
        payload["filter"] = self.filter
        return payload


@dataclass(frozen=True)
class NetworkConfig:
    """Network gossip configuration exposed via ``/v1/configuration``."""

    block_gossip_size: int
    block_gossip_period_ms: int
    transaction_gossip_size: int
    transaction_gossip_period_ms: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "NetworkConfig":
        if not isinstance(payload, Mapping):
            raise RuntimeError("network section must be an object")
        try:
            block_gossip_size = int(payload["block_gossip_size"])
            block_gossip_period_ms = int(payload["block_gossip_period_ms"])
            transaction_gossip_size = int(payload["transaction_gossip_size"])
            transaction_gossip_period_ms = int(payload["transaction_gossip_period_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("network section is missing numeric gossip fields") from exc
        return cls(
            block_gossip_size=block_gossip_size,
            block_gossip_period_ms=block_gossip_period_ms,
            transaction_gossip_size=transaction_gossip_size,
            transaction_gossip_period_ms=transaction_gossip_period_ms,
        )


@dataclass(frozen=True)
class QueueConfig:
    """Transaction queue configuration exposed via ``/v1/configuration``."""

    capacity: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "QueueConfig":
        if not isinstance(payload, Mapping):
            raise RuntimeError("queue section must be an object")
        try:
            capacity = int(payload["capacity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("queue section missing numeric `capacity`") from exc
        return cls(capacity=capacity)


@dataclass(frozen=True)
class ConfidentialGasSchedule:
    """Confidential verification gas schedule."""

    proof_base: int
    per_public_input: int
    per_proof_byte: int
    per_nullifier: int
    per_commitment: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ConfidentialGasSchedule":
        if not isinstance(payload, Mapping):
            raise RuntimeError("confidential gas section must be an object")
        try:
            proof_base = int(payload["proof_base"])
            per_public_input = int(payload["per_public_input"])
            per_proof_byte = int(payload["per_proof_byte"])
            per_nullifier = int(payload["per_nullifier"])
            per_commitment = int(payload["per_commitment"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("confidential gas section missing numeric fields") from exc
        return cls(
            proof_base=proof_base,
            per_public_input=per_public_input,
            per_proof_byte=per_proof_byte,
            per_nullifier=per_nullifier,
            per_commitment=per_commitment,
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "proof_base": self.proof_base,
            "per_public_input": self.per_public_input,
            "per_proof_byte": self.per_proof_byte,
            "per_nullifier": self.per_nullifier,
            "per_commitment": self.per_commitment,
        }


@dataclass(frozen=True)
class TransportNoritoRpcConfig:
    """Norito-RPC transport summary exposed via ``/v1/configuration``."""

    enabled: bool
    stage: str
    require_mtls: bool
    canary_allowlist_size: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TransportNoritoRpcConfig":
        if not isinstance(payload, Mapping):
            raise RuntimeError("transport.norito_rpc section must be an object")
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise RuntimeError("transport.norito_rpc section missing `enabled`")
        stage = payload.get("stage")
        if not isinstance(stage, str) or not stage:
            raise RuntimeError("transport.norito_rpc section missing `stage`")
        require_mtls = payload.get("require_mtls")
        if not isinstance(require_mtls, bool):
            raise RuntimeError("transport.norito_rpc section missing `require_mtls`")
        try:
            canary_allowlist_size = int(payload["canary_allowlist_size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "transport.norito_rpc section missing numeric `canary_allowlist_size`"
            ) from exc
        return cls(
            enabled=enabled,
            stage=stage,
            require_mtls=require_mtls,
            canary_allowlist_size=canary_allowlist_size,
        )


@dataclass(frozen=True)
class TransportConfig:
    """Transport configuration exposed via ``/v1/configuration``."""

    norito_rpc: Optional[TransportNoritoRpcConfig]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "TransportConfig":
        if not isinstance(payload, Mapping):
            raise RuntimeError("transport section must be an object")
        norito_section = payload.get("norito_rpc")
        norito_rpc = (
            TransportNoritoRpcConfig.from_payload(norito_section)
            if isinstance(norito_section, Mapping)
            else None
        )
        return cls(norito_rpc=norito_rpc)


@dataclass(frozen=True)
class ConfigurationSnapshot:
    """Typed configuration payload returned by ``GET /v1/configuration``."""

    public_key_hex: str
    logger: LoggerConfig
    network: NetworkConfig
    queue: Optional[QueueConfig]
    confidential_gas: Optional[ConfidentialGasSchedule]
    transport: Optional[TransportConfig]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ConfigurationSnapshot":
        if not isinstance(payload, Mapping):
            raise RuntimeError("configuration response must be an object")
        public_key = payload.get("public_key")
        if not isinstance(public_key, str) or not public_key:
            raise RuntimeError("configuration response missing `public_key`")
        logger = LoggerConfig.from_payload(payload.get("logger", {}))
        network = NetworkConfig.from_payload(payload.get("network", {}))
        queue_section = payload.get("queue")
        queue = QueueConfig.from_payload(queue_section) if isinstance(queue_section, Mapping) else None
        gas_section = payload.get("confidential_gas")
        confidential_gas = (
            ConfidentialGasSchedule.from_payload(gas_section)
            if isinstance(gas_section, Mapping)
            else None
        )
        transport_section = payload.get("transport")
        transport = (
            TransportConfig.from_payload(transport_section)
            if isinstance(transport_section, Mapping)
            else None
        )
        return cls(
            public_key_hex=public_key,
            logger=logger,
            network=network,
            queue=queue,
            confidential_gas=confidential_gas,
            transport=transport,
        )

# Keep the public model identity stable even though definitions live in this
# private support module.
for _model in tuple(globals().values()):
    if isinstance(_model, type) and _model.__module__ == __name__:
        _model.__module__ = f"{__package__}.client"
del _model
