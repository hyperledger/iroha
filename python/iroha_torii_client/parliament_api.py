"""Strict authenticated Python bindings for the first-release Parliament API.

The casting-proof response is intentionally returned as opaque canonical
Norito.  This module validates its transport frame and size, but only the
native ABI-29 verifier can authenticate finality, membership, and the embedded
Core archive before a wallet accesses secret ballot material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ._account_id import decode_canonical_i105_account_id
from .governance_proposals import GovernanceProposalKind
from .norito_frame import (
    encode_norito_frame,
    validate_norito_frame,
    validate_opaque_norito_frame,
)

PARLIAMENT_API_VERSION_V1 = 1
PARLIAMENT_ATTEMPT_DRAFT_PATH_V1 = "/v1/gov/parliament/attempts/draft"
PARLIAMENT_ATTEMPT_READ_PATH_V1 = (
    "/v1/gov/parliament/attempts/{governance_attempt_id}"
)
PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1 = (
    "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-context"
)
PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1 = (
    "/v1/gov/parliament/ballots/{ballot_attempt_id}/casting-proof"
)
PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1 = (
    "/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context"
)
PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1 = (
    "/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release"
)
PARLIAMENT_TRANSITION_DRAFT_PATH_V1 = "/v1/gov/parliament/transitions/draft"

PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1 = (
    "iroha.governance.parliament.attempt.create.v1"
)
PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1 = (
    "iroha.governance.parliament.transition.submit.v1"
)
_PARLIAMENT_INSTRUCTION_TYPE_NAME_BY_WIRE_ID_V1 = {
    PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1: (
        "iroha_data_model::isi::governance::parliament::"
        "CreateParliamentGovernanceAttemptV1"
    ),
    PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1: (
        "iroha_data_model::isi::governance::parliament::"
        "SubmitParliamentLifecycleTransitionV1"
    ),
}
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_V1 = (
    "iroha.torii.v1.parliament.timed_ovn_casting_proof.request"
)
PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_V1 = (
    "iroha.torii.v1.parliament.timed_ovn_casting_proof.response"
)
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1 = (
    "adccf322a5fcf43040e20bea238f55f3"
)
PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1 = (
    "46d29299272433b1299646bee722bd11"
)
PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1 = 1
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1 = 0x02
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1 = 8
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1 = 0
PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1 = 52

PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1 = 16 * 1024 * 1024
PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 = 16
_PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 = 1
_PARLIAMENT_SORTITION_RETRIES_MAX_V1 = 16
PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1 = 4 * 1024 * 1024
PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1 = 8 * 1024 * 1024
# A maximal 32 x 2,858-byte freeze call is below 92 KiB before framing and
# below 184 KiB as hex; 1 MiB leaves ample fixed-envelope headroom.
PARLIAMENT_TRANSITION_DRAFT_RESPONSE_MAX_BYTES_V1 = 1024 * 1024
PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 = 3_624
PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1 = 2_858
PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1 = 1_000
PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1 = 32
PARLIAMENT_TLE_MAX_COMMITTEE_SIZE_V1 = 31
_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_MAX_V1 = 10

_U16_MAX = (1 << 16) - 1
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1
_FIRST_RELEASE_DATA_MODEL_VERSION = 4
_LOWER_ID = re.compile(r"[0-9a-f]{64}")
_LOWER_BYTES = re.compile(r"(?:[0-9a-f]{2})+")
_DECIMAL_UINT = re.compile(r"0|[1-9][0-9]*")
_CANONICAL_NUMERIC = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_PRIVATE_FIELDS = frozenset(
    {"private_key", "privateKey", "seed", "mnemonic", "private_key_seed"}
)
_AMBIENT_AUTH_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-token",
        "x-iroha-account",
        "x-iroha-signature",
        "x-iroha-timestamp-ms",
        "x-iroha-nonce",
        "x-iroha-witness",
        "x-iroha-operator-public-key",
        "x-iroha-operator-timestamp-ms",
        "x-iroha-operator-nonce",
        "x-iroha-operator-signature",
    }
)


def encode_parliament_timed_ovn_casting_proof_request_v1(
    trusted_checkpoint_height: int,
) -> bytes:
    """Encode the sole canonical V1 checkpoint-promotion request frame."""

    if type(trusted_checkpoint_height) is not int:
        raise TypeError("trusted_checkpoint_height must be an unsigned 64-bit integer")
    if trusted_checkpoint_height <= 0 or trusted_checkpoint_height > _U64_MAX:
        raise ValueError("trusted_checkpoint_height must be within 1..=18446744073709551615")
    payload = b"".join(
        (
            b"\x02",
            PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1.to_bytes(2, "little"),
            b"\x08",
            trusted_checkpoint_height.to_bytes(8, "little"),
        )
    )
    frame = encode_norito_frame(
        payload,
        type_name=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_V1,
        flags=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1,
        payload_alignment=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1,
    )
    if len(frame) != PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1:
        raise AssertionError("canonical Parliament casting-proof request width drifted")
    return frame


_PARLIAMENT_ROUTES_V1 = frozenset(
    {
        "/v1/gov/capabilities",
        PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
        PARLIAMENT_ATTEMPT_READ_PATH_V1,
        PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1,
        PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1,
        PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1,
        PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1,
        PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
    }
)
_PROPOSAL_KINDS_V1 = frozenset(
    {
        "DEPLOY_CONTRACT",
        "CONTRACT_EMERGENCY_HOLD",
        "CONTRACT_LIFECYCLE_GOVERNANCE",
        "GLOBAL_DATA_TRIGGER_PERMISSION_GOVERNANCE",
        "MUSUBI_REGISTRY_GOVERNANCE",
        "RUNTIME_UPGRADE",
        "SCCP_ROUTE_GOVERNANCE",
        "SORAFS_PROVIDER_GOVERNANCE",
        "VALIDATION_FEE_PAYOUT_LIFECYCLE",
        "VALIDATION_FEE_POLICY",
    }
)
_TARGET_BODY_FIELDS = frozenset(
    {
        "rules_committee",
        "agenda_council",
        "interest_panel",
        "review_panel",
        "coordination_council",
        "mpc_committee",
        "fma_committee",
        "oversight_committee",
        "policy_jury",
        "confirmation_jury",
    }
)
_CAPABILITIES_FIELDS = frozenset(
    {
        "schema",
        "version",
        "network_id",
        "current_height",
        "network_prefix",
        "abi_version",
        "data_model_version",
        "approval_mode",
        "private_ballot_protocol",
        "mandatory_private_ballots",
        "proposal_backed_referendum_ballots_supported",
        "standalone_plain_ballots_supported",
        "standalone_zk_ballots_supported",
        "citizenship_asset_id",
        "citizenship_bond_amount",
        "citizenship_escrow_account",
        "voting_asset_id",
        "min_bond_amount",
        "bond_escrow_account",
        "min_enactment_delay",
        "invitation_phase_blocks",
        "registration_phase_blocks",
        "survivor_freeze_phase_blocks",
        "commitment_phase_blocks",
        "release_delay_blocks",
        "opening_phase_blocks",
        "max_ballot_retries",
        "max_corpus_entries",
        "target_body_sizes",
        "supported_proposal_kinds",
        "supported_routes",
    }
)

_PUBLIC_TRANSITION_FIELDS = {
    "EscalateRisk": ("target",),
    "CompleteQualification": None,
    "RegisterSortitionRequest": ("requests",),
    "ConsumeSortitionPulseBatch": (
        "request_ids",
        "beacon_session_id",
        "pulse_height",
        "pulse_id",
    ),
    "BeginInvitationAcceptance": ("election_attempt_id",),
    "FailBodyElectionNoRoster": ("election_attempt_id",),
    "SealBodyRoster": ("election_attempt_id",),
    "AdvanceBodyPhase": ("body_instance_id", "target"),
    "RecordAttemptAbsence": ("body_instance_id", "assignment_id"),
    "EndorsePublicFinding": ("body_instance_id", "result_root"),
    "RegisterBallotAttempt": (
        "body_instance_id",
        "ballot_attempt_id",
        "sequence",
        "tle_session_id",
        "tle_key_session_id",
        "release_beacon_session_id",
        "release_height",
    ),
    "CloseBallotRegistration": ("ballot_attempt_id",),
    "FreezeBallotSurvivors": ("ballot_attempt_id",),
    "FreezeTimedOvnCorpus": ("ballot_attempt_id", "ballot_records"),
    "BeginBallotOpeningBatch": (
        "ballot_attempt_ids",
        "release_beacon_session_id",
        "release_height",
        "pulse_id",
    ),
    "FailBallotNoResult": ("ballot_attempt_id",),
    "FinalizeOpenedBallot": ("ballot_attempt_id", "final_release"),
    "RecordInvitationResponse": ("election_attempt_id", "body", "decision"),
    "RegisterBallotParticipant": ("ballot_attempt_id", "registration_record"),
    "RecordBallotDropout": ("ballot_attempt_id",),
    "FailPublicFindingNoResult": ("body_instance_id",),
}
_BODY_ORDER = (
    "rules-committee",
    "agenda-council",
    "interest-panel",
    "review-panel",
    "coordination-council",
    "mpc-committee",
    "fma-committee",
    "oversight-committee",
    "policy-jury",
    "confirmation-jury",
)
_RISK_TIERS = frozenset({"Routine", "Standard", "Constitutional", "Emergency"})
_DELIBERATION_PHASES = frozenset(
    {
        "Orientation",
        "Evidence",
        "Questions",
        "Responses",
        "Deliberation",
        "Reflection",
        "Vote",
    }
)
@dataclass(frozen=True)
class ParliamentInstructionDraftV1:
    """One canonical instruction skeleton for local transaction signing."""

    wire_id: str
    payload_hex: str


@dataclass(frozen=True)
class ParliamentAttemptDraftResponseV1:
    """Strict response from the attempt-draft route."""

    proposal_content_id: str
    governance_attempt_id: str
    instruction: ParliamentInstructionDraftV1


@dataclass(frozen=True)
class ParliamentTransitionDraftResponseV1:
    """Strict response from the lifecycle-transition draft route."""

    governance_attempt_id: str
    transition_kind: str
    transition_digest: bytes
    instruction: ParliamentInstructionDraftV1


@dataclass(frozen=True)
class ParliamentAttemptReadResponseV1:
    """Bounded outer projection from one authenticated attempt read."""

    governance_attempt_id: str
    current_height: int
    policy_version: int
    timed_ovn_progress: Tuple[Optional["ParliamentTimedOvnProgressProjectionV1"], ...]
    state_payload: bytes
    raw: Dict[str, Any]


@dataclass(frozen=True)
class ParliamentTimedOvnProgressProjectionV1:
    """Aggregate-only active-ballot status and next contiguous corpus offset."""

    ballot_attempt_id: str
    status: str
    frozen_survivor_count: Optional[int]
    accepted_ballot_prefix_count: Optional[int]


@dataclass(frozen=True)
class ParliamentTleKeySessionPublicStateV1:
    """Complete bounded public transcript for an adaptive TLE key session."""

    key_session_id: str
    network_id: bytes
    roster_hash: bytes
    committee_size: int
    threshold: int
    group_public_key: bytes
    transcript_hash: bytes
    raw: Dict[str, Any]


@dataclass(frozen=True)
class ParliamentTimedOvnReleaseIdentityProjectionV1:
    """Frozen public timed-OVN future release identity."""

    tle_key_session_id: str
    governance_attempt_id: str
    body_instance_id: str
    ballot_attempt_id: str
    survivor_corpus_root: bytes
    no_recovery_root: bytes
    target_finalized_height: int
    parameter_hash: bytes


@dataclass(frozen=True)
class ParliamentTimedOvnCastingContextResponseV1:
    """Structurally checked node-local diagnostic casting context.

    This projection is not consensus-authenticated and must never authorize
    secret-local preparation. Use the finality-bound casting-proof route and
    ABI-29 native verifier for that purpose.
    """

    current_height: int
    phase: str
    ballot_attempt_id: str
    key_session: ParliamentTleKeySessionPublicStateV1
    archive_norito: bytes
    raw: Dict[str, Any]


@dataclass(frozen=True)
class ParliamentTleReleaseContextResponseV1:
    """Core-authorized public release context within its opening window."""

    current_height: int
    ballot_attempt_id: str
    governance_attempt_id: str
    body_instance_id: str
    release_height: int
    opening_deadline_height: int
    key_session: ParliamentTleKeySessionPublicStateV1
    release_identity: ParliamentTimedOvnReleaseIdentityProjectionV1
    identity_digest: bytes
    identity_payload: bytes
    raw: Dict[str, Any]


@dataclass(frozen=True)
class ParliamentTlePartialReleaseShareV1:
    """One public proof-carrying adaptive TLE partial release."""

    key_session_id: str
    identity_digest: bytes
    participant_index: int
    sigma: bytes
    proof_x: bytes
    proof_y: bytes
    z_s: bytes
    z_r: bytes
    z_u: bytes


@dataclass(frozen=True)
class GovernanceTargetBodySizesV1:
    """Configured target seats for all ten Parliament bodies."""

    rules_committee: int
    agenda_council: int
    interest_panel: int
    review_panel: int
    coordination_council: int
    mpc_committee: int
    fma_committee: int
    oversight_committee: int
    policy_jury: int
    confirmation_jury: int


@dataclass(frozen=True)
class GovernanceCapabilitiesV1:
    """Fail-closed readiness projection from ``GET /v1/gov/capabilities``."""

    network_id: str
    current_height: int
    network_prefix: int
    abi_version: int
    data_model_version: int
    standalone_plain_ballots_supported: bool
    target_body_sizes: GovernanceTargetBodySizesV1
    supported_proposal_kinds: Tuple[str, ...]
    supported_routes: Tuple[str, ...]
    raw: Dict[str, Any]


def _exact(value: Any, fields: Iterable[str], context: str) -> Mapping[str, Any]:
    expected = frozenset(fields)
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TypeError(f"{context} must be an object with string field names")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            raise TypeError(f"{context} is missing required field `{missing[0]}`")
        raise TypeError(f"{context} contains unknown field `{unknown[0]}`")
    return value


def _text(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TypeError(f"{context} must be exact non-empty text")
    return value


def _uint(
    value: Any,
    context: str,
    maximum: int = _U64_MAX,
    *,
    minimum: int = 0,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise TypeError(f"{context} must be an integer in {minimum}..{maximum}")
    return value


def _decimal_uint(
    value: Any,
    context: str,
    *,
    maximum: int = _U64_MAX,
    minimum: int = 0,
) -> int:
    if not isinstance(value, str) or _DECIMAL_UINT.fullmatch(value) is None:
        raise TypeError(f"{context} must be a canonical unsigned decimal string")
    return _uint(int(value), context, maximum, minimum=minimum)


def _id(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or _LOWER_ID.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise TypeError(
            f"{context} must be exactly 64 lowercase non-zero hexadecimal characters"
        )
    return value


def _bytes(value: Any, width: int, context: str, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, list) or len(value) != width:
        raise TypeError(f"{context} must contain exactly {width} JSON bytes")
    decoded = bytes(
        _uint(byte, f"{context}[{index}]", 255)
        for index, byte in enumerate(value)
    )
    if nonzero and not any(decoded):
        raise TypeError(f"{context} must be non-zero")
    return decoded


def _lower_hex(value: Any, context: str, *, maximum_bytes: Optional[int] = None) -> str:
    if not isinstance(value, str) or _LOWER_BYTES.fullmatch(value) is None:
        raise TypeError(f"{context} must be non-empty complete lowercase hexadecimal bytes")
    if maximum_bytes is not None and len(value) // 2 > maximum_bytes:
        raise ValueError(f"{context} exceeds its {maximum_bytes}-byte bound")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{context} must be boolean")
    return value


def _canonical_account_bytes(
    value: Any,
    context: str,
    *,
    expected_discriminant: Optional[int] = None,
) -> bytes:
    literal = _text(value, context)
    if "@" in literal:
        raise TypeError(f"{context} must be a canonical domainless I105 account id")
    try:
        return decode_canonical_i105_account_id(
            literal,
            expected_discriminant=expected_discriminant,
        )
    except ValueError as exc:
        raise TypeError(f"{context} must be a canonical domainless I105 account id") from exc


def _asset_definition_id(value: Any, context: str) -> str:
    literal = _text(value, context)
    if literal.count("#") != 1 or any(not part for part in literal.split("#")):
        raise TypeError(f"{context} must be a canonical asset definition id")
    return literal


def _require_media_type(value: Any, expected: str, context: str) -> None:
    if not isinstance(value, str) or not value or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise TypeError(f"{context} response must use {expected} content type")
    segments = value.split(";")
    if segments[0].strip().lower() != expected:
        raise TypeError(f"{context} response must use {expected} content type")
    parameters: Dict[str, str] = {}
    for segment in segments[1:]:
        if not segment.strip() or "=" not in segment:
            raise TypeError(f"{context} response has an invalid content-type parameter")
        raw_name, raw_value = segment.split("=", 1)
        name = raw_name.strip().lower()
        parameter = raw_value.strip()
        if (
            re.fullmatch(r"[a-z0-9!#$&^_.+-]+", name) is None
            or name in parameters
            or not parameter
        ):
            raise TypeError(f"{context} response has an invalid content-type parameter")
        if len(parameter) >= 2 and parameter[0] == parameter[-1] == '"':
            parameter = parameter[1:-1]
        if re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+", parameter) is None:
            raise TypeError(f"{context} response has an invalid content-type parameter")
        parameters[name] = parameter
    if expected == "application/json":
        if set(parameters) - {"charset"} or parameters.get("charset", "utf-8").lower() != "utf-8":
            raise TypeError(f"{context} response must use UTF-8 application/json")
    elif parameters:
        raise TypeError(f"{context} response must use bare {expected} content type")


def _json_clone(value: Any, context: str, *, depth: int = 0) -> Any:
    if depth > 128:
        raise ValueError(f"{context} exceeds the JSON nesting bound")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError(f"{context} contains a Unicode surrogate string")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return _uint(value, context)
    if isinstance(value, (list, tuple)):
        return [
            _json_clone(item, f"{context}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{context} contains a non-string field name")
            if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                raise ValueError(f"{context} contains a Unicode surrogate field name")
            if key in _PRIVATE_FIELDS:
                raise TypeError(f"{context}.{key} is forbidden; sign drafts locally")
            result[key] = _json_clone(item, f"{context}.{key}", depth=depth + 1)
        return result
    raise TypeError(f"{context} contains a value that is not canonical JSON")


def _strict_json_object(body: bytes, context: str) -> Mapping[str, Any]:
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{context} must be strict UTF-8 JSON") from exc

    def object_without_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{context} contains duplicate field `{key}`")
            result[key] = value
        return result

    def reject_float(_value: str) -> Any:
        raise ValueError(f"{context} must not contain floating-point numbers")

    def reject_constant(_value: str) -> Any:
        raise ValueError(f"{context} must not contain non-finite numbers")

    def parse_uint(value: str) -> int:
        if value.startswith("-"):
            raise ValueError(f"{context} must not contain negative integers")
        parsed = int(value)
        if parsed > _U64_MAX:
            raise ValueError(f"{context} contains an integer larger than u64")
        return parsed

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_int=parse_uint,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(context):
            raise
        raise ValueError(f"{context} contains invalid JSON: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise TypeError(f"{context} must be a JSON object")
    pending = [(parsed, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > 128:
            raise ValueError(f"{context} exceeds the JSON nesting bound")
        if isinstance(current, Mapping):
            for key, item in current.items():
                if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
                    raise ValueError(f"{context} contains a Unicode surrogate field name")
                pending.append((item, depth + 1))
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        elif isinstance(current, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in current
        ):
            raise ValueError(f"{context} contains a Unicode surrogate string")
    cloned = _json_clone(parsed, context)
    if not isinstance(cloned, Mapping):
        raise AssertionError("validated Parliament response root remains an object")
    return cloned


def _read_bounded_response(response: Any, maximum: int, context: str) -> bytes:
    try:
        content_length = response.headers.get("Content-Length")
        declared_length: Optional[int] = None
        if content_length is not None:
            if (
                not isinstance(content_length, str)
                or len(content_length) > 20
                or _DECIMAL_UINT.fullmatch(content_length) is None
            ):
                raise ValueError(
                    f"{context} Content-Length must be a canonical unsigned decimal integer"
                )
            declared_length = int(content_length)
            if declared_length > maximum:
                raise ValueError(f"{context} exceeds its {maximum}-byte size bound")
        body = bytearray()
        for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
            if not chunk:
                continue
            if not isinstance(chunk, (bytes, bytearray)):
                raise TypeError(f"{context} yielded a non-byte response chunk")
            if len(chunk) > maximum - len(body):
                raise ValueError(f"{context} exceeds its {maximum}-byte size bound")
            body.extend(chunk)
        if declared_length is not None and declared_length != len(body):
            raise ValueError(f"{context} Content-Length differs from the response body")
        return bytes(body)
    finally:
        response.close()


def _instruction(
    value: Any, expected_wire_id: str, context: str
) -> ParliamentInstructionDraftV1:
    if not isinstance(value, list) or len(value) != 1:
        raise TypeError(f"{context} must contain exactly one instruction")
    record = _exact(value[0], {"wire_id", "payload_hex"}, f"{context}[0]")
    wire_id = _text(record["wire_id"], f"{context}[0].wire_id")
    if wire_id != expected_wire_id:
        raise ValueError(f"{context}[0].wire_id is not the canonical Parliament instruction")
    try:
        expected_type_name = _PARLIAMENT_INSTRUCTION_TYPE_NAME_BY_WIRE_ID_V1[
            expected_wire_id
        ]
    except KeyError as exc:
        raise ValueError(f"{context}[0].wire_id has no exact first-release schema") from exc
    payload_hex = _lower_hex(record["payload_hex"], f"{context}[0].payload_hex")
    validate_norito_frame(
        bytes.fromhex(payload_hex),
        context=f"{context}[0].payload_hex",
        expected_type_name=expected_type_name,
    )
    return ParliamentInstructionDraftV1(wire_id=wire_id, payload_hex=payload_hex)


def _tagged_unit(value: Any, field: str, accepted: Iterable[str], context: str) -> str:
    record = _exact(value, {field}, context)
    tag = _text(record[field], f"{context}.{field}")
    if tag not in frozenset(accepted):
        raise TypeError(f"{context}.{field} is not an admitted first-release value")
    return tag


def _strict_id_list(value: Any, context: str) -> Tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1
    ):
        raise ValueError(f"{context} must contain one through 1000 identifiers")
    result = tuple(_id(item, f"{context}[{index}]") for index, item in enumerate(value))
    if any(left >= right for left, right in zip(result, result[1:])):
        raise TypeError(f"{context} must be strictly increasing and distinct")
    return result


def _validate_sortition_request(
    value: Any,
    *,
    expected_governance_attempt_id: str,
    context: str,
) -> Dict[str, Any]:
    request = _exact(
        value,
        {
            "id",
            "governance_attempt_id",
            "body_election_attempt_id",
            "body",
            "candidate_root",
            "candidate_count",
            "target_seats",
            "request_height",
            "pulse_height",
            "beacon_session_id",
        },
        context,
    )
    request_id = _id(request["id"], f"{context}.id")
    governance_attempt_id = _id(
        request["governance_attempt_id"], f"{context}.governance_attempt_id"
    )
    if governance_attempt_id != expected_governance_attempt_id:
        raise ValueError(
            f"{context}.governance_attempt_id differs from the transition attempt"
        )
    election_attempt_id = _id(
        request["body_election_attempt_id"],
        f"{context}.body_election_attempt_id",
    )
    body = _text(request["body"], f"{context}.body")
    if body not in _BODY_ORDER:
        raise TypeError(f"{context}.body is not a canonical Parliament body")
    _bytes(request["candidate_root"], 32, f"{context}.candidate_root", nonzero=True)
    request_candidate_count = _uint(
        request["candidate_count"],
        f"{context}.candidate_count",
        _U32_MAX,
        minimum=1,
    )
    target_seats = _uint(
        request["target_seats"],
        f"{context}.target_seats",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    request_height = _uint(
        request["request_height"], f"{context}.request_height", minimum=1
    )
    pulse_height = _uint(
        request["pulse_height"], f"{context}.pulse_height", minimum=1
    )
    if pulse_height <= request_height:
        raise ValueError(f"{context}.pulse_height must follow request_height")
    beacon_session_id = _id(
        request["beacon_session_id"], f"{context}.beacon_session_id"
    )
    return {
        "id": request_id,
        "governance_attempt_id": governance_attempt_id,
        "body_election_attempt_id": election_attempt_id,
        "body": body,
        "candidate_count": request_candidate_count,
        "target_seats": target_seats,
        "request_height": request_height,
        "pulse_height": pulse_height,
        "beacon_session_id": beacon_session_id,
    }


def _normalize_transition(
    value: Any, expected_governance_attempt_id: str
) -> Tuple[Dict[str, Any], str]:
    transition = _json_clone(value, "transition")
    if not isinstance(transition, Mapping):
        raise TypeError("transition must be a JSON object")
    tag = _text(transition.get("transition"), "transition.transition")
    fields = _PUBLIC_TRANSITION_FIELDS.get(tag, ...)
    if fields is ...:
        raise TypeError("transition tag is unknown, removed, or consensus-owned")
    required_outer = {"transition"} if fields is None else {"transition", "payload"}
    _exact(transition, required_outer, "transition")
    if fields is None:
        return dict(transition), tag

    payload = _exact(transition["payload"], fields, f"transition.{tag}.payload")
    id_fields = (
        "assignment_id",
        "ballot_attempt_id",
        "beacon_session_id",
        "body_instance_id",
        "election_attempt_id",
        "pulse_id",
        "release_beacon_session_id",
        "tle_key_session_id",
        "tle_session_id",
    )
    for field in id_fields:
        if field in payload:
            _id(payload[field], f"transition.{tag}.payload.{field}")
    if "sequence" in payload:
        _uint(payload["sequence"], f"transition.{tag}.payload.sequence", _U32_MAX)
    for field in ("pulse_height", "release_height"):
        if field in payload:
            _uint(payload[field], f"transition.{tag}.payload.{field}", minimum=1)
    if tag == "EscalateRisk":
        _tagged_unit(payload["target"], "tier", _RISK_TIERS, "target")
    if tag == "RegisterSortitionRequest":
        requests = payload["requests"]
        if (
            not isinstance(requests, list)
            or not requests
            or len(requests) > _PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_MAX_V1
        ):
            raise ValueError("sortition request batch must contain one through 10 requests")
        previous_body_index = -1
        common_slot_and_count = None
        for index, item in enumerate(requests):
            entry_context = f"transition.RegisterSortitionRequest.payload.requests[{index}]"
            entry = _exact(item, {"sequence", "request"}, entry_context)
            _uint(entry["sequence"], f"{entry_context}.sequence", _U32_MAX)
            request = _validate_sortition_request(
                entry["request"],
                expected_governance_attempt_id=expected_governance_attempt_id,
                context=f"{entry_context}.request",
            )
            body_index = _BODY_ORDER.index(request["body"])
            if body_index <= previous_body_index:
                raise TypeError("sortition request batch must be strictly body-ordered")
            previous_body_index = body_index
            slot_and_count = (
                request["request_height"],
                request["pulse_height"],
                request["beacon_session_id"],
                request["candidate_count"],
            )
            if common_slot_and_count is None:
                common_slot_and_count = slot_and_count
            elif slot_and_count != common_slot_and_count:
                raise ValueError("sortition request batch must share one pulse slot and count")
    if tag == "ConsumeSortitionPulseBatch":
        _strict_id_list(payload["request_ids"], "request_ids")
    if tag == "AdvanceBodyPhase":
        _tagged_unit(payload["target"], "phase", _DELIBERATION_PHASES, "target")
    if tag == "BeginBallotOpeningBatch":
        _strict_id_list(payload["ballot_attempt_ids"], "ballot_attempt_ids")
    if tag == "RecordInvitationResponse":
        body = _text(payload["body"], "body")
        if body not in _BODY_ORDER:
            raise TypeError("body is not a canonical Parliament body")
        _tagged_unit(payload["decision"], "decision", {"Accept", "Decline"}, "decision")
    if tag == "EndorsePublicFinding":
        _bytes(payload["result_root"], 32, "result_root", nonzero=True)
    if tag == "RegisterBallotParticipant":
        _bytes(
            payload["registration_record"],
            PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1,
            "registration_record",
        )
    if tag == "FreezeTimedOvnCorpus":
        records = payload["ballot_records"]
        if (
            not isinstance(records, list)
            or not records
            or len(records) > PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1
        ):
            raise ValueError("ballot_records must contain one through 32 records")
        for index, record in enumerate(records):
            _bytes(
                record,
                PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1,
                f"ballot_records[{index}]",
            )
    if tag == "FinalizeOpenedBallot":
        release = _exact(
            payload["final_release"],
            {"key_session_id", "identity_digest", "signature"},
            "final_release",
        )
        _id(release["key_session_id"], "final_release.key_session_id")
        _bytes(release["identity_digest"], 32, "final_release.identity_digest", nonzero=True)
        _bytes(release["signature"], 48, "final_release.signature", nonzero=True)
    return dict(transition), tag


def _parse_attempt_draft(
    value: Any,
    expected_proposal_content_id: str,
    expected_governance_attempt_id: str,
) -> ParliamentAttemptDraftResponseV1:
    record = _exact(
        value,
        {"version", "proposal_content_id", "governance_attempt_id", "tx_instructions"},
        "Parliament attempt draft response",
    )
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("unsupported Parliament attempt draft response version")
    proposal_id = _id(record["proposal_content_id"], "proposal_content_id")
    attempt_id = _id(record["governance_attempt_id"], "governance_attempt_id")
    if proposal_id != _id(expected_proposal_content_id, "expected_proposal_content_id"):
        raise ValueError("proposal_content_id differs from the exact request binding")
    if attempt_id != _id(expected_governance_attempt_id, "expected_governance_attempt_id"):
        raise ValueError("governance_attempt_id differs from the exact request binding")
    return ParliamentAttemptDraftResponseV1(
        proposal_content_id=proposal_id,
        governance_attempt_id=attempt_id,
        instruction=_instruction(
            record["tx_instructions"],
            PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1,
            "tx_instructions",
        ),
    )


def _parse_transition_draft(
    value: Any,
    expected_attempt_id: str,
    expected_kind: str,
    expected_digest: bytes,
) -> ParliamentTransitionDraftResponseV1:
    if expected_kind not in _PUBLIC_TRANSITION_FIELDS:
        raise TypeError("expected transition kind is unknown or consensus-owned")
    if type(expected_digest) is not bytes or len(expected_digest) != 32 or not any(
        expected_digest
    ):
        raise TypeError("expected_transition_digest must be 32 non-zero immutable bytes")
    record = _exact(
        value,
        {
            "version",
            "governance_attempt_id",
            "transition_kind",
            "transition_digest",
            "tx_instructions",
        },
        "Parliament transition draft response",
    )
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("unsupported Parliament transition draft response version")
    attempt_id = _id(record["governance_attempt_id"], "governance_attempt_id")
    if attempt_id != _id(expected_attempt_id, "expected_governance_attempt_id"):
        raise ValueError("governance_attempt_id differs from the exact request binding")
    kind = _tagged_unit(
        record["transition_kind"],
        "kind",
        _PUBLIC_TRANSITION_FIELDS,
        "transition_kind",
    )
    if kind != expected_kind:
        raise ValueError("transition_kind differs from the exact request binding")
    digest = _bytes(record["transition_digest"], 32, "transition_digest", nonzero=True)
    if digest != expected_digest:
        raise ValueError("transition_digest differs from the exact request binding")
    return ParliamentTransitionDraftResponseV1(
        governance_attempt_id=attempt_id,
        transition_kind=kind,
        transition_digest=digest,
        instruction=_instruction(
            record["tx_instructions"],
            PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1,
            "tx_instructions",
        ),
    )


def _parse_body_states(
    value: Any, required_bodies: Sequence[Mapping[str, Any]]
) -> Tuple[Dict[str, Any], ...]:
    if not isinstance(value, list) or len(value) != len(required_bodies):
        raise TypeError("body_states must exactly match the required body pipeline")
    fields = {
        "body",
        "body_instance_id",
        "status",
        "public_finding_opened_at_height",
        "public_finding_phase_blocks",
        "public_finding_deadline_height",
        "no_result_kind",
        "no_result_height",
        "timed_ovn_progress",
    }
    statuses = {
        "AwaitingSortition",
        "AcceptingInvitations",
        "RosterSealed",
        "Deliberating",
        "Balloting",
        "Approved",
        "Rejected",
        "NoQuorum",
        "NoResult",
        "Superseded",
    }
    phases = {
        "Orientation",
        "Evidence",
        "Questions",
        "Responses",
        "Deliberation",
        "Reflection",
        "Vote",
    }
    no_results = {
        "PublicFindingQuorumUnreachable",
        "PublicFindingDeadlineExpired",
        "BallotRegistrationDeadlineExpired",
        "BallotSurvivorDeadlineExpired",
        "BallotCommitmentDeadlineExpired",
        "BallotReleasePulseUnavailable",
        "BallotOpeningDeadlineExpired",
        "SortitionRetriesExhausted",
        "ConfirmationJuryCapacityUnavailable",
        "RandomnessRedrawBudgetExhausted",
    }
    parsed = []
    for index, item in enumerate(value):
        context = f"body_states[{index}]"
        state = _exact(item, fields, context)
        if state["body"] != required_bodies[index]["body"]:
            raise ValueError(f"{context}.body differs from required_bodies order")
        instance = state["body_instance_id"]
        status_value = state["status"]
        if (instance is None) != (status_value is None):
            raise TypeError(f"{context} must bind body_instance_id and status together")
        status = None
        if instance is not None:
            _id(instance, f"{context}.body_instance_id")
            status_record = _exact(
                status_value,
                {"status", "phase"}
                if isinstance(status_value, Mapping)
                and status_value.get("status") == "Deliberating"
                else {"status"},
                f"{context}.status",
            )
            status = _text(status_record["status"], f"{context}.status.status")
            if status not in statuses:
                raise TypeError(f"{context}.status is unknown")
            if status == "Deliberating":
                _tagged_unit(
                    status_record["phase"], "phase", phases, f"{context}.status.phase"
                )
        schedule = (
            state["public_finding_opened_at_height"],
            state["public_finding_phase_blocks"],
            state["public_finding_deadline_height"],
        )
        if any(item is None for item in schedule) != all(item is None for item in schedule):
            raise TypeError(f"{context} must expose the complete public-finding schedule")
        if schedule[0] is not None:
            opened = _uint(schedule[0], f"{context}.public_finding_opened_at_height")
            span = _uint(
                schedule[1], f"{context}.public_finding_phase_blocks", minimum=1
            )
            deadline = _uint(schedule[2], f"{context}.public_finding_deadline_height")
            if opened + span != deadline:
                raise ValueError(f"{context} public-finding deadline is inconsistent")
        no_result = (state["no_result_kind"], state["no_result_height"])
        if (no_result[0] is None) != (no_result[1] is None):
            raise TypeError(f"{context} must bind no-result kind and height together")
        if no_result[0] is not None:
            _tagged_unit(no_result[0], "reason", no_results, f"{context}.no_result_kind")
            _uint(no_result[1], f"{context}.no_result_height")
            if status != "NoResult":
                raise ValueError(f"{context} no-result facts require NoResult status")
        progress = (
            None
            if state["timed_ovn_progress"] is None
            else _parse_timed_ovn_progress(
                state["timed_ovn_progress"], f"{context}.timed_ovn_progress"
            )
        )
        private_body = state["body"] in {"policy-jury", "confirmation-jury"}
        if progress is not None and (not private_body or instance is None):
            raise TypeError(
                f"{context}.timed_ovn_progress requires an active private body"
            )
        parsed.append(
            {
                "body": state["body"],
                "body_instance_id": instance,
                "status": status,
                "timed_ovn_progress": progress,
            }
        )
    return tuple(parsed)


def _parse_timed_ovn_progress(
    value: Any, context: str
) -> ParliamentTimedOvnProgressProjectionV1:
    record = _exact(
        value,
        {
            "ballot_attempt_id",
            "status",
            "frozen_survivor_count",
            "accepted_ballot_prefix_count",
        },
        context,
    )
    ballot_attempt_id = _id(record["ballot_attempt_id"], f"{context}.ballot_attempt_id")
    status = _tagged_unit(
        record["status"],
        "status",
        {
            "Registration",
            "SurvivorFreeze",
            "TimedCommitment",
            "AwaitingRelease",
            "Opening",
            "Finalized",
            "NoResult",
            "Superseded",
        },
        f"{context}.status",
    )
    survivors_value = record["frozen_survivor_count"]
    prefix_value = record["accepted_ballot_prefix_count"]
    if (survivors_value is None) != (prefix_value is None):
        raise TypeError(f"{context} survivor and prefix counts must appear together")
    if survivors_value is None:
        if status not in {"Registration", "SurvivorFreeze", "NoResult", "Superseded"}:
            raise ValueError(f"{context} must expose counts after survivor freeze")
        survivors = None
        prefix = None
    else:
        survivors = _uint(
            survivors_value,
            f"{context}.frozen_survivor_count",
            PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
            minimum=1,
        )
        prefix = _uint(
            prefix_value,
            f"{context}.accepted_ballot_prefix_count",
            survivors,
        )
        if status == "TimedCommitment" and prefix >= survivors:
            raise ValueError(f"{context} TimedCommitment prefix must remain incomplete")
        if status in {"AwaitingRelease", "Opening", "Finalized"} and prefix != survivors:
            raise ValueError(f"{context} sealed/released prefix must equal frozen survivors")
        if status in {"Registration", "SurvivorFreeze"}:
            raise ValueError(f"{context} exposes counts before survivor freeze")
    return ParliamentTimedOvnProgressProjectionV1(
        ballot_attempt_id=ballot_attempt_id,
        status=status,
        frozen_survivor_count=survivors,
        accepted_ballot_prefix_count=prefix,
    )


def _validate_expected_head(value: Any, context: str) -> None:
    record = _exact(value, {"state", "head"}, context)
    state = _text(record["state"], f"{context}.state")
    if state == "Absent":
        head = _exact(record["head"], {"subject_id"}, f"{context}.head")
    elif state == "Present":
        head = _exact(
            record["head"],
            {"subject_id", "version", "head_root"},
            f"{context}.head",
        )
        _uint(head["version"], f"{context}.head.version", minimum=1)
        _bytes(head["head_root"], 32, f"{context}.head.head_root", nonzero=True)
    else:
        raise TypeError(f"{context}.state must be Absent or Present")
    _bytes(head["subject_id"], 32, f"{context}.head.subject_id", nonzero=True)


def _validate_public_finding_binding(
    value: Any,
    *,
    original_seats: int,
    context: str,
) -> None:
    record = _exact(
        value,
        {"endorsement_root", "endorsing_assignments", "endorsements", "quorum"},
        context,
    )
    _bytes(
        record["endorsement_root"],
        32,
        f"{context}.endorsement_root",
        nonzero=True,
    )
    assignments = _strict_id_list(
        record["endorsing_assignments"], f"{context}.endorsing_assignments"
    )
    endorsements = _uint(
        record["endorsements"],
        f"{context}.endorsements",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    quorum = _uint(
        record["quorum"],
        f"{context}.quorum",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    expected_quorum = (2 * original_seats + 2) // 3
    if quorum != expected_quorum:
        raise ValueError(f"{context}.quorum differs from the immutable seat quorum")
    if endorsements != quorum or len(assignments) != endorsements:
        raise ValueError(
            f"{context}.endorsements must equal quorum and the assignment count"
        )


def _validate_ballot_binding(
    value: Any,
    *,
    original_seats: int,
    result_height: int,
    context: str,
) -> Dict[str, Any]:
    fields = {
        "ballot_attempt_id",
        "ballot_attempt_sequence",
        "tle_session_id",
        "tle_key_session_id",
        "registration_root",
        "dropout_root",
        "survivor_root",
        "corpus_root",
        "no_recovery_root",
        "timed_commitment_root",
        "release_beacon_session_id",
        "registered_at_height",
        "registration_close_height",
        "survivor_freeze_height",
        "commitment_close_height",
        "registration_closed_at_height",
        "survivors_frozen_at_height",
        "commitment_closed_at_height",
        "max_ballot_retries",
        "max_corpus_entries",
        "release_height",
        "opening_deadline_height",
        "release_pulse_id",
        "opening_height",
        "opening_root",
        "tally",
        "outcome",
    }
    record = _exact(value, fields, context)
    ballot_attempt_id = _id(
        record["ballot_attempt_id"], f"{context}.ballot_attempt_id"
    )
    ballot_attempt_sequence = _uint(
        record["ballot_attempt_sequence"],
        f"{context}.ballot_attempt_sequence",
        _U32_MAX,
    )
    tle_session_id = _id(record["tle_session_id"], f"{context}.tle_session_id")
    _id(record["tle_key_session_id"], f"{context}.tle_key_session_id")
    release_beacon_session_id = _id(
        record["release_beacon_session_id"],
        f"{context}.release_beacon_session_id",
    )
    release_pulse_id = _id(
        record["release_pulse_id"], f"{context}.release_pulse_id"
    )
    for field in (
        "registration_root",
        "dropout_root",
        "survivor_root",
        "corpus_root",
        "no_recovery_root",
        "timed_commitment_root",
        "opening_root",
    ):
        _bytes(record[field], 32, f"{context}.{field}", nonzero=True)

    heights = {
        field: _uint(record[field], f"{context}.{field}", minimum=1)
        for field in (
            "registered_at_height",
            "registration_close_height",
            "survivor_freeze_height",
            "commitment_close_height",
            "registration_closed_at_height",
            "survivors_frozen_at_height",
            "commitment_closed_at_height",
            "release_height",
            "opening_deadline_height",
            "opening_height",
        )
    }
    if not (
        heights["registered_at_height"]
        < heights["registration_close_height"]
        < heights["survivor_freeze_height"]
        < heights["commitment_close_height"]
        < heights["release_height"]
        < heights["opening_deadline_height"]
    ):
        raise ValueError(f"{context} lifecycle heights are not strictly ordered")
    if (
        heights["registration_closed_at_height"]
        != heights["registration_close_height"]
        or heights["survivors_frozen_at_height"]
        != heights["survivor_freeze_height"]
        or heights["commitment_closed_at_height"]
        <= heights["survivor_freeze_height"]
        or heights["commitment_closed_at_height"]
        > heights["commitment_close_height"]
    ):
        raise ValueError(f"{context} consensus close heights are outside their slots")
    if not (
        heights["release_height"]
        <= heights["opening_height"]
        <= heights["opening_deadline_height"]
    ) or not (
        heights["opening_height"] <= result_height <= heights["opening_deadline_height"]
    ):
        raise ValueError(f"{context} opening/result heights are outside the release window")

    max_ballot_retries = _uint(
        record["max_ballot_retries"],
        f"{context}.max_ballot_retries",
        16,
    )
    if ballot_attempt_sequence > max_ballot_retries:
        raise ValueError(f"{context}.ballot_attempt_sequence exceeds the retry budget")
    max_corpus_entries = _uint(
        record["max_corpus_entries"],
        f"{context}.max_corpus_entries",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    required_commitment_blocks = (
        max_corpus_entries + PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1 - 1
    ) // PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1
    if max_corpus_entries < original_seats:
        raise ValueError(f"{context}.max_corpus_entries is below original_seats")
    if (
        heights["registration_close_height"] - heights["registered_at_height"]
        < max_corpus_entries + 1
        or heights["survivor_freeze_height"]
        - heights["registration_close_height"]
        < max_corpus_entries
        or heights["commitment_close_height"]
        - heights["survivor_freeze_height"]
        < required_commitment_blocks
    ):
        raise ValueError(f"{context} frozen schedule cannot service its maximum corpus")
    tally = _exact(
        record["tally"],
        {"original_seats", "accepted_ballots", "aye", "nay", "abstain"},
        f"{context}.tally",
    )
    tally_original_seats = _uint(
        tally["original_seats"],
        f"{context}.tally.original_seats",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    accepted_ballots = _uint(
        tally["accepted_ballots"],
        f"{context}.tally.accepted_ballots",
        PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
    )
    aye = _uint(tally["aye"], f"{context}.tally.aye", _U32_MAX)
    nay = _uint(tally["nay"], f"{context}.tally.nay", _U32_MAX)
    abstain = _uint(tally["abstain"], f"{context}.tally.abstain", _U32_MAX)
    if tally_original_seats != original_seats:
        raise ValueError(f"{context}.tally.original_seats differs from the body binding")
    if accepted_ballots > max_corpus_entries or accepted_ballots > original_seats:
        raise ValueError(f"{context}.tally.accepted_ballots exceeds an immutable bound")
    if aye + nay + abstain != accepted_ballots:
        raise ValueError(f"{context}.tally option counts do not conserve accepted ballots")
    outcome = _tagged_unit(
        record["outcome"],
        "outcome",
        {"Approved", "Rejected", "NoQuorum", "NoResult"},
        f"{context}.outcome",
    )
    quorum = (2 * original_seats + 2) // 3
    expected_outcome = (
        "NoQuorum"
        if accepted_ballots < quorum
        else "Approved"
        if aye > nay
        else "Rejected"
    )
    if outcome != expected_outcome:
        raise ValueError(f"{context}.outcome differs from the deterministic tally")
    if outcome != "Approved":
        raise ValueError(f"{context} is not an approving certificate ballot")
    return {
        "ballot_attempt_id": ballot_attempt_id,
        "tle_session_id": tle_session_id,
        "release_beacon_session_id": release_beacon_session_id,
        "release_height": heights["release_height"],
        "release_pulse_id": release_pulse_id,
        "accepted_ballots": accepted_ballots,
        "aye": aye,
        "nay": nay,
    }


def _validate_certificate_outer(
    value: Any,
    *,
    attempt: Mapping[str, Any],
    policy_version: int,
    required_bodies: Sequence[Mapping[str, Any]],
    body_states: Sequence[Mapping[str, Any]],
) -> None:
    # Typed identifiers and commitment roots are admitted here as canonical,
    # nonzero wire values. Their Norito-derived content hashes remain opaque to
    # the Python boundary; every directly repeated field is still exact-bound.
    record = _exact(
        value,
        {
            "proposal_content_id",
            "governance_attempt_id",
            "governance_attempt_sequence",
            "risk_tier",
            "body_bindings",
            "policy_version",
            "effect_preimage_hash",
            "expected_head",
            "certified_at_height",
            "enact_at_height",
        },
        "certificate",
    )
    if _id(record["proposal_content_id"], "certificate.proposal_content_id") != attempt[
        "proposal_content_id"
    ]:
        raise ValueError("certificate proposal_content_id differs from attempt")
    if _id(record["governance_attempt_id"], "certificate.governance_attempt_id") != attempt[
        "id"
    ]:
        raise ValueError("certificate governance_attempt_id differs from attempt")
    if (
        _uint(
            record["governance_attempt_sequence"],
            "certificate.governance_attempt_sequence",
            PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
        )
        != attempt["sequence"]
    ):
        raise ValueError("certificate governance_attempt_sequence differs from attempt")
    certificate_risk_tier = _tagged_unit(
        record["risk_tier"],
        "tier",
        _RISK_TIERS,
        "certificate.risk_tier",
    )
    if certificate_risk_tier != attempt["risk_tier"]["tier"]:
        raise ValueError("certificate risk_tier differs from attempt")
    certificate_policy_version = _uint(
        record["policy_version"], "certificate.policy_version", minimum=1
    )
    if certificate_policy_version != _PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1:
        raise ValueError("certificate policy_version is not first-release Parliament V1")
    if certificate_policy_version != policy_version:
        raise ValueError("certificate policy_version differs from the attempt projection")
    _bytes(
        record["effect_preimage_hash"],
        32,
        "certificate.effect_preimage_hash",
        nonzero=True,
    )
    _validate_expected_head(record["expected_head"], "certificate.expected_head")
    certified = _uint(
        record["certified_at_height"], "certificate.certified_at_height", minimum=1
    )
    enacted = _uint(record["enact_at_height"], "certificate.enact_at_height", minimum=1)
    if enacted <= certified:
        raise ValueError("certificate enact_at_height must follow certified_at_height")
    bindings = record["body_bindings"]
    if not isinstance(bindings, list) or len(bindings) != len(required_bodies):
        raise TypeError("certificate.body_bindings must match required_bodies exactly")
    binding_fields = {
        "body_instance_id",
        "election_attempt_id",
        "election_attempt_sequence",
        "sortition_request_id",
        "sortition_request",
        "body",
        "original_seats",
        "beacon_session_id",
        "beacon_pulse_id",
        "roster_root",
        "assignment_root",
        "result_root",
        "result_height",
        "public_finding",
        "ballot",
    }
    seen_body_instance_ids: set[str] = set()
    seen_election_attempt_ids: set[str] = set()
    seen_sortition_request_ids: set[str] = set()
    seen_ballot_attempt_ids: set[str] = set()
    seen_tle_session_ids: set[str] = set()
    seen_release_pulse_ids: set[str] = set()
    seen_release_slots: set[Tuple[str, int]] = set()
    sortition_pulse_ids: set[str] = set()
    policy_binding: Optional[Dict[str, Any]] = None
    confirmation_binding: Optional[Dict[str, Any]] = None
    latest_body_result_height = 0
    for index, item in enumerate(bindings):
        context = f"certificate.body_bindings[{index}]"
        binding = _exact(item, binding_fields, context)
        body = _text(binding["body"], f"{context}.body")
        if body != required_bodies[index]["body"]:
            raise ValueError(f"{context}.body differs from required_bodies order")
        body_instance_id = _id(
            binding["body_instance_id"], f"{context}.body_instance_id"
        )
        if body_instance_id != body_states[index]["body_instance_id"]:
            raise ValueError(f"{context}.body_instance_id differs from body_states")
        election_attempt_id = _id(
            binding["election_attempt_id"], f"{context}.election_attempt_id"
        )
        sortition_request_id = _id(
            binding["sortition_request_id"], f"{context}.sortition_request_id"
        )
        beacon_session_id = _id(
            binding["beacon_session_id"], f"{context}.beacon_session_id"
        )
        beacon_pulse_id = _id(
            binding["beacon_pulse_id"], f"{context}.beacon_pulse_id"
        )
        for identifier, seen, field in (
            (body_instance_id, seen_body_instance_ids, "body_instance_id"),
            (election_attempt_id, seen_election_attempt_ids, "election_attempt_id"),
            (sortition_request_id, seen_sortition_request_ids, "sortition_request_id"),
        ):
            if identifier in seen:
                raise ValueError(f"certificate.body_bindings reuses {field}")
            seen.add(identifier)
        sortition_pulse_ids.add(beacon_pulse_id)
        election_attempt_sequence = _uint(
            binding["election_attempt_sequence"],
            f"{context}.election_attempt_sequence",
            _PARLIAMENT_SORTITION_RETRIES_MAX_V1,
        )
        original_seats = _uint(
            binding["original_seats"],
            f"{context}.original_seats",
            PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
            minimum=1,
        )
        for field in ("roster_root", "assignment_root", "result_root"):
            _bytes(binding[field], 32, f"{context}.{field}", nonzero=True)
        result_height = _uint(
            binding["result_height"], f"{context}.result_height", minimum=1
        )
        latest_body_result_height = max(latest_body_result_height, result_height)
        if result_height > certified:
            raise ValueError(f"{context}.result_height follows certificate finalization")
        request = _validate_sortition_request(
            binding["sortition_request"],
            expected_governance_attempt_id=attempt["id"],
            context=f"{context}.sortition_request",
        )
        if (
            request["id"] != sortition_request_id
            or request["body_election_attempt_id"] != election_attempt_id
            or request["body"] != body
            or request["beacon_session_id"] != beacon_session_id
        ):
            raise ValueError(f"{context}.sortition_request differs from its binding indexes")
        if (
            original_seats > request["target_seats"]
            or original_seats > request["candidate_count"]
        ):
            raise ValueError(f"{context}.original_seats exceeds its sortition bounds")
        if result_height <= request["pulse_height"]:
            raise ValueError(f"{context}.result_height must follow the sortition pulse")

        decision_mode = required_bodies[index]["decision_mode"]["mode"]
        expects_ballot = decision_mode == "HiddenBindingBallot"
        if expects_ballot != (body in {"policy-jury", "confirmation-jury"}):
            raise ValueError(f"{context} decision mode is invalid for the body role")
        if expects_ballot:
            if binding["public_finding"] is not None or binding["ballot"] is None:
                raise TypeError(f"{context} must carry only a hidden ballot binding")
            ballot = _validate_ballot_binding(
                binding["ballot"],
                original_seats=original_seats,
                result_height=result_height,
                context=f"{context}.ballot",
            )
            progress = body_states[index]["timed_ovn_progress"]
            if (
                progress is None
                or progress.status != "Finalized"
                or progress.ballot_attempt_id != ballot["ballot_attempt_id"]
                or progress.frozen_survivor_count != ballot["accepted_ballots"]
                or progress.accepted_ballot_prefix_count != ballot["accepted_ballots"]
            ):
                raise ValueError(f"{context}.ballot differs from timed_ovn_progress")
            for identifier, seen, field in (
                (
                    ballot["ballot_attempt_id"],
                    seen_ballot_attempt_ids,
                    "ballot_attempt_id",
                ),
                (ballot["tle_session_id"], seen_tle_session_ids, "tle_session_id"),
                (
                    ballot["release_pulse_id"],
                    seen_release_pulse_ids,
                    "release_pulse_id",
                ),
            ):
                if identifier in seen:
                    raise ValueError(f"certificate.body_bindings reuses {field}")
                seen.add(identifier)
            release_slot = (
                ballot["release_beacon_session_id"],
                ballot["release_height"],
            )
            if release_slot in seen_release_slots:
                raise ValueError("certificate.body_bindings reuses a TLE release slot")
            seen_release_slots.add(release_slot)
            private_binding = {
                "election_attempt_sequence": election_attempt_sequence,
                "request_height": request["request_height"],
                "result_height": result_height,
                "beacon_session_id": beacon_session_id,
                "beacon_pulse_id": beacon_pulse_id,
                "ballot": ballot,
            }
            if body == "policy-jury":
                if policy_binding is not None:
                    raise ValueError("certificate contains more than one policy-jury")
                policy_binding = private_binding
            elif body == "confirmation-jury":
                if confirmation_binding is not None:
                    raise ValueError("certificate contains more than one confirmation-jury")
                confirmation_binding = private_binding
        else:
            if body_states[index]["timed_ovn_progress"] is not None:
                raise ValueError(f"{context} public body exposes timed_ovn_progress")
            if binding["public_finding"] is None or binding["ballot"] is not None:
                raise TypeError(f"{context} must carry only a public-finding binding")
            _validate_public_finding_binding(
                binding["public_finding"],
                original_seats=original_seats,
                context=f"{context}.public_finding",
            )
    if not sortition_pulse_ids.isdisjoint(seen_release_pulse_ids):
        raise ValueError("certificate reuses a sortition pulse for ballot release")
    if certified != latest_body_result_height:
        raise ValueError(
            "certificate.certified_at_height must equal the latest body result height"
        )
    if policy_binding is None:
        raise ValueError("certificate must contain exactly one approving policy-jury ballot")
    policy_ballot = policy_binding["ballot"]
    decisive = policy_ballot["aye"] + policy_ballot["nay"]
    requires_confirmation = (
        decisive > 0
        and abs(policy_ballot["aye"] - policy_ballot["nay"]) * 100 < decisive * 5
    )
    if requires_confirmation != (confirmation_binding is not None):
        raise ValueError(
            "certificate confirmation-jury presence differs from the policy margin"
        )
    if confirmation_binding is not None:
        initial_attempt = confirmation_binding["election_attempt_sequence"] == 0
        request_height = confirmation_binding["request_height"]
        policy_result_height = policy_binding["result_height"]
        valid_request_height = (
            request_height == policy_result_height
            if initial_attempt
            else request_height > policy_result_height
        )
        fresh_pulse = (
            confirmation_binding["beacon_pulse_id"]
            != policy_binding["beacon_pulse_id"]
        )
        if not valid_request_height or not fresh_pulse:
            raise ValueError(
                "certificate confirmation-jury request height must match the atomic "
                "initial request or follow it on retry, with a fresh pulse"
            )


def _parse_attempt_read(value: Any, expected_attempt_id: str) -> ParliamentAttemptReadResponseV1:
    fields = {
        "version",
        "current_height",
        "attempt",
        "policy_version",
        "required_bodies",
        "body_states",
        "certificate",
        "terminal_height",
        "execution_failure_root",
        "superseding_head",
        "state_payload_hex",
    }
    record = _exact(value, fields, "Parliament attempt read response")
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("unsupported Parliament attempt read response version")
    current_height = _uint(record["current_height"], "current_height", minimum=1)
    policy_version = _uint(record["policy_version"], "policy_version", minimum=1)
    if policy_version != _PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1:
        raise TypeError("policy_version is not first-release Parliament V1")
    attempt = _exact(
        record["attempt"],
        {"id", "proposal_content_id", "sequence", "risk_tier", "stage", "status"},
        "attempt",
    )
    attempt_id = _id(attempt["id"], "attempt.id")
    if attempt_id != _id(expected_attempt_id, "expected_governance_attempt_id"):
        raise ValueError("attempt.id differs from the requested canonical identifier")
    _id(attempt["proposal_content_id"], "attempt.proposal_content_id")
    _uint(
        attempt["sequence"],
        "attempt.sequence",
        PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
    )
    _tagged_unit(
        attempt["risk_tier"],
        "tier",
        {"Routine", "Standard", "Constitutional", "Emergency"},
        "attempt.risk_tier",
    )
    _tagged_unit(
        attempt["stage"],
        "stage",
        {
            "Qualification",
            "Rules",
            "Agenda",
            "Interest",
            "Review",
            "Coordination",
            "Mpc",
            "Fma",
            "Oversight",
            "PolicyJury",
            "ConfirmationJury",
            "Certification",
            "Enactment",
        },
        "attempt.stage",
    )
    _tagged_unit(
        attempt["status"],
        "status",
        {"Active", "Certified", "Rejected", "Enacted", "Superseded", "ExecutionFailed"},
        "attempt.status",
    )
    required = record["required_bodies"]
    if not isinstance(required, list) or not 1 <= len(required) <= 10:
        raise TypeError("required_bodies must contain one through ten projections")
    body_indices = []
    for index, item in enumerate(required):
        projection = _exact(item, {"body", "decision_mode"}, f"required_bodies[{index}]")
        body = _text(projection["body"], f"required_bodies[{index}].body")
        if body not in _BODY_ORDER:
            raise TypeError(f"required_bodies[{index}].body is unknown")
        body_indices.append(_BODY_ORDER.index(body))
        decision_mode = _tagged_unit(
            projection["decision_mode"],
            "mode",
            {"PublicFinding", "HiddenBindingBallot"},
            f"required_bodies[{index}].decision_mode",
        )
        expected_mode = (
            "HiddenBindingBallot"
            if body in {"policy-jury", "confirmation-jury"}
            else "PublicFinding"
        )
        if decision_mode != expected_mode:
            raise ValueError(
                f"required_bodies[{index}].decision_mode differs from the body protocol"
            )
    if any(left >= right for left, right in zip(body_indices, body_indices[1:])):
        raise TypeError("required_bodies must use strict canonical body order")
    body_states = _parse_body_states(record["body_states"], required)
    if record["terminal_height"] is not None:
        _uint(record["terminal_height"], "terminal_height", minimum=1)
    if record["execution_failure_root"] is not None:
        _bytes(record["execution_failure_root"], 32, "execution_failure_root", nonzero=True)
    if record["certificate"] is not None:
        _validate_certificate_outer(
            record["certificate"],
            attempt=attempt,
            policy_version=policy_version,
            required_bodies=required,
            body_states=body_states,
        )
    if record["superseding_head"] is not None:
        _validate_expected_head(record["superseding_head"], "superseding_head")
    state_hex = _lower_hex(
        record["state_payload_hex"],
        "state_payload_hex",
        maximum_bytes=PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1,
    )
    state_payload = bytes.fromhex(state_hex)
    validate_opaque_norito_frame(
        state_payload,
        context="Parliament attempt state_payload_hex",
    )
    return ParliamentAttemptReadResponseV1(
        governance_attempt_id=attempt_id,
        current_height=current_height,
        policy_version=policy_version,
        timed_ovn_progress=tuple(
            state["timed_ovn_progress"] for state in body_states
        ),
        state_payload=state_payload,
        raw=dict(record),
    )


def _parse_tle_key_session(value: Any) -> ParliamentTleKeySessionPublicStateV1:
    fields = {
        "version",
        "key_session_id",
        "network_id",
        "roster_hash",
        "committee_size",
        "threshold",
        "generator_h",
        "generator_v",
        "qualified_dealers",
        "qualified_dealer_commitments",
        "dkg_event_hash",
        "group_public_key",
        "public_shares",
        "transcript_hash",
    }
    record = _exact(value, fields, "tle_key_session")
    if (
        _uint(record["version"], "tle_key_session.version", _U16_MAX)
        != PARLIAMENT_API_VERSION_V1
    ):
        raise TypeError("unsupported Parliament TLE key-session version")
    key_session_id = _id(record["key_session_id"], "tle_key_session.key_session_id")
    network_id = _bytes(record["network_id"], 32, "tle_key_session.network_id", nonzero=True)
    roster_hash = _bytes(record["roster_hash"], 32, "tle_key_session.roster_hash", nonzero=True)
    generator_h = _bytes(record["generator_h"], 96, "tle_key_session.generator_h", nonzero=True)
    generator_v = _bytes(record["generator_v"], 96, "tle_key_session.generator_v", nonzero=True)
    dkg_event_hash = _bytes(
        record["dkg_event_hash"], 32, "tle_key_session.dkg_event_hash", nonzero=True
    )
    group_public_key = _bytes(
        record["group_public_key"],
        96,
        "tle_key_session.group_public_key",
        nonzero=True,
    )
    transcript_hash = _bytes(
        record["transcript_hash"], 32, "tle_key_session.transcript_hash", nonzero=True
    )
    committee_size = _uint(
        record["committee_size"],
        "tle_key_session.committee_size",
        PARLIAMENT_TLE_MAX_COMMITTEE_SIZE_V1,
        minimum=4,
    )
    threshold = _uint(record["threshold"], "tle_key_session.threshold", 11, minimum=2)
    if (committee_size - 1) % 3 != 0 or threshold != (committee_size - 1) // 3 + 1:
        raise ValueError(
            "tle_key_session committee_size/threshold is not an exact 3f+1/f+1 profile"
        )
    dealers = record["qualified_dealers"]
    if not isinstance(dealers, list) or not threshold <= len(dealers) <= committee_size:
        raise ValueError("qualified_dealers violates the threshold/committee bound")
    dealer_indices = tuple(
        _uint(item, f"qualified_dealers[{index}]", committee_size, minimum=1)
        for index, item in enumerate(dealers)
    )
    if any(left >= right for left, right in zip(dealer_indices, dealer_indices[1:])):
        raise TypeError("qualified_dealers must be strictly increasing")
    commitments = record["qualified_dealer_commitments"]
    if not isinstance(commitments, list) or len(commitments) != len(dealer_indices):
        raise TypeError("qualified_dealer_commitments must align with qualified_dealers")
    for index, item in enumerate(commitments):
        dealer = _exact(
            item,
            {
                "dealer_index",
                "coefficient_commitments",
                "constant_pok_commitment",
                "constant_pok_response",
            },
            f"qualified_dealer_commitments[{index}]",
        )
        if (
            _uint(
                dealer["dealer_index"],
                f"qualified_dealer_commitments[{index}].dealer_index",
                committee_size,
                minimum=1,
            )
            != dealer_indices[index]
        ):
            raise ValueError("dealer commitment index differs from qualified_dealers")
        coefficients = dealer["coefficient_commitments"]
        if not isinstance(coefficients, list) or len(coefficients) != threshold:
            raise TypeError("dealer coefficient commitments must contain exactly threshold entries")
        for coefficient_index, coefficient in enumerate(coefficients):
            _bytes(
                coefficient,
                96,
                f"qualified_dealer_commitments[{index}].coefficient_commitments[{coefficient_index}]",
                nonzero=True,
            )
        _bytes(
            dealer["constant_pok_commitment"],
            96,
            f"qualified_dealer_commitments[{index}].constant_pok_commitment",
            nonzero=True,
        )
        _bytes(
            dealer["constant_pok_response"],
            32,
            f"qualified_dealer_commitments[{index}].constant_pok_response",
        )
    shares = record["public_shares"]
    if not isinstance(shares, list) or len(shares) != committee_size:
        raise TypeError("public_shares must contain the complete ordered committee")
    participant_hashes = set()
    for offset, item in enumerate(shares):
        share = _exact(
            item,
            {"index", "participant_hash", "public_key_share"},
            f"public_shares[{offset}]",
        )
        if (
            _uint(share["index"], f"public_shares[{offset}].index", committee_size, minimum=1)
            != offset + 1
        ):
            raise TypeError("public_shares must use the exact one-based sequence")
        participant_hash = _bytes(
            share["participant_hash"],
            32,
            f"public_shares[{offset}].participant_hash",
            nonzero=True,
        )
        if participant_hash in participant_hashes:
            raise TypeError("public_shares must bind distinct participant hashes")
        participant_hashes.add(participant_hash)
        _bytes(
            share["public_key_share"],
            96,
            f"public_shares[{offset}].public_key_share",
            nonzero=True,
        )
    # Keep generator validation explicit even though selected fields are not
    # surfaced individually by the compact Python DTO.
    if not generator_h or not generator_v or not dkg_event_hash:
        raise AssertionError("validated non-empty public transcript fields")
    return ParliamentTleKeySessionPublicStateV1(
        key_session_id=key_session_id,
        network_id=network_id,
        roster_hash=roster_hash,
        committee_size=committee_size,
        threshold=threshold,
        group_public_key=group_public_key,
        transcript_hash=transcript_hash,
        raw=dict(record),
    )


def _parse_release_identity(
    value: Any, context: str = "release_identity"
) -> ParliamentTimedOvnReleaseIdentityProjectionV1:
    record = _exact(
        value,
        {
            "tle_key_session_id",
            "governance_attempt_id",
            "body_instance_id",
            "ballot_attempt_id",
            "survivor_corpus_root",
            "no_recovery_root",
            "target_finalized_height",
            "parameter_hash",
        },
        context,
    )
    return ParliamentTimedOvnReleaseIdentityProjectionV1(
        tle_key_session_id=_id(record["tle_key_session_id"], f"{context}.tle_key_session_id"),
        governance_attempt_id=_id(
            record["governance_attempt_id"], f"{context}.governance_attempt_id"
        ),
        body_instance_id=_id(record["body_instance_id"], f"{context}.body_instance_id"),
        ballot_attempt_id=_id(record["ballot_attempt_id"], f"{context}.ballot_attempt_id"),
        survivor_corpus_root=_bytes(
            record["survivor_corpus_root"],
            32,
            f"{context}.survivor_corpus_root",
            nonzero=True,
        ),
        no_recovery_root=_bytes(
            record["no_recovery_root"], 32, f"{context}.no_recovery_root", nonzero=True
        ),
        target_finalized_height=_uint(
            record["target_finalized_height"], f"{context}.target_finalized_height", minimum=1
        ),
        parameter_hash=_bytes(
            record["parameter_hash"], 32, f"{context}.parameter_hash", nonzero=True
        ),
    )


def _canonical_base64(value: Any, maximum: int, context: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{context} must be non-empty canonical padded standard base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise TypeError(f"{context} must be canonical padded standard base64") from exc
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{context} exceeds its byte bound or is not canonical base64")
    return decoded


def _parse_casting_context(
    value: Any, expected_ballot_attempt_id: str, expected_network_id: str
) -> ParliamentTimedOvnCastingContextResponseV1:
    fields = {
        "version",
        "current_height",
        "phase",
        "session",
        "registration_opened_at_finalized_height",
        "target_finalized_height",
        "tle_key_session",
        "registration_records_hex",
        "survivor_participant_hashes",
        "release_identity",
        "archive_norito_base64",
    }
    record = _exact(value, fields, "Parliament timed-OVN casting-context response")
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("unsupported Parliament timed-OVN casting-context version")
    current_height = _uint(record["current_height"], "current_height", minimum=1)
    phase = _text(record["phase"], "phase")
    if phase not in {"Registered", "RegistrationClosed", "SurvivorsFrozen"}:
        raise TypeError("phase is not a cast-capable timed-OVN phase")
    session = _exact(
        record["session"],
        {
            "network_id",
            "proposal_content_id",
            "governance_attempt_id",
            "body_instance_id",
            "ballot_attempt_id",
            "parameter_hash",
            "tle_key_session_id",
            "tle_key_transcript_hash",
            "tle_master_public_key",
        },
        "session",
    )
    session_network_id = _bytes(
        session["network_id"], 32, "session.network_id", nonzero=True
    )
    if session_network_id != bytes.fromhex(expected_network_id[5:69]):
        raise ValueError("session.network_id differs from canonical auth")
    _id(session["proposal_content_id"], "session.proposal_content_id")
    governance_attempt_id = _id(session["governance_attempt_id"], "session.governance_attempt_id")
    body_instance_id = _id(session["body_instance_id"], "session.body_instance_id")
    ballot_attempt_id = _id(session["ballot_attempt_id"], "session.ballot_attempt_id")
    if ballot_attempt_id != _id(expected_ballot_attempt_id, "expected_ballot_attempt_id"):
        raise ValueError("session.ballot_attempt_id differs from the requested identifier")
    parameter_hash = _bytes(session["parameter_hash"], 32, "session.parameter_hash", nonzero=True)
    session_key_id = _id(session["tle_key_session_id"], "session.tle_key_session_id")
    session_transcript = _bytes(
        session["tle_key_transcript_hash"], 32, "session.tle_key_transcript_hash", nonzero=True
    )
    session_master_key = _bytes(
        session["tle_master_public_key"], 96, "session.tle_master_public_key", nonzero=True
    )
    registration_opened = _uint(
        record["registration_opened_at_finalized_height"],
        "registration_opened_at_finalized_height",
        minimum=1,
    )
    target_height = _uint(record["target_finalized_height"], "target_finalized_height", minimum=1)
    if registration_opened > current_height or target_height <= registration_opened:
        raise ValueError("casting-context height schedule is inconsistent")
    key_session = _parse_tle_key_session(record["tle_key_session"])
    if (
        key_session.key_session_id != session_key_id
        or key_session.network_id != session_network_id
        or key_session.transcript_hash != session_transcript
        or key_session.group_public_key != session_master_key
    ):
        raise ValueError("timed-OVN session differs from its public TLE transcript")
    registration_records = record["registration_records_hex"]
    if (
        not isinstance(registration_records, list)
        or len(registration_records) > PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1
        or (phase != "Registered" and not registration_records)
    ):
        raise ValueError("registration_records_hex violates the casting-phase bound")
    canonical_records = tuple(
        _lower_hex(item, f"registration_records_hex[{index}]")
        for index, item in enumerate(registration_records)
    )
    if any(
        len(item) != PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 * 2
        for item in canonical_records
    ) or len(set(canonical_records)) != len(canonical_records):
        raise TypeError("registration_records_hex is not an exact unique canonical corpus")
    if phase == "SurvivorsFrozen":
        survivors = record["survivor_participant_hashes"]
        if (
            not isinstance(survivors, list)
            or not survivors
            or len(survivors) > len(canonical_records)
            or record["release_identity"] is None
        ):
            raise TypeError("SurvivorsFrozen requires bounded survivor hashes and release identity")
        decoded_survivors = tuple(
            _bytes(item, 32, f"survivor_participant_hashes[{index}]", nonzero=True)
            for index, item in enumerate(survivors)
        )
        if len(set(decoded_survivors)) != len(decoded_survivors):
            raise TypeError("survivor participant hashes must be unique")
        release = _parse_release_identity(record["release_identity"])
        if (
            release.tle_key_session_id != session_key_id
            or release.governance_attempt_id != governance_attempt_id
            or release.body_instance_id != body_instance_id
            or release.ballot_attempt_id != ballot_attempt_id
            or release.target_finalized_height != target_height
            or release.parameter_hash != parameter_hash
        ):
            raise ValueError("frozen release identity differs from the timed-OVN session")
    elif record["survivor_participant_hashes"] is not None or record["release_identity"] is not None:
        raise TypeError("pre-freeze casting context must not expose frozen state")
    archive = _canonical_base64(
        record["archive_norito_base64"],
        PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1,
        "archive_norito_base64",
    )
    validate_opaque_norito_frame(
        archive, context="Parliament timed-OVN casting archive"
    )
    return ParliamentTimedOvnCastingContextResponseV1(
        current_height=current_height,
        phase=phase,
        ballot_attempt_id=ballot_attempt_id,
        key_session=key_session,
        archive_norito=archive,
        raw=dict(record),
    )


def _validate_release_identity_payload(
    payload: bytes,
    *,
    governance_attempt_id: str,
    body_instance_id: str,
    ballot_attempt_id: str,
    release_identity: ParliamentTimedOvnReleaseIdentityProjectionV1,
    release_height: int,
) -> None:
    domain = b"iroha.parliament.tle.identity-payload.v1\0"
    if len(payload) != 243 or not payload.startswith(domain):
        raise TypeError("identity_payload_hex has the wrong domain or canonical width")
    offset = len(domain)
    if payload[offset : offset + 2] != (1).to_bytes(2, "big"):
        raise TypeError("identity payload version must equal one")
    offset += 2
    for expected, field in (
        (bytes.fromhex(governance_attempt_id), "governance_attempt_id"),
        (bytes.fromhex(body_instance_id), "body_instance_id"),
        (bytes.fromhex(ballot_attempt_id), "ballot_attempt_id"),
        (release_identity.survivor_corpus_root, "survivor_corpus_root"),
        (release_identity.no_recovery_root, "no_recovery_root"),
    ):
        if payload[offset : offset + 32] != expected:
            raise ValueError(f"identity payload {field} binding differs")
        offset += 32
    if payload[offset : offset + 8] != release_height.to_bytes(8, "big"):
        raise ValueError("identity payload release height differs")
    offset += 8
    if payload[offset : offset + 32] != release_identity.parameter_hash:
        raise ValueError("identity payload parameter_hash binding differs")


def _release_message_digest(
    key_session: ParliamentTleKeySessionPublicStateV1, identity_payload: bytes
) -> bytes:
    message = b"".join(
        (
            b"iroha.threshold-bls.message.v1\0",
            b"iroha.threshold-bls.session.v1\0",
            (1).to_bytes(2, "big"),
            bytes((2,)),
            key_session.network_id,
            bytes.fromhex(key_session.key_session_id),
            key_session.roster_hash,
            key_session.committee_size.to_bytes(2, "big"),
            key_session.threshold.to_bytes(2, "big"),
            len(identity_payload).to_bytes(4, "big"),
            identity_payload,
        )
    )
    return hashlib.sha256(message).digest()


def _parse_release_context(
    value: Any, expected_ballot_attempt_id: str, expected_network_id: str
) -> ParliamentTleReleaseContextResponseV1:
    record = _exact(
        value,
        {
            "version",
            "current_height",
            "ballot_attempt_id",
            "governance_attempt_id",
            "body_instance_id",
            "status",
            "release_height",
            "opening_deadline_height",
            "tle_key_session",
            "release_identity",
            "identity_digest",
            "identity_payload_hex",
        },
        "Parliament TLE release-context response",
    )
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("unsupported Parliament TLE release-context version")
    current_height = _uint(record["current_height"], "current_height", minimum=1)
    ballot_attempt_id = _id(record["ballot_attempt_id"], "ballot_attempt_id")
    if ballot_attempt_id != _id(expected_ballot_attempt_id, "expected_ballot_attempt_id"):
        raise ValueError("ballot_attempt_id differs from the requested identifier")
    governance_attempt_id = _id(record["governance_attempt_id"], "governance_attempt_id")
    body_instance_id = _id(record["body_instance_id"], "body_instance_id")
    _tagged_unit(record["status"], "status", {"Opening"}, "status")
    release_height = _uint(record["release_height"], "release_height", minimum=1)
    opening_deadline = _uint(
        record["opening_deadline_height"], "opening_deadline_height", minimum=1
    )
    if not release_height <= current_height <= opening_deadline:
        raise ValueError("TLE release context lies outside its inclusive opening window")
    key_session = _parse_tle_key_session(record["tle_key_session"])
    if key_session.network_id != bytes.fromhex(expected_network_id[5:69]):
        raise ValueError("tle_key_session.network_id differs from canonical auth")
    identity = _parse_release_identity(record["release_identity"])
    if (
        identity.tle_key_session_id != key_session.key_session_id
        or identity.governance_attempt_id != governance_attempt_id
        or identity.body_instance_id != body_instance_id
        or identity.ballot_attempt_id != ballot_attempt_id
        or identity.target_finalized_height != release_height
    ):
        raise ValueError("release_identity differs from the top-level Parliament/TLE bindings")
    identity_digest = _bytes(record["identity_digest"], 32, "identity_digest", nonzero=True)
    identity_payload_hex = _lower_hex(record["identity_payload_hex"], "identity_payload_hex")
    if len(identity_payload_hex) != 486:
        raise TypeError("identity_payload_hex must encode exactly 243 bytes")
    identity_payload = bytes.fromhex(identity_payload_hex)
    _validate_release_identity_payload(
        identity_payload,
        governance_attempt_id=governance_attempt_id,
        body_instance_id=body_instance_id,
        ballot_attempt_id=ballot_attempt_id,
        release_identity=identity,
        release_height=release_height,
    )
    if identity_digest != _release_message_digest(key_session, identity_payload):
        raise ValueError(
            "identity_digest differs from the threshold-session-framed release message"
        )
    return ParliamentTleReleaseContextResponseV1(
        current_height=current_height,
        ballot_attempt_id=ballot_attempt_id,
        governance_attempt_id=governance_attempt_id,
        body_instance_id=body_instance_id,
        release_height=release_height,
        opening_deadline_height=opening_deadline,
        key_session=key_session,
        release_identity=identity,
        identity_digest=identity_digest,
        identity_payload=identity_payload,
        raw=dict(record),
    )


def _parse_partial_release(
    value: Any,
    expected_context: ParliamentTleReleaseContextResponseV1,
) -> ParliamentTlePartialReleaseShareV1:
    record = _exact(
        value,
        {
            "key_session_id",
            "identity_digest",
            "participant_index",
            "sigma",
            "proof_x",
            "proof_y",
            "z_s",
            "z_r",
            "z_u",
        },
        "Parliament TLE partial release",
    )
    key_session_id = _id(record["key_session_id"], "key_session_id")
    if key_session_id != expected_context.key_session.key_session_id:
        raise ValueError("partial key_session_id differs from the authorized context")
    identity_digest = _bytes(record["identity_digest"], 32, "identity_digest", nonzero=True)
    if identity_digest != expected_context.identity_digest:
        raise ValueError("partial identity_digest differs from the authorized context")
    participant_index = _uint(
        record["participant_index"],
        "participant_index",
        expected_context.key_session.committee_size,
        minimum=1,
    )
    return ParliamentTlePartialReleaseShareV1(
        key_session_id=key_session_id,
        identity_digest=identity_digest,
        participant_index=participant_index,
        sigma=_bytes(record["sigma"], 48, "sigma", nonzero=True),
        proof_x=_bytes(record["proof_x"], 96, "proof_x", nonzero=True),
        proof_y=_bytes(record["proof_y"], 48, "proof_y", nonzero=True),
        z_s=_bytes(record["z_s"], 32, "z_s"),
        z_r=_bytes(record["z_r"], 32, "z_r"),
        z_u=_bytes(record["z_u"], 32, "z_u"),
    )


def _parse_capabilities(value: Any, expected_network_id: str) -> GovernanceCapabilitiesV1:
    record = _exact(value, _CAPABILITIES_FIELDS, "governance capabilities response")
    if record["schema"] != "iroha.governance.capabilities.v1":
        raise TypeError("governance capabilities schema is not first-release V1")
    if _uint(record["version"], "version", _U16_MAX) != PARLIAMENT_API_VERSION_V1:
        raise TypeError("governance capabilities version is not first-release V1")
    network_id = _text(record["network_id"], "network_id")
    if network_id != expected_network_id:
        raise ValueError("governance capabilities network_id differs from canonical auth")
    current_height = _decimal_uint(record["current_height"], "current_height", minimum=1)
    network_prefix = _decimal_uint(record["network_prefix"], "network_prefix", maximum=_U16_MAX)
    abi_version = _decimal_uint(record["abi_version"], "abi_version", maximum=_U16_MAX, minimum=1)
    if abi_version != 1:
        raise TypeError("governance capabilities must advertise first-release ABI version 1")
    data_model_version = _decimal_uint(
        record["data_model_version"], "data_model_version", maximum=_U32_MAX, minimum=1
    )
    if data_model_version != _FIRST_RELEASE_DATA_MODEL_VERSION:
        raise TypeError(
            "governance capabilities advertise an unsupported data-model version"
        )
    if record["approval_mode"] != "PARLIAMENT_ATTEMPT_TIMED_OVN_V1":
        raise TypeError("governance capabilities approval_mode is not Parliament V1")
    if record["private_ballot_protocol"] != "TIMED_OVN_TLE_THRESHOLD_BLS_V1":
        raise TypeError("governance capabilities private ballot protocol is unsupported")
    if not _boolean(record["mandatory_private_ballots"], "mandatory_private_ballots"):
        raise ValueError("governance capabilities must require private binding ballots")
    if _boolean(
        record["proposal_backed_referendum_ballots_supported"],
        "proposal_backed_referendum_ballots_supported",
    ):
        raise ValueError("proposal-backed referendum routes must not replace Parliament")
    plain = _boolean(
        record["standalone_plain_ballots_supported"],
        "standalone_plain_ballots_supported",
    )
    if not _boolean(record["standalone_zk_ballots_supported"], "standalone_zk_ballots_supported"):
        raise ValueError("standalone ZK governance must remain available")
    for field in ("citizenship_asset_id", "voting_asset_id"):
        _asset_definition_id(record[field], field)
    for field in ("citizenship_escrow_account", "bond_escrow_account"):
        _canonical_account_bytes(
            record[field], field, expected_discriminant=network_prefix
        )
    for field in ("citizenship_bond_amount", "min_bond_amount"):
        if not isinstance(record[field], str) or _CANONICAL_NUMERIC.fullmatch(record[field]) is None:
            raise TypeError(f"{field} must be a canonical non-negative numeric string")
    for field in (
        "min_enactment_delay",
        "invitation_phase_blocks",
        "registration_phase_blocks",
        "survivor_freeze_phase_blocks",
        "commitment_phase_blocks",
        "release_delay_blocks",
        "opening_phase_blocks",
    ):
        _decimal_uint(record[field], field, minimum=1)
    _decimal_uint(record["max_ballot_retries"], "max_ballot_retries", maximum=16)
    _decimal_uint(
        record["max_corpus_entries"],
        "max_corpus_entries",
        maximum=PARLIAMENT_TIMED_OVN_CORPUS_ENTRIES_V1,
        minimum=1,
    )
    target_record = _exact(record["target_body_sizes"], _TARGET_BODY_FIELDS, "target_body_sizes")
    targets = {
        field: _decimal_uint(
            target_record[field], f"target_body_sizes.{field}", maximum=1000, minimum=1
        )
        for field in _TARGET_BODY_FIELDS
    }
    target_sizes = GovernanceTargetBodySizesV1(**targets)
    proposal_kinds = record["supported_proposal_kinds"]
    if not isinstance(proposal_kinds, list):
        raise TypeError("supported_proposal_kinds must be an array")
    normalized_kinds = tuple(
        _text(item, f"supported_proposal_kinds[{index}]")
        for index, item in enumerate(proposal_kinds)
    )
    if len(set(normalized_kinds)) != len(normalized_kinds) or frozenset(normalized_kinds) != _PROPOSAL_KINDS_V1:
        raise ValueError("supported_proposal_kinds is not the exact first-release set")
    routes = record["supported_routes"]
    if not isinstance(routes, list):
        raise TypeError("supported_routes must be an array")
    normalized_routes = tuple(
        _text(item, f"supported_routes[{index}]") for index, item in enumerate(routes)
    )
    if len(set(normalized_routes)) != len(normalized_routes):
        raise ValueError("supported_routes must not contain duplicates")
    if not _PARLIAMENT_ROUTES_V1.issubset(normalized_routes):
        raise ValueError("supported_routes does not advertise every canonical Parliament route")
    return GovernanceCapabilitiesV1(
        network_id=network_id,
        current_height=current_height,
        network_prefix=network_prefix,
        abi_version=abi_version,
        data_model_version=data_model_version,
        standalone_plain_ballots_supported=plain,
        target_body_sizes=target_sizes,
        supported_proposal_kinds=normalized_kinds,
        supported_routes=normalized_routes,
        raw=dict(record),
    )


class ParliamentApiV1Mixin:
    """Authenticated, bounded transport methods for the canonical Parliament routes."""

    _canonical_request_headers: Callable[..., Any]
    _encode_json_body: Callable[..., bytes]
    _expect_status: Callable[..., None]
    _request: Callable[..., Any]
    _require_canonical_auth: Callable[..., Any]
    _require_exact_i105_account_id: Callable[..., str]
    _session: Any

    def _reject_parliament_ambient_auth(self, context: str) -> None:
        session = self._session
        if getattr(session, "auth", None) is not None:
            raise ValueError(f"{context} rejects Session.auth credential fallback")
        session_headers = getattr(session, "headers", {})
        try:
            header_names = tuple(session_headers)
        except TypeError as exc:
            raise ValueError(f"{context} requires inspectable session headers") from exc
        for name in header_names:
            if isinstance(name, str) and name.lower() in _AMBIENT_AUTH_HEADERS:
                raise ValueError(f"{context} rejects ambient session header {name}")
        cookies = getattr(session, "cookies", None)
        if cookies is not None:
            try:
                if len(cookies) != 0:
                    raise ValueError(f"{context} rejects ambient session cookies")
            except TypeError as exc:
                raise ValueError(f"{context} requires inspectable session cookies") from exc

    def _parliament_response(
        self,
        method: str,
        path: str,
        *,
        canonical_auth: Any,
        maximum_response_bytes: int,
        context: str,
        body: Optional[bytes] = None,
        request_media_type: Optional[str] = None,
        response_media_type: str = "application/json",
    ) -> bytes:
        self._reject_parliament_ambient_auth(context)
        auth = self._require_canonical_auth(canonical_auth, context)
        self._require_exact_i105_account_id(
            auth.account_id, f"{context}.canonical_auth.account_id"
        )
        headers = {"Accept": response_media_type, "Accept-Encoding": "identity"}
        if request_media_type is not None:
            headers["Content-Type"] = request_media_type
        final_headers = self._canonical_request_headers(
            method,
            path,
            body or b"",
            canonical_auth=auth,
            headers=headers,
            has_body=body is not None,
        )
        if not hasattr(final_headers, "reject_ambient_auth"):
            raise ValueError(f"{context} requires a credential-free prepared request")
        final_headers.reject_ambient_auth = True
        response = self._request(
            method,
            path,
            headers=final_headers,
            data=body,
            stream=True,
            allow_retry=False,
            allow_redirects=False,
        )
        content_encoding = response.headers.get("Content-Encoding")
        if content_encoding is not None and (
            not isinstance(content_encoding, str)
            or content_encoding.strip().lower() != "identity"
        ):
            response.close()
            raise TypeError(f"{context} response must not use content encoding")
        self._expect_status(
            response,
            {200},
            maximum_body_bytes=maximum_response_bytes,
            context=context,
        )
        try:
            _require_media_type(
                response.headers.get("Content-Type", ""), response_media_type, context
            )
        except (TypeError, ValueError):
            response.close()
            raise
        return _read_bounded_response(response, maximum_response_bytes, f"{context} response")

    def _parliament_json(
        self,
        method: str,
        path: str,
        *,
        canonical_auth: Any,
        maximum_response_bytes: int,
        context: str,
        body_payload: Optional[Mapping[str, Any]] = None,
    ) -> Mapping[str, Any]:
        body = self._encode_json_body(body_payload) if body_payload is not None else None
        raw = self._parliament_response(
            method,
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=maximum_response_bytes,
            context=context,
            body=body,
            request_media_type="application/json" if body is not None else None,
        )
        return _strict_json_object(raw, context)

    def get_governance_capabilities_v1(self, *, canonical_auth: Any) -> GovernanceCapabilitiesV1:
        """Fetch strict fail-closed Parliament readiness for the signed network."""

        payload = self._parliament_json(
            "GET",
            "/v1/gov/capabilities",
            canonical_auth=canonical_auth,
            maximum_response_bytes=64 * 1024,
            context="governance capabilities",
        )
        return _parse_capabilities(payload, canonical_auth.network_id)

    def draft_parliament_attempt_v1(
        self,
        proposal: Mapping[str, Any],
        attempt_sequence: int,
        *,
        expected_proposal_content_id: str,
        expected_governance_attempt_id: str,
        canonical_auth: Any,
    ) -> ParliamentAttemptDraftResponseV1:
        """Draft one attempt and bind the response to independently derived IDs."""

        expected_proposal_id = _id(
            expected_proposal_content_id, "expected_proposal_content_id"
        )
        expected_attempt_id = _id(
            expected_governance_attempt_id, "expected_governance_attempt_id"
        )
        normalized_proposal = _json_clone(proposal, "proposal")
        GovernanceProposalKind.from_payload(normalized_proposal)
        request = {
            "version": PARLIAMENT_API_VERSION_V1,
            "proposal": normalized_proposal,
            "attempt_sequence": _uint(
                attempt_sequence,
                "attempt_sequence",
                PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1,
            ),
        }
        payload = self._parliament_json(
            "POST",
            PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
            canonical_auth=canonical_auth,
            maximum_response_bytes=1024 * 1024,
            context="Parliament attempt draft",
            body_payload=request,
        )
        return _parse_attempt_draft(
            payload, expected_proposal_id, expected_attempt_id
        )

    def get_parliament_attempt_v1(
        self, governance_attempt_id: str, *, canonical_auth: Any
    ) -> ParliamentAttemptReadResponseV1:
        """Fetch and validate one bounded Parliament reducer projection."""

        attempt_id = _id(governance_attempt_id, "governance_attempt_id")
        path = PARLIAMENT_ATTEMPT_READ_PATH_V1.replace(
            "{governance_attempt_id}", attempt_id
        )
        payload = self._parliament_json(
            "GET",
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=2 * PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1 + 2 * 1024 * 1024,
            context="Parliament attempt read",
        )
        return _parse_attempt_read(payload, attempt_id)

    def get_parliament_timed_ovn_casting_context_v1(
        self, ballot_attempt_id: str, *, canonical_auth: Any
    ) -> ParliamentTimedOvnCastingContextResponseV1:
        """Fetch a bounded node-local diagnostic public wallet context.

        This route is not a finality proof and its archive is not safe for
        secret use until independently authenticated through the proof route.
        """

        ballot_id = _id(ballot_attempt_id, "ballot_attempt_id")
        path = PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1.replace(
            "{ballot_attempt_id}", ballot_id
        )
        payload = self._parliament_json(
            "GET",
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=4 * PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1,
            context="Parliament timed-OVN casting context",
        )
        return _parse_casting_context(payload, ballot_id, canonical_auth.network_id)

    def get_parliament_timed_ovn_casting_proof_page_v1(
        self,
        ballot_attempt_id: str,
        trusted_checkpoint_height: int,
        *,
        canonical_auth: Any,
    ) -> bytes:
        """Transport one canonical casting-proof page for native verification.

        The request is derived from the externally trusted nonzero checkpoint
        height. This validates only request/response framing and byte bounds.
        The returned bytes MUST be passed with the external network, checkpoint
        context, and ballot ID to the ABI-29 native proof verifier before secret
        seed material is accessed.
        """

        ballot_id = _id(ballot_attempt_id, "ballot_attempt_id")
        request_norito = encode_parliament_timed_ovn_casting_proof_request_v1(
            trusted_checkpoint_height
        )
        validate_norito_frame(
            request_norito,
            context="Parliament casting-proof request",
            expected_type_name=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_V1,
            expected_padding_length=0,
            expected_flags=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1,
        )
        path = PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1.replace(
            "{ballot_attempt_id}", ballot_id
        )
        response = self._parliament_response(
            "POST",
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1,
            context="Parliament timed-OVN casting proof",
            body=request_norito,
            request_media_type="application/x-norito",
            response_media_type="application/x-norito",
        )
        validate_norito_frame(
            response,
            context="Parliament casting-proof response",
            expected_type_name=PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_V1,
            expected_padding_length=0,
            expected_flags=PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1,
        )
        return response

    def get_parliament_tle_release_context_v1(
        self, ballot_attempt_id: str, *, canonical_auth: Any
    ) -> ParliamentTleReleaseContextResponseV1:
        """Fetch a complete public TLE context during its inclusive opening window."""

        ballot_id = _id(ballot_attempt_id, "ballot_attempt_id")
        path = PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1.replace(
            "{ballot_attempt_id}", ballot_id
        )
        payload = self._parliament_json(
            "GET",
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=1024 * 1024,
            context="Parliament TLE release context",
        )
        return _parse_release_context(payload, ballot_id, canonical_auth.network_id)

    def request_parliament_tle_partial_release_v1(
        self,
        ballot_attempt_id: str,
        release_context: ParliamentTleReleaseContextResponseV1,
        *,
        canonical_auth: Any,
    ) -> ParliamentTlePartialReleaseShareV1:
        """Request one bodyless node-local partial bound to a fetched context.

        The returned public proof is structurally checked and rebound here;
        callers must still verify its adaptive-TLE proof equations before use.
        """

        ballot_id = _id(ballot_attempt_id, "ballot_attempt_id")
        if not isinstance(release_context, ParliamentTleReleaseContextResponseV1):
            raise TypeError("release_context must be ParliamentTleReleaseContextResponseV1")
        if release_context.ballot_attempt_id != ballot_id:
            raise ValueError("release context ballot id differs from the partial-release request")
        auth = self._require_canonical_auth(
            canonical_auth, "Parliament TLE partial release"
        )
        if bytes.fromhex(auth.network_id[5:69]) != release_context.key_session.network_id:
            raise ValueError(
                "release context network differs from the partial-release canonical auth"
            )
        path = PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1.replace(
            "{ballot_attempt_id}", ballot_id
        )
        payload = self._parliament_json(
            "POST",
            path,
            canonical_auth=canonical_auth,
            maximum_response_bytes=16 * 1024,
            context="Parliament TLE partial release",
        )
        return _parse_partial_release(payload, release_context)

    def draft_parliament_transition_v1(
        self,
        governance_attempt_id: str,
        transition: Mapping[str, Any],
        *,
        expected_transition_digest: bytes,
        canonical_auth: Any,
    ) -> ParliamentTransitionDraftResponseV1:
        """Draft one closed public lifecycle transition for local signing."""

        attempt_id = _id(governance_attempt_id, "governance_attempt_id")
        if (
            type(expected_transition_digest) is not bytes
            or len(expected_transition_digest) != 32
            or not any(expected_transition_digest)
        ):
            raise TypeError(
                "expected_transition_digest must be 32 non-zero immutable bytes"
            )
        normalized_transition, kind = _normalize_transition(transition, attempt_id)
        request = {
            "version": PARLIAMENT_API_VERSION_V1,
            "governance_attempt_id": attempt_id,
            "transition": normalized_transition,
        }
        payload = self._parliament_json(
            "POST",
            PARLIAMENT_TRANSITION_DRAFT_PATH_V1,
            canonical_auth=canonical_auth,
            maximum_response_bytes=PARLIAMENT_TRANSITION_DRAFT_RESPONSE_MAX_BYTES_V1,
            context="Parliament transition draft",
            body_payload=request,
        )
        return _parse_transition_draft(
            payload, attempt_id, kind, expected_transition_digest
        )


__all__ = [
    "GovernanceCapabilitiesV1",
    "GovernanceTargetBodySizesV1",
    "PARLIAMENT_API_VERSION_V1",
    "PARLIAMENT_ATTEMPT_CREATE_WIRE_ID_V1",
    "PARLIAMENT_ATTEMPT_DRAFT_PATH_V1",
    "PARLIAMENT_ATTEMPT_READ_PATH_V1",
    "PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1",
    "PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_READ_PATH_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_PATH_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_BYTES_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_FLAGS_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PADDING_BYTES_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_PAYLOAD_ALIGNMENT_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_HASH_HEX_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_REQUEST_SCHEMA_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_MAX_BYTES_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_HASH_HEX_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_RESPONSE_SCHEMA_V1",
    "PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1",
    "PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1",
    "PARLIAMENT_TLE_PARTIAL_RELEASE_PATH_V1",
    "PARLIAMENT_TLE_RELEASE_CONTEXT_READ_PATH_V1",
    "PARLIAMENT_TRANSITION_DRAFT_PATH_V1",
    "PARLIAMENT_TRANSITION_DRAFT_RESPONSE_MAX_BYTES_V1",
    "PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1",
    "ParliamentAttemptDraftResponseV1",
    "ParliamentAttemptReadResponseV1",
    "ParliamentInstructionDraftV1",
    "ParliamentTimedOvnCastingContextResponseV1",
    "ParliamentTimedOvnProgressProjectionV1",
    "ParliamentTimedOvnReleaseIdentityProjectionV1",
    "ParliamentTleKeySessionPublicStateV1",
    "ParliamentTlePartialReleaseShareV1",
    "ParliamentTleReleaseContextResponseV1",
    "ParliamentTransitionDraftResponseV1",
    "encode_parliament_timed_ovn_casting_proof_request_v1",
]
