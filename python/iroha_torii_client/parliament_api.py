"""Strict authenticated Python bindings for the first-release Parliament API.

The module covers governance readiness, attempt drafting and reading, and
lifecycle-transition drafting. Every response is validated against the exact
first-release contract before it is exposed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ._account_id import decode_canonical_i105_account_id
from .governance_proposals import GovernanceProposalKind
from .norito_frame import (
    validate_norito_frame,
    validate_opaque_norito_frame,
)

PARLIAMENT_API_VERSION_V1 = 1
PARLIAMENT_ATTEMPT_DRAFT_PATH_V1 = "/v1/gov/parliament/attempts/draft"
PARLIAMENT_ATTEMPT_READ_PATH_V1 = (
    "/v1/gov/parliament/attempts/{governance_attempt_id}"
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

PARLIAMENT_ATTEMPT_STATE_MAX_BYTES_V1 = 16 * 1024 * 1024
PARLIAMENT_GOVERNANCE_ATTEMPT_SEQUENCE_MAX_V1 = 16
_PARLIAMENT_GOVERNANCE_POLICY_VERSION_V1 = 1
_PARLIAMENT_SORTITION_RETRIES_MAX_V1 = 16
# The largest remaining draft is a 1,000-identifier ConsumeSortitionPulseBatch:
# about 32 KB of payload and 64 KB as hex. 1 MiB leaves ample fixed-envelope
# headroom.
PARLIAMENT_TRANSITION_DRAFT_RESPONSE_MAX_BYTES_V1 = 1024 * 1024
# Mirrors Rust ``MAX_PARLIAMENT_BODY_TARGET_SEATS_V1``; it also bounds every
# seat, quorum, endorsement, and assignment-count field of one body.
MAX_BODY_TARGET_SEATS = 1_000
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

_PARLIAMENT_ROUTES_V1 = frozenset(
    {
        "/v1/gov/capabilities",
        PARLIAMENT_ATTEMPT_DRAFT_PATH_V1,
        PARLIAMENT_ATTEMPT_READ_PATH_V1,
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
    "RecordInvitationResponse": ("election_attempt_id", "body", "decision"),
    "FailPublicFindingNoResult": ("body_instance_id",),
    "RegisterInitialSortition": None,
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
_NO_RESULT_KINDS_V1 = frozenset(
    {
        "PublicFindingQuorumUnreachable",
        "PublicFindingDeadlineExpired",
        "SortitionRetriesExhausted",
        "ConfirmationJuryCapacityUnavailable",
        "RandomnessRedrawBudgetExhausted",
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
    state_payload: bytes
    raw: Dict[str, Any]


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
        or len(value) > MAX_BODY_TARGET_SEATS
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
        MAX_BODY_TARGET_SEATS,
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
        "beacon_session_id",
        "body_instance_id",
        "election_attempt_id",
        "pulse_id",
    )
    for field in id_fields:
        if field in payload:
            _id(payload[field], f"transition.{tag}.payload.{field}")
    if "pulse_height" in payload:
        _uint(
            payload["pulse_height"],
            f"transition.{tag}.payload.pulse_height",
            minimum=1,
        )
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
    if tag == "RecordInvitationResponse":
        body = _text(payload["body"], "body")
        if body not in _BODY_ORDER:
            raise TypeError("body is not a canonical Parliament body")
        _tagged_unit(payload["decision"], "decision", {"Accept", "Decline"}, "decision")
    if tag == "EndorsePublicFinding":
        _bytes(payload["result_root"], 32, "result_root", nonzero=True)
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
            _tagged_unit(
                no_result[0], "reason", _NO_RESULT_KINDS_V1, f"{context}.no_result_kind"
            )
            _uint(no_result[1], f"{context}.no_result_height")
            if status != "NoResult":
                raise ValueError(f"{context} no-result facts require NoResult status")
        parsed.append(
            {
                "body": state["body"],
                "body_instance_id": instance,
                "status": status,
            }
        )
    return tuple(parsed)


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
        MAX_BODY_TARGET_SEATS,
        minimum=1,
    )
    quorum = _uint(
        record["quorum"],
        f"{context}.quorum",
        MAX_BODY_TARGET_SEATS,
        minimum=1,
    )
    expected_quorum = (2 * original_seats + 2) // 3
    if quorum != expected_quorum:
        raise ValueError(f"{context}.quorum differs from the immutable seat quorum")
    if endorsements != quorum or len(assignments) != endorsements:
        raise ValueError(
            f"{context}.endorsements must equal quorum and the assignment count"
        )


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
        _id(binding["beacon_pulse_id"], f"{context}.beacon_pulse_id")
        for identifier, seen, field in (
            (body_instance_id, seen_body_instance_ids, "body_instance_id"),
            (election_attempt_id, seen_election_attempt_ids, "election_attempt_id"),
            (sortition_request_id, seen_sortition_request_ids, "sortition_request_id"),
        ):
            if identifier in seen:
                raise ValueError(f"certificate.body_bindings reuses {field}")
            seen.add(identifier)
        _uint(
            binding["election_attempt_sequence"],
            f"{context}.election_attempt_sequence",
            _PARLIAMENT_SORTITION_RETRIES_MAX_V1,
        )
        original_seats = _uint(
            binding["original_seats"],
            f"{context}.original_seats",
            MAX_BODY_TARGET_SEATS,
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
            # TODO(parliament anonymous ballot, P4): validate the anonymous body-result
            # binding (BallotClosureRecordV1 + result_root) for private-jury bodies here;
            # until it lands this SDK admits no certificate that contains a private-jury
            # body.
            raise ValueError(
                f"{context} private-jury result binding is not admitted until the "
                "anonymous-ballot result binding is supported"
            )
        if binding["public_finding"] is None or binding["ballot"] is not None:
            raise TypeError(f"{context} must carry only a public-finding binding")
        _validate_public_finding_binding(
            binding["public_finding"],
            original_seats=original_seats,
            context=f"{context}.public_finding",
        )
    if certified != latest_body_result_height:
        raise ValueError(
            "certificate.certified_at_height must equal the latest body result height"
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
        state_payload=state_payload,
        raw=dict(record),
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
    if _boolean(
        record["proposal_backed_referendum_ballots_supported"],
        "proposal_backed_referendum_ballots_supported",
    ):
        raise ValueError("proposal-backed referendum routes must not replace Parliament")
    plain = _boolean(
        record["standalone_plain_ballots_supported"],
        "standalone_plain_ballots_supported",
    )
    if _boolean(record["standalone_zk_ballots_supported"], "standalone_zk_ballots_supported"):
        raise ValueError(
            "standalone ZK ballots have no supported relation and must not be advertised"
        )
    for field in ("citizenship_asset_id", "voting_asset_id"):
        _asset_definition_id(record[field], field)
    for field in ("citizenship_escrow_account", "bond_escrow_account"):
        _canonical_account_bytes(
            record[field], field, expected_discriminant=network_prefix
        )
    for field in ("citizenship_bond_amount", "min_bond_amount"):
        if not isinstance(record[field], str) or _CANONICAL_NUMERIC.fullmatch(record[field]) is None:
            raise TypeError(f"{field} must be a canonical non-negative numeric string")
    for field in ("min_enactment_delay", "invitation_phase_blocks"):
        _decimal_uint(record[field], field, minimum=1)
    target_record = _exact(record["target_body_sizes"], _TARGET_BODY_FIELDS, "target_body_sizes")
    targets = {
        field: _decimal_uint(
            target_record[field],
            f"target_body_sizes.{field}",
            maximum=MAX_BODY_TARGET_SEATS,
            minimum=1,
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
    "PARLIAMENT_TRANSITION_DRAFT_PATH_V1",
    "PARLIAMENT_TRANSITION_DRAFT_RESPONSE_MAX_BYTES_V1",
    "PARLIAMENT_TRANSITION_SUBMIT_WIRE_ID_V1",
    "ParliamentAttemptDraftResponseV1",
    "ParliamentAttemptReadResponseV1",
    "ParliamentInstructionDraftV1",
    "ParliamentTransitionDraftResponseV1",
]
