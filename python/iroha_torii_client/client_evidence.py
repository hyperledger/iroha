"""Closed Sumeragi evidence DATA decoding; no signature or historical-state authority."""

from __future__ import annotations

import re
from typing import Any, Callable, Literal, Mapping, cast

from .client_status_models import (
    SUMERAGI_EVIDENCE_CLASSES,
    SUMERAGI_EVIDENCE_KINDS,
    SccpEvidenceAttribution,
    SccpEvidenceOffender,
    SccpForgeryAnchor,
    SccpForgeryEvidenceRecord,
    SccpForgeryOffender,
    SccpForgeryRecord,
    SccpForgeryRule,
    SccpForgerySubmission,
    SccpGenerationEvidenceScope,
    SumeragiEvidenceAppliedPenaltyStatus,
    SumeragiEvidenceOffender,
    SumeragiEvidencePenaltyDetails,
    SumeragiEvidencePenaltyStatus,
    SumeragiEvidencePendingPenaltyStatus,
    SumeragiEvidenceRecord,
    SumeragiEvidenceScope,
    SumeragiLaneEvidenceScope,
    SumeragiNativeEvidenceRecord,
)


def _fields(client: Any, value: Any, context: str, fields: set[str]) -> Mapping[str, Any]:
    record = client._ensure_mapping(value, context)
    actual = set(record)
    missing = sorted(fields - actual)
    unexpected = sorted(str(field) for field in actual - fields)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise RuntimeError(f"{context} must use the exact server fields ({'; '.join(details)})")
    return record


def _unsigned(value: Any, context: str, maximum: int = 0xFFFFFFFFFFFFFFFF) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeError(f"{context} must be a non-negative JSON integer")
    if value > maximum:
        raise RuntimeError(f"{context} must be <= {maximum}")
    return value


def _fixed_hex(value: Any, context: str, length: int) -> str:
    if not isinstance(value, str) or len(value) != length * 2 or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
        raise RuntimeError(f"{context} must be an exact {length}-byte hexadecimal string")
    return value


def _exact_string(client: Any, value: Any, context: str) -> str:
    literal = client._require_non_empty_string(value, context)
    if literal != value:
        raise RuntimeError(f"{context} must not contain surrounding whitespace")
    return literal


def _scope(client: Any, value: Any, context: str, material: str, hash_literal: Callable[[Any, str], str]) -> SumeragiEvidenceScope:
    scope = _fields(client, value, context, {"kind", "value"})
    kind = scope["kind"]
    if material == "sccp":
        if kind != "sccp_generation":
            raise RuntimeError(f"{context}.kind must be sccp_generation")
        detail = _fields(client, scope["value"], f"{context}.value", {"generation"})
        return SumeragiEvidenceScope(kind="sccp_generation", value=SccpGenerationEvidenceScope(
            generation=_unsigned(detail["generation"], f"{context}.value.generation"),
        ))
    if kind == "root":
        if scope["value"] is not None:
            raise RuntimeError(f"{context}.value must be null for root scope")
        return SumeragiEvidenceScope(kind="root", value=None)
    if kind != "lane":
        raise RuntimeError(f"{context}.kind must be root or lane")
    context = f"{context}.value"
    lane = _fields(client, scope["value"], context, {
        "lane", "incarnation", "created_at", "admission_parent_height", "admission_parent_hash",
        "admission_parent_core_hash", "admission_parent_result",
    })
    return SumeragiEvidenceScope(kind="lane", value=SumeragiLaneEvidenceScope(
        lane=_unsigned(lane["lane"], f"{context}.lane", 0xFFFFFFFF),
        incarnation=_fixed_hex(lane["incarnation"], f"{context}.incarnation", 32),
        created_at=_unsigned(lane["created_at"], f"{context}.created_at"),
        admission_parent_height=_unsigned(lane["admission_parent_height"], f"{context}.admission_parent_height"),
        admission_parent_hash=hash_literal(lane["admission_parent_hash"], f"{context}.admission_parent_hash"),
        admission_parent_core_hash=_fixed_hex(lane["admission_parent_core_hash"], f"{context}.admission_parent_core_hash", 32),
        admission_parent_result=_fixed_hex(lane["admission_parent_result"], f"{context}.admission_parent_result", 32),
    ))


def parse_sumeragi_evidence_record(client: Any, payload: Any, *, context: str, hash_literal: Callable[[Any, str], str]) -> SumeragiEvidenceRecord:
    """Decode the current tagged model through the shared exact field validators."""
    try:
        record = _fields(client, payload, context, {"kind", "value"})
        kind = _exact_string(client, record["kind"], f"{context}.kind")
        if kind not in SUMERAGI_EVIDENCE_KINDS:
            raise RuntimeError(f"{context}.kind must be NativeSumeragiEvidence or SccpForgeryEvidence")
        value = (
            _native(client, record["value"], f"{context}.value", hash_literal)
            if kind == "NativeSumeragiEvidence"
            else _forgery(client, record["value"], f"{context}.value", hash_literal)
        )
        return SumeragiEvidenceRecord(kind=cast(Literal["NativeSumeragiEvidence", "SccpForgeryEvidence"], kind), value=value)
    except (TypeError, ValueError) as error:
        # Transported malformed DATA has one response-error boundary. Preserve
        # the original codec/shape error for diagnostics and dependent clients.
        raise RuntimeError(f"{context} is malformed: {error}") from error


def _penalty(client: Any, record: Mapping[str, Any], context: str) -> SumeragiEvidencePenaltyStatus:
    penalty = client._ensure_mapping(
        record["penalty_status"], f"{context}.penalty_status"
    )
    penalty_fields = set(penalty)
    if penalty_fields != {"status", "details"}:
        missing = sorted({"status", "details"} - penalty_fields)
        unexpected = sorted(
            str(field) for field in penalty_fields - {"status", "details"}
        )
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise RuntimeError(
            f"{context}.penalty_status must use the exact server fields "
            f"({'; '.join(details)})"
        )
    penalty_literal = _exact_string(client,
        penalty["status"], f"{context}.penalty_status.status"
    )
    if penalty_literal == "pending":
        if penalty["details"] is not None:
            raise RuntimeError(
                f"{context}.penalty_status.details must be null when status is pending"
            )
        penalty_status: SumeragiEvidencePenaltyStatus = (
            SumeragiEvidencePendingPenaltyStatus(
                status="pending",
                details=None,
            )
        )
    elif penalty_literal == "applied":
        penalty_details = client._ensure_mapping(
            penalty["details"], f"{context}.penalty_status.details"
        )
        if set(penalty_details) != {"height"}:
            raise RuntimeError(
                f"{context}.penalty_status.details must contain exactly height"
            )
        penalty_height = penalty_details["height"]
        if (
            isinstance(penalty_height, bool)
            or not isinstance(penalty_height, int)
            or not 0 <= penalty_height <= 0xFFFFFFFFFFFFFFFF
        ):
            raise RuntimeError(
                f"{context}.penalty_status.details.height must be a non-negative JSON u64"
            )
        typed_details = SumeragiEvidencePenaltyDetails(height=penalty_height)
        penalty_status = SumeragiEvidenceAppliedPenaltyStatus(
            status="applied",
            details=typed_details,
        )
    else:
        raise RuntimeError(
            f"{context}.penalty_status.status must be pending or applied"
        )
    return penalty_status


def _native(client: Any, payload: Any, context: str, hash_literal: Callable[[Any, str], str]) -> SumeragiNativeEvidenceRecord:
    record = client._ensure_mapping(payload, context)

    required_fields = {
        "scope", "class", "instance", "height", "epoch", "context_id",
        "authority_generation", "offenders", "safety_violation", "native_frame_hash",
        "recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height",
        "penalty_status",
    }
    actual_fields = set(record)
    missing = sorted(required_fields - actual_fields)
    unexpected = sorted(str(field) for field in actual_fields - required_fields)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        raise RuntimeError(
            f"{context} must use the exact server fields ({'; '.join(details)})"
        )

    def json_unsigned(
        field: str, *, maximum: int = 0xFFFFFFFFFFFFFFFF
    ) -> int:
        value = record[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError(f"{context}.{field} must be a non-negative JSON integer")
        if value > maximum:
            raise RuntimeError(f"{context}.{field} must be <= {maximum}")
        return value

    def evidence_hash(field: str) -> str:
        return client._require_exact_lower_hex_string(
            record[field],
            context=f"{context}.{field}",
            expected_length=64,
        )

    def exact_non_empty_string_for_value(value: Any, field_context: str) -> str:
        literal = client._require_non_empty_string(value, field_context)
        if literal != value:
            raise RuntimeError(
                f"{field_context} must not contain surrounding whitespace"
            )
        return literal

    def exact_non_empty_string(field: str) -> str:
        return exact_non_empty_string_for_value(
            record[field], f"{context}.{field}"
        )

    evidence_class = exact_non_empty_string("class")
    if evidence_class not in SUMERAGI_EVIDENCE_CLASSES:
        allowed = ", ".join(sorted(SUMERAGI_EVIDENCE_CLASSES))
        raise RuntimeError(f"{context}.class must be one of: {allowed}")
    raw_offenders = record["offenders"]
    # Different-view CommitQC conflicts do not attribute individual signers.
    permits_unattributed_safety_violation = (
        evidence_class == "conflicting_certificates"
        and record["safety_violation"] is True
    )
    if (
        not isinstance(raw_offenders, list)
        or len(raw_offenders) > 1024
        or (not raw_offenders and not permits_unattributed_safety_violation)
    ):
        raise RuntimeError(
            f"{context}.offenders must contain between 1 and 1024 entries, "
            "or be empty for a conflicting-certificate safety violation"
        )
    offenders = []
    peers = set()
    previous_signer = -1
    for index, offender in enumerate(raw_offenders):
        offender_context = f"{context}.offenders[{index}]"
        if not isinstance(offender, Mapping) or set(offender) != {"signer", "peer_id"}:
            raise RuntimeError(f"{offender_context} must contain exactly signer and peer_id")
        signer = offender["signer"]
        if type(signer) is not int or not previous_signer < signer <= 1023:
            raise RuntimeError(f"{offender_context}.signer must increase strictly within 0..1023")
        peer_id = offender["peer_id"]
        # Validate the canonical public-key shape; attribution is authenticated by the node.
        if not isinstance(peer_id, str) or re.fullmatch(r"ea0130[0-9A-F]{96}", peer_id) is None:
            raise RuntimeError(f"{offender_context}.peer_id must be a canonical BLS-normal public key")
        if peer_id in peers:
            raise RuntimeError(f"{offender_context}.peer_id must be unique")
        peers.add(peer_id)
        previous_signer = signer
        offenders.append(SumeragiEvidenceOffender(signer, peer_id))
    safety_violation = record["safety_violation"]
    if not isinstance(safety_violation, bool):
        raise RuntimeError(f"{context}.safety_violation must be a boolean")
    penalty_status = _penalty(client, record, context)
    return SumeragiNativeEvidenceRecord(
        scope=_scope(client, record["scope"], f"{context}.scope", "native", hash_literal),
        class_=cast(
            Literal["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"], evidence_class
        ),
        height=json_unsigned("height"),
        epoch=json_unsigned("epoch"),
        context_id=evidence_hash("context_id"),
        instance=evidence_hash("instance"),
        authority_generation=evidence_hash("authority_generation"),
        offenders=tuple(offenders),
        safety_violation=safety_violation,
        native_frame_hash=evidence_hash("native_frame_hash"),
        recorded_height=json_unsigned("recorded_height"),
        recorded_view=json_unsigned("recorded_view"),
        recorded_ms=json_unsigned("recorded_ms"),
        consensus_admitted_height=json_unsigned("consensus_admitted_height"),
        penalty_status=penalty_status,
    )


def _forgery(client: Any, payload: Any, context: str, hash_literal: Callable[[Any, str], str]) -> SccpForgeryEvidenceRecord:
    # Strict DATA projection only: no certificate, witness, or offender authentication.
    audit = _fields(client, payload, context, {
        "record", "attribution", "recorded_height", "recorded_view", "recorded_ms",
        "consensus_admitted_height", "penalty_status",
    })
    where = f"{context}.record"
    record = _fields(client, audit["record"], where, {"evidence", "rule", "generation", "start_height", "offenders"})
    evidence_context = f"{where}.evidence"
    evidence = _fields(client, record["evidence"], evidence_context, {"qc", "header", "aggregate_signature", "anchor"})
    anchor = None
    if evidence["anchor"] is not None:
        anchor_context = f"{evidence_context}.anchor"
        source = _fields(client, evidence["anchor"], anchor_context, {"core_hash", "result", "path"})
        path = source["path"]
        if not isinstance(path, list) or len(path) != 12:
            raise RuntimeError(f"{anchor_context}.path must contain exactly 12 siblings")
        anchor = SccpForgeryAnchor(
            core_hash=_fixed_hex(source["core_hash"], f"{anchor_context}.core_hash", 32),
            result=_fixed_hex(source["result"], f"{anchor_context}.result", 32),
            path=tuple(_fixed_hex(entry, f"{anchor_context}.path[{index}]", 32) for index, entry in enumerate(path)),
        )
    rule = _fields(client, record["rule"], f"{where}.rule", {"rule", "detail"})
    if rule["rule"] not in ("E1", "E2", "E3", "E4") or rule["detail"] is not None:
        raise RuntimeError(f"{where}.rule must be an exact E1..E4 rule with null detail")
    generation = _unsigned(record["generation"], f"{where}.generation")
    start_height = _unsigned(record["start_height"], f"{where}.start_height")
    if generation == 0 or start_height == 0:
        raise RuntimeError(f"{where} generation and start_height must be nonzero")
    raw_offenders = record["offenders"]
    if not isinstance(raw_offenders, list) or not 1 <= len(raw_offenders) <= 31:
        raise RuntimeError(f"{where}.offenders must contain between 1 and 31 entries")
    offenders = []
    registrations = set()
    previous_signer = -1
    for index, raw in enumerate(raw_offenders):
        offender_context = f"{where}.offenders[{index}]"
        offender = _fields(client, raw, offender_context, {"signer", "lane_id", "validator", "activation_height"})
        signer = _unsigned(offender["signer"], f"{offender_context}.signer", 30)
        if signer <= previous_signer:
            raise RuntimeError(f"{offender_context}.signer must increase strictly")
        previous_signer = signer
        lane = _unsigned(offender["lane_id"], f"{offender_context}.lane_id", 0xFFFFFFFF)
        validator = client._require_exact_i105_account_id(offender["validator"], f"{offender_context}.validator")
        registration = (lane, validator)
        if registration in registrations:
            raise RuntimeError(f"{offender_context} validator registration must be unique")
        registrations.add(registration)
        activation = _unsigned(offender["activation_height"], f"{offender_context}.activation_height")
        if not 1 <= activation <= start_height:
            raise RuntimeError(f"{offender_context}.activation_height must be within the generation start")
        offenders.append(SccpForgeryOffender(signer, lane, validator, activation))
    attribution_context = f"{context}.attribution"
    attribution = _fields(client, audit["attribution"], attribution_context, {
        "scope", "instance", "height", "epoch", "context_id", "authority_generation", "offenders", "safety_violation",
    })
    scope = _scope(client, attribution["scope"], f"{attribution_context}.scope", "sccp", hash_literal)
    height = _unsigned(attribution["height"], f"{attribution_context}.height")
    if not isinstance(scope.value, SccpGenerationEvidenceScope) or scope.value.generation != generation or height != start_height:
        raise RuntimeError(f"{attribution_context} must match the recorded generation and liability start")
    raw_attributed = attribution["offenders"]
    if not isinstance(raw_attributed, list) or len(raw_attributed) != len(offenders):
        raise RuntimeError(f"{attribution_context}.offenders must match the recorded signers")
    attributed = []
    for index, raw in enumerate(raw_attributed):
        at = f"{attribution_context}.offenders[{index}]"
        offender = _fields(client, raw, at, {"signer", "peer_id", "lane_stake"})
        signer = _unsigned(offender["signer"], f"{at}.signer", 30)
        peer = _exact_string(client, offender["peer_id"], f"{at}.peer_id")
        if signer != offenders[index].signer or offender["lane_stake"] is not None:
            raise RuntimeError(f"{at} must retain the SCCP signer and null lane_stake")
        if re.fullmatch(r"ea0130[0-9A-F]{96}", peer) is None:
            raise RuntimeError(f"{at}.peer_id must be a canonical BLS-normal public key")
        attributed.append(SccpEvidenceOffender(signer, peer, None))
    safety = attribution["safety_violation"]
    if not isinstance(safety, bool):
        raise RuntimeError(f"{attribution_context}.safety_violation must be a boolean")
    return SccpForgeryEvidenceRecord(
        record=SccpForgeryRecord(
            evidence=SccpForgerySubmission(
                qc=_fixed_hex(evidence["qc"], f"{evidence_context}.qc", 116),
                header=_fixed_hex(evidence["header"], f"{evidence_context}.header", 221),
                aggregate_signature=_fixed_hex(evidence["aggregate_signature"], f"{evidence_context}.aggregate_signature", 96),
                anchor=anchor,
            ),
            rule=SccpForgeryRule(cast(Literal["E1", "E2", "E3", "E4"], rule["rule"]), None),
            generation=generation,
            start_height=start_height,
            offenders=tuple(offenders),
        ),
        attribution=SccpEvidenceAttribution(
            scope=scope,
            instance=_fixed_hex(attribution["instance"], f"{attribution_context}.instance", 32),
            height=height,
            epoch=_unsigned(attribution["epoch"], f"{attribution_context}.epoch"),
            context_id=_fixed_hex(attribution["context_id"], f"{attribution_context}.context_id", 32),
            authority_generation=_fixed_hex(attribution["authority_generation"], f"{attribution_context}.authority_generation", 32),
            offenders=tuple(attributed),
            safety_violation=safety,
        ),
        recorded_height=_unsigned(audit["recorded_height"], f"{context}.recorded_height"),
        recorded_view=_unsigned(audit["recorded_view"], f"{context}.recorded_view"),
        recorded_ms=_unsigned(audit["recorded_ms"], f"{context}.recorded_ms"),
        consensus_admitted_height=_unsigned(audit["consensus_admitted_height"], f"{context}.consensus_admitted_height"),
        penalty_status=_penalty(client, audit, context),
    )
