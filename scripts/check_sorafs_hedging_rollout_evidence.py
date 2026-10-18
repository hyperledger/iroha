#!/usr/bin/env python3
"""Validate SoraFS hedging and billing rollout evidence artifacts."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from sorafs_checker_preflight import (  # noqa: E402
    emit_checker_error_block,
    emit_checker_error_lines,
    emit_checker_exception,
    emit_checker_notice,
    render_and_write_checker_summary,
    validate_checker_preflight,
)
from sorafs_evidence_paths import (  # noqa: E402
    discover_evidence_files,
    evidence_path_identities,
)
from sorafs_evidence_json import (  # noqa: E402
    load_evidence_json_with_sha256_or_record_error,
)
from sorafs_evidence_validation import (  # noqa: E402
    archive_artifact_path_label,
    forbidden_non_production_markers,
    build_evidence_artifact,
    count_evidence_artifacts,
    recognized_evidence_artifacts,
    count_evidence_files,
    evidence_gate_status,
    evidence_artifact_is_valid,
    evidence_artifact_fingerprint,
    evidence_schema_by_kind,
    hashable_evidence_values,
    init_evidence_artifact_buckets,
    build_required_evidence_summary,
    record_explicit_evidence_validation_errors,
    record_evidence_artifact,
    record_evidence_validation_errors,
    record_observed_evidence_value,
    validate_bound_evidence_digest_references,
    validate_bound_evidence_tuple_references,
    require_2xx_status,
    require_bool_true,
    require_count_equal,
    require_count_length_match,
    require_false,
    require_false_or_governed,
    require_hex,
    require_config_backed_governance_approval,
    require_hex_string_array,
    validate_standard_evidence_payload,
    require_maximum_int,
    require_minimum_int,
    require_minimum_value,
    require_non_negative_int,
    require_object,
    require_object_array,
    required_evidence_has_all_kinds,
    required_evidence_has_any_kind,
    required_evidence_kind_names,
    require_passed_status,
    require_policy_digest,
    require_positive_int,
    require_recent_timestamp,
    require_string,
    require_string_coverage,
    require_string_equal,
    require_string_inventory_count_match,
    record_string_value_binding_errors,
    require_zero_count,
)
from sorafs_required_kinds import (  # noqa: E402
    parse_required_kinds as parse_required_evidence_kinds,
)
from sorafs_response_args import (  # noqa: E402
    EvidenceArgumentParser,
    expand_response_args,
    non_negative_int_arg,
    positive_int_arg,
)


from sorafs_topology_qualification import (  # noqa: E402
    add_topology_qualification_argument,
    bind_lane_summary_to_topology,
)

SUMMARY_SCHEMA = "sorafs.hedging_billing.rollout_evidence_gate.v1"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FEED_LAG_SECS = 15 * 60
DEFAULT_MAX_CYCLE_AGE_SECS = 45 * 24 * 60 * 60
MAX_DIVERGENCE_BPS = 10_000
DEFAULT_MAX_DIVERGENCE_BPS = 500
DEFAULT_MIN_BILLING_CYCLES = 2
DEFAULT_MIN_NATIVE_BRIDGE_ARTIFACTS = 2
REQUIRED_NATIVE_BRIDGE_ABI_VERSION = 30
HEX64_LEN = 64
CYCLE_ID_PATTERN = re.compile(r"^billing-cycle-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
CYCLE_ID_ERROR = "cycle_id must match canonical lowercase `billing-cycle-*`"
STATEMENT_LABEL_PATTERN = re.compile(
    r"^billing-statement-[a-z0-9]+(?:-[a-z0-9]+)*\Z"
)
STATEMENT_LABEL_ERROR = (
    "statements[].name must match canonical lowercase `billing-statement-*`"
)
LINE_ITEM_LABEL_PATTERN = re.compile(
    r"^billing-line-item-[a-z0-9]+(?:-[a-z0-9]+)*\Z"
)
LINE_ITEM_LABEL_ERROR = (
    "line_items[].name must match canonical lowercase `billing-line-item-*`"
)
ACKNOWLEDGEMENT_PROBE_LABEL_PATTERN = re.compile(
    r"^billing-ack-probe-[a-z0-9]+(?:-[a-z0-9]+)*\Z"
)
ACKNOWLEDGEMENT_PROBE_LABEL_ERROR = (
    "acknowledgement_probes[] must match canonical lowercase `billing-ack-probe-*`"
)
NATIVE_BRIDGE_ARTIFACT_ID_PATTERN = re.compile(
    r"^hedging-native-artifact-[a-z0-9]+(?:-[a-z0-9]+)*\Z"
)
NATIVE_BRIDGE_ARTIFACT_ID_ERROR = (
    "artifacts[].id must match canonical lowercase `hedging-native-artifact-*`"
)
NATIVE_BRIDGE_ARTIFACT_FAMILY_PREFIXES = (
    ("swift", "hedging-native-artifact-swift-"),
    ("jni", "hedging-native-artifact-jni-"),
)
FORBIDDEN_CYCLE_ID_MARKERS = frozenset(
    (
        "debug",
        "dev",
        "draft",
        "example",
        "fake",
        "latest",
        "placeholder",
        "sample",
        "secret",
        "test",
        "todo",
    )
)
FORBIDDEN_INVENTORY_LABEL_MARKERS = frozenset(
    (
        "debug",
        "dev",
        "draft",
        "example",
        "fake",
        "latest",
        "local",
        "mock",
        "placeholder",
        "sample",
        "sandbox",
        "secret",
        "test",
        "todo",
    )
)

REQUIRED_PUBLICATION_ROUTES = (
    "statements_list",
    "statement_fetch",
    "statement_acknowledgement",
)
REQUIRED_RECONCILIATION_SOURCES = (
    "orderbook-settlement",
    "reserve-rent-ledger",
    "egress-accounting",
    "orchestrator-fees",
    "governance-penalties",
)
REQUIRED_METRICS = (
    "sorafs_hedging_billing_last_tick_fresh",
    "sorafs_hedging_billing_finalized_projection_ready",
    "sorafs_hedging_billing_finalized_lag_blocks",
    "sorafs_hedging_billing_finalized_head_height",
    "sorafs_hedging_billing_finalized_height",
)
REQUIRED_PRICE_FEEDS = (
    "feed-primary",
    "feed-secondary",
    "feed-tertiary",
)
CYCLE_BOUND_KINDS = (
    "statement_publication",
    "reconciliation",
    "metrics_alerts",
    "governance_approval",
)
POLICY_BOUND_KINDS = ("governance_approval",)

SENSITIVE_KEYS = {
    "authorization",
    "authorization_header",
    "access_token",
    "api_key",
    "bearer_token",
    "billing_statement",
    "body",
    "client_secret",
    "customer_email",
    "invoice_body",
    "payload",
    "payload_b64",
    "payload_body",
    "payload_bytes",
    "private_key",
    "raw_billing_statement",
    "raw_financial_records",
    "raw_line_items",
    "raw_statement",
    "reference_price_payload",
    "response_body",
    "secret",
    "seed_phrase",
    "signing_key",
    "statement_body",
    "statement_payload",
    "token",
}


def require_only_required_values(
    payload: dict[str, Any],
    array_field: str,
    field: str,
    required_values: tuple[str, ...],
    errors: list[str],
) -> None:
    """Reject reviewed inventory rows outside a required closed string set."""

    values = payload.get(array_field)
    if not isinstance(values, list):
        return
    allowed = frozenset(required_values)
    for item in values:
        if field:
            if not isinstance(item, dict):
                continue
            value = item.get(field)
        else:
            value = item
        if not isinstance(value, str) or value not in allowed:
            errors.append(f"{array_field} must not include unknown values")
            return


def require_cycle_id(payload: dict[str, Any], errors: list[str]) -> str:
    """Require a reviewed lowercase billing cycle identifier."""

    cycle_id = require_string(payload, "cycle_id", errors)
    if not cycle_id:
        return ""
    if CYCLE_ID_PATTERN.fullmatch(cycle_id) is None:
        errors.append(CYCLE_ID_ERROR)
        return ""
    forbidden = forbidden_non_production_markers(cycle_id, FORBIDDEN_CYCLE_ID_MARKERS)
    if forbidden:
        errors.append(f"cycle_id must not contain non-production markers {forbidden}")
        return ""
    return cycle_id


def require_inventory_label(
    value: Any,
    *,
    path: str,
    pattern: re.Pattern[str],
    label_error: str,
    errors: list[str],
) -> str:
    """Require a reviewed production inventory label with the expected family."""

    if not isinstance(value, str):
        return ""
    if pattern.fullmatch(value) is None:
        errors.append(label_error)
        return value
    forbidden = forbidden_non_production_markers(value, FORBIDDEN_INVENTORY_LABEL_MARKERS)
    if forbidden:
        errors.append(f"{path} must not contain non-production markers {forbidden}")
    return value


def require_scalar_inventory_labels(
    payload: dict[str, Any],
    field: str,
    *,
    pattern: re.Pattern[str],
    label_error: str,
    errors: list[str],
) -> None:
    """Require reviewed labels for scalar string inventory entries."""

    values = payload.get(field)
    if not isinstance(values, list):
        return
    for index, value in enumerate(values):
        require_inventory_label(
            value,
            path=f"{field}[{index}]",
            pattern=pattern,
            label_error=label_error,
            errors=errors,
        )


@dataclass(frozen=True)
class EvidenceKind:
    """One SFM-5 rollout evidence class."""

    name: str
    schema: str


EVIDENCE_KINDS: tuple[EvidenceKind, ...] = (
    EvidenceKind("feed_collector", "sorafs.hedging.feed_collector_canary.v1"),
    EvidenceKind("reference_price", "sorafs.hedging.reference_price_canary.v1"),
    EvidenceKind("billing_cycle", "sorafs.billing.cycle_canary.v1"),
    EvidenceKind("statement_publication", "sorafs.billing.statement_publication_canary.v1"),
    EvidenceKind("reconciliation", "sorafs.billing.reconciliation_canary.v1"),
    EvidenceKind("metrics_alerts", "sorafs.hedging_billing.metrics_alert_canary.v1"),
    EvidenceKind("native_bridge_release", "sorafs.hedging_billing.native_bridge_release.v1"),
    EvidenceKind("governance_approval", "sorafs.hedging_billing.governance_approval.v1"),
)

SCHEMA_TO_KIND = {kind.schema: kind for kind in EVIDENCE_KINDS}
KIND_BY_NAME = {kind.name: kind for kind in EVIDENCE_KINDS}
DEFAULT_REQUIRED_KINDS = tuple(kind.name for kind in EVIDENCE_KINDS)
COMMON_EVIDENCE_REQUIRED_FIELDS: tuple[str, ...] = (
    "schema",
    "status",
    "deployment_id",
    "environment",
    "deployment_context_reviewed",
)
EVIDENCE_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "feed_collector": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "feed_count",
        "accepted_feed_count",
        "feeds",
        "primary_feed_present",
        "secondary_feed_present",
        "rejected_feed_count",
        "stale_feed_count",
        "feed_lag_seconds",
        "payload_bytes_included",
        "response_bodies_included",
    ),
    "reference_price": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "decision_id_hex",
        "feed_quorum_met",
        "signed_payload_verified",
        "reference_price_micro_usd",
        "feed_count",
        "accepted_feed_count",
        "feeds",
        "rejected_feed_count",
        "stale_feed_count",
        "divergence_bps",
        "decision_lag_seconds",
        "payload_bytes_included",
    ),
    "billing_cycle": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "cycle_id",
        "cycle_index",
        "staged_cycle",
        "generated_at_unix",
        "statement_count",
        "signed_statement_count",
        "statements",
        "line_item_count",
        "line_items",
        "total_micro_xor",
        "total_usd_micro",
        "reference_price_bound",
        "reference_decision_id_hex",
        "policy_digest_hex",
        "line_item_root_hex",
        "statement_bundle_digest_hex",
        "reconciliation_digest_hex",
        "acknowledgement_required",
        "statement_bodies_included",
        "raw_financial_records_included",
        "statement_digests_hex",
    ),
    "statement_publication": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "statement_bundle_digest_hex",
        "reconciliation_digest_hex",
        "route_count",
        "passed_route_count",
        "acknowledgement_probe_count",
        "acknowledgement_probes",
        "routes",
        "response_bodies_included",
    ),
    "reconciliation": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "statement_bundle_digest_hex",
        "reconciliation_digest_hex",
        "source_count",
        "sources",
        "line_item_count",
        "line_items",
        "reconciled_line_item_count",
        "mismatch_count",
        "unmatched_event_count",
        "raw_financial_records_included",
    ),
    "metrics_alerts": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "statement_bundle_digest_hex",
        "reconciliation_digest_hex",
        "metrics_scrape_success",
        "dashboard_provisioned",
        "alert_rules_installed",
        "critical_alerts_firing",
        "metrics",
        "metric_count",
        "response_bodies_included",
    ),
    "native_bridge_release": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "bridge_abi_version",
        "artifact_count",
        "artifact_hashes_verified",
        "sdk_wrappers_verified",
        "artifacts",
    ),
    "governance_approval": COMMON_EVIDENCE_REQUIRED_FIELDS
    + (
        "statement_bundle_digest_hex",
        "reconciliation_digest_hex",
        "approved",
        "governance_vote_recorded",
        "iroha_config_bound",
        "manual_override_policy_present",
        "treasury_limits_present",
        "config_source",
        "policy_digest_hex",
    ),
}


@dataclass(frozen=True)
class ValidationOptions:
    """Thresholds for the SFM-5 rollout gate."""

    now_unix: int
    max_feed_lag_secs: int
    max_cycle_age_secs: int
    max_divergence_bps: int
    min_billing_cycles: int


def validate_threshold_options(args: argparse.Namespace) -> list[str]:
    """Validate checker threshold options before evidence evaluation."""

    errors: list[str] = []
    if args.max_divergence_bps > MAX_DIVERGENCE_BPS:
        errors.append(f"--max-divergence-bps must be <= {MAX_DIVERGENCE_BPS}")
    return errors



FINGERPRINT_FIELDS: tuple[str, ...] = (
    "deployment_id",
    "environment",
    "deployment_context_reviewed",
    "cycle_index",
    "generated_at_unix",
    "decision_id_hex",
    "statement_count",
    "reference_decision_id_hex",
    "policy_digest_hex",
    "statement_bundle_digest_hex",
    "reconciliation_digest_hex",
    "metric_count",
    "metrics",
)
BILLING_CYCLE_DETAIL_FIELDS: tuple[str, ...] = (
    "deployment_id",
    "environment",
    "cycle_id",
    "cycle_index",
    "generated_at_unix",
    "statement_count",
    "reference_decision_id_hex",
    "policy_digest_hex",
    "statement_bundle_digest_hex",
    "reconciliation_digest_hex",
        )


def validated_billing_cycle_fingerprint_values(
    kind_name: str,
    payload: dict[str, Any],
) -> dict[str, str]:
    """Return billing-cycle fingerprint fields only after canonical validation."""

    if kind_name != "billing_cycle":
        return {}
    cycle_errors: list[str] = []
    cycle_id = require_cycle_id(payload, cycle_errors)
    return {"cycle_id": cycle_id} if cycle_id else {}


def native_bridge_artifact_family(artifact_id: Any) -> str | None:
    """Return the reviewed native bridge family prefix for an artifact id."""

    if not isinstance(artifact_id, str):
        return None
    for family, prefix in NATIVE_BRIDGE_ARTIFACT_FAMILY_PREFIXES:
        if artifact_id.startswith(prefix):
            return family
    return None


def validate_native_bridge_artifact_family_coverage(
    artifact_records: list[tuple[int, dict[str, Any]]],
    errors: list[str],
) -> None:
    """Require native bridge release artifacts to cover each reviewed family."""

    covered_families: set[str] = set()
    found_unknown_artifact_family = False
    for _index, record in artifact_records:
        artifact_id = record.get("id")
        family = native_bridge_artifact_family(artifact_id)
        if family is None:
            if isinstance(artifact_id, str) and artifact_id:
                found_unknown_artifact_family = True
            continue
        covered_families.add(family)

    if found_unknown_artifact_family:
        errors.append(
            "artifacts[].id must start with a reviewed native bridge family prefix"
        )
    required_families = {
        family for family, _prefix in NATIVE_BRIDGE_ARTIFACT_FAMILY_PREFIXES
    }
    if required_families - covered_families:
        errors.append(
            "artifacts must include at least one native bridge artifact for every "
            "reviewed bridge family"
        )


def validate_routes(payload: dict[str, Any], errors: list[str]) -> None:
    for index, record in require_object_array(payload, "routes", errors):
        require_bool_true(record, "passed", errors, path=f"routes[{index}].passed")
        require_2xx_status(
            record,
            "status_code",
            errors,
            path=f"routes[{index}].status_code",
        )
        require_hex(
            record,
            "body_blake3_hex",
            HEX64_LEN,
            errors,
            path=f"routes[{index}].body_blake3_hex",
        )
        for field in ("publisher_identity_present", "signature_verified"):
            require_bool_true(record, field, errors, path=f"routes[{index}].{field}")


def validate_feed_collector(
    payload: dict[str, Any],
    errors: list[str],
    options: ValidationOptions,
) -> None:
    feed_count = require_count_equal(payload, "feed_count", "accepted_feed_count", errors)
    require_minimum_value(feed_count, "feed_count", len(REQUIRED_PRICE_FEEDS), errors)
    require_string_inventory_count_match(
        payload,
        "feeds",
        "feed_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    require_string_coverage(
        payload,
        "feeds",
        "name",
        REQUIRED_PRICE_FEEDS,
        errors,
        allow_scalar_items=False,
    )
    require_only_required_values(payload, "feeds", "name", REQUIRED_PRICE_FEEDS, errors)
    for _index, record in require_object_array(payload, "feeds", errors):
        require_string(record, "name", errors)
    require_bool_true(payload, "primary_feed_present", errors)
    require_bool_true(payload, "secondary_feed_present", errors)
    require_zero_count(payload, "rejected_feed_count", errors)
    require_zero_count(payload, "stale_feed_count", errors)
    require_maximum_int(payload, "feed_lag_seconds", options.max_feed_lag_secs, errors)
    require_false(payload, "payload_bytes_included", errors)
    require_false(payload, "response_bodies_included", errors)


def validate_reference_price(
    payload: dict[str, Any],
    errors: list[str],
    options: ValidationOptions,
) -> None:
    require_hex(payload, "decision_id_hex", HEX64_LEN, errors)
    require_bool_true(payload, "feed_quorum_met", errors)
    require_bool_true(payload, "signed_payload_verified", errors)
    require_positive_int(payload, "reference_price_micro_usd", errors)
    feed_count = require_count_equal(payload, "feed_count", "accepted_feed_count", errors)
    require_minimum_value(
        feed_count,
        "feed_count",
        len(REQUIRED_PRICE_FEEDS),
        errors,
    )
    require_string_inventory_count_match(
        payload,
        "feeds",
        "feed_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    require_string_coverage(
        payload,
        "feeds",
        "name",
        REQUIRED_PRICE_FEEDS,
        errors,
        allow_scalar_items=False,
    )
    require_only_required_values(payload, "feeds", "name", REQUIRED_PRICE_FEEDS, errors)
    for _index, record in require_object_array(payload, "feeds", errors):
        require_string(record, "name", errors)
    require_zero_count(payload, "rejected_feed_count", errors)
    require_zero_count(payload, "stale_feed_count", errors)
    require_maximum_int(payload, "divergence_bps", MAX_DIVERGENCE_BPS, errors)
    if options.max_divergence_bps < MAX_DIVERGENCE_BPS:
        require_maximum_int(
            payload,
            "divergence_bps",
            options.max_divergence_bps,
            errors,
        )
    require_maximum_int(
        payload,
        "decision_lag_seconds",
        options.max_feed_lag_secs,
        errors,
    )
    require_false(payload, "degraded", errors)
    require_false(payload, "payload_bytes_included", errors)


def validate_billing_cycle(
    payload: dict[str, Any],
    errors: list[str],
    options: ValidationOptions,
) -> None:
    require_cycle_id(payload, errors)
    require_positive_int(payload, "cycle_index", errors)
    require_bool_true(payload, "staged_cycle", errors)
    require_recent_timestamp(
        payload,
        "generated_at_unix",
        errors,
        now_unix=options.now_unix,
        max_age_secs=options.max_cycle_age_secs,
    )
    statement_count = require_count_equal(
        payload, "statement_count", "signed_statement_count", errors
    )
    require_minimum_value(statement_count, "statement_count", 1, errors)
    require_string_inventory_count_match(
        payload,
        "statements",
        "statement_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    for index, record in require_object_array(payload, "statements", errors):
        name = require_string(record, "name", errors)
        require_inventory_label(
            name,
            path=f"statements[{index}].name",
            pattern=STATEMENT_LABEL_PATTERN,
            label_error=STATEMENT_LABEL_ERROR,
            errors=errors,
        )
    require_positive_int(payload, "line_item_count", errors)
    require_string_inventory_count_match(
        payload,
        "line_items",
        "line_item_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    for index, record in require_object_array(payload, "line_items", errors):
        name = require_string(record, "name", errors)
        require_inventory_label(
            name,
            path=f"line_items[{index}].name",
            pattern=LINE_ITEM_LABEL_PATTERN,
            label_error=LINE_ITEM_LABEL_ERROR,
            errors=errors,
        )
    require_positive_int(payload, "total_micro_xor", errors)
    require_positive_int(payload, "total_usd_micro", errors)
    require_bool_true(payload, "reference_price_bound", errors)
    require_hex(payload, "reference_decision_id_hex", HEX64_LEN, errors)
    require_policy_digest(payload, errors)
    require_hex(payload, "line_item_root_hex", HEX64_LEN, errors)
    require_hex(payload, "statement_bundle_digest_hex", HEX64_LEN, errors)
    require_hex(payload, "reconciliation_digest_hex", HEX64_LEN, errors)
    require_bool_true(payload, "acknowledgement_required", errors)
    require_false(payload, "statement_bodies_included", errors)
    require_false(payload, "raw_financial_records_included", errors)
    require_hex_string_array(
        payload,
        "statement_digests_hex",
        HEX64_LEN,
        errors,
        non_empty=True,
        expected_length=statement_count if statement_count else None,
        expected_length_label="statement_count",
        unique=True,
    )


def validate_statement_publication(payload: dict[str, Any], errors: list[str]) -> None:
    require_hex(payload, "statement_bundle_digest_hex", HEX64_LEN, errors)
    require_hex(payload, "reconciliation_digest_hex", HEX64_LEN, errors)
    require_count_equal(payload, "route_count", "passed_route_count", errors)
    require_string_inventory_count_match(
        payload,
        "routes",
        "route_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    require_positive_int(payload, "acknowledgement_probe_count", errors)
    require_string_inventory_count_match(
        payload,
        "acknowledgement_probes",
        "acknowledgement_probe_count",
        errors,
    )
    require_scalar_inventory_labels(
        payload,
        "acknowledgement_probes",
        pattern=ACKNOWLEDGEMENT_PROBE_LABEL_PATTERN,
        label_error=ACKNOWLEDGEMENT_PROBE_LABEL_ERROR,
        errors=errors,
    )
    require_string_coverage(
        payload,
        "routes",
        "name",
        REQUIRED_PUBLICATION_ROUTES,
        errors,
    )
    require_only_required_values(payload, "routes", "name", REQUIRED_PUBLICATION_ROUTES, errors)
    require_false(payload, "response_bodies_included", errors)
    validate_routes(payload, errors)


def validate_reconciliation(payload: dict[str, Any], errors: list[str]) -> None:
    require_hex(payload, "statement_bundle_digest_hex", HEX64_LEN, errors)
    require_hex(payload, "reconciliation_digest_hex", HEX64_LEN, errors)
    require_positive_int(payload, "source_count", errors)
    require_string_coverage(
        payload,
        "sources",
        "name",
        REQUIRED_RECONCILIATION_SOURCES,
        errors,
    )
    require_only_required_values(
        payload,
        "sources",
        "name",
        REQUIRED_RECONCILIATION_SOURCES,
        errors,
    )
    require_string_inventory_count_match(
        payload,
        "sources",
        "source_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    require_count_equal(payload, "line_item_count", "reconciled_line_item_count", errors)
    require_string_inventory_count_match(
        payload,
        "line_items",
        "line_item_count",
        errors,
        field="name",
        allow_scalar_items=False,
    )
    for index, record in require_object_array(payload, "line_items", errors):
        name = require_string(record, "name", errors)
        require_inventory_label(
            name,
            path=f"line_items[{index}].name",
            pattern=LINE_ITEM_LABEL_PATTERN,
            label_error=LINE_ITEM_LABEL_ERROR,
            errors=errors,
        )
    require_zero_count(payload, "mismatch_count", errors)
    require_zero_count(payload, "unmatched_event_count", errors)
    require_false(payload, "raw_financial_records_included", errors)


def validate_metrics_alerts(payload: dict[str, Any], errors: list[str]) -> None:
    require_hex(payload, "statement_bundle_digest_hex", HEX64_LEN, errors)
    require_hex(payload, "reconciliation_digest_hex", HEX64_LEN, errors)
    require_bool_true(payload, "metrics_scrape_success", errors)
    require_bool_true(payload, "dashboard_provisioned", errors)
    require_bool_true(payload, "alert_rules_installed", errors)
    require_false(payload, "critical_alerts_firing", errors)
    require_string_coverage(payload, "metrics", "", REQUIRED_METRICS, errors)
    require_only_required_values(payload, "metrics", "", REQUIRED_METRICS, errors)
    require_positive_int(payload, "metric_count", errors)
    require_string_inventory_count_match(payload, "metrics", "metric_count", errors)
    require_false(payload, "response_bodies_included", errors)


def validate_native_bridge_release(payload: dict[str, Any], errors: list[str]) -> None:
    bridge_abi_version = require_minimum_int(payload, "bridge_abi_version", 1, errors)
    if (
        bridge_abi_version is not None
        and bridge_abi_version != REQUIRED_NATIVE_BRIDGE_ABI_VERSION
    ):
        errors.append(
            "bridge_abi_version must equal the sole first-release ABI "
            f"{REQUIRED_NATIVE_BRIDGE_ABI_VERSION}"
        )
    artifact_count = require_positive_int(payload, "artifact_count", errors)
    require_minimum_value(
        artifact_count,
        "artifact_count",
        DEFAULT_MIN_NATIVE_BRIDGE_ARTIFACTS,
        errors,
    )
    require_bool_true(payload, "artifact_hashes_verified", errors)
    require_bool_true(payload, "sdk_wrappers_verified", errors)
    require_false(payload, "debug_artifacts", errors)
    artifact_records = require_object_array(payload, "artifacts", errors)
    if not artifact_records:
        return
    require_count_length_match(
        artifact_count,
        artifact_records,
        "artifact_count",
        "artifacts",
        errors,
    )
    require_string_inventory_count_match(
        payload,
        "artifacts",
        "artifact_count",
        errors,
        field="id",
        allow_scalar_items=False,
    )
    for index, record in artifact_records:
        artifact_id = require_string(record, "id", errors)
        require_inventory_label(
            artifact_id,
            path=f"artifacts[{index}].id",
            pattern=NATIVE_BRIDGE_ARTIFACT_ID_PATTERN,
            label_error=NATIVE_BRIDGE_ARTIFACT_ID_ERROR,
            errors=errors,
        )
        require_hex(record, "sha256", HEX64_LEN, errors)
    validate_native_bridge_artifact_family_coverage(artifact_records, errors)


def validate_governance_approval(payload: dict[str, Any], errors: list[str]) -> None:
    require_hex(payload, "statement_bundle_digest_hex", HEX64_LEN, errors)
    require_hex(payload, "reconciliation_digest_hex", HEX64_LEN, errors)
    require_config_backed_governance_approval(payload, errors)
    require_bool_true(payload, "manual_override_policy_present", errors)
    require_bool_true(payload, "treasury_limits_present", errors)
    require_policy_digest(payload, errors)
    require_false_or_governed(
        payload,
        "hedge_execution_enabled",
        "hedge_execution_governed",
        errors,
    )


def validate_kind_specific(
    kind: EvidenceKind,
    payload: dict[str, Any],
    errors: list[str],
    options: ValidationOptions,
) -> None:
    require_passed_status(payload, errors)

    if kind.name == "feed_collector":
        validate_feed_collector(payload, errors, options)
    elif kind.name == "reference_price":
        validate_reference_price(payload, errors, options)
    elif kind.name == "billing_cycle":
        validate_billing_cycle(payload, errors, options)
    elif kind.name == "statement_publication":
        validate_statement_publication(payload, errors)
    elif kind.name == "reconciliation":
        validate_reconciliation(payload, errors)
    elif kind.name == "metrics_alerts":
        validate_metrics_alerts(payload, errors)
    elif kind.name == "native_bridge_release":
        validate_native_bridge_release(payload, errors)
    elif kind.name == "governance_approval":
        validate_governance_approval(payload, errors)


def validate_evidence_payload(
    payload: dict[str, Any],
    options: ValidationOptions,
) -> tuple[str | None, list[str]]:
    return validate_standard_evidence_payload(
        payload,
        SCHEMA_TO_KIND,
        "SoraFS SFM-5 rollout artifact",
        SENSITIVE_KEYS,
        "rollout evidence",
        lambda kind, checked_payload, errors: validate_kind_specific(
            kind, checked_payload, errors, options
        ),
        require_reviewed_deployment_context=True,
    )


def require_single_active_digest(
    digests: set[str],
    errors: list[str],
    *,
    label: str,
) -> set[str]:
    """Return one active rollout digest or fail closed on mixed anchors."""

    if len(digests) <= 1:
        return digests
    errors.append(f"{label} must contain exactly one active digest")
    return set()


def require_single_active_binding(
    bindings: set[Any],
    errors: list[str],
    *,
    label: str,
) -> set[Any]:
    """Return one active rollout binding or fail closed on mixed anchors."""

    if len(bindings) <= 1:
        return bindings
    errors.append(f"{label} must contain exactly one active binding")
    return set()


def build_summary(
    evidence_dirs: list[Path],
    evidence_files: list[Path],
    required_kinds: tuple[str, ...],
    options: ValidationOptions,
    summary_out: Path | None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []

    artifacts_by_kind = init_evidence_artifact_buckets(DEFAULT_REQUIRED_KINDS)
    valid_billing_cycles: list[dict[str, Any]] = []
    valid_billing_cycle_artifacts: list[dict[str, Any]] = []
    valid_reference_decision_ids: set[str] = set()
    valid_policy_digests: set[str] = set()
    valid_cycle_bindings: set[tuple[str, str]] = set()
    cycle_bound_artifacts: list[tuple[str, dict[str, Any]]] = []
    policy_bound_artifacts: list[tuple[str, dict[str, Any]]] = []
    metric_counts: set[int] = set()
    metric_names: set[str] = set()
    files = discover_evidence_files(
        evidence_dirs,
        evidence_files,
        errors,
        reserved_output_paths=() if summary_out is None else (summary_out,),
    )
    explicit = evidence_path_identities(evidence_files, errors)

    for path in files:
        loaded = load_evidence_json_with_sha256_or_record_error(
            path, MAX_EVIDENCE_BYTES, errors
        )
        if loaded is None:
            continue
        payload, digest = loaded
        kind_name, validation_errors = validate_evidence_payload(payload, options)
        if kind_name is None:
            record_explicit_evidence_validation_errors(
                path, explicit, validation_errors, errors
            )
            continue
        artifact = build_evidence_artifact(
            archive_artifact_path_label(path, evidence_dirs),
            digest,
            payload,
            validation_errors,
            FINGERPRINT_FIELDS,
        )
        fingerprint_values = validated_billing_cycle_fingerprint_values(
            kind_name,
            payload,
        )
        if fingerprint_values:
            evidence_artifact_fingerprint(artifact).update(fingerprint_values)
        artifact_valid = evidence_artifact_is_valid(artifact)
        if kind_name == "billing_cycle" and artifact_valid:
            valid_billing_cycle_artifacts.append(artifact)
            policy_digest = evidence_artifact_fingerprint(artifact).get("policy_digest_hex")
            if isinstance(policy_digest, str):
                valid_policy_digests.add(policy_digest)
        if kind_name == "reference_price" and artifact_valid:
            decision_id = payload.get("decision_id_hex")
            if isinstance(decision_id, str):
                valid_reference_decision_ids.add(decision_id)
        if kind_name == "metrics_alerts" and artifact_valid:
            record_observed_evidence_value(metric_counts, payload.get("metric_count"))
            metric_names.update(hashable_evidence_values(payload.get("metrics")))
        if kind_name in CYCLE_BOUND_KINDS and artifact_valid:
            cycle_bound_artifacts.append((kind_name, artifact))
        if kind_name in POLICY_BOUND_KINDS and artifact_valid:
            policy_bound_artifacts.append((kind_name, artifact))
        record_evidence_artifact(artifacts_by_kind, kind_name, artifact, errors)
        record_evidence_validation_errors(path, validation_errors, errors)

    if required_evidence_has_all_kinds(
        required_kinds, ("billing_cycle", "reference_price")
    ):
        for artifact in valid_billing_cycle_artifacts:
            cycle = evidence_artifact_fingerprint(artifact)
            decision_id = cycle.get("reference_decision_id_hex")
            record_string_value_binding_errors(
                artifact,
                decision_id,
                valid_reference_decision_ids,
                errors,
                message=(
                    "billing_cycle reference_decision_id_hex must reference a valid "
                    "reference_price decision_id_hex"
                ),
            )

    valid_billing_cycles = [
        {
            field: cycle[field]
            for field in BILLING_CYCLE_DETAIL_FIELDS
            if field in cycle
        }
        for artifact in valid_billing_cycle_artifacts
        for cycle in [evidence_artifact_fingerprint(artifact)]
        if evidence_artifact_is_valid(artifact)
    ]
    valid_cycle_bindings = {
        (statement_bundle, reconciliation_digest)
        for cycle in valid_billing_cycles
        for statement_bundle in [cycle.get("statement_bundle_digest_hex")]
        for reconciliation_digest in [cycle.get("reconciliation_digest_hex")]
        if isinstance(statement_bundle, str) and isinstance(reconciliation_digest, str)
    }

    valid_cycle_bindings = require_single_active_binding(
        valid_cycle_bindings,
        errors,
        label="valid_cycle_bindings",
    )
    valid_policy_digests = require_single_active_digest(
        valid_policy_digests,
        errors,
        label="valid_policy_digests",
    )

    if required_evidence_has_any_kind(required_kinds, ("billing_cycle",)):
        distinct_cycle_ids = {
            cycle["cycle_id"]
            for cycle in valid_billing_cycles
            if isinstance(cycle.get("cycle_id"), str)
        }
        require_minimum_value(
            len(distinct_cycle_ids),
            "billing_cycle rollout evidence",
            options.min_billing_cycles,
            errors,
            message=(
                "billing_cycle rollout evidence must include at least "
                f"{options.min_billing_cycles} distinct valid staged cycles"
            ),
        )

    validate_bound_evidence_tuple_references(
        required_kinds=required_kinds,
        missing_anchor_required_kinds=CYCLE_BOUND_KINDS,
        bound_artifacts=cycle_bound_artifacts,
        valid_anchor_bindings=valid_cycle_bindings,
        binding_fields=("statement_bundle_digest_hex", "reconciliation_digest_hex"),
        errors=errors,
        binding_error_template=(
            "{kind_name} statement_bundle_digest_hex and "
            "reconciliation_digest_hex must match a valid billing_cycle artifact"
        ),
        missing_anchor_error_template=(
            "{kind_name} statement_bundle_digest_hex and "
            "reconciliation_digest_hex require a valid billing_cycle artifact"
        ),
    )

    validate_bound_evidence_digest_references(
        required_kinds=required_kinds,
        missing_anchor_required_kinds=("billing_cycle",) + POLICY_BOUND_KINDS,
        bound_artifacts=policy_bound_artifacts,
        valid_anchor_digests=valid_policy_digests,
        digest_field="policy_digest_hex",
        errors=errors,
        binding_error_template=(
            "{kind_name} policy_digest_hex must reference a valid "
            "billing_cycle policy_digest_hex"
        ),
        missing_anchor_error_template=(
            "{kind_name} policy_digest_hex requires a valid billing_cycle "
            "policy_digest_hex"
        ),
    )

    required = build_required_evidence_summary(
        required_kinds,
        artifacts_by_kind,
        evidence_schema_by_kind(KIND_BY_NAME),
        errors,
        evidence_label="rollout",
    )

    summary = {
        "schema": SUMMARY_SCHEMA,
        "status": evidence_gate_status(errors),
        "required_kinds": required_evidence_kind_names(required_kinds),
        "thresholds": {
            "max_feed_lag_secs": options.max_feed_lag_secs,
            "max_cycle_age_secs": options.max_cycle_age_secs,
            "max_divergence_bps": options.max_divergence_bps,
            "min_billing_cycles": options.min_billing_cycles,
        },
        "evidence_file_count": count_evidence_files(files),
        "recognized_artifact_count": count_evidence_artifacts(artifacts_by_kind),
        "recognized_artifacts": recognized_evidence_artifacts(artifacts_by_kind),
        "valid_billing_cycles": valid_billing_cycles,
        "valid_reference_decision_ids": sorted(valid_reference_decision_ids),
        "valid_policy_digests": sorted(valid_policy_digests),
        "metrics": sorted(metric_names),
        "metric_count_values": sorted(metric_counts),
        "valid_cycle_bindings": [
            {
                "statement_bundle_digest_hex": statement_bundle,
                "reconciliation_digest_hex": reconciliation_digest,
            }
            for statement_bundle, reconciliation_digest in sorted(valid_cycle_bindings)
        ],
        "required": required,
        "errors": errors,
    }
    return summary, errors


def main(argv: list[str] | None = None) -> int:
    parser = EvidenceArgumentParser(
        description="Validate SoraFS SFM-5 hedging and billing rollout evidence artifacts."
    )
    add_topology_qualification_argument(parser)
    parser.add_argument(
        "--evidence-dir",
        action="append",
        type=Path,
        default=[],
        help="Directory containing rollout evidence JSON artifacts.",
    )
    parser.add_argument(
        "--evidence",
        action="append",
        type=Path,
        default=[],
        help="Explicit rollout evidence JSON artifact.",
    )
    parser.add_argument(
        "--require-kind",
        action="append",
        default=[],
        help="Required evidence kind, or comma-separated kinds. Defaults to all SFM-5 kinds.",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional summary JSON output path.")
    parser.add_argument(
        "--now-unix",
        type=positive_int_arg,
        required=True,
        help="Required reviewed validator clock used for age checks.",
    )
    parser.add_argument(
        "--max-feed-lag-secs",
        type=non_negative_int_arg,
        default=DEFAULT_MAX_FEED_LAG_SECS,
    )
    parser.add_argument(
        "--max-cycle-age-secs",
        type=non_negative_int_arg,
        default=DEFAULT_MAX_CYCLE_AGE_SECS,
    )
    parser.add_argument(
        "--max-divergence-bps",
        type=non_negative_int_arg,
        default=DEFAULT_MAX_DIVERGENCE_BPS,
    )
    parser.add_argument(
        "--min-billing-cycles",
        type=positive_int_arg,
        default=DEFAULT_MIN_BILLING_CYCLES,
    )
    try:
        expanded = expand_response_args(sys.argv[1:] if argv is None else argv, parser)
    except ValueError as error:
        emit_checker_exception(error)
        return 2
    try:
        args = parser.parse_args(expanded)
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 1

    try:
        required_kinds = parse_required_evidence_kinds(
            args.require_kind,
            allowed_kinds=KIND_BY_NAME,
            default_required=DEFAULT_REQUIRED_KINDS,
        )
    except ValueError as error:
        emit_checker_exception(error)
        return 2

    threshold_errors = validate_threshold_options(args)
    if threshold_errors:
        emit_checker_error_lines(threshold_errors)
        return 2

    options = ValidationOptions(
        now_unix=args.now_unix,
        max_feed_lag_secs=args.max_feed_lag_secs,
        max_cycle_age_secs=args.max_cycle_age_secs,
        max_divergence_bps=args.max_divergence_bps,
        min_billing_cycles=args.min_billing_cycles,
    )
    preflight_errors = validate_checker_preflight(args)
    if preflight_errors:
        emit_checker_error_lines(preflight_errors)
        return 2

    summary, errors = build_summary(
        args.evidence_dir, args.evidence, required_kinds, options, args.summary_out
    )
    errors.extend(
        bind_lane_summary_to_topology(
            summary, args.topology_qualification_summary
        )
    )
    summary["status"] = evidence_gate_status(errors)
    rendered_summary, summary_errors = render_and_write_checker_summary(
        args.summary_out, summary
    )
    if summary_errors:
        emit_checker_error_lines(summary_errors)
        return 2

    if errors:
        emit_checker_error_block(
            "ERROR: SoraFS hedging/billing rollout evidence is incomplete:",
            errors,
        )
        return 1

    emit_checker_notice(
        "SoraFS hedging/billing rollout evidence is ready: "
        f"{summary['recognized_artifact_count']} recognized artifact(s) cover "
        f"{len(required_kinds)} required kind(s), including "
        f"{len(summary['valid_billing_cycles'])} staged billing cycle(s).",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
