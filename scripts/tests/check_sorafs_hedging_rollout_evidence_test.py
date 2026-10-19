"""Tests for scripts/check_sorafs_hedging_rollout_evidence.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "check_sorafs_hedging_rollout_evidence.py"
SPEC = importlib.util.spec_from_file_location(
    "check_sorafs_hedging_rollout_evidence",
    MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader  # pragma: no cover - defensive
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TEST_DIR = Path(__file__).resolve().parent
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))
from sorafs_rollout_runner_test_support import TopologyBoundChecker  # noqa: E402


NOW_UNIX = 1_800_100_000
GENERATED_AT = NOW_UNIX - 120
DIGEST = "ab" * 32
DIGEST_2 = "ef" * 32
DEPLOYMENT_ID = "hedging-production-a"
ENVIRONMENT = "production"
CHECKER = TopologyBoundChecker(
    MODULE.main,
    deployment_id=DEPLOYMENT_ID,
    environment=ENVIRONMENT,
    name="hedging-checker",
)


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def with_context(payload: dict) -> dict:
    payload.setdefault("generated_at_unix", GENERATED_AT)
    payload["deployment_id"] = DEPLOYMENT_ID
    payload["environment"] = ENVIRONMENT
    payload["deployment_context_reviewed"] = True
    return payload


def feed_collector(*, lag: int = 60) -> dict:
    return with_context({
        "schema": "sorafs.hedging.feed_collector_canary.v1",
        "status": "passed",
        "feed_count": len(MODULE.REQUIRED_PRICE_FEEDS),
        "accepted_feed_count": len(MODULE.REQUIRED_PRICE_FEEDS),
        "feeds": [{"name": name} for name in MODULE.REQUIRED_PRICE_FEEDS],
        "primary_feed_present": True,
        "secondary_feed_present": True,
        "rejected_feed_count": 0,
        "stale_feed_count": 0,
        "feed_lag_seconds": lag,
        "payload_bytes_included": False,
        "response_bodies_included": False,
    })


def reference_price(*, divergence_bps: int = 50) -> dict:
    return with_context({
        "schema": "sorafs.hedging.reference_price_canary.v1",
        "status": "passed",
        "decision_id_hex": DIGEST,
        "feed_quorum_met": True,
        "signed_payload_verified": True,
        "reference_price_micro_usd": 4_200_000,
        "feed_count": len(MODULE.REQUIRED_PRICE_FEEDS),
        "accepted_feed_count": len(MODULE.REQUIRED_PRICE_FEEDS),
        "feeds": [{"name": name} for name in MODULE.REQUIRED_PRICE_FEEDS],
        "rejected_feed_count": 0,
        "stale_feed_count": 0,
        "divergence_bps": divergence_bps,
        "decision_lag_seconds": 60,
        "degraded": False,
        "payload_bytes_included": False,
    })


def billing_cycle(cycle_id: str, cycle_index: int, *, generated_at: int = GENERATED_AT) -> dict:
    return with_context({
        "schema": "sorafs.billing.cycle_canary.v1",
        "status": "passed",
        "cycle_id": cycle_id,
        "cycle_index": cycle_index,
        "staged_cycle": True,
        "generated_at_unix": generated_at,
        "statement_count": 2,
        "signed_statement_count": 2,
        "statements": [
            {"name": "billing-statement-00"},
            {"name": "billing-statement-01"},
        ],
        "line_item_count": 5,
        "line_items": [
            {"name": f"billing-line-item-{index:02d}"} for index in range(5)
        ],
        "total_micro_xor": 10_000,
        "total_usd_micro": 42_000,
        "reference_price_bound": True,
        "reference_decision_id_hex": DIGEST,
        "policy_digest_hex": DIGEST,
        "line_item_root_hex": DIGEST,
        "statement_bundle_digest_hex": DIGEST,
        "reconciliation_digest_hex": DIGEST,
        "acknowledgement_required": True,
        "statement_bodies_included": False,
        "raw_financial_records_included": False,
        "statement_digests_hex": [DIGEST, "cd" * 32],
    })


def statement_publication() -> dict:
    routes = [
        {
            "name": name,
            "passed": True,
            "status_code": 200 if name != "statement_acknowledgement" else 202,
            "body_blake3_hex": DIGEST_2,
            "publisher_identity_present": True,
            "signature_verified": True,
        }
        for name in ("statements_list", "statement_fetch", "statement_acknowledgement")
    ]
    return with_context({
        "schema": "sorafs.billing.statement_publication_canary.v1",
        "status": "passed",
        "statement_bundle_digest_hex": DIGEST,
        "reconciliation_digest_hex": DIGEST,
        "route_count": len(routes),
        "passed_route_count": len(routes),
        "acknowledgement_probe_count": 1,
        "acknowledgement_probes": ["billing-ack-probe-00"],
        "response_bodies_included": False,
        "routes": routes,
    })


def reconciliation(*, mismatch_count: int = 0) -> dict:
    return with_context({
        "schema": "sorafs.billing.reconciliation_canary.v1",
        "status": "passed",
        "statement_bundle_digest_hex": DIGEST,
        "reconciliation_digest_hex": DIGEST,
        "source_count": 5,
        "sources": [
            {"name": "orderbook-settlement"},
            {"name": "reserve-rent-ledger"},
            {"name": "egress-accounting"},
            {"name": "orchestrator-fees"},
            {"name": "governance-penalties"},
        ],
        "line_item_count": 5,
        "line_items": [
            {"name": f"billing-line-item-{index:02d}"} for index in range(5)
        ],
        "reconciled_line_item_count": 5,
        "mismatch_count": mismatch_count,
        "unmatched_event_count": 0,
        "raw_financial_records_included": False,
    })


def metrics_alerts(*, critical: bool = False) -> dict:
    return with_context({
        "schema": "sorafs.hedging_billing.metrics_alert_canary.v1",
        "status": "passed",
        "statement_bundle_digest_hex": DIGEST,
        "reconciliation_digest_hex": DIGEST,
        "metrics_scrape_success": True,
        "dashboard_provisioned": True,
        "alert_rules_installed": True,
        "critical_alerts_firing": critical,
        "metrics": [
            "sorafs_hedging_billing_last_tick_fresh",
            "sorafs_hedging_billing_finalized_projection_ready",
            "sorafs_hedging_billing_finalized_lag_blocks",
            "sorafs_hedging_billing_finalized_head_height",
            "sorafs_hedging_billing_finalized_height",
        ],
        "metric_count": 5,
        "response_bodies_included": False,
    })


def native_bridge_release(
    *,
    abi: int = 31,
    artifacts: list[dict[str, str]] | None = None,
) -> dict:
    artifacts = artifacts or [
        {"id": "hedging-native-artifact-swift-xcframework", "sha256": DIGEST},
        {"id": "hedging-native-artifact-jni-macos-arm64", "sha256": "ef" * 32},
    ]
    return with_context({
        "schema": "sorafs.hedging_billing.native_bridge_release.v1",
        "status": "passed",
        "bridge_abi_version": abi,
        "artifact_count": len(artifacts),
        "artifact_hashes_verified": True,
        "sdk_wrappers_verified": True,
        "debug_artifacts": False,
        "artifacts": artifacts,
    })


def governance_approval() -> dict:
    return with_context({
        "schema": "sorafs.hedging_billing.governance_approval.v1",
        "status": "passed",
        "statement_bundle_digest_hex": DIGEST,
        "reconciliation_digest_hex": DIGEST,
        "approved": True,
        "governance_vote_recorded": True,
        "iroha_config_bound": True,
        "manual_override_policy_present": True,
        "treasury_limits_present": True,
        "config_source": "iroha_config",
        "policy_digest_hex": DIGEST,
        "hedge_execution_enabled": False,
    })


def write_complete_evidence(root: Path) -> None:
    write_json(root / "feed-collector.json", feed_collector())
    write_json(root / "reference-price.json", reference_price())
    write_json(root / "billing-cycle-1.json", billing_cycle("billing-cycle-1", 1))
    write_json(root / "billing-cycle-2.json", billing_cycle("billing-cycle-2", 2))
    write_json(root / "statement-publication.json", statement_publication())
    write_json(root / "reconciliation.json", reconciliation())
    write_json(root / "metrics-alerts.json", metrics_alerts())
    write_json(root / "native-bridge-release.json", native_bridge_release())
    write_json(root / "governance-approval.json", governance_approval())


CYCLE_BOUND_FIXTURES = (
    ("statement_publication", "statement-publication.json", statement_publication),
    ("reconciliation", "reconciliation.json", reconciliation),
    ("metrics_alerts", "metrics-alerts.json", metrics_alerts),
    ("governance_approval", "governance-approval.json", governance_approval),
)

POLICY_BOUND_FIXTURES = (
    ("governance_approval", "governance-approval.json", governance_approval),
)


def run_gate(root: Path, *extra: str) -> int:
    return CHECKER(["--evidence-dir", str(root), "--now-unix", str(NOW_UNIX), *extra])


def validation_options(**overrides: int) -> object:
    values = {
        "now_unix": NOW_UNIX,
        "max_feed_lag_secs": MODULE.DEFAULT_MAX_FEED_LAG_SECS,
        "max_cycle_age_secs": MODULE.DEFAULT_MAX_CYCLE_AGE_SECS,
        "max_divergence_bps": MODULE.DEFAULT_MAX_DIVERGENCE_BPS,
        "min_billing_cycles": MODULE.DEFAULT_MIN_BILLING_CYCLES,
    }
    values.update(overrides)
    return MODULE.ValidationOptions(**values)


def test_complete_rollout_evidence_passes(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 0

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["schema"] == "sorafs.hedging_billing.rollout_evidence_gate.v1"
    assert payload["status"] == "ready"
    assert payload["required"]["billing_cycle"]["valid"] is True
    assert len(payload["valid_billing_cycles"]) == 2
    assert payload["valid_cycle_bindings"] == [
        {
            "statement_bundle_digest_hex": DIGEST,
            "reconciliation_digest_hex": DIGEST,
        }
    ]
    assert payload["valid_policy_digests"] == [DIGEST]
    assert payload["metrics"] == sorted(MODULE.REQUIRED_METRICS)
    assert payload["metric_count_values"] == [len(MODULE.REQUIRED_METRICS)]
    metrics_artifact = payload["required"]["metrics_alerts"]["artifacts"][0]
    assert metrics_artifact["fingerprint"]["metric_count"] == len(
        MODULE.REQUIRED_METRICS
    )
    assert metrics_artifact["fingerprint"]["metrics"] == list(MODULE.REQUIRED_METRICS)
    assert payload["required"]["feed_collector"]["artifacts"][0]["fingerprint"][
        "deployment_id"
    ] == DEPLOYMENT_ID


def test_bound_fixture_tables_cover_checker_bound_kind_sets() -> None:
    assert (
        tuple(kind_name for kind_name, _file_name, _factory in CYCLE_BOUND_FIXTURES)
        == MODULE.CYCLE_BOUND_KINDS
    )
    assert (
        tuple(kind_name for kind_name, _file_name, _factory in POLICY_BOUND_FIXTURES)
        == MODULE.POLICY_BOUND_KINDS
    )


def test_fixture_inventories_cover_checker_required_sets() -> None:
    assert tuple(route["name"] for route in statement_publication()["routes"]) == (
        MODULE.REQUIRED_PUBLICATION_ROUTES
    )
    assert tuple(source["name"] for source in reconciliation()["sources"]) == (
        MODULE.REQUIRED_RECONCILIATION_SOURCES
    )


def test_payload_safety_flags_are_required(tmp_path: Path) -> None:
    cases = (
        (
            "feed_collector",
            "feed-collector.json",
            feed_collector,
            "payload_bytes_included",
        ),
        (
            "feed_collector",
            "feed-collector.json",
            feed_collector,
            "response_bodies_included",
        ),
        (
            "reference_price",
            "reference-price.json",
            reference_price,
            "degraded",
        ),
        (
            "reference_price",
            "reference-price.json",
            reference_price,
            "payload_bytes_included",
        ),
        (
            "billing_cycle",
            "billing-cycle-1.json",
            lambda: billing_cycle("billing-cycle-1", 1),
            "statement_bodies_included",
        ),
        (
            "billing_cycle",
            "billing-cycle-1.json",
            lambda: billing_cycle("billing-cycle-1", 1),
            "raw_financial_records_included",
        ),
        (
            "statement_publication",
            "statement-publication.json",
            statement_publication,
            "response_bodies_included",
        ),
        (
            "reconciliation",
            "reconciliation.json",
            reconciliation,
            "raw_financial_records_included",
        ),
        (
            "metrics_alerts",
            "metrics-alerts.json",
            metrics_alerts,
            "critical_alerts_firing",
        ),
        (
            "metrics_alerts",
            "metrics-alerts.json",
            metrics_alerts,
            "response_bodies_included",
        ),
        (
            "native_bridge_release",
            "native-bridge-release.json",
            native_bridge_release,
            "debug_artifacts",
        ),
    )
    for kind, filename, factory, field in cases:
        root = tmp_path / f"{kind}-{field}"
        root.mkdir()
        write_complete_evidence(root)
        payload = factory()
        del payload[field]
        write_json(root / filename, payload)
        summary = root / "summary.json"

        assert run_gate(root, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        artifact = result["required"][kind]["artifacts"][0]
        assert artifact["valid"] is False
        assert f"{field} must be false" in artifact["errors"]


def test_response_file_arguments_pass(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    args = tmp_path / "hedging.args"
    args.write_text(
        f"--evidence-dir {tmp_path}\n--now-unix {NOW_UNIX}\n",
        encoding="utf-8",
    )

    assert CHECKER([f"@{args}"]) == 0


def test_deployment_context_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = feed_collector()
    del payload["deployment_id"]
    write_json(tmp_path / "feed-collector.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["feed_collector"]["artifacts"][0]
    assert "deployment_id must be a non-empty canonical string" in artifact["errors"]


def test_unreviewed_deployment_context_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = governance_approval()
    payload["deployment_id"] = "hedging-dev-a"
    payload["environment"] = "dev"
    write_json(tmp_path / "governance-approval.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact_errors = result["required"]["governance_approval"]["artifacts"][0][
        "errors"
    ]
    assert (
        "deployment_id must not contain non-reviewed deployment markers ['dev']"
        in artifact_errors
    )
    assert "environment must be one of" in "\n".join(artifact_errors)


def test_missing_second_billing_cycle_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    (tmp_path / "billing-cycle-2.json").unlink()

    assert run_gate(tmp_path) == 1


def test_stale_feed_collector_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "feed-collector.json", feed_collector(lag=10_000))

    assert run_gate(tmp_path) == 1


def test_reference_price_divergence_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "reference-price.json", reference_price(divergence_bps=2_000))

    assert run_gate(tmp_path) == 1


def test_reference_price_divergence_bps_must_be_basis_points() -> None:
    payload = reference_price(divergence_bps=10_001)
    options = validation_options(max_divergence_bps=MODULE.MAX_DIVERGENCE_BPS + 1)

    kind, errors = MODULE.validate_evidence_payload(payload, options)

    assert kind == "reference_price"
    assert "divergence_bps must be <= 10000" in errors


def test_reference_price_degraded_flag_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    del payload["degraded"]
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["reference_price"]["artifacts"][0]
    assert "degraded must be false" in artifact["errors"]


def test_max_divergence_threshold_must_be_possible(
    tmp_path: Path,
    capsys,
) -> None:
    summary = tmp_path / "summary.json"

    assert (
        run_gate(
            tmp_path,
            "--summary-out",
            str(summary),
            "--max-divergence-bps",
            "10001",
        )
        == 2
    )

    captured = capsys.readouterr()
    assert "--max-divergence-bps must be <= 10000" in captured.err
    assert not summary.exists()


def test_integer_unit_slo_fields_reject_fractional_and_negative_values(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    feed_payload = feed_collector()
    feed_payload["feed_lag_seconds"] = 12.5
    write_json(tmp_path / "feed-collector.json", feed_payload)
    reference_payload = reference_price()
    reference_payload["divergence_bps"] = 50.5
    reference_payload["decision_lag_seconds"] = -1
    write_json(tmp_path / "reference-price.json", reference_payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    feed_errors = result["required"]["feed_collector"]["artifacts"][0]["errors"]
    reference_errors = result["required"]["reference_price"]["artifacts"][0]["errors"]
    assert "feed_lag_seconds must be a non-negative integer" in feed_errors
    assert "divergence_bps must be a non-negative integer" in reference_errors
    assert "decision_lag_seconds must be a non-negative integer" in reference_errors


def test_feed_collector_feed_count_must_match_unique_feeds(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = feed_collector()
    payload["feed_count"] += 1
    payload["accepted_feed_count"] = payload["feed_count"]
    write_json(tmp_path / "feed-collector.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["feed_collector"]["artifacts"][0]
    assert "feed_count must match unique feeds count" in artifact["errors"]


def test_feed_collector_feeds_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = feed_collector()
    payload["feeds"].append(dict(payload["feeds"][0]))
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "feed-collector.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["feed_collector"]["artifacts"][0]
    assert "feeds must not contain duplicate values" in artifact["errors"]
    assert "feed_count must match unique feeds count" in artifact["errors"]


def test_feed_collector_feeds_must_not_include_unknown_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = feed_collector()
    payload["feeds"].append({"name": "feed-shadow"})
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "feed-collector.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["feed_collector"]["artifacts"][0]
    assert "feeds must not include unknown values" in artifact["errors"]


def test_feed_collector_must_cover_required_price_feeds(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = feed_collector()
    payload["feeds"] = payload["feeds"][:-1]
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "feed-collector.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["feed_collector"]["artifacts"][0]
    assert "feed_count must be at least 3" in artifact["errors"]
    assert "feeds must include name `feed-tertiary`" in artifact["errors"]


def test_reference_price_feed_count_must_match_unique_feeds(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    payload["feed_count"] += 1
    payload["accepted_feed_count"] = payload["feed_count"]
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reference_price"]["artifacts"][0]
    assert "feed_count must match unique feeds count" in artifact["errors"]


def test_reference_price_feeds_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    payload["feeds"].append(dict(payload["feeds"][0]))
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reference_price"]["artifacts"][0]
    assert "feeds must not contain duplicate values" in artifact["errors"]
    assert "feed_count must match unique feeds count" in artifact["errors"]


def test_reference_price_feeds_must_not_include_unknown_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    payload["feeds"].append({"name": "feed-shadow"})
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reference_price"]["artifacts"][0]
    assert "feeds must not include unknown values" in artifact["errors"]


def test_reference_price_must_cover_required_price_feeds(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    payload["feeds"] = payload["feeds"][:-1]
    payload["feed_count"] = len(payload["feeds"])
    payload["accepted_feed_count"] = len(payload["feeds"])
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reference_price"]["artifacts"][0]
    assert "feed_count must be at least 3" in artifact["errors"]
    assert "feeds must include name `feed-tertiary`" in artifact["errors"]


def test_reference_price_accepted_feed_count_must_equal_feed_count(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = reference_price()
    payload["accepted_feed_count"] -= 1
    write_json(tmp_path / "reference-price.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reference_price"]["artifacts"][0]
    assert "accepted_feed_count must equal feed_count" in artifact["errors"]


def test_sensitive_statement_body_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statement_body"] = {"account": "buyer"}
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path) == 1


def test_sensitive_key_spelling_variants_fail(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = feed_collector()
    payload["transport"] = {
        "accessToken": "runtime-only-token",
        "api-key": "runtime-only-key",
        "payloadIncluded": True,
        "privateKey": "runtime-only-private-key",
        "response-body": "{}",
    }
    write_json(tmp_path / "feed-collector.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    errors = "\n".join(result["required"]["feed_collector"]["artifacts"][0]["errors"])
    assert (
        errors.count("transport.<sensitive-key> must not be present in rollout evidence")
        == 4
    )
    assert "transport.<sensitive-inclusion-marker> must be false" in errors
    assert "transport.accessToken" not in errors
    assert "transport.api-key" not in errors
    assert "transport.payloadIncluded" not in errors
    assert "transport.privateKey" not in errors
    assert "transport.response-body" not in errors


def test_statement_publication_route_count_must_match_unique_routes(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["route_count"] += 1
    payload["passed_route_count"] = payload["route_count"]
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert "route_count must match unique routes count" in artifact["errors"]


def test_statement_publication_routes_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["routes"].append(dict(payload["routes"][0]))
    payload["route_count"] = len(payload["routes"])
    payload["passed_route_count"] = len(payload["routes"])
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert "routes must not contain duplicate values" in artifact["errors"]
    assert "route_count must match unique routes count" in artifact["errors"]


def test_statement_publication_routes_must_not_include_unknown_values(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    unknown = dict(payload["routes"][0])
    unknown["name"] = "statement_shadow_route"
    payload["routes"].append(unknown)
    payload["route_count"] = len(payload["routes"])
    payload["passed_route_count"] = len(payload["routes"])
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert "routes must not include unknown values" in artifact["errors"]


def test_statement_publication_route_body_hash_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    del payload["routes"][0]["body_blake3_hex"]
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert "routes[0].body_blake3_hex must be a non-empty string" in artifact["errors"]


def test_statement_publication_ack_probe_count_must_match_unique_probes(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["acknowledgement_probe_count"] += 1
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert (
        "acknowledgement_probe_count must match unique acknowledgement_probes count"
        in artifact["errors"]
    )


def test_statement_publication_ack_probes_must_not_duplicate(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["acknowledgement_probes"].append(payload["acknowledgement_probes"][0])
    payload["acknowledgement_probe_count"] = len(payload["acknowledgement_probes"])
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert "acknowledgement_probes must not contain duplicate values" in artifact[
        "errors"
    ]
    assert (
        "acknowledgement_probe_count must match unique acknowledgement_probes count"
        in artifact["errors"]
    )


def test_statement_publication_ack_probe_labels_must_use_billing_ack_family(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["acknowledgement_probes"][0] = "statement-ack-probe-00"
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert MODULE.ACKNOWLEDGEMENT_PROBE_LABEL_ERROR in artifact["errors"]


def test_statement_publication_ack_probe_labels_reject_non_production_markers(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload["acknowledgement_probes"][0] = "billing-ack-probe-placeholder"
    write_json(tmp_path / "statement-publication.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["statement_publication"]["artifacts"][0]
    assert (
        "acknowledgement_probes[0] must not contain non-production markers ['placeholder']"
        in artifact["errors"]
    )


def test_governed_hedge_execution_can_pass(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = governance_approval()
    payload["hedge_execution_enabled"] = True
    payload["hedge_execution_governed"] = True
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path) == 0


def test_hedge_execution_enabled_requires_governance(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    payload["hedge_execution_enabled"] = True
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["governance_approval"]["artifacts"][0]
    assert "hedge_execution_governed must be true" in artifact["errors"]


def test_hedge_execution_enabled_rejects_non_boolean_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    payload["hedge_execution_enabled"] = "false"
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["governance_approval"]["artifacts"][0]
    assert (
        "hedge_execution_enabled must be false or explicitly governed"
        in artifact["errors"]
    )


def test_billing_cycle_requires_reference_binding_digest(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    del payload["reference_decision_id_hex"]
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path) == 1


def test_billing_cycle_requires_policy_digest(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = billing_cycle("billing-cycle-1", 1)
    del payload["policy_digest_hex"]
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    required = result["required"]["billing_cycle"]
    artifact = next(
        artifact
        for artifact in required["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert "policy_digest_hex must be a non-empty string" in artifact["errors"]
    assert result["valid_policy_digests"] == [DIGEST]


def test_billing_cycle_id_must_be_canonical(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = billing_cycle("cycle_1", 1)
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifacts = result["required"]["billing_cycle"]["artifacts"]
    assert any(MODULE.CYCLE_ID_ERROR in artifact["errors"] for artifact in artifacts)


def test_billing_cycle_id_rejects_generic_cycle_family(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = billing_cycle("cycle-1", 1)
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifacts = result["required"]["billing_cycle"]["artifacts"]
    assert any(MODULE.CYCLE_ID_ERROR in artifact["errors"] for artifact in artifacts)


def test_billing_cycle_id_rejects_non_production_markers(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = billing_cycle("billing-cycle-prod-placeholder", 1)
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifacts = result["required"]["billing_cycle"]["artifacts"]
    assert any(
        "cycle_id must not contain non-production markers ['placeholder']"
        in artifact["errors"]
        for artifact in artifacts
    )


def test_billing_cycle_id_non_production_marker_stdout_does_not_echo_cycle_id(
    tmp_path: Path,
    capsys,
) -> None:
    write_complete_evidence(tmp_path)
    invalid_cycle_id = "billing-cycle-prod-placeholder"
    payload = billing_cycle(invalid_cycle_id, 1)
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path) == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    diagnostics = json.dumps(payload, sort_keys=True)
    assert (
        "cycle_id must not contain non-production markers ['placeholder']"
        in diagnostics
    )
    assert invalid_cycle_id not in diagnostics
    assert (
        "cycle_id must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert invalid_cycle_id not in captured.err


def test_billing_cycle_id_accepts_future_production_label(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-prod-a-202607", 1)
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path) == 0


def test_billing_cycle_reference_must_match_valid_reference_price(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = billing_cycle("billing-cycle-1", 1)
    payload["reference_decision_id_hex"] = "cd" * 32
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["billing_cycle"]
    artifact = next(
        artifact
        for artifact in required["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "billing_cycle reference_decision_id_hex must reference a valid "
        "reference_price decision_id_hex"
    ]


def test_governance_policy_digest_must_match_valid_billing_cycle(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = governance_approval()
    payload["policy_digest_hex"] = DIGEST_2
    write_json(tmp_path / "governance-approval.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["governance_approval"]["artifacts"][0]
    assert result["valid_policy_digests"] == [DIGEST]
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "governance_approval policy_digest_hex must reference a valid "
        "billing_cycle policy_digest_hex"
    ]


def test_all_policy_bound_artifacts_reject_billing_cycle_policy_mismatch(
    tmp_path: Path,
) -> None:
    for kind_name, file_name, factory in POLICY_BOUND_FIXTURES:
        case_dir = tmp_path / kind_name
        case_dir.mkdir()
        write_complete_evidence(case_dir)
        payload = factory()
        payload["policy_digest_hex"] = DIGEST_2
        write_json(case_dir / file_name, payload)
        summary = case_dir / "summary.json"

        assert run_gate(case_dir, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        required = result["required"][kind_name]
        artifact = required["artifacts"][0]
        assert result["valid_policy_digests"] == [DIGEST]
        assert required["valid"] is False
        assert artifact["valid"] is False
        assert (
            f"{kind_name} policy_digest_hex must reference a valid "
            "billing_cycle policy_digest_hex"
        ) in artifact["errors"]


def test_multiple_valid_policy_anchors_fail_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-2", 2)
    payload["policy_digest_hex"] = DIGEST_2
    write_json(tmp_path / "billing-cycle-2.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["valid_policy_digests"] == []
    assert (
        "valid_policy_digests must contain exactly one active digest"
        in result["errors"]
    )


def test_policy_bound_subset_requires_billing_cycle_anchor(tmp_path: Path) -> None:
    write_json(tmp_path / "governance-approval.json", governance_approval())
    summary = tmp_path / "summary.json"

    assert (
        run_gate(
            tmp_path,
            "--require-kind",
            "governance_approval",
            "--summary-out",
            str(summary),
        )
        == 1
    )

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["governance_approval"]["artifacts"][0]
    assert result["valid_policy_digests"] == []
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "governance_approval statement_bundle_digest_hex and "
        "reconciliation_digest_hex require a valid billing_cycle artifact",
        "governance_approval policy_digest_hex requires a valid billing_cycle "
        "policy_digest_hex",
    ]


def test_statement_publication_requires_cycle_binding(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = statement_publication()
    payload.pop("statement_bundle_digest_hex")
    write_json(tmp_path / "statement-publication.json", payload)

    assert run_gate(tmp_path) == 1


def test_reconciliation_cycle_binding_must_match_billing_cycle(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    payload = reconciliation()
    payload["reconciliation_digest_hex"] = DIGEST_2
    write_json(tmp_path / "reconciliation.json", payload)

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["reconciliation"]
    artifact = required["artifacts"][0]
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "reconciliation statement_bundle_digest_hex and reconciliation_digest_hex "
        "must match a valid billing_cycle artifact"
    ]


def test_all_cycle_bound_artifacts_reject_billing_cycle_tuple_mismatch(
    tmp_path: Path,
) -> None:
    for kind_name, file_name, factory in CYCLE_BOUND_FIXTURES:
        case_dir = tmp_path / kind_name
        case_dir.mkdir()
        write_complete_evidence(case_dir)
        payload = factory()
        payload["reconciliation_digest_hex"] = DIGEST_2
        write_json(case_dir / file_name, payload)
        summary = case_dir / "summary.json"

        assert run_gate(case_dir, "--summary-out", str(summary)) == 1

        result = json.loads(summary.read_text(encoding="utf-8"))
        required = result["required"][kind_name]
        artifact = required["artifacts"][0]
        assert required["valid"] is False
        assert artifact["valid"] is False
        assert (
            f"{kind_name} statement_bundle_digest_hex and reconciliation_digest_hex "
            "must match a valid billing_cycle artifact"
        ) in artifact["errors"]


def test_multiple_valid_cycle_binding_anchors_fail_closed(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-2", 2)
    payload["statement_bundle_digest_hex"] = DIGEST_2
    payload["reconciliation_digest_hex"] = DIGEST_2
    write_json(tmp_path / "billing-cycle-2.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    assert result["valid_cycle_bindings"] == []
    assert (
        "valid_cycle_bindings must contain exactly one active binding"
        in result["errors"]
    )


def test_cycle_bound_subset_requires_billing_cycle_anchor(tmp_path: Path) -> None:
    write_json(tmp_path / "statement-publication.json", statement_publication())
    summary = tmp_path / "summary.json"

    assert (
        run_gate(
            tmp_path,
            "--require-kind",
            "statement_publication",
            "--summary-out",
            str(summary),
        )
        == 1
    )

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["statement_publication"]
    artifact = required["artifacts"][0]
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "statement_publication statement_bundle_digest_hex and "
        "reconciliation_digest_hex require a valid billing_cycle artifact"
    ]


def test_stale_billing_cycle_does_not_anchor_cycle_bound_evidence(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    summary = tmp_path / "summary.json"
    stale_generated_at = NOW_UNIX - MODULE.DEFAULT_MAX_CYCLE_AGE_SECS - 1
    write_json(
        tmp_path / "billing-cycle-1.json",
        billing_cycle("billing-cycle-1", 1, generated_at=stale_generated_at),
    )
    write_json(
        tmp_path / "billing-cycle-2.json",
        billing_cycle("billing-cycle-2", 2, generated_at=stale_generated_at),
    )

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    required = payload["required"]["statement_publication"]
    artifact = required["artifacts"][0]
    assert payload["valid_cycle_bindings"] == []
    assert required["valid"] is False
    assert artifact["valid"] is False
    assert artifact["errors"] == [
        "statement_publication statement_bundle_digest_hex and "
        "reconciliation_digest_hex require a valid billing_cycle artifact"
    ]


def test_billing_cycle_statement_digest_count_must_match(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statement_digests_hex"] = [DIGEST]
    write_json(tmp_path / "billing-cycle-1.json", payload)

    assert run_gate(tmp_path) == 1


def test_billing_cycle_statement_count_must_match_unique_statements(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statement_count"] += 1
    payload["signed_statement_count"] = payload["statement_count"]
    payload["statement_digests_hex"].append("34" * 32)
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert "statement_count must match unique statements count" in artifact["errors"]


def test_billing_cycle_statements_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statements"].append(dict(payload["statements"][0]))
    payload["statement_count"] = len(payload["statements"])
    payload["signed_statement_count"] = len(payload["statements"])
    payload["statement_digests_hex"].append("34" * 32)
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert "statements must not contain duplicate values" in artifact["errors"]
    assert "statement_count must match unique statements count" in artifact["errors"]


def test_billing_cycle_statement_labels_must_use_billing_statement_family(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statements"][0]["name"] = "statement-00"
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert MODULE.STATEMENT_LABEL_ERROR in artifact["errors"]


def test_billing_cycle_statement_labels_reject_non_production_markers(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["statements"][0]["name"] = "billing-statement-placeholder"
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert (
        "statements[0].name must not contain non-production markers ['placeholder']"
        in artifact["errors"]
    )


def test_billing_cycle_line_item_count_must_match_unique_line_items(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["line_item_count"] += 1
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert "line_item_count must match unique line_items count" in artifact["errors"]


def test_billing_cycle_line_items_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["line_items"].append(dict(payload["line_items"][0]))
    payload["line_item_count"] = len(payload["line_items"])
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert "line_items must not contain duplicate values" in artifact["errors"]
    assert "line_item_count must match unique line_items count" in artifact["errors"]


def test_billing_cycle_line_item_labels_must_use_billing_line_item_family(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["line_items"][0]["name"] = "line-item-00"
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert MODULE.LINE_ITEM_LABEL_ERROR in artifact["errors"]


def test_billing_cycle_line_item_labels_reject_non_production_markers(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1", 1)
    payload["line_items"][0]["name"] = "billing-line-item-placeholder"
    write_json(tmp_path / "billing-cycle-1.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = next(
        artifact
        for artifact in result["required"]["billing_cycle"]["artifacts"]
        if artifact["fingerprint"]["cycle_id"] == "billing-cycle-1"
    )
    assert (
        "line_items[0].name must not contain non-production markers ['placeholder']"
        in artifact["errors"]
    )


def test_reconciliation_mismatch_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "reconciliation.json", reconciliation(mismatch_count=1))

    assert run_gate(tmp_path) == 1


def test_reconciliation_reconciled_line_item_count_must_match(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["reconciled_line_item_count"] = 4
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["reconciliation"]["artifacts"][0]
    assert (
        "reconciled_line_item_count must equal line_item_count"
        in artifact["errors"]
    )


def test_reconciliation_source_count_must_match_unique_sources(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["source_count"] += 1
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["reconciliation"]["artifacts"][0]
    assert "source_count must match unique sources count" in artifact["errors"]


def test_reconciliation_sources_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["sources"].append(dict(payload["sources"][0]))
    payload["source_count"] = len(payload["sources"])
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["reconciliation"]["artifacts"][0]
    assert "sources must not contain duplicate values" in artifact["errors"]
    assert "source_count must match unique sources count" in artifact["errors"]


def test_reconciliation_sources_must_not_include_unknown_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["sources"].append({"name": "shadow-ledger"})
    payload["source_count"] = len(payload["sources"])
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["reconciliation"]["artifacts"][0]
    assert "sources must not include unknown values" in artifact["errors"]


def test_reconciliation_line_item_count_must_match_unique_line_items(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["line_item_count"] += 1
    payload["reconciled_line_item_count"] = payload["line_item_count"]
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reconciliation"]["artifacts"][0]
    assert "line_item_count must match unique line_items count" in artifact["errors"]


def test_reconciliation_line_items_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["line_items"].append(dict(payload["line_items"][0]))
    payload["line_item_count"] = len(payload["line_items"])
    payload["reconciled_line_item_count"] = payload["line_item_count"]
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reconciliation"]["artifacts"][0]
    assert "line_items must not contain duplicate values" in artifact["errors"]
    assert "line_item_count must match unique line_items count" in artifact["errors"]


def test_reconciliation_line_item_labels_must_use_billing_line_item_family(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["line_items"][0]["name"] = "line-item-00"
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reconciliation"]["artifacts"][0]
    assert MODULE.LINE_ITEM_LABEL_ERROR in artifact["errors"]


def test_reconciliation_line_item_labels_reject_non_production_markers(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = reconciliation()
    payload["line_items"][0]["name"] = "billing-line-item-placeholder"
    write_json(tmp_path / "reconciliation.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["reconciliation"]["artifacts"][0]
    assert (
        "line_items[0].name must not contain non-production markers ['placeholder']"
        in artifact["errors"]
    )


def test_metrics_critical_alert_fails(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "metrics-alerts.json", metrics_alerts(critical=True))

    assert run_gate(tmp_path) == 1


def test_metrics_metric_count_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = metrics_alerts()
    del payload["metric_count"]
    write_json(tmp_path / "metrics-alerts.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["metrics_alerts"]["artifacts"][0]
    assert "metric_count must be a positive integer" in artifact["errors"]


def test_metrics_metric_count_must_match_unique_metrics(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = metrics_alerts()
    payload["metric_count"] += 1
    write_json(tmp_path / "metrics-alerts.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["metrics_alerts"]["artifacts"][0]
    assert "metric_count must match unique metrics count" in artifact["errors"]


def test_metrics_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = metrics_alerts()
    payload["metrics"].append(payload["metrics"][0])
    payload["metric_count"] = len(payload["metrics"])
    write_json(tmp_path / "metrics-alerts.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["metrics_alerts"]["artifacts"][0]
    assert "metrics must not contain duplicate values" in artifact["errors"]
    assert "metric_count must match unique metrics count" in artifact["errors"]


def test_metrics_must_not_include_unknown_values(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = metrics_alerts()
    payload["metrics"].append("shadow_hedging_metric")
    payload["metric_count"] = len(payload["metrics"])
    write_json(tmp_path / "metrics-alerts.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1
    result = json.loads(summary.read_text(encoding="utf-8"))
    artifact = result["required"]["metrics_alerts"]["artifacts"][0]
    assert "metrics must not include unknown values" in artifact["errors"]


@pytest.mark.parametrize("abi", [20, 21, 22, 23])
def test_native_bridge_abi_must_equal_twenty_four(tmp_path: Path, abi: int) -> None:
    write_complete_evidence(tmp_path)
    write_json(tmp_path / "native-bridge-release.json", native_bridge_release(abi=abi))

    summary = tmp_path / "summary.json"
    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1
    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert (
        "bridge_abi_version must equal the sole first-release ABI 31"
        in artifact["errors"]
    )


def test_native_bridge_debug_artifacts_flag_is_required(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    del payload["debug_artifacts"]
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert "debug_artifacts must be false" in artifact["errors"]


def test_native_bridge_artifact_count_must_match_unique_artifacts(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    payload["artifact_count"] += 1
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert "artifact_count must equal artifacts length" in artifact["errors"]
    assert "artifact_count must match unique artifacts count" in artifact["errors"]


def test_native_bridge_release_requires_minimum_artifact_set(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    write_json(
        tmp_path / "native-bridge-release.json",
        native_bridge_release(
            artifacts=[
                {
                    "id": "hedging-native-artifact-swift-xcframework",
                    "sha256": DIGEST,
                }
            ]
        ),
    )
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert "artifact_count must be at least 2" in artifact["errors"]


def test_native_bridge_artifacts_must_cover_reviewed_families(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    write_json(
        tmp_path / "native-bridge-release.json",
        native_bridge_release(
            artifacts=[
                {
                    "id": "hedging-native-artifact-swift-xcframework",
                    "sha256": DIGEST,
                },
                {
                    "id": "hedging-native-artifact-swift-ios-simulator",
                    "sha256": "ef" * 32,
                },
            ]
        ),
    )
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert (
        "artifacts must include at least one native bridge artifact for every "
        "reviewed bridge family"
    ) in artifact["errors"]


def test_native_bridge_artifacts_must_not_duplicate(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    payload["artifacts"].append(dict(payload["artifacts"][0]))
    payload["artifact_count"] = len(payload["artifacts"])
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert "artifacts must not contain duplicate values" in artifact["errors"]
    assert "artifact_count must match unique artifacts count" in artifact["errors"]


def test_native_bridge_artifact_ids_must_use_reviewed_family(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    payload["artifacts"][0]["id"] = "NoritoBridge.xcframework"
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert MODULE.NATIVE_BRIDGE_ARTIFACT_ID_ERROR in artifact["errors"]


def test_native_bridge_artifact_ids_must_use_reviewed_family_prefix(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    artifact_id = "hedging-native-artifact-rust-bridge"
    payload["artifacts"][0]["id"] = artifact_id
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    errors = "\n".join(artifact["errors"])
    assert (
        "artifacts[].id must start with a reviewed native bridge family prefix"
        in errors
    )
    assert artifact_id not in errors


def test_native_bridge_artifact_ids_reject_non_production_markers(
    tmp_path: Path,
) -> None:
    write_complete_evidence(tmp_path)
    payload = native_bridge_release()
    payload["artifacts"][0]["id"] = "hedging-native-artifact-placeholder"
    write_json(tmp_path / "native-bridge-release.json", payload)
    summary = tmp_path / "summary.json"

    assert run_gate(tmp_path, "--summary-out", str(summary)) == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    artifact = payload["required"]["native_bridge_release"]["artifacts"][0]
    assert (
        "artifacts[0].id must not contain non-production markers ['placeholder']"
        in artifact["errors"]
    )


def test_invalid_duplicate_artifact_fails_even_with_valid_artifact(tmp_path: Path) -> None:
    write_complete_evidence(tmp_path)
    payload = billing_cycle("billing-cycle-1-duplicate", 3)
    payload["statement_bodies_included"] = True
    write_json(tmp_path / "billing-cycle-invalid.json", payload)

    assert run_gate(tmp_path) == 1


def test_invalid_optional_artifact_fails_subset_gate(tmp_path: Path) -> None:
    write_json(tmp_path / "feed-collector.json", feed_collector())
    payload = native_bridge_release(abi=11)
    write_json(tmp_path / "native-bridge-release.json", payload)

    assert run_gate(tmp_path, "--require-kind", "feed_collector") == 1


def test_explicit_unknown_schema_fails(tmp_path: Path) -> None:
    path = write_json(tmp_path / "unknown.json", {"schema": "sorafs.hedging.unknown.v1"})

    assert CHECKER(["--evidence", str(path), "--now-unix", str(NOW_UNIX)]) == 1
