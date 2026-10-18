"""Tests for scripts/build_sorafs_hedging_canary.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = SCRIPT_ROOT / "build_sorafs_hedging_canary.py"
CHECKER_PATH = SCRIPT_ROOT / "check_sorafs_hedging_rollout_evidence.py"

SPEC = importlib.util.spec_from_file_location(
    "build_sorafs_hedging_canary",
    MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader  # pragma: no cover - defensive
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CHECKER_SPEC = importlib.util.spec_from_file_location(
    "check_sorafs_hedging_rollout_evidence",
    CHECKER_PATH,
)
CHECKER = importlib.util.module_from_spec(CHECKER_SPEC)
assert CHECKER_SPEC and CHECKER_SPEC.loader  # pragma: no cover - defensive
sys.modules[CHECKER_SPEC.name] = CHECKER
CHECKER_SPEC.loader.exec_module(CHECKER)

from sorafs_rollout_runner_test_support import write_topology_qualification  # noqa: E402


DECISION_DIGEST = "a" * 64
LINE_ROOT_DIGEST = "b" * 64
STATEMENT_BUNDLE_DIGEST = "c" * 64
RECONCILIATION_DIGEST = "d" * 64
POLICY_DIGEST = "e" * 64
STATEMENT_DIGEST_A = "1" * 64
STATEMENT_DIGEST_B = "2" * 64
ARTIFACT_DIGEST = "f" * 64
ROUTE_BODY_DIGEST = "9" * 64
GENERATED_AT = 1_800_100_000


def canary_path(tmp_path: Path, kind: str, suffix: str = "") -> Path:
    stem = kind if not suffix else f"{kind}-{suffix}"
    return tmp_path / f"{stem}.json"


def checker_options() -> object:
    return CHECKER.ValidationOptions(
        now_unix=GENERATED_AT,
        max_feed_lag_secs=CHECKER.DEFAULT_MAX_FEED_LAG_SECS,
        max_cycle_age_secs=CHECKER.DEFAULT_MAX_CYCLE_AGE_SECS,
        max_divergence_bps=CHECKER.DEFAULT_MAX_DIVERGENCE_BPS,
        min_billing_cycles=CHECKER.DEFAULT_MIN_BILLING_CYCLES,
    )


def args_for(kind: str, tmp_path: Path, suffix: str = "") -> list[str]:
    args = [
        "--kind",
        kind,
        "--out",
        str(canary_path(tmp_path, kind, suffix)),
        "--deployment-id",
        "sorafs-hedging-prod-20260701",
        "--environment",
        "production",
        "--generated-at-unix",
        str(GENERATED_AT),
        "--now-unix",
        str(GENERATED_AT),
    ]
    for claim in MODULE.TRUE_CLAIMS[kind]:
        args.extend(["--verified-claim", claim])
    if kind in MODULE.CYCLE_BINDING_KINDS:
        args.extend(
            [
                "--statement-bundle-digest-hex",
                STATEMENT_BUNDLE_DIGEST,
                "--reconciliation-digest-hex",
                RECONCILIATION_DIGEST,
            ]
        )
    if kind in MODULE.POLICY_DIGEST_KINDS:
        args.extend(["--policy-digest-hex", POLICY_DIGEST])
    if kind == "feed_collector":
        args.extend(["--feed-count", "3", "--feed-lag-seconds", "60"])
        for feed in MODULE.REQUIRED_PRICE_FEEDS:
            args.extend(["--feed", feed])
    elif kind == "reference_price":
        args.extend(
            [
                "--decision-id-hex",
                DECISION_DIGEST,
                "--reference-price-micro-usd",
                "4200000",
                "--feed-count",
                "3",
                "--divergence-bps",
                "50",
                "--decision-lag-seconds",
                "60",
            ]
        )
        for feed in MODULE.REQUIRED_PRICE_FEEDS:
            args.extend(["--feed", feed])
    elif kind == "billing_cycle":
        cycle_index = 2 if suffix == "b" else 1
        args.extend(
            [
                "--cycle-id",
                f"billing-cycle-{cycle_index}",
                "--cycle-index",
                str(cycle_index),
                "--line-item-count",
                "5",
                "--total-micro-xor",
                "10000",
                "--total-usd-micro",
                "42000",
                "--reference-decision-id-hex",
                DECISION_DIGEST,
                "--line-item-root-hex",
                LINE_ROOT_DIGEST,
                "--statement-digest-hex",
                STATEMENT_DIGEST_A,
                "--statement-digest-hex",
                STATEMENT_DIGEST_B,
                "--statement",
                "billing-statement-00",
                "--statement",
                "billing-statement-01",
            ]
        )
        for index in range(5):
            args.extend(["--line-item", f"billing-line-item-{index:02d}"])
    elif kind == "statement_publication":
        args.extend(["--acknowledgement-probe-count", "1"])
        args.extend(["--acknowledgement-probe", "billing-ack-probe-00"])
        args.extend(["--route-body-blake3-hex", ROUTE_BODY_DIGEST])
        for route in MODULE.REQUIRED_PUBLICATION_ROUTES:
            args.extend(["--route", route])
    elif kind == "reconciliation":
        args.extend(["--line-item-count", "5"])
        for index in range(5):
            args.extend(["--line-item", f"billing-line-item-{index:02d}"])
        for source in MODULE.REQUIRED_RECONCILIATION_SOURCES:
            args.extend(["--source", source])
    elif kind == "metrics_alerts":
        for metric in MODULE.REQUIRED_METRICS:
            args.extend(["--metric", metric])
    elif kind == "native_bridge_release":
        args.extend(["--bridge-abi-version", "30"])
        args.extend(
            ["--artifact", f"hedging-native-artifact-swift-xcframework:{ARTIFACT_DIGEST}"]
        )
        args.extend(
            ["--artifact", f"hedging-native-artifact-jni-macos-arm64:{ARTIFACT_DIGEST}"]
        )
    elif kind == "governance_approval":
        args.extend(["--policy-digest-hex", POLICY_DIGEST])
    return args


def assert_rejected_without_artifact(
    args: list[str],
    *,
    kind: str,
    tmp_path: Path,
    capsys,
    expected_error: str,
) -> None:
    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert expected_error in captured.err
    assert not canary_path(tmp_path, kind).exists()


def test_builds_payload_free_billing_cycle_canary(tmp_path: Path) -> None:
    assert MODULE.main(args_for("billing_cycle", tmp_path)) == 0

    payload = json.loads(canary_path(tmp_path, "billing_cycle").read_text("utf-8"))

    assert payload["schema"] == "sorafs.billing.cycle_canary.v1"
    assert payload["statement_bundle_digest_hex"] == STATEMENT_BUNDLE_DIGEST
    assert payload["reconciliation_digest_hex"] == RECONCILIATION_DIGEST
    assert payload["reference_decision_id_hex"] == DECISION_DIGEST
    assert payload["policy_digest_hex"] == POLICY_DIGEST
    assert payload["statement_count"] == 2
    assert [statement["name"] for statement in payload["statements"]] == [
        "billing-statement-00",
        "billing-statement-01",
    ]
    assert [line_item["name"] for line_item in payload["line_items"]] == [
        "billing-line-item-00",
        "billing-line-item-01",
        "billing-line-item-02",
        "billing-line-item-03",
        "billing-line-item-04",
    ]
    for claim in MODULE.TRUE_CLAIMS["billing_cycle"]:
        assert payload[claim] is True
    for field in MODULE.FORCED_FALSE_FIELDS["billing_cycle"]:
        assert payload[field] is False
    kind, errors = CHECKER.validate_evidence_payload(payload, checker_options())
    assert kind == "billing_cycle"
    assert errors == []


def test_builds_payload_free_statement_publication_canary(tmp_path: Path) -> None:
    assert MODULE.main(args_for("statement_publication", tmp_path)) == 0

    payload = json.loads(canary_path(tmp_path, "statement_publication").read_text("utf-8"))

    assert payload["schema"] == "sorafs.billing.statement_publication_canary.v1"
    assert payload["route_count"] == len(MODULE.REQUIRED_PUBLICATION_ROUTES)
    assert payload["passed_route_count"] == len(MODULE.REQUIRED_PUBLICATION_ROUTES)
    assert [route["name"] for route in payload["routes"]] == list(
        MODULE.REQUIRED_PUBLICATION_ROUTES
    )
    assert all(
        route["body_blake3_hex"] == ROUTE_BODY_DIGEST for route in payload["routes"]
    )
    kind, errors = CHECKER.validate_evidence_payload(payload, checker_options())
    assert kind == "statement_publication"
    assert errors == []


def test_billing_cycle_id_must_be_canonical(tmp_path: Path, capsys) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--cycle-id") + 1] = "cycle_1"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--cycle-id must match canonical lowercase `billing-cycle-*`"
        in captured.err
    )


def test_billing_cycle_id_rejects_generic_cycle_family(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--cycle-id") + 1] = "cycle-1"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--cycle-id must match canonical lowercase `billing-cycle-*`"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_id_rejects_non_production_markers(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--cycle-id") + 1] = "billing-cycle-prod-placeholder"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--cycle-id must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_id_accepts_future_production_label(tmp_path: Path) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--cycle-id") + 1] = "billing-cycle-prod-a-202607"

    assert MODULE.main(args) == 0

    payload = json.loads(canary_path(tmp_path, "billing_cycle").read_text("utf-8"))
    assert payload["cycle_id"] == "billing-cycle-prod-a-202607"


def test_builds_payload_free_metrics_alerts_canary(tmp_path: Path) -> None:
    assert MODULE.main(args_for("metrics_alerts", tmp_path)) == 0

    payload = json.loads(canary_path(tmp_path, "metrics_alerts").read_text("utf-8"))

    assert payload["schema"] == "sorafs.hedging_billing.metrics_alert_canary.v1"
    assert payload["metrics"] == list(MODULE.REQUIRED_METRICS)
    assert payload["metric_count"] == len(MODULE.REQUIRED_METRICS)
    for claim in MODULE.TRUE_CLAIMS["metrics_alerts"]:
        assert payload[claim] is True
    for field in MODULE.FORCED_FALSE_FIELDS["metrics_alerts"]:
        assert payload[field] is False
    kind, errors = CHECKER.validate_evidence_payload(payload, checker_options())
    assert kind == "metrics_alerts"
    assert errors == []


def test_generated_canaries_pass_full_hedging_gate(tmp_path: Path) -> None:
    evidence_paths: list[Path] = []
    for kind in MODULE.CANARY_KINDS:
        assert MODULE.main(args_for(kind, tmp_path)) == 0
        evidence_paths.append(canary_path(tmp_path, kind))
        if kind == "billing_cycle":
            assert MODULE.main(args_for(kind, tmp_path, "b")) == 0
            evidence_paths.append(canary_path(tmp_path, kind, "b"))
    summary = tmp_path / "summary.json"

    command = []
    for path in evidence_paths:
        command.extend(["--evidence", str(path)])
    command.extend(["--summary-out", str(summary), "--now-unix", str(GENERATED_AT)])
    command.extend(
        [
            "--topology-qualification-summary",
            str(
                write_topology_qualification(
                    tmp_path / "topology-qualification.json",
                    deployment_id="sorafs-hedging-prod-20260701",
                )
            ),
        ]
    )

    assert CHECKER.main(command) == 0

    payload = json.loads(summary.read_text("utf-8"))
    assert payload["status"] == "ready"
    assert payload["valid_reference_decision_ids"] == [DECISION_DIGEST]
    assert payload["valid_policy_digests"] == [POLICY_DIGEST]
    assert len(payload["valid_billing_cycles"]) == CHECKER.DEFAULT_MIN_BILLING_CYCLES
    assert payload["valid_cycle_bindings"] == [
        {
            "statement_bundle_digest_hex": STATEMENT_BUNDLE_DIGEST,
            "reconciliation_digest_hex": RECONCILIATION_DIGEST,
        }
    ]


def test_response_file_can_build_reference_price_canary(tmp_path: Path) -> None:
    args_file = tmp_path / "reference.args"
    args_file.write_text("\n".join(args_for("reference_price", tmp_path)), encoding="utf-8")

    assert MODULE.main([f"@{args_file}"]) == 0

    payload = json.loads(canary_path(tmp_path, "reference_price").read_text("utf-8"))
    assert payload["decision_id_hex"] == DECISION_DIGEST
    assert payload["reference_price_micro_usd"] == 4_200_000
    assert [feed["name"] for feed in payload["feeds"]] == list(
        MODULE.REQUIRED_PRICE_FEEDS
    )


def test_duplicate_native_bridge_artifact_id_fails_closed_without_leaking(
    tmp_path: Path, capsys
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    artifact_id = "NoritoBridge-private-key-placeholder"
    first_artifact = args.index("--artifact") + 1
    args[first_artifact] = f"{artifact_id}:{ARTIFACT_DIGEST}"
    args.extend(["--artifact", f"{artifact_id}:{'0' * 64}"])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "duplicate --artifact id" in captured.err
    assert artifact_id not in captured.err
    assert not canary_path(tmp_path, "native_bridge_release").exists()


@pytest.mark.parametrize("abi", [20, 21, 22])
def test_native_bridge_release_requires_exact_abi_before_write(
    tmp_path: Path,
    capsys,
    abi: int,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    args[args.index("--bridge-abi-version") + 1] = str(abi)

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--bridge-abi-version must equal the sole first-release ABI 30" in captured.err
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_native_bridge_artifact_id_requires_reviewed_family_before_write(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    first_artifact = args.index("--artifact") + 1
    args[first_artifact] = f"NoritoBridge.xcframework:{ARTIFACT_DIGEST}"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        CHECKER.NATIVE_BRIDGE_ARTIFACT_ID_ERROR.replace(
            "artifacts[].id", "--artifact[0].id"
        )
        in captured.err
    )
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_native_bridge_artifact_id_rejects_non_production_markers_before_write(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    first_artifact = args.index("--artifact") + 1
    args[first_artifact] = f"hedging-native-artifact-placeholder:{ARTIFACT_DIGEST}"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--artifact[0].id must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_native_bridge_release_requires_minimum_artifacts_before_write(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    first_artifact = args.index("--artifact")
    del args[first_artifact + 2:first_artifact + 4]

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--artifact must include at least 2 distinct artifacts" in captured.err
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_native_bridge_release_requires_family_coverage_before_write(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    artifact_positions = [
        index + 1 for index, value in enumerate(args) if value == "--artifact"
    ]
    for index, position in enumerate(artifact_positions):
        args[position] = (
            f"hedging-native-artifact-swift-extra-{index:02d}:{ARTIFACT_DIGEST}"
        )

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--artifact must include at least one native bridge artifact for every "
        "reviewed bridge family"
    ) in captured.err
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_native_bridge_release_rejects_unreviewed_family_before_write(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("native_bridge_release", tmp_path)
    first_artifact = args.index("--artifact") + 1
    artifact_id = "hedging-native-artifact-rust-bridge"
    args[first_artifact] = f"{artifact_id}:{ARTIFACT_DIGEST}"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--artifact id must start with a reviewed native bridge family prefix"
        in captured.err
    )
    assert artifact_id not in captured.err
    assert not canary_path(tmp_path, "native_bridge_release").exists()


def test_billing_cycle_statement_inventory_must_match_statement_digests(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args.extend(["--statement", "billing-statement-02"])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--statement unique values must match --statement-digest-hex" in captured.err
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_statement_inventory_must_use_billing_statement_family(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--statement") + 1] = "statement-00"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--statement must match canonical lowercase `billing-statement-*`"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_statement_inventory_rejects_non_production_markers(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--statement") + 1] = "billing-statement-placeholder"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--statement[0] must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_statement_inventory_must_not_duplicate(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    first_statement = args.index("--statement") + 1
    args.extend(["--statement", args[first_statement]])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--statement must not contain duplicates" in captured.err
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_line_item_inventory_must_match_line_item_count(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--line-item-count") + 1] = "6"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--line-item unique values must match --line-item-count" in captured.err
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_line_item_inventory_must_not_duplicate(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    first_line_item = args.index("--line-item") + 1
    args.extend(["--line-item", args[first_line_item]])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--line-item must not contain duplicates" in captured.err
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_line_item_inventory_must_use_billing_line_item_family(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--line-item") + 1] = "line-item-00"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--line-item must match canonical lowercase `billing-line-item-*`"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_billing_cycle_line_item_inventory_rejects_non_production_markers(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("billing_cycle", tmp_path)
    args[args.index("--line-item") + 1] = "billing-line-item-placeholder"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--line-item[0] must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert not canary_path(tmp_path, "billing_cycle").exists()


def test_reconciliation_line_item_inventory_must_match_line_item_count(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reconciliation", tmp_path)
    args[args.index("--line-item-count") + 1] = "6"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--line-item unique values must match --line-item-count" in captured.err
    assert not canary_path(tmp_path, "reconciliation").exists()


def test_reconciliation_line_item_inventory_must_not_duplicate(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reconciliation", tmp_path)
    first_line_item = args.index("--line-item") + 1
    args.extend(["--line-item", args[first_line_item]])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--line-item must not contain duplicates" in captured.err
    assert not canary_path(tmp_path, "reconciliation").exists()


def test_reconciliation_line_item_inventory_must_use_billing_line_item_family(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reconciliation", tmp_path)
    args[args.index("--line-item") + 1] = "line-item-00"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--line-item must match canonical lowercase `billing-line-item-*`"
        in captured.err
    )
    assert not canary_path(tmp_path, "reconciliation").exists()


def test_reconciliation_line_item_inventory_rejects_non_production_markers(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reconciliation", tmp_path)
    args[args.index("--line-item") + 1] = "billing-line-item-placeholder"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--line-item[0] must not contain non-production markers ['placeholder']"
        in captured.err
    )
    assert not canary_path(tmp_path, "reconciliation").exists()


def test_statement_publication_ack_probe_inventory_must_match_count(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("statement_publication", tmp_path)
    args[args.index("--acknowledgement-probe-count") + 1] = "2"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--acknowledgement-probe unique values must match "
        "--acknowledgement-probe-count"
    ) in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


def test_statement_publication_ack_probe_inventory_must_not_duplicate(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("statement_publication", tmp_path)
    first_probe = args.index("--acknowledgement-probe") + 1
    args.extend(["--acknowledgement-probe", args[first_probe]])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--acknowledgement-probe must not contain duplicates" in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


def test_statement_publication_ack_probe_inventory_must_use_billing_ack_family(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("statement_publication", tmp_path)
    args[args.index("--acknowledgement-probe") + 1] = "statement-ack-probe-00"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--acknowledgement-probe must match canonical lowercase "
        "`billing-ack-probe-*`"
    ) in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


def test_statement_publication_ack_probe_inventory_rejects_non_production_markers(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("statement_publication", tmp_path)
    args[args.index("--acknowledgement-probe") + 1] = (
        "billing-ack-probe-placeholder"
    )

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--acknowledgement-probe[0] must not contain non-production markers "
        "['placeholder']"
    ) in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


def test_statement_publication_requires_route_body_digest(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("statement_publication", tmp_path)
    index = args.index("--route-body-blake3-hex")
    del args[index : index + 2]

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--route-body-blake3-hex must be exact lowercase 32-byte hex" in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


def test_feed_collector_requires_complete_required_price_feeds(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("feed_collector", tmp_path)
    missing_feed = MODULE.REQUIRED_PRICE_FEEDS[-1]
    index = next(
        index
        for index, value in enumerate(args[:-1])
        if value == "--feed" and args[index + 1] == missing_feed
    )
    del args[index : index + 2]
    args[args.index("--feed-count") + 1] = str(len(MODULE.REQUIRED_PRICE_FEEDS) - 1)

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--feed must include every required value" in captured.err
    assert not canary_path(tmp_path, "feed_collector").exists()


def test_feed_collector_feed_count_must_match_required_price_feeds(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("feed_collector", tmp_path)
    args[args.index("--feed-count") + 1] = str(len(MODULE.REQUIRED_PRICE_FEEDS) + 1)

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--feed-count must match the number of required unique --feed values"
        in captured.err
    )
    assert not canary_path(tmp_path, "feed_collector").exists()


def test_reference_price_feed_inventory_must_match_feed_count(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reference_price", tmp_path)
    args[args.index("--feed-count") + 1] = "4"

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert (
        "--feed-count must match the number of required unique --feed values"
        in captured.err
    )
    assert not canary_path(tmp_path, "reference_price").exists()


def test_reference_price_requires_complete_required_price_feeds(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reference_price", tmp_path)
    missing_feed = MODULE.REQUIRED_PRICE_FEEDS[-1]
    index = next(
        index
        for index, value in enumerate(args[:-1])
        if value == "--feed" and args[index + 1] == missing_feed
    )
    del args[index : index + 2]
    args[args.index("--feed-count") + 1] = str(len(MODULE.REQUIRED_PRICE_FEEDS) - 1)

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--feed must include every required value" in captured.err
    assert not canary_path(tmp_path, "reference_price").exists()


def test_reference_price_feed_inventory_must_not_duplicate(
    tmp_path: Path,
    capsys,
) -> None:
    args = args_for("reference_price", tmp_path)
    first_feed = args.index("--feed") + 1
    args.extend(["--feed", args[first_feed]])

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--feed must not contain duplicates" in captured.err
    assert not canary_path(tmp_path, "reference_price").exists()


def test_missing_verified_claim_fails_closed(tmp_path: Path, capsys) -> None:
    args = args_for("reference_price", tmp_path)
    index = args.index("--verified-claim")
    del args[index : index + 2]

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--verified-claim must include every required value" in captured.err
    assert not canary_path(tmp_path, "reference_price").exists()


def test_missing_publication_route_coverage_fails_closed(tmp_path: Path, capsys) -> None:
    args = args_for("statement_publication", tmp_path)
    index = args.index("--route")
    del args[index : index + 2]

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--route must include every required value" in captured.err
    assert not canary_path(tmp_path, "statement_publication").exists()


@pytest.mark.parametrize(
    ("kind", "option", "duplicate_value", "unknown_value"),
    (
        (
            "reference_price",
            "--verified-claim",
            MODULE.TRUE_CLAIMS["reference_price"][0],
            "unreviewed-hedging-claim",
        ),
        (
            "reference_price",
            "--feed",
            MODULE.REQUIRED_PRICE_FEEDS[0],
            "unreviewed-price-feed",
        ),
        (
            "statement_publication",
            "--route",
            MODULE.REQUIRED_PUBLICATION_ROUTES[0],
            "unreviewed-publication-route",
        ),
        (
            "reconciliation",
            "--source",
            MODULE.REQUIRED_RECONCILIATION_SOURCES[0],
            "unreviewed-reconciliation-source",
        ),
        (
            "metrics_alerts",
            "--metric",
            MODULE.REQUIRED_METRICS[0],
            "unreviewed-hedging-metric",
        ),
    ),
)
def test_closed_set_inputs_reject_duplicate_and_unknown_values_before_write(
    kind: str,
    option: str,
    duplicate_value: str,
    unknown_value: str,
    tmp_path: Path,
    capsys,
) -> None:
    duplicate_args = args_for(kind, tmp_path)
    duplicate_args.extend([option, duplicate_value])
    assert_rejected_without_artifact(
        duplicate_args,
        kind=kind,
        tmp_path=tmp_path,
        capsys=capsys,
        expected_error=f"{option} must not contain duplicates",
    )

    unknown_dir = tmp_path / "unknown"
    unknown_dir.mkdir()
    unknown_args = args_for(kind, unknown_dir)
    unknown_args.extend([option, unknown_value])
    assert_rejected_without_artifact(
        unknown_args,
        kind=kind,
        tmp_path=unknown_dir,
        capsys=capsys,
        expected_error=f"{option} contains an unknown value",
    )


def test_excessive_divergence_fails_before_write(tmp_path: Path, capsys) -> None:
    args = args_for("reference_price", tmp_path)
    args[args.index("--divergence-bps") + 1] = str(
        CHECKER.DEFAULT_MAX_DIVERGENCE_BPS + 1
    )

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--divergence-bps must be <=" in captured.err
    assert not canary_path(tmp_path, "reference_price").exists()


def test_hedge_execution_enabled_requires_governance_before_write(
    tmp_path: Path, capsys
) -> None:
    args = args_for("governance_approval", tmp_path)
    args.append("--hedge-execution-enabled")

    assert MODULE.main(args) == 2

    captured = capsys.readouterr()
    assert "--hedge-execution-governed is required" in captured.err
    assert not canary_path(tmp_path, "governance_approval").exists()


def test_output_symlink_is_rejected(tmp_path: Path, capsys) -> None:
    target = tmp_path / "target.json"
    symlink = canary_path(tmp_path, "feed_collector")
    symlink.symlink_to(target)

    assert MODULE.main(args_for("feed_collector", tmp_path)) == 2

    captured = capsys.readouterr()
    assert "--out" in captured.err
    assert "must not be a symlink" in captured.err
    assert not target.exists()


def test_output_directory_is_rejected(tmp_path: Path, capsys) -> None:
    output_dir = canary_path(tmp_path, "feed_collector")
    output_dir.mkdir()

    assert MODULE.main(args_for("feed_collector", tmp_path)) == 2

    captured = capsys.readouterr()
    assert "--out" in captured.err
    assert "must not be a directory" in captured.err
    assert output_dir.is_dir()
