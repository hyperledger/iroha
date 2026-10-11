#!/usr/bin/env python3
"""Guard the binaries selected by an ordinary workspace build.

The check runs ``cargo metadata --locked`` and compares the resolved default
feature graph with the first-release shipping inventory below. It also pins
the exact declared binary owners and count so developer generators, probes,
benchmarks, and evidence tools cannot silently disappear or be replaced behind explicit
non-default features such as ``dev-tools``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


EXPECTED_DEFAULT_BINS = frozenset(
    {
        ("iroha_cli", "iroha"),
        ("iroha_kagami", "kagami"),
        ("iroha_monitor", "iroha_monitor"),
        ("iroha_python_rs", "iroha_privacy_wallet_worker"),
        ("iroha_torii", "attachment_sanitizer"),
        ("irohad", "iroha3d"),
        ("irohad", "iroha3d_taira"),
        ("irohad", "sorafs_governance_dag"),
        ("irohad", "taira_bootle_lantern_broker"),
        ("kotodama_toolchain", "koto"),
        ("izanami", "izanami"),
        ("mochi-ui", "mochi"),
        ("musubi", "musubi"),
        ("sora-vpn-backend", "sora-vpn-backend"),
        ("sora-vpn-helper", "sora-vpn-controller"),
        ("soradns-resolver", "soradns-resolver"),
        ("sorafs_car", "sorafs_fetch"),
        ("sorafs_car", "sorafs_manifest_builder"),
        ("sorafs_node", "sorafs-node"),
        ("sorafs_orchestrator", "sorafs_cli"),
        ("soranet-puzzle-service", "soranet-puzzle-service"),
        ("soranet-relay", "directory"),
        ("soranet-relay", "soranet-relay"),
    }
)
# Non-default generators, probes, and evidence tools retain explicit ownership.
EXPECTED_DECLARED_BINS = EXPECTED_DEFAULT_BINS | frozenset(
    {
        ("build-support", "clippy-inventory"),
        ("build-support", "sumeragi_baseline_report"),
        ("build-support", "sumeragi_da_report"),
        ("connect_norito_bridge", "soracloud_request_signer"),
        ("connect_norito_bridge", "swift_parity_regen"),
        ("fastpq_prover", "fastpq_cuda_bench"),
        ("fastpq_prover", "fastpq_fixture_rebind"),
        ("fastpq_prover", "fastpq_json"),
        ("fastpq_prover", "fastpq_metal_bench"),
        ("integration_tests", "refresh_nexus_streaming_fixtures"),
        ("integration_tests", "sorafs-gateway-fixtures"),
        ("iroha_cli", "account_literal_reencode"),
        ("iroha_cli", "gov_instruction"),
        ("iroha_cli", "taira_fee_sponsor_program"),
        ("iroha_core", "fastpq_fixture_capture"),
        ("iroha_core", "privacy_exact12_action_driver"),
        ("iroha_core", "validation_fee_rewards_evidence_verify"),
        ("iroha_core_zk", "kagemusha_wallet_artifacts"),
        ("iroha_crypto", "gost_perf_check"),
        ("iroha_crypto", "sm_perf_check"),
        ("iroha_crypto", "soranet_handshake_check"),
        ("iroha_data_model", "axt_fixtures"),
        ("iroha_data_model", "cancel_asset_lock_fixtures"),
        ("iroha_data_model", "musubi_fixtures"),
        ("iroha_data_model", "privacy_exact12_fixtures"),
        ("iroha_genesis", "account_literal"),
        ("iroha_genesis", "genesis_dump"),
        ("iroha_genesis", "genesis_inspect"),
        ("iroha_genesis", "genesis_resign"),
        ("iroha_kagami", "iroha_authenticated_tool_controller"),
        ("iroha_test_network", "taira_beacon_bootstrap"),
        ("irohad", "iroha_test_runtime_provider_broker"),
        ("irohad", "sorafs_external_software_signer"),
        ("ivm", "gas_probe"),
        ("ivm", "gen_abi_hash_doc"),
        ("ivm", "gen_header_doc"),
        ("ivm", "gen_pointer_types_doc"),
        ("ivm", "gen_proof_coverage_inventory"),
        ("ivm", "gen_syscalls_doc"),
        ("ivm", "ivm_fixture_export"),
        ("ivm", "ivm_prebuild"),
        ("ivm", "ivm_predecoder_export"),
        ("ivm_artifact_admission", "ivm_artifact_admit"),
        ("kotlin-fixture-gen", "kotlin-fixture-gen"),
        ("kotodama_toolchain", "dump_program"),
        ("norito", "norito_regen_goldens"),
        ("norito_codegen_exporter", "norito-schema-inventory"),
        ("norito_codegen_exporter", "norito_codegen_exporter"),
        ("soradns-resolver", "soradns_transparency_report"),
        ("soradns-resolver", "soradns_transparency_tail"),
        ("sorafs_car", "da_reconstruct"),
        ("sorafs_car", "provider_admission_fixtures"),
        ("sorafs_car", "sorafs_chunk_store"),
        ("sorafs_car", "sorafs_manifest_chunk_store"),
        ("sorafs_car", "sorafs_provider_advert"),
        ("sorafs_car", "soranet_trustless_verifier"),
        ("sorafs_car", "taikai_car"),
        ("sorafs_chunker", "export_vectors"),
        ("sorafs_chunker", "sorafs_chunk_digest"),
        ("sorafs_chunker", "sorafs_chunk_dump"),
        ("sorafs_manifest", "generate_hedging_fixtures"),
        ("sorafs_manifest", "generate_orderbook_fixtures"),
        ("sorafs_manifest", "generate_pdp_fixtures"),
        ("sorafs_manifest", "generate_por_fixtures"),
        ("sorafs_manifest", "generate_replication_order_fixture"),
        ("sorafs_orchestrator", "taikai_viewer"),
        ("soranet-handshake-harness", "soranet-handshake-harness"),
        ("soranet-relay", "soranet-popctl"),
        ("soranet-relay", "soranet_admission_token"),
        ("soranet-relay", "soranet_vpn_settlement"),
        ("telemetry-schema-diff", "telemetry-schema-diff"),
        ("xtask", "compute_gateway"),
        ("xtask", "control-plane-mock"),
        ("xtask", "torii-mock-harness"),
        ("xtask", "xtask"),
    }
)

FORBIDDEN_COMPATIBILITY_BINS = frozenset(
    {"iroha2", "iroha2d", "iroha3", "iroha_cli", "irohad"}
)
BASELINE_DEFAULT_BIN_COUNT = 92
MAX_DEFAULT_BIN_COUNT = 24
BASELINE_DECLARED_BIN_COUNT = 116
EXPECTED_DECLARED_BIN_COUNT = len(EXPECTED_DECLARED_BINS)


def load_metadata(root: Path) -> dict[str, Any]:
    """Load the locked Cargo metadata graph for ``root``."""

    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def resolved_default_bins(metadata: dict[str, Any]) -> set[tuple[str, str]]:
    """Return workspace binaries enabled by the resolved default feature graph."""

    workspace_members = set(metadata["workspace_members"])
    resolved_features = {
        node["id"]: set(node.get("features", ()))
        for node in metadata["resolve"]["nodes"]
    }
    enabled: set[tuple[str, str]] = set()
    for package in metadata["packages"]:
        package_id = package["id"]
        if package_id not in workspace_members:
            continue
        features = resolved_features.get(package_id, set())
        for target in package["targets"]:
            if "bin" not in target["kind"]:
                continue
            required = set(target.get("required-features") or ())
            if required <= features:
                enabled.add((package["name"], target["name"]))
    return enabled


def all_workspace_bins(metadata: dict[str, Any]) -> set[tuple[str, str]]:
    """Return every binary target declared by workspace packages."""

    workspace_members = set(metadata["workspace_members"])
    return {
        (package["name"], target["name"])
        for package in metadata["packages"]
        if package["id"] in workspace_members
        for target in package["targets"]
        if "bin" in target["kind"]
    }


def check_metadata(metadata: dict[str, Any]) -> list[str]:
    """Return deterministic target-inventory violations."""

    errors: list[str] = []
    actual = resolved_default_bins(metadata)
    missing = sorted(EXPECTED_DEFAULT_BINS - actual)
    unexpected = sorted(actual - EXPECTED_DEFAULT_BINS)
    if missing:
        errors.append(f"shipping binaries no longer enabled by default: {missing!r}")
    if unexpected:
        errors.append(f"non-shipping binaries enabled by default: {unexpected!r}")
    if len(actual) > MAX_DEFAULT_BIN_COUNT:
        errors.append(
            f"default binary count {len(actual)} exceeds {MAX_DEFAULT_BIN_COUNT} "
            f"(pre-refactor baseline: {BASELINE_DEFAULT_BIN_COUNT})"
        )

    declared = all_workspace_bins(metadata)
    missing_declared = sorted(EXPECTED_DECLARED_BINS - declared)
    unexpected_declared = sorted(declared - EXPECTED_DECLARED_BINS)
    if missing_declared:
        errors.append(f"reviewed binary owners are no longer declared: {missing_declared!r}")
    if unexpected_declared:
        errors.append(f"unreviewed binary owners are declared: {unexpected_declared!r}")
    if len(declared) != EXPECTED_DECLARED_BIN_COUNT:
        errors.append(
            f"declared binary count {len(declared)} differs from the expected "
            f"{EXPECTED_DECLARED_BIN_COUNT} in the reviewed first-release inventory "
            f"(pre-refactor baseline: {BASELINE_DECLARED_BIN_COUNT})"
        )

    forbidden = sorted(
        target
        for target in declared
        if target[1] in FORBIDDEN_COMPATIBILITY_BINS
    )
    if forbidden:
        errors.append(f"retired compatibility binaries are declared: {forbidden!r}")
    return errors


def main() -> int:
    """Run the workspace target-inventory guard."""

    parser = argparse.ArgumentParser(
        description="Reject non-shipping default binaries and retired aliases."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root containing Cargo.toml (default: inferred)",
    )
    args = parser.parse_args()

    errors = check_metadata(load_metadata(args.root.resolve()))
    if errors:
        print("Workspace target inventory violations:")
        for error in errors:
            print(f"  - {error}")
        return 1

    reduction = BASELINE_DEFAULT_BIN_COUNT - len(EXPECTED_DEFAULT_BINS)
    print(
        "Workspace target inventory passed: "
        f"{len(EXPECTED_DEFAULT_BINS)} default binaries "
        f"({reduction} fewer than the {BASELINE_DEFAULT_BIN_COUNT}-target baseline), "
        f"{EXPECTED_DECLARED_BIN_COUNT} total declared binaries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
