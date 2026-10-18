#!/usr/bin/env python3
"""Validate the exact first-release NoritoBridge XCFramework inventory."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
import sys
from pathlib import Path

EXPECTED_SLICES = {
    "ios-arm64": {
        "architectures": ["arm64"],
        "platform": "ios",
        "variant": None,
    },
    "ios-arm64_x86_64-simulator": {
        "architectures": ["arm64", "x86_64"],
        "platform": "ios",
        "variant": "simulator",
    },
    "macos-arm64_x86_64": {
        "architectures": ["arm64", "x86_64"],
        "platform": "macos",
        "variant": None,
    },
}
EXPECTED_MANIFEST_FIELDS = {
    "version",
    "native_bridge_abi_version",
    "privacy_production_enabled",
    "cargo_features",
    "build_environment",
    "source_commit",
    "embedded_source_commit",
    "source_tree_dirty",
    "source_fingerprint_sha256",
    "cargo_lock_sha256",
    "bridge_header_sha256",
    "required_symbols",
    "forbidden_symbols",
    "hashes",
}
EXPECTED_BUILD_ENVIRONMENT_FIELDS = {
    "schema",
    "hermetic_runner_schema",
    "hermetic_runner_sha256",
    "wallet_runtime_authority",
    "wallet_runtime_trust_ed25519_hex",
    "environment_profiles",
    "cargo_build_jobs",
    "rust_toolchain_channel",
    "cargo_release",
    "cargo_commit_hash",
    "cargo_binary_sha256",
    "rustc_release",
    "rustc_commit_hash",
    "rustc_binary_sha256",
    "rustdoc_release",
    "rustdoc_commit_hash",
    "rustdoc_binary_sha256",
    "python_version",
    "python_binary_sha256",
    "git_version",
    "git_binary_sha256",
    "rustup_version",
    "rustup_binary_sha256",
    "xcode_version",
    "xcode_build_version",
    "iphoneos_sdk_version",
    "iphonesimulator_sdk_version",
    "macosx_sdk_version",
    "iphoneos_deployment_target",
    "iphonesimulator_deployment_target",
    "macosx_deployment_target",
}
COMMON_BUILD_ENVIRONMENT = {
    "CARGO",
    "CARGO_BUILD_JOBS",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CONNECT_NORITO_SOURCE_REVISION",
    "HOME",
    "IROHA_GIT_COMMIT_HASH",
    "LANG",
    "LC_ALL",
    "MOBILE_SDK_WALLET_RUNTIME_AUTHORITY",
    "MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX",
    "NORITO_SKIP_BINDINGS_SYNC",
    "PATH",
    "RUSTC",
    "RUSTDOC",
    "RUSTUP_HOME",
    "TMPDIR",
    "VERGEN_GIT_SHA",
}
EXPECTED_ENVIRONMENT_PROFILES = {
    "apple-ios-device": sorted(
        COMMON_BUILD_ENVIRONMENT
        | {"DEVELOPER_DIR", "IPHONEOS_DEPLOYMENT_TARGET", "SDKROOT"}
    ),
    "apple-ios-simulator": sorted(
        COMMON_BUILD_ENVIRONMENT
        | {
            "DEVELOPER_DIR",
            "IPHONEOS_DEPLOYMENT_TARGET",
            "IPHONESIMULATOR_DEPLOYMENT_TARGET",
            "SDKROOT",
        }
    ),
    "apple-macos": sorted(
        COMMON_BUILD_ENVIRONMENT
        | {"DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT"}
    ),
}
EXPECTED_REQUIRED_SYMBOLS = [
    "connect_norito_bridge_abi_version",
    "connect_norito_domain_id_validate_v1",
    "soranet_mldsa_parameters",
    "soranet_mldsa_generate_keypair",
    "soranet_mldsa_sign",
    "soranet_mldsa_verify",
    "connect_norito_free",
    "connect_norito_chain_discriminant_scope_enter",
    "connect_norito_chain_discriminant_scope_exit",
    "connect_norito_encode_transfer_signed_transaction",
    "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg",
    "connect_norito_encode_transfer_instruction_box",
    "connect_norito_detached_transaction_scaffold_inspect_v1",
    "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1",
    "connect_norito_canonical_json_blake3_v1",
    "connect_norito_encode_account_onboarding_plan_body_v1",
    "connect_norito_alias_instruction_round_trip_v1",
    "connect_norito_account_read_permission_multisig_payload_hash",
    "connect_norito_account_read_permission_multisig_finalize",
    "iroha_privacy_compiled_profile_catalog_v1",
    "iroha_privacy_validate_compiled_profile_catalog_v1",
    "iroha_privacy_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_capability_manifest_v1",
    "iroha_privacy_free_buffer",
    "connect_norito_sorafs_reference_validate_bundle_json",
    "connect_norito_sorafs_reference_validate_governance_json",
    "connect_norito_sorafs_reference_validate_governance_dag_block_json",
    "connect_norito_sorafs_reference_validate_governance_dag_head_chain_json",
    "connect_norito_validation_fee_current_policy_proof_request_v1",
    "connect_norito_validation_fee_current_policy_proof_verify_v1",
    "connect_norito_retail_fee_intent_hash_v1",
    "connect_norito_retail_fee_assessment_marker_v1",
    "connect_norito_retail_fee_assessment_decode_v1",
    "connect_norito_private_settlement_committee_proof_response_verify_v1",
    "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
    "connect_norito_private_settlement_audit_approval_response_verify_v1",
    "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
    "connect_norito_kagemusha_wallet_revision_v1",
    "connect_norito_kagemusha_wallet_open_begin_v1",
    "connect_norito_kagemusha_wallet_open_finish_v1",
    "connect_norito_kagemusha_wallet_open_cancel_v1",
    "connect_norito_kagemusha_wallet_close_v1",
    "connect_norito_kagemusha_wallet_activity_v1",
    "connect_norito_kagemusha_wallet_setup_v1",
    "connect_norito_kagemusha_wallet_execute_v1",
    "connect_norito_kagemusha_wallet_load_original_validate_v1",
    "connect_norito_kagemusha_wallet_request_status_v1",
    "connect_norito_kagemusha_wallet_retry_v1",
    "connect_norito_kagemusha_wallet_resume_v1",
    "connect_norito_kagemusha_wallet_fold_v1",
    "connect_norito_kagemusha_wallet_credit_status_v1",
    "connect_norito_kagemusha_wallet_snapshot_v1",
    "connect_norito_kagemusha_wallet_review_v1",
    "connect_norito_kagemusha_wallet_execute_reviewed_v1",
    "connect_norito_kagemusha_wallet_discard_review_v1",
    "connect_norito_kagemusha_wallet_installation_begin_v1",
    "connect_norito_kagemusha_wallet_installation_register_v1",
    "connect_norito_kagemusha_wallet_installation_close_v1",
    "connect_norito_kagemusha_wallet_registration_source_relocate_v1",
    "connect_norito_kagemusha_wallet_observe_v1",
    "connect_norito_kagemusha_wallet_account_original_v1",
    "connect_norito_kagemusha_wallet_account_display_v1",
    "connect_norito_kagemusha_wallet_enrollment_v1",
    "connect_norito_kagemusha_wallet_enrollment_refusal_v1",
]
EXPECTED_FORBIDDEN_SYMBOLS = [
    "connect_norito_kagemusha_v1_payment_request_validate",
    "connect_norito_kagemusha_v1_payment_validate",
    "connect_norito_kagemusha_v1_acknowledgement_validate",
    "connect_norito_kagemusha_v1_complete_exchange_validate",
    "connect_norito_kagemusha_v1_mint_authorization_validate",
    "connect_norito_kagemusha_v1_mint_credit_validate",
    "connect_norito_kagemusha_v1_mint_credit_against_authorization_validate",
    "connect_norito_kagemusha_v1_redemption_voucher_validate",
    "connect_norito_kagemusha_v1_payment_request_text_validate",
    "connect_norito_kagemusha_v1_payment_text_validate",
    "connect_norito_kagemusha_v1_acknowledgement_text_validate",
    "connect_norito_kagemusha_v1_complete_exchange_text_validate",
    "connect_norito_kagemusha_v1_mint_authorization_text_validate",
    "connect_norito_kagemusha_v1_mint_credit_text_validate",
    "connect_norito_kagemusha_v1_mint_credit_against_authorization_text_validate",
    "connect_norito_kagemusha_v1_redemption_voucher_text_validate",
    "connect_norito_kagemusha_device_mint_stage_command_v1_validate",
    "connect_norito_kagemusha_device_mint_stage_result_v1_validate",
    "connect_norito_kagemusha_contract_vector_v1",
    "connect_norito_kagemusha_core_coordinator_contract_v1",
    "connect_norito_kagemusha_core_coordinator_install_v1",
    "connect_norito_kagemusha_core_coordinator_open_v1",
    "connect_norito_kagemusha_core_coordinator_invoke_v1",
    "connect_norito_kagemusha_core_coordinator_close_v1",
    "connect_norito_kagemusha_testnet_state_proof_observe_v1",
    "connect_norito_kagemusha_testnet_finalized_mint_observe_v1",
    "connect_norito_kagemusha_testnet_value_admit_v1",
    "connect_norito_kagemusha_testnet_value_credit_v1",
    "connect_norito_kagemusha_testnet_native_startup_contract_v1",
    "connect_norito_kagemusha_testnet_native_startup_activate_v1",
    "connect_norito_kagemusha_ordinary_runtime_startup_v1",
    "connect_norito_kagemusha_ordinary_current_control_v1",
    "connect_norito_kagemusha_ordinary_outgoing_v1",
    "connect_norito_kagemusha_ordinary_incoming_v1",
    "connect_norito_kagemusha_ordinary_integrity_refresh_v1",
    "connect_norito_kagemusha_ordinary_mint_funding_v1",
    "connect_norito_kagemusha_device_capabilities_v1",
    "connect_norito_kagemusha_device_execute_v1",
    "connect_norito_kagemusha_device_command_response_v1_verify",
    "connect_norito_kagemusha_reserve_finality_hint_v1",
    "connect_norito_kagemusha_reserve_finality_verify_v1",
    "connect_norito_kagemusha_top_up_signed_request_validate_v1",
    "connect_norito_validation_fee_hijiri_quote_request_v1",
    "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
    "connect_norito_kagemusha_device_response_authenticator_v1_verify",
    "connect_norito_get_chain_discriminant",
    "connect_norito_set_chain_discriminant",
    "connect_norito_private_settlement_auditor_capsule_response_verify_v1",
    "iroha_privacy_capabilities_v1",
    "iroha_privacy_validate_capabilities_v1",
    "iroha_privacy_proof_request_v1",
    "iroha_privacy_build_proof_v1",
    "iroha_privacy_verify_proof_v1",
]
LIBRARY_NAME = "libNoritoBridge.a"
MANIFEST_NAME = "NoritoBridge.artifacts.json"
EXPECTED_HEADER_ENTRIES = {
    "NoritoBridge.h",
    "connect_norito_bridge.h",
    "module.modulemap",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
NUMERIC_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}")
GIT_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")
XCODE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}")
PYTHON_312_VERSION = re.compile(r"3\.12\.[0-9]+")
XCODE_BUILD_VERSION = re.compile(r"[A-Za-z0-9.]+")


class ValidationError(RuntimeError):
    """The artifact does not satisfy the first-release inventory."""


def _duplicates_rejected(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidationError(f"missing {label}: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"{label} is not a non-symbolic regular file: {path}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_entries(path: Path, expected: set[str], label: str) -> None:
    try:
        actual = {entry.name for entry in path.iterdir()}
    except OSError as error:
        raise ValidationError(f"unable to inspect {label}: {path}") from error
    if actual != expected:
        raise ValidationError(
            f"{label} inventory is not exact "
            f"(missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)})"
        )


def _reject_internal_symlinks(xcframework: Path) -> None:
    for root, directories, files in os.walk(xcframework, followlinks=False):
        for name in [*directories, *files]:
            child = Path(root) / name
            if stat.S_ISLNK(child.lstat().st_mode):
                raise ValidationError(f"XCFramework contains a symlink: {child}")


def _validate_build_environment(root: Path, environment: object) -> None:
    if not isinstance(environment, dict) or set(environment) != (
        EXPECTED_BUILD_ENVIRONMENT_FIELDS
    ):
        actual = set(environment) if isinstance(environment, dict) else set()
        raise ValidationError(
            "artifact build_environment field inventory is not exact "
            f"(missing={sorted(EXPECTED_BUILD_ENVIRONMENT_FIELDS - actual)}, "
            f"unexpected={sorted(actual - EXPECTED_BUILD_ENVIRONMENT_FIELDS)})"
        )
    if not isinstance(environment["wallet_runtime_authority"], str) or environment["wallet_runtime_authority"] not in {"bpng-taira-v7", "cbsi-release-v1", "application-release-v1"}:
        raise ValidationError("artifact Native runtime authority is not exact")
    public_root = environment["wallet_runtime_trust_ed25519_hex"]
    if not isinstance(public_root, str) or SHA256.fullmatch(public_root) is None or public_root == "0" * 64:
        raise ValidationError("artifact Native runtime public root is not exact")
    if environment["environment_profiles"] != EXPECTED_ENVIRONMENT_PROFILES:
        raise ValidationError("artifact build environment allowlists are not exact")
    if (
        environment["schema"] != "iroha.mobile-native-build-environment.v1"
        or environment["hermetic_runner_schema"]
        != "iroha.mobile-hermetic-command.v1"
        or type(environment["cargo_build_jobs"]) is not int
        or environment["cargo_build_jobs"] != 1
        or environment["rust_toolchain_channel"] != "1.93.1"
        or environment["cargo_release"] != "1.93.1"
        or environment["rustc_release"] != "1.93.1"
        or environment["rustdoc_release"] != "1.93.1"
        or environment["rustdoc_commit_hash"] != environment["rustc_commit_hash"]
        or environment["iphoneos_deployment_target"] != "15.0"
        or environment["iphonesimulator_deployment_target"] != "15.0"
        or environment["macosx_deployment_target"] != "12.0"
    ):
        raise ValidationError("artifact build environment identity is not exact")
    for field in (
        "hermetic_runner_sha256",
        "cargo_binary_sha256",
        "rustc_binary_sha256",
        "rustdoc_binary_sha256",
        "python_binary_sha256",
        "git_binary_sha256",
        "rustup_binary_sha256",
    ):
        value = environment[field]
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise ValidationError(f"artifact build environment {field} is not canonical")
    for field in ("cargo_commit_hash", "rustc_commit_hash", "rustdoc_commit_hash"):
        value = environment[field]
        if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
            raise ValidationError(f"artifact build environment {field} is not canonical")
    python_version = environment["python_version"]
    if (
        not isinstance(python_version, str)
        or PYTHON_312_VERSION.fullmatch(python_version) is None
    ):
        raise ValidationError("artifact build environment Python is not exact 3.12")
    for field in (
        "rustup_version",
        "iphoneos_sdk_version",
        "iphonesimulator_sdk_version",
        "macosx_sdk_version",
    ):
        value = environment[field]
        if not isinstance(value, str) or NUMERIC_VERSION.fullmatch(value) is None:
            raise ValidationError(f"artifact build environment {field} is not canonical")
    git_version = environment["git_version"]
    if not isinstance(git_version, str) or GIT_VERSION.fullmatch(git_version) is None:
        raise ValidationError("artifact Git version is not canonical")
    xcode_version = environment["xcode_version"]
    if (
        not isinstance(xcode_version, str)
        or XCODE_VERSION.fullmatch(xcode_version) is None
    ):
        raise ValidationError("artifact Xcode version is not canonical")
    xcode_build = environment["xcode_build_version"]
    if (
        not isinstance(xcode_build, str)
        or XCODE_BUILD_VERSION.fullmatch(xcode_build) is None
    ):
        raise ValidationError("artifact Xcode build version is not canonical")

    runner = root / "scripts/run_mobile_hermetic_command.py"
    _regular_file(runner, "mobile hermetic command runner")
    if _sha256(runner) != environment["hermetic_runner_sha256"]:
        raise ValidationError("artifact hermetic runner digest does not match source")


def _validate_root_identity(
    root: Path, payload: dict[str, object], lockfile: Path, *, local_integration: bool = False,
) -> None:
    if local_integration and lockfile != root / "Cargo.lock":
        raise ValidationError("local integration requires the explicitly selected root Cargo.lock")
    if not local_integration and lockfile == root / "Cargo.lock":
        raise ValidationError("privacy production artifacts require an explicit external canonical graph snapshot")
    _regular_file(root / "Cargo.lock", "root source Cargo.lock")
    _regular_file(lockfile, "selected build Cargo.lock")
    if not local_integration and lockfile.lstat().st_mode & 0o222:
        raise ValidationError("privacy production selected Cargo lock must be read-only")
    if _sha256(lockfile) != payload["cargo_lock_sha256"]:
        raise ValidationError("artifact Cargo.lock digest does not match selected build lock")

    header = root / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
    _regular_file(header, "authoritative NoritoBridge header")
    if _sha256(header) != payload["bridge_header_sha256"]:
        raise ValidationError("artifact bridge header digest does not match source")
    header_abis = re.findall(
        r"^#define[ \t]+CONNECT_NORITO_BRIDGE_ABI_VERSION[ \t]+([0-9]+)[ \t]*$",
        header.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if header_abis != ["30"]:
        raise ValidationError("authoritative NoritoBridge header ABI is not exact 30")

    bridge_source = root / "crates/connect_norito_bridge/src/lib.rs"
    _regular_file(bridge_source, "authoritative NoritoBridge source")
    source = bridge_source.read_text(encoding="utf-8")
    bridge_abis = re.findall(
        r"^const CONNECT_NORITO_BRIDGE_ABI_VERSION: u32 = "
        r"(PRIVACY_BRIDGE_ABI_VERSION_V1);$",
        source,
        re.MULTILINE,
    )
    if bridge_abis != ["PRIVACY_BRIDGE_ABI_VERSION_V1"]:
        raise ValidationError("authoritative NoritoBridge ABI alias is not exact")

    protocol = root / "crates/iroha_data_model/src/privacy/protocol.rs"
    _regular_file(protocol, "authoritative privacy bridge ABI source")
    protocol_abis = re.findall(
        r"^pub const PRIVACY_BRIDGE_ABI_VERSION_V1: u32 = ([0-9]+);$",
        protocol.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if protocol_abis != ["30"]:
        raise ValidationError("authoritative privacy bridge ABI is not exact 30")


def _load_manifest(manifest_path: Path, root: Path, lockfile: Path, *, local_integration: bool = False) -> dict[str, object]:
    _regular_file(manifest_path, "embedded artifact manifest")
    try:
        payload = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_duplicates_rejected,
        )
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise ValidationError(f"artifact manifest is not canonical JSON: {error}") from error
    expected_fields = EXPECTED_MANIFEST_FIELDS | ({"artifact_scope"} if local_integration else set())
    if local_integration and (not isinstance(payload, dict) or payload.get("artifact_scope") != "local-integration"):
        raise ValidationError("local integration requires its explicit artifact scope marker")
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        actual = set(payload) if isinstance(payload, dict) else set()
        raise ValidationError(
            "artifact manifest field inventory is not exact "
            f"(missing={sorted(expected_fields - actual)}, "
            f"unexpected={sorted(actual - expected_fields)})"
        )
    if (
        not isinstance(payload["version"], str)
        or SEMVER.fullmatch(payload["version"]) is None
    ):
        raise ValidationError("artifact version is not canonical")
    if payload["native_bridge_abi_version"] != 30:
        raise ValidationError("artifact does not bind exact native bridge ABI 30")
    if payload["privacy_production_enabled"] is not True:
        raise ValidationError("artifact must include mandatory privacy support")
    expected_features = ["privacy-production-enabled"]
    if payload["cargo_features"] != expected_features:
        raise ValidationError("artifact Cargo feature inventory is not exact")
    _validate_build_environment(root, payload["build_environment"])
    if not isinstance(payload["source_commit"], str) or COMMIT.fullmatch(
        payload["source_commit"]
    ) is None:
        raise ValidationError("artifact source_commit is not canonical")
    if not isinstance(payload["embedded_source_commit"], str) or COMMIT.fullmatch(
        payload["embedded_source_commit"]
    ) is None:
        raise ValidationError("artifact embedded_source_commit is not canonical")
    if type(payload["source_tree_dirty"]) is not bool:
        raise ValidationError("artifact source_tree_dirty must be boolean")
    for field in (
        "source_fingerprint_sha256",
        "cargo_lock_sha256",
        "bridge_header_sha256",
    ):
        if not isinstance(payload[field], str) or SHA256.fullmatch(payload[field]) is None:
            raise ValidationError(f"artifact {field} is not canonical")
    if payload["required_symbols"] != EXPECTED_REQUIRED_SYMBOLS:
        raise ValidationError("artifact required symbol inventory is not exact")
    if payload["forbidden_symbols"] != EXPECTED_FORBIDDEN_SYMBOLS:
        raise ValidationError("artifact forbidden symbol inventory is not exact")
    hashes = payload["hashes"]
    if not isinstance(hashes, dict) or set(hashes) != set(EXPECTED_SLICES):
        raise ValidationError("artifact slice hash registry is not exact")
    if any(not isinstance(value, str) or SHA256.fullmatch(value) is None for value in hashes.values()):
        raise ValidationError("artifact slice hash is not canonical")
    _validate_root_identity(root, payload, lockfile, local_integration=local_integration)
    return payload


def _load_repository_module(root: Path, filename: str, module_name: str):
    module_path = root / "scripts" / filename
    _regular_file(module_path, f"NoritoBridge repository module {filename}")
    spec = importlib.util.spec_from_file_location(
        module_name,
        module_path,
    )
    if spec is None or spec.loader is None:
        raise ValidationError(f"unable to load NoritoBridge repository module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_swift_pin_owner(root: Path):
    return _load_repository_module(
        root,
        "norito_bridge_source_seal.py",
        "norito_bridge_source_seal_for_artifact_validation",
    )


def _canonical_environment_path(name: str, *, directory: bool = False) -> Path:
    raw = os.environ.get(name)
    if raw is None:
        raise ValidationError(f"{name} is required for repository provenance")
    candidate = Path(raw)
    if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
        raise ValidationError(f"{name} must be an absolute canonical path")
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValidationError(f"{name} is unavailable: {error}") from error
    expected_mode = stat.S_ISDIR if directory else stat.S_ISREG
    if resolved != candidate or stat.S_ISLNK(metadata.st_mode) or not expected_mode(
        metadata.st_mode
    ):
        kind = "directory" if directory else "regular file"
        raise ValidationError(f"{name} must be a non-symbolic canonical {kind}")
    return candidate


def _tool_output(executable: Path, arguments: list[str], environment: dict[str, str]) -> str:
    try:
        return subprocess.run(
            [str(executable), *arguments],
            executable=str(executable),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValidationError(f"unable to authenticate build tool {executable}") from error


def _verbose_rust_identity(executable: Path) -> tuple[str, str]:
    output = _tool_output(
        executable,
        ["--version", "--verbose"],
        {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": f"{executable.parent}:/usr/bin:/bin",
            "TMPDIR": "/tmp",
        },
    )
    fields = {}
    for line in output.splitlines():
        key, separator, value = line.partition(": ")
        if separator:
            fields[key] = value
    release = fields.get("release")
    commit = fields.get("commit-hash")
    if release is None or commit is None:
        raise ValidationError(f"build tool returned incomplete identity: {executable}")
    return release, commit


def _validate_tool_provenance(
    payload: dict[str, object],
    source_seal: object,
) -> None:
    environment = payload["build_environment"]
    assert isinstance(environment, dict)
    cargo, rustc, rustdoc, git = source_seal.source_seal_tools()
    for tool in (cargo, rustc, rustdoc):
        tool.authenticate()
    try:
        actual_tools = {
            "cargo_binary_sha256": cargo.canonical,
            "rustc_binary_sha256": rustc.canonical,
            "rustdoc_binary_sha256": rustdoc.canonical,
            "git_binary_sha256": git,
            "python_binary_sha256": Path(sys.executable).resolve(strict=True),
            "rustup_binary_sha256": _canonical_environment_path(
                "NORITO_BRIDGE_SEAL_RUSTUP"
            ),
        }
        for field, executable in actual_tools.items():
            _regular_file(executable, f"authenticated build tool for {field}")
            if _sha256(executable) != environment[field]:
                raise ValidationError(f"artifact build tool digest mismatch: {field}")

        cargo_release, cargo_commit = _verbose_rust_identity(cargo.canonical)
        rustc_release, rustc_commit = _verbose_rust_identity(rustc.canonical)
        rustdoc_release, rustdoc_commit = _verbose_rust_identity(rustdoc.canonical)
        if (
            (cargo_release, cargo_commit)
            != (environment["cargo_release"], environment["cargo_commit_hash"])
            or (rustc_release, rustc_commit)
            != (environment["rustc_release"], environment["rustc_commit_hash"])
            or (rustdoc_release, rustdoc_commit)
            != (environment["rustdoc_release"], environment["rustdoc_commit_hash"])
        ):
            raise ValidationError("artifact Rust tool identity does not match executables")
        if platform.python_version() != environment["python_version"]:
            raise ValidationError("artifact Python version does not match executable")

        common_environment = {
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/tmp",
        }
        git_output = _tool_output(git, ["--version"], common_environment)
        git_match = re.fullmatch(
            r"git version ([0-9]+(?:\.[0-9]+){1,3})(?: .*)?\n?",
            git_output,
        )
        if git_match is None or git_match.group(1) != environment["git_version"]:
            raise ValidationError("artifact Git version does not match executable")

        rustup = actual_tools["rustup_binary_sha256"]
        rustup_output = _tool_output(rustup, ["--version"], common_environment)
        rustup_match = re.match(r"rustup ([0-9]+(?:\.[0-9]+){1,2})", rustup_output)
        if (
            rustup_match is None
            or rustup_match.group(1) != environment["rustup_version"]
        ):
            raise ValidationError("artifact rustup version does not match executable")

        developer_dir = _canonical_environment_path(
            "NORITO_BRIDGE_SEAL_DEVELOPER_DIR",
            directory=True,
        )
        apple_environment = dict(common_environment)
        apple_environment["DEVELOPER_DIR"] = str(developer_dir)
        xcode_output = _tool_output(
            Path("/usr/bin/xcodebuild"),
            ["-version"],
            apple_environment,
        )
        xcode_values = dict(
            line.split(" ", 1) for line in xcode_output.splitlines() if " " in line
        )
        if (
            xcode_values.get("Xcode") != environment["xcode_version"]
            or xcode_values.get("Build")
            != f"version {environment['xcode_build_version']}"
        ):
            raise ValidationError("artifact Xcode identity does not match source host")
        for sdk, field in (
            ("iphoneos", "iphoneos_sdk_version"),
            ("iphonesimulator", "iphonesimulator_sdk_version"),
            ("macosx", "macosx_sdk_version"),
        ):
            value = _tool_output(
                Path("/usr/bin/xcrun"),
                ["--sdk", sdk, "--show-sdk-version"],
                apple_environment,
            ).strip()
            if value != environment[field]:
                raise ValidationError(f"artifact {sdk} SDK identity does not match host")
    finally:
        for tool in (cargo, rustc, rustdoc):
            tool.authenticate()


def _validate_repository_provenance(
    root: Path,
    payload: dict[str, object],
    lockfile: Path,
) -> None:
    """Recompute the selected source closure for a standalone archive owner."""

    source_seal = _load_repository_module(
        root,
        "norito_bridge_source_seal.py",
        "norito_bridge_source_seal_for_provenance_validation",
    )
    pin_commit = _load_repository_module(
        root,
        "check_mobile_sdk_artifact_pin_commit.py",
        "norito_bridge_pin_commit_for_provenance_validation",
    )
    try:
        _validate_tool_provenance(payload, source_seal)
        snapshot = source_seal.snapshot(root, "apple", lockfile)
        actual_fingerprint = snapshot["source_fingerprint_sha256"]
        actual_dirty = snapshot["source_tree_dirty"]
        relationship = pin_commit.validate_pin_relationship(
            root,
            payload["source_commit"],
        )
        expected_embedded_commit = pin_commit.embedded_source_commit(
            root,
            payload["source_commit"],
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise ValidationError(
            f"unable to authenticate artifact source provenance: {error}"
        ) from error
    if relationship not in {"direct", "pin-parent"}:
        raise ValidationError("artifact source commit relationship is not canonical")
    if payload["embedded_source_commit"] != expected_embedded_commit:
        raise ValidationError("artifact embedded source commit does not match source")
    if payload["source_tree_dirty"] is not actual_dirty:
        raise ValidationError("artifact source dirty state does not match source")
    if relationship == "pin-parent" and actual_dirty:
        raise ValidationError(
            "artifact pin-only child commit requires a clean authenticated source closure"
        )
    if payload["source_fingerprint_sha256"] != actual_fingerprint:
        raise ValidationError("artifact source fingerprint does not match source")


def _validate_swift_pins(root: Path, loader: Path, hashes: dict[str, str]) -> None:
    _regular_file(loader, "Swift native bridge loader")
    pin_owner = _load_swift_pin_owner(root)
    contents = loader.read_bytes()
    try:
        pins = pin_owner.swift_native_bridge_hash_pins(contents)
    except RuntimeError as error:
        raise ValidationError(str(error)) from error
    if pins != hashes:
        raise ValidationError("Swift loader slice pins are stale, duplicated, or non-canonical")


def validate(
    *,
    root: Path,
    lockfile_path: Path,
    xcframework: Path,
    manifest_path: Path,
    manifest_link: Path,
    expected_link_target: str,
    swift_loader: Path | None = None,
    verify_repository_provenance: bool = False,
    allow_dirty_source: bool = False,
    local_integration: bool = False,
) -> dict[str, object]:
    if allow_dirty_source and not verify_repository_provenance:
        raise ValidationError(
            "dirty-source allowance requires repository provenance verification"
        )
    root = root.resolve(strict=True)
    source_seal = _load_swift_pin_owner(root)
    try:
        lockfile = source_seal.selected_lockfile_path(root, lockfile_path)
        lock_identity = source_seal.lockfile_identity(lockfile)
    except RuntimeError as error:
        raise ValidationError(str(error)) from error
    if xcframework.is_symlink() or not xcframework.is_dir():
        raise ValidationError("XCFramework root is not a non-symbolic directory")
    if manifest_path != xcframework / MANIFEST_NAME:
        raise ValidationError("embedded artifact manifest has a non-canonical location")
    _reject_internal_symlinks(xcframework)
    if local_integration:
        policy = _load_repository_module(root, "norito_bridge_local_integration.py", "local_apple_validation_policy")
        try:
            policy.directory(root, xcframework.parent, "artifact")
        except (OSError, ValueError, policy.subprocess.CalledProcessError) as error:
            raise ValidationError(str(error)) from error
    payload = _load_manifest(manifest_path, root, lockfile, local_integration=local_integration)

    expected_top_level = {"Info.plist", MANIFEST_NAME, *EXPECTED_SLICES}
    expected_top_level.add(".privacy-production-enabled")
    _exact_entries(xcframework, expected_top_level, "XCFramework top-level")
    privacy_marker = xcframework / ".privacy-production-enabled"
    _regular_file(privacy_marker, "privacy-production-enabled marker")
    if privacy_marker.stat().st_size != 0:
        raise ValidationError("privacy-production-enabled marker must be empty")

    info_path = xcframework / "Info.plist"
    _regular_file(info_path, "XCFramework Info.plist")
    try:
        with info_path.open("rb") as source:
            info = plistlib.load(source)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        raise ValidationError(f"XCFramework Info.plist is malformed: {error}") from error
    expected_info_fields = {
        "AvailableLibraries",
        "CFBundlePackageType",
        "XCFrameworkFormatVersion",
    }
    if not isinstance(info, dict) or set(info) != expected_info_fields:
        raise ValidationError("XCFramework metadata field inventory is not exact")
    if info.get("CFBundlePackageType") != "XFWK" or info.get(
        "XCFrameworkFormatVersion"
    ) != "1.0":
        raise ValidationError("XCFramework metadata identity is not canonical")
    libraries = info.get("AvailableLibraries")
    if (
        not isinstance(libraries, list)
        or len(libraries) != len(EXPECTED_SLICES)
        or any(not isinstance(value, dict) for value in libraries)
    ):
        raise ValidationError("XCFramework slice registry is not canonical")
    metadata = {value.get("LibraryIdentifier"): value for value in libraries}
    if len(metadata) != len(libraries) or set(metadata) != set(EXPECTED_SLICES):
        raise ValidationError("XCFramework slice registry is missing, duplicated, or unexpected")
    binary_path_shapes = {"BinaryPath" in value for value in libraries}
    if len(binary_path_shapes) != 1:
        raise ValidationError(
            "XCFramework slice BinaryPath presence must be uniform across every slice"
        )

    headers: list[bytes] = []
    authoritative_headers = {
        "NoritoBridge.h": root
        / "crates/connect_norito_bridge/include/NoritoBridge.h",
        "connect_norito_bridge.h": root
        / "crates/connect_norito_bridge/include/connect_norito_bridge.h",
        "module.modulemap": root
        / "crates/connect_norito_bridge/module.modulemap.template",
    }
    authoritative_header_bytes = {}
    for name, path in authoritative_headers.items():
        _regular_file(path, f"authoritative {name}")
        authoritative_header_bytes[name] = path.read_bytes()
    hashes = payload["hashes"]
    assert isinstance(hashes, dict)
    for identifier, expected in EXPECTED_SLICES.items():
        library = metadata[identifier]
        expected_library_fields = {
            "HeadersPath",
            "LibraryIdentifier",
            "LibraryPath",
            "SupportedArchitectures",
            "SupportedPlatform",
        }
        if expected["variant"] is not None:
            expected_library_fields.add("SupportedPlatformVariant")
        actual_library_fields = frozenset(library)
        if actual_library_fields not in {
            frozenset(expected_library_fields),
            frozenset(expected_library_fields | {"BinaryPath"}),
        }:
            raise ValidationError(
                f"XCFramework slice metadata field inventory is not exact: {identifier}"
            )
        if (
            library.get("LibraryPath") != LIBRARY_NAME
            or library.get("HeadersPath") != "Headers"
            or library.get("SupportedArchitectures") != expected["architectures"]
            or library.get("SupportedPlatform") != expected["platform"]
        ):
            raise ValidationError(f"XCFramework slice metadata is not canonical: {identifier}")
        variant = expected["variant"]
        if (variant is None and "SupportedPlatformVariant" in library) or (
            variant is not None and library.get("SupportedPlatformVariant") != variant
        ):
            raise ValidationError(f"XCFramework slice variant is not canonical: {identifier}")
        if "BinaryPath" in library and library["BinaryPath"] != LIBRARY_NAME:
            raise ValidationError(f"XCFramework slice BinaryPath conflicts: {identifier}")

        slice_path = xcframework / identifier
        headers_path = slice_path / "Headers"
        _exact_entries(slice_path, {"Headers", LIBRARY_NAME}, f"slice {identifier}")
        _exact_entries(headers_path, EXPECTED_HEADER_ENTRIES, f"headers {identifier}")
        binary = slice_path / LIBRARY_NAME
        _regular_file(binary, f"slice binary {identifier}")
        if _sha256(binary) != hashes[identifier]:
            raise ValidationError(f"artifact slice hash mismatch: {identifier}")
        modulemap = headers_path / "module.modulemap"
        _regular_file(modulemap, f"module map {identifier}")
        for name, expected_contents in authoritative_header_bytes.items():
            candidate = headers_path / name
            _regular_file(candidate, f"{name} {identifier}")
            if candidate.read_bytes() != expected_contents:
                raise ValidationError(
                    f"XCFramework {name} differs from authoritative source: {identifier}"
                )
        bridge_header = headers_path / "connect_norito_bridge.h"
        _regular_file(bridge_header, f"bridge header {identifier}")
        headers.append(bridge_header.read_bytes())
    if len(set(headers)) != 1 or hashlib.sha256(headers[0]).hexdigest() != payload[
        "bridge_header_sha256"
    ]:
        raise ValidationError("slice headers are not identical to the manifest digest")

    if not manifest_link.is_symlink() or os.readlink(manifest_link) != expected_link_target:
        raise ValidationError("public artifact manifest link is not canonical")
    try:
        resolved_link = manifest_link.resolve(strict=True)
    except OSError as error:
        raise ValidationError("public artifact manifest link is broken") from error
    if resolved_link != manifest_path.resolve(strict=True):
        raise ValidationError("public artifact manifest link resolves outside the XCFramework")
    if swift_loader is not None:
        _validate_swift_pins(root, swift_loader, hashes)
    if verify_repository_provenance:
        _validate_repository_provenance(root, payload, lockfile)
        if payload["source_tree_dirty"] and not allow_dirty_source:
            raise ValidationError("release artifact must be built from a clean source tree")
    try:
        if source_seal.lockfile_identity(lockfile) != lock_identity:
            raise ValidationError("selected Cargo lock changed during artifact validation")
    except RuntimeError as error:
        raise ValidationError(str(error)) from error
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--lockfile-path", required=True, type=Path)
    parser.add_argument("--xcframework", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-link", required=True, type=Path)
    parser.add_argument("--expected-link-target", required=True)
    parser.add_argument("--swift-loader", type=Path)
    parser.add_argument("--verify-repository-provenance", action="store_true")
    parser.add_argument("--allow-dirty-source", action="store_true")
    parser.add_argument("--local-integration", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        validate(
            root=arguments.root,
            lockfile_path=arguments.lockfile_path,
            xcframework=arguments.xcframework,
            manifest_path=arguments.manifest,
            manifest_link=arguments.manifest_link,
            expected_link_target=arguments.expected_link_target,
            swift_loader=arguments.swift_loader,
            verify_repository_provenance=arguments.verify_repository_provenance,
            allow_dirty_source=arguments.allow_dirty_source,
            local_integration=arguments.local_integration,
        )
    except (OSError, UnicodeError, ValidationError) as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
