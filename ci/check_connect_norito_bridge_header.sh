#!/usr/bin/env bash
# Verify current native bridge ABI/header parity and reject retired C/JNI exports.
# Requires Python 3, a C11 compiler (CC) and a C++17 compiler (CXX); reads only repository sources.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_LIB="${ROOT_DIR}/crates/connect_norito_bridge/src/lib.rs"
PRIVATE_SETTLEMENT_RUST="${ROOT_DIR}/crates/connect_norito_bridge/src/private_settlement_ffi.rs"
HEADER="${ROOT_DIR}/crates/connect_norito_bridge/include/connect_norito_bridge.h"
UMBRELLA="${ROOT_DIR}/crates/connect_norito_bridge/include/NoritoBridge.h"
PRIVACY_MODEL="${ROOT_DIR}/crates/iroha_data_model/src/privacy/protocol.rs"
RETAIL_MODEL="${ROOT_DIR}/crates/iroha_data_model/src/validation_fee/retail.rs"
PLATFORM_JNI_RUST="${ROOT_DIR}/crates/connect_norito_bridge/src/platform_jni.rs"
MODE="${1:-}"

SELF_TESTS=(
  --self-test-missing-wallet-jni-symbol
  --self-test-unknown-wallet-jni-symbol
  --self-test-unknown-wallet-sign-symbol
  --self-test-retired-kagemusha-header-symbol
  --self-test-retired-kagemusha-rust-symbol
  --self-test-retired-kagemusha-jni-symbol
  --self-test-retired-kagemusha-jni-module-symbol
  --self-test-missing-wallet-header-symbol
  --self-test-missing-wallet-rust-symbol
  --self-test-unknown-wallet-header-symbol
  --self-test-unknown-wallet-rust-symbol
  --self-test-bad-wallet-header-width
  --self-test-bad-wallet-rust-width
  --self-test-bad-wallet-setup-header-request
  --self-test-bad-wallet-setup-rust-request
  --self-test-bad-wallet-open-header-request
  --self-test-bad-wallet-open-rust-request
  --self-test-bad-wallet-enrollment-header-request
  --self-test-bad-wallet-enrollment-rust-request
  --self-test-bad-wallet-install-rust-request
  --self-test-bad-wallet-installation-register-output
  --self-test-bad-wallet-installation-close-owner
  --self-test-bad-wallet-enrollment-rust-result
  --self-test-bad-wallet-review-header-request
  --self-test-bad-wallet-observe-selector
  --self-test-bad-wallet-account-original-length
  --self-test-bad-wallet-account-display-prefix
  --self-test-retired-offline-cash-header-symbol
  --self-test-retired-offline-cash-rust-symbol
  --self-test-retired-pixel6-jni-symbol
  --self-test-missing-domain-header-symbol
  --self-test-missing-domain-rust-symbol
  --self-test-bad-domain-length-width
  --self-test-bad-abi
  --self-test-bad-wallet-memory-rust-status
  --self-test-bad-wallet-storage-header-status
  --self-test-retired-wallet-no-space-status
  --self-test-missing-privacy-header-symbol
  --self-test-bad-privacy-signature
  --self-test-missing-privacy-rust-symbol
  --self-test-extra-privacy-symbol
  --self-test-missing-retail-header-symbol
  --self-test-bad-retail-signature
  --self-test-bad-retail-marker-bound
  --self-test-bad-retail-intent-bound
  --self-test-bad-retail-assessment-bound
  --self-test-retired-fee-header-symbol
  --self-test-missing-sorafs-reference-header-symbol
  --self-test-missing-sorafs-reference-rust-symbol
  --self-test-bad-sorafs-reference-bundle-signature
  --self-test-bad-sorafs-reference-bundle-layout
  --self-test-bad-sorafs-reference-bundle-limit
  --self-test-missing-generated-transaction-signer
  --self-test-missing-conviction-update-signer-header-symbol
  --self-test-bad-generated-transaction-signer-signature
  --self-test-forbidden-retired-transaction-signer
  --self-test-bad-deallocator-signature
  --self-test-umbrella-drift
  --self-test-umbrella-comment-growth
)

usage() {
  echo "usage: ci/check_connect_norito_bridge_header.sh [--self-test|--self-test-*]" >&2
}

run_contract_check() {
  local rust_lib="$1"
  local header="$2"
  local umbrella="$3"
  local privacy_model="$4"
  local retail_model="$5"
  local private_settlement_rust="$6"
  local platform_jni_rust="$7"

  python3 - \
    "${rust_lib}" \
    "${header}" \
    "${umbrella}" \
    "${privacy_model}" \
    "${retail_model}" \
    "${private_settlement_rust}" \
    "${platform_jni_rust}" <<'PY'
from pathlib import Path
import re
import sys

rust = Path(sys.argv[1]).read_text(encoding="utf-8")
header = Path(sys.argv[2]).read_text(encoding="utf-8")
umbrella = Path(sys.argv[3]).read_text(encoding="utf-8")
privacy = Path(sys.argv[4]).read_text(encoding="utf-8")
retail_model = Path(sys.argv[5]).read_text(encoding="utf-8")
rust += "\n" + Path(sys.argv[6]).read_text(encoding="utf-8")
jni_path = Path(sys.argv[7])
wallet_exports_path = jni_path.parent / "kagemusha_wallet_ffi/exports.rs"
rust += "\n" + wallet_exports_path.read_text(encoding="utf-8")
wallet_load_path = jni_path.parent / "kagemusha_wallet_load_original.rs"
rust += "\n" + wallet_load_path.read_text(encoding="utf-8")
for relative in ("review.rs", "installed/exports.rs", "observation.rs"):
    rust += "\n" + (jni_path.parent / "kagemusha_wallet_ffi" / relative).read_text(encoding="utf-8")
native_sources = [jni_path, *sorted(
    source for source in jni_path.parent.rglob("*.rs") if source != jni_path
)]
native_rust = "\n".join(source.read_text(encoding="utf-8") for source in native_sources)


def require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"[connect-norito-header] missing or invalid {label}")


PRIVACY_EXPORTS = {
    "iroha_privacy_compiled_profile_catalog_v1",
    "iroha_privacy_validate_compiled_profile_catalog_v1",
    "iroha_privacy_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_fixture_bundle_v1",
    "iroha_privacy_validate_exact12_capability_manifest_v1",
    "iroha_privacy_free_buffer",
}
SORAFS_REFERENCE_EXPORTS = {
    "connect_norito_sorafs_reference_build_signed_orderbook_order_cancel",
    "connect_norito_sorafs_reference_build_signed_orderbook_order_request",
    "connect_norito_sorafs_reference_build_signed_orderbook_settlement_receipt",
    "connect_norito_sorafs_reference_derive_orderbook_order_id",
    "connect_norito_sorafs_reference_sign_orderbook_payload",
    "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
    "connect_norito_sorafs_reference_validate_bundle_json",
    "connect_norito_sorafs_reference_validate_governance_json",
    "connect_norito_sorafs_reference_validate_hedging_json",
    "connect_norito_sorafs_reference_validate_governance_dag_block_json",
    "connect_norito_sorafs_reference_validate_governance_dag_head_chain_json",
    "connect_norito_sorafs_reference_validate_orderbook_json",
    "connect_norito_sorafs_reference_validate_pdp_bundle_json",
    "connect_norito_sorafs_reference_validate_pdp_challenge_proof_json",
    "connect_norito_sorafs_reference_validate_pdp_commitment_challenge_json",
    "connect_norito_sorafs_reference_validate_pdp_payload_json",
    "connect_norito_sorafs_reference_validate_pop_json",
}
DETACHED_EXPORTS = {
    "connect_norito_canonical_json_blake3_v1",
    "connect_norito_detached_transaction_scaffold_finalize_ed25519_v1",
    "connect_norito_detached_transaction_scaffold_inspect_v1",
}
RETAIL_EXPORTS = {
    "connect_norito_retail_fee_intent_hash_v1",
    "connect_norito_retail_fee_assessment_marker_v1",
    "connect_norito_retail_fee_assessment_decode_v1",
}
PRIVATE_SETTLEMENT_EXPORTS = {
    "connect_norito_private_settlement_committee_proof_response_verify_v1",
    "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
    "connect_norito_private_settlement_audit_approval_response_verify_v1",
}
KAGEMUSHA_WALLET_EXPORTS = {
    "connect_norito_kagemusha_wallet_revision_v1",
    "connect_norito_kagemusha_wallet_open_begin_v1",
    "connect_norito_kagemusha_wallet_open_finish_v1",
    "connect_norito_kagemusha_wallet_open_cancel_v1",
    "connect_norito_kagemusha_wallet_close_v1",
    "connect_norito_kagemusha_wallet_activity_v1",
    "connect_norito_kagemusha_wallet_execute_v1",
    "connect_norito_kagemusha_wallet_setup_v1",
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
}
KAGEMUSHA_WALLET_JNI_EXPORTS = {
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_" + method
    for method in ("revision", "openBegin", "openFinish", "openCancel", "close", "activity", "call", "setup", "enrollment", "enrollmentRefusal", "execute", "review", "executeReviewed", "discardReview", "snapshot")
} | {
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_beginInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_registerInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_closeInstallation",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_relocateRegistrationSource",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletObservationNativeV1_observe",
}
KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS = {
    "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate",
}
TRANSACTION_SIGNER_BASE_EXPORTS = {
    "connect_norito_encode_account_read_permission_multisig_signed_transaction",
    "connect_norito_encode_burn_signed_transaction",
    "connect_norito_encode_claim_identifier_signed_transaction",
    "connect_norito_encode_governance_cast_plain_ballot_signed_transaction",
    "connect_norito_encode_governance_cast_zk_ballot_signed_transaction",
    "connect_norito_encode_governance_propose_deploy_v1_signed_transaction",
    "connect_norito_encode_mint_signed_transaction",
    "connect_norito_encode_multisig_register_signed_transaction",
    "connect_norito_encode_register_zk_asset_signed_transaction",
    "connect_norito_encode_remove_key_value_signed_transaction",
    "connect_norito_encode_set_key_value_signed_transaction",
    "connect_norito_encode_transfer_signed_transaction",
}
TRANSACTION_SIGNER_ALGORITHM_ONLY_EXPORTS = {
    "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg",
}
TRANSACTION_SIGNER_EXPORTS = TRANSACTION_SIGNER_BASE_EXPORTS | {
    f"{name}_alg" for name in TRANSACTION_SIGNER_BASE_EXPORTS
} | TRANSACTION_SIGNER_ALGORITHM_ONLY_EXPORTS


def split_parameters(value: str) -> list[str]:
    value = value.strip()
    if not value or value == "void":
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def header_exports(prefix: str) -> set[str]:
    return set(re.findall(
        rf'(?:int32_t|uint32_t|void)\s+({re.escape(prefix)}[a-z0-9_]+)\s*\(',
        header,
    ))


def exact(label: str, expected: set[str], actual: set[str]) -> None:
    if actual != expected:
        raise SystemExit(
            f"[connect-norito-header] {label} inventory mismatch: "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def signer_template_suffix(template_name: str) -> tuple[str, list[str]]:
    match = re.search(
        rf'pub\s+unsafe\s+extern\s+"C"\s+fn\s+'
        rf'{re.escape(f"${template_name}")}\s*\(\s*'
        r'\$\(\s*\$argument\s*:\s*\$argument_type\s*,\s*\)\*\s*'
        rf'(.*?)\)\s*->\s*([^\s{{]+)\s*{{',
        rust,
        re.S,
    )
    if match is None:
        raise SystemExit(f"cannot parse generated signer template: ${template_name}")
    return match.group(2), split_parameters(match.group(1))


GENERATED_RUST_SIGNATURES: dict[str, tuple[str, list[str]]] = {}


def register_generated_signature(name: str, return_type: str, parameters: list[str]) -> None:
    if name in GENERATED_RUST_SIGNATURES:
        raise SystemExit(f"duplicate generated Rust FFI export: {name}")
    GENERATED_RUST_SIGNATURES[name] = (return_type, parameters)


signer_default_return, signer_default_suffix = signer_template_suffix("default")
signer_algorithm_return, signer_algorithm_suffix = signer_template_suffix("with_algorithm")
signer_invocation_pattern = re.compile(
    r'define_ed25519_signed_transaction_wrapper!\s*\{\s*'
    r'(?P<default>connect_norito_encode_[a-z0-9_]+_signed_transaction)\s*=>\s*'
    r'(?P<algorithm>connect_norito_encode_[a-z0-9_]+_signed_transaction_alg)\s*'
    r'\((?P<arguments>.*?)\)\s*'
    r'identifiers:\s*\(\s*'
    r'(?P<algorithm_code>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*'
    r'(?P<signed_bytes>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*'
    r'(?P<hash_bytes>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;',
    re.S,
)
for match in signer_invocation_pattern.finditer(rust):
    default_name = match.group("default")
    algorithm_name = match.group("algorithm")
    if algorithm_name != f"{default_name}_alg":
        raise SystemExit(f"generated signer algorithm export must pair with {default_name}")
    arguments = split_parameters(match.group("arguments"))
    register_generated_signature(
        default_name,
        signer_default_return,
        arguments + signer_default_suffix,
    )
    register_generated_signature(
        algorithm_name,
        signer_algorithm_return,
        arguments + [
            parameter.replace("$algorithm_code", match.group("algorithm_code"))
            for parameter in signer_algorithm_suffix
        ],
    )

DIRECT_RUST_EXPORTS = set(re.findall(
    r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
    rust,
))
if set(GENERATED_RUST_SIGNATURES) & DIRECT_RUST_EXPORTS:
    raise SystemExit("Rust FFI exports overlap direct and generated definitions")


def rust_exports(prefix: str) -> set[str]:
    return {
        name
        for name in DIRECT_RUST_EXPORTS | set(GENERATED_RUST_SIGNATURES)
        if name.startswith(prefix)
    }


def canonical_rust_type(value: str) -> str:
    value = " ".join(value.strip().split())
    if value.startswith("*const "):
        return "const" + canonical_rust_type(value.removeprefix("*const ")) + "*"
    if value.startswith("*mut "):
        return canonical_rust_type(value.removeprefix("*mut ")) + "*"
    mapping = {
        "()": "void",
        "c_char": "char",
        "c_int": "int32_t",
        "std::ffi::c_int": "int32_t",
        "i32": "int32_t",
        "c_uchar": "uint8_t",
        "c_ulong": "unsignedlong",
        "usize": "size_t",
        "PlatformCallbacks": "connect_norito_kagemusha_platform_v1",
        "WalletResult": "connect_norito_kagemusha_wallet_result_v1",
        "WalletSnapshot": "connect_norito_kagemusha_wallet_snapshot_v1_t",
        "WalletOperationRequest": "connect_norito_kagemusha_wallet_operation_request_v1",
        "WalletSetupRequest": "connect_norito_kagemusha_wallet_setup_request_v1",
        "WalletEnrollmentItem": "connect_norito_kagemusha_wallet_enrollment_item_v1",
        "WalletOpenRequest": "connect_norito_kagemusha_wallet_open_request_v1",
        "WalletReviewRequest": "connect_norito_kagemusha_wallet_review_request_v1",
        "WalletRuntimeOriginals": "connect_norito_kagemusha_wallet_runtime_originals_v1",
        "WalletInstallationAttempt": "connect_norito_kagemusha_wallet_installation_attempt_v1",
        "WalletEnrollmentRequest": "connect_norito_kagemusha_wallet_enrollment_request_v1",
        "ConnectNoritoSorafsReferenceBundlePayload": "ConnectNoritoSorafsReferenceBundlePayload",
        "ConnectNoritoSorafsReferenceInput": "ConnectNoritoSorafsReferenceInput",
        "u8": "uint8_t",
        "u16": "uint16_t",
        "u32": "uint32_t",
        "u64": "uint64_t",
    }
    try:
        return mapping[value]
    except KeyError as error:
        raise SystemExit(f"unsupported Rust FFI type: {value}") from error


def canonical_c_type(value: str) -> str:
    # C prototypes may omit parameter names, including the wallet callback table.
    if value.strip().endswith("*"):
        return "".join(value.split())
    match = re.fullmatch(r"(.+?)([A-Za-z_][A-Za-z0-9_]*)", value.strip(), re.S)
    if match is None:
        raise SystemExit(f"cannot parse C FFI parameter: {value}")
    return "".join(match.group(1).split())


def rust_signature(name: str) -> tuple[str, list[str]]:
    generated = GENERATED_RUST_SIGNATURES.get(name)
    if generated is not None:
        return (
            canonical_rust_type(generated[0]),
            [canonical_rust_type(value.split(":", 1)[1]) for value in generated[1]],
        )
    match = re.search(
        rf'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+{re.escape(name)}\s*'
        rf'\((.*?)\)\s*(?:->\s*([^\s{{]+))?\s*{{',
        rust,
        re.S,
    )
    if match is None:
        raise SystemExit(f"cannot parse Rust FFI signature: {name}")
    return (
        canonical_rust_type(match.group(2) or "()"),
        [canonical_rust_type(value.split(":", 1)[1]) for value in split_parameters(match.group(1))],
    )


def c_signature(name: str) -> tuple[str, list[str]]:
    match = re.search(
        rf'(int32_t|uint32_t|void)\s+{re.escape(name)}\s*\((.*?)\)\s*;',
        header,
        re.S,
    )
    if match is None:
        raise SystemExit(f"cannot parse C FFI signature: {name}")
    return match.group(1), [canonical_c_type(value) for value in split_parameters(match.group(2))]


def require_signature_parity(names: set[str]) -> None:
    for name in sorted(names):
        rust_value = rust_signature(name)
        c_value = c_signature(name)
        if rust_value != c_value:
            raise SystemExit(
                f"Rust/C FFI signature mismatch for {name}: rust={rust_value}, c={c_value}"
            )


def parameter_names(parameters: str, rust_parameters: bool) -> list[str]:
    names = []
    for parameter in split_parameters(parameters):
        if rust_parameters:
            names.append(parameter.split(":", 1)[0].strip())
        else:
            match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', parameter)
            if match is None:
                raise SystemExit(f"cannot parse C parameter: {parameter}")
            names.append(match.group(1))
    return names


def rust_parameter_names(name: str) -> list[str]:
    generated = GENERATED_RUST_SIGNATURES.get(name)
    if generated is not None:
        return parameter_names(",".join(generated[1]), True)
    match = re.search(
        rf'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+{re.escape(name)}\s*\((.*?)\)\s*'
        rf'(?:->\s*[^\s{{]+)?\s*{{',
        rust,
        re.S,
    )
    if match is None:
        raise SystemExit(f"cannot parse Rust FFI parameters: {name}")
    return parameter_names(match.group(1), True)


def c_parameter_names(name: str) -> list[str]:
    match = re.search(
        rf'(?:int32_t|uint32_t|void)\s+{re.escape(name)}\s*\((.*?)\)\s*;',
        header,
        re.S,
    )
    if match is None:
        raise SystemExit(f"cannot parse C FFI parameters: {name}")
    return parameter_names(match.group(1), False)


# The wallet has one current ABI; every other KAGEMUSHA C export is retired.
native_c_exports = set(re.findall(
    r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
    native_rust,
))
exact("Rust KAGEMUSHA wallet", KAGEMUSHA_WALLET_EXPORTS, {
    name for name in native_c_exports if name.startswith("connect_norito_kagemusha_")
})
exact("C KAGEMUSHA wallet", KAGEMUSHA_WALLET_EXPORTS, header_exports("connect_norito_kagemusha_"))
native_jni_exports = set(re.findall(r"\b(Java_[A-Za-z0-9_]*)\s*\(", native_rust))
exact("current JNI wallet", KAGEMUSHA_WALLET_JNI_EXPORTS,
      native_jni_exports & KAGEMUSHA_WALLET_JNI_EXPORTS)
exact("current JNI Load original DATA", KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS,
      native_jni_exports & KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS)
exact("retired Rust offline cash", set(), {
    name for name in native_c_exports if name.startswith("connect_norito_offline_cash_")
})
exact("retired C offline cash", set(), header_exports("connect_norito_offline_cash_"))
retired_jni_prefixes = (
    "Java_org_hyperledger_iroha_sdk_offline_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_probe_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_wallet_Kagemusha",
    "Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_",
)
exact(
    "retired JNI KAGEMUSHA",
    set(),
    {
        name for name in native_jni_exports
        if ("kagemusha" in name.lower() or name.startswith(retired_jni_prefixes))
        and name not in KAGEMUSHA_WALLET_JNI_EXPORTS
        and name not in KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS
    },
)
exact("Rust privacy", PRIVACY_EXPORTS, rust_exports("iroha_privacy_"))
exact("C privacy", PRIVACY_EXPORTS, header_exports("iroha_privacy_"))
exact(
    "Rust SoraFS reference",
    SORAFS_REFERENCE_EXPORTS,
    rust_exports("connect_norito_sorafs_reference_"),
)
exact(
    "C SoraFS reference",
    SORAFS_REFERENCE_EXPORTS,
    header_exports("connect_norito_sorafs_reference_"),
)
exact(
    "Rust detached transaction",
    DETACHED_EXPORTS,
    rust_exports("connect_norito_detached_transaction_")
    | rust_exports("connect_norito_canonical_json_"),
)
exact(
    "C detached transaction",
    DETACHED_EXPORTS,
    header_exports("connect_norito_detached_transaction_")
    | header_exports("connect_norito_canonical_json_"),
)
exact("Rust retail fee", RETAIL_EXPORTS, rust_exports("connect_norito_retail_fee_"))
exact("C retail fee", RETAIL_EXPORTS, header_exports("connect_norito_retail_fee_"))
# First-release artifacts cannot retain a second, retired fee protocol.
exact("retired Rust Hijiri", set(), rust_exports("connect_norito_validation_fee_hijiri_quote_"))
exact("retired C Hijiri", set(), header_exports("connect_norito_validation_fee_hijiri_quote_"))
exact("Rust private settlement", PRIVATE_SETTLEMENT_EXPORTS, rust_exports("connect_norito_private_settlement_"))
exact("C private settlement", PRIVATE_SETTLEMENT_EXPORTS, header_exports("connect_norito_private_settlement_"))

signer_name = re.compile(r"^connect_norito_encode_[a-z0-9_]+_signed_transaction(?:_alg)?$")
rust_transaction_signers = {
    name for name in rust_exports("connect_norito_encode_") if signer_name.fullmatch(name)
}
header_transaction_signers = {
    name for name in header_exports("connect_norito_encode_") if signer_name.fullmatch(name)
}
exact("Rust transaction signer", TRANSACTION_SIGNER_EXPORTS, rust_transaction_signers)
exact("C transaction signer", TRANSACTION_SIGNER_EXPORTS, header_transaction_signers)
for name in sorted(rust_transaction_signers):
    rust_names = rust_parameter_names(name)
    header_names = c_parameter_names(name)
    if rust_names[:2] != ["network_id_ptr", "network_id_len"]:
        raise SystemExit(f"Rust signer {name} must start with exact NetworkId pointer/length")
    if header_names[:2] != ["network_id", "network_id_len"]:
        raise SystemExit(f"C signer {name} must start with exact NetworkId pointer/length")
    rust_fee_index = rust_names.index("fee_payment_json_ptr")
    header_fee_index = header_names.index("fee_payment_json")
    if rust_names[rust_fee_index:rust_fee_index + 4] != [
        "fee_payment_json_ptr", "fee_payment_json_len", "private_key_ptr", "private_key_len"
    ]:
        raise SystemExit(f"Rust signer {name} fee/private-key argument ordering drift")
    if header_names[header_fee_index:header_fee_index + 4] != [
        "fee_payment_json", "fee_payment_json_len", "private_key", "private_key_len"
    ]:
        raise SystemExit(f"C signer {name} fee/private-key argument ordering drift")

require_signature_parity(
    PRIVACY_EXPORTS
    | SORAFS_REFERENCE_EXPORTS
    | DETACHED_EXPORTS
    | RETAIL_EXPORTS
    | PRIVATE_SETTLEMENT_EXPORTS
    | KAGEMUSHA_WALLET_EXPORTS
    | rust_transaction_signers
    | {"connect_norito_bridge_abi_version", "connect_norito_free", "connect_norito_domain_id_validate_v1"}
)

require(r"#define\s+CONNECT_NORITO_BRIDGE_ABI_VERSION\s+31\b", header, "C bridge ABI version")
require(r"pub\s+const\s+PRIVACY_BRIDGE_ABI_VERSION_V1:\s*u32\s*=\s*31\s*;", privacy, "Rust bridge ABI version")
require(
    r"const\s+CONNECT_NORITO_BRIDGE_ABI_VERSION:\s*u32\s*=\s*PRIVACY_BRIDGE_ABI_VERSION_V1\s*;",
    rust,
    "bridge ABI binding",
)
# Design §5.3 typed runtime capacity results: one C name per Native status, no alias.
for rust_name, value in (("NOT_ENOUGH_STORAGE", "-12"), ("NOT_ENOUGH_MEMORY", "-14")):
    require(
        rf"pub\s+const\s+{rust_name}\s*:\s*i32\s*=\s*{value}\s*;",
        native_rust,
        f"Rust KAGEMUSHA wallet {rust_name} status",
    )
    require(
        rf"#define\s+CONNECT_NORITO_KAGEMUSHA_WALLET_{rust_name}\s+{value}(?:\s|$)",
        header,
        f"C KAGEMUSHA wallet {rust_name} status",
    )
if re.search(r"\bpub\s+const\s+NO_SPACE\b", native_rust):
    raise SystemExit("[connect-norito-header] retired KAGEMUSHA wallet NO_SPACE status")
for rust_name, value, header_name in (
    (
        "ERR_RETAIL_FEE_ASSESSMENT",
        "-506",
        "CONNECT_NORITO_ERR_RETAIL_FEE_ASSESSMENT",
    ),
):
    require(rf"const\s+{rust_name}\s*:\s*c_int\s*=\s*{value}\s*;", rust, rust_name)
    require(rf"#define\s+{header_name}\s+{value}(?:\s|$)", header, header_name)

for name, expected in {
    "CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1": "64",
    "CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_TOTAL_BYTES_V1": "67108864",
    "CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_MAX_BLOCKS_V1": "64",
    "CONNECT_NORITO_SORAFS_REFERENCE_GOVERNANCE_DAG_CID_BYTES_V1": "32",
    "CONNECT_NORITO_SORAFS_REFERENCE_MAX_INPUT_BYTES_V1": "67108864",
    "CONNECT_NORITO_SORAFS_REFERENCE_MAX_LABEL_BYTES_V1": "1024",
}.items():
    require(rf"pub\s+const\s+{name}\s*:\s*u32\s*=\s*{expected}\s*;", rust, f"Rust {name}")
    require(rf"#define\s+{name}\s+{expected}\b", header, f"C {name}")

require(
    r"typedef\s+struct\s+ConnectNoritoSorafsReferenceInput\s*\{\s*"
    r"const\s+uint8_t\s*\*\s*bytes_ptr\s*;\s*size_t\s+bytes_len\s*;\s*"
    r"const\s+uint8_t\s*\*\s*label_ptr\s*;\s*size_t\s+label_len\s*;\s*"
    r"\}\s*ConnectNoritoSorafsReferenceInput\s*;",
    header,
    "SoraFS governance descriptor layout",
)
require(
    r"typedef\s+struct\s+ConnectNoritoSorafsReferenceBundlePayload\s*\{\s*"
    r"uint32_t\s+kind\s*;\s*const\s+uint8_t\s*\*\s*bytes_ptr\s*;\s*"
    r"size_t\s+bytes_len\s*;\s*const\s+uint8_t\s*\*\s*label_ptr\s*;\s*"
    r"size_t\s+label_len\s*;\s*\}\s*ConnectNoritoSorafsReferenceBundlePayload\s*;",
    header,
    "SoraFS bundle descriptor layout",
)

# These are the actual Native operation bounds, not retired header aliases.
for name, value in (
    ("RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES", "262_144"),
    ("RETAIL_FEE_ASSESSMENT_MAX_BYTES", "4_096"),
    ("RETAIL_FEE_MARKER_MAX_BYTES", "4_096"),
):
    require(rf"const\s+{name}\s*:\s*usize\s*=\s*{value}\s*;", rust, name)
require(r"pub\s+const\s+RETAIL_FEE_ASSESSMENT_METADATA_KEY\s*:\s*&str\s*=\s*\"validation_fee_assessment\"", retail_model, "typed retail assessment metadata owner")
for name, maximum, operation in (
    ("connect_norito_retail_fee_intent_hash_v1", "RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES", "retail_fee_intent_hash_v1"),
    ("connect_norito_retail_fee_assessment_marker_v1", "RETAIL_FEE_ASSESSMENT_MAX_BYTES", "retail_fee_assessment_marker_v1"),
    ("connect_norito_retail_fee_assessment_decode_v1", "RETAIL_FEE_MARKER_MAX_BYTES", "retail_fee_assessment_decode_v1"),
):
    require(rf"fn\s+{name}\b[^{{]+\{{.*?retail_fee_bridge_call\s*\([^;]*?\b{maximum}\s*,\s*{operation}\b", rust, f"{name} exact operation input bound")
require(r"value\.qualifying_payments\s*>\s*1_000", rust, "Native retail qualifying count cap")
require(r"bytes\.len\(\)\s*>\s*\(RETAIL_FEE_MARKER_MAX_BYTES\s*-\s*RETAIL_FEE_MARKER_PREFIX\.len\(\)\)\s*/\s*2", rust, "Native complete marker output cap")
require(r"json\.len\(\)\s*>\s*RETAIL_FEE_ASSESSMENT_MAX_BYTES", rust, "Native assessment JSON output cap")

def umbrella_contract(contents: str) -> list[str]:
    # Documentation and formatting do not alter the sole canonical include owner.
    without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", contents, flags=re.S)
    return without_comments.split()


if umbrella_contract(umbrella) != [
    "#ifndef", "NORITOBRIDGE_H", "#define", "NORITOBRIDGE_H",
    "#include", '"connect_norito_bridge.h"', "#endif",
]:
    raise SystemExit("[connect-norito-header] umbrella header drift")

print(
    "[connect-norito-header] ABI 31 synchronized: "
    f"{len(PRIVACY_EXPORTS)} privacy, "
    f"{len(SORAFS_REFERENCE_EXPORTS)} SoraFS, {len(DETACHED_EXPORTS)} detached, "
    f"{len(RETAIL_EXPORTS)} retail-fee, "
    f"{len(PRIVATE_SETTLEMENT_EXPORTS)} private-settlement, "
    f"{len(KAGEMUSHA_WALLET_EXPORTS)} KAGEMUSHA wallet, "
    f"and {len(TRANSACTION_SIGNER_EXPORTS)} transaction-signer exports"
)
PY
}

compile_header() {
  if ! command -v "${CC:-cc}" >/dev/null 2>&1; then
    echo "[connect-norito-header] required C compiler not found: ${CC:-cc}" >&2
    exit 1
  fi
  if ! command -v "${CXX:-c++}" >/dev/null 2>&1; then
    echo "[connect-norito-header] required C++ compiler not found: ${CXX:-c++}" >&2
    exit 1
  fi

  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/iroha-bridge-header-compile.XXXXXX")"
  trap 'rm -rf "${tmp}"' RETURN
  printf '#include "%s"\nint main(void) { return 0; }\n' "${HEADER}" >"${tmp}/header.c"
  printf '#include "%s"\nint main() { return 0; }\n' "${HEADER}" >"${tmp}/header.cc"
  "${CC:-cc}" -std=c11 -fsyntax-only "${tmp}/header.c"
  "${CXX:-c++}" -std=c++17 -fsyntax-only "${tmp}/header.cc"
}

replace_once() {
  local path="$1"
  local source="$2"
  local replacement="$3"
  python3 - "${path}" "${source}" "${replacement}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = sys.argv[2]
replacement = sys.argv[3]
text = path.read_text(encoding="utf-8")
if text.count(source) != 1:
    raise SystemExit(f"negative-control mutation count is not one for {source!r}")
path.write_text(text.replace(source, replacement), encoding="utf-8")
PY
}

replace_regex_once() {
  local path="$1"
  local pattern="$2"
  local replacement="$3"
  python3 - "${path}" "${pattern}" "${replacement}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
pattern = sys.argv[2]
replacement = sys.argv[3]
text = path.read_text(encoding="utf-8")
updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
if count != 1:
    raise SystemExit(
        f"negative-control regex mutation count must be one (found {count}): {pattern}"
    )
path.write_text(updated, encoding="utf-8")
PY
}

make_negative_workspace() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/iroha-bridge-header.XXXXXX")"
  cp "${RUST_LIB}" "${tmp}/lib.rs"
  cp "${PRIVATE_SETTLEMENT_RUST}" "${tmp}/private_settlement_ffi.rs"
  cp "${PLATFORM_JNI_RUST}" "${tmp}/platform_jni.rs"
  cp -R "${PLATFORM_JNI_RUST%.rs}" "${tmp}/platform_jni"
  cp "${ROOT_DIR}/crates/connect_norito_bridge/src/kagemusha_wallet_ffi.rs" "${tmp}/kagemusha_wallet_ffi.rs"
  cp -R "${ROOT_DIR}/crates/connect_norito_bridge/src/kagemusha_wallet_ffi" "${tmp}/kagemusha_wallet_ffi"
  cp "${ROOT_DIR}/crates/connect_norito_bridge/src/kagemusha_wallet_load_original.rs" "${tmp}/kagemusha_wallet_load_original.rs"
  cp -R "${ROOT_DIR}/crates/connect_norito_bridge/src/kagemusha_wallet_load_original" "${tmp}/kagemusha_wallet_load_original"
  cp "${PRIVACY_MODEL}" "${tmp}/privacy.rs"
  cp "${RETAIL_MODEL}" "${tmp}/retail_fee_model.rs"
  cp "${HEADER}" "${tmp}/connect_norito_bridge.h"
  cp "${UMBRELLA}" "${tmp}/NoritoBridge.h"
  printf '%s' "${tmp}"
}

expect_contract_rejection() {
  local tmp="$1"
  local expected_diagnostic="${2:-}"
  local output
  if output="$(run_contract_check \
      "${tmp}/lib.rs" \
      "${tmp}/connect_norito_bridge.h" \
      "${tmp}/NoritoBridge.h" \
      "${tmp}/privacy.rs" \
      "${tmp}/retail_fee_model.rs" \
      "${tmp}/private_settlement_ffi.rs" \
      "${tmp}/platform_jni.rs" 2>&1)"; then
    echo "[connect-norito-header] negative control unexpectedly passed: ${MODE}" >&2
    exit 1
  fi
  if [[ -n "${expected_diagnostic}" && "${output}" != *"${expected_diagnostic}"* ]]; then
    echo "[connect-norito-header] negative control rejected for the wrong reason: ${MODE}" >&2
    echo "${output}" >&2
    exit 1
  fi
  echo "[connect-norito-header] negative control rejected expected drift: ${MODE}"
}

if [[ "${MODE}" == "--self-test" ]]; then
  "${BASH_SOURCE[0]}"
  for control in "${SELF_TESTS[@]}"; do
    "${BASH_SOURCE[0]}" "${control}"
  done
  exit 0
fi

if [[ "${MODE}" == --self-test-* ]]; then
  # Prove the authoritative inputs pass before mutating a private copy. This
  # prevents an unrelated source error from masquerading as a negative test.
  run_contract_check \
    "${RUST_LIB}" \
    "${HEADER}" \
    "${UMBRELLA}" \
    "${PRIVACY_MODEL}" \
    "${RETAIL_MODEL}" \
    "${PRIVATE_SETTLEMENT_RUST}" \
    "${PLATFORM_JNI_RUST}" >/dev/null
  tmp="$(make_negative_workspace)"
  trap 'rm -rf "${tmp}"' EXIT
  tmp_rust="${tmp}/lib.rs"
  tmp_header="${tmp}/connect_norito_bridge.h"
  tmp_umbrella="${tmp}/NoritoBridge.h"
  expected_diagnostic=""

  case "${MODE}" in
    --self-test-bad-wallet-observe-selector)
      replace_regex_once "${tmp}/kagemusha_wallet_ffi/observation.rs" \
        '(fn connect_norito_kagemusha_wallet_observe_v1\(.*?selector: )u32' '\1u64'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_observe_v1"
      ;;
    --self-test-bad-wallet-account-original-length)
      replace_regex_once "${tmp}/kagemusha_wallet_ffi/observation.rs" \
        '(fn connect_norito_kagemusha_wallet_account_original_v1\(.*?length: )usize' '\1u32'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_account_original_v1"
      ;;
    --self-test-bad-wallet-account-display-prefix)
      replace_regex_once "${tmp}/kagemusha_wallet_ffi/observation.rs" \
        '(fn connect_norito_kagemusha_wallet_account_display_v1\(.*?prefix: )u16' '\1u32'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_account_display_v1"
      ;;
    --self-test-missing-wallet-jni-symbol)
      replace_once "${tmp}/platform_jni/kagemusha_wallet_advance.rs" \
        "fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_call(" \
        "fn removed_wallet_call("
      expected_diagnostic="current JNI wallet inventory mismatch"
      ;;
    --self-test-unknown-wallet-jni-symbol)
      printf '\npub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_sign() -> jint { 0 }\n' >> "${tmp}/platform_jni/kagemusha_wallet_advance.rs"
      expected_diagnostic="retired JNI KAGEMUSHA inventory mismatch"
      ;;
    --self-test-unknown-wallet-sign-symbol)
      printf '\nint32_t connect_norito_kagemusha_wallet_sign_v1(void);\n' >> "${tmp_header}"
      expected_diagnostic="C KAGEMUSHA wallet inventory mismatch: missing=[], extra=['connect_norito_kagemusha_wallet_sign_v1']"
      ;;
    --self-test-retired-kagemusha-header-symbol)
      printf '\nint32_t connect_norito_kagemusha_retired_v1(void);\n' >> "${tmp_header}"
      expected_diagnostic="C KAGEMUSHA wallet inventory mismatch"
      ;;
    --self-test-retired-kagemusha-rust-symbol)
      printf '\npub unsafe extern "C" fn connect_norito_kagemusha_retired_v1() -> c_int { 0 }\n' >> "${tmp_rust}"
      expected_diagnostic="Rust KAGEMUSHA wallet inventory mismatch"
      ;;
    --self-test-missing-wallet-header-symbol)
      replace_once "${tmp_header}" \
        "connect_norito_kagemusha_wallet_credit_status_v1" \
        "removed_connect_norito_kagemusha_wallet_credit_status_v1"
      expected_diagnostic="C KAGEMUSHA wallet inventory mismatch: missing=['connect_norito_kagemusha_wallet_credit_status_v1']"
      ;;
    --self-test-missing-wallet-rust-symbol)
      replace_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        "connect_norito_kagemusha_wallet_credit_status_v1" \
        "removed_connect_norito_kagemusha_wallet_credit_status_v1"
      expected_diagnostic="Rust KAGEMUSHA wallet inventory mismatch: missing=['connect_norito_kagemusha_wallet_credit_status_v1']"
      ;;
    --self-test-unknown-wallet-header-symbol)
      printf '\nint32_t connect_norito_kagemusha_wallet_unknown_v1(void);\n' >> "${tmp_header}"
      expected_diagnostic="C KAGEMUSHA wallet inventory mismatch: missing=[], extra=['connect_norito_kagemusha_wallet_unknown_v1']"
      ;;
    --self-test-unknown-wallet-rust-symbol)
      printf '\npub extern "C" fn connect_norito_kagemusha_wallet_unknown_v1() -> i32 { 0 }\n' >> "${tmp}/kagemusha_wallet_ffi/exports.rs"
      expected_diagnostic="Rust KAGEMUSHA wallet inventory mismatch: missing=[], extra=['connect_norito_kagemusha_wallet_unknown_v1']"
      ;;
    --self-test-bad-wallet-header-width)
      replace_once "${tmp_header}" \
        "connect_norito_kagemusha_wallet_execute_v1(uint64_t handle," \
        "connect_norito_kagemusha_wallet_execute_v1(uint32_t handle,"
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_execute_v1"
      ;;
    --self-test-bad-wallet-rust-width)
      replace_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        $'connect_norito_kagemusha_wallet_execute_v1(\n    handle: u64,' \
        $'connect_norito_kagemusha_wallet_execute_v1(\n    handle: u32,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_execute_v1"
      ;;
    --self-test-bad-wallet-setup-header-request)
      replace_once "${tmp_header}" \
        "connect_norito_kagemusha_wallet_setup_v1(uint64_t handle, const connect_norito_kagemusha_wallet_setup_request_v1* request," \
        "connect_norito_kagemusha_wallet_setup_v1(uint64_t handle, const connect_norito_kagemusha_wallet_operation_request_v1* request,"
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_setup_v1"
      ;;
    --self-test-bad-wallet-setup-rust-request)
      replace_regex_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        '(fn connect_norito_kagemusha_wallet_setup_v1\(.*?request: \*const )WalletSetupRequest' \
        '\1WalletOperationRequest'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_setup_v1"
      ;;
    --self-test-bad-wallet-open-header-request)
      replace_once "${tmp_header}" \
        "connect_norito_kagemusha_wallet_open_begin_v1(uint64_t runtime, const connect_norito_kagemusha_wallet_open_request_v1* request," \
        "connect_norito_kagemusha_wallet_open_begin_v1(uint64_t runtime, const connect_norito_kagemusha_wallet_setup_request_v1* request,"
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_open_begin_v1"
      ;;
    --self-test-bad-wallet-open-rust-request)
      replace_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        'request: *const WalletOpenRequest,' \
        'request: *const WalletSetupRequest,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_open_begin_v1"
      ;;
    --self-test-bad-wallet-enrollment-header-request)
      replace_once "${tmp_header}" \
        "const connect_norito_kagemusha_wallet_enrollment_request_v1* request," \
        "const connect_norito_kagemusha_wallet_setup_request_v1* request,"
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_enrollment_v1"
      ;;
    --self-test-bad-wallet-enrollment-rust-request)
      replace_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        'request: *const WalletEnrollmentRequest,' \
        'request: *const WalletSetupRequest,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_enrollment_v1"
      ;;
    --self-test-bad-wallet-install-rust-request)
      replace_once "${tmp}/kagemusha_wallet_ffi/installed/exports.rs" \
        'request: *const WalletRuntimeOriginals,' \
        'request: *const WalletOpenRequest,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_installation_begin_v1"
      ;;
    --self-test-bad-wallet-installation-register-output)
      replace_once "${tmp}/kagemusha_wallet_ffi/installed/exports.rs" \
        'out_runtime: *mut u64,' \
        'out_runtime: *mut u32,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_installation_register_v1"
      ;;
    --self-test-bad-wallet-installation-close-owner)
      replace_once "${tmp_header}" \
        'connect_norito_kagemusha_wallet_installation_attempt_v1** attempt);' \
        'connect_norito_kagemusha_wallet_installation_attempt_v1* attempt);'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_installation_close_v1"
      ;;
    --self-test-bad-wallet-enrollment-rust-result)
      replace_once "${tmp}/kagemusha_wallet_ffi/exports.rs" \
        $'request: *const WalletEnrollmentRequest,\n    out: *mut WalletResult,' \
        $'request: *const WalletEnrollmentRequest,\n    out: *mut WalletSnapshot,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_enrollment_v1"
      ;;
    --self-test-bad-wallet-review-header-request)
      replace_once "${tmp_header}" \
        'const connect_norito_kagemusha_wallet_review_request_v1 *request,' \
        'const connect_norito_kagemusha_wallet_open_request_v1 *request,'
      expected_diagnostic="Rust/C FFI signature mismatch for connect_norito_kagemusha_wallet_review_v1"
      ;;
    --self-test-retired-kagemusha-jni-symbol)
      printf '\npub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_kagemusha_RetiredBridge_nativeRetired() -> jint { 0 }\n' >> "${tmp}/platform_jni.rs"
      expected_diagnostic="retired JNI KAGEMUSHA inventory mismatch"
      ;;
    --self-test-retired-kagemusha-jni-module-symbol)
      printf '\npub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_kagemusha_RetiredBridge_nativeRetired() -> jint { 0 }\n' >> "${tmp}/platform_jni/private_settlement.rs"
      expected_diagnostic="retired JNI KAGEMUSHA inventory mismatch"
      ;;
    --self-test-retired-offline-cash-header-symbol)
      printf '\nint32_t connect_norito_offline_cash_retired_v1(void);\n' >> "${tmp_header}"
      expected_diagnostic="retired C offline cash inventory mismatch"
      ;;
    --self-test-retired-offline-cash-rust-symbol)
      printf '\npub unsafe extern "C" fn connect_norito_offline_cash_retired_v1() -> c_int { 0 }\n' >> "${tmp}/private_settlement_ffi.rs"
      expected_diagnostic="retired Rust offline cash inventory mismatch"
      ;;
    --self-test-retired-pixel6-jni-symbol)
      printf '\npub unsafe extern "system" fn Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_nativeRetired() -> jint { 0 }\n' >> "${tmp}/platform_jni/private_settlement.rs"
      expected_diagnostic="retired JNI KAGEMUSHA inventory mismatch"
      ;;
    --self-test-missing-domain-header-symbol)
      replace_once "${tmp_header}" \
        "connect_norito_domain_id_validate_v1" "removed_domain_id_validate_v1"
      ;;
    --self-test-missing-domain-rust-symbol)
      replace_once "${tmp_rust}" \
        'pub unsafe extern "C" fn connect_norito_domain_id_validate_v1' \
        'pub unsafe extern "C" fn removed_domain_id_validate_v1'
      ;;
    --self-test-bad-domain-length-width)
      replace_once "${tmp_header}" \
        'connect_norito_domain_id_validate_v1(const char* input, unsigned long input_len)' \
        'connect_norito_domain_id_validate_v1(const char* input, uint32_t input_len)'
      ;;
    --self-test-bad-abi)
      replace_once "${tmp_header}" \
        "#define CONNECT_NORITO_BRIDGE_ABI_VERSION 31" \
        "#define CONNECT_NORITO_BRIDGE_ABI_VERSION 22"
      ;;
    --self-test-bad-wallet-memory-rust-status)
      replace_once "${tmp}/kagemusha_wallet_ffi.rs" \
        "pub const NOT_ENOUGH_MEMORY: i32 = -14;" \
        "pub const NOT_ENOUGH_MEMORY: i32 = -15;"
      expected_diagnostic="missing or invalid Rust KAGEMUSHA wallet NOT_ENOUGH_MEMORY status"
      ;;
    --self-test-bad-wallet-storage-header-status)
      replace_once "${tmp_header}" \
        "#define CONNECT_NORITO_KAGEMUSHA_WALLET_NOT_ENOUGH_STORAGE -12" \
        "#define CONNECT_NORITO_KAGEMUSHA_WALLET_NOT_ENOUGH_STORAGE -13"
      expected_diagnostic="missing or invalid C KAGEMUSHA wallet NOT_ENOUGH_STORAGE status"
      ;;
    --self-test-retired-wallet-no-space-status)
      replace_once "${tmp}/kagemusha_wallet_ffi.rs" \
        "pub const TERMINAL: i32 = -13;" \
        "pub const TERMINAL: i32 = -13;
pub const NO_SPACE: i32 = -12;"
      expected_diagnostic="retired KAGEMUSHA wallet NO_SPACE status"
      ;;
    --self-test-missing-privacy-header-symbol)
      replace_once "${tmp_header}" \
        "iroha_privacy_compiled_profile_catalog_v1" \
        "removed_iroha_privacy_compiled_profile_catalog_v1"
      ;;
    --self-test-bad-privacy-signature)
      replace_regex_once "${tmp_header}" \
        '(iroha_privacy_compiled_profile_catalog_v1\s*\([^;]*?)unsigned long\* out_len' \
        '\g<1>unsigned long out_len'
      ;;
    --self-test-missing-privacy-rust-symbol)
      replace_once "${tmp_rust}" \
        'pub unsafe extern "C" fn iroha_privacy_compiled_profile_catalog_v1' \
        'pub unsafe extern "C" fn removed_iroha_privacy_compiled_profile_catalog_v1'
      ;;
    --self-test-extra-privacy-symbol)
      replace_once "${tmp_header}" \
        $'#ifdef __cplusplus\nextern "C" {' \
        $'int32_t iroha_privacy_retired_v1(void);\n\n#ifdef __cplusplus\nextern "C" {'
      ;;
    --self-test-missing-retail-header-symbol)
      replace_once "${tmp_header}" \
        "connect_norito_retail_fee_assessment_decode_v1" \
        "removed_connect_norito_retail_fee_assessment_decode_v1"
      ;;
    --self-test-bad-retail-signature)
      replace_regex_once "${tmp_header}" \
        '(connect_norito_retail_fee_assessment_decode_v1\s*\(\s*const uint8_t\* input,\s*)unsigned long input_len' \
        '\g<1>uint32_t input_len'
      ;;
    --self-test-bad-retail-marker-bound)
      replace_once "${tmp_rust}" \
        "const RETAIL_FEE_MARKER_MAX_BYTES: usize = 4_096;" \
        "const RETAIL_FEE_MARKER_MAX_BYTES: usize = 4_095;"
      ;;
    --self-test-bad-retail-intent-bound)
      replace_once "${tmp_rust}" \
        "const RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES: usize = 262_144;" \
        "const RETAIL_FEE_BRIDGE_MAX_INPUT_BYTES: usize = 262_145;"
      ;;
    --self-test-bad-retail-assessment-bound)
      replace_once "${tmp_rust}" \
        "const RETAIL_FEE_ASSESSMENT_MAX_BYTES: usize = 4_096;" \
        "const RETAIL_FEE_ASSESSMENT_MAX_BYTES: usize = 4_097;"
      ;;
    --self-test-retired-fee-header-symbol)
      printf '\nint32_t connect_norito_validation_fee_hijiri_quote_request_v1(void);\n' >> "${tmp_header}"
      ;;
    --self-test-missing-sorafs-reference-header-symbol)
      replace_once "${tmp_header}" \
        "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json" \
        "removed_connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json"
      ;;
    --self-test-missing-sorafs-reference-rust-symbol)
      replace_once "${tmp_rust}" \
        'pub unsafe extern "C" fn connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json' \
        'pub unsafe extern "C" fn removed_connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json'
      ;;
    --self-test-bad-sorafs-reference-bundle-signature)
      replace_regex_once "${tmp_header}" \
        '(connect_norito_sorafs_reference_validate_bundle_json\s*\(\s*)const ConnectNoritoSorafsReferenceBundlePayload\*' \
        '\g<1>ConnectNoritoSorafsReferenceBundlePayload*'
      ;;
    --self-test-bad-sorafs-reference-bundle-layout)
      replace_regex_once "${tmp_header}" \
        '(typedef struct ConnectNoritoSorafsReferenceBundlePayload\s*\{\s*)uint32_t kind' \
        '\g<1>uint16_t kind'
      ;;
    --self-test-bad-sorafs-reference-bundle-limit)
      replace_once "${tmp_header}" \
        "#define CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1 64" \
        "#define CONNECT_NORITO_SORAFS_REFERENCE_BUNDLE_MAX_PAYLOADS_V1 63"
      ;;
    --self-test-missing-generated-transaction-signer)
      replace_once "${tmp_rust}" \
        "    connect_norito_encode_burn_signed_transaction =>" \
        "    removed_connect_norito_encode_burn_signed_transaction =>"
      ;;
    --self-test-missing-conviction-update-signer-header-symbol)
      replace_once "${tmp_header}" \
        "connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg" \
        "removed_governance_update_plain_conviction_signed_transaction_alg"
      expected_diagnostic="C transaction signer inventory mismatch: missing=['connect_norito_encode_governance_update_plain_conviction_signed_transaction_alg']"
      ;;
    --self-test-bad-generated-transaction-signer-signature)
      replace_once "${tmp_rust}" \
        '$algorithm_code: u8,' \
        '$algorithm_code: u16,'
      ;;
    --self-test-forbidden-retired-transaction-signer)
      replace_once "${tmp_rust}" \
        "    connect_norito_encode_burn_signed_transaction =>" \
        "    connect_norito_encode_shield_signed_transaction =>"
      ;;
    --self-test-bad-deallocator-signature)
      replace_once "${tmp_header}" \
        "void connect_norito_free(uint8_t *ptr);" \
        "void connect_norito_free(const uint8_t *ptr);"
      ;;
    --self-test-umbrella-comment-growth)
      printf '\n/* Documentary growth preserves the canonical include owner. */\n// Additional source guidance.\n' >> "${tmp_umbrella}"
      run_contract_check \
        "${tmp_rust}" "${tmp_header}" "${tmp_umbrella}" \
        "${tmp}/privacy.rs" \
        "${tmp}/retail_fee_model.rs" "${tmp}/private_settlement_ffi.rs" \
        "${tmp}/platform_jni.rs"
      echo "[connect-norito-header] positive control preserved canonical umbrella: ${MODE}"
      exit 0
      ;;
    --self-test-umbrella-drift)
      replace_once "${tmp_umbrella}" \
        '#include "connect_norito_bridge.h"' \
        '#include "wrong_bridge.h"'
      ;;
    *)
      usage
      exit 2
      ;;
  esac

  expect_contract_rejection "${tmp}" "${expected_diagnostic}"
  exit 0
fi

if [[ -n "${MODE}" ]]; then
  usage
  exit 2
fi

run_contract_check \
  "${RUST_LIB}" \
  "${HEADER}" \
  "${UMBRELLA}" \
  "${PRIVACY_MODEL}" \
  "${RETAIL_MODEL}" \
  "${PRIVATE_SETTLEMENT_RUST}" \
  "${PLATFORM_JNI_RUST}"
compile_header
