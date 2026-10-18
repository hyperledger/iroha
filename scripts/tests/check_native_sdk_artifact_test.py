"""Focused first-release contract tests for native SDK artifact inspection."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import re
import types
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/check_native_sdk_artifact.py"
SPEC = importlib.util.spec_from_file_location("check_native_sdk_artifact", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RETIRED_KAGEMUSHA_C_SYMBOLS = {
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
    "connect_norito_kagemusha_ordinary_runtime_startup_v1",
    "connect_norito_kagemusha_ordinary_current_control_v1",
    "connect_norito_kagemusha_ordinary_outgoing_v1",
    "connect_norito_kagemusha_testnet_state_proof_observe_v1",
    "connect_norito_kagemusha_testnet_finalized_mint_observe_v1",
    "connect_norito_kagemusha_testnet_value_admit_v1",
    "connect_norito_kagemusha_testnet_value_credit_v1",
    "connect_norito_kagemusha_testnet_native_startup_contract_v1",
    "connect_norito_kagemusha_testnet_native_startup_activate_v1",
    "connect_norito_kagemusha_ordinary_incoming_v1",
    "connect_norito_kagemusha_ordinary_integrity_refresh_v1",
    "connect_norito_kagemusha_ordinary_mint_funding_v1",
    "connect_norito_kagemusha_device_capabilities_v1",
    "connect_norito_kagemusha_device_execute_v1",
    "connect_norito_kagemusha_device_command_response_v1_verify",
    "connect_norito_kagemusha_reserve_finality_hint_v1",
    "connect_norito_kagemusha_reserve_finality_verify_v1",
    "connect_norito_kagemusha_top_up_signed_request_validate_v1",
}
RETIRED_KAGEMUSHA_C_PREFIX = (
    "connect_norito_" + "_".join(reversed(("cash", "offline"))) + "_"
)


def test_native_c_contracts_exclude_retired_kagemusha_exports() -> None:
    assert len(RETIRED_KAGEMUSHA_C_SYMBOLS) == 42
    for sdk in ("c-jni", "csharp"):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        assert RETIRED_KAGEMUSHA_C_SYMBOLS.isdisjoint(required)
        expected = MODULE.KAGEMUSHA_WALLET_C_EXPORTS + (
            MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS + MODULE.KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS if sdk == "c-jni" else ()
        )
        assert tuple(symbol for symbol in required if "kagemusha" in symbol.lower()) == expected


def test_current_wallet_export_contract_matches_every_apple_inventory() -> None:
    """Keep the independently reviewed publication and admission inventories exact."""
    expected = MODULE.KAGEMUSHA_WALLET_C_EXPORTS
    assert len(expected) == len(set(expected)) == 27
    for relative, start, end in (
        ("scripts/build_norito_xcframework.sh", '"required_symbols": [', '"forbidden_symbols": ['),
        ("scripts/validate_norito_bridge_xcframework.py", "EXPECTED_REQUIRED_SYMBOLS = [", "EXPECTED_FORBIDDEN_SYMBOLS = ["),
        ("scripts/check_mobile_sdk_artifacts.sh", "REQUIRED_PROTOCOL_C_SYMBOLS=(", "\n)"),
        ("ci/check_connect_norito_bridge_header.sh", "KAGEMUSHA_WALLET_EXPORTS = {", "\n}"),
    ):
        source = (REPO_ROOT / relative).read_text().split(start, 1)[1].split(end, 1)[0]
        observed = re.findall(r"connect_norito_kagemusha_[A-Za-z0-9_]+", source)
        assert len(observed) == len(expected), relative
        assert set(observed) == set(expected), relative
        if not relative.startswith("ci/"):
            assert tuple(observed) == expected, relative


def test_current_wallet_exports_are_accepted_and_unknown_names_are_rejected() -> None:
    current = (
        MODULE.KAGEMUSHA_WALLET_C_EXPORTS
        + MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS
        + MODULE.KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS
    )
    assert len(current) == len(set(current)) == 48
    for sdk in ("c-jni", "csharp"):
        MODULE.validate_retired_protocol_symbols(current, sdk=sdk)
        for symbol in (*current, "connect_norito_free"):
            assert not MODULE.is_retired_kagemusha_export(symbol)
        for symbol in (
            "connect_norito_kagemusha_wallet_install_runtime_v1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_installRuntime",
            "connect_norito_kagemusha_wallet_load_original_validate_v1_optional",
            "connect_norito_kagemusha_wallet_enrollment_v1_optional",
            "connect_norito_kagemusha_wallet_fresh_grant_v1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletEnrollmentNativeV1_freshGrant",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletEnrollmentNativeV1_enroll",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_reviewV2",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate_optional",
            "connect_norito_kagemusha_wallet_unknown_v1",
            "connect_norito_kagemusha_wallet_sign_v1",
            "connect_norito_kagemusha_wallet_open_v1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_open",
            "connect_norito_kagemusha_wallet_open_v2",
            "connect_norito_kagemusha_wallet_open_v1_alias",
            "connect_norito_kagemusha_retired_v1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_sign",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV2_open",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_open_alias",
            *sorted(RETIRED_KAGEMUSHA_C_SYMBOLS),
        ):
            assert MODULE.is_retired_kagemusha_export(symbol)
            try:
                MODULE.validate_retired_protocol_symbols([*current, symbol], sdk=sdk)
            except MODULE.ArtifactContractError as error:
                assert symbol in str(error)
            else:
                raise AssertionError("unknown KAGEMUSHA export accepted: " + symbol)


def test_current_new_wallet_exports_are_each_mandatory_and_optional_aliases_are_rejected() -> None:
    new_c = tuple("connect_norito_kagemusha_wallet_" + suffix + "_v1"
                  for suffix in ("review", "execute_reviewed", "discard_review", "installation_begin", "installation_register", "installation_close", "registration_source_relocate", "observe", "account_original", "account_display", "enrollment", "enrollment_refusal"))
    new_jni = tuple("Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_" + method
                    for method in ("review", "executeReviewed", "discardReview", "enrollment", "enrollmentRefusal")) + (
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_beginInstallation",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_registerInstallation",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_closeInstallation",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_relocateRegistrationSource",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletObservationNativeV1_observe",
    )
    for sdk, added in (("csharp", new_c), ("c-jni", new_c + new_jni)):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        for missing in added:
            assert missing in required
            library = types.SimpleNamespace(**{symbol: object() for symbol in required if symbol != missing})
            with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
                try:
                    MODULE.probe_c_abi(Path("symbol-DATA-only"), required)
                except MODULE.ArtifactContractError as error:
                    assert str(error) == "native C ABI artifact is missing required symbols: " + missing
                else:
                    raise AssertionError("missing required current wallet export accepted: " + missing)
            assert MODULE.is_retired_kagemusha_export(missing + "_optional")
            try:
                MODULE.validate_retired_protocol_symbols([*required, missing + "_optional"], sdk=sdk)
            except MODULE.ArtifactContractError as error:
                assert missing + "_optional" in str(error)
            else:
                raise AssertionError("optional wallet alias accepted")


def test_current_wallet_c_and_jni_inventory_matches_independent_source_declarations() -> None:
    header = (REPO_ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h").read_text()
    native = "\n".join(path.read_text() for path in (REPO_ROOT / "crates/connect_norito_bridge/src").rglob("*.rs"))
    c_header = set(re.findall(r"(?:int32_t|uint32_t|void)\s+(connect_norito_kagemusha_wallet_[A-Za-z0-9_]+)\s*\(", header))
    c_rust = set(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(connect_norito_kagemusha_wallet_[A-Za-z0-9_]+)\s*\(', native))
    jni_rust = set(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+(Java_org_hyperledger_iroha_sdk_offline_wallet_Kagemusha[A-Za-z0-9_]+)\s*\(', native))
    kotlin = (REPO_ROOT / "kotlin/kagemusha-wallet-android/src/main/java/org/hyperledger/iroha/sdk/offline/wallet/KagemushaWalletV1.kt").read_text()
    methods = re.findall(r"external\s+fun\s+(\w+)\s*\(", kotlin)
    declared = {"Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_" + method for method in methods}
    assert len(methods) == len(set(methods)) == 15
    assert c_header == c_rust == set(MODULE.KAGEMUSHA_WALLET_C_EXPORTS)
    assert declared == {symbol for symbol in MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS if "KagemushaWalletNativeV1_" in symbol}
    assert jni_rust == set(MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS + MODULE.KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS)


def test_native_privacy_inventory_requires_authoritative_capability_validator() -> None:
    missing = "iroha_privacy_validate_exact12_capability_manifest_v1"
    assert len(MODULE.APPROVED_PRIVACY_C_EXPORTS) == 6
    assert missing in MODULE.REQUIRED_SYMBOLS["csharp"]
    symbols = [symbol for symbol in MODULE.APPROVED_PRIVACY_C_EXPORTS if symbol != missing]
    try:
        MODULE.validate_privacy_c_exports(symbols, require_exact=True)
    except MODULE.ArtifactContractError as error:
        assert str(error) == (
            "native bridge artifact is missing approved privacy C symbols: " + missing
        )
    else:
        raise AssertionError("native privacy artifact without capability validator was accepted")


def test_native_c_probe_rejects_missing_privacy_capability_validator() -> None:
    missing = "iroha_privacy_validate_exact12_capability_manifest_v1"
    library = types.SimpleNamespace(**{
        symbol: object() for symbol in MODULE.REQUIRED_SYMBOLS["csharp"]
        if symbol != missing
    })
    with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
        try:
            MODULE.probe_c_abi(Path("test-only-library"), MODULE.REQUIRED_SYMBOLS["csharp"])
        except MODULE.ArtifactContractError as error:
            assert str(error) == (
                "native C ABI artifact is missing required symbols: " + missing
            )
        else:
            raise AssertionError("C# native probe accepted missing capability validator")


def test_current_fee_jni_requires_the_kotlin_sdk_owner() -> None:
    required = set(MODULE.REQUIRED_SYMBOLS["c-jni"])
    assert {
        "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_" + method
        for method in ("nativeBridgeAbiVersion", "nativeIntentHashV1",
                       "nativeAssessmentMarkerV1", "nativeDecodeAssessmentV1")
    } <= required
    assert not any(symbol.startswith("Java_pg_") for symbol in required)
    assert not any("OfflineNativeCore" in symbol for symbol in required)


def test_current_host_jni_rejects_each_missing_shipping_endpoint() -> None:
    required = MODULE.REQUIRED_SYMBOLS["c-jni"]
    for missing in (*MODULE.CONFIDENTIAL_PROVER_JNI_EXPORTS, *MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS,
                    *MODULE.PRIVACY_BRIDGE_JNI_EXPORTS):
        assert required.count(missing) == 1
        library = types.SimpleNamespace(**{
            symbol: object() for symbol in required if symbol != missing
        })
        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
            try:
                MODULE.probe_c_abi(Path("test-only-library"), required)
            except MODULE.ArtifactContractError as error:
                assert str(error) == "native C ABI artifact is missing required symbols: " + missing
            else:
                raise AssertionError("native probe accepted missing JNI endpoint: " + missing)


def test_privacy_jni_inventory_matches_kotlin_loader_and_native_declarations() -> None:
    """Prevent ABI-compatible libraries from disabling the shared wallet loader."""
    prefix = "Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_"
    kotlin = (REPO_ROOT / "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyNativeBridge.kt").read_text()
    methods = re.findall(r"external\s+fun\s+(\w+)\s*\(", kotlin)
    assert len(methods) == len(set(methods))
    declared = {prefix + method for method in methods}
    native = "\n".join(path.read_text() for path in
                       (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni").rglob("*.rs"))
    exported = set(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+('
                             + prefix + r'\w+)\s*\(', native))
    derivation = (REPO_ROOT / "crates/connect_norito_bridge/src/confidential_note_ffi.rs").read_text()
    for invocation in re.findall(r'(?:revision|default|one_input|two_input|four_input|merkle_path)_export!\((.*?)\);',
                                 derivation, re.DOTALL):
        exported.update(re.findall(prefix + r'\w+', invocation))
    assert declared == exported == set(MODULE.PRIVACY_BRIDGE_JNI_EXPORTS)
    assert declared <= set(MODULE.REQUIRED_SYMBOLS["c-jni"])
    mobile = (REPO_ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text()
    inventory = mobile.split("REQUIRED_PRIVACY_JNI_SYMBOLS=(", 1)[1].split("\n)", 1)[0]
    assert tuple(re.findall(prefix + r'\w+', inventory)) == MODULE.PRIVACY_BRIDGE_JNI_EXPORTS


def test_native_c_probe_rejects_an_artifact_without_request_bound_settlement_verification() -> None:
    missing = "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1"
    library = types.SimpleNamespace(**{
        symbol: object() for symbol in MODULE.REQUIRED_SYMBOLS["c-jni"]
        if symbol != missing
    })
    with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
        try:
            MODULE.probe_c_abi(Path("test-only-library"), MODULE.REQUIRED_SYMBOLS["c-jni"])
        except MODULE.ArtifactContractError as error:
            assert str(error) == "native C ABI artifact is missing required symbols: " + missing
        else:
            raise AssertionError("native probe accepted missing request-bound verifier")


def test_retired_diagnostic_jni_exports_are_not_required_or_defined() -> None:
    required = set(MODULE.REQUIRED_SYMBOLS["c-jni"])
    native_sources = "\n".join(
        path.read_text() for path in
        (REPO_ROOT / "crates/connect_norito_bridge/src").rglob("*.rs")
    )
    for owner in (
        "Java_org_hyperledger_iroha_sdk_offline_KagemushaDeviceLifecycleBridgeV1_00024NativeEndpoint_",
        "Java_org_hyperledger_iroha_sdk_offline_KagemushaCoreCoordinatorJniV1_",
        "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetStateProofObservationJniV1_",
        "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetFinalizedMintObservationJniV1_",
        "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetValueAdmissionJniV1_",
        "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetValueCreditJniV1_",
        "Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_",
    ):
        assert not any(symbol.startswith(owner) for symbol in required), owner
        assert owner not in native_sources, owner
        retired = owner + "nativeContractV1"
        try:
            MODULE.validate_retired_protocol_symbols([retired], sdk="c-jni")
        except MODULE.ArtifactContractError as error:
            assert retired in str(error)
        else:
            raise AssertionError("retired JNI owner was accepted: " + owner)


def test_private_settlement_rejects_each_missing_kotlin_jni_endpoint() -> None:
    required = MODULE.REQUIRED_SYMBOLS["c-jni"]
    for method in ("nativeBridgeAbiVersion", "nativeVerifyCommitteeProofResponseV1",
                   "nativeVerifyAuditorCapsuleResponseWithRequestV1", "nativeVerifyAuditApprovalResponseV1"):
        missing = "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_" + method
        assert missing in required
        library = types.SimpleNamespace(**{
            symbol: object() for symbol in required if symbol != missing
        })
        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
            try:
                MODULE.probe_c_abi(Path("test-only-library"), required)
            except MODULE.ArtifactContractError as error:
                assert str(error) == "native C ABI artifact is missing required symbols: " + missing
            else:
                raise AssertionError("native probe accepted missing settlement endpoint")


def test_native_c_probe_rejects_each_missing_current_c_export() -> None:
    for sdk in ("c-jni", "csharp"):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        for missing in required:
            if missing.startswith("Java_"):
                continue
            assert required.count(missing) == 1
            library = types.SimpleNamespace(**{
                symbol: object() for symbol in required if symbol != missing
            })
            with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
                try:
                    MODULE.probe_c_abi(Path("test-only-library"), required)
                except MODULE.ArtifactContractError as error:
                    assert str(error) == "native C ABI artifact is missing required symbols: " + missing
                else:
                    raise AssertionError(f"missing C export was accepted: {sdk}: {missing}")


def test_current_required_c_symbols_are_declared_by_the_native_header() -> None:
    header = (
        REPO_ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
    ).read_text(encoding="utf-8")
    for sdk in ("c-jni", "csharp"):
        for symbol in MODULE.REQUIRED_SYMBOLS[sdk]:
            if not symbol.startswith("Java_"):
                assert re.search(rf"\b{re.escape(symbol)}\s*\(", header), symbol
    assert not any(symbol in header for symbol in RETIRED_KAGEMUSHA_C_SYMBOLS)


def test_retired_kagemusha_c_exports_are_rejected() -> None:
    for sdk in ("c-jni", "csharp"):
        for symbol in sorted(RETIRED_KAGEMUSHA_C_SYMBOLS):
            try:
                MODULE.validate_retired_protocol_symbols([symbol], sdk=sdk)
            except MODULE.ArtifactContractError as error:
                assert symbol in str(error)
            else:
                raise AssertionError("retired KAGEMUSHA export accepted: " + symbol)


def test_native_artifact_checker_has_no_retired_protocol_surface() -> None:
    retired = {
        "c-jni": {
            "connect_norito_validation_fee_hijiri_quote_request_v1",
            "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
            "connect_norito_kagemusha_device_response_authenticator_v1_verify",
            "Java_org_hyperledger_iroha_sdk_offline_KagemushaDeviceLifecycleBridgeV1_00024NativeEndpoint_nativeVerifyResponseAuthenticatorV1",
            "connect_norito_private_settlement_auditor_capsule_response_verify_v1",
            "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditorCapsuleResponseV1",
            "Java_org_hyperledger_iroha_android_client_AtomicPrivateSettlementNativeResponseVerifierV1_nativeVerifyAuditorCapsuleResponseV1",
            # The Google first-device sign-up key JNI owner retired at bridge ABI 29.
            "Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_reserve",
            "Java_org_hyperledger_iroha_sdk_crypto_keystore_NativeFirstDeviceAuthKeyJniV1_restore",
        },
        "csharp": {
            "connect_norito_validation_fee_hijiri_quote_request_v1",
            "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
            "connect_norito_kagemusha_device_response_authenticator_v1_verify",
            "connect_norito_private_settlement_auditor_capsule_response_verify_v1",
        },
        "node": {"privateSettlementVerifyAuditorCapsuleResponseV1", "validationFeeHijiriQuoteRequestV1", "validationFeeVerifyHijiriQuoteResponseV1"},
        "python": {"private_settlement_verify_auditor_capsule_response_v1", "validation_fee_hijiri_quote_request_v1", "validation_fee_verify_hijiri_quote_response_v1"},
    }
    for sdk, forbidden in retired.items():
        assert forbidden == set(MODULE.RETIRED_PROTOCOL_SYMBOLS[sdk])
        assert forbidden.isdisjoint(MODULE.REQUIRED_SYMBOLS[sdk])


def test_retired_protocol_symbol_inventory_is_rejected() -> None:
    for symbols in (
        ["connect_norito_private_settlement_auditor_capsule_response_verify_v1"],
        [RETIRED_KAGEMUSHA_C_PREFIX + "v1_payment_validate"],
        ["connect_norito_kagemusha_unrecognized_v1"],
        ["connect_norito_kagemusha_wallet_commit_v1"],
        ["Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_commit"],
    ):
        try:
            MODULE.validate_retired_protocol_symbols(symbols, sdk="csharp")
        except MODULE.ArtifactContractError as error:
            assert "retired protocol symbols" in str(error)
        else:
            raise AssertionError(f"retired symbols were accepted: {symbols}")


def test_command_verifier_never_accepts_previous_c_or_jni_alias() -> None:
    old_c = "connect_norito_kagemusha_device_response_authenticator_v1_verify"
    old_jni = (
        "Java_org_hyperledger_iroha_sdk_offline_"
        "KagemushaDeviceLifecycleBridgeV1_00024NativeEndpoint_"
        "nativeVerifyResponseAuthenticatorV1"
    )
    for sdk, aliases in (("c-jni", (old_c, old_jni)), ("csharp", (old_c,))):
        for alias in aliases:
            symbols = [*MODULE.REQUIRED_SYMBOLS[sdk], alias]
            try:
                MODULE.validate_retired_protocol_symbols(symbols, sdk=sdk)
            except MODULE.ArtifactContractError as error:
                assert alias in str(error)
            else:
                raise AssertionError(f"retired verifier alias was accepted: {sdk}: {alias}")


def test_retired_top_up_binding_is_rejected_for_c_and_kotlin_exports() -> None:
    retired = ("connect_norito_kagemusha_top_up_signed_request_validate_v1",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaTopUpSubmissionJniV1_nativeBridgeAbiVersion",
        "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaTopUpSubmissionJniV1_nativeValidate")
    required = MODULE.REQUIRED_SYMBOLS["c-jni"]
    for symbol in retired:
        assert symbol not in required
        try:
            MODULE.validate_retired_protocol_symbols([*required, symbol], sdk="c-jni")
        except MODULE.ArtifactContractError as error:
            assert symbol in str(error)
        else:
            raise AssertionError("retired top-up binding accepted: " + symbol)


def test_python_probe_disables_bytecode_in_its_actual_isolated_child(tmp_path: Path) -> None:
    """An inert probe exercises child flags without claiming native qualification."""
    artifact = tmp_path / "probe_fixture.py"
    artifact.write_text(
        "import sys\n"
        "assert sys.flags.isolated == 1\n"
        "assert sys.dont_write_bytecode\n"
        "def connect_norito_bridge_abi_version():\n"
        "    return 28\n",
        encoding="utf-8",
    )
    assert MODULE.probe_python_abi(
        artifact, ("connect_norito_bridge_abi_version",)
    ) == 28
    assert not (tmp_path / "__pycache__").exists()


def test_retired_abi23_privacy_export_marker_is_rejected() -> None:
    marker = "iroha_privacy_abi23_compiled_profile_catalog_v1"
    assert MODULE.STALE_PRIVACY_ABI_MARKER_RE.search(marker)
    try:
        MODULE.validate_privacy_c_exports(
            [marker, *MODULE.APPROVED_PRIVACY_C_EXPORTS], require_exact=False
        )
    except MODULE.ArtifactContractError as error:
        assert "stale privacy/bridge ABI marker" in str(error)
    else:
        raise AssertionError("retired ABI-23 privacy export marker was accepted")


def test_retired_abi26_privacy_export_markers_are_rejected() -> None:
    for marker in (
        "iroha_privacy_abi26_compiled_profile_catalog_v1",
        "iroha_privacy_compiled_profile_catalog_v26",
    ):
        assert MODULE.STALE_PRIVACY_ABI_MARKER_RE.search(marker)
        try:
            MODULE.validate_privacy_c_exports(
                [marker, *MODULE.APPROVED_PRIVACY_C_EXPORTS], require_exact=False
            )
        except MODULE.ArtifactContractError as error:
            assert "stale privacy/bridge ABI marker" in str(error)
        else:
            raise AssertionError("retired ABI-26 privacy export marker was accepted")


def test_retired_abi23_manifest_and_schema_are_rejected() -> None:
    manifest = {
        "artifact_sha256": "a" * 64,
        "artifact_size": 1,
        "bridge_abi_version": MODULE.REQUIRED_BRIDGE_ABI_VERSION,
        "privacy_c_exports": [],
        "privacy_c_exports_inspected": False,
        "required_symbols": list(MODULE.REQUIRED_SYMBOLS["python"]),
        "schema": MODULE.SCHEMA,
        "sdk": "python",
        "source_commit": "b" * 40,
        "source_tree_clean": True,
        "target": "aarch64-apple-darwin",
        "workspace_source_manifest_sha256": "c" * 64,
    }
    MODULE.validate_manifest(manifest)
    for field, retired, expected in (
        ("bridge_abi_version", 23, "must be exactly 30"),
        ("bridge_abi_version", 24, "must be exactly 30"),
        ("bridge_abi_version", 25, "must be exactly 30"),
        ("bridge_abi_version", 26, "must be exactly 30"),
        ("bridge_abi_version", 27, "must be exactly 30"),
        ("bridge_abi_version", 28, "must be exactly 30"),
        ("bridge_abi_version", 29, "must be exactly 30"),
        ("schema", "iroha.native-sdk-abi29-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi28-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi27-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi26-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi25-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi24-artifact.v1", "schema is unsupported"),
        ("schema", "iroha.native-sdk-abi23-artifact.v1", "schema is unsupported"),
    ):
        stale = {**manifest, field: retired}
        try:
            MODULE.validate_manifest(stale)
        except MODULE.ArtifactContractError as error:
            assert expected in str(error)
        else:
            raise AssertionError(f"retired {field} was accepted")


def test_wallet_prover_inventory_covers_native_owners_and_consumable_jobs() -> None:
    """A rebuilt mobile artifact must expose the complete owner/job contract."""
    assert len(MODULE.CONFIDENTIAL_PROVER_C_EXPORTS) == 10
    assert len(MODULE.CONFIDENTIAL_PROVER_JNI_EXPORTS) == 10
    header = (REPO_ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h").read_text()
    owner = (REPO_ROOT / "crates/connect_norito_bridge/src/confidential_prover_ffi.rs").read_text()
    jni = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/confidential_prover.rs").read_text()
    required = set(MODULE.REQUIRED_SYMBOLS["c-jni"])
    for symbol in MODULE.CONFIDENTIAL_PROVER_C_EXPORTS:
        assert symbol in required
        assert re.search(r"\b" + symbol + r"\s*\(", header)
        assert re.search(r"\bfn\s+" + symbol + r"\s*\(", owner)
    for symbol in MODULE.CONFIDENTIAL_PROVER_JNI_EXPORTS:
        assert symbol in required
        assert re.search(r"\bfn\s+" + symbol + r"\s*\(", jni)
    assert "iroha_android_privacy_ConfidentialProverNative" not in jni


def test_csharp_wallet_inventory_matches_actual_native_imports() -> None:
    """Every managed wallet P/Invoke is a mandatory packaged C# export."""
    source = (REPO_ROOT / "csharp/src/Hyperledger.Iroha.Sdk/Privacy/ConfidentialWalletNative.cs").read_text()
    imports = set(re.findall(r'EntryPoint = "([^"]+)"', source))
    assert set(MODULE.CONFIDENTIAL_PROVER_C_EXPORTS) <= imports
    assert len(imports) == 18
    assert imports <= set(MODULE.REQUIRED_SYMBOLS["csharp"])
    for missing in sorted(imports):
        library = types.SimpleNamespace(**{
            symbol: object() for symbol in MODULE.REQUIRED_SYMBOLS["csharp"]
            if symbol != missing
        })
        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
            try:
                MODULE.probe_c_abi(Path("test-only-library"), MODULE.REQUIRED_SYMBOLS["csharp"])
            except MODULE.ArtifactContractError as error:
                assert "missing required symbols" in str(error)
                assert missing in str(error)
            else:
                raise AssertionError(f"C# artifact without {missing} was accepted")


def test_retired_abi24_privacy_export_marker_is_rejected() -> None:
    """A scalar-anchor bridge marker cannot qualify the checkpoint ABI."""
    marker = "iroha_privacy_abi24_compiled_profile_catalog_v1"
    assert MODULE.STALE_PRIVACY_ABI_MARKER_RE.search(marker)
    try:
        MODULE.validate_privacy_c_exports(
            [marker, *MODULE.APPROVED_PRIVACY_C_EXPORTS], require_exact=False
        )
    except MODULE.ArtifactContractError as error:
        assert "stale privacy/bridge ABI marker" in str(error)
    else:
        raise AssertionError("retired ABI-24 privacy export marker was accepted")


def test_first_release_requires_only_current_kotlin_jni_namespace() -> None:
    required = MODULE.REQUIRED_SYMBOLS["c-jni"]
    assert not any(symbol.startswith("Java_org_hyperledger_iroha_android_") for symbol in required)
    for method in ("nativeBridgeAbiVersion", "nativeVerifyCommitteeProofResponseV1",
                   "nativeVerifyAuditorCapsuleResponseWithRequestV1", "nativeVerifyAuditApprovalResponseV1"):
        assert "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_" + method in required
        legacy = "Java_org_hyperledger_iroha_android_client_AtomicPrivateSettlementNativeResponseVerifierV1_" + method
        try:
            MODULE.validate_retired_protocol_symbols([*required, legacy], sdk="c-jni")
        except MODULE.ArtifactContractError as error:
            assert "retired protocol symbols" in str(error)
        else:
            raise AssertionError("obsolete Java namespace export was accepted")
    for legacy in ("Java_org_hyperledger_iroha_android_crypto_NativeSignerBridge_nativeSignDetached",
                   "Java_org_hyperledger_iroha_android_validationfee_ValidationFeeHijiriQuoteBridge_nativeEncodeRequestV1",
                   "Java_org_hyperledger_iroha_android_any_Unknown_nativeMethod"):
        try:
            MODULE.validate_retired_protocol_symbols([legacy], sdk="c-jni")
        except MODULE.ArtifactContractError:
            pass
        else:
            raise AssertionError("foreign legacy namespace escaped current ownership")


def test_native_domain_admission_is_required_for_both_c_deliverables() -> None:
    missing = "connect_norito_domain_id_validate_v1"
    for sdk in ("c-jni", "csharp"):
        assert MODULE.REQUIRED_SYMBOLS[sdk].count(missing) == 1
        library = types.SimpleNamespace(**{
            symbol: object() for symbol in MODULE.REQUIRED_SYMBOLS[sdk]
            if symbol != missing
        })
        with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
            try:
                MODULE.probe_c_abi(Path("test-only-library"), MODULE.REQUIRED_SYMBOLS[sdk])
            except MODULE.ArtifactContractError as error:
                assert str(error) == "native C ABI artifact is missing required symbols: " + missing
            else:
                raise AssertionError("native probe accepted missing canonical domain admission")


def test_current_fee_artifact_contract_requires_real_native_owners_and_rejects_retired_quote() -> None:
    current = (
        "connect_norito_retail_fee_intent_hash_v1",
        "connect_norito_retail_fee_assessment_marker_v1",
        "connect_norito_retail_fee_assessment_decode_v1",
        "connect_norito_validation_fee_current_policy_proof_request_v1",
        "connect_norito_validation_fee_current_policy_proof_verify_v1",
    )
    for sdk in ("c-jni", "csharp"):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        for name in current:
            assert required.count(name) == 1
            library = types.SimpleNamespace(**{symbol: object() for symbol in required if symbol != name})
            with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
                try:
                    MODULE.probe_c_abi(Path("DATA-only-missing-export-negative"), required)
                except MODULE.ArtifactContractError as error:
                    assert str(error) == "native C ABI artifact is missing required symbols: " + name
                else:
                    raise AssertionError("missing current fee owner was accepted")
    for method in ("nativeBridgeAbiVersion", "nativeIntentHashV1", "nativeAssessmentMarkerV1", "nativeDecodeAssessmentV1"):
        assert "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_" + method in MODULE.REQUIRED_SYMBOLS["c-jni"]
    assert "validationFeeCurrentPolicyProofRequestV1" in MODULE.REQUIRED_SYMBOLS["node"]
    assert "validationFeeVerifyCurrentPolicyProofV1" in MODULE.REQUIRED_SYMBOLS["node"]
    for sdk in ("c-jni", "csharp", "node", "python"):
        for symbol in MODULE.RETIRED_PROTOCOL_SYMBOLS[sdk]:
            try:
                MODULE.validate_retired_protocol_symbols([*MODULE.REQUIRED_SYMBOLS[sdk], symbol], sdk=sdk)
            except MODULE.ArtifactContractError:
                pass
            else:
                raise AssertionError("retired native quote symbol was accepted: " + symbol)

def test_current_inventory_is_exact_for_posix_and_windows() -> None:
    """Execute the real inventory expression with each host name, without a DLL."""
    syntax = ast.parse(MODULE_PATH.read_text())
    declaration = next(node for node in syntax.body
                       if isinstance(node, ast.AnnAssign)
                       and isinstance(node.target, ast.Name)
                       and node.target.id == "REQUIRED_SYMBOLS")
    for host in ("posix", "nt"):
        namespace = dict(vars(MODULE))
        namespace["os"] = types.SimpleNamespace(name=host)
        expression = compile(ast.Expression(declaration.value), str(MODULE_PATH), "eval")
        inventories = eval(expression, namespace)
        for sdk in ("c-jni", "csharp"):
            assert inventories[sdk] == MODULE.REQUIRED_SYMBOLS[sdk]
            assert len(inventories[sdk]) == len(set(inventories[sdk]))
            assert "connect_norito_domain_id_validate_v1" in inventories[sdk]
            expected = MODULE.KAGEMUSHA_WALLET_C_EXPORTS + (
                MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS + MODULE.KAGEMUSHA_LOAD_ORIGINAL_JNI_EXPORTS if sdk == "c-jni" else ()
            )
            assert tuple(symbol for symbol in inventories[sdk] if "kagemusha" in symbol.lower()) == expected


def test_private_settlement_rejects_each_missing_actual_endpoint() -> None:
    """Synthetic symbol output tests refusal; it cannot qualify a native library."""
    c_symbols = (
        "connect_norito_private_settlement_committee_proof_response_verify_v1",
        "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
        "connect_norito_private_settlement_audit_approval_response_verify_v1",
    )
    jni_methods = (
        "nativeBridgeAbiVersion", "nativeVerifyCommitteeProofResponseV1",
        "nativeVerifyAuditorCapsuleResponseWithRequestV1", "nativeVerifyAuditApprovalResponseV1",
    )
    for sdk in ("c-jni", "csharp"):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        endpoints = c_symbols + (tuple(
            "Java_org_hyperledger_iroha_sdk_client_AtomicPrivateSettlementNativeResponseVerifierV1_" + method
            for method in jni_methods
        ) if sdk == "c-jni" else ())
        for missing in endpoints:
            assert required.count(missing) == 1
            library = types.SimpleNamespace(**{
                symbol: object() for symbol in required if symbol != missing
            })
            with mock.patch.object(MODULE.ctypes, "CDLL", return_value=library):
                try:
                    MODULE.probe_c_abi(Path("test-only-library"), required)
                except MODULE.ArtifactContractError as error:
                    assert str(error) == "native C ABI artifact is missing required symbols: " + missing
                else:
                    raise AssertionError("endpoint absence accepted: " + sdk + ": " + missing)


def test_current_fee_jni_inventory_matches_shipping_consumer_and_definitions() -> None:
    """Current Kotlin declarations and native definitions share one exact owner."""
    consumer = (REPO_ROOT / "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/validationfee/RetailFeeAssessmentBridge.kt").read_text()
    declared = set(re.findall(r"@JvmStatic\s+private\s+external\s+fun\s+(native\w+)\s*\(", consumer))
    assert declared == {"nativeBridgeAbiVersion", "nativeIntentHashV1",
                        "nativeAssessmentMarkerV1", "nativeDecodeAssessmentV1"}
    owner = "Java_org_hyperledger_iroha_sdk_validationfee_RetailFeeAssessmentBridge_"
    selected = tuple(symbol for symbol in MODULE.REQUIRED_SYMBOLS["c-jni"]
                     if symbol.startswith(owner))
    assert len(selected) == len(set(selected)) == len(declared)
    assert set(selected) == {owner + method for method in declared}
    source = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/part_1.rs").read_text()
    for method in declared:
        assert re.search(r'pub\s+unsafe\s+extern\s+"system"\s+fn\s+' + owner + method + r'\b', source)


def test_current_required_header_declarations_have_no_platform_exclusions() -> None:
    """Mandatory C declarations are available on every supported host platform."""
    header = (REPO_ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h").read_text()
    required = {symbol for sdk in ("c-jni", "csharp")
                for symbol in MODULE.REQUIRED_SYMBOLS[sdk] if not symbol.startswith("Java_")}
    conditions = []
    declarations = set()
    for line in header.splitlines():
        directive = line.strip()
        if re.match(r"#\s*(?:if|ifdef|ifndef)\b", directive):
            conditions.append(directive)
        elif re.match(r"#\s*endif\b", directive):
            assert conditions
            conditions.pop()
        elif re.match(r"#\s*(?:else|elif)\b", directive):
            assert conditions
            conditions[-1] = conditions[-1] + " " + directive
        names = set(re.findall(r"\b([a-z][a-z0-9_]+)\s*\(", line)) & required
        if names:
            assert not any(re.search(r"_WIN32|__unix__|__APPLE__|__ANDROID__", condition)
                           for condition in conditions), (names, conditions)
            declarations.update(names)
    assert declarations == required


def test_required_current_jni_exports_include_windows_hosts() -> None:
    """Required current JNI definitions share the supported host platform gate."""
    bridge = REPO_ROOT / "crates/connect_norito_bridge/src"
    platform = (bridge / "platform_jni.rs").read_text()
    load_original = (bridge / "kagemusha_wallet_load_original.rs").read_text()
    gates = [
        re.search(r'#!\[cfg\((.*?)\)\]', platform, re.DOTALL),
        re.search(
            r'#\[cfg\((.*?)\)\]\s*'
            r'#\[path = "kagemusha_wallet_load_original/jni.rs"\]\s*mod jni;',
            load_original,
            re.DOTALL,
        ),
    ]
    for relative in ("kagemusha_wallet_ffi/installed.rs",):
        source = (bridge / relative).read_text()
        gates.append(re.search(r'#\[cfg\((.*?)\)\]\s*mod jni;', source, re.DOTALL))
    derivation = (bridge / "confidential_note_ffi.rs").read_text()
    gates.append(re.search(r'#\[cfg\((.*?)\)\]\s*mod jni_exports\s*\{', derivation, re.DOTALL))
    for declaration in gates:
        assert declaration is not None
        assert 'windows' in declaration.group(1)
        for target in ("android", "linux", "macos"):
            assert f'target_os = "{target}"' in declaration.group(1)
    sources = "\n".join(path.read_text() for path in
                         (bridge / "platform_jni").rglob("*.rs"))
    sources += "\n" + (bridge / "kagemusha_wallet_load_original/jni.rs").read_text()
    for relative in ("kagemusha_wallet_ffi/installed/jni.rs",):
        sources += "\n" + (bridge / relative).read_text()
    macro_symbols = set()
    for invocation in re.findall(r'(?:revision|default|one_input|two_input|four_input|merkle_path)_export!\((.*?)\);',
                                 derivation, re.DOTALL):
        macro_symbols.update(re.findall(r'Java_\w+', invocation))
    for symbol in MODULE.REQUIRED_SYMBOLS["c-jni"]:
        if symbol.startswith("Java_"):
            assert symbol in macro_symbols or re.search(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+' + re.escape(symbol) + r'\b', sources), symbol


def test_required_prover_jni_module_is_portable_and_retired_startup_is_absent() -> None:
    """Current portable JNI modules remain declared without a Unix-only gate."""
    source = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni.rs").read_text()
    declaration = "mod confidential_prover;"
    assert declaration in source
    assert re.search(r'#\[cfg\([^\]]+\)\]\s*' + re.escape(declaration), source) is None
    assert "mod kagemusha_testnet_native_startup;" not in source
    wrappers = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/confidential_prover.rs").read_text()
    for symbol in MODULE.CONFIDENTIAL_PROVER_JNI_EXPORTS:
        assert symbol in MODULE.REQUIRED_SYMBOLS["c-jni"]
        assert re.search(r'pub\s+extern\s+"system"\s+fn\s+' + re.escape(symbol) + r'\b', wrappers)


def test_current_wallet_jni_inventory_matches_shipping_consumer_and_definitions() -> None:
    """Wallet artifacts require the exact JNI surface exposed to Kotlin."""
    declared_exports = set()
    defined_exports = []
    for filename, owner, methods, relative in (
        ("KagemushaWalletV1.kt", "KagemushaWalletNativeV1", {"revision", "openBegin", "openFinish", "openCancel", "close", "activity", "call", "setup", "enrollment", "enrollmentRefusal", "execute", "review", "executeReviewed", "discardReview", "snapshot"}, "platform_jni/kagemusha_wallet_advance.rs"),
        ("KagemushaWalletInstalledRuntimeV1.kt", "KagemushaWalletInstalledRuntimeNativeV1", {"beginInstallation", "registerInstallation", "closeInstallation", "relocateRegistrationSource"}, "kagemusha_wallet_ffi/installed/jni.rs"),
        ("KagemushaWalletOutputV1.kt", "KagemushaWalletObservationNativeV1", {"observe"}, "platform_jni/kagemusha_wallet_observation.rs"),
    ):
        consumer = (REPO_ROOT / "kotlin/kagemusha-wallet-android/src/main/java/org/hyperledger/iroha/sdk/offline/wallet" / filename).read_text()
        declared = re.findall(r"@JvmStatic\s+external\s+fun\s+(\w+)\s*\(", consumer)
        assert len(declared) == len(set(declared)) == len(methods)
        assert set(declared) == methods
        declared_exports.update("Java_org_hyperledger_iroha_sdk_offline_wallet_" + owner + "_" + method for method in declared)
        source = (REPO_ROOT / "crates/connect_norito_bridge/src" / relative).read_text()
        defined_exports.extend(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+(Java_\w+)\s*\(', source))
    source = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/kagemusha_wallet_review.rs").read_text()
    defined_exports.extend(re.findall(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+(Java_\w+)\s*\(', source))
    expected = MODULE.KAGEMUSHA_WALLET_JNI_EXPORTS
    assert len(expected) == len(set(expected)) == len(declared_exports) == 20
    assert set(expected) == declared_exports
    assert len(defined_exports) == len(set(defined_exports)) == len(expected)
    assert set(defined_exports) == set(expected)
    checker = (REPO_ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text()
    inventory = checker.split("REQUIRED_WALLET_JNI_SYMBOLS=(\n", 1)[1].split("\n)", 1)[0]
    assert tuple(inventory.split()) == expected


def test_swift_retained_bridge_exports_have_one_canonical_header_owner() -> None:
    """Retained bridge exports consume one canonical C declaration without substitutes."""
    from collections import Counter

    def c_tokens(source: str) -> list[str]:
        """Tokenize the bounded C inventory after splicing, ignoring lexical decoys."""
        source = re.sub(r"\\\r?\n", "", source)
        identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+")
        tokens = []
        cursor = 0
        line_start = True
        while cursor < len(source):
            character = source[cursor]
            if character.isspace():
                if character in "\r\n":
                    line_start = True
                cursor += 1
                continue
            if source.startswith("//", cursor):
                end = source.find("\n", cursor + 2)
                cursor = len(source) if end == -1 else end
                continue
            if source.startswith("/*", cursor):
                end = source.find("*/", cursor + 2)
                assert end != -1, "unterminated C comment"
                if "\n" in source[cursor:end + 2]:
                    line_start = True
                cursor = end + 2
                continue
            if line_start and character == "#":
                end = source.find("\n", cursor + 1)
                cursor = len(source) if end == -1 else end
                continue
            if character in "\"'":
                start = cursor
                cursor += 1
                while cursor < len(source) and source[cursor] != character:
                    cursor += 2 if source[cursor] == "\\" else 1
                assert cursor < len(source), "unterminated C literal"
                cursor += 1
                if source[start:cursor] == '"C"':
                    tokens.append("@C-linkage")
                line_start = False
                continue
            match = identifier.match(source, cursor)
            if match:
                tokens.append(match.group())
                cursor = match.end()
            else:
                tokens.append(character)
                cursor += 1
            line_start = False
        return tokens

    def prototype_counts(source: str) -> Counter:
        """Count outer declarators at semicolons, excluding typedefs and bodies."""
        counts = Counter()
        statement = []
        linkage_depth = skipped_depth = parentheses = brackets = 0
        for token in c_tokens(source):
            if skipped_depth:
                skipped_depth += (token == "{") - (token == "}")
                continue
            if token == "{":
                if statement == ["extern", "@C-linkage"]:
                    linkage_depth += 1
                else:
                    skipped_depth = 1
                statement = []
                parentheses = brackets = 0
                continue
            if token == "}":
                assert linkage_depth > 0, "unmatched C linkage brace"
                linkage_depth -= 1
                statement = []
                continue
            if token == ";" and parentheses == brackets == 0:
                names = []
                if "typedef" not in statement:
                    declarators = []
                    declarator = []
                    paren_depth = bracket_depth = 0
                    for item in statement:
                        if item == "," and paren_depth == bracket_depth == 0:
                            declarators.append(declarator)
                            declarator = []
                        else:
                            declarator.append(item)
                        paren_depth += (item == "(") - (item == ")")
                        bracket_depth += (item == "[") - (item == "]")
                    assert paren_depth == bracket_depth == 0
                    declarators.append(declarator)
                    for ordinal, declarator in enumerate(declarators):
                        depths = []
                        paren_depth = bracket_depth = 0
                        initialized = False
                        for item in declarator:
                            depths.append((paren_depth, bracket_depth))
                            if item == "=" and paren_depth == bracket_depth == 0:
                                initialized = True
                            paren_depth += (item == "(") - (item == ")")
                            bracket_depth += (item == "[") - (item == "]")
                        assert paren_depth == bracket_depth == 0
                        if initialized:
                            continue
                        for index, item in enumerate(declarator):
                            if not item.startswith("connect_norito_"):
                                continue
                            left = index
                            while left > 0 and declarator[left - 1] == "(":
                                left -= 1
                            right = index + 1
                            wrappers = index - left
                            if declarator[right:right + wrappers] != [")"] * wrappers:
                                continue
                            right += wrappers
                            if (
                                (left > 0 or ordinal > 0)
                                and depths[left] == (0, 0)
                                and declarator[right:right + 1] == ["("]
                            ):
                                names.append(item)
                counts.update(names)
                statement = []
                continue
            statement.append(token)
            parentheses += (token == "(") - (token == ")")
            brackets += (token == "[") - (token == "]")
            assert parentheses >= 0 and brackets >= 0
        assert linkage_depth == skipped_depth == parentheses == brackets == 0
        return counts

    def retained_exports(source: str) -> set[str]:
        """Read references only from the unique outer required_exports initializer."""
        tokens = c_tokens(source)
        initializers = []
        braces = parentheses = brackets = 0
        for index, token in enumerate(tokens):
            if token == "required_exports" and braces == parentheses == brackets == 0:
                cursor = index + 1
                while cursor < len(tokens) and tokens[cursor] not in {";", "=", "{", "}"}:
                    cursor += 1
                if tokens[cursor:cursor + 2] == ["=", "{"]:
                    start = cursor + 2
                    cursor = start
                    depth = 1
                    while cursor < len(tokens) and depth:
                        depth += (tokens[cursor] == "{") - (tokens[cursor] == "}")
                        cursor += 1
                    assert depth == 0 and tokens[cursor:cursor + 1] == [";"]
                    initializers.append({
                        item for item in tokens[start:cursor - 1]
                        if item.startswith("connect_norito_")
                    })
            braces += (token == "{") - (token == "}")
            parentheses += (token == "(") - (token == ")")
            brackets += (token == "[") - (token == "]")
            assert braces >= 0 and parentheses >= 0 and brackets >= 0
        assert braces == parentheses == brackets == 0
        assert len(initializers) == 1, "required_exports must have one outer initializer"
        return initializers[0]

    # Controls exercise lexical and declaration syntax independently of current files.
    first, second = "connect_norito_first", "connect_norito_second"
    assert prototype_counts(f"int32_t\n{first}\n(void);") == Counter({first: 1})
    assert prototype_counts(f"int32_t/* separator */{first}(void);") == Counter({first: 1})
    assert prototype_counts(
        f"extern \"C\" {{ int32_t {first}(void); int32_t {second}(void); }}"
    ) == Counter({first: 1, second: 1})
    assert prototype_counts(
        f"int32_t {first}(void);int32_t {first}(void);"
    ) == Counter({first: 2})
    assert prototype_counts(
        f"int32_t {first}(void), {second}(void);"
    ) == Counter({first: 1, second: 1})
    assert prototype_counts(f"int32_t ({first})(void);") == Counter({first: 1})
    assert prototype_counts(f"int32_t ((({first})))(void);") == Counter({first: 1})
    assert prototype_counts(
        f"int32_t {first}(void), ordinary = 42;"
    ) == Counter({first: 1})
    assert prototype_counts(
        f"int32_t ordinary = 42, ({first})(void), (({second}))(void);"
    ) == Counter({first: 1, second: 1})
    assert prototype_counts(
        f"int32_t (*({first}))(void), (*(({second})))(void);"
    ) == Counter()
    assert prototype_counts(f"/* int32_t {first}(void); */") == Counter()
    assert prototype_counts(f"// int32_t {first}(void);\n") == Counter()
    assert prototype_counts(
        f'const char *text = "int32_t {first}(void);"; char quote = \'"\' ;'
    ) == Counter()
    assert prototype_counts(
        f'const char *text = "escaped \\" int32_t {first}(void);";'
    ) == Counter()
    assert prototype_counts(
        f"#define FAKE int32_t \\\n{first}(void);\n"
    ) == Counter()
    assert prototype_counts(
        f"/* directive prefix */ #define FAKE int32_t {first}(void);\n"
    ) == Counter()
    assert prototype_counts(
        f"// continued comment \\\nint32_t {first}(void);\n"
    ) == Counter()
    assert prototype_counts(
        f"void function(void) {{ {first}(); }} int32_t value = {first}();"
    ) == Counter()
    assert prototype_counts(
        f"typedef int32_t {first}(void); "
        f"typedef struct {{ int32_t (*{first})(void); }} Record;"
    ) == Counter()
    assert prototype_counts(
        f"void {first}(void (*{second})(void));"
    ) == Counter({first: 1})
    assert prototype_counts(
        f"int32_t\n/* local substitute */\n{first}\n(\nvoid\n);\n"
    ) == Counter({first: 1})
    assert c_tokens("connect_norito_/**/first") == ["connect_norito_", "first"]

    initializer = (
        "static NoritoBridgeExportReference required_exports[] = { "
        f"(NoritoBridgeExportReference){first}, "
        f"(NoritoBridgeExportReference)&{second}, "
        f"(NoritoBridgeExportReference)((&{first})), "
        f"((NoritoBridgeExportReference)({second})), "
        '/* connect_norito_comment */ "connect_norito_string", '
        "'x' };"
    )
    assert retained_exports(initializer) == {first, second}
    assert retained_exports(
        f"int32_t connect_norito_outside(void); "
        f"void function(void) {{ void *required_exports[] = {{connect_norito_local}}; }}"
        f'const char *text = "required_exports[] = {{connect_norito_literal}};";'
        f"// required_exports[] = {{connect_norito_comment}};\n"
        + initializer
    ) == {first, second}
    assert retained_exports(
        "#define FAKE required_exports[] = { \\\nconnect_norito_macro };\n"
        + initializer
    ) == {first, second}

    header = (
        REPO_ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
    ).read_text(encoding="utf-8")
    retention = (
        REPO_ROOT / "IrohaSwift/Sources/NoritoBridgeRetention/NoritoBridgeRetention.c"
    ).read_text(encoding="utf-8")
    retained = retained_exports(retention)
    assert {
        "connect_norito_decode_control_approve_sig_alg",
        "connect_norito_encode_envelope_sign_result_ok_with_alg",
        "connect_norito_kagemusha_wallet_revision_v1",
    } <= retained
    declarations = prototype_counts(header)
    for symbol in retained:
        assert declarations[symbol] == 1, symbol
    assert not prototype_counts(retention), "local bridge declarations substitute for the owner"
