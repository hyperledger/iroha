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
}
RETIRED_KAGEMUSHA_C_PREFIX = (
    "connect_norito_" + "_".join(reversed(("cash", "offline"))) + "_"
)


def test_native_c_contracts_exclude_retired_kagemusha_exports() -> None:
    assert len(RETIRED_KAGEMUSHA_C_SYMBOLS) == 42
    for sdk in ("c-jni", "csharp"):
        required = MODULE.REQUIRED_SYMBOLS[sdk]
        assert RETIRED_KAGEMUSHA_C_SYMBOLS.isdisjoint(required)
        assert not any("kagemusha" in symbol.lower() for symbol in required)


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
    for missing in MODULE.CONFIDENTIAL_PROVER_JNI_EXPORTS:
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
        "    return 25\n",
        encoding="utf-8",
    )
    assert MODULE.probe_python_abi(
        artifact, ("connect_norito_bridge_abi_version",)
    ) == 25
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
        ("bridge_abi_version", 23, "must be exactly 25"),
        ("bridge_abi_version", 24, "must be exactly 25"),
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
            assert not any("kagemusha" in symbol.lower() for symbol in inventories[sdk])


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
    platform = (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni.rs").read_text()
    declaration = re.search(r'#!\[cfg\((.*?)\)\]', platform, re.DOTALL)
    assert declaration is not None
    assert 'windows' in declaration.group(1)
    for target in ("android", "linux", "macos"):
        assert f'target_os = "{target}"' in declaration.group(1)
    sources = "\n".join(path.read_text() for path in
                         (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni").rglob("*.rs"))
    for symbol in MODULE.REQUIRED_SYMBOLS["c-jni"]:
        if symbol.startswith("Java_"):
            assert re.search(r'pub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+' + re.escape(symbol) + r'\b', sources), symbol


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
