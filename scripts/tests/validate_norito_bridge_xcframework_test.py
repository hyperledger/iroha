#!/usr/bin/env python3
"""Tests for the shared strict NoritoBridge inventory validator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ROOT
SCRIPT = ROOT / "scripts/validate_norito_bridge_xcframework.py"
SPEC = importlib.util.spec_from_file_location("validate_norito_bridge_xcframework", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class StrictNoritoBridgeValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # Model the reviewed source independently of the host checkout. The
        # selected external graph and artifacts remain siblings even when tests
        # run under checkout-local TMPDIR; no release path guard is mocked.
        source_root = Path(self.temporary.name).resolve() / "reviewed-source"
        for relative in (
            "scripts/norito_bridge_source_seal.py",
            "scripts/run_mobile_hermetic_command.py",
            "scripts/build_norito_xcframework.sh",
            "scripts/check_mobile_sdk_artifacts.sh",
            "crates/connect_norito_bridge/include/connect_norito_bridge.h",
            "crates/connect_norito_bridge/include/NoritoBridge.h",
            "crates/soranet_pq/include/soranet_pq.h",
            "crates/connect_norito_bridge/module.modulemap.template",
            "crates/connect_norito_bridge/src/lib.rs",
            "crates/iroha_data_model/src/privacy/protocol.rs",
        ):
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPOSITORY_ROOT / relative, destination)
        graph = b'version = 4\n\n[[package]]\nname = "validator-fixture"\nversion = "0.0.0"\n'
        (source_root / "Cargo.lock").write_bytes(graph)
        graph_directory = Path(self.temporary.name).resolve() / "graph"
        graph_directory.mkdir()
        self.lockfile = graph_directory / "Cargo.lock"
        self.lockfile.write_bytes(graph)
        self.lockfile.chmod(0o400)
        graph_owner = source_root / "ci/privacy_sdk_cargo_lockfile.sh"
        graph_owner.parent.mkdir()
        graph_owner.write_text(
            'readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"'
            + hashlib.sha256(graph).hexdigest() + '"\n', encoding="utf-8",
        )
        source_context = mock.patch.object(sys.modules[__name__], "ROOT", source_root)
        source_context.start()
        self.addCleanup(source_context.stop)
        self.artifact_root = Path(self.temporary.name).resolve() / "artifact"
        self.xcframework = self.artifact_root / "NoritoBridge.xcframework"
        self.xcframework.mkdir(parents=True)
        (self.xcframework / ".privacy-production-enabled").touch()
        self.hashes: dict[str, str] = {}
        header = (
            ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
        ).read_bytes()
        libraries = []
        for identifier, expected in validator.EXPECTED_SLICES.items():
            headers = self.xcframework / identifier / "Headers"
            headers.mkdir(parents=True)
            binary = self.xcframework / identifier / validator.LIBRARY_NAME
            binary.write_bytes((identifier + "\n").encode("ascii"))
            self.hashes[identifier] = hashlib.sha256(binary.read_bytes()).hexdigest()
            (headers / "NoritoBridge.h").write_bytes(
                (
                    ROOT
                    / "crates/connect_norito_bridge/include/NoritoBridge.h"
                ).read_bytes()
            )
            (headers / "connect_norito_bridge.h").write_bytes(header)
            (headers / "module.modulemap").write_bytes(
                (
                    ROOT
                    / "crates/connect_norito_bridge/module.modulemap.template"
                ).read_bytes()
            )
            library = {
                "LibraryIdentifier": identifier,
                "LibraryPath": validator.LIBRARY_NAME,
                "HeadersPath": "Headers",
                "SupportedArchitectures": expected["architectures"],
                "SupportedPlatform": expected["platform"],
            }
            if expected["variant"] is not None:
                library["SupportedPlatformVariant"] = expected["variant"]
            libraries.append(library)
        with (self.xcframework / "Info.plist").open("wb") as output:
            plistlib.dump(
                {
                    "AvailableLibraries": libraries,
                    "CFBundlePackageType": "XFWK",
                    "XCFrameworkFormatVersion": "1.0",
                },
                output,
            )
        self.manifest = self.xcframework / validator.MANIFEST_NAME
        exact_hash = "a" * 64
        rust_commit = "b" * 40
        self.payload = {
            "version": "1.0.0",
            "native_bridge_abi_version": 25,
            "privacy_production_enabled": True,
            "cargo_features": ["privacy-production-enabled"],
            "build_environment": {
                "schema": "iroha.mobile-native-build-environment.v1",
                "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
                "hermetic_runner_sha256": hashlib.sha256(
                    (ROOT / "scripts/run_mobile_hermetic_command.py").read_bytes()
                ).hexdigest(),
                "environment_profiles": validator.EXPECTED_ENVIRONMENT_PROFILES,
                "cargo_build_jobs": 1,
                "rust_toolchain_channel": "1.93.1",
                "cargo_release": "1.93.1",
                "cargo_commit_hash": "c" * 40,
                "cargo_binary_sha256": exact_hash,
                "rustc_release": "1.93.1",
                "rustc_commit_hash": rust_commit,
                "rustc_binary_sha256": exact_hash,
                "rustdoc_release": "1.93.1",
                "rustdoc_commit_hash": rust_commit,
                "rustdoc_binary_sha256": exact_hash,
                "python_version": "3.12.13",
                "python_binary_sha256": exact_hash,
                "git_version": "2.50.1",
                "git_binary_sha256": exact_hash,
                "rustup_version": "1.28.2",
                "rustup_binary_sha256": exact_hash,
                "xcode_version": "26.5",
                "xcode_build_version": "17F12",
                "iphoneos_sdk_version": "26.5",
                "iphonesimulator_sdk_version": "26.5",
                "macosx_sdk_version": "26.5",
                "iphoneos_deployment_target": "15.0",
                "iphonesimulator_deployment_target": "15.0",
                "macosx_deployment_target": "12.0",
            },
            "source_commit": "1" * 40,
            "embedded_source_commit": "1" * 40,
            "source_tree_dirty": False,
            "source_fingerprint_sha256": "2" * 64,
            "cargo_lock_sha256": hashlib.sha256(
                (ROOT / "Cargo.lock").read_bytes()
            ).hexdigest(),
            "bridge_header_sha256": hashlib.sha256(header).hexdigest(),
            "required_symbols": list(validator.EXPECTED_REQUIRED_SYMBOLS),
            "forbidden_symbols": list(validator.EXPECTED_FORBIDDEN_SYMBOLS),
            "hashes": self.hashes,
        }
        self.write_manifest()
        self.manifest_link = self.artifact_root / validator.MANIFEST_NAME
        self.manifest_link.symlink_to(
            "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
        )
        self.loader = Path(self.temporary.name) / "NativeBridge.swift"
        self.write_loader(self.hashes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_current_retail_codec_inventory_is_required_and_quote_aliases_forbidden(self) -> None:
        for symbol in (
            "connect_norito_retail_fee_intent_hash_v1",
            "connect_norito_retail_fee_assessment_marker_v1",
            "connect_norito_retail_fee_assessment_decode_v1",
        ):
            self.assertEqual(validator.EXPECTED_REQUIRED_SYMBOLS.count(symbol), 1)
            self.assertNotIn(symbol, validator.EXPECTED_FORBIDDEN_SYMBOLS)
        for symbol in (
            "connect_norito_validation_fee_hijiri_quote_request_v1",
            "connect_norito_validation_fee_hijiri_quote_response_verify_v1",
        ):
            self.assertNotIn(symbol, validator.EXPECTED_REQUIRED_SYMBOLS)
            self.assertEqual(validator.EXPECTED_FORBIDDEN_SYMBOLS.count(symbol), 1)

    def test_native_symbol_inventories_match_authoritative_header(self) -> None:
        """Source inventories must require current C exports before packaging."""
        header = (
            ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
        ).read_text(encoding="utf-8")
        pq_header = (ROOT / "crates/soranet_pq/include/soranet_pq.h").read_text(
            encoding="utf-8"
        )
        for symbol in validator.EXPECTED_REQUIRED_SYMBOLS:
            with self.subTest(symbol=symbol):
                owner = pq_header if symbol.startswith("soranet_mldsa_") else header
                self.assertRegex(owner, rf"\b{re.escape(symbol)}\s*\(")

        builder = (ROOT / "scripts/build_norito_xcframework.sh").read_text(
            encoding="utf-8"
        )
        builder_inventory = builder.split('  "required_symbols": [', 1)[1].split(
            "\n  ],", 1
        )[0]
        self.assertEqual(
            re.findall(r'"([a-z][a-z0-9_]+)"', builder_inventory),
            validator.EXPECTED_REQUIRED_SYMBOLS,
        )
        checker = (ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text(
            encoding="utf-8"
        )
        # The packaging checker refuses retired KAGEMUSHA exports by namespace; the
        # exact forbidden inventory is owned by the validator and the builder above.
        self.assertNotIn("RETIRED_KAGEMUSHA_C_SYMBOLS", checker)
        self.assertEqual(re.findall(r"connect_norito_kagemusha_[A-Za-z0-9_]+", checker), [])
        self.assertEqual(checker.count("grep -Eq '^_?connect_norito_kagemusha_'"), 1)

    def test_current_mobile_protocol_inventory_matches_required_bridge_exports(self) -> None:
        checker = (ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text(
            encoding="utf-8"
        )
        inventory = checker.split("REQUIRED_PROTOCOL_C_SYMBOLS=(\n", 1)[1].split(
            "\n)", 1
        )[0]
        self.assertEqual(
            inventory.split(),
            [
                symbol for symbol in validator.EXPECTED_REQUIRED_SYMBOLS
                if not symbol.startswith("soranet_mldsa_")
            ],
        )
        builder = (ROOT / "scripts/build_norito_xcframework.sh").read_text(
            encoding="utf-8"
        )
        forbidden = builder.split('  "forbidden_symbols": [', 1)[1].split(
            "\n  ],", 1
        )[0]
        retired_auditor_symbol = "_".join((
            "connect_norito_private_settlement_auditor_capsule_response", "verify", "v1"
        ))
        forbidden = forbidden.replace(
            '"$RETIRED_AUDITOR_CAPSULE_VERIFY_SYMBOL"', f'"{retired_auditor_symbol}"'
        )
        self.assertEqual(
            re.findall(r'"([a-z][a-z0-9_]+)"', forbidden),
            validator.EXPECTED_FORBIDDEN_SYMBOLS,
        )

    def check_mobile_binary_symbols(
        self, symbols: list[str], mode: str = "apple"
    ) -> subprocess.CompletedProcess[str]:
        """Exercise the packaging guard with an explicit exported symbol table."""
        checker = (ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text(
            encoding="utf-8"
        )
        inventories = "REQUIRED_PROTOCOL_C_SYMBOLS=(\n" + checker.split(
            "REQUIRED_PROTOCOL_C_SYMBOLS=(\n", 1
        )[1].split("check_source_contract() {", 1)[0]
        guard = "check_binary_symbols() {" + checker.split(
            "check_binary_symbols() {", 1
        )[1].split("\ncheck_apple() {", 1)[0]
        program = (
            'set -euo pipefail\nFAILURES=0\n'
            'fail() { printf "%s\\n" "$1" >&2; FAILURES=$((FAILURES + 1)); }\n'
            'nm() { printf "%s\\n" "$MOCK_EXPORTED_SYMBOLS"; }\n'
            + inventories + guard
            + '\ncheck_binary_symbols fixture fixture "$1"\n'
            + '[[ "$FAILURES" -eq 0 ]]\n'
        )
        return subprocess.run(
            ["/bin/bash", "-s", "--", mode], input=program, text=True,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin", "MOCK_EXPORTED_SYMBOLS": "\n".join(symbols)},
            check=False,
        )

    def test_mobile_binary_guard_requires_current_exports(self) -> None:
        current = [
            symbol for symbol in validator.EXPECTED_REQUIRED_SYMBOLS
            if not symbol.startswith("soranet_mldsa_")
        ]
        for mode in ("apple", "elf"):
            with self.subTest(mode=mode):
                result = self.check_mobile_binary_symbols(current, mode)
                self.assertEqual(result.returncode, 0, result.stderr)
        for missing in (
            "connect_norito_bridge_abi_version",
            "connect_norito_domain_id_validate_v1",
            "connect_norito_validation_fee_current_policy_proof_verify_v1",
            "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
            "iroha_privacy_validate_exact12_capability_manifest_v1",
        ):
            with self.subTest(missing=missing):
                result = self.check_mobile_binary_symbols(
                    [symbol for symbol in current if symbol != missing]
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"missing {missing}", result.stderr)

    def test_mobile_binary_guard_rejects_retired_c_and_jni_exports(self) -> None:
        checker = (ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text(
            encoding="utf-8"
        )
        current = [
            symbol for symbol in validator.EXPECTED_REQUIRED_SYMBOLS
            if not symbol.startswith("soranet_mldsa_")
        ]
        retired_c = [
            symbol for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS
            if symbol.startswith("connect_norito_kagemusha_")
        ]
        for symbol in (
            *retired_c,
            "connect_norito_kagemusha_unlisted_v1",
            "connect_norito_offline_cash_unlisted_v1",
        ):
            for mode in ("apple", "elf"):
                with self.subTest(symbol=symbol, mode=mode):
                    exported = "_" + symbol if mode == "apple" else symbol
                    result = self.check_mobile_binary_symbols([*current, exported], mode)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("retired KAGEMUSHA", result.stderr)
        # Former exports of each retired class family; the checker matches namespaces.
        retired_jni = [
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaReserveFinalityJniV1_nativeVerify",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaTopUpSubmissionJniV1_nativeValidate",
            "Java_org_hyperledger_iroha_sdk_offline_KagemushaDeviceLifecycleBridgeV1_00024NativeEndpoint_nativeExecuteV1",
            "Java_org_hyperledger_iroha_sdk_offline_KagemushaCoreCoordinatorJniV1_nativeInvokeV1",
            "Java_org_hyperledger_iroha_sdk_offline_KagemushaOrdinaryRuntimeJniV1_nativeStartupV1",
            "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaTestnetValueCreditJniV1_nativeCreditV1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaTestnetNativeStartupJniV1_nativeActivateV1",
            "Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_nativeCreateV1",
        ]
        for symbol in retired_jni:
            self.assertNotIn(symbol, checker)
        unlisted = retired_jni[0].rsplit("_native", 1)[0] + "_nativeUnlistedV1"
        for symbol in (
            *retired_jni,
            unlisted,
            "Java_org_hyperledger_iroha_sdk_offline_KagemushaFirstDeviceHardwareEvidenceJniV1_nativeUnlistedV1",
            "Java_org_hyperledger_iroha_sdk_offline_probe_KagemushaUnlistedJniV1_nativeUnlistedV1",
            "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaUnlistedJniV1_nativeUnlistedV1",
            "Java_org_hyperledger_iroha_sdk_offline_probe_Pixel6TestnetDiagnosticSelectionJniV1_nativeUnlistedV1",
        ):
            with self.subTest(symbol=symbol):
                result = self.check_mobile_binary_symbols([*current, symbol], "elf")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("retired KAGEMUSHA JNI", result.stderr)

    def test_retired_kagemusha_exports_cannot_be_required(self) -> None:
        for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS:
            if not symbol.startswith("connect_norito_kagemusha_"):
                continue
            with self.subTest(symbol=symbol):
                self.assertNotIn(symbol, validator.EXPECTED_REQUIRED_SYMBOLS)
                self.payload["required_symbols"] = [
                    *validator.EXPECTED_REQUIRED_SYMBOLS, symbol
                ]
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "required symbol inventory"):
                    self.validate()

    def write_manifest(self) -> None:
        self.manifest.write_text(
            json.dumps(self.payload, indent=2) + "\n", encoding="utf-8"
        )

    def write_loader(self, hashes: dict[str, str]) -> None:
        self.loader.write_text(
            "    private static let expectedHashes: [String: String] = [\n"
            + "\n".join(
                f'        "{key}": "{hashes[key]}"{"," if index < 2 else ""}'
                for index, key in enumerate(
                    (
                        "macos-arm64_x86_64",
                        "ios-arm64",
                        "ios-arm64_x86_64-simulator",
                    )
                )
            )
            + "\n    ]\n",
            encoding="utf-8",
        )

    def validate(self, lockfile: Path | None = None) -> None:
        if lockfile is None:
            lockfile = self.lockfile
        validator.validate(
            root=ROOT,
            lockfile_path=lockfile,
            xcframework=self.xcframework,
            manifest_path=self.manifest,
            manifest_link=self.manifest_link,
            expected_link_target="NoritoBridge.xcframework/NoritoBridge.artifacts.json",
            swift_loader=self.loader,
        )

    def test_explicit_external_lock_is_authenticated_without_replacing_root_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory).resolve() / "Cargo.lock"
            external.write_bytes((ROOT / "Cargo.lock").read_bytes())
            external.chmod(0o400)
            root_before = (ROOT / "Cargo.lock").read_bytes()
            source_seal = validator._load_swift_pin_owner(ROOT)
            digest = hashlib.sha256(external.read_bytes()).hexdigest()
            self.payload["cargo_lock_sha256"] = digest
            self.write_manifest()
            with (
                mock.patch.object(validator, "_load_swift_pin_owner", return_value=source_seal),
            ):
                validator.validate(
                    root=ROOT, lockfile_path=external, xcframework=self.xcframework,
                    manifest_path=self.manifest, manifest_link=self.manifest_link,
                    expected_link_target="NoritoBridge.xcframework/NoritoBridge.artifacts.json",
                    swift_loader=self.loader,
                )
                self.assertEqual((ROOT / "Cargo.lock").read_bytes(), root_before)
                # Replacing the selected inode with identical bytes is still
                # mutation; a matching digest alone cannot authorize success.
                def replace_selected(*_arguments):
                    replacement = external.with_name("replacement.lock")
                    replacement.write_bytes(external.read_bytes())
                    replacement.replace(external)
                with (
                    mock.patch.object(validator, "_validate_swift_pins", side_effect=replace_selected),
                    self.assertRaisesRegex(validator.ValidationError, "changed during artifact validation"),
                ):
                    validator.validate(
                        root=ROOT, lockfile_path=external, xcframework=self.xcframework,
                        manifest_path=self.manifest, manifest_link=self.manifest_link,
                        expected_link_target="NoritoBridge.xcframework/NoritoBridge.artifacts.json",
                        swift_loader=self.loader,
                    )
            external.chmod(0o600)
            external.write_bytes(b"unreviewed validator fixture\n")
            external.chmod(0o400)
            with self.assertRaisesRegex(validator.ValidationError, "canonical reviewed graph"):
                validator.validate(
                    root=ROOT, lockfile_path=external, xcframework=self.xcframework,
                    manifest_path=self.manifest, manifest_link=self.manifest_link,
                    expected_link_target="NoritoBridge.xcframework/NoritoBridge.artifacts.json",
                )

    def test_privacy_artifact_cannot_select_root_even_with_matching_graph_bytes(self) -> None:
        payload = dict(self.payload, privacy_production_enabled=True)
        with self.assertRaisesRegex(validator.ValidationError, "explicit external canonical graph snapshot"):
            validator._validate_root_identity(ROOT, payload, ROOT / "Cargo.lock")

    def test_every_native_artifact_requires_readonly_external_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory).resolve() / "Cargo.lock"
            external.write_bytes((ROOT / "Cargo.lock").read_bytes())
            payload = dict(self.payload, privacy_production_enabled=True)
            external.chmod(0o600)
            with self.assertRaisesRegex(validator.ValidationError, "must be read-only"):
                validator._validate_root_identity(ROOT, payload, external)
            with self.assertRaisesRegex(validator.ValidationError, "must be read-only"):
                validator._validate_root_identity(ROOT, self.payload, external)
            external.chmod(0o400)
            validator._validate_root_identity(ROOT, payload, external)
            self.assertEqual(external.read_bytes(), (ROOT / "Cargo.lock").read_bytes())

    def test_missing_lock_selection_has_no_default(self) -> None:
        with self.assertRaisesRegex(TypeError, "lockfile_path"):
            validator.validate(
                root=ROOT, xcframework=self.xcframework,
                manifest_path=self.manifest, manifest_link=self.manifest_link,
                expected_link_target="NoritoBridge.xcframework/NoritoBridge.artifacts.json",
            )

    def test_rejects_disabled_or_non_boolean_native_support(self) -> None:
        for value in (False, 0, 1, "true", None):
            with self.subTest(value=value):
                self.payload["privacy_production_enabled"] = value
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "mandatory privacy support"):
                    self.validate()

    def test_rejects_omitted_native_feature_and_marker(self) -> None:
        self.payload["cargo_features"] = []
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "Cargo feature inventory"):
            self.validate()
        self.payload["cargo_features"] = ["privacy-production-enabled"]
        self.write_manifest()
        (self.xcframework / ".privacy-production-enabled").unlink()
        with self.assertRaisesRegex(validator.ValidationError, "top-level"):
            self.validate()

    def test_accepts_only_the_canonical_inventory(self) -> None:
        self.validate()

    def test_rejects_manifest_missing_current_domain_fee_settlement_or_mldsa_exports(self) -> None:
        for missing in (
            "connect_norito_domain_id_validate_v1",
            "connect_norito_validation_fee_current_policy_proof_request_v1",
            "connect_norito_validation_fee_current_policy_proof_verify_v1",
            "connect_norito_private_settlement_committee_proof_response_verify_v1",
            "connect_norito_private_settlement_auditor_capsule_response_verify_with_request_v1",
            "connect_norito_private_settlement_audit_approval_response_verify_v1",
            "soranet_mldsa_parameters",
            "soranet_mldsa_generate_keypair",
            "soranet_mldsa_sign",
            "soranet_mldsa_verify",
        ):
            with self.subTest(missing=missing):
                self.payload["required_symbols"] = [
                    symbol for symbol in validator.EXPECTED_REQUIRED_SYMBOLS
                    if symbol != missing
                ]
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "required symbol inventory"):
                    self.validate()

    def test_rejects_manifests_omitting_either_retired_mint_stage_export(self) -> None:
        for missing in (
            "connect_norito_kagemusha_device_mint_stage_command_v1_validate",
            "connect_norito_kagemusha_device_mint_stage_result_v1_validate",
        ):
            with self.subTest(missing=missing):
                self.payload["forbidden_symbols"] = [
                    symbol for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS
                    if symbol != missing
                ]
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "forbidden symbol inventory"):
                    self.validate()

    def test_rejects_manifest_missing_authoritative_privacy_capability_validator(self) -> None:
        self.payload["required_symbols"] = [
            symbol for symbol in validator.EXPECTED_REQUIRED_SYMBOLS
            if symbol != "iroha_privacy_validate_exact12_capability_manifest_v1"
        ]
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "required symbol inventory"):
            self.validate()

    def test_rejects_manifest_omitting_retired_top_up_request_binding(self) -> None:
        self.payload["forbidden_symbols"] = [
            symbol for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS
            if symbol != "connect_norito_kagemusha_top_up_signed_request_validate_v1"
        ]
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "forbidden symbol inventory"):
            self.validate()

    def test_rejects_manifest_omitting_retired_coordinator_or_state_observer(self) -> None:
        for missing in (
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
        ):
            with self.subTest(missing=missing):
                self.payload["forbidden_symbols"] = [
                    symbol for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS
                    if symbol != missing
                ]
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "forbidden symbol inventory"):
                    self.validate()

    def test_rejects_manifests_omitting_either_retired_reserve_finality_export(self) -> None:
        for missing in (
            "connect_norito_kagemusha_reserve_finality_hint_v1",
            "connect_norito_kagemusha_reserve_finality_verify_v1",
        ):
            with self.subTest(missing=missing):
                self.payload["forbidden_symbols"] = [
                    symbol for symbol in validator.EXPECTED_FORBIDDEN_SYMBOLS
                    if symbol != missing
                ]
                self.write_manifest()
                with self.assertRaisesRegex(validator.ValidationError, "forbidden symbol inventory"):
                    self.validate()

    def test_repository_provenance_rejects_dirty_source_without_allowance(self) -> None:
        self.payload["source_tree_dirty"] = True
        self.write_manifest()
        arguments = {
            "root": ROOT,
            "lockfile_path": self.lockfile,
            "xcframework": self.xcframework,
            "manifest_path": self.manifest,
            "manifest_link": self.manifest_link,
            "expected_link_target": (
                "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
            ),
            "swift_loader": self.loader,
            "verify_repository_provenance": True,
        }
        with (
            mock.patch.object(validator, "_validate_repository_provenance"),
            self.assertRaisesRegex(validator.ValidationError, "clean source tree"),
        ):
            validator.validate(**arguments)
        with mock.patch.object(validator, "_validate_repository_provenance"):
            validator.validate(**arguments, allow_dirty_source=True)

    def test_dirty_allowance_requires_provenance_verification(self) -> None:
        with self.assertRaisesRegex(
            validator.ValidationError, "requires repository provenance"
        ):
            validator.validate(
                root=ROOT,
            lockfile_path=self.lockfile,
                xcframework=self.xcframework,
                manifest_path=self.manifest,
                manifest_link=self.manifest_link,
                expected_link_target=(
                    "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
                ),
                swift_loader=self.loader,
                allow_dirty_source=True,
            )

    def test_rejects_unknown_manifest_fields_and_stale_pins(self) -> None:
        self.payload["legacy_hash"] = "4" * 64
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "field inventory"):
            self.validate()
        del self.payload["legacy_hash"]
        self.write_manifest()
        stale = dict(self.hashes)
        stale["ios-arm64"] = "5" * 64
        self.write_loader(stale)
        with self.assertRaisesRegex(validator.ValidationError, "pins are stale"):
            self.validate()

    def test_decoy_pin_dictionary_cannot_replace_expected_hashes(self) -> None:
        contents = self.loader.read_text(encoding="utf-8")
        decoy = contents.replace(
            "    private static let expectedHashes: [String: String] = [",
            "let decoyHashes = [",
        ).replace("        ", "    ").replace("    ]", "]")
        self.loader.write_text(
            contents.replace(
                "private static let expectedHashes",
                "private static let retiredHashes",
            )
            + decoy,
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            validator.ValidationError,
            "canonical expectedHashes block",
        ):
            self.validate()

    def test_rejects_extra_files_slices_and_symlinks(self) -> None:
        extra = self.xcframework / "historical.txt"
        extra.write_text("retired\n", encoding="utf-8")
        with self.assertRaisesRegex(validator.ValidationError, "inventory is not exact"):
            self.validate()
        extra.unlink()

        old_slice = self.xcframework / "ios-x86_64"
        old_slice.mkdir()
        with self.assertRaisesRegex(validator.ValidationError, "inventory is not exact"):
            self.validate()
        old_slice.rmdir()

        symbolic = self.xcframework / "alias"
        symbolic.symlink_to("Info.plist")
        with self.assertRaisesRegex(validator.ValidationError, "contains a symlink"):
            self.validate()

    def test_rejects_fabricated_environment_policy_and_source_identity(self) -> None:
        environment = self.payload["build_environment"]
        assert isinstance(environment, dict)
        environment["cargo_build_jobs"] = 2
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "environment identity"):
            self.validate()

        environment["cargo_build_jobs"] = 1
        self.payload["required_symbols"] = ["connect_norito_bridge_abi_version"]
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "required symbol"):
            self.validate()

        self.payload["required_symbols"] = list(validator.EXPECTED_REQUIRED_SYMBOLS)
        self.payload["cargo_lock_sha256"] = "3" * 64
        self.write_manifest()
        with self.assertRaisesRegex(validator.ValidationError, "Cargo.lock digest"):
            self.validate()

    def test_standalone_owner_recomputes_source_provenance(self) -> None:
        source_seal = types.SimpleNamespace(
            snapshot=lambda _root, _platform, _lock: {"source_fingerprint_sha256": "2" * 64, "source_tree_dirty": False},
        )
        pin_commit = types.SimpleNamespace(
            validate_pin_relationship=lambda _root, _commit: "direct",
            embedded_source_commit=lambda _root, commit: commit,
        )
        with (
            mock.patch.object(
                validator,
                "_load_repository_module",
                side_effect=(source_seal, pin_commit),
            ),
            mock.patch.object(validator, "_validate_tool_provenance"),
        ):
            validator._validate_repository_provenance(ROOT, self.payload, ROOT / "Cargo.lock")

        self.payload["embedded_source_commit"] = "3" * 40
        with (
            mock.patch.object(
                validator,
                "_load_repository_module",
                side_effect=(source_seal, pin_commit),
            ),
            mock.patch.object(validator, "_validate_tool_provenance"),
            self.assertRaisesRegex(
                validator.ValidationError,
                "embedded source commit does not match",
            ),
        ):
            validator._validate_repository_provenance(ROOT, self.payload, ROOT / "Cargo.lock")
        self.payload["embedded_source_commit"] = "1" * 40

        dirty_source_seal = types.SimpleNamespace(
            snapshot=lambda _root, _platform, _lock: {"source_fingerprint_sha256": "2" * 64, "source_tree_dirty": True},
        )
        pin_parent = types.SimpleNamespace(
            validate_pin_relationship=lambda _root, _commit: "pin-parent",
            embedded_source_commit=lambda _root, commit: commit,
        )
        self.payload["source_tree_dirty"] = True
        with (
            mock.patch.object(
                validator,
                "_load_repository_module",
                side_effect=(dirty_source_seal, pin_parent),
            ),
            mock.patch.object(validator, "_validate_tool_provenance"),
            self.assertRaisesRegex(
                validator.ValidationError, "clean authenticated source closure"
            ),
        ):
            validator._validate_repository_provenance(ROOT, self.payload, ROOT / "Cargo.lock")

        self.payload["source_tree_dirty"] = False

        self.payload["source_fingerprint_sha256"] = "4" * 64
        with (
            mock.patch.object(
                validator,
                "_load_repository_module",
                side_effect=(source_seal, pin_commit),
            ),
            mock.patch.object(validator, "_validate_tool_provenance"),
            self.assertRaisesRegex(validator.ValidationError, "fingerprint"),
        ):
            validator._validate_repository_provenance(ROOT, self.payload, ROOT / "Cargo.lock")

    def test_tool_provenance_accepts_exact_tools_and_rejects_identity_drift(self) -> None:
        tools_root = Path(self.temporary.name).resolve() / "tools"
        tools_root.mkdir()
        tool_paths = {}
        for name in ("cargo", "rustc", "rustdoc", "git", "rustup"):
            path = tools_root / name
            path.write_bytes((name + "\n").encode("ascii"))
            tool_paths[name] = path

        authenticated_tools = {
            name: types.SimpleNamespace(
                canonical=tool_paths[name],
                authenticate=mock.Mock(),
            )
            for name in ("cargo", "rustc", "rustdoc")
        }
        source_seal = types.SimpleNamespace(
            source_seal_tools=lambda: (
                authenticated_tools["cargo"],
                authenticated_tools["rustc"],
                authenticated_tools["rustdoc"],
                tool_paths["git"],
            )
        )
        environment = self.payload["build_environment"]
        assert isinstance(environment, dict)
        for name in ("cargo", "rustc", "rustdoc", "git", "rustup"):
            environment[f"{name}_binary_sha256"] = hashlib.sha256(
                tool_paths[name].read_bytes()
            ).hexdigest()
        python = Path(sys.executable).resolve(strict=True)
        environment["python_binary_sha256"] = hashlib.sha256(
            python.read_bytes()
        ).hexdigest()
        environment["python_version"] = validator.platform.python_version()
        actual_rust_identities = {
            "cargo": ("1.93.1", "c" * 40),
            "rustc": ("1.93.1", "b" * 40),
            "rustdoc": ("1.93.1", "b" * 40),
        }

        def tool_output(
            executable: Path, arguments: list[str], _environment: dict[str, str]
        ) -> str:
            if arguments == ["--version", "--verbose"]:
                release, commit = actual_rust_identities[executable.name]
                return f"release: {release}\ncommit-hash: {commit}\n"
            if executable == tool_paths["git"]:
                return f"git version {environment['git_version']}\n"
            if executable == tool_paths["rustup"]:
                return f"rustup {environment['rustup_version']}\n"
            if executable == Path("/usr/bin/xcodebuild"):
                return (
                    f"Xcode {environment['xcode_version']}\n"
                    f"Build version {environment['xcode_build_version']}\n"
                )
            sdk = arguments[1]
            return f"{environment[f'{sdk}_sdk_version']}\n"

        with (
            mock.patch.dict(
                validator.os.environ,
                {
                    "NORITO_BRIDGE_SEAL_RUSTUP": str(tool_paths["rustup"]),
                    "NORITO_BRIDGE_SEAL_DEVELOPER_DIR": str(tools_root),
                },
                clear=False,
            ),
            mock.patch.object(validator, "_tool_output", side_effect=tool_output),
        ):
            validator._validate_tool_provenance(self.payload, source_seal)

            environment["cargo_binary_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                validator.ValidationError,
                "artifact build tool digest mismatch: cargo_binary_sha256",
            ):
                validator._validate_tool_provenance(self.payload, source_seal)
            environment["cargo_binary_sha256"] = hashlib.sha256(
                tool_paths["cargo"].read_bytes()
            ).hexdigest()

            environment["rustc_release"] = "1.93.0"
            with self.assertRaisesRegex(
                validator.ValidationError,
                "Rust tool identity",
            ):
                validator._validate_tool_provenance(self.payload, source_seal)

    def test_rejects_extra_plist_keys_and_copied_header_drift(self) -> None:
        info_path = self.xcframework / "Info.plist"
        with info_path.open("rb") as source:
            info = plistlib.load(source)
        info["LegacyCompatibility"] = True
        with info_path.open("wb") as output:
            plistlib.dump(info, output)
        with self.assertRaisesRegex(validator.ValidationError, "field inventory"):
            self.validate()

        del info["LegacyCompatibility"]
        info["AvailableLibraries"][0]["LegacyPath"] = "retired"
        with info_path.open("wb") as output:
            plistlib.dump(info, output)
        with self.assertRaisesRegex(validator.ValidationError, "field inventory"):
            self.validate()

        del info["AvailableLibraries"][0]["LegacyPath"]
        with info_path.open("wb") as output:
            plistlib.dump(info, output)
        wrapper = self.xcframework / "ios-arm64/Headers/NoritoBridge.h"
        wrapper.write_bytes(wrapper.read_bytes() + b"// drift\n")
        with self.assertRaisesRegex(validator.ValidationError, "authoritative source"):
            self.validate()

    def test_binary_path_shape_is_uniform_across_every_slice(self) -> None:
        info_path = self.xcframework / "Info.plist"
        with info_path.open("rb") as source:
            info = plistlib.load(source)
        for library in info["AvailableLibraries"]:
            library["BinaryPath"] = validator.LIBRARY_NAME
        with info_path.open("wb") as output:
            plistlib.dump(info, output)
        self.validate()

        del info["AvailableLibraries"][0]["BinaryPath"]
        with info_path.open("wb") as output:
            plistlib.dump(info, output)
        with self.assertRaisesRegex(validator.ValidationError, "must be uniform"):
            self.validate()

    def test_production_marker_is_an_empty_regular_file(self) -> None:
        self.payload["privacy_production_enabled"] = True
        self.payload["cargo_features"] = ["privacy-production-enabled"]
        self.write_manifest()
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory).resolve() / "Cargo.lock"
            lockfile.write_bytes((ROOT / "Cargo.lock").read_bytes())
            lockfile.chmod(0o400)
            marker = self.xcframework / ".privacy-production-enabled"
            marker.unlink()
            marker.mkdir()
            with self.assertRaisesRegex(validator.ValidationError, "regular file"):
                self.validate(lockfile)
            marker.rmdir()

            marker.write_bytes(b"enabled\n")
            with self.assertRaisesRegex(validator.ValidationError, "must be empty"):
                self.validate(lockfile)

if __name__ == "__main__":
    unittest.main()
