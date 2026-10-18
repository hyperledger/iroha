#!/usr/bin/env python3
"""Freeze the fail-closed ABI-30 C# privacy test and workflow contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from scripts import check_native_sdk_artifact as checker


REPO_ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    """Read one UTF-8 repository file."""

    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def workflow_job(source: str, name: str) -> str:
    """Return one top-level workflow job block."""

    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        source,
    )
    if match is None:
        raise AssertionError(f"missing workflow job: {name}")
    return match.group(0)


class PrivacyCsharpNativeContractTests(unittest.TestCase):
    """Guard C# privacy tests against native capability skips."""

    def test_exact12_test_requires_native_bridge_unconditionally(self) -> None:
        source = read(
            "csharp/tests/Hyperledger.Iroha.Sdk.Tests/PrivacyNativeTests.cs"
        )
        method_name = (
            "Exact12FixtureBundleRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()"
        )
        start = source.index(method_name)
        native_assertion = source.index("var bundle =", start)
        preflight = source[start:native_assertion]

        self.assertIn(
            "Assert.True(\n"
            "            PrivacyNative.IsAvailable(),\n"
            "            \"ABI-30 connect_norito_bridge with exact-12 fixture "
            "symbols is required.\");",
            preflight,
        )

        catalog_method = (
            "CompiledProfileCatalogRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()"
        )
        catalog_start = source.index(catalog_method)
        catalog_native_call = source.index("var catalog =", catalog_start)
        catalog_preflight = source[catalog_start:catalog_native_call]
        self.assertIn(
            "Assert.True(\n"
            "            PrivacyNative.IsAvailable(),\n"
            "            \"ABI-30 connect_norito_bridge with compiled-profile "
            "catalog symbols is required.\");",
            catalog_preflight,
        )
        self.assertNotIn("WhenAvailable", source)
        self.assertNotIn("IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE", source)
        self.assertNotIn("if (!PrivacyNative.IsAvailable())", source)

    def test_csharp_artifact_manifest_requires_all_privacy_symbols(self) -> None:
        required = checker.REQUIRED_SYMBOLS["csharp"]
        for symbol in (
            "connect_norito_bridge_abi_version",
            "connect_norito_free",
            "connect_norito_sorafs_reference_validate_appeal_finance_cancel_asset_lock_json",
        ):
            self.assertIn(symbol, required)
        self.assertEqual(
            tuple(symbol for symbol in required if symbol.startswith("iroha_privacy_")),
            (
                "iroha_privacy_compiled_profile_catalog_v1",
                "iroha_privacy_validate_compiled_profile_catalog_v1",
                "iroha_privacy_exact12_fixture_bundle_v1",
                "iroha_privacy_validate_exact12_fixture_bundle_v1",
                "iroha_privacy_validate_exact12_capability_manifest_v1",
                "iroha_privacy_free_buffer",
            ),
        )

    def test_csharp_runner_authenticates_the_only_loadable_bridge(self) -> None:
        source = read("ci/check_privacy_csharp_sdk.sh")
        for marker in (
            '"${IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE:-}" != "1"',
            "PRIVACY_CSHARP_NATIVE_ARTIFACT",
            "PRIVACY_CSHARP_NATIVE_MANIFEST",
            "scripts/check_native_sdk_artifact.py",
            '"${PYTHON_BIN}" -I -B "${ABI30_ARTIFACT_CHECKER}" verify',
            '--artifact "${PRIVACY_CSHARP_NATIVE_ARTIFACT}"',
            '--manifest "${PRIVACY_CSHARP_NATIVE_MANIFEST}"',
            '--source-root "${ROOT_DIR}"',
            '"${LD_LIBRARY_PATH:-}" != "${NATIVE_DIRECTORY}"',
            "Hyperledger.Iroha.Sdk.Tests.PrivacyNativeTests",
            "Hyperledger.Iroha.Sdk.Tests.PrivacyExact12FixtureCodecV1Tests",
            "Hyperledger.Iroha.Sdk.Tests.VerifyingKeyBackendTagTests",
            '--filter-class "${test_class}"',
        ):
            self.assertIn(marker, source)

    def test_workflow_builds_authenticates_and_consumes_bridge(self) -> None:
        source = read(".github/workflows/pr_privacy_sdk_guard.yml")
        csharp = workflow_job(source, "privacy_csharp_sdk_tests")
        job_header = csharp[: csharp.index("    steps:\n")]
        test_step_start = csharp.index(
            "      - name: Privacy C# SDK tests through authenticated ABI29"
        )
        test_step_end = csharp.index(
            "      - name: Revalidate ABI29 C# privacy input after execution",
            test_step_start,
        )
        test_step = csharp[test_step_start:test_step_end]

        for path in (
            '      - "scripts/check_native_sdk_artifact.py"',
            '      - "scripts/tests/check_privacy_csharp_native_contract_test.py"',
        ):
            self.assertIn(path, source)
        for marker in (
            "needs: privacy_jvm_sdk_tests",
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            "privacy-jvm-native-abi29-${{ github.sha }}",
            "Authenticate exact ABI29 C# privacy input",
            "scripts/check_native_sdk_artifact.py verify",
            'IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE: "1"',
            "LD_LIBRARY_PATH: ${{ runner.temp }}/privacy-jvm-native-abi29",
            "PRIVACY_CSHARP_NATIVE_ARTIFACT: ${{ runner.temp }}/"
            "privacy-jvm-native-abi29/libconnect_norito_bridge.so",
            "PRIVACY_CSHARP_NATIVE_MANIFEST: ${{ runner.temp }}/"
            "privacy-jvm-native-abi29/native-sdk-abi29-csharp.json",
            "run: ci/check_privacy_csharp_sdk.sh",
        ):
            self.assertIn(marker, csharp)

        self.assertNotIn("${{ runner.temp }}", job_header)
        self.assertIn(
            "LD_LIBRARY_PATH: ${{ runner.temp }}/privacy-jvm-native-abi29",
            test_step,
        )

        ordered = (
            csharp.index("actions/setup-dotnet@"),
            csharp.index("actions/download-artifact@"),
            csharp.index("Authenticate exact ABI29 C# privacy input"),
            csharp.index("Privacy C# SDK tests"),
        )
        self.assertEqual(ordered, tuple(sorted(ordered)))


if __name__ == "__main__":
    unittest.main()
