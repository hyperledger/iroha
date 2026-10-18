#!/usr/bin/env python3
"""Freeze the fail-closed ABI-30 Kotlin privacy owner and Java consumers."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import importlib.util
import sys

SPEC = importlib.util.spec_from_file_location(
    "privacy_jvm_manifest_contract", Path(__file__).resolve().parents[1] / "check_privacy_exact12_sdk_manifest_parity.py"
)
assert SPEC is not None and SPEC.loader is not None
manifest_parity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manifest_parity
SPEC.loader.exec_module(manifest_parity)


REPO_ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    """Read one UTF-8 repository file."""

    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def read_rust_bridge_source() -> str:
    """Read the authenticated split JNI source closure."""

    return manifest_parity._rust_bridge_source(REPO_ROOT)


def workflow_job(source: str, name: str) -> str:
    """Return one top-level workflow job block."""

    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        source,
    )
    if match is None:
        raise AssertionError(f"missing workflow job: {name}")
    return match.group(0)


class PrivacyJvmNativeContractTests(unittest.TestCase):
    """Guard both JVM languages against native capability skips."""

    def test_kotlin_native_tests_require_the_bridge_unconditionally(self) -> None:
        source = read(
            "kotlin/core-jvm/src/test/kotlin/org/hyperledger/iroha/sdk/"
            "privacy/PrivacyNativeBridgeTest.kt"
        )
        for method, native_call, message in (
            (
                "compiledProfileCatalogRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()",
                "PrivacyNativeBridge.compiledProfileCatalogV1()",
                "compiled-profile catalog JNI exports is required",
            ),
            (
                "exact12FixtureBundleRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()",
                "PrivacyNativeBridge.exact12FixtureBundleV1()",
                "exact-12 fixture JNI exports is required",
            ),
        ):
            start = source.index(method)
            preflight = source[start : source.index(native_call, start)]
            self.assertIn(
                "val available = PrivacyNativeBridge.isNativeAvailable()",
                preflight,
            )
            self.assertIn(
                "assertTrue(\n            available,",
                preflight,
            )
            self.assertIn(message, preflight)
        for forbidden in (
            "WhenAvailable",
            "IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE",
            "if (!available) return",
        ):
            self.assertNotIn(forbidden, source)

    def test_java_native_tests_require_the_bridge_unconditionally(self) -> None:
        source = read(
            "kotlin/core-jvm/src/test/java/org/hyperledger/iroha/sdk/"
            "privacy/PrivacyNativeBridgeJavaConsumerTest.java"
        )
        for method, native_call, message in (
            (
                "compiledProfileCatalogRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()",
                "PrivacyNativeBridge.compiledProfileCatalogV1()",
                "compiled-profile catalog JNI exports is required",
            ),
            (
                "exact12FixtureBundleRoundTripsAndRejectsAdversarialBytesThroughNativeAbi24()",
                "PrivacyNativeBridge.exact12FixtureBundleV1()",
                "exact-12 fixture JNI exports is required",
            ),
        ):
            self.assertIn(f"  @Test\n  public void {method}", source)
            start = source.index(f"public void {method}")
            preflight = source[start : source.index(native_call, start)]
            self.assertIn(
                "final boolean available = PrivacyNativeBridge.isNativeAvailable();",
                preflight,
            )
            self.assertIn(
                "if (!available) {",
                preflight,
            )
            self.assertIn("throw new AssertionError(", preflight)
            self.assertIn(message, preflight)
        for forbidden in (
            "WhenAvailable",
            "IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE",
            "if (!available) return",
        ):
            self.assertNotIn(forbidden, source)

    def test_rust_bridge_exports_only_canonical_privacy_jni_namespace(self) -> None:
        source = read_rust_bridge_source()
        for namespace in ("sdk",):
            prefix = (
                "Java_org_hyperledger_iroha_"
                f"{namespace}_privacy_PrivacyNativeBridge_"
            )
            for method in (
                "nativeBridgeAbiVersion",
                "nativeCompiledProfileCatalog",
                "nativeValidateCompiledProfileCatalog",
                "nativeExact12FixtureBundle",
                "nativeValidateExact12FixtureBundle",
            ):
                self.assertEqual(1, source.count(prefix + method))
        self.assertNotIn("Java_org_hyperledger_iroha_android_privacy_PrivacyNativeBridge_", source)

    def test_jvm_runner_authenticates_the_only_loadable_bridge(self) -> None:
        source = read("ci/check_privacy_jvm_sdk.sh")
        for marker in (
            'ABI30_CHECKER="${ROOT_DIR}/scripts/check_native_sdk_artifact.py"',
            '"${PYTHON_BIN}" -I -S "${ABI30_CHECKER}" verify',
            'export IROHA_NATIVE_LIBRARY_PATH="${NATIVE_LIBRARY_DIR}"',
            'export LD_LIBRARY_PATH="${NATIVE_LIBRARY_DIR}"',
            '-Djava.library.path="${NATIVE_LIBRARY_DIR}"',
            "org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridgeTest",
            "org.hyperledger.iroha.sdk.privacy.PrivacyNativeBridgeJavaConsumerTest",
        ):
            self.assertIn(marker, source)

    def test_workflow_builds_and_exports_authenticated_bridge(self) -> None:
        source = read(".github/workflows/pr_privacy_sdk_guard.yml")
        job = workflow_job(source, "privacy_jvm_sdk_tests")
        self.assertIn(
            '      - "scripts/tests/check_privacy_jvm_native_contract_test.py"',
            source,
        )
        for marker in (
            "PRIVACY_JVM_SDK_PYTHON_BIN: ${{ steps.privacy-jvm-python.outputs.python-path }}",
            "PRIVACY_JVM_NATIVE_EXPORT_DIR: ${{ runner.temp }}/privacy-jvm-native-abi29",
            "run: ci/check_privacy_jvm_sdk.sh",
            "Upload source-bound privacy JVM native ABI29 input",
            "privacy-jvm-native-abi29-${{ github.sha }}",
        ):
            self.assertIn(marker, job)
        self.assertNotIn("IROHA_REQUIRE_PRIVACY_EXACT12_NATIVE", job)


if __name__ == "__main__":
    unittest.main()
