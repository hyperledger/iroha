#!/usr/bin/env python3
"""Tests for the sole Kotlin JNI source ownership and ABI guard."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/check_jni_sdk_android_pairs.py"
SPEC = importlib.util.spec_from_file_location("check_jni_sdk_android_pairs", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("failed to load JNI pair guard")
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)
SOURCE = (
    REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni/part_3.rs"
).read_text(encoding="utf-8")


class JniSdkAndroidPairGuardTests(unittest.TestCase):
    """Keep current owners, signatures, bodies, and attributes exact."""

    def test_repository_inventory_is_exact(self) -> None:
        result = GUARD.audit_source(SOURCE)
        self.assertEqual(40, result.sdk_count)
        self.assertEqual(9, result.privacy_count)
        self.assertEqual(5, result.governance_count)
        self.assertEqual(GUARD.EXPECTED_GOVERNANCE_SOURCE_DIGEST, result.governance_digest)
        self.assertEqual(GUARD.EXPECTED_ABI_DIGEST, result.abi_digest)
        self.assertEqual(GUARD.EXPECTED_ATTRIBUTE_DIGEST, result.attribute_digest)

    def test_rejects_current_symbol_drift(self) -> None:
        mutated = SOURCE.replace("NativeSignerBridge_nativeSignDetached(",
                                 "NativeSignerBridge_nativeSignDetachedV2(", 1)
        self.assertNotEqual(SOURCE, mutated)
        with self.assertRaisesRegex(GUARD.AuditError, "inventory changed"):
            GUARD.audit_source(mutated)

    def test_rejects_every_retired_android_owner(self) -> None:
        for suffix in GUARD.EXPECTED_COMMON_SUFFIXES:
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(GUARD.AuditError, "retired Android"):
                    GUARD.audit_source(SOURCE + "\n" + GUARD.ANDROID_PREFIX + suffix)

    def test_rejects_helper_argument_reordering(self) -> None:
        mutated = SOURCE.replace(
            "java_native_public_key_from_private(&mut env, algorithm_code, private_key)",
            "java_native_public_key_from_private(&mut env, private_key, algorithm_code)",
            1,
        )
        self.assertNotEqual(SOURCE, mutated, "mutation must alter the guarded source")
        with self.assertRaisesRegex(GUARD.AuditError, "signature/body contract changed"):
            GUARD.audit_source(mutated)

    def test_multisig_pairs_keep_network_fee_and_signature_binding(self) -> None:
        for method, old, new in (
            ("payload", "&mut env,\n        network_id,\n        authority,\n        reporting_account,\n        change,\n        creation_time_ms,",
             "&mut env,\n        authority,\n        network_id,\n        reporting_account,\n        change,\n        creation_time_ms,"),
            ("finalize", "fee_payment_json,\n        signature,", "signature,\n        fee_payment_json,"),
        ):
            with self.subTest(method=method):
                mutated = SOURCE.replace(old, new, 1)
                self.assertNotEqual(SOURCE, mutated)
                with self.assertRaisesRegex(GUARD.AuditError, "signature/body contract changed"):
                    GUARD.audit_source(mutated)

    def test_rejects_platform_documentation_drift(self) -> None:
        mutated = SOURCE.replace(
            "Validate a Torii Exact12 capability manifest for the Kotlin/JVM SDK.",
            "Validate a Torii Exact12 capability manifest for SDK.",
            1,
        )
        self.assertNotEqual(SOURCE, mutated, "mutation must alter the guarded source")
        with self.assertRaisesRegex(GUARD.AuditError, "documentation/attribute contract changed"):
            GUARD.audit_source(mutated)

    def test_rejects_retired_macro(self) -> None:
        with self.assertRaisesRegex(GUARD.AuditError, "retired paired"):
            GUARD.audit_source(SOURCE + "\njni_sdk_android_pairs! {}\n")

    def test_rejects_uninventoried_trailing_source(self) -> None:
        for item in (
            '#[unsafe(no_mangle)]\npub unsafe extern "system" fn '
            + GUARD.SDK_PREFIX + 'foreign_Unexpected_nativeExtra() {}',
            'pub fn unreviewed_helper() {}',
            'const UNREVIEWED_OWNER: u8 = 1;',
        ):
            with self.subTest(item=item):
                with self.assertRaisesRegex(GUARD.AuditError, "unexpected source after"):
                    GUARD.audit_source(SOURCE + "\n" + item + "\n")

    def test_governance_helpers_and_original_proof_bindings_are_exact(self) -> None:
        for old, new in (
            ("fn clear_parliament_jni_exception", "fn changed_exception_owner"),
            ("nativeVerifyCastingProofPageV1(", "nativeVerifyCastingProofPageV2("),
            (".map(|page| page.promoted_checkpoint)", ".map(|page| Vec::new())"),
            ("expected_ballot_attempt_id,\n        )", "network_id,\n        )"),
            ("if seed_bytes.len() != CONNECT_NORITO_PARLIAMENT_TIMED_OVN_SEED_BYTES_V1", "if false"),
        ):
            with self.subTest(owner=old):
                mutated = SOURCE.replace(old, new, 1)
                self.assertNotEqual(SOURCE, mutated)
                with self.assertRaisesRegex(GUARD.AuditError, "governance helper/signature/body"):
                    GUARD.audit_source(mutated)

    def test_trailing_whitespace_does_not_change_inventory(self) -> None:
        self.assertEqual(GUARD.audit_source(SOURCE), GUARD.audit_source(SOURCE + "\n" * 1000))

    def test_rejects_duplicate_export(self) -> None:
        mutated = SOURCE + "\npub unsafe extern \"system\" fn " + GUARD.SDK_PREFIX + GUARD.EXPECTED_COMMON_SUFFIXES[0] + "() {}\n"
        with self.assertRaisesRegex(GUARD.AuditError, "inventory changed"):
            GUARD.audit_source(mutated)

    def test_rejects_instance_receiver(self) -> None:
        mutated = SOURCE.replace("_class: jni::objects::JClass<'_>",
                                 "_class: jni::objects::JObject<'_>", 1)
        self.assertNotEqual(SOURCE, mutated)
        with self.assertRaisesRegex(GUARD.AuditError, "signature/body contract changed"):
            GUARD.audit_source(mutated)

    def test_rejects_duplicate_no_mangle(self) -> None:
        mutated = SOURCE.replace("#[unsafe(no_mangle)]", "#[unsafe(no_mangle)]\n#[unsafe(no_mangle)]", 1)
        with self.assertRaisesRegex(GUARD.AuditError, "exactly one"):
            GUARD.audit_source(mutated)

    def test_all_platform_sources_have_only_current_namespace(self) -> None:
        for path in (REPO_ROOT / "crates/connect_norito_bridge/src/platform_jni").glob("*.rs"):
            with self.subTest(path=path.name):
                source = path.read_text()
                self.assertNotIn(GUARD.ANDROID_PREFIX, source)
                self.assertNotIn("jni_sdk_android_pairs", source)

    def test_rejects_retired_privacy_methods_without_network_binding(self) -> None:
        for method in (
            "nativeValidateExact12CapabilityManifest",
            "nativeRequireExact12CapabilityTuple",
            "nativeValidateExact12SubmitProofConstruction",
        ):
            with self.subTest(method=method):
                mutated = SOURCE.replace(method + "ForNetworkV1", method)
                self.assertNotEqual(SOURCE, mutated)
                with self.assertRaisesRegex(GUARD.AuditError, "inventory changed"):
                    GUARD.audit_source(mutated)

    def test_rejects_dropped_expected_network_parameter(self) -> None:
        mutated = SOURCE.replace(
            "    expected_network: jni::objects::JByteArray<'_>,\n", "", 1,
        )
        self.assertNotEqual(SOURCE, mutated)
        with self.assertRaisesRegex(GUARD.AuditError, "signature/body contract changed"):
            GUARD.audit_source(mutated)

    def test_rejects_every_retired_android_privacy_export(self) -> None:
        for suffix in GUARD.EXPECTED_SDK_ONLY_SUFFIXES:
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(GUARD.AuditError, "retired Android"):
                    GUARD.audit_source(SOURCE + "\n" + GUARD.ANDROID_PREFIX + suffix)

    def test_confidential_exports_have_one_kotlin_owner(self) -> None:
        source = (REPO_ROOT / "crates/connect_norito_bridge/src/confidential_note_ffi.rs").read_text()
        GUARD.audit_confidential_source(source)
        for method in GUARD.CONFIDENTIAL_PRIVACY_METHODS:
            with self.subTest(method=method):
                symbol = "Java_org_hyperledger_iroha_sdk_privacy_PrivacyNativeBridge_" + method
                with self.assertRaisesRegex(GUARD.AuditError, "inventory changed"):
                    GUARD.audit_confidential_source(source.replace(symbol, "removed", 1))
                with self.assertRaisesRegex(GUARD.AuditError, "retired Android"):
                    GUARD.audit_confidential_source(source + "\n" + symbol.replace("iroha_sdk_", "iroha_android_"))


if __name__ == "__main__":
    unittest.main()
