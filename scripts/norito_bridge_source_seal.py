#!/usr/bin/env python3
"""Compute and verify source seals for production mobile SDK artifacts.

The seal follows the transitive local-package dependency closure of
``connect_norito_bridge`` for every packaged target on the selected mobile
platform.  Platform inputs also bind the SDK sources compiled into the shipping
application: Swift on Apple, and Kotlin/Java on Android.  This keeps the native
artifact and its directly paired SDK source on one authenticated snapshot
without pulling in unrelated workspace tools such as Kagami or test-network
helpers. The explicit ``android-armv7-diagnostic`` profile follows the same
authentication rules for one experimental target; it is not an Android release
profile and does not widen the packaged target inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterable


APPLE_TARGETS = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
)
ANDROID_TARGETS = (
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
)
# Development-only closure; it never widens the admitted Android inventory.
ANDROID_ARMV7_DIAGNOSTIC_TARGETS = ("armv7-linux-androideabi",)
COMMON_ROOT_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "ci/check_connect_norito_bridge_header.sh",
    "ci/privacy_sdk_cargo_lockfile.sh",
    "rust-toolchain.toml",
    "rust-toolchain",
    ".cargo",
    "vendor",
    "scripts/check_mobile_sdk_artifact_pin_commit.py",
    "codec",
    "scripts/check_mobile_sdk_artifacts.sh",
    "scripts/mobile_sdk_android_artifacts.py",
    "scripts/norito_bridge_source_seal.py",
    "scripts/ivm_artifacts.tsv",
    "scripts/run_mobile_hermetic_command.py",
)
APPLE_ROOT_INPUTS = (
    "crates/connect_norito_bridge/RELEASE_NOTES.md",
    "IrohaSwift/Package.swift",
    "IrohaSwift/Package.resolved",
    "IrohaSwift/Sources/IrohaSwift",
    "IrohaSwift/Sources/IrohaSwiftMobileTransports",
    "IrohaSwift/Sources/NoritoBridgeRetention",
    "IrohaSwift/VERSION",
    "scripts/archive_norito_xcframework.py",
    "scripts/build_norito_xcframework.sh",
    "scripts/normalize_pqcrypto_archive.py",
    "scripts/exec_with_file_lock.py",
    "scripts/norito_bridge_apple_slice_handoff.py",
    "scripts/package_mobile_sdk_artifacts.sh",
    "scripts/validate_norito_bridge_archive.py",
    "scripts/update_norito_bridge_swift_pins.py",
    "scripts/validate_norito_bridge_xcframework.py",
    "scripts/norito_bridge_local_integration.py",
)
APPLE_REQUIRED_ROOT_INPUTS = ("IrohaSwift/Package.resolved",)
# CBSI consumes these Gradle builds directly through composite substitution, so
# their shipping JVM sources must be bound alongside the native `.so` closure.
ANDROID_ROOT_INPUTS = (
    "scripts/norito_bridge_local_integration.py",
    "scripts/publish_android_sdk.sh",
    "scripts/android_publish_snapshot.sh",
    "scripts/android_sbom_provenance.sh",
    "scripts/mobile_sdk_android_publication.py",
    "gradle/mobile-sdk-external-android-build.settings.gradle.kts",
    "kotlin/settings.gradle.kts",
    "kotlin/build.gradle.kts",
    "kotlin/gradle.properties",
    "kotlin/gradle/libs.versions.toml",
    "kotlin/gradle/wrapper/gradle-wrapper.jar",
    "kotlin/gradle/wrapper/gradle-wrapper.properties",
    "kotlin/gradlew",
    "kotlin/gradlew.bat",
    "kotlin/core-jvm/build.gradle.kts",
    "kotlin/core-jvm/src/main",
    "kotlin/client-android/build.gradle.kts",
    "kotlin/client-android/src/main",
    "kotlin/kagemusha-wallet-android/build.gradle.kts",
    "kotlin/kagemusha-wallet-android/src/main",
    "kotlin/client-android/consumer-rules.pro",
    "kotlin/kagemusha-wallet-android/consumer-rules.pro",
    "java/norito_java/settings.gradle.kts",
    "java/norito_java/build.gradle.kts",
    "java/norito_java/gradle.properties",
    "java/norito_java/src/main",
    "java/iroha_android/settings.gradle.kts",
    "java/iroha_android/build.gradle.kts",
    "java/iroha_android/gradle.properties",
    "java/iroha_android/schemas/norito_schema_manifest.json",
    "java/iroha_android/core/build.gradle.kts",
    "java/iroha_android/core/src/main",
    "java/iroha_android/src/main",
    "java/iroha_android/android/build.gradle.kts",
    "java/iroha_android/android/src/main",
    "scripts/package_mobile_sdk_artifacts.sh",
    "scripts/mobile_sdk_android_package_inputs.py",
)
PLATFORM_TARGETS = {
    "apple": APPLE_TARGETS,
    "android": ANDROID_TARGETS,
    "android-armv7-diagnostic": ANDROID_ARMV7_DIAGNOSTIC_TARGETS,
}
PLATFORM_ROOT_INPUTS = {
    "apple": APPLE_ROOT_INPUTS,
    "android": ANDROID_ROOT_INPUTS,
    "android-armv7-diagnostic": ANDROID_ROOT_INPUTS
    + ("scripts/inspect_android_armv7_diagnostic.py", "scripts/norito_bridge_local_integration.py"),
}
# Kept as a public union for callers/tests which construct their own input set.
ROOT_INPUTS = tuple(
    dict.fromkeys(COMMON_ROOT_INPUTS + APPLE_ROOT_INPUTS + ANDROID_ROOT_INPUTS
                  + ("scripts/inspect_android_armv7_diagnostic.py",))
)
SNAPSHOT_SCHEMA = "iroha.norito-bridge-source-seal.v1"
CANONICAL_CARGO_LOCK_OWNER = "ci/privacy_sdk_cargo_lockfile.sh"
SWIFT_NATIVE_BRIDGE_PATH = "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
SWIFT_NATIVE_BRIDGE_HASH_KEYS = frozenset(
    {
        "macos-arm64_x86_64",
        "ios-arm64",
        "ios-arm64_x86_64-simulator",
    }
)
SWIFT_NATIVE_BRIDGE_HASH_PIN = re.compile(
    rb'^(?P<prefix>[ \t]+)"(?P<key>macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
    rb': "(?P<digest>[0-9a-f]{64})"(?P<suffix>,?)$',
    re.MULTILINE,
)
SWIFT_NATIVE_BRIDGE_HASH_BLOCK = re.compile(
    rb'^    private static let expectedHashes: \[String: String\] = \[\n'
    rb'(?P<body>(?:[ \t]+"(?:macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
    rb': "[0-9a-f]{64}",\n){2}'
    rb'[ \t]+"(?:macos-arm64_x86_64|ios-arm64|ios-arm64_x86_64-simulator)"'
    rb': "[0-9a-f]{64}"\n)'
    rb'^    \]$',
    re.MULTILINE,
)


# Only public source/build input filenames may be opened by the derived seal. A
# prohibited required input stops the seal; it is never silently dropped.
# .ko is Kotodama source; compiled IVM .to bytecode is a separate input role.
_PUBLIC_SOURCE_SUFFIXES = frozenset({
    ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".inc",
    ".s", ".metal", ".cu", ".proto", ".fbs", ".swift", ".kt", ".java", ".ko",
    ".py", ".sh", ".bat", ".kts", ".gradle", ".properties", ".xml",
    ".toml", ".lock", ".json", ".jsonl", ".yaml", ".yml", ".txt", ".md",
    ".rst", ".adoc", ".csv", ".tsv", ".nrt", ".bin", ".ptx", ".podspec",
    ".template", ".cmake", ".in", ".js", ".ts", ".css", ".html", ".map",
    ".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".snap", ".expect",
    ".hex", ".pub", ".hash", ".sha256", ".checksum",
})
# Exact public consumer-rule resources used by the maintained Android builds.
# This admits their filenames only after the material/provider/path refusal above;
# it does not admit a dotted SPI name or an arbitrary .pro file.
_REVIEWED_PUBLIC_ANDROID_RESOURCE_INPUTS = frozenset({
    "java/iroha_android/core/src/main/resources/META-INF/proguard/iroha3.pro",
    "kotlin/core-jvm/src/main/resources/META-INF/proguard/consumer-proguard-rules.pro",
})
# Exact public trybuild diagnostics in the maintained package closures.
# These are 68 expected originals plus three tracked event-set diagnostic copies
# retained under iroha_data_model_derive/wip; their full bytes remain sealed.
# This admits no other .stderr name or material/provider/path/custody exception.
_REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS = frozenset({
    "crates/iroha_data_model_derive/tests/ui_fail/event_set_identity_duplicate.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/event_set_identity_invalid.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/event_set_identity_missing.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/has_origin_multiple_attributes.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/registrable_builder_identity_duplicate.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/registrable_builder_identity_invalid.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/registrable_builder_identity_missing.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/transparent_api_private_field.stderr",
    "crates/iroha_data_model_derive/tests/ui_fail/transparent_api_private_item.stderr",
    "crates/iroha_data_model_derive/wip/event_set_identity_duplicate.stderr",
    "crates/iroha_data_model_derive/wip/event_set_identity_invalid.stderr",
    "crates/iroha_data_model_derive/wip/event_set_identity_missing.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/generics.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_commas.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_conflicts.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_default_invalid_expr.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_env_without_var.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_no_comma_between_attrs.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/invalid_attrs_struct.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/removed_key_attribute.stderr",
    "crates/iroha_derive/tests/config_base_ui_fail/unsupported_shapes.stderr",
    "crates/iroha_derive/tests/ui_fail/from_variant_conflicting_implementation.stderr",
    "crates/iroha_derive/tests/ui_fail/from_variant_incorrect_attr_placement.stderr",
    "crates/iroha_derive/tests/ui_fail/from_variant_removed_skip_container.stderr",
    "crates/iroha_derive/tests/ui_fail/from_variant_same_type.stderr",
    "crates/iroha_derive/tests/ui_fail/from_variant_skip_try_from_non_newtype.stderr",
    "crates/iroha_derive/tests/ui_fail/struct_from_variant.stderr",
    "crates/iroha_derive/tests/ui_fail/telemetry_future_non_async.stderr",
    "crates/iroha_executor_data_model_derive/tests/ui/fail/parameter_missing_default.stderr",
    "crates/iroha_executor_data_model_derive/tests/ui/fail/parameter_missing_traits.stderr",
    "crates/iroha_executor_data_model_derive/tests/ui/fail/permission_missing_deserialize.stderr",
    "crates/iroha_executor_data_model_derive/tests/ui/fail/permission_missing_serde.stderr",
    "crates/iroha_primitives/tests/ui_fail/must_use_not_used.stderr",
    "crates/iroha_primitives_derive/tests/ui/fail/numeric_empty.stderr",
    "crates/iroha_primitives_derive/tests/ui/fail/numeric_invalid.stderr",
    "crates/iroha_primitives_derive/tests/ui/fail/socket_addr_bad.stderr",
    "crates/iroha_primitives_derive/tests/ui/fail/socket_addr_missing_colon.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/duplicate_binary_validation_hook.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/duplicate_prepared_field_decode.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/enum_duplicate_index.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/malformed_binary_validation_hook.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/transparent_enum_multi_variant.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/transparent_struct_multiple_fields.stderr",
    "crates/iroha_schema_derive/tests/ui_fail/valued_prepared_field_decode.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/args_no_wsv.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/bare_spec.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/doubled_plus.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/metric_name_with_space.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/no_args.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/non_snake_case_name.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/not_execute.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/not_return_result.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/return_nothing.stderr",
    "crates/iroha_telemetry_derive/tests/ui_fail/trailing_plus.stderr",
    "crates/norito_derive/tests/ui/fail/attrs_conflict_named.stderr",
    "crates/norito_derive/tests/ui/fail/attrs_conflict_tuple.stderr",
    "crates/norito_derive/tests/ui/fail/attrs_tuple_rename.stderr",
    "crates/norito_derive/tests/ui/fail/enum_duplicate_index.stderr",
    "crates/norito_derive/tests/ui/fail/fastjson_enum.stderr",
    "crates/norito_derive/tests/ui/fail/frame_identity_schema_name.stderr",
    "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr",
    "crates/norito_derive/tests/ui/fail/json_enum_missing_tag.stderr",
    "crates/norito_derive/tests/ui/fail/json_required_option_misuse.stderr",
    "crates/norito_derive/tests/ui/fail/prepared_record_generic.stderr",
    "crates/norito_derive/tests/ui/fail/prepared_record_tuple.stderr",
    "crates/norito_derive/tests/ui/fail/prepared_record_unit.stderr",
    "crates/norito_derive/tests/ui/fail/prepared_record_validation.stderr",
    "crates/norito_derive/tests/ui/fail/schema_identity_duplicate.stderr",
    "crates/norito_derive/tests/ui/fail/schema_identity_generic_frame.stderr",
    "crates/norito_derive/tests/ui/fail/schema_identity_missing.stderr",
    "crates/norito_derive/tests/ui/fail/schema_identity_nested.stderr",
})
# Exact checked-in IVM goldens owned by scripts/ivm_artifacts.tsv: 43 paired
# Kotodama outputs and two canonical predecoder fixtures. Source intake seals
# the full bytes; it grants no compilation, deployment or runtime qualification.
# No other .to file (including a SoraFS deployment manifest) is admitted.
_REVIEWED_PUBLIC_IVM_ARTIFACT_INPUTS = frozenset({
    "crates/iroha/tests/fixtures/contract_code_readback/code_readback.to",
    "crates/ivm/docs/examples/01_hajimari.to",
    "crates/ivm/docs/examples/02_view_public_fn.to",
    "crates/ivm/docs/examples/03_kaizen_permission.to",
    "crates/ivm/docs/examples/04_foreach_map.to",
    "crates/ivm/docs/examples/05_range_for.to",
    "crates/ivm/docs/examples/06_map_ops.to",
    "crates/ivm/docs/examples/07_set_detail_authority.to",
    "crates/ivm/docs/examples/08_call_transfer_asset.to",
    "crates/ivm/docs/examples/09_struct_and_state.to",
    "crates/ivm/docs/examples/10_meta_header.to",
    "crates/ivm/docs/examples/11_detail_and_transfer.to",
    "crates/ivm/docs/examples/12_nft_flow.to",
    "crates/ivm/docs/examples/13_register_and_mint.to",
    "crates/ivm/docs/examples/14_map_sum_take2.to",
    "crates/ivm/docs/examples/15_modulo.to",
    "crates/ivm/docs/examples/16_register_domain.to",
    "crates/ivm/docs/examples/18_ternary.to",
    "crates/ivm/docs/examples/19_contract_flow_test.to",
    "crates/ivm/tests/data/add.to",
    "crates/ivm/tests/data/amm.to",
    "crates/ivm/tests/data/complex.to",
    "crates/ivm/tests/data/control.to",
    "crates/ivm/tests/data/mfc.to",
    "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode00_vlen0_cycles0_abi1.to",
    "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode03_vlen8_cycles1000_abi1.to",
    "crates/kotodama_lang/src/samples/asset_ops.to",
    "crates/kotodama_lang/src/samples/create_nft_for_every_user_trigger.to",
    "crates/kotodama_lang/src/samples/dex_contract.to",
    "crates/kotodama_lang/src/samples/dex_simple.to",
    "crates/kotodama_lang/src/samples/domain_ops.to",
    "crates/kotodama_lang/src/samples/irohaswap.to",
    "crates/kotodama_lang/src/samples/kotodama_swap.to",
    "crates/kotodama_lang/src/samples/lending_simple.to",
    "crates/kotodama_lang/src/samples/mint_rose_trigger.to",
    "crates/kotodama_lang/src/samples/native_escrow.to",
    "crates/kotodama_lang/src/samples/perp_funding.to",
    "crates/kotodama_lang/src/samples/query_assets_and_save_cursor.to",
    "crates/kotodama_lang/src/samples/smart_contract_can_filter_queries.to",
    "crates/kotodama_lang/src/samples/stablecoin_simple.to",
    "crates/kotodama_lang/src/samples/subscription_billing_trigger.to",
    "crates/kotodama_lang/src/samples/subscription_usage_recorder.to",
    "crates/kotodama_lang/src/samples/threshold_escrow.to",
    "crates/kotodama_lang/src/samples/tuple_return_demo.to",
    "crates/kotodama_lang/src/samples/zk_vote_ballot.to",
})
# These named public Rust modules and predecoder fixture inputs happen to live
# in directories named artifacts/run. Only those two directory words are
# excepted for these exact files; every other operational/material gate remains.
_REVIEWED_PUBLIC_SOURCE_FOLDER_INPUTS = frozenset({
    "crates/iroha_core/src/sumeragi/certified_chain/artifacts/tests.rs",
    "crates/iroha_p2p/src/peer/run/admission_class_tests.rs",
    "crates/iroha_p2p/src/peer/run/granted.rs",
    "crates/iroha_p2p/src/peer/run/payload_codec_tests.rs",
    "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode00_vlen0_cycles0_abi1.to",
    "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode03_vlen8_cycles1000_abi1.to",
})
# Fixed public parser seeds, offsets, codec/checksum goldens, normative grammar,
# Objective-C source and the embedded Metal library, traced to their source
# owners. There is no general binary, extensionless or uncommon-suffix role.
_REVIEWED_PUBLIC_FIXTURE_INPUTS = frozenset({
    "crates/iroha_core/tests/fixtures/repo_lifecycle_proof.digest",
    "crates/iroha_core_privacy/src/privacy_engines/fcmp_plus_plus/test_vectors/SHA256SUMS",
    "crates/ivm/fuzz/corpus/artifact_admission_v1/canonical_seed",
    "crates/ivm/fuzz/corpus/artifact_admission_v1/raw_malformed_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/arithmetic_full_width_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/arithmetic_rounding_tie_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/raw_malformed_envelope_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/raw_malformed_frame_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/staged_oog_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/valid_decimal_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/valid_int_seed",
    "crates/ivm/fuzz/corpus/numeric_v1/valid_quantity_seed",
    "crates/ivm/fuzz/corpus/tlv_validate/acdef51ee223031b697842004824832b9eed6272",
    "crates/ivm/metal/v1/ivm_kernels.metallib",
    "crates/kotodama_lang/grammar/v1.lex",
    "crates/norito/accelerators/jsonstage1_metal/src/metal.m",
    "crates/norito/tests/data/escaped_quote.tape",
    "crates/norito/tests/data/small_a1.tape",
    "crates/norito/tests/data/small_empty.tape",
    "crates/norito/tests/data/string_x.tape",
    "crates/norito/tests/data/two_backslashes.tape",
    "crates/norito/tests/fixtures/sample_payload_frame.norito",
    "crates/sorafs_manifest/src/signer/final_promotion/tests/statement_fixture.message",
})
# Two exact MockEnv inputs and two static compiler/contract assets have names
# caught by the material rule. Their public, non-operational roles are bound to
# reviewed complete bytes through the existing no-follow reader. These are
# source-fixture pins, never credential, signing or runtime authority inputs.
_REVIEWED_PUBLIC_STATIC_CONTRACT_INPUTS = frozenset({
    "crates/iroha_zkp_halo2/src/generalized_bulletproof_secret_cleanup_contracts_v1.txt",
    "crates/kotodama_lang/src/assets/diagnostics_v1/secret_reject_cases_v1.tsv",
})
_REVIEWED_PUBLIC_MOCK_ENV_INPUTS = frozenset({
    "crates/iroha_config/tests/fixtures/full.env",
    "crates/iroha_config/tests/fixtures/minimal_file_and_env.env",
})
_REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS = {
    "crates/iroha_config/tests/fixtures/full.env": ("3f0cd58caab9edb0f4f3c02c9788962854d996d6de949af36508cce01b9a24dd", 2249),
    "crates/iroha_config/tests/fixtures/minimal_file_and_env.env": ("196c68787e11f84107aaa983a5cb02a97b5d2ef6f860269c85920a1baf5817f5", 26),
    "crates/iroha_zkp_halo2/src/generalized_bulletproof_secret_cleanup_contracts_v1.txt": ("06f3e6f960e02cb8a452e85d634d6b5b7518ac511d9ab98c69d2ba3e42d8eb4f", 53080),
    "crates/kotodama_lang/src/assets/diagnostics_v1/secret_reject_cases_v1.tsv": ("0d62f715c83be396e55b2abb499e7e59a497f1ebeff60e1768ac50bff617714a", 3261),
}

_MATERIAL_SUFFIXES = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdb", ".asc",
    ".der", ".crt", ".cer", ".mobileprovision", ".env",
})
_PROHIBITED_SOURCE_PARTS = frozenset({
    "credentials", "secrets", "materials", "private", "private-fixtures",
    "private_fixtures", "key-material", "key_material", ".ssh", ".kube",
    ".aws", ".gcloud", "deploy", "deployment", "deployments", "infra",
    "infrastructure", "ops", "operations", "terraform", "ansible", "target",
    "build", "artifacts", "output", "run", "runs", ".git", ".codex",
    "node_modules",
})
_MATERIAL_FILENAME = re.compile(
    r"(^|[-_.])(credentials?|creds|secrets?|passwords?|service[-_]account|"
    r"google[-_]services|firebase[-_]admin|id_rsa|id_ed25519|private[-_]key|"
    r"api[-_]key|auth[-_]token)([-_.]|$)", re.IGNORECASE,
)
_CODE_SUFFIXES = frozenset({
    ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".inc",
    ".s", ".metal", ".cu", ".proto", ".fbs", ".swift", ".kt", ".java", ".ko",
    ".py", ".sh", ".bat", ".kts", ".js", ".ts",
})
_PUBLIC_BASENAMES = frozenset({
    "Cargo.toml", "Cargo.lock", "Package.swift", "Package.resolved", "VERSION",
    "rust-toolchain", "Makefile", "CMakeLists.txt", "LICENSE", "NOTICE",
    "README", ".gitignore", ".gitattributes", ".cargo-checksum.json",
})


# Reviewed exact vendor roles: original Cargo manifests named by their normalized
# owners, spelling ignore words consumed by Concread's Makefile, and deterministic
# public BLS generator vectors included by the curve tests. This does not admit
# any other .orig/.dat filename or override material/provider/alias refusal.
_REVIEWED_PUBLIC_VENDOR_INPUTS = frozenset({
    "vendor/concread/.codespell_ignore",
    "vendor/axum-core/Cargo.toml.orig",
    "vendor/bytes/Cargo.toml.orig",
    "vendor/http-body-util/Cargo.toml.orig",
    "vendor/concread/Cargo.toml.orig",
    "vendor/wayland-scanner-0.31.10/Cargo.toml.orig",
})

# Exact public parser seeds reviewed from the Norito cargo-fuzz owners. The
# pinned declaration travels with a frozen working-source cut; it never changes
# the snapshot Git index or admits arbitrary untracked/ignored hexadecimal files.
_NORITO_PUBLIC_CORPUS_MANIFEST = "crates/norito/fuzz/public_corpus_manifest.json"
_NORITO_PUBLIC_CORPUS_MANIFEST_SHA256 = "6614365dae962dd554f4c47760f89a565d3b820396a6891d89a9f69af2ef7166"
_NORITO_PUBLIC_CORPUS_SEED_COUNT = 741
_NORITO_PUBLIC_CORPUS_TARGETS = frozenset({
    "json_from_json_equiv", "json_parse_string", "json_parse_string_ref", "json_skip_value",
})


def _norito_public_corpus_path(relative: str) -> bool:
    path = pathlib.PurePosixPath(relative)
    return (len(path.parts) == 6 and path.parts[:4] == ("crates", "norito", "fuzz", "corpus")
            and path.parts[4] in _NORITO_PUBLIC_CORPUS_TARGETS
            and re.fullmatch(r"[0-9a-f]{40}", path.name) is not None)


def _public_source_relative(
    relative: str, *, file_name: bool = True,
    reviewed_corpus_inputs: frozenset[str] = frozenset(),
) -> pathlib.PurePosixPath:
    """Admit a canonical public filename before filesystem or content intake."""
    path = pathlib.PurePosixPath(relative)
    if (not relative or path.is_absolute() or path.as_posix() != relative
            or ".." in path.parts or "\\" in relative
            or any(ord(character) < 32 or ord(character) == 127 for character in relative)):
        raise RuntimeError(f"source-seal input path is not canonical: {relative!r}")
    lower = relative.lower()
    reviewed_fixture = relative in _REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS
    if (any(part.lower() in _PROHIBITED_SOURCE_PARTS
            and not (relative in _REVIEWED_PUBLIC_SOURCE_FOLDER_INPUTS
                     and part.lower() in {"artifacts", "run"}) for part in path.parts)
            or "vultr" in lower or "sydneycreds" in lower
            or (path.suffix.lower() in _MATERIAL_SUFFIXES
                and not (relative in _REVIEWED_PUBLIC_MOCK_ENV_INPUTS
                         and path.suffix == ".env"))
            or path.name.lower().startswith(".env")
            or (path.suffix.lower() not in _CODE_SUFFIXES
                and _MATERIAL_FILENAME.search(path.name)
                and relative not in _REVIEWED_PUBLIC_STATIC_CONTRACT_INPUTS)):
        raise RuntimeError(f"source-seal input is prohibited material or operational input: {relative}")
    if file_name and not (relative in ROOT_INPUTS
            or relative in _REVIEWED_PUBLIC_VENDOR_INPUTS
            or relative in _REVIEWED_PUBLIC_ANDROID_RESOURCE_INPUTS
            or relative in _REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS
            or relative in _REVIEWED_PUBLIC_IVM_ARTIFACT_INPUTS
            or relative in _REVIEWED_PUBLIC_SOURCE_FOLDER_INPUTS
            or relative in _REVIEWED_PUBLIC_FIXTURE_INPUTS
            or reviewed_fixture
            or relative in reviewed_corpus_inputs
            or path.suffix.lower() in _PUBLIC_SOURCE_SUFFIXES
            or path.name in _PUBLIC_BASENAMES
            or path.name.startswith(("LICENSE-", "LICENSE.", "COPYING", "COPYRIGHT",
                                     "NOTICE", "AUTHORS", "CHANGELOG", "README"))):
        raise RuntimeError(f"source-seal input is not an admitted public filename: {relative}")
    return path


def _source_path_metadata(
    root: pathlib.Path, relative: str, *, allow_directory: bool = False,
) -> tuple[pathlib.Path, dict[pathlib.Path, tuple[object, ...]]]:
    """Reject every ancestor alias before admitting a source content descriptor."""
    # Fixed public roles never bypass provider/canonical-name or descriptor custody.
    # Every other material/operational path is refused before content intake.
    relative_path = _public_source_relative(relative, file_name=False)
    corpus_entry = None
    corpus_identities = {}
    if not allow_directory and _norito_public_corpus_path(relative):
        corpus_inputs, corpus_identities = _reviewed_norito_public_corpus(root)
        _public_source_relative(relative, reviewed_corpus_inputs=frozenset(corpus_inputs))
        corpus_entry = corpus_inputs[relative]
    else:
        _public_source_relative(relative, file_name=not allow_directory)
    if not root.is_absolute() or root != pathlib.Path(os.path.abspath(root)):
        raise RuntimeError("source-seal root must be absolute and canonical")
    source = root.joinpath(*relative_path.parts)
    identities: dict[pathlib.Path, tuple[object, ...]] = {}
    for component in (*reversed(source.parents), source):
        value = component.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise RuntimeError(f"source-seal input is symlinked: {relative}")
        if component != source and not stat.S_ISDIR(value.st_mode):
            raise RuntimeError(f"source-seal ancestor is not a directory: {relative}")
        if component == source and not (stat.S_ISREG(value.st_mode)
                or (allow_directory and stat.S_ISDIR(value.st_mode))):
            raise RuntimeError(f"source-seal input is not a regular file: {relative}")
        identities[component] = (_source_directory_identity(value)
            if stat.S_ISDIR(value.st_mode) else _source_identity(value))
    if corpus_entry is not None:
        for component, identity in corpus_identities.items():
            if component in identities and identities[component] != identity:
                raise RuntimeError(f"source-seal corpus declaration ancestor changed: {relative}")
            identities[component] = identity
        declaration = root / _NORITO_PUBLIC_CORPUS_MANIFEST
        identities[declaration] += ("reviewed-public-corpus", _NORITO_PUBLIC_CORPUS_MANIFEST_SHA256,
                                  corpus_entry["sha256"], corpus_entry["bytes"])
    return source, identities


def _source_directory_identity(value: os.stat_result) -> tuple[object, ...]:
    # Directory timestamps/link counts can change for unrelated admitted children;
    # device/inode/type binding and O_NOFOLLOW authenticate this exact traversal.
    return (value.st_dev, value.st_ino, value.st_mode)


def _source_identity(value: os.stat_result) -> tuple[object, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_public_source_bytes(root: pathlib.Path, relative: str) -> bytes:
    """Read only the admitted file through a complete no-follow descriptor walk."""
    source, initial = _source_path_metadata(root, relative)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("source-seal no-follow directory descriptors are unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory = pathlib.Path(source.anchor)
    descriptor = os.open(directory, directory_flags)
    try:
        if _source_directory_identity(os.fstat(descriptor)) != initial[directory]:
            raise RuntimeError(f"source-seal ancestor changed before content intake: {relative}")
        for part in source.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            directory /= part
            if _source_directory_identity(os.fstat(descriptor)) != initial[directory]:
                raise RuntimeError(f"source-seal ancestor changed before content intake: {relative}")
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(source.name, flags, dir_fd=descriptor), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or _source_identity(before) != initial[source]:
                raise RuntimeError(f"source-seal input changed before content intake: {relative}")
            contents = stream.read()
            after = os.fstat(stream.fileno())
            _, current = _source_path_metadata(root, relative)
            if (_source_identity(after) != initial[source] or current != initial
                    or len(contents) != after.st_size):
                raise RuntimeError(f"source-seal input changed while authenticating: {relative}")
            reviewed_fixture = _REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS.get(relative)
            if reviewed_fixture is not None:
                digest, size = reviewed_fixture
                if (len(contents) != size
                        or hashlib.sha256(contents).hexdigest() != digest):
                    raise RuntimeError(f"source-seal public fixture differs from its reviewed original: {relative}")
            if _norito_public_corpus_path(relative):
                declaration = initial[root / _NORITO_PUBLIC_CORPUS_MANIFEST]
                if (len(contents) != declaration[-1]
                        or hashlib.sha256(contents).hexdigest() != declaration[-2]
                        or hashlib.sha1(contents).hexdigest() != source.name):
                    raise RuntimeError(f"source-seal corpus original differs from its reviewed role: {relative}")
            return contents
    finally:
        os.close(descriptor)


def _reviewed_norito_public_corpus(
    root: pathlib.Path,
) -> tuple[dict[str, dict[str, object]], dict[pathlib.Path, tuple[object, ...]]]:
    """Authenticate the exact public seed declaration through the same no-follow reader."""
    try:
        _, initial = _source_path_metadata(root, _NORITO_PUBLIC_CORPUS_MANIFEST)
        contents = _read_public_source_bytes(root, _NORITO_PUBLIC_CORPUS_MANIFEST)
        _, current = _source_path_metadata(root, _NORITO_PUBLIC_CORPUS_MANIFEST)
    except FileNotFoundError as error:
        raise RuntimeError("source-seal required public corpus declaration is missing") from error
    if (current != initial
            or hashlib.sha256(contents).hexdigest() != _NORITO_PUBLIC_CORPUS_MANIFEST_SHA256):
        raise RuntimeError("source-seal public corpus declaration differs from its reviewed original")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError("source-seal public corpus declaration has duplicate object keys")
            value[key] = item
        return value

    try:
        value = json.loads(contents, object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("source-seal public corpus declaration is not canonical JSON") from error
    if (not isinstance(value, dict) or set(value) != {"schema", "entries"}
            or value["schema"] != "iroha.norito.public-fuzz-corpus.v1"
            or not isinstance(value["entries"], list)
            or len(value["entries"]) != _NORITO_PUBLIC_CORPUS_SEED_COUNT):
        raise RuntimeError("source-seal public corpus declaration has an unreviewed shape")
    entries = {}
    for item in value["entries"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}:
            raise RuntimeError("source-seal public corpus declaration has an unreviewed entry")
        relative = item["path"]
        if not isinstance(relative, str):
            raise RuntimeError("source-seal public corpus declaration path is not text")
        _public_source_relative(relative, file_name=False)
        if (not _norito_public_corpus_path(relative) or relative in entries
                or not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or type(item["bytes"]) is not int or item["bytes"] < 0):
            raise RuntimeError("source-seal public corpus declaration has an unreviewed entry")
        entries[relative] = item
    if list(entries) != sorted(entries):
        raise RuntimeError("source-seal public corpus declaration is not ordered")
    return entries, initial


class AuthenticatedTool:
    """One tool's proxy invocation and authenticated canonical executable."""

    __slots__ = ("invocation", "canonical", "canonical_identity")

    def __init__(
        self,
        *,
        invocation: pathlib.Path,
        canonical: pathlib.Path,
        canonical_identity: tuple[int, int, int, int, int],
    ) -> None:
        self.invocation = invocation
        self.canonical = canonical
        self.canonical_identity = canonical_identity

    def authenticate(self) -> None:
        try:
            canonical = self.invocation.resolve(strict=True)
            stat_result = canonical.stat()
        except OSError as error:
            raise RuntimeError(
                f"source-seal tool became unavailable: {self.invocation}"
            ) from error
        identity = (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_mode,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        )
        if canonical != self.canonical or identity != self.canonical_identity:
            raise RuntimeError(
                f"source-seal tool changed after authentication: {self.invocation}"
            )


def required_tool(environment_name: str, fallback_name: str) -> AuthenticatedTool:
    configured = os.environ.get(environment_name)
    candidate = pathlib.Path(configured) if configured else None
    if candidate is None:
        discovered = shutil.which(fallback_name)
        if discovered is None:
            raise RuntimeError(f"required source-seal tool is unavailable: {fallback_name}")
        candidate = pathlib.Path(discovered)
    if not candidate.is_absolute():
        raise RuntimeError(f"{environment_name} must name an absolute executable")
    invocation = pathlib.Path(os.path.abspath(candidate))
    canonical = invocation.resolve(strict=True)
    if not canonical.is_file() or not os.access(canonical, os.X_OK):
        raise RuntimeError(f"source-seal tool is not a regular executable: {canonical}")
    stat_result = canonical.stat()
    return AuthenticatedTool(
        invocation=invocation,
        canonical=canonical,
        canonical_identity=(
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_mode,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        ),
    )


def source_seal_home() -> pathlib.Path:
    configured = os.environ.get("NORITO_BRIDGE_SEAL_HOME")
    if configured:
        candidate = pathlib.Path(configured)
        if not candidate.is_absolute():
            raise RuntimeError("NORITO_BRIDGE_SEAL_HOME must be absolute")
        return candidate.resolve(strict=True)
    if os.name == "posix":
        import pwd

        return pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    return pathlib.Path.home().resolve(strict=True)


def canonical_cargo_lock_sha256(root: pathlib.Path) -> str:
    """Read the sole reviewed graph declaration without executing shell source."""
    path = root / CANONICAL_CARGO_LOCK_OWNER
    _, contents = _read_canonical_regular_bytes(
        path, "canonical Cargo graph owner", allow_executable=True,
    )
    try:
        source = contents.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("canonical Cargo graph owner must be UTF-8") from error
    declaration = "readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"
    if len(re.findall(r"(?m)^[ \t]*readonly[ \t]+PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=", source)) != 1:
        raise RuntimeError("exactly one canonical Cargo graph declaration is required")
    matches = re.findall(r'^' + re.escape(declaration) + r'"([0-9a-f]{64})"$', source, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError("canonical Cargo graph declaration must contain one exact lowercase SHA-256")
    return matches[0]


def selected_lockfile_path(
    root: pathlib.Path, configured: pathlib.Path | None = None
) -> pathlib.Path:
    """Authenticate the caller's explicit root or reviewed external build lock."""

    if configured is None:
        raise RuntimeError("an explicit --lockfile-path selection is required")
    candidate = configured
    lockfile_identity(candidate)
    root_lock = root / "Cargo.lock"
    lockfile_identity(root_lock)
    if candidate != root_lock:
        if root == candidate or root in candidate.parents:
            raise RuntimeError("alternate Cargo lock must be outside the source root")
        expected = canonical_cargo_lock_sha256(root)
        if lockfile_identity(root_lock)[-1] != expected:
            raise RuntimeError("root source Cargo lock does not match the canonical reviewed graph")
        if lockfile_identity(candidate)[-1] != expected:
            raise RuntimeError("external Cargo lock does not match the canonical reviewed graph")
    return candidate


def _read_canonical_regular_bytes(
    candidate: pathlib.Path, label: str, *, allow_executable: bool = False,
) -> tuple[tuple[object, ...], bytes]:
    """Bind the bytes read to the same canonical pathname and open descriptor."""
    if not candidate.is_absolute() or candidate != pathlib.Path(os.path.abspath(candidate)):
        raise RuntimeError(f"{label} path must be absolute and canonical")
    maximum = 16 * 1024 * 1024
    def identity(value: os.stat_result) -> tuple[object, ...]:
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    try:
        initial = candidate.lstat()
        if candidate.resolve(strict=True) != candidate or not stat.S_ISREG(initial.st_mode):
            raise RuntimeError(f"{label} must be a non-symbolic regular file")
        # NONBLOCK prevents a regular-file-to-FIFO race from blocking admission.
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(os.open(candidate, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError(f"{label} must be a non-symbolic regular file")
            if identity(initial) != identity(before):
                raise RuntimeError(f"{label} changed while being authenticated")
            if before.st_nlink != 1 or (not allow_executable and before.st_mode & 0o111):
                raise RuntimeError(f"{label} must be singly linked and non-executable")
            if not 0 < before.st_size <= maximum:
                raise RuntimeError(f"{label} must contain between 1 byte and 16 MiB")
            contents = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            current = candidate.lstat()
            if (identity(before) != identity(after) or identity(before) != identity(current)
                    or len(contents) != before.st_size or candidate.resolve(strict=True) != candidate):
                raise RuntimeError(f"{label} changed while being authenticated")
    except OSError as error:
        raise RuntimeError(f"{label} must be a non-symbolic regular file") from error
    return identity(after), contents


def lockfile_identity(candidate: pathlib.Path) -> tuple[object, ...]:
    """Read a canonical lock while binding its inode, metadata and exact bytes."""
    identity, contents = _read_canonical_regular_bytes(candidate, "selected Cargo lock")
    return (*identity, hashlib.sha256(contents).hexdigest())


def source_seal_environment(
    *,
    cargo: AuthenticatedTool,
    rustc: AuthenticatedTool,
    rustdoc: AuthenticatedTool,
    git: pathlib.Path,
) -> dict[str, str]:
    home = source_seal_home()
    cargo_home = pathlib.Path(
        os.environ.get("NORITO_BRIDGE_SEAL_CARGO_HOME", str(home / ".cargo"))
    )
    rustup_home = pathlib.Path(
        os.environ.get("NORITO_BRIDGE_SEAL_RUSTUP_HOME", str(home / ".rustup"))
    )
    temporary_directory = pathlib.Path(
        os.environ.get("NORITO_BRIDGE_SEAL_TMPDIR", "/tmp")
    )
    for label, path in (
        ("NORITO_BRIDGE_SEAL_CARGO_HOME", cargo_home),
        ("NORITO_BRIDGE_SEAL_RUSTUP_HOME", rustup_home),
        ("NORITO_BRIDGE_SEAL_TMPDIR", temporary_directory),
    ):
        if not path.is_absolute():
            raise RuntimeError(f"{label} must be absolute")
    path_entries = tuple(
        dict.fromkeys(
            (
                str(cargo.invocation.parent),
                str(rustc.invocation.parent),
                str(rustdoc.invocation.parent),
                str(git.parent),
                "/usr/bin",
                "/bin",
            )
        )
    )
    environment = {
        "CARGO": str(cargo.invocation),
        "CARGO_BUILD_JOBS": "1",
        "CARGO_HOME": str(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join(path_entries),
        "RUSTC": str(rustc.invocation),
        "RUSTDOC": str(rustdoc.invocation),
        "RUSTUP_HOME": str(rustup_home),
        "TMPDIR": str(temporary_directory),
    }
    configured_target = os.environ.get("NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR")
    if not configured_target:
        raise RuntimeError("NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR is required")
    target = pathlib.Path(configured_target)
    if not target.is_absolute() or target != pathlib.Path(os.path.abspath(target)):
        raise RuntimeError(
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR must be an absolute canonical directory"
        )
    try:
        metadata = target.lstat()
        resolved = target.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR is unavailable"
        ) from error
    if (
        resolved != target
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise RuntimeError(
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR must be a non-symbolic "
            "canonical directory"
        )
    environment["CARGO_TARGET_DIR"] = str(target)
    return environment


def source_seal_tools() -> tuple[
    AuthenticatedTool, AuthenticatedTool, AuthenticatedTool, pathlib.Path
]:
    git = pathlib.Path("/usr/bin/git").resolve(strict=True)
    if not git.is_file() or not os.access(git, os.X_OK):
        raise RuntimeError("pinned source-seal Git executable is unavailable")
    return (
        required_tool("NORITO_BRIDGE_SEAL_CARGO", "cargo"),
        required_tool("NORITO_BRIDGE_SEAL_RUSTC", "rustc"),
        required_tool("NORITO_BRIDGE_SEAL_RUSTDOC", "rustdoc"),
        git,
    )


def run(
    root: pathlib.Path,
    executable: AuthenticatedTool | pathlib.Path,
    args: list[str],
    environment: dict[str, str],
) -> bytes:
    if isinstance(executable, AuthenticatedTool):
        executable.authenticate()
        invocation = executable.invocation
        canonical = executable.canonical
    else:
        invocation = executable
        canonical = executable
    arguments = args
    if canonical == pathlib.Path("/usr/bin/git").resolve(strict=True):
        # Git repository-local settings and persistent replacement refs are
        # outside the authenticated source bytes. Read-only seal operations
        # must neither reinterpret those bytes nor execute a local monitor.
        arguments = [
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ]
    try:
        result = subprocess.run(
            [str(invocation), *arguments],
            executable=str(canonical),
            cwd=root,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
    finally:
        if isinstance(executable, AuthenticatedTool):
            executable.authenticate()
    return result


def metadata(
    root: pathlib.Path,
    target: str,
    lockfile_path: pathlib.Path | None = None,
    *, android_armv7_diagnostic: bool = False,
) -> dict[str, object]:
    lockfile = selected_lockfile_path(root, lockfile_path)
    lock_identity_before = lockfile_identity(lockfile)
    root_lock = root / "Cargo.lock"
    root_lock_identity_before = lockfile_identity(root_lock)
    cargo, rustc, rustdoc, git = source_seal_tools()
    rustc.authenticate()
    rustdoc.authenticate()
    environment = source_seal_environment(
        cargo=cargo, rustc=rustc, rustdoc=rustdoc, git=git
    )
    configuration_owner = None
    configuration = None
    invocation_directory = root
    invocation_observation = None
    diagnostic_configuration = None
    cargo_configuration = None
    if android_armv7_diagnostic:
        if target not in ANDROID_ARMV7_DIAGNOSTIC_TARGETS:
            raise RuntimeError("Android diagnostic metadata requires the exact armv7 target")
        diagnostic_configuration = android_armv7_diagnostic_configuration(root)
    if target in APPLE_TARGETS + ANDROID_TARGETS:
        helper = pathlib.Path(__file__).with_name("run_mobile_hermetic_command.py")
        specification = importlib.util.spec_from_file_location(
            "norito_bridge_build_configuration", helper
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("Native Cargo configuration owner is unavailable")
        configuration_owner = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(configuration_owner)
        configured_invocation = os.environ.get("NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR", str(root))
        if configured_invocation != str(root):
            if target in ANDROID_TARGETS and not android_armv7_diagnostic:
                cargo_configuration = android_cargo_configuration(root)
            invocation_observation = configuration_owner.authenticate_cargo_invocation_directory(
                root, pathlib.Path(configured_invocation)
            )
            invocation_directory = invocation_observation[0]
        configuration = configuration_owner.authenticate_build_cargo_configuration(
            invocation_directory, pathlib.Path(environment["CARGO_HOME"])
        )
    try:
        output = run(
            invocation_directory,
            cargo,
            [
                "metadata",
                "--locked",
                "--offline",
                "--manifest-path",
                str(root / "Cargo.toml"),
                "--format-version",
                "1",
                "--features",
                "connect_norito_bridge/privacy-production-enabled",
                "--filter-platform",
                target,
            ],
            environment,
        )
    finally:
        rustc.authenticate()
        rustdoc.authenticate()
        if configuration_owner is not None:
            configuration_owner.recheck_build_cargo_configuration(configuration)
            if invocation_observation is not None:
                configuration_owner.recheck_cargo_invocation_directory(root, invocation_observation)
        if (diagnostic_configuration is not None
                and android_armv7_diagnostic_configuration(root) != diagnostic_configuration):
            raise RuntimeError("Android diagnostic configuration changed during metadata authentication")
        if (cargo_configuration is not None
                and android_cargo_configuration(root) != cargo_configuration):
            raise RuntimeError("Android Cargo configuration changed during metadata authentication")
        if lockfile_identity(lockfile) != lock_identity_before:
            raise RuntimeError("selected Cargo lock changed during metadata authentication")
        if lockfile_identity(root_lock) != root_lock_identity_before:
            raise RuntimeError("root Cargo lock changed during metadata authentication")
    return json.loads(output)


def local_dependency_roots(
    root: pathlib.Path,
    targets: Iterable[str] = APPLE_TARGETS,
    lockfile_path: pathlib.Path | None = None,
    *, android_armv7_diagnostic: bool = False,
) -> set[str]:
    package_roots: set[pathlib.Path] = set()
    for target in targets:
        document = (
            metadata(root, target, lockfile_path, android_armv7_diagnostic=True)
            if android_armv7_diagnostic else metadata(root, target, lockfile_path)
        )
        packages = {
            package["id"]: package
            for package in document["packages"]
            if isinstance(package, dict)
        }
        resolve = document.get("resolve")
        if not isinstance(resolve, dict):
            raise RuntimeError("cargo metadata did not return a resolve graph")
        nodes = {
            node["id"]: node
            for node in resolve.get("nodes", [])
            if isinstance(node, dict)
        }
        roots = [
            package_id
            for package_id, package in packages.items()
            if package.get("name") == "connect_norito_bridge"
            and pathlib.Path(str(package["manifest_path"])).resolve()
            == (root / "crates/connect_norito_bridge/Cargo.toml").resolve()
        ]
        if len(roots) != 1:
            raise RuntimeError(
                f"expected one connect_norito_bridge package for {target}, found {len(roots)}"
            )

        pending = roots
        visited: set[str] = set()
        while pending:
            package_id = pending.pop()
            if package_id in visited:
                continue
            visited.add(package_id)
            node = nodes.get(package_id)
            if node is None:
                raise RuntimeError(f"missing resolve node for {package_id}")
            for dependency in node.get("deps", []):
                if isinstance(dependency, dict) and isinstance(dependency.get("pkg"), str):
                    pending.append(dependency["pkg"])

        for package_id in visited:
            package = packages.get(package_id)
            if package is None:
                continue
            manifest = pathlib.Path(str(package["manifest_path"])).resolve()
            try:
                relative = manifest.parent.relative_to(root)
            except ValueError:
                continue
            package_roots.add(relative)

    return {path.as_posix() for path in package_roots}


def seal_inputs(
    root: pathlib.Path,
    platform: str = "apple",
    lockfile_path: pathlib.Path | None = None,
) -> list[str]:
    lockfile = selected_lockfile_path(root, lockfile_path)
    try:
        targets = PLATFORM_TARGETS[platform]
        platform_inputs = PLATFORM_ROOT_INPUTS[platform]
    except KeyError as error:
        raise RuntimeError(f"unsupported source-seal platform: {platform}") from error
    if platform == "apple":
        for value in APPLE_REQUIRED_ROOT_INPUTS:
            required = root / value
            try:
                metadata = required.lstat()
            except OSError as error:
                raise RuntimeError(f"required Apple source-seal input is missing: {value}") from error
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    f"required Apple source-seal input is not a regular file: {value}"
                )
    candidates = set(COMMON_ROOT_INPUTS)
    candidates.update(platform_inputs)
    candidates.update(
        local_dependency_roots(root, targets, lockfile, android_armv7_diagnostic=True)
        if platform == "android-armv7-diagnostic"
        else local_dependency_roots(root, targets, lockfile)
    )
    existing = [
        value
        for value in candidates
        if (root / value).exists()
    ]
    return sorted(existing)


def listed_files(
    root: pathlib.Path,
    inputs: Iterable[str],
    lockfile_path: pathlib.Path | None = None,
) -> list[str]:
    lockfile = selected_lockfile_path(root, lockfile_path)
    input_set = set(inputs)
    cargo, rustc, rustdoc, git = source_seal_tools()
    output = run(
        root,
        git,
        [
            "ls-files",
            "-z",
            "-co",
            "--exclude-standard",
            "--",
            *inputs,
        ],
        source_seal_environment(cargo=cargo, rustc=rustc, rustdoc=rustdoc, git=git),
    )
    listed = {
        value.decode("utf-8")
        for value in output.split(b"\0")
        if value
    }

    # Some workspace-wide build inputs are intentionally ignored by repository
    # policy (notably the selected Cargo.lock). They still affect the bridge binary,
    # so an explicit ROOT_INPUT must be sealed even when `git ls-files -co
    # --exclude-standard` omits it. Do not recursively include arbitrary ignored
    # files below directory inputs: build outputs and local corpora remain outside
    # the production source seal unless named explicitly above.
    for relative in ROOT_INPUTS:
        if relative not in input_set:
            continue
        try:
            source, identities = _source_path_metadata(root, relative, allow_directory=True)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(int(identities[source][2])):
            _public_source_relative(relative)
            listed.add(relative)

    # Classification is an authenticated source input even for an explicit seed
    # selection. This does not recursively enumerate or admit ignored local corpora.
    if any(_norito_public_corpus_path(relative) for relative in listed):
        listed.add(_NORITO_PUBLIC_CORPUS_MANIFEST)

    present = []
    for relative in listed:
        try:
            _source_path_metadata(root, relative)
        except FileNotFoundError:
            # `git ls-files --cached` includes intentionally deleted tracked
            # files. Their absence is authenticated by the source status and
            # by their removal from this byte inventory.
            continue
        except OSError as error:
            raise RuntimeError(
                f"failed to inspect source-seal input: {relative}"
            ) from error
        present.append(relative)

    return sorted(present)


def _swift_native_bridge_hash_block(
    contents: bytes,
) -> tuple[re.Match[bytes], list[re.Match[bytes]]]:
    blocks = list(SWIFT_NATIVE_BRIDGE_HASH_BLOCK.finditer(contents))
    if len(blocks) != 1:
        raise RuntimeError(
            "NativeBridge.swift must contain exactly one canonical expectedHashes block"
        )
    block = blocks[0]
    matches = list(SWIFT_NATIVE_BRIDGE_HASH_PIN.finditer(block.group("body")))
    keys = [match.group("key").decode("ascii") for match in matches]
    suffixes = [match.group("suffix") for match in matches]
    if (
        len(matches) != len(SWIFT_NATIVE_BRIDGE_HASH_KEYS)
        or set(keys) != set(SWIFT_NATIVE_BRIDGE_HASH_KEYS)
        or suffixes != [b",", b",", b""]
    ):
        raise RuntimeError(
            "NativeBridge.swift must contain exactly one canonical fallback hash "
            "for every Apple artifact slice"
        )
    return block, matches


def swift_native_bridge_hash_pins(contents: bytes) -> dict[str, str]:
    """Return pins from the sole executable ``expectedHashes`` declaration."""

    _block, matches = _swift_native_bridge_hash_block(contents)
    return {
        match.group("key").decode("ascii"): match.group("digest").decode("ascii")
        for match in matches
    }


def rewrite_swift_native_bridge_hash_pins(
    contents: bytes,
    hashes: dict[str, str],
) -> bytes:
    """Rewrite only the canonical ``expectedHashes`` declaration."""

    if set(hashes) != set(SWIFT_NATIVE_BRIDGE_HASH_KEYS) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in hashes.values()
    ):
        raise RuntimeError("Swift native bridge replacement hashes are not canonical")
    block, _matches = _swift_native_bridge_hash_block(contents)
    body = block.group("body")

    def replace(match: re.Match[bytes]) -> bytes:
        key = match.group("key").decode("ascii")
        return (
            match.group("prefix")
            + b'"'
            + match.group("key")
            + b'": "'
            + hashes[key].encode("ascii")
            + b'"'
            + match.group("suffix")
        )

    rewritten = SWIFT_NATIVE_BRIDGE_HASH_PIN.sub(replace, body)
    body_start, body_end = block.span("body")
    return contents[:body_start] + rewritten + contents[body_end:]


def normalize_swift_native_bridge_hash_pins(contents: bytes) -> bytes:
    """Normalize the three manifestless fallback digests for source sealing.

    The artifact checker authenticates these values independently against every
    slice in the embedded manifest. Normalizing only the digest literals keeps
    a mechanical pin-only child commit on the exact source fingerprint of the
    artifact-producing parent without excluding any executable loader logic.
    """

    return rewrite_swift_native_bridge_hash_pins(
        contents,
        {key: "0" * 64 for key in SWIFT_NATIVE_BRIDGE_HASH_KEYS},
    )


def fingerprint(
    root: pathlib.Path,
    inputs: list[str],
    lockfile_path: pathlib.Path | None = None,
) -> str:
    lockfile = selected_lockfile_path(root, lockfile_path)
    digest = hashlib.sha256()
    for relative in listed_files(root, inputs, lockfile):
        contents = _read_public_source_bytes(root, relative)
        if relative == SWIFT_NATIVE_BRIDGE_PATH:
            contents = normalize_swift_native_bridge_hash_pins(contents)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(contents)
        digest.update(b"\0")
    # Fixed domain separator binds the selected build graph independently of
    # root Cargo.lock. Host-specific external path spelling is not serialized.
    digest.update(b"\0selected-cargo-lock-sha256\0")
    digest.update(bytes.fromhex(str(lockfile_identity(lockfile)[-1])))
    return digest.hexdigest()


def status(
    root: pathlib.Path,
    inputs: list[str],
    lockfile_path: pathlib.Path | None = None,
) -> str:
    lockfile = selected_lockfile_path(root, lockfile_path)
    # Root Cargo.lock remains an independently authenticated source input.
    status_inputs = inputs
    cargo, rustc, rustdoc, git = source_seal_tools()
    output = run(
        root,
        git,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *status_inputs,
        ],
        source_seal_environment(cargo=cargo, rustc=rustc, rustdoc=rustdoc, git=git),
    )
    return output.decode("utf-8").rstrip("\n")


def source_commit(root: pathlib.Path) -> str:
    cargo, rustc, rustdoc, git = source_seal_tools()
    value = run(
        root,
        git,
        ["rev-parse", "--verify", "HEAD"],
        source_seal_environment(cargo=cargo, rustc=rustc, rustdoc=rustdoc, git=git),
    ).decode("ascii").strip()
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("source commit is not a canonical lowercase Git SHA-1")
    return value



def android_cargo_configuration(root: pathlib.Path, *, diagnostic: bool = False) -> dict[str, object]:
    """Bind explicit private cache/cwd/config originals to the source seal."""
    cache = os.environ.get("NORITO_BRIDGE_SEAL_CARGO_HOME")
    invocation = os.environ.get("NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR")
    if (not cache or not invocation or cache != str(pathlib.Path(cache))
            or invocation != str(pathlib.Path(invocation))):
        raise RuntimeError("Android Cargo seal requires explicit canonical Cargo cache and invocation directory")
    helper = pathlib.Path(__file__).with_name("norito_bridge_local_integration.py")
    specification = importlib.util.spec_from_file_location("android_armv7_configuration_policy", helper)
    if specification is None or specification.loader is None:
        raise RuntimeError("Android diagnostic configuration policy is unavailable")
    owner = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(owner)
    if diagnostic:
        return owner.android_armv7_diagnostic_configuration(
            root, pathlib.Path(cache), pathlib.Path(invocation), local_integration=True,
        )
    return owner.android_cargo_configuration(root, pathlib.Path(cache), pathlib.Path(invocation))


def android_armv7_diagnostic_configuration(root: pathlib.Path) -> dict[str, object]:
    return android_cargo_configuration(root, diagnostic=True)


def snapshot(
    root: pathlib.Path,
    platform: str,
    lockfile_path: pathlib.Path | None = None,
) -> dict[str, object]:
    """Return the canonical source state consumed by one platform build."""

    lockfile = selected_lockfile_path(root, lockfile_path)
    lock_identity_before = lockfile_identity(lockfile)
    root_lock = root / "Cargo.lock"
    root_lock_identity_before = lockfile_identity(root_lock)
    diagnostic_configuration = (
        android_armv7_diagnostic_configuration(root)
        if platform == "android-armv7-diagnostic" else None
    )
    cargo_configuration = (
        android_cargo_configuration(root)
        if platform == "android" and "NORITO_BRIDGE_SEAL_CARGO_INVOCATION_DIR" in os.environ
        else None
    )
    inputs = seal_inputs(root, platform, lockfile)
    source_commit_before = source_commit(root)
    source_status_before = status(root, inputs, lockfile)
    source_fingerprint_before = fingerprint(root, inputs, lockfile)
    source_fingerprint_after = fingerprint(root, inputs, lockfile)
    source_status_after = status(root, inputs, lockfile)
    source_commit_after = source_commit(root)
    if lockfile_identity(lockfile) != lock_identity_before:
        raise RuntimeError("selected Cargo lock changed while authenticating the source snapshot")
    if lockfile_identity(root_lock) != root_lock_identity_before:
        raise RuntimeError("root Cargo lock changed while authenticating the source snapshot")
    if source_commit_before != source_commit_after:
        raise RuntimeError(
            f"{platform} NoritoBridge source commit changed while authenticating "
            "the selected-source fingerprint"
        )
    if (
        source_status_before != source_status_after
        or source_fingerprint_before != source_fingerprint_after
    ):
        raise RuntimeError(
            f"{platform} NoritoBridge selected source changed while authenticating "
            "the build snapshot"
        )
    if (diagnostic_configuration is not None
            and android_armv7_diagnostic_configuration(root) != diagnostic_configuration):
        raise RuntimeError("Android diagnostic configuration changed while authenticating the source snapshot")
    if (cargo_configuration is not None
            and android_cargo_configuration(root) != cargo_configuration):
        raise RuntimeError("Android Cargo configuration changed while authenticating the source snapshot")
    document = {
        "schema": SNAPSHOT_SCHEMA,
        "platform": platform,
        "targets": list(PLATFORM_TARGETS[platform]),
        "source_commit": source_commit_before,
        "source_tree_dirty": bool(source_status_before),
        "source_status": source_status_before,
        "source_fingerprint_sha256": source_fingerprint_before,
    }
    if diagnostic_configuration is not None:
        document["diagnostic_configuration"] = diagnostic_configuration
    if cargo_configuration is not None:
        document["cargo_configuration"] = cargo_configuration
    return document


def snapshot_bytes(
    root: pathlib.Path,
    platform: str,
    lockfile_path: pathlib.Path | None = None,
) -> bytes:
    return (
        json.dumps(
            snapshot(root, platform, lockfile_path),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def verify_snapshot(
    root: pathlib.Path,
    platform: str,
    snapshot_path: pathlib.Path,
    lockfile_path: pathlib.Path | None = None,
) -> None:
    """Reject a missing, tampered, stale, or mixed-source build snapshot."""

    expected = snapshot_path.read_bytes()
    current = snapshot_bytes(root, platform, lockfile_path)
    if expected != current:
        raise RuntimeError(
            f"{platform} NoritoBridge source changed after the build started"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("fingerprint", "paths", "snapshot", "status", "verify")
    )
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument(
        "--platform", choices=tuple(PLATFORM_TARGETS), default="apple"
    )
    parser.add_argument(
        "--snapshot",
        type=pathlib.Path,
        help="Build-start snapshot to authenticate in verify mode.",
    )
    parser.add_argument(
        "--lockfile-path",
        type=pathlib.Path,
        required=True,
        help="Absolute canonical Cargo lock consumed by metadata and fingerprinting.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root
    _source_path_metadata(root, "Cargo.toml")
    lockfile = selected_lockfile_path(root, args.lockfile_path)
    inputs = seal_inputs(root, args.platform, lockfile)
    if args.mode == "fingerprint":
        print(fingerprint(root, inputs, lockfile))
    elif args.mode == "paths":
        print("\n".join(inputs))
    elif args.mode == "status":
        value = status(root, inputs, lockfile)
        if value:
            print(value)
    elif args.mode == "snapshot":
        sys.stdout.buffer.write(snapshot_bytes(root, args.platform, lockfile))
    else:
        if args.snapshot is None:
            raise RuntimeError("verify mode requires --snapshot")
        verify_snapshot(root, args.platform, args.snapshot.resolve(), lockfile)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"norito bridge source seal failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
