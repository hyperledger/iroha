from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "norito_bridge_source_seal.py"
APPLE_BUILDER = Path(__file__).parents[1] / "build_norito_xcframework.sh"
HERMETIC_RUNNER = Path(__file__).parents[1] / "run_mobile_hermetic_command.py"
ANDROID_BUILDER = Path(__file__).parents[2] / "kotlin/client-android/build.gradle.kts"
SPEC = importlib.util.spec_from_file_location("norito_bridge_source_seal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
seal = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = seal
SPEC.loader.exec_module(seal)


class NoritoBridgeAndroidConsumerRuleResourceTests(unittest.TestCase):
    """A maintained public resource filename never exempts source bytes or custody."""

    RESOURCE = (
        "kotlin/core-jvm/src/main/resources/META-INF/proguard/"
        "consumer-proguard-rules.pro"
    )
    RULES = b"-keep class org.hyperledger.iroha.sdk.PublicSyntheticRuleV1 { *; }\n"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_reviewed_resources_are_exactly_the_consumer_rules(self) -> None:
        self.assertEqual(
            seal._REVIEWED_PUBLIC_ANDROID_RESOURCE_INPUTS,
            frozenset({
                "java/iroha_android/core/src/main/resources/META-INF/proguard/iroha3.pro",
                self.RESOURCE,
            }),
        )
        for retired in (
            "kotlin/client-android/src/main/resources/META-INF/services/"
            "org.hyperledger.iroha.sdk.offline.KagemushaFirstDeviceHardwareEvidenceServiceFactoryV1",
            "kotlin/kagemusha-wallet-android/src/main/resources/META-INF/services/"
            "org.hyperledger.iroha.sdk.offline.KagemushaOrdinaryMintFundingNativeOwnerV1",
        ):
            with self.subTest(retired=retired):
                with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                    seal._public_source_relative(retired)

    def test_consumer_rules_admit_only_the_exact_public_resource(self) -> None:
        self.assertEqual(seal._public_source_relative(self.RESOURCE).as_posix(), self.RESOURCE)
        for relative in (
            self.RESOURCE + ".bak",
            self.RESOURCE + "Unreviewed",
            self.RESOURCE.replace("consumer-proguard-rules", "other-proguard-rules"),
            self.RESOURCE.replace("core-jvm/", "client-android/"),
            self.RESOURCE.replace("META-INF/proguard/", "META-INF/unreviewed/"),
            self.RESOURCE.replace("META-INF/proguard/", "META-INF/services/"),
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                    seal._public_source_relative(relative)

    def test_consumer_rules_fingerprint_every_byte_and_reject_aliases(self) -> None:
        path = self.root / self.RESOURCE
        path.parent.mkdir(parents=True)
        path.write_bytes(self.RULES)
        lockfile = self.root / "Cargo.lock"
        lockfile.write_bytes(b"public synthetic lock\n")
        with mock.patch.object(seal, "listed_files", return_value=[self.RESOURCE]), \
                mock.patch.object(seal, "selected_lockfile_path", return_value=lockfile), \
                mock.patch.object(seal, "lockfile_identity", return_value=("0" * 64,)):
            original = seal.fingerprint(self.root, [self.RESOURCE], lockfile)
            self.assertEqual(seal._read_public_source_bytes(self.root, self.RESOURCE), self.RULES)
            path.write_bytes(self.RULES + b"# changed original\n")
            self.assertNotEqual(seal.fingerprint(self.root, [self.RESOURCE], lockfile), original)
            path.write_bytes(self.RULES)
            self.assertEqual(seal.fingerprint(self.root, [self.RESOURCE], lockfile), original)
            actual = path.with_name(path.name + ".txt")
            path.rename(actual)
            path.symlink_to(actual)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                seal.fingerprint(self.root, [self.RESOURCE], lockfile)

    def test_consumer_rules_cannot_override_material_or_provider_refusal(self) -> None:
        for relative in (
            "secrets/" + self.RESOURCE,
            "vultr/" + self.RESOURCE,
            self.RESOURCE + ".pem",
            self.RESOURCE + ".key",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                    seal._public_source_relative(relative)


class NoritoBridgeSourceSealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source_seal_target = self.root / "source-seal-cargo-target"
        self.source_seal_target.mkdir()
        self.environment_patch = mock.patch.dict(
            os.environ,
            {
                "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR": str(
                    self.source_seal_target
                )
            },
            clear=False,
        )
        self.environment_patch.start()
        for relative, contents in {
            "Cargo.toml": "[workspace]\n",
            "Cargo.lock": "# locked\n",
            "ci/check_connect_norito_bridge_header.sh": "#!/bin/sh\n",
            "rust-toolchain.toml": "[toolchain]\nchannel = 'stable'\n",
            "crates/connect_norito_bridge/RELEASE_NOTES.md": "# release\n",
            "IrohaSwift/Package.swift": "// package\n",
            "IrohaSwift/Package.resolved": '{"pins":[],"version":3}\n',
            "IrohaSwift/VERSION": "0.1.0\n",
            "IrohaSwift/Sources/IrohaSwift/Core.swift": "public struct Core {}\n",
            "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift": (
                "    private static let expectedHashes: [String: String] = [\n"
                '        "macos-arm64_x86_64": "' + ("1" * 64) + '",\n'
                '        "ios-arm64": "' + ("2" * 64) + '",\n'
                '        "ios-arm64_x86_64-simulator": "' + ("3" * 64) + '"\n'
                "    ]\n"
            ),
            "IrohaSwift/Sources/IrohaSwiftMobileTransports/Nfc.swift":
                "public struct Nfc {}\n",
            "scripts/build_norito_xcframework.sh": "#!/bin/sh\n",
            "scripts/archive_norito_xcframework.py": "#!/usr/bin/env python3\n",
            "scripts/check_mobile_sdk_artifact_pin_commit.py": "#!/usr/bin/env python3\n",
            "scripts/check_mobile_sdk_artifacts.sh": "#!/bin/sh\n",
            "scripts/exec_with_file_lock.py": "#!/usr/bin/env python3\n",
            "scripts/norito_bridge_source_seal.py": "# fixture\n",
            "scripts/normalize_pqcrypto_archive.py": "# archive normalization fixture\n",
            "scripts/norito_bridge_local_integration.py": "# local integration policy fixture\n",
            "scripts/norito_bridge_apple_slice_handoff.py": "#!/usr/bin/env python3\n",
            "scripts/package_mobile_sdk_artifacts.sh": "#!/bin/sh\n",
            "scripts/validate_norito_bridge_archive.py": "#!/usr/bin/env python3\n",
            "scripts/update_norito_bridge_swift_pins.py": "#!/usr/bin/env python3\n",
            "scripts/validate_norito_bridge_xcframework.py": "#!/usr/bin/env python3\n",
            "kotlin/client-android/build.gradle.kts": "// android\n",
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        self.write_graph_owner((self.root / "Cargo.lock").read_bytes())
        self.git("init", "-q")
        self.git("config", "user.name", "Source Seal Test")
        self.git("config", "user.email", "source-seal@example.invalid")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")

    def test_trybuild_diagnostics_admit_only_exact_reviewed_roles(self) -> None:
        expected = frozenset({
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
        self.assertEqual(seal._REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS, expected)
        self.assertNotIn(".stderr", seal._PUBLIC_SOURCE_SUFFIXES)
        for relative in expected:
            with self.subTest(relative=relative):
                self.assertEqual(seal._public_source_relative(relative).as_posix(), relative)

    def test_maintained_prepared_record_trybuild_diagnostics_are_complete_public_roles(self) -> None:
        repository_root = SCRIPT.parent.parent.resolve()
        for directory in (
            "crates/iroha_schema_derive/tests/ui_fail",
            "crates/norito_derive/tests/ui/fail",
        ):
            for source in (repository_root / directory).glob("*.stderr"):
                with self.subTest(diagnostic=source.name):
                    relative = source.relative_to(repository_root).as_posix()
                    self.assertIn(relative, seal._REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS)
                    self.assertTrue(source.with_suffix(".rs").is_file())

    def test_trybuild_diagnostics_seal_complete_bytes_and_tracked_deletion(self) -> None:
        originals = {}
        for relative in seal._REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            # Public synthetic diagnostics exercise source custody only, not compilation.
            contents = ("error: test-only diagnostic for " + path.stem + "\n").encode()
            path.write_bytes(contents)
            originals[relative] = contents
        self.git("add", "crates")
        inputs = sorted({"/".join(relative.split("/")[:2]) for relative in originals})
        listed = seal.listed_files(self.root, inputs, self.root / "Cargo.lock")
        self.assertEqual(set(listed), set(originals))
        original = seal.fingerprint(self.root, inputs, self.root / "Cargo.lock")
        for relative, contents in sorted(originals.items()):
            self.assertEqual(seal._read_public_source_bytes(self.root, relative), contents)
        # Mutate one original per package and each retained copy, covering all roles.
        selected = {}
        for relative in sorted(originals):
            role = relative.split("/")[1]
            if "/wip/" in relative:
                role = relative
            selected.setdefault(role, relative)
        for relative in selected.values():
            contents = originals[relative]
            with self.subTest(relative=relative):
                self.assertEqual(seal._read_public_source_bytes(self.root, relative), contents)
                path = self.root / relative
                path.write_bytes(contents + b"  changed expected diagnostic\n")
                self.assertNotEqual(
                    seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original
                )
                path.write_bytes(contents)
                self.assertEqual(
                    seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original
                )
        (self.root / sorted(originals)[0]).unlink()
        self.assertNotEqual(
            seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original
        )

    def test_trybuild_diagnostics_reject_unreviewed_filename_roles(self) -> None:
        for relative in (
            "crates/norito_derive/tests/ui/fail/unreviewed.stderr",
            "crates/norito_derive/tests/ui/fail/prepared_record_other.stderr",
            "crates/norito_derive/tests/ui/pass/prepared_record_generic.stderr",
            "crates/norito_derive/tests/ui/fail/prepared_record_generic.stderr.log",
            "crates/norito_derive/tests/ui/pass/json_deny_unknown_fields_tuple.stderr",
            "crates/another_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr",
            "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.STDERR",
            "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr.bak",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                    seal._public_source_relative(relative)

    def test_trybuild_diagnostics_cannot_override_material_or_provider_refusal(self) -> None:
        for relative in (
            "crates/norito_derive/tests/private/example.stderr",
            "crates/norito_derive/tests/ui/fail/auth-token.stderr",
            "crates/norito_derive/tests/ui/fail/credentials.stderr",
            "crates/norito_derive/tests/ui/fail/example.pem",
            "crates/norito_derive/tests/ui/fail/.env.local",
            "crates/norito_derive/tests/ui/fail/vultr.stderr",
            "crates/norito_derive/tests/ui/fail/sydneycreds.stderr",
            "output/json_deny_unknown_fields_tuple.stderr",
        ):
            with self.subTest(relative=relative):
                # A mistaken future role declaration must not bypass earlier refusal.
                with mock.patch.object(
                    seal, "_REVIEWED_PUBLIC_RUST_DIAGNOSTIC_INPUTS", frozenset({relative})
                ):
                    with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                        seal._public_source_relative(relative)

    def test_trybuild_diagnostics_reject_symlinked_file_and_ancestor(self) -> None:
        relative = "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"error: public test-only diagnostic\n")
        original = path.read_bytes()
        self.assertEqual(seal._read_public_source_bytes(self.root, relative), original)
        target = self.root / "public-target.txt"
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            seal._read_public_source_bytes(self.root, relative)
        path.unlink()
        path.write_bytes(original)
        directory = path.parent
        retained = directory.with_name("retained-fail")
        directory.rename(retained)
        directory.symlink_to(retained, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            seal._read_public_source_bytes(self.root, relative)

    def test_trybuild_diagnostics_reject_noncanonical_paths_before_content_intake(self) -> None:
        relative = "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr"
        for offered in (
            "/" + relative, "./" + relative, "crates/../" + relative,
            relative.replace("/", "\\", 1), relative + "\n", relative + "\x00",
        ):
            with self.subTest(relative=offered):
                with mock.patch.object(seal.os, "open") as open_file:
                    with self.assertRaisesRegex(RuntimeError, "not canonical"):
                        seal._read_public_source_bytes(self.root, offered)
                    open_file.assert_not_called()

    def test_trybuild_diagnostics_preserve_root_and_regular_file_refusal(self) -> None:
        relative = "crates/norito_derive/tests/ui/fail/json_deny_unknown_fields_tuple.stderr"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()
        with self.assertRaisesRegex(RuntimeError, "not a regular file"):
            seal._read_public_source_bytes(self.root, relative)
        path.rmdir()
        os.mkfifo(path)
        with mock.patch.object(seal.os, "open") as open_file:
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                seal._read_public_source_bytes(self.root, relative)
            open_file.assert_not_called()
        path.unlink()
        path.write_bytes(b"error: public test-only diagnostic\n")
        for root in (Path("relative-root"), self.root / "ancestor" / ".."):
            with self.subTest(root=root):
                with self.assertRaisesRegex(RuntimeError, "root must be absolute and canonical"):
                    seal._read_public_source_bytes(root, relative)

    def test_kotodama_is_source_without_admitting_compiled_bytecode(self) -> None:
        self.assertIn(".ko", seal._PUBLIC_SOURCE_SUFFIXES)
        self.assertIn(".ko", seal._CODE_SUFFIXES)
        self.assertNotIn(".to", seal._PUBLIC_SOURCE_SUFFIXES)
        self.assertNotIn(".to", seal._CODE_SUFFIXES)
        for relative in (
            "crates/ivm/fixtures/koto_v1/kotodama/064.ko",
            "crates/kotodama_lang/src/samples/example.ko",
            "crates/another_public_package/tests/a_new_source.ko",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(seal._public_source_relative(relative).as_posix(), relative)
        for relative in (
            "crates/ivm/fixtures/compiled.to", "crates/ivm/fixtures/example.ko.bak",
            "crates/ivm/fixtures/example.unknown",
        ):
            with self.subTest(relative=relative):
                with mock.patch.object(seal.os, "open") as open_file:
                    with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                        seal._read_public_source_bytes(self.root, relative)
                    open_file.assert_not_called()

    def test_kotodama_source_bytes_and_tracked_deletion_change_fingerprint(self) -> None:
        relative = "crates/ivm/fixtures/koto_v1/kotodama/064.ko"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        original = b"module SourceOnlyFixture { fn value() -> int { 1 } }\n"
        path.write_bytes(original)
        self.git("add", relative)
        inputs = ["crates/ivm"]
        self.assertEqual(seal.listed_files(self.root, inputs, self.root / "Cargo.lock"), [relative])
        self.assertEqual(seal._read_public_source_bytes(self.root, relative), original)
        fingerprint = seal.fingerprint(self.root, inputs, self.root / "Cargo.lock")
        path.write_bytes(original.replace(b"1", b"2"))
        self.assertNotEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), fingerprint)
        path.write_bytes(original)
        self.assertEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), fingerprint)
        path.unlink()
        self.assertNotEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), fingerprint)

    def test_kotodama_preserves_material_provider_and_canonical_path_refusal(self) -> None:
        for relative in (
            "credentials/public.ko", "crates/example/private/public.ko",
            "crates/example/deploy/public.ko", "crates/example/artifacts/public.ko",
            "crates/example/output/public.ko", "crates/example/vultr/public.ko",
            "crates/example/sydneycreds/public.ko", "crates/example/public.ko.pem",
            "crates/example/.env.ko",
        ):
            with self.subTest(relative=relative):
                with mock.patch.object(seal.os, "open") as open_file:
                    with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                        seal._read_public_source_bytes(self.root, relative)
                    open_file.assert_not_called()
        for relative in (
            "/crates/example/public.ko", "crates/../example/public.ko",
            "crates\\example/public.ko", "crates/example/public.ko\n",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(RuntimeError, "not canonical"):
                    seal._public_source_relative(relative)

    def test_kotodama_preserves_no_follow_and_regular_file_custody(self) -> None:
        relative = "crates/ivm/fixtures/koto_v1/kotodama/064.ko"
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        target = self.root / "public.txt"
        target.write_bytes(b"module SourceOnlyFixture {}\n")
        path.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            seal._read_public_source_bytes(self.root, relative)
        path.unlink()
        os.mkfifo(path)
        with mock.patch.object(seal.os, "open") as open_file:
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                seal._read_public_source_bytes(self.root, relative)
            open_file.assert_not_called()

    def public_role_original(self, relative: str) -> bytes:
        # Canonical checked-in public sources, or byte-identical retained originals
        # in a staged source-only test tree; never a proof/issuer/runtime original.
        return (Path(__file__).parents[2] / relative).read_bytes()

    def public_role_inputs(self) -> frozenset[str]:
        return (seal._REVIEWED_PUBLIC_IVM_ARTIFACT_INPUTS
                | seal._REVIEWED_PUBLIC_SOURCE_FOLDER_INPUTS
                | seal._REVIEWED_PUBLIC_FIXTURE_INPUTS
                | frozenset(seal._REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS))

    def test_public_ivm_roles_match_owned_selected_catalog(self) -> None:
        rows = [line.split("\t") for line in
                self.public_role_original("scripts/ivm_artifacts.tsv").decode().splitlines()
                if line and not line.startswith("#")]
        expected = frozenset(row[2] for row in rows if row[2].startswith((
            "crates/iroha/", "crates/ivm/", "crates/kotodama_lang/")))
        self.assertEqual(len(expected), 45)
        self.assertEqual(expected, seal._REVIEWED_PUBLIC_IVM_ARTIFACT_INPUTS)
        self.assertNotIn(".to", seal._PUBLIC_SOURCE_SUFFIXES)
        self.assertNotIn(".to", seal._CODE_SUFFIXES)
        for owner, source, artifact in rows:
            if artifact in expected:
                self.assertIn(owner, ("kotodama-standard", "kotodama-zk", "predecoder"))
                if owner.startswith("kotodama"):
                    self.assertTrue(self.public_role_original(source))

    def test_public_required_roles_are_exact_without_suffix_widening(self) -> None:
        self.assertEqual(len(self.public_role_inputs()), 80)
        self.assertEqual(len(seal._REVIEWED_PUBLIC_SOURCE_FOLDER_INPUTS), 10)
        self.assertEqual(len(seal._REVIEWED_PUBLIC_FIXTURE_INPUTS), 23)
        self.assertEqual(len(seal._REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS), 4)
        for relative in self.public_role_inputs():
            self.assertEqual(seal._public_source_relative(relative).as_posix(), relative)
        for suffix in (".to", ".env", ".digest", ".tape", ".metallib", ".lex", ".m",
                       ".norito", ".message"):
            self.assertNotIn(suffix, seal._PUBLIC_SOURCE_SUFFIXES)
        for relative in (
            "crates/ivm/docs/examples/unowned.to",
            "crates/ivm/metal/v1/unowned.metallib",
            "crates/ivm/fuzz/corpus/numeric_v1/unowned_seed",
            "crates/norito/tests/data/unowned.tape",
            "crates/norito/tests/fixtures/unowned.norito",
            "crates/kotodama_lang/grammar/other.lex",
            "crates/norito/accelerators/jsonstage1_metal/src/other.m",
        ):
            with self.subTest(relative=relative), mock.patch.object(seal.os, "open") as opened:
                with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                    seal._read_public_source_bytes(self.root, relative)
                opened.assert_not_called()

    def test_public_required_originals_full_bytes_and_deletion_are_sealed(self) -> None:
        originals = {}
        for relative in sorted(self.public_role_inputs()):
            contents = self.public_role_original(relative)
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            originals[relative] = contents
        self.git("add", "crates")
        inputs = sorted({"/".join(relative.split("/")[:2]) for relative in originals})
        self.assertEqual(set(seal.listed_files(self.root, inputs, self.root / "Cargo.lock")),
                         set(originals))
        original = seal.fingerprint(self.root, inputs, self.root / "Cargo.lock")
        for relative, contents in originals.items():
            self.assertEqual(seal._read_public_source_bytes(self.root, relative), contents)
        selected = (
            "crates/ivm/docs/examples/01_hajimari.to",
            "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode00_vlen0_cycles0_abi1.to",
            "crates/iroha_p2p/src/peer/run/granted.rs",
            "crates/ivm/metal/v1/ivm_kernels.metallib",
            "crates/ivm/fuzz/corpus/numeric_v1/valid_int_seed",
            "crates/norito/tests/data/small_a1.tape",
            "crates/norito/tests/fixtures/sample_payload_frame.norito",
        )
        for relative in selected:
            path = self.root / relative
            path.write_bytes(originals[relative] + b"test-only source custody mutation")
            self.assertNotEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original)
            path.write_bytes(originals[relative])
            self.assertEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original)
        (self.root / selected[0]).unlink()
        self.assertNotEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), original)

    def test_public_source_folder_roles_do_not_admit_operations_or_neighbors(self) -> None:
        for relative in (
            "crates/iroha_core/src/sumeragi/certified_chain/artifacts/other.rs",
            "crates/iroha_core_zk/src/kagemusha_v1_recursion/artifacts/unowned.bin",
            "crates/iroha_p2p/src/peer/run/other.rs",
            "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/unowned.to",
            "crates/ivm/tests/fixtures/predecoder/mixed/private/artifacts/unowned.to",
            "crates/ivm/tests/fixtures/predecoder/mixed/deploy/artifacts/unowned.to",
            "crates/iroha_p2p/src/peer/run/credentials.pem",
        ):
            with self.subTest(relative=relative), mock.patch.object(seal.os, "open") as opened:
                with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                    seal._read_public_source_bytes(self.root, relative)
                opened.assert_not_called()
        # Even an erroneous future general role declaration cannot override custody
        # or operational/material/provider refusal; only the exact source modules
        # allow the two reviewed directory words.
        for relative in ("credentials/example.to", "crates/p/deploy/a.to",
                         "crates/p/vultr/a.to", "crates/p/sydneycreds/a.to",
                         "crates/p/example.pem", "crates/p/.env.local"):
            with mock.patch.object(seal, "_REVIEWED_PUBLIC_FIXTURE_INPUTS", frozenset({relative})):
                with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                    seal._public_source_relative(relative)

    def test_public_nonoperational_fixture_pins_reject_content_substitution(self) -> None:
        self.assertEqual(seal._REVIEWED_PUBLIC_MOCK_ENV_INPUTS, frozenset({
            "crates/iroha_config/tests/fixtures/full.env",
            "crates/iroha_config/tests/fixtures/minimal_file_and_env.env",
        }))
        self.assertEqual(seal._REVIEWED_PUBLIC_STATIC_CONTRACT_INPUTS, frozenset({
            "crates/iroha_zkp_halo2/src/generalized_bulletproof_secret_cleanup_contracts_v1.txt",
            "crates/kotodama_lang/src/assets/diagnostics_v1/secret_reject_cases_v1.tsv",
        }))
        self.assertEqual(frozenset(seal._REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS),
                         seal._REVIEWED_PUBLIC_MOCK_ENV_INPUTS
                         | seal._REVIEWED_PUBLIC_STATIC_CONTRACT_INPUTS)
        for relative, (digest, size) in seal._REVIEWED_PUBLIC_NONOPERATIONAL_FIXTURE_PINS.items():
            contents = self.public_role_original(relative)
            self.assertEqual((seal.hashlib.sha256(contents).hexdigest(), len(contents)), (digest, size))
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            self.assertEqual(seal._read_public_source_bytes(self.root, relative), contents)
            path.write_bytes(contents + b"test-only substitution")
            with self.assertRaisesRegex(RuntimeError, "differs from its reviewed original"):
                seal._read_public_source_bytes(self.root, relative)
            path.write_bytes(contents[:-1] + bytes([contents[-1] ^ 1]))
            with self.assertRaisesRegex(RuntimeError, "differs from its reviewed original"):
                seal._read_public_source_bytes(self.root, relative)

    def test_public_roles_keep_source_descriptor_and_root_custody(self) -> None:
        for relative in (
            "crates/iroha_p2p/src/peer/run/granted.rs",
            "crates/ivm/tests/fixtures/predecoder/mixed/artifacts/artifact_v1_1_mode00_vlen0_cycles0_abi1.to",
            "crates/iroha_config/tests/fixtures/minimal_file_and_env.env",
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            contents = self.public_role_original(relative)
            path.write_bytes(contents)
            self.assertEqual(seal._read_public_source_bytes(self.root, relative), contents)
            target = self.root / "public-fixture.txt"
            target.write_bytes(contents)
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                seal._read_public_source_bytes(self.root, relative)
            path.unlink()
            os.mkfifo(path)
            with mock.patch.object(seal.os, "open") as opened:
                with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                    seal._read_public_source_bytes(self.root, relative)
                opened.assert_not_called()
            path.unlink()
            path.write_bytes(contents)
            parent = path.parent
            retained = parent.with_name(parent.name + "-retained-public-fixture")
            parent.rename(retained)
            parent.symlink_to(retained, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                seal._read_public_source_bytes(self.root, relative)
            parent.unlink()
            retained.rename(parent)
            with self.assertRaisesRegex(RuntimeError, "root must be absolute and canonical"):
                seal._read_public_source_bytes(Path("relative-root"), relative)
            for offered in ("/" + relative, "./" + relative, relative + "\n"):
                with self.assertRaisesRegex(RuntimeError, "not canonical"):
                    seal._public_source_relative(offered)

    def test_public_source_owner_catalog_is_a_sealed_common_input(self) -> None:
        self.assertIn("scripts/ivm_artifacts.tsv", seal.COMMON_ROOT_INPUTS)
        owner = self.root / "scripts/ivm_artifacts.tsv"
        owner.write_bytes(self.public_role_original("scripts/ivm_artifacts.tsv"))
        inputs = self.inputs("android-armv7-diagnostic")
        self.assertIn("scripts/ivm_artifacts.tsv", inputs)
        before = seal.fingerprint(self.root, inputs, self.root / "Cargo.lock")
        owner.write_bytes(owner.read_bytes() + b"# source-only catalog mutation\n")
        self.assertNotEqual(seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"), before)

    def test_unproven_env_and_operational_originals_still_refuse_before_open(self) -> None:
        for relative in (
            "crates/iroha_config/tests/fixtures/bad.multiple_bad_envs.env",
            "crates/iroha_config/tests/fixtures/other.env",
            "crates/iroha_config/tests/fixtures/full.env.key",
            "crates/iroha_config/tests/fixtures/secret.env",
            "crates/iroha_zkp_halo2/src/other_secret_cleanup_contracts.txt",
            "crates/kotodama_lang/src/assets/diagnostics_v1/other_secret_reject.tsv",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.car",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.manifest.to",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.manifest.json",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.pack.json",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.plan.json",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.pin-register.response.json",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.storage-pin.0.response.json",
            "crates/sorafs_orchestrator/.sorafs/deploy/payload.bin/payload.bin.storage-pin.1.response.json",
        ):
            with self.subTest(relative=relative), mock.patch.object(seal.os, "open") as opened:
                with self.assertRaisesRegex(RuntimeError, "prohibited material or operational"):
                    seal._read_public_source_bytes(self.root, relative)
                opened.assert_not_called()
        with mock.patch.object(seal.os, "open") as opened:
            with self.assertRaisesRegex(RuntimeError, "not an admitted public filename"):
                seal._read_public_source_bytes(self.root,
                    "crates/iroha_core/crates/iroha_core/tests/fixtures/repo_lifecycle_proof.digest")
            opened.assert_not_called()

    def write_graph_owner(self, graph: bytes) -> None:
        owner = self.root / seal.CANONICAL_CARGO_LOCK_OWNER
        owner.parent.mkdir(parents=True, exist_ok=True)
        owner.write_text(
            "readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"
            + '"' + seal.hashlib.sha256(graph).hexdigest() + '"\n', encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.environment_patch.stop()
        self.temporary.cleanup()

    def git(self, *arguments: str) -> bytes:
        environment = os.environ.copy()
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        ).stdout

    def inputs(self, platform: str) -> list[str]:
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
            return seal.seal_inputs(self.root, platform, lockfile_path=self.root / "Cargo.lock")

    def git_child_environment(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": "/var/empty",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def test_git_child_uses_fixed_settings_and_original_executable(self) -> None:
        git = Path("/usr/bin/git").resolve(strict=True)
        arguments = ["rev-parse", "--verify", "HEAD"]
        environment = self.git_child_environment()
        completed = subprocess.CompletedProcess([], 0, stdout=b"observed\n")
        with mock.patch.object(seal.subprocess, "run", return_value=completed) as run:
            self.assertEqual(seal.run(self.root, git, arguments, environment), b"observed\n")
        self.assertEqual(run.call_args.args[0], [
            str(git), "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", *arguments,
        ])
        self.assertEqual(run.call_args.kwargs["executable"], str(git))
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)
        self.assertIs(run.call_args.kwargs["env"], environment)
        self.assertEqual(arguments, ["rev-parse", "--verify", "HEAD"])

    def test_git_child_ignores_actual_persistent_blob_replacement(self) -> None:
        original = (self.root / "Cargo.lock").read_bytes()
        original_blob = self.git("rev-parse", "HEAD:Cargo.lock").decode("ascii").strip()
        replacement = self.root / ".git" / "replacement-blob"
        replacement.write_bytes(b"# distinctly replaced fixture lock\n")
        replacement_blob = self.git("hash-object", "-w", str(replacement)).decode("ascii").strip()
        self.assertNotEqual(original_blob, replacement_blob)
        self.git("replace", original_blob, replacement_blob)
        self.assertEqual(self.git("show", "HEAD:Cargo.lock"), replacement.read_bytes())
        observed = seal.run(
            self.root, Path("/usr/bin/git").resolve(strict=True),
            ["show", "HEAD:Cargo.lock"], self.git_child_environment(),
        )
        self.assertEqual(observed, original)
        self.assertEqual(self.git("replace", "-l").decode("ascii").strip(), original_blob)

    def test_git_child_does_not_execute_actual_local_fsmonitor(self) -> None:
        marker = self.root / ".git" / "fsmonitor-invoked"
        monitor = self.root / ".git" / "benign-fsmonitor"
        monitor.write_text(
            "#!/bin/sh\n"
            + "printf invoked > " + shlex.quote(str(marker)) + "\n"
            + "printf 'fixture-token\\0'\n",
            encoding="utf-8",
        )
        monitor.chmod(0o700)
        self.git("config", "core.fsmonitor", str(monitor))
        self.git("status", "--porcelain=v1", "--untracked-files=all")
        self.assertTrue(marker.is_file(), "unprotected Git must exercise the benign monitor")
        marker.unlink()
        (self.root / "Cargo.lock").write_bytes(b"# changed tracked fixture lock\n")
        observed = seal.run(
            self.root, Path("/usr/bin/git").resolve(strict=True),
            ["status", "--porcelain=v1", "--untracked-files=all", "--", "Cargo.lock"],
            self.git_child_environment(),
        )
        self.assertFalse(marker.exists(), "source-seal Git must disable the local monitor")
        self.assertIn(b" M Cargo.lock", observed)

    def test_apple_seal_includes_package_lock_and_mobile_transports(self) -> None:
        apple = self.inputs("apple")
        for retired in (
            "IrohaSwift/IrohaSwift.podspec",
            "crates/connect_norito_bridge/NoritoBridge.podspec.template",
            "scripts/render_norito_bridge_podspec.py",
        ):
            self.assertNotIn(retired, seal.APPLE_ROOT_INPUTS)
        self.assertIn("crates/connect_norito_bridge/RELEASE_NOTES.md", apple)
        self.assertIn("IrohaSwift/Package.swift", apple)
        self.assertIn("IrohaSwift/Package.resolved", apple)
        self.assertIn("IrohaSwift/Sources/IrohaSwift", apple)
        self.assertIn("IrohaSwift/Sources/IrohaSwiftMobileTransports", apple)
        self.assertIn("IrohaSwift/VERSION", apple)
        self.assertIn("scripts/exec_with_file_lock.py", apple)
        self.assertIn("scripts/archive_norito_xcframework.py", apple)
        self.assertIn("scripts/norito_bridge_apple_slice_handoff.py", apple)
        self.assertIn("scripts/normalize_pqcrypto_archive.py", apple)
        self.assertIn("scripts/norito_bridge_local_integration.py", apple)
        self.assertIn("scripts/package_mobile_sdk_artifacts.sh", apple)
        self.assertIn("scripts/validate_norito_bridge_archive.py", apple)
        self.assertIn("scripts/update_norito_bridge_swift_pins.py", apple)
        self.assertIn("scripts/validate_norito_bridge_xcframework.py", apple)
        self.assertIn("scripts/check_mobile_sdk_artifact_pin_commit.py", apple)
        self.assertIn("ci/check_connect_norito_bridge_header.sh", apple)

        android = self.inputs("android")
        self.assertIn("gradle/mobile-sdk-external-android-build.settings.gradle.kts", seal.ANDROID_ROOT_INPUTS)
        self.assertNotIn("IrohaSwift/Package.resolved", android)
        self.assertNotIn("IrohaSwift/Sources/IrohaSwiftMobileTransports", android)
        self.assertNotIn("scripts/exec_with_file_lock.py", android)
        self.assertNotIn("scripts/norito_bridge_apple_slice_handoff.py", android)
        self.assertIn("scripts/check_mobile_sdk_artifact_pin_commit.py", android)

    def test_apple_seal_requires_regular_package_resolution_lock(self) -> None:
        resolved = self.root / "IrohaSwift/Package.resolved"
        canonical = resolved.read_bytes()
        resolved.unlink()
        with self.assertRaisesRegex(RuntimeError, "source-seal input is missing"):
            self.inputs("apple")

        target = self.root / "replacement-Package.resolved"
        target.write_bytes(canonical)
        resolved.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "source-seal input is not a regular file"):
            self.inputs("apple")

        resolved.unlink()
        resolved.write_bytes(canonical)
        self.assertIn("IrohaSwift/Package.resolved", self.inputs("apple"))

    def test_apple_fingerprint_normalizes_only_native_bridge_hash_pins(self) -> None:
        inputs = self.inputs("apple")
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        loader = self.root / "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
        contents = loader.read_text(encoding="utf-8")
        loader.write_text(contents.replace("1" * 64, "a" * 64), encoding="utf-8")
        self.assertEqual(original, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))

        loader.write_text(
            loader.read_text(encoding="utf-8") + "let changedLogic = true\n",
            encoding="utf-8",
        )
        self.assertNotEqual(original, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))

    def test_apple_fingerprint_authenticates_a_tracked_source_deletion(self) -> None:
        inputs = self.inputs("apple")
        relative = "IrohaSwift/Sources/IrohaSwift/Core.swift"
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")

        (self.root / relative).unlink()

        self.assertNotIn(relative, seal.listed_files(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))
        self.assertNotEqual(original, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))
        self.assertIn(f" D {relative}", seal.status(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))

    def test_apple_fingerprint_authenticates_archive_normalizer_logic(self) -> None:
        inputs = self.inputs("apple")
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        for relative in (
            "scripts/normalize_pqcrypto_archive.py",
            "scripts/norito_bridge_local_integration.py",
        ):
            with self.subTest(source_owner=relative):
                source_owner = self.root / relative
                original_contents = source_owner.read_text(encoding="utf-8")
                source_owner.write_text(original_contents + "# changed admission logic\n", encoding="utf-8")
                self.assertNotEqual(original, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))
                source_owner.write_text(original_contents, encoding="utf-8")

    def test_apple_fingerprint_authenticates_header_parity_gate(self) -> None:
        inputs = self.inputs("apple")
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        gate = self.root / "ci/check_connect_norito_bridge_header.sh"
        gate.write_text(gate.read_text(encoding="utf-8") + "# changed gate\n", encoding="utf-8")
        self.assertNotEqual(
            original,
            seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"),
        )
        self.assertIn(
            "ci/check_connect_norito_bridge_header.sh",
            seal.status(self.root, inputs, lockfile_path=self.root / "Cargo.lock"),
        )

    def test_selected_lock_is_root_lock_in_metadata_and_fingerprint(self) -> None:
        root_lock = self.root / "Cargo.lock"
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
            inputs = seal.seal_inputs(self.root, "apple", root_lock)

        original = seal.fingerprint(self.root, inputs, root_lock)
        root_lock.write_text("# changed root lock\n", encoding="utf-8")
        self.assertNotEqual(original, seal.fingerprint(self.root, inputs, root_lock))

        cargo = mock.Mock()
        rustc = mock.Mock()
        rustdoc = mock.Mock()
        git = Path("/usr/bin/git")
        with (
            mock.patch.object(
                seal, "source_seal_tools", return_value=(cargo, rustc, rustdoc, git)
            ),
            mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(self.root / "cargo-home")}),
            mock.patch.object(seal, "run", return_value=b"{}") as run,
        ):
            seal.metadata(self.root, "aarch64-apple-darwin", root_lock)
        arguments = run.call_args.args[2]
        self.assertNotIn("-Z", arguments)
        self.assertNotIn("unstable-options", arguments)
        self.assertNotIn("--lockfile-path", arguments)
        self.assertIn("--locked", arguments)
        self.assertIn("--offline", arguments)
        self.assertEqual(
            arguments[arguments.index("--manifest-path") + 1],
            str(self.root / "Cargo.toml"),
        )

    def test_external_snapshot_rejects_replaced_root_lock_with_identical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external = Path(external_directory).resolve() / "Cargo.lock"
            root_lock = self.root / "Cargo.lock"
            external.write_bytes(root_lock.read_bytes())
            calls = 0

            def observe_fingerprint(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    replacement = self.root / "replacement.lock"
                    replacement.write_bytes(root_lock.read_bytes())
                    replacement.replace(root_lock)
                return "1" * 64

            with (
                mock.patch.object(seal, "seal_inputs", return_value=[]),
                mock.patch.object(seal, "source_commit", return_value="1" * 40),
                mock.patch.object(seal, "status", return_value=""),
                mock.patch.object(seal, "fingerprint", side_effect=observe_fingerprint),
            ):
                with self.assertRaisesRegex(RuntimeError, "root Cargo lock changed while authenticating"):
                    seal.snapshot(self.root, "apple", external)
            self.assertEqual(calls, 2)
            self.assertEqual(root_lock.read_bytes(), external.read_bytes())

    def test_selected_lock_must_be_explicit_canonical_regular_and_non_symbolic(self) -> None:
        root_lock = self.root / "Cargo.lock"
        with self.assertRaisesRegex(RuntimeError, "explicit --lockfile-path"):
            seal.selected_lockfile_path(self.root)
        self.assertEqual(seal.selected_lockfile_path(self.root, root_lock), root_lock)

        with self.assertRaisesRegex(RuntimeError, "absolute and canonical"):
            seal.selected_lockfile_path(self.root, Path("Cargo.lock"))

        alternate = self.root / "alternate-Cargo.lock"
        alternate.write_text("# alternate lock\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "outside the source root"):
            seal.selected_lockfile_path(self.root, alternate)

        root_lock.unlink()
        with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
            seal.selected_lockfile_path(self.root, root_lock)

        root_lock.mkdir()
        with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
            seal.selected_lockfile_path(self.root, root_lock)
        root_lock.rmdir()

        root_lock.symlink_to(alternate)
        with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
            seal.selected_lockfile_path(self.root, root_lock)

    def test_reviewed_external_lock_binds_root_source_and_selected_graph_separately(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external = Path(external_directory).resolve() / "Cargo.lock"
            root_lock = self.root / "Cargo.lock"
            original = root_lock.read_bytes()
            external.write_bytes(original)
            digest = seal.hashlib.sha256(original).hexdigest()
            self.assertEqual(seal.selected_lockfile_path(self.root, external), external)
            self.assertNotEqual(root_lock.stat().st_ino, external.stat().st_ino)
            with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
                inputs = seal.seal_inputs(self.root, "apple", external)
            baseline = seal.fingerprint(self.root, inputs, external)
            root_lock.write_bytes(original + b"# root source change\n")
            with self.assertRaisesRegex(RuntimeError, "root source Cargo lock"):
                seal.fingerprint(self.root, inputs, external)
            # Ordinary explicit-root source inspection still observes its changed
            # source; it does not authorize an external privacy artifact build.
            changed_root = seal.fingerprint(self.root, inputs, root_lock)
            self.assertNotEqual(baseline, changed_root)
            self.assertIn("Cargo.lock", seal.status(self.root, inputs, root_lock))
            self.assertEqual(seal.lockfile_identity(external)[-1], digest)
            root_lock.write_bytes(original)
            external.write_bytes(b"unreviewed graph\n")
            with self.assertRaisesRegex(RuntimeError, "canonical reviewed graph"):
                seal.fingerprint(self.root, inputs, external)
            # A separately reviewed fixture graph updates the sole fixture owner
            # and both physical locks coherently; no production pin is relaxed.
            root_lock.write_bytes(external.read_bytes())
            self.write_graph_owner(external.read_bytes())
            self.assertNotEqual(changed_root, seal.fingerprint(self.root, inputs, external))

    def test_external_lock_rejects_unreviewed_graph_and_symbolic_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            directory = Path(external_directory).resolve()
            external = directory / "Cargo.lock"
            external.write_bytes(b"unreviewed unit-test graph\n")
            with self.assertRaisesRegex(RuntimeError, "canonical reviewed graph"):
                seal.selected_lockfile_path(self.root, external)
            alias = self.root / "lock-alias"
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
                seal.selected_lockfile_path(self.root, alias / "Cargo.lock")

    def test_external_metadata_authenticates_equal_lock_and_uses_original_root_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as external_directory:
            external = Path(external_directory).resolve() / "Cargo.lock"
            external.write_bytes((self.root / "Cargo.lock").read_bytes())
            with (
                mock.patch.object(seal, "source_seal_tools", return_value=(mock.Mock(), mock.Mock(), mock.Mock(), Path("/usr/bin/git"))),
                mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(self.root / "cargo-home")}),
                mock.patch.object(seal, "run", return_value=b"{}") as run,
            ):
                seal.metadata(self.root, "aarch64-apple-darwin", external)
            arguments = run.call_args.args[2]
            self.assertEqual(arguments[arguments.index("--manifest-path") + 1], str(self.root / "Cargo.toml"))
            self.assertIn("--locked", arguments)
            self.assertIn("--offline", arguments)
            self.assertNotIn("--lockfile-path", arguments)
            self.assertNotIn("-Z", arguments)
            self.assertNotIn("unstable-options", arguments)
            external.write_bytes(b"different graph\n")
            with self.assertRaisesRegex(RuntimeError, "canonical reviewed graph"):
                seal.metadata(self.root, "aarch64-apple-darwin", external)

    def test_native_metadata_rechecks_configuration_even_after_cargo_failure(self) -> None:
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        configuration = cargo_home / "config.toml"
        for target in seal.APPLE_TARGETS + seal.ANDROID_TARGETS:
            with self.subTest(target=target):
                configuration.unlink(missing_ok=True)

                def changed_configuration(*_args, **_kwargs):
                    configuration.write_text('[net]\noffline = true\n', encoding="utf-8")
                    raise RuntimeError("mock Cargo failure")

                with (
                    mock.patch.object(seal, "source_seal_tools", return_value=(mock.Mock(), mock.Mock(), mock.Mock(), Path("/usr/bin/git"))),
                    mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(cargo_home)}),
                    mock.patch.object(seal, "run", side_effect=changed_configuration),
                ):
                    with self.assertRaisesRegex(RuntimeError, "configuration changed during invocation"):
                        seal.metadata(self.root, target, self.root / "Cargo.lock")

    def test_android_metadata_rejects_bootstrap_configuration_before_cargo(self) -> None:
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        (cargo_home / "config.toml").write_text(
            '[env]\nRUSTC_BOOTSTRAP = {value = "1", force = true}\n', encoding="utf-8"
        )
        with (
            mock.patch.object(seal, "source_seal_tools", return_value=(mock.Mock(), mock.Mock(), mock.Mock(), Path("/usr/bin/git"))),
            mock.patch.object(seal, "source_seal_environment", return_value={"CARGO_HOME": str(cargo_home)}),
            mock.patch.object(seal, "run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "Native Cargo configuration forbids env"):
                seal.metadata(self.root, seal.ANDROID_TARGETS[0], self.root / "Cargo.lock")
        run.assert_not_called()

    def test_canonical_graph_owner_is_unique_strict_and_part_of_both_platform_seals(self) -> None:
        owner = self.root / seal.CANONICAL_CARGO_LOCK_OWNER
        original = owner.read_text()
        digest = seal.hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest()
        self.assertEqual(seal.canonical_cargo_lock_sha256(self.root), digest)
        self.assertIn(seal.CANONICAL_CARGO_LOCK_OWNER, seal.COMMON_ROOT_INPUTS)
        for source in (
            original + original,
            original + original.replace("readonly ", "readonly\t"),
            original.replace(digest, digest.upper()),
            original.replace(digest, "0" * 63),
            original.replace("PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256", "OLD_GRAPH_OWNER"),
        ):
            with self.subTest(source=source):
                owner.write_text(source)
                with self.assertRaisesRegex(RuntimeError, "canonical Cargo graph declaration"):
                    seal.canonical_cargo_lock_sha256(self.root)
        owner.write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "between 1 byte and 16 MiB"):
            seal.canonical_cargo_lock_sha256(self.root)
        owner.write_text(original)
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
            inputs = seal.seal_inputs(self.root, "apple", self.root / "Cargo.lock")
        before = seal.fingerprint(self.root, inputs, self.root / "Cargo.lock")
        owner.write_text(original + "# source owner edit\n")
        self.assertNotEqual(before, seal.fingerprint(self.root, inputs, self.root / "Cargo.lock"))
        replacement = owner.with_suffix(".replacement")
        owner.rename(replacement)
        owner.symlink_to(replacement)
        with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
            seal.canonical_cargo_lock_sha256(self.root)

    def test_external_graph_snapshot_rejects_hardlinks_and_executable_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory).resolve() / "Cargo.lock"
            os.link(self.root / "Cargo.lock", external)
            with self.assertRaisesRegex(RuntimeError, "singly linked"):
                seal.selected_lockfile_path(self.root, external)
            external.unlink()
            external.write_bytes((self.root / "Cargo.lock").read_bytes())
            external.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "non-executable"):
                seal.selected_lockfile_path(self.root, external)

    def test_lock_reader_rejects_fifo_before_open_and_fifo_substitution(self) -> None:
        fifo = self.root / "nonregular-Cargo.lock"
        os.mkfifo(fifo, 0o600)
        with mock.patch.object(seal.os, "open", side_effect=AssertionError("must not open a known FIFO")) as opened:
            with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
                seal.lockfile_identity(fifo)
        opened.assert_not_called()
        root_lock = self.root / "Cargo.lock"
        real_open = os.open
        def substitute_fifo(candidate, flags):
            self.assertEqual(candidate, root_lock)
            self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(fifo, flags)
        with mock.patch.object(seal.os, "open", side_effect=substitute_fifo):
            with self.assertRaisesRegex(RuntimeError, "non-symbolic regular file"):
                seal.lockfile_identity(root_lock)

    def test_canonical_graph_owner_rejects_a_descriptor_from_another_inode(self) -> None:
        owner = self.root / seal.CANONICAL_CARGO_LOCK_OWNER
        replacement = self.root / "same-byte-owner-copy.sh"
        replacement.write_bytes(owner.read_bytes())
        real_open = os.open
        def substituted_open(candidate, flags):
            self.assertEqual(candidate, owner)
            self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
            return real_open(replacement, flags)
        with mock.patch.object(seal.os, "open", side_effect=substituted_open):
            with self.assertRaisesRegex(RuntimeError, "changed while being authenticated"):
                seal.canonical_cargo_lock_sha256(self.root)

    def test_source_seal_cargo_environment_binds_jobs_rustdoc_and_fixed_target(
        self,
    ) -> None:
        tools = self.root / "source-seal-tools"
        target = self.root / "source-seal-target"
        tools.mkdir()
        target.mkdir()
        for name in ("cargo", "rustc", "rustdoc"):
            executable = tools / name
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        configured = {
            "NORITO_BRIDGE_SEAL_CARGO": str(tools / "cargo"),
            "NORITO_BRIDGE_SEAL_RUSTC": str(tools / "rustc"),
            "NORITO_BRIDGE_SEAL_RUSTDOC": str(tools / "rustdoc"),
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR": str(target),
        }
        with (
            mock.patch.dict(os.environ, configured, clear=False),
            mock.patch.object(seal, "source_seal_home", return_value=self.root),
        ):
            cargo, rustc, rustdoc, git = seal.source_seal_tools()
            environment = seal.source_seal_environment(
                cargo=cargo,
                rustc=rustc,
                rustdoc=rustdoc,
                git=git,
            )
        self.assertEqual(environment["CARGO_BUILD_JOBS"], "1")
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(target))
        self.assertEqual(environment["RUSTC"], str(tools / "rustc"))
        self.assertEqual(environment["RUSTDOC"], str(tools / "rustdoc"))
        self.assertNotIn("RUSTC_BOOTSTRAP", environment)

        missing_target = dict(configured)
        del missing_target["NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR"]
        with (
            mock.patch.dict(os.environ, missing_target, clear=True),
            mock.patch.object(seal, "source_seal_home", return_value=self.root),
        ):
            cargo, rustc, rustdoc, git = seal.source_seal_tools()
            with self.assertRaisesRegex(
                RuntimeError, "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR is required"
            ):
                seal.source_seal_environment(
                    cargo=cargo,
                    rustc=rustc,
                    rustdoc=rustdoc,
                    git=git,
                )

    def test_apple_fingerprint_and_dirty_state_bind_mobile_transport_bytes(self) -> None:
        inputs = self.inputs("apple")
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        transport = self.root / "IrohaSwift/Sources/IrohaSwiftMobileTransports/Nfc.swift"
        transport.write_text("public struct MutatedNfc {}\n", encoding="utf-8")

        self.assertNotEqual(original, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))
        self.assertIn("Nfc.swift", seal.status(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))

    def test_apple_fingerprint_binds_package_resolution_and_untracked_transport(self) -> None:
        inputs = self.inputs("apple")
        original = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        resolved = self.root / "IrohaSwift/Package.resolved"
        resolved.write_text('{"pins":[{"identity":"changed"}],"version":3}\n', encoding="utf-8")
        changed_lock = seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        self.assertNotEqual(original, changed_lock)

        extra = self.root / "IrohaSwift/Sources/IrohaSwiftMobileTransports/Extra.swift"
        extra.write_text("public struct Extra {}\n", encoding="utf-8")
        self.assertNotEqual(changed_lock, seal.fingerprint(self.root, inputs, lockfile_path=self.root / "Cargo.lock"))
        dirty = seal.status(self.root, inputs, lockfile_path=self.root / "Cargo.lock")
        self.assertIn("Package.resolved", dirty)
        self.assertIn("Extra.swift", dirty)

    def test_unknown_platform_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unsupported source-seal platform"):
            self.inputs("windows")

    def test_armv7_diagnostic_seals_only_its_dependency_target(self) -> None:
        profile = "android-armv7-diagnostic"
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()) as closure:
            seal.seal_inputs(self.root, profile, self.root / "Cargo.lock")
        self.assertEqual(closure.call_args.args[1], ("armv7-linux-androideabi",))
        self.assertEqual(seal.PLATFORM_TARGETS["android"],
                         ("aarch64-linux-android", "x86_64-linux-android"))
        self.assertIn("scripts/inspect_android_armv7_diagnostic.py",
                      seal.PLATFORM_ROOT_INPUTS[profile])

    def test_armv7_diagnostic_closure_retains_target_specific_local_dependency(self) -> None:
        bridge = self.root / "crates/connect_norito_bridge/Cargo.toml"
        dependency = self.root / "crates/armv7-only/Cargo.toml"
        document = {
            "packages": [
                {"id": "bridge", "name": "connect_norito_bridge", "manifest_path": str(bridge)},
                {"id": "arm-dependency", "name": "armv7-only", "manifest_path": str(dependency)},
                {"id": "unrelated", "name": "unrelated", "manifest_path": str(self.root / "crates/unrelated/Cargo.toml")},
            ],
            "resolve": {"nodes": [
                {"id": "bridge", "deps": [{"pkg": "arm-dependency"}]},
                {"id": "arm-dependency", "deps": []},
                {"id": "unrelated", "deps": []},
            ]},
        }
        with mock.patch.object(seal, "metadata", return_value=document) as metadata:
            observed = seal.local_dependency_roots(self.root,
                seal.ANDROID_ARMV7_DIAGNOSTIC_TARGETS, self.root / "Cargo.lock")
        self.assertEqual(observed, {"crates/connect_norito_bridge", "crates/armv7-only"})
        metadata.assert_called_once_with(self.root, "armv7-linux-androideabi", self.root / "Cargo.lock")

    def test_armv7_diagnostic_snapshot_cannot_verify_as_android_release(self) -> None:
        original = self.root / "armv7-diagnostic-seal.json"
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
            original.write_bytes(seal.snapshot_bytes(self.root, "android-armv7-diagnostic", self.root / "Cargo.lock"))
            seal.verify_snapshot(self.root, "android-armv7-diagnostic", original, self.root / "Cargo.lock")
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                seal.verify_snapshot(self.root, "android", original, self.root / "Cargo.lock")

    def test_armv7_inspector_mutation_invalidates_diagnostic_seal(self) -> None:
        helper = self.root / "scripts/inspect_android_armv7_diagnostic.py"
        helper.write_text("# original inspection recipe\n", encoding="utf-8")
        original = self.root / "armv7-diagnostic-seal.json"
        with mock.patch.object(seal, "local_dependency_roots", return_value=set()):
            original.write_bytes(seal.snapshot_bytes(self.root, "android-armv7-diagnostic", self.root / "Cargo.lock"))
            helper.write_text("# substituted inspection recipe\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                seal.verify_snapshot(self.root, "android-armv7-diagnostic", original, self.root / "Cargo.lock")

    def test_apple_builder_never_relies_on_the_default_seal_platform(self) -> None:
        builder = APPLE_BUILDER.read_text(encoding="utf-8")
        invocations = re.findall(
            r"run_source_seal (?:fingerprint|status)[^\n]*",
            builder,
        )
        self.assertEqual(len(invocations), 2)
        for invocation in invocations:
            self.assertIn("--platform apple", invocation)
        self.assertGreaterEqual(
            builder.count('--lockfile-path "$CARGO_LOCKFILE"'),
            2,
        )

    def test_apple_builder_uses_one_selected_lock_for_all_five_builds(self) -> None:
        builder = APPLE_BUILDER.read_text(encoding="utf-8")
        self.assertEqual(builder.count("run_hermetic_apple_cargo \\\n"), 5)
        self.assertNotIn(
            '-Z unstable-options --lockfile-path "$CARGO_LOCKFILE"',
            builder,
        )
        self.assertIn('--manifest-path "$ROOT_DIR/Cargo.toml"', builder)
        self.assertNotIn('--set "RUSTC_BOOTSTRAP=1"', builder)
        self.assertIn('--set "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"', builder)
        self.assertIn('--set "RUSTDOC=$RUSTDOC_BINARY"', builder)
        self.assertEqual(
            builder.count('--set "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"'),
            1,
        )
        self.assertNotIn("CARGO_BUILD_DIR_", builder)
        self.assertNotRegex(builder, r"rm -rf[^\n]*CARGO_TARGET_DIR")
        self.assertNotIn("write_static_xcframework_info_plist", builder)
        self.assertNotIn("copy_static_xcframework_slice", builder)
        self.assertNotIn("rebuilding the fallback", builder)
        self.assertIn("xcodebuild_status=$?", builder)
        self.assertIn('exit "$xcodebuild_status"', builder)
        self.assertIn(
            "Cargo target, build, and output directories must be pairwise disjoint",
            builder,
        )
        self.assertIn(
            '"cargo_lock_sha256": "$CARGO_LOCK_SHA256_START"',
            builder,
        )

        runner = HERMETIC_RUNNER.read_text(encoding="utf-8")
        self.assertIn('"CARGO_BUILD_JOBS"', runner)
        self.assertIn('"RUSTDOC"', runner)

    def test_apple_hermetic_runner_rejects_incomplete_or_noncanonical_envelope(
        self,
    ) -> None:
        tools = self.root / "hermetic-tools"
        target = self.root / "cargo-target"
        tools.mkdir()
        target.mkdir()
        for name in ("cargo", "rustc", "rustdoc"):
            executable = tools / name
            executable.write_text('#!/bin/sh\nif [ "${RUSTC_BOOTSTRAP+x}" = x ]; then exit 77; fi\nexit 0\n', encoding="utf-8")
            executable.chmod(0o755)
        environment = {
            "CARGO": str(tools / "cargo"),
            "CARGO_BUILD_JOBS": "1",
            "CARGO_HOME": str(self.root / "cargo-home"),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target),
            "CONNECT_NORITO_SOURCE_REVISION": "1" * 40,
            "DEVELOPER_DIR": str(self.root / "developer"),
            "HOME": str(self.root),
            "IPHONEOS_DEPLOYMENT_TARGET": "15.0",
            "IROHA_GIT_COMMIT_HASH": "1" * 40,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NORITO_SKIP_BINDINGS_SYNC": "1",
            "PATH": f"{tools}:/usr/bin:/bin",
            "RUSTC": str(tools / "rustc"),
            "RUSTDOC": str(tools / "rustdoc"),
            "RUSTUP_HOME": str(self.root / "rustup-home"),
            "SDKROOT": str(self.root / "sdk"),
            "TMPDIR": str(self.root),
            "VERGEN_GIT_SHA": "1" * 40,
        }

        def run(assignments: dict[str, str], profile: str = "apple-ios-device") -> subprocess.CompletedProcess[str]:
            command = [sys.executable, "-I", "-S", str(HERMETIC_RUNNER)]
            command.extend(("--profile", profile))
            for name, value in assignments.items():
                command.extend(("--set", f"{name}={value}"))
            command.extend(("--", str(tools / "cargo")))
            return subprocess.run(command, cwd=self.root, text=True, capture_output=True, check=False)

        for profile in ("apple-ios-device", "apple-ios-simulator", "apple-macos"):
            selected = dict(environment)
            if profile == "apple-ios-simulator":
                selected["IPHONESIMULATOR_DEPLOYMENT_TARGET"] = "15.0"
            elif profile == "apple-macos":
                del selected["IPHONEOS_DEPLOYMENT_TARGET"]
                selected["MACOSX_DEPLOYMENT_TARGET"] = "12.0"
            with self.subTest(profile=profile), mock.patch.dict(os.environ, {"RUSTC_BOOTSTRAP": "1"}):
                self.assertEqual(run(selected, profile).returncode, 0, "ambient bootstrap must not reach Apple Cargo")
                for bootstrap in ("", "0", "1"):
                    injected = dict(selected, RUSTC_BOOTSTRAP=bootstrap)
                    refused = run(injected, profile)
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertIn("unexpected=['RUSTC_BOOTSTRAP']", refused.stderr)

        missing_rustdoc = dict(environment)
        del missing_rustdoc["RUSTDOC"]
        rejected = run(missing_rustdoc)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("environment inventory is not exact", rejected.stderr)
        wrong_jobs = dict(environment)
        wrong_jobs["CARGO_BUILD_JOBS"] = "2"
        rejected = run(wrong_jobs)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("CARGO_BUILD_JOBS must be exactly '1'", rejected.stderr)
        mismatched_revision = dict(environment)
        mismatched_revision["VERGEN_GIT_SHA"] = "2" * 40
        rejected = run(mismatched_revision)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("source revision variables must be identical", rejected.stderr)
        noncanonical_revision = dict(environment)
        for name in (
            "CONNECT_NORITO_SOURCE_REVISION",
            "IROHA_GIT_COMMIT_HASH",
            "VERGEN_GIT_SHA",
        ):
            noncanonical_revision[name] = "A" * 40
        rejected = run(noncanonical_revision)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("identical canonical commits", rejected.stderr)
        target_link = self.root / "cargo-target-link"
        target_link.symlink_to(target, target_is_directory=True)
        linked_target = dict(environment)
        linked_target["CARGO_TARGET_DIR"] = str(target_link)
        rejected = run(linked_target)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("non-symbolic canonical directory", rejected.stderr)

    def apple_configuration_runner(self):
        spec = importlib.util.spec_from_file_location("tested_mobile_hermetic_command", HERMETIC_RUNNER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_apple_cargo_configuration_keeps_registry_network_and_custom_aliases(self) -> None:
        runner = self.apple_configuration_runner()
        nested = self.root / "nested" / "work"
        nested.mkdir(parents=True)
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        configuration = self.root / ".cargo" / "config.toml"
        configuration.parent.mkdir(exist_ok=True)
        configuration.write_text('[net]\noffline = true\n[registries.fixture]\nindex = "https://example.invalid/index"\n[alias]\nxtask = "run --package xtask --"\n', encoding="utf-8")
        observations = runner.authenticate_build_cargo_configuration(nested, cargo_home)
        self.assertIn(configuration, observations)
        self.assertIsNotNone(observations[configuration])
        self.assertIn(cargo_home / "config", observations)
        self.assertIsNone(observations[cargo_home / "config"])
        runner.recheck_build_cargo_configuration(observations)

    def test_apple_cargo_configuration_refuses_all_compiler_override_owners(self) -> None:
        runner = self.apple_configuration_runner()
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        configuration = cargo_home / "config.toml"
        forbidden = (
            '[profile.release]\nopt-level = 0\n',
            '[unstable]\nbuild-std = ["std"]\n',
            '[build]\nrustc-wrapper = "/untrusted/wrapper"\n',
            '[build]\nrustc-workspace-wrapper = "/untrusted/wrapper"\n',
            '[build]\nrustflags = ["--cfg", "unreviewed"]\n',
            '[build]\nrustdocflags = ["--cfg", "unreviewed"]\n',
            '[build]\ntarget-dir = "/untrusted/target"\n',
            '[target.aarch64-apple-darwin]\nlinker = "/untrusted/linker"\n',
            '[target.aarch64-apple-darwin]\nrunner = "/untrusted/runner"\n',
            '[target.aarch64-apple-darwin.native]\nrustc-cfg = ["unreviewed"]\n',
            '[env]\nRUSTC_BOOTSTRAP = {value = "1", force = true}\n',
            '[alias]\nbuild = "check"\n',
            'paths = ["/untrusted/dependency"]\n',
            '[patch.crates-io]\nexample = {path = "/untrusted/dependency"}\n',
            'include = "/untrusted/config"\n',
        )
        for body in forbidden:
            with self.subTest(config=body.splitlines()[0]):
                configuration.write_text(body, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "Native Cargo configuration (forbids|overrides)"):
                    runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.write_text('malformed = [', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "cannot be parsed"):
            runner.authenticate_build_cargo_configuration(self.root, cargo_home)

    def test_apple_cargo_configuration_rechecks_absence_contents_and_inode(self) -> None:
        runner = self.apple_configuration_runner()
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        configuration = cargo_home / "config"
        observations = runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.write_text('[net]\noffline = true\n', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "changed during invocation"):
            runner.recheck_build_cargo_configuration(observations)
        observations = runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.write_text('[net]\noffline = false\n', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "changed during invocation"):
            runner.recheck_build_cargo_configuration(observations)
        observations = runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        replacement = cargo_home / "replacement"
        replacement.write_bytes(configuration.read_bytes())
        replacement.replace(configuration)
        with self.assertRaisesRegex(RuntimeError, "changed during invocation"):
            runner.recheck_build_cargo_configuration(observations)
        observations = runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.unlink()
        with self.assertRaisesRegex(RuntimeError, "changed during invocation"):
            runner.recheck_build_cargo_configuration(observations)

    def test_apple_cargo_configuration_rejects_symbolic_nonregular_and_oversized_files(self) -> None:
        runner = self.apple_configuration_runner()
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        configuration = cargo_home / "config.toml"
        target = cargo_home / "original"
        target.write_text('[net]\noffline = true\n', encoding="utf-8")
        configuration.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "not canonical"):
            runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.unlink()
        configuration.mkdir()
        with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
            runner.authenticate_build_cargo_configuration(self.root, cargo_home)
        configuration.rmdir()
        configuration.write_bytes(b" " * (runner._BUILD_CARGO_CONFIG_MAX_BYTES + 1))
        with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
            runner.authenticate_build_cargo_configuration(self.root, cargo_home)

    def test_android_builder_binds_exact_root_lock_and_complete_cargo_envelope(
        self,
    ) -> None:
        builder = ANDROID_BUILDER.read_text(encoding="utf-8")
        for required in (
            '"CARGO_BUILD_JOBS"',
            '"RUSTDOC"',
            '"cargo_build_jobs" to 1',
            '"rustdoc_release" to tools.rustdocRelease',
            '"rustdoc_commit_hash" to tools.rustdocCommitHash',
            '"rustdoc_binary_sha256" to sha256Hex(tools.rustdoc)',
            '"CARGO_BUILD_JOBS=1"',
            '"RUSTDOC=${tools.rustdoc}"',
            '"--locked"',
            '"--offline"',
            '"--jobs"',
            '"--lockfile-path"',
            'tools.cargoLock.toString()',
            '"NORITO_BRIDGE_SEAL_RUSTDOC" to tools.rustdoc.toString()',
            '"NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR" to',
        ):
            self.assertIn(required, builder)
        self.assertIn("rustdocCommitHash == rustcCommitHash", builder)
        self.assertNotIn("MOBILE_SDK_ANDROID_CARGO_LOCK", builder)
        self.assertNotIn("RUSTC_BOOTSTRAP", builder)
        self.assertNotIn('"unstable-options"', builder)
        self.assertIn('"--manifest-path",\n                        irohaRoot.resolve("Cargo.toml").absolutePath,', builder)
        self.assertEqual(builder.count('"--lockfile-path",\n                tools.cargoLock.toString(),'), 2)

    def test_android_hermetic_runner_rejects_inexact_environment_and_command(
        self,
    ) -> None:
        tools = self.root / "android-hermetic-tools"
        target = self.root / "android-cargo-target"
        ndk = self.root / "android-ndk"
        tools.mkdir()
        target.mkdir()
        ndk.mkdir()
        for name in ("cargo", "rustc", "rustdoc"):
            executable = tools / name
            executable.write_text('#!/bin/sh\nif [ "${RUSTC_BOOTSTRAP+x}" = x ]; then exit 77; fi\nexit 0\n', encoding="utf-8")
            executable.chmod(0o755)
        environment = {
            "ANDROID_NDK_HOME": str(ndk),
            "ANDROID_NDK_ROOT": str(ndk),
            "CARGO": str(tools / "cargo"),
            "CARGO_BUILD_JOBS": "1",
            "CARGO_HOME": str(self.root / "cargo-home"),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target),
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NORITO_SKIP_BINDINGS_SYNC": "1",
            "PATH": f"{tools}:/usr/bin:/bin",
            "RUSTC": str(tools / "rustc"),
            "RUSTDOC": str(tools / "rustdoc"),
            "RUSTUP_HOME": str(self.root / "rustup-home"),
            "TMPDIR": str(self.root),
        }
        cargo_arguments = [
            "ndk",
            "-t",
            "arm64-v8a",
            "-o",
            str(self.root / "staging"),
            "build",
            "--locked",
            "--offline",
            "--jobs",
            "1",
            "--manifest-path",
            str(self.root / "Cargo.toml"),
            "--release",
            "-p",
            "connect_norito_bridge",
        ]

        def run(
            assignments: dict[str, str],
            arguments: list[str],
        ) -> subprocess.CompletedProcess[str]:
            command = [sys.executable, "-I", "-S", str(HERMETIC_RUNNER)]
            command.extend(("--profile", "android-cargo"))
            for name, value in assignments.items():
                command.extend(("--set", f"{name}={value}"))
            command.extend(("--", str(tools / "cargo"), *arguments))
            return subprocess.run(
                command,
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
            )

        (tools / "cargo").write_text(
            '#!/bin/sh\n/bin/echo "$CARGO_TARGET_DIR"\n'
            'if [ "${AMBIENT_CHILD_POLICY+x}" = x ]; then exit 91; fi\n'
            'if [ "${RUSTC_BOOTSTRAP+x}" = x ]; then exit 77; fi\nexit 0\n',
            encoding="utf-8",
        )
        with mock.patch.dict(
            os.environ,
            {"AMBIENT_CHILD_POLICY": "TEST ONLY injected", "RUSTC_BOOTSTRAP": "1"},
        ):
            accepted = run(environment, cargo_arguments)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout.strip().splitlines(), [str(target)])

        # The retired compiled-binding originals are not part of the Android profile.
        public_input_directory = tempfile.TemporaryDirectory()
        self.addCleanup(public_input_directory.cleanup)
        retired_original = Path(public_input_directory.name).resolve() / "retired-original.bin"
        retired_original.write_bytes(b"TEST ONLY retired public original; no runtime authority")
        for retired in (
            "MOBILE_SDK_HARDWARE_BOOTSTRAP_COMPILED_BINDING_FILE",
            "MOBILE_SDK_ORDINARY_CONTEXT_COMPILED_BINDING_FILE",
        ):
            with self.subTest(retired=retired):
                rejected = run(dict(environment, **{retired: str(retired_original)}), cargo_arguments)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertIn(f"unexpected=['{retired}']", rejected.stderr)

        (tools / "cargo").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        for bootstrap in ("", "0", "1"):
            with self.subTest(bootstrap=bootstrap):
                changed = dict(environment, RUSTC_BOOTSTRAP=bootstrap)
                rejected = run(changed, cargo_arguments)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("unexpected=['RUSTC_BOOTSTRAP']", rejected.stderr)
        for forbidden in ("-Z", "-Zunstable-options", "--lockfile-path", "--config", "--config=build.jobs=2"):
            with self.subTest(forbidden=forbidden):
                rejected = run(environment, [*cargo_arguments, forbidden])
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("alternate Cargo envelope form", rejected.stderr)
        cargo_home = Path(environment["CARGO_HOME"])
        cargo_home.mkdir()
        config = cargo_home / "config.toml"
        config.write_text('[env]\nRUSTC_BOOTSTRAP = {value = "1", force = true}\n', encoding="utf-8")
        rejected = run(environment, cargo_arguments)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("Native Cargo configuration forbids env", rejected.stderr)
        config.unlink()

        for name, value, expected in (
            ("CARGO_BUILD_JOBS", "2", "must be exactly '1'"),
            ("CARGO_NET_OFFLINE", "false", "must be exactly 'true'"),
        ):
            with self.subTest(environment=name):
                changed = dict(environment)
                changed[name] = value
                rejected = run(changed, cargo_arguments)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected, rejected.stderr)

        missing_rustdoc = dict(environment)
        del missing_rustdoc["RUSTDOC"]
        rejected = run(missing_rustdoc, cargo_arguments)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("environment inventory is not exact", rejected.stderr)

        for removed, expected in (
            (("--offline",), "exactly one --offline"),
            (("--jobs", "1"), "exactly one --jobs"),
            (("--manifest-path", str(self.root / "Cargo.toml")), "exactly one --manifest-path"),
        ):
            with self.subTest(command=removed):
                altered = list(cargo_arguments)
                position = altered.index(removed[0])
                del altered[position : position + len(removed)]
                rejected = run(environment, altered)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected, rejected.stderr)

        alternate_manifest = self.root / "alternate-Cargo.toml"
        alternate_manifest.write_text("[workspace]\n", encoding="utf-8")
        altered = list(cargo_arguments)
        altered[altered.index("--manifest-path") + 1] = str(alternate_manifest)
        rejected = run(environment, altered)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exact sequence --manifest-path", rejected.stderr)

        (tools / "cargo").write_text(
            """#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--manifest-path" ]; then
    shift
    printf '# changed during invocation\\n' > "${1%/*}/Cargo.lock"
    exit 0
  fi
  shift
done
exit 65
""",
            encoding="utf-8",
        )
        rejected = run(environment, cargo_arguments)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("Android root Cargo.lock changed during", rejected.stderr)

    def test_symlinked_rustup_style_proxies_preserve_dispatch_and_fail_on_retarget(
        self,
    ) -> None:
        tools = self.root / "tools"
        tools.mkdir()
        multiplexer = tools / "rustup"
        replacement = tools / "replacement"
        for executable in (multiplexer, replacement):
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        cargo_proxy = tools / "cargo"
        rustc_proxy = tools / "rustc"
        rustdoc_proxy = tools / "rustdoc"
        cargo_proxy.symlink_to(multiplexer.name)
        rustc_proxy.symlink_to(multiplexer.name)
        rustdoc_proxy.symlink_to(multiplexer.name)

        with mock.patch.dict(
            os.environ,
            {
                "NORITO_BRIDGE_SEAL_CARGO": str(cargo_proxy),
                "NORITO_BRIDGE_SEAL_RUSTC": str(rustc_proxy),
                "NORITO_BRIDGE_SEAL_RUSTDOC": str(rustdoc_proxy),
            },
            clear=False,
        ):
            cargo = seal.required_tool("NORITO_BRIDGE_SEAL_CARGO", "cargo")
            rustc = seal.required_tool("NORITO_BRIDGE_SEAL_RUSTC", "rustc")
            rustdoc = seal.required_tool("NORITO_BRIDGE_SEAL_RUSTDOC", "rustdoc")

        self.assertEqual(cargo.invocation, cargo_proxy)
        self.assertEqual(rustc.invocation, rustc_proxy)
        self.assertEqual(rustdoc.invocation, rustdoc_proxy)
        canonical_multiplexer = multiplexer.resolve()
        self.assertEqual(cargo.canonical, canonical_multiplexer)
        self.assertEqual(rustc.canonical, canonical_multiplexer)

        completed = subprocess.CompletedProcess([], 0, stdout=b"")
        with mock.patch.object(seal.subprocess, "run", return_value=completed) as run:
            seal.run(self.root, cargo, ["metadata"], {"PATH": str(tools)})
        self.assertEqual(
            run.call_args.args[0],
            [str(cargo_proxy), "metadata"],
        )
        self.assertEqual(
            run.call_args.kwargs["executable"], str(canonical_multiplexer)
        )

        cargo_proxy.unlink()
        cargo_proxy.symlink_to(replacement.name)
        with self.assertRaisesRegex(RuntimeError, "changed after authentication"):
            seal.run(self.root, cargo, ["metadata"], {"PATH": str(tools)})


if __name__ == "__main__":
    unittest.main()
