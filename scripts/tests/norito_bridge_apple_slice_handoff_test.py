from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest


SCRIPT = Path(__file__).parents[1] / "norito_bridge_apple_slice_handoff.py"
SPEC = importlib.util.spec_from_file_location(
    "norito_bridge_apple_slice_handoff", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class NoritoBridgeAppleSliceHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.archives = self.root / "archives"
        self.libraries = self.root / "libraries"
        self.stage = self.root / "stage"
        self.archives.mkdir()
        self.libraries.mkdir()
        self.stage.mkdir()
        self.common_path = self.root / "common.json"
        self.common = self.valid_common()
        self.write_common(self.common_path, self.common)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def valid_common() -> dict[str, object]:
        digest = "a" * 64
        rust_commit = "b" * 40
        return {
            "schema": handoff.COMMON_SCHEMA,
            "source_commit": "c" * 40,
            "embedded_source_commit": "c" * 40,
            "source_tree_dirty": False,
            "source_fingerprint_sha256": digest,
            "cargo_lock_sha256": digest,
            "bridge_header_sha256": digest,
            "privacy_production_enabled": True,
            "cargo_features": ["privacy-production-enabled"],
            "build_environment": {
                "schema": "iroha.mobile-native-build-environment.v1",
                "wallet_runtime_authority": "cbsi-release-v1",
                "wallet_runtime_trust_ed25519_hex": "3" * 64,
                "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
                "hermetic_runner_sha256": digest,
                "cargo_build_jobs": 1,
                "cargo_incremental": 0,
                "cargo_net_offline": True,
                "rust_toolchain_channel": "1.93.1",
                "cargo_release": "1.93.1",
                "cargo_commit_hash": rust_commit,
                "cargo_binary_sha256": digest,
                "rustc_release": "1.93.1",
                "rustc_commit_hash": rust_commit,
                "rustc_binary_sha256": digest,
                "rustdoc_release": "1.93.1",
                "rustdoc_commit_hash": rust_commit,
                "rustdoc_binary_sha256": digest,
                "python_version": "3.12.11",
                "python_binary_sha256": digest,
                "git_version": "2.39.5",
                "git_binary_sha256": digest,
                "rustup_version": "1.28.2",
                "rustup_binary_sha256": digest,
                "xcode_version": "15.4",
                "xcode_build_version": "15F31d",
                "iphoneos_sdk_version": "17.5",
                "iphonesimulator_sdk_version": "17.5",
                "macosx_sdk_version": "14.5",
                "iphoneos_deployment_target": "15.0",
                "iphonesimulator_deployment_target": "15.0",
                "macosx_deployment_target": "12.0",
            },
        }

    def test_public_runtime_root_is_mandatory_exact_build_data(self):
        for invalid in [None, "", "0"*64, "A"*64, "3"*63, "3"*65, 1, True]:
            common=self.valid_common();common["build_environment"]["wallet_runtime_trust_ed25519_hex"]=invalid
            with self.assertRaises(handoff.HandoffError):handoff.validate_common(common)
        common=self.valid_common();del common["build_environment"]["wallet_runtime_trust_ed25519_hex"]
        with self.assertRaises(handoff.HandoffError):handoff.validate_common(common)

    def test_application_authority_is_exact_and_cannot_be_omitted(self):
        for authority in ["bpng-taira-v7", "cbsi-release-v1"]:
            common=self.valid_common();common["build_environment"]["wallet_runtime_authority"]=authority
            handoff.validate_common(common)
        for authority in [None, "", "bpng", "bpng-taira-v6", "BPNG-TAIRA-V7", "bpng-taira-v7\n", 1, True, {}, []]:
            common=self.valid_common();common["build_environment"]["wallet_runtime_authority"]=authority
            with self.assertRaises(handoff.HandoffError):handoff.validate_common(common)
        common=self.valid_common();del common["build_environment"]["wallet_runtime_authority"]
        with self.assertRaises(handoff.HandoffError):handoff.validate_common(common)

    def test_disabled_native_support_and_missing_feature_are_rejected(self) -> None:
        for value in (False, 0, 1, "true", None):
            with self.subTest(value=value):
                common = self.valid_common()
                common["privacy_production_enabled"] = value
                with self.assertRaisesRegex(handoff.HandoffError, "mandatory privacy support"):
                    handoff.validate_common(common)
        common = self.valid_common()
        common["cargo_features"] = []
        with self.assertRaisesRegex(handoff.HandoffError, "non-canonical Cargo feature"):
            handoff.validate_common(common)

    @staticmethod
    def write_common(path: Path, common: dict[str, object]) -> None:
        path.write_text(
            json.dumps(common, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def pack_inventory(
        self, *, common_overrides: dict[str, dict[str, object]] | None = None
    ) -> tuple[list[str], dict[str, bytes]]:
        digest_arguments: list[str] = []
        expected_libraries: dict[str, bytes] = {}
        for index, (target, profile) in enumerate(
            handoff.TARGET_PROFILES.items(), start=1
        ):
            target_root = self.archives / target
            target_root.mkdir()
            library = self.libraries / f"{target}.a"
            payload = (f"{target}\n".encode("utf-8")) * index
            library.write_bytes(payload)
            expected_libraries[target] = payload
            common_path = self.common_path
            if common_overrides and target in common_overrides:
                common_path = self.root / f"{target}.common.json"
                changed = json.loads(json.dumps(self.common))
                overrides = common_overrides[target]
                environment_overrides = overrides.get("build_environment")
                if environment_overrides is not None:
                    changed["build_environment"].update(environment_overrides)
                    overrides = {
                        key: value
                        for key, value in overrides.items()
                        if key != "build_environment"
                    }
                changed.update(overrides)
                self.write_common(common_path, changed)
            archive = target_root / handoff.ARCHIVE_NAME
            handoff.pack(
                argparse.Namespace(
                    common=common_path,
                    target=target,
                    profile=profile,
                    library=library,
                    archive=archive,
                )
            )
            digest_arguments.append(
                f"{target}={hashlib.sha256(archive.read_bytes()).hexdigest()}"
            )
        return digest_arguments, expected_libraries

    def test_roundtrip_restores_exact_five_slice_inventory(self) -> None:
        digest_arguments, expected_libraries = self.pack_inventory()
        destination = self.stage / "cargo-libraries"
        handoff.restore(
            argparse.Namespace(
                common=self.common_path,
                archive_root=self.archives,
                destination=destination,
                sha256=digest_arguments,
            )
        )

        self.assertEqual(
            {entry.name for entry in destination.iterdir()},
            set(handoff.TARGET_PROFILES),
        )
        for target, expected in expected_libraries.items():
            self.assertEqual(
                (destination / target / handoff.LIBRARY_NAME).read_bytes(),
                expected,
            )

    def test_restore_rejects_archive_digest_tampering(self) -> None:
        digest_arguments, _ = self.pack_inventory()
        digest_arguments[0] = digest_arguments[0].split("=", 1)[0] + "=" + "0" * 64

        with self.assertRaisesRegex(handoff.HandoffError, "archive digest mismatch"):
            handoff.restore(
                argparse.Namespace(
                    common=self.common_path,
                    archive_root=self.archives,
                    destination=self.stage / "cargo-libraries",
                    sha256=digest_arguments,
                )
            )

    def test_restore_rejects_nonzero_tar_padding_with_matching_digest(self) -> None:
        digest_arguments, _ = self.pack_inventory()
        target = "aarch64-apple-ios"
        archive = self.archives / target / handoff.ARCHIVE_NAME
        with tarfile.open(archive, mode="r:") as reader:
            attestation = reader.getmembers()[0]
        padding_offset = attestation.offset_data + attestation.size
        with archive.open("r+b") as handle:
            handle.seek(padding_offset)
            handle.write(b"x")
        replacement = f"{target}={hashlib.sha256(archive.read_bytes()).hexdigest()}"
        digest_arguments[0] = replacement

        with self.assertRaisesRegex(
            handoff.HandoffError, "archive padding is non-canonical"
        ):
            handoff.restore(
                argparse.Namespace(
                    common=self.common_path,
                    archive_root=self.archives,
                    destination=self.stage / "cargo-libraries",
                    sha256=digest_arguments,
                )
            )

    def test_restore_rejects_a_mixed_source_snapshot(self) -> None:
        target = "x86_64-apple-darwin"
        digest_arguments, _ = self.pack_inventory(
            common_overrides={target: {"source_commit": "d" * 40}}
        )

        with self.assertRaisesRegex(
            handoff.HandoffError, "build contract differs from the assembler"
        ):
            handoff.restore(
                argparse.Namespace(
                    common=self.common_path,
                    archive_root=self.archives,
                    destination=self.stage / "cargo-libraries",
                    sha256=digest_arguments,
                )
            )

    def test_restore_retains_but_does_not_equalize_orchestration_tools(self) -> None:
        target = "x86_64-apple-darwin"
        digest_arguments, expected_libraries = self.pack_inventory(
            common_overrides={
                target: {
                    "build_environment": {
                        "python_version": "3.12.12",
                        "python_binary_sha256": "d" * 64,
                        "git_version": "2.50.1",
                        "git_binary_sha256": "e" * 64,
                        "rustup_version": "1.28.3",
                        "rustup_binary_sha256": "f" * 64,
                    }
                }
            }
        )
        destination = self.stage / "cargo-libraries"

        handoff.restore(
            argparse.Namespace(
                common=self.common_path,
                archive_root=self.archives,
                destination=destination,
                sha256=digest_arguments,
            )
        )

        self.assertEqual(
            (destination / target / handoff.LIBRARY_NAME).read_bytes(),
            expected_libraries[target],
        )

    def test_pack_rejects_a_target_profile_mismatch(self) -> None:
        library = self.libraries / "device.a"
        library.write_bytes(b"device")
        target_root = self.archives / "aarch64-apple-ios"
        target_root.mkdir()

        with self.assertRaisesRegex(
            handoff.HandoffError, "target and hermetic profile do not match"
        ):
            handoff.pack(
                argparse.Namespace(
                    common=self.common_path,
                    target="aarch64-apple-ios",
                    profile="apple-macos",
                    library=library,
                    archive=target_root / handoff.ARCHIVE_NAME,
                )
            )

    def test_common_attestation_rejects_boolean_cargo_job_count(self) -> None:
        common = json.loads(json.dumps(self.common))
        common["build_environment"]["cargo_build_jobs"] = True

        with self.assertRaisesRegex(
            handoff.HandoffError, "exactly one Cargo job"
        ):
            handoff.validate_common(common)

    def test_common_attestation_rejects_malformed_embedded_source_commit(
        self,
    ) -> None:
        common = json.loads(json.dumps(self.common))
        common["embedded_source_commit"] = "not-a-commit"

        with self.assertRaisesRegex(
            handoff.HandoffError, "non-canonical embedded source commit"
        ):
            handoff.validate_common(common)


if __name__ == "__main__":
    unittest.main()
