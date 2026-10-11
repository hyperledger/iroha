#!/usr/bin/env python3
"""Tests for the guarded Swift fallback-pin owner."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import fcntl
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
OWNER = REPO / "scripts/update_norito_bridge_swift_pins.py"
OWNER_SPEC = importlib.util.spec_from_file_location(
    "update_norito_bridge_swift_pins_for_test",
    OWNER,
)
assert OWNER_SPEC is not None and OWNER_SPEC.loader is not None
pin_owner = importlib.util.module_from_spec(OWNER_SPEC)
sys.modules[OWNER_SPEC.name] = pin_owner
OWNER_SPEC.loader.exec_module(pin_owner)
SLICES = {
    "ios-arm64": (["arm64"], "ios", None),
    "ios-arm64_x86_64-simulator": (["arm64", "x86_64"], "ios", "simulator"),
    "macos-arm64_x86_64": (["arm64", "x86_64"], "macos", None),
}
VALIDATOR_SCRIPT = REPO / "scripts/validate_norito_bridge_xcframework.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "validate_norito_bridge_xcframework_for_pin_owner_test",
    VALIDATOR_SCRIPT,
)
assert VALIDATOR_SPEC is not None and VALIDATOR_SPEC.loader is not None
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
sys.modules[VALIDATOR_SPEC.name] = validator
VALIDATOR_SPEC.loader.exec_module(validator)


class SwiftPinOwnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.temporary_root = Path(self.temporary.name).resolve()
        self.root = self.temporary_root / "repo"
        scripts = self.root / "scripts"
        scripts.mkdir(parents=True)
        for name in (
            "norito_bridge_source_seal.py",
            "run_mobile_hermetic_command.py",
        ):
            shutil.copy2(REPO / "scripts" / name, scripts / name)
        (scripts / "validate_norito_bridge_xcframework.py").write_text(
            '''"""Pin-owner test double requiring the full provenance contract."""
import fcntl
import json
import os
from pathlib import Path


class ValidationError(RuntimeError):
    pass


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def validate(
    *,
    root,
    lockfile_path,
    xcframework,
    manifest_path,
    manifest_link,
    expected_link_target,
    swift_loader=None,
    verify_repository_provenance=False,
    allow_dirty_source=False,
):
    if verify_repository_provenance is not True:
        raise ValidationError("full repository provenance was not requested")
    if os.environ.get("PIN_OWNER_TEST_REJECT_PROVENANCE") == "1":
        raise ValidationError("simulated stale repository provenance")
    if lockfile_path != root.parent / "graph/Cargo.lock" or lockfile_path.stat().st_mode & 0o222:
        raise ValidationError("pin owner failed to propagate explicit selected lock")
    lock_path = manifest_path.parent.parent / ".NoritoBridge.publish.lockfile"
    if os.environ.get("PIN_OWNER_TEST_ASSERT_LOCK_HELD") == "1":
        descriptor = os.open(lock_path, os.O_RDWR)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise ValidationError("artifact publication lock was not held")
        finally:
            os.close(descriptor)
    if not manifest_link.is_symlink() or os.readlink(manifest_link) != expected_link_target:
        raise ValidationError("manifest link is not canonical")
    payload = json.loads(
        manifest_path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    if payload["source_tree_dirty"] and not allow_dirty_source:
        raise ValidationError("release artifact must be built from a clean source tree")
    marker = manifest_path.parent.parent / ".mutate-manifest-after-validation"
    if marker.exists():
        changed = dict(payload)
        changed["hashes"] = {key: "f" * 64 for key in payload["hashes"]}
        manifest_path.write_text(
            json.dumps(changed, sort_keys=True) + "\\n",
            encoding="utf-8",
        )
    if os.environ.get("PIN_OWNER_TEST_REPLACE_SELECTED_LOCK") == "1":
        replacement = lockfile_path.with_name("replacement-Cargo.lock")
        replacement.write_bytes(lockfile_path.read_bytes())
        replacement.replace(lockfile_path)
    if os.environ.get("PIN_OWNER_TEST_REPLACE_LOCK") == "1":
        lock_path.unlink()
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
    return payload
''',
            encoding="utf-8",
        )
        # Pure graph data for this pin-owner fixture, never a production Cargo selection.
        graph = b'version = 4\n\n[[package]]\nname = "swift-pin-owner-fixture"\nversion = "0.0.0"\n'
        (self.root / "Cargo.lock").write_bytes(graph)
        (self.root / "ci").mkdir()
        (self.root / "ci/privacy_sdk_cargo_lockfile.sh").write_text(
            'readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"'
            + hashlib.sha256(graph).hexdigest() + '"\n', encoding="utf-8")
        graph_directory = self.temporary_root / "graph"
        graph_directory.mkdir()
        self.lockfile = graph_directory / "Cargo.lock"
        shutil.copyfile(self.root / "Cargo.lock", self.lockfile)
        self.lockfile.chmod(0o400)
        authoritative_headers = {
            "include/NoritoBridge.h": REPO
            / "crates/connect_norito_bridge/include/NoritoBridge.h",
            "include/connect_norito_bridge.h": REPO
            / "crates/connect_norito_bridge/include/connect_norito_bridge.h",
            "module.modulemap.template": REPO
            / "crates/connect_norito_bridge/module.modulemap.template",
            "src/lib.rs": REPO / "crates/connect_norito_bridge/src/lib.rs",
        }
        bridge_root = self.root / "crates/connect_norito_bridge"
        for relative, source in authoritative_headers.items():
            destination = bridge_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        privacy_protocol = (
            self.root / "crates/iroha_data_model/src/privacy/protocol.rs"
        )
        privacy_protocol.parent.mkdir(parents=True)
        shutil.copy2(
            REPO / "crates/iroha_data_model/src/privacy/protocol.rs",
            privacy_protocol,
        )
        self.loader = (
            self.root / "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
        )
        self.loader.parent.mkdir(parents=True)
        self.old_hashes = {key: str(index + 1) * 64 for index, key in enumerate(SLICES)}
        self.write_loader(self.old_hashes)

        self.artifact = self.temporary_root / "artifact"
        self.output_root = self.temporary_root / "outputs"
        self.output_root.mkdir()
        xcframework = self.artifact / "NoritoBridge.xcframework"
        xcframework.mkdir(parents=True)
        (xcframework / ".privacy-production-enabled").touch()
        header = (
            REPO / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
        ).read_bytes()
        libraries = []
        self.hashes = {}
        for identifier, (architectures, platform, variant) in SLICES.items():
            headers = xcframework / identifier / "Headers"
            headers.mkdir(parents=True)
            binary = xcframework / identifier / "libNoritoBridge.a"
            binary.write_bytes(identifier.encode("ascii"))
            self.hashes[identifier] = hashlib.sha256(binary.read_bytes()).hexdigest()
            (headers / "NoritoBridge.h").write_bytes(
                (REPO / "crates/connect_norito_bridge/include/NoritoBridge.h").read_bytes()
            )
            (headers / "connect_norito_bridge.h").write_bytes(header)
            (headers / "module.modulemap").write_bytes(
                (
                    REPO
                    / "crates/connect_norito_bridge/module.modulemap.template"
                ).read_bytes()
            )
            library = {
                "LibraryIdentifier": identifier,
                "LibraryPath": "libNoritoBridge.a",
                "HeadersPath": "Headers",
                "SupportedArchitectures": architectures,
                "SupportedPlatform": platform,
            }
            if variant is not None:
                library["SupportedPlatformVariant"] = variant
            libraries.append(library)
        with (xcframework / "Info.plist").open("wb") as output:
            plistlib.dump(
                {
                    "AvailableLibraries": libraries,
                    "CFBundlePackageType": "XFWK",
                    "XCFrameworkFormatVersion": "1.0",
                },
                output,
            )
        payload = {
            "version": "1.0.0",
            "native_bridge_abi_version": 29,
            "privacy_production_enabled": True,
            "cargo_features": ["privacy-production-enabled"],
            "build_environment": {
                "schema": "iroha.mobile-native-build-environment.v1",
                "wallet_runtime_authority": "cbsi-release-v1",
                "wallet_runtime_trust_ed25519_hex": "3" * 64,
                "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
                "hermetic_runner_sha256": hashlib.sha256(
                    (scripts / "run_mobile_hermetic_command.py").read_bytes()
                ).hexdigest(),
                "environment_profiles": validator.EXPECTED_ENVIRONMENT_PROFILES,
                "cargo_build_jobs": 1,
                "rust_toolchain_channel": "1.93.1",
                "cargo_release": "1.93.1",
                "cargo_commit_hash": "c" * 40,
                "cargo_binary_sha256": "d" * 64,
                "rustc_release": "1.93.1",
                "rustc_commit_hash": "b" * 40,
                "rustc_binary_sha256": "e" * 64,
                "rustdoc_release": "1.93.1",
                "rustdoc_commit_hash": "b" * 40,
                "rustdoc_binary_sha256": "f" * 64,
                "python_version": "3.12.13",
                "python_binary_sha256": "1" * 64,
                "git_version": "2.50.1",
                "git_binary_sha256": "2" * 64,
                "rustup_version": "1.28.2",
                "rustup_binary_sha256": "3" * 64,
                "xcode_version": "26.5",
                "xcode_build_version": "17F12",
                "iphoneos_sdk_version": "26.5",
                "iphonesimulator_sdk_version": "26.5",
                "macosx_sdk_version": "26.5",
                "iphoneos_deployment_target": "15.0",
                "iphonesimulator_deployment_target": "15.0",
                "macosx_deployment_target": "12.0",
            },
            "source_commit": "a" * 40,
            "embedded_source_commit": "a" * 40,
            "source_tree_dirty": False,
            "source_fingerprint_sha256": "b" * 64,
            "cargo_lock_sha256": hashlib.sha256(
                (self.root / "Cargo.lock").read_bytes()
            ).hexdigest(),
            "bridge_header_sha256": hashlib.sha256(header).hexdigest(),
            "required_symbols": list(validator.EXPECTED_REQUIRED_SYMBOLS),
            "forbidden_symbols": list(validator.EXPECTED_FORBIDDEN_SYMBOLS),
            "hashes": self.hashes,
        }
        (xcframework / "NoritoBridge.artifacts.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        (self.artifact / "NoritoBridge.artifacts.json").symlink_to(
            "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_loader(self, hashes: dict[str, str]) -> None:
        order = (
            "macos-arm64_x86_64",
            "ios-arm64",
            "ios-arm64_x86_64-simulator",
        )
        self.loader.write_text(
            "    private static let expectedHashes: [String: String] = [\n"
            + "\n".join(
                f'        "{key}": "{hashes[key]}"{"," if index < 2 else ""}'
                for index, key in enumerate(order)
            )
            + "\n    ]\n",
            encoding="utf-8",
        )

    def run_owner(
        self,
        *arguments: str,
        artifact: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(OWNER),
                "--root",
                str(self.root),
                "--lockfile-path", str(self.lockfile),
                "--artifact-dir",
                str(artifact or self.artifact),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_check_and_external_output_are_the_only_supported_modes(self) -> None:
        preimage = self.loader.read_bytes()
        help_result = self.run_owner("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--check", help_result.stdout)
        self.assertIn("--output OUTPUT", help_result.stdout)
        self.assertIn("--allow-dirty-source", help_result.stdout)
        self.assertNotIn("--write", help_result.stdout)

        stale = self.run_owner("--check")
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("pins are stale", stale.stderr)

        retired = self.run_owner("--check", "--write")
        self.assertNotEqual(retired.returncode, 0)
        self.assertIn("unrecognized arguments: --write", retired.stderr)
        self.assertEqual(self.loader.read_bytes(), preimage)

        self.write_loader(self.hashes)
        self.assertEqual(self.run_owner("--check").returncode, 0)

    def test_selected_build_lock_replacement_aborts_before_pin_output(self) -> None:
        preimage = self.loader.read_bytes()
        output = self.output_root / "selected-lock-replaced.swift"
        environment = os.environ.copy()
        environment["PIN_OWNER_TEST_REPLACE_SELECTED_LOCK"] = "1"
        result = self.run_owner(
            "--output", str(output), "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(), environment=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected Cargo lock changed during Swift pin projection", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.loader.read_bytes(), preimage)

    def test_output_mode_never_mutates_the_loader(self) -> None:
        preimage = self.loader.read_bytes()
        output = self.output_root / "prospective.swift"
        result = self.run_owner(
            "--output",
            str(output),
            "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.loader.read_bytes(), preimage)
        self.assertNotEqual(output.read_bytes(), preimage)
        duplicate = self.run_owner(
            "--output",
            str(output),
            "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(),
        )
        self.assertNotEqual(duplicate.returncode, 0)

        repository_output = self.root / "prospective.swift"
        confined = self.run_owner(
            "--output",
            str(repository_output),
            "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(),
        )
        self.assertNotEqual(confined.returncode, 0)
        self.assertIn("outside the repository", confined.stderr)
        self.assertFalse(repository_output.exists())

        symbolic_parent = self.temporary_root / "symbolic-output"
        symbolic_parent.symlink_to(self.output_root, target_is_directory=True)
        symbolic_output = symbolic_parent / "symbolic-prospective.swift"
        symbolic = self.run_owner(
            "--output",
            str(symbolic_output),
            "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(),
        )
        self.assertNotEqual(symbolic.returncode, 0)
        self.assertIn("non-symbolic canonical directory", symbolic.stderr)
        self.assertFalse(symbolic_output.exists())

    def test_both_modes_forward_dirty_source_allowance_only_when_explicit(self) -> None:
        """Exercise CLI propagation with a provenance double, not native admission."""
        manifest = self.artifact / "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["source_tree_dirty"] = True
        manifest.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        self.write_loader(self.hashes)
        preimage = self.loader.read_bytes()
        output = self.output_root / "dirty-local.swift"
        modes = (
            ("--check",),
            (
                "--output", str(output), "--expected-preimage-sha256",
                hashlib.sha256(preimage).hexdigest(),
            ),
        )
        for arguments in modes:
            with self.subTest(mode=arguments[0]):
                rejected = self.run_owner(*arguments)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("clean source tree", rejected.stderr)
                self.assertFalse(output.exists())
                accepted = self.run_owner(*arguments, "--allow-dirty-source")
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                self.assertEqual(self.loader.read_bytes(), preimage)
        self.assertEqual(output.read_bytes(), preimage)

    def test_dirty_source_allowance_keeps_provenance_and_preimage_guards(self) -> None:
        """A CLI allowance cannot bypass the rejecting provenance test double."""
        self.write_loader(self.hashes)
        preimage = self.loader.read_bytes()
        output = self.output_root / "rejected.swift"
        stale_environment = os.environ.copy()
        stale_environment["PIN_OWNER_TEST_REJECT_PROVENANCE"] = "1"
        for arguments in (
            ("--check",),
            (
                "--output", str(output), "--expected-preimage-sha256",
                hashlib.sha256(preimage).hexdigest(),
            ),
        ):
            with self.subTest(mode=arguments[0]):
                rejected = self.run_owner(
                    *arguments, "--allow-dirty-source", environment=stale_environment,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("stale repository provenance", rejected.stderr)
                self.assertFalse(output.exists())
                self.assertEqual(self.loader.read_bytes(), preimage)
        wrong_preimage = self.run_owner(
            "--output", str(output), "--allow-dirty-source",
            "--expected-preimage-sha256", "0" * 64,
        )
        self.assertNotEqual(wrong_preimage.returncode, 0)
        self.assertIn("preimage differs", wrong_preimage.stderr)
        self.assertFalse(output.exists())

    def test_dirty_source_allowance_cannot_skip_real_tool_provenance(self) -> None:
        """Run the real validator without mocks; invalid tools must still refuse."""
        for name in (
            "validate_norito_bridge_xcframework.py",
            "check_mobile_sdk_artifact_pin_commit.py",
        ):
            shutil.copy2(REPO / "scripts" / name, self.root / "scripts" / name)
        manifest = self.artifact / "NoritoBridge.xcframework/NoritoBridge.artifacts.json"
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["source_tree_dirty"] = True
        manifest.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        self.write_loader(self.hashes)
        preimage = self.loader.read_bytes()
        output = self.output_root / "unverified-tools.swift"
        environment = os.environ.copy()
        environment["NORITO_BRIDGE_SEAL_CARGO"] = str(self.temporary_root / "missing-cargo")
        for arguments in (
            ("--check",),
            (
                "--output", str(output), "--expected-preimage-sha256",
                hashlib.sha256(preimage).hexdigest(),
            ),
        ):
            with self.subTest(mode=arguments[0]):
                rejected = self.run_owner(
                    *arguments, "--allow-dirty-source", environment=environment,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("unable to authenticate artifact source provenance", rejected.stderr)
                self.assertIn("missing-cargo", rejected.stderr)
                self.assertFalse(output.exists())
                self.assertEqual(self.loader.read_bytes(), preimage)

    def test_builder_forwards_only_its_explicit_dirty_source_option(self) -> None:
        """Execute the real argument assembly; do not invoke any native build."""
        source = (REPO / "scripts/build_norito_xcframework.sh").read_text(encoding="utf-8")
        self.assertIn("ALLOW_DIRTY_SOURCE=0", source)
        fragment = source.split("SWIFT_PIN_OWNER_ARGUMENTS=(", 1)[1].split("\nenv -i \\\n", 1)[0]
        fragment = "SWIFT_PIN_OWNER_ARGUMENTS=(" + fragment
        invocation = source.split('"$ROOT_DIR/scripts/update_norito_bridge_swift_pins.py"', 1)[1]
        self.assertTrue(invocation.startswith(' \\\n  "${SWIFT_PIN_OWNER_ARGUMENTS[@]}"\n'))
        environment = {
            "PATH": "/usr/bin:/bin",
            "ROOT_DIR": "/repo with spaces",
            "CARGO_LOCKFILE": "/reviewed graph/Cargo.lock",
            "PUBLISH_ROOT": "/external artifacts",
            "PUBLISH_PROSPECTIVE_LOADER": "/external artifacts/prospective.swift",
            "SWIFT_PIN_PREIMAGE_SHA256": "a" * 64,
        }
        expected = [
            "--root", environment["ROOT_DIR"],
            "--artifact-dir", environment["PUBLISH_ROOT"],
            "--lockfile-path", environment["CARGO_LOCKFILE"],
            "--output", environment["PUBLISH_PROSPECTIVE_LOADER"],
            "--expected-preimage-sha256", environment["SWIFT_PIN_PREIMAGE_SHA256"],
        ]
        for allowance in ("0", "1", "true"):
            with self.subTest(allowance=allowance):
                result = subprocess.run(
                    ["/bin/bash", "-euc", fragment + '\nprintf "%s\\0" "${SWIFT_PIN_OWNER_ARGUMENTS[@]}"'],
                    env={**environment, "ALLOW_DIRTY_SOURCE": allowance},
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                arguments = result.stdout.decode().split("\0")[:-1]
                self.assertEqual(arguments, expected + (["--allow-dirty-source"] if allowance == "1" else []))

    def test_late_output_competitor_is_preserved(self) -> None:
        output = self.output_root / "prospective.swift"
        retained = self.output_root / "owner-output.retained"
        projected = b"owner projection\n"
        competitor = b"late competitor\n"
        original_fsync = pin_owner.os.fsync
        swapped = False

        def swap_path(descriptor: int) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                output.rename(retained)
                output.write_bytes(competitor)
            original_fsync(descriptor)

        with mock.patch.object(pin_owner.os, "fsync", side_effect=swap_path):
            with self.assertRaises(pin_owner.PinOwnerError):
                pin_owner._write_new_file(output, projected, 0o600, self.root)

        self.assertTrue(swapped)
        self.assertEqual(output.read_bytes(), competitor)
        self.assertEqual(retained.read_bytes(), projected)

    def test_artifact_lock_and_repository_provenance_are_mandatory(self) -> None:
        lock_path = self.artifact / ".NoritoBridge.publish.lockfile"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            contended = self.run_owner("--check")
        finally:
            os.close(descriptor)
        self.assertNotEqual(contended.returncode, 0)
        self.assertIn("artifact publication lock", contended.stderr)

        stale_environment = os.environ.copy()
        stale_environment["PIN_OWNER_TEST_REJECT_PROVENANCE"] = "1"
        stale = self.run_owner("--check", environment=stale_environment)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("stale repository provenance", stale.stderr)

        repository_artifact = self.root / "artifact"
        shutil.copytree(self.artifact, repository_artifact, symlinks=True)
        confined = self.run_owner("--check", artifact=repository_artifact)
        self.assertNotEqual(confined.returncode, 0)
        self.assertIn("outside the repository", confined.stderr)

        self.write_loader(self.hashes)
        held_environment = os.environ.copy()
        held_environment["PIN_OWNER_TEST_ASSERT_LOCK_HELD"] = "1"
        held = self.run_owner("--check", environment=held_environment)
        self.assertEqual(held.returncode, 0, held.stderr)

        replaced_environment = os.environ.copy()
        replaced_environment["PIN_OWNER_TEST_REPLACE_LOCK"] = "1"
        replaced = self.run_owner("--check", environment=replaced_environment)
        self.assertNotEqual(replaced.returncode, 0)
        self.assertIn("not authenticated", replaced.stderr)

    def test_symbolic_loader_is_rejected_without_following_it(self) -> None:
        real_loader = self.loader.with_name("NativeBridge.real.swift")
        self.loader.rename(real_loader)
        self.loader.symlink_to(real_loader.name)
        result = self.run_owner("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not traverse symbolic links", result.stderr)
        self.assertEqual(real_loader.read_bytes(), self.loader.read_bytes())

    def test_projection_uses_the_single_validated_manifest_payload(self) -> None:
        preimage = self.loader.read_bytes()
        marker = self.artifact / ".mutate-manifest-after-validation"
        marker.touch()
        output = self.output_root / "single-payload.swift"
        result = self.run_owner(
            "--output",
            str(output),
            "--expected-preimage-sha256",
            hashlib.sha256(preimage).hexdigest(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        contents = output.read_text(encoding="utf-8")
        for key, value in self.hashes.items():
            self.assertIn(f'"{key}": "{value}"', contents)
        self.assertNotIn("f" * 64, contents)

    def test_decoy_hash_dictionary_cannot_satisfy_or_redirect_projection(self) -> None:
        preimage = self.loader.read_bytes()
        decoy = (
            b"\nlet decoyHashes = [\n"
            + b"\n".join(
                f'    "{key}": "{self.old_hashes[key]}"'
                f'{"," if index < 2 else ""}'.encode("ascii")
                for index, key in enumerate(
                    (
                        "macos-arm64_x86_64",
                        "ios-arm64",
                        "ios-arm64_x86_64-simulator",
                    )
                )
            )
            + b"\n]\n"
        )
        self.loader.write_bytes(preimage + decoy)
        guarded_preimage = self.loader.read_bytes()
        output = self.output_root / "decoy-safe.swift"
        result = self.run_owner(
            "--output",
            str(output),
            "--expected-preimage-sha256",
            hashlib.sha256(guarded_preimage).hexdigest(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        projected = output.read_text(encoding="utf-8")
        for key in SLICES:
            self.assertIn(f'"{key}": "{self.hashes[key]}"', projected)
            self.assertIn(f'"{key}": "{self.old_hashes[key]}"', projected)

        self.loader.write_text(
            self.loader.read_text(encoding="utf-8").replace(
                "private static let expectedHashes",
                "private static let retiredHashes",
            ),
            encoding="utf-8",
        )
        rejected = self.run_owner("--check")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("canonical expectedHashes block", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
