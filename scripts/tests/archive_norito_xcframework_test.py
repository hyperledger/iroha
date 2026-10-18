#!/usr/bin/env python3
"""Focused tests for the deterministic NoritoBridge archive owner."""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import zlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ROOT
OWNER = ROOT / "scripts/archive_norito_xcframework.py"
VALIDATOR = ROOT / "scripts/validate_norito_bridge_xcframework.py"
SOURCE_DATE_EPOCH = "1700000001"
NORMALIZED_ZIP_TIME = (2023, 11, 14, 22, 13, 20)
# Mechanical fixtures never select a moving checkout or release Cargo graph.
FIXTURE_CARGO_LOCK = (
    b'version = 4\n\n[[package]]\nname = "archive-owner-fixture"\nversion = "0.0.0"\n'
)
FIXTURE_SOURCE_FILES = (
    "scripts/archive_norito_xcframework.py",
    "scripts/validate_norito_bridge_xcframework.py",
    "scripts/norito_bridge_source_seal.py",
    "scripts/check_mobile_sdk_artifact_pin_commit.py",
    "scripts/run_mobile_hermetic_command.py",
    "scripts/build_norito_xcframework.sh",
    "scripts/check_mobile_sdk_artifacts.sh",
    "crates/connect_norito_bridge/include/connect_norito_bridge.h",
    "crates/connect_norito_bridge/include/NoritoBridge.h",
    "crates/connect_norito_bridge/module.modulemap.template",
    "crates/connect_norito_bridge/src/lib.rs",
    "crates/iroha_data_model/src/privacy/protocol.rs",
)
SLICE_METADATA = {
    "ios-arm64": ("ios", ["arm64"], None),
    "ios-arm64_x86_64-simulator": (
        "ios",
        ["arm64", "x86_64"],
        "simulator",
    ),
    "macos-arm64_x86_64": ("macos", ["arm64", "x86_64"], None),
}


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def reference_stored_zip(framework: Path) -> bytes:
    """Encode the small ASCII fixture's ZIP records without the archive owner.

    This independent oracle fixes the ZIP record layout, metadata and ordering,
    while taking payload bytes from the fixture. It intentionally handles only
    these small stored entries; production ZIP64 remains the owner's concern.
    """
    year, month, day, hour, minute, second = NORMALIZED_ZIP_TIME
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    entries = [(b"NoritoBridge.xcframework/", framework)]
    for path in framework.rglob("*"):
        name = "NoritoBridge.xcframework/" + path.relative_to(framework).as_posix()
        entries.append(((name + ("/" if path.is_dir() else "")).encode("ascii"), path))
    entries.sort(key=lambda item: item[0])
    local = bytearray()
    central = bytearray()
    for name, path in entries:
        directory = path.is_dir()
        contents = b"" if directory else path.read_bytes()
        checksum = zlib.crc32(contents) & 0xFFFFFFFF
        size = len(contents)
        mode = (stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)
        attributes = (mode << 16) | (0x10 if directory else 0)
        offset = len(local)
        local.extend(struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, dos_time, dos_date,
            checksum, size, size, len(name), 0,
        ))
        local.extend(name)
        local.extend(contents)
        central.extend(struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20, 0, 0,
            dos_time, dos_date, checksum, size, size, len(name), 0, 0, 0, 0,
            attributes, offset,
        ))
        central.extend(name)
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
        len(central), len(local), 0,
    )
    return bytes(local + central) + end


def load_owner_module():
    spec = importlib.util.spec_from_file_location("norito_bridge_archive_owner", OWNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load archive owner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_validator_module():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "norito_bridge_archive_test_validator",
        VALIDATOR,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load XCFramework validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ArchiveNoritoXcframeworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="norito-bridge-archive-owner-test."
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        # A source fixture and sibling outputs exercise the real external-path
        # rules even when the entire test lives under checkout-local TMPDIR.
        # These are current owner scripts plus unit inputs, not a native build.
        source_root = self.root / "reviewed-source"
        for relative in FIXTURE_SOURCE_FILES:
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPOSITORY_ROOT / relative, destination)
        (source_root / "Cargo.lock").write_bytes(FIXTURE_CARGO_LOCK)
        graph_directory = self.root / "graph"
        graph_directory.mkdir()
        self.lockfile = graph_directory / "Cargo.lock"
        self.lockfile.write_bytes(FIXTURE_CARGO_LOCK)
        self.lockfile.chmod(0o400)
        graph_owner = source_root / "ci/privacy_sdk_cargo_lockfile.sh"
        graph_owner.parent.mkdir()
        graph_owner.write_text(
            'readonly PRIVACY_SDK_CANONICAL_CARGO_LOCK_SHA256=\\\n"'
            + digest(FIXTURE_CARGO_LOCK) + '"\n', encoding="utf-8",
        )
        source_context = mock.patch.multiple(
            sys.modules[__name__], ROOT=source_root,
            OWNER=source_root / "scripts/archive_norito_xcframework.py",
            VALIDATOR=source_root / "scripts/validate_norito_bridge_xcframework.py",
        )
        source_context.start()
        self.addCleanup(source_context.stop)
        self.artifact_root = self.root / "artifacts"
        self.output_root = self.root / "packages"
        self.scratch_root = self.root / "scratch"
        self.framework = self.artifact_root / "NoritoBridge.xcframework"
        self.artifact_root.mkdir()
        self.output_root.mkdir()
        self.scratch_root.mkdir()
        self._write_complete_generation()
        self.mechanical_runner = self.root / "mechanical_archive_runner.py"
        self._write_mechanical_runner()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_complete_generation(self) -> None:
        validator = load_validator_module()
        header = (
            ROOT / "crates/connect_norito_bridge/include/connect_norito_bridge.h"
        ).read_bytes()
        wrapper = (
            ROOT / "crates/connect_norito_bridge/include/NoritoBridge.h"
        ).read_bytes()
        module_map = (
            ROOT / "crates/connect_norito_bridge/module.modulemap.template"
        ).read_bytes()
        libraries: list[dict[str, object]] = []
        hashes: dict[str, str] = {}
        self.framework.mkdir()
        for identifier, (platform, architectures, variant) in SLICE_METADATA.items():
            binary = f"native:{identifier}:abi30".encode()
            slice_root = self.framework / identifier
            headers = slice_root / "Headers"
            headers.mkdir(parents=True)
            (slice_root / "libNoritoBridge.a").write_bytes(binary)
            (headers / "connect_norito_bridge.h").write_bytes(header)
            (headers / "NoritoBridge.h").write_bytes(wrapper)
            (headers / "module.modulemap").write_bytes(module_map)
            hashes[identifier] = digest(binary)
            library: dict[str, object] = {
                "BinaryPath": "libNoritoBridge.a",
                "HeadersPath": "Headers",
                "LibraryIdentifier": identifier,
                "LibraryPath": "libNoritoBridge.a",
                "SupportedArchitectures": architectures,
                "SupportedPlatform": platform,
            }
            if variant is not None:
                library["SupportedPlatformVariant"] = variant
            libraries.append(library)

        (self.framework / ".privacy-production-enabled").touch()
        info = {
            "AvailableLibraries": libraries,
            "CFBundlePackageType": "XFWK",
            "XCFrameworkFormatVersion": "1.0",
        }
        with (self.framework / "Info.plist").open("wb") as handle:
            plistlib.dump(info, handle, sort_keys=True)
        build_environment = {
            "schema": "iroha.mobile-native-build-environment.v1",
                "wallet_runtime_authority": "cbsi-release-v1",
                "wallet_runtime_trust_ed25519_hex": "3" * 64,
            "hermetic_runner_schema": "iroha.mobile-hermetic-command.v1",
            "hermetic_runner_sha256": digest(
                (ROOT / "scripts/run_mobile_hermetic_command.py").read_bytes()
            ),
            "environment_profiles": validator.EXPECTED_ENVIRONMENT_PROFILES,
            "cargo_build_jobs": 1,
            "rust_toolchain_channel": "1.93.1",
            "cargo_release": "1.93.1",
            "cargo_commit_hash": "4" * 40,
            "cargo_binary_sha256": "4" * 64,
            "rustc_release": "1.93.1",
            "rustc_commit_hash": "5" * 40,
            "rustc_binary_sha256": "5" * 64,
            "rustdoc_release": "1.93.1",
            "rustdoc_commit_hash": "5" * 40,
            "rustdoc_binary_sha256": "6" * 64,
            "python_version": "3.12.13",
            "python_binary_sha256": "7" * 64,
            "git_version": "2.51.0",
            "git_binary_sha256": "8" * 64,
            "rustup_version": "1.28.2",
            "rustup_binary_sha256": "9" * 64,
            "xcode_version": "16.2",
            "xcode_build_version": "16C5032a",
            "iphoneos_sdk_version": "18.2",
            "iphonesimulator_sdk_version": "18.2",
            "macosx_sdk_version": "15.2",
            "iphoneos_deployment_target": "15.0",
            "iphonesimulator_deployment_target": "15.0",
            "macosx_deployment_target": "12.0",
        }
        manifest = {
            "version": "0.1.0",
            "native_bridge_abi_version": 30,
            "privacy_production_enabled": True,
            "cargo_features": ["privacy-production-enabled"],
            "build_environment": build_environment,
            "source_commit": "1" * 40,
            "embedded_source_commit": "1" * 40,
            "source_tree_dirty": False,
            "source_fingerprint_sha256": "2" * 64,
            "cargo_lock_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
            "bridge_header_sha256": digest(header),
            "required_symbols": validator.EXPECTED_REQUIRED_SYMBOLS,
            "forbidden_symbols": validator.EXPECTED_FORBIDDEN_SYMBOLS,
            "hashes": hashes,
        }
        (self.framework / "NoritoBridge.artifacts.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def _write_mechanical_runner(self) -> None:
        self.mechanical_runner.write_text(
            """\
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


owner = load("mechanical_archive_owner", Path(sys.argv[1]))
validator = load("mechanical_archive_validator", Path(sys.argv[2]))
validator._validate_repository_provenance = lambda _root, _payload, _lockfile: None
owner._load_generation_validator = lambda: validator
owner._validate_native_binaries = lambda _snapshot, _validator: None
if "--exercise-owner-cli" in sys.argv[6:]:
    sys.argv = [
        str(sys.argv[1]), "--lockfile-path", str(Path(sys.argv[1]).resolve().parents[2] / "graph/Cargo.lock"), "--xcframework", sys.argv[3],
        "--output", sys.argv[4], "--scratch-dir", sys.argv[5],
        *(["--allow-dirty-source"] if "--allow-dirty-source" in sys.argv[6:] else []),
    ]
    owner.main()
else:
    digest, size = owner.archive_xcframework(sys.argv[3], sys.argv[4], sys.argv[5], lockfile_path=Path(sys.argv[1]).resolve().parents[2] / "graph/Cargo.lock")
    print(f"{digest} {size}")
""",
            encoding="utf-8",
        )

    def _run(
        self,
        output: Path,
        *,
        expect_success: bool = True,
        environment_updates: dict[str, str] | None = None,
        pass_fds: tuple[int, ...] = (),
        owner_cli: bool = False,
        allow_dirty_source: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
        environment.pop("NORITO_BRIDGE_OUTPUT_LOCK_FD", None)
        if environment_updates is not None:
            environment.update(environment_updates)
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(self.mechanical_runner),
                str(OWNER),
                str(VALIDATOR),
                str(self.framework),
                str(output),
                str(self.scratch_root),
                *(["--exercise-owner-cli"] if owner_cli else []),
                *(["--allow-dirty-source"] if allow_dirty_source else []),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            pass_fds=pass_fds,
            timeout=30,
        )
        if expect_success and result.returncode != 0:
            self.fail(f"archive owner failed:\nstdout={result.stdout}\nstderr={result.stderr}")
        if not expect_success and result.returncode == 0:
            self.fail("archive owner unexpectedly succeeded")
        return result

    def test_dirty_archive_cli_requires_explicit_allowance(self) -> None:
        """Exercise full CLI publication with labeled provenance/native doubles."""
        manifest_path = self.framework / "NoritoBridge.artifacts.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["source_tree_dirty"] = True
        manifest_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        output = self.output_root / "dirty-local.zip"
        rejected = self._run(output, expect_success=False, owner_cli=True)
        self.assertIn("clean source tree", rejected.stderr)
        self.assertFalse(output.exists())

        accepted = self._run(output, owner_cli=True, allow_dirty_source=True)
        self.assertIn("[norito-bridge-archive] sha256=", accepted.stdout)
        with zipfile.ZipFile(output) as archive:
            archived_manifest = json.loads(
                archive.read("NoritoBridge.xcframework/NoritoBridge.artifacts.json")
            )
        self.assertTrue(archived_manifest["source_tree_dirty"])
        self.assertEqual(
            archived_manifest["source_fingerprint_sha256"],
            payload["source_fingerprint_sha256"],
        )

    def test_local_integration_scope_cannot_be_archived_even_with_dirty_allowance(self) -> None:
        """Actual archive generation admission rejects scope before provenance."""
        owner = load_owner_module()
        validator = load_validator_module()
        manifest_path = self.framework / "NoritoBridge.artifacts.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["artifact_scope"] = "local-integration"
        for dirty in (False, True):
            with self.subTest(dirty=dirty):
                payload["source_tree_dirty"] = dirty
                manifest_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                with mock.patch.object(owner, "_load_generation_validator", return_value=validator):
                    with self.assertRaisesRegex(owner.ArchiveError, "field inventory"):
                        owner._validate_generation(self.framework, lockfile_path=self.lockfile, allow_dirty_source=True)
                self.assertEqual(list(self.output_root.iterdir()), [])

    def test_dirty_archive_cli_keeps_real_tool_provenance(self) -> None:
        """The actual owner/validator, without mocks, must reject absent Cargo."""
        manifest_path = self.framework / "NoritoBridge.artifacts.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["source_tree_dirty"] = True
        manifest_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        output = self.output_root / "unverified-dirty.zip"
        environment = os.environ.copy()
        environment.update({
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
            "NORITO_BRIDGE_SEAL_CARGO": str(self.root / "missing-cargo"),
        })
        environment.pop("NORITO_BRIDGE_OUTPUT_LOCK_FD", None)
        result = subprocess.run(
            [
                sys.executable, "-I", "-S", "-B", str(OWNER),
                "--lockfile-path", str(self.lockfile), "--xcframework", str(self.framework),
                "--output", str(output),
                "--scratch-dir", str(self.scratch_root),
                "--allow-dirty-source",
            ],
            env=environment, capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unable to authenticate artifact source provenance", result.stderr)
        self.assertIn("missing-cargo", result.stderr)
        self.assertFalse(output.exists())

    def test_builder_forwards_only_explicit_dirty_archive_allowance(self) -> None:
        """Execute actual argument assembly without invoking a native build."""
        source = (ROOT / "scripts/build_norito_xcframework.sh").read_text(encoding="utf-8")
        self.assertIn("ALLOW_DIRTY_SOURCE=0", source)
        fragment = source.split("  ARCHIVE_OWNER_ARGUMENTS=(", 1)[1].split("\n  env -i \\\n", 1)[0]
        fragment = "  ARCHIVE_OWNER_ARGUMENTS=(" + fragment
        invocation = source.split('"$PYTHON_BINARY" -I -S -B "$ARCHIVE_OWNER"', 1)[1]
        self.assertTrue(invocation.startswith(' \\\n      "${ARCHIVE_OWNER_ARGUMENTS[@]}"\n'))
        environment = {
            "PATH": "/usr/bin:/bin",
            "FINAL_XCFRAMEWORK": "/external artifacts/NoritoBridge.xcframework",
            "ARCHIVE_OUTPUT": "/external artifacts/NoritoBridge.xcframework.zip",
            "BUILD_DIR": "/external scratch",
            "CARGO_LOCKFILE": "/reviewed graph/Cargo.lock",
        }
        expected = [
            "--lockfile-path", environment["CARGO_LOCKFILE"],
            "--xcframework", environment["FINAL_XCFRAMEWORK"],
            "--output", environment["ARCHIVE_OUTPUT"],
            "--scratch-dir", environment["BUILD_DIR"],
        ]
        for allowance in ("0", "1", "true"):
            with self.subTest(allowance=allowance):
                result = subprocess.run(
                    ["/bin/bash", "-euc", fragment + '\nprintf "%s\\0" "${ARCHIVE_OWNER_ARGUMENTS[@]}"'],
                    env={**environment, "ALLOW_DIRTY_SOURCE": allowance},
                    capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                arguments = result.stdout.decode().split("\0")[:-1]
                self.assertEqual(arguments, expected + (["--allow-dirty-source"] if allowance == "1" else []))

    def test_sorted_archive_is_stable_across_source_mtime_and_mode_changes(self) -> None:
        first = self.output_root / "first.zip"
        second = self.output_root / "second.zip"
        first_result = self._run(first)

        for path in sorted(self.framework.rglob("*")):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
            os.utime(path, ns=(1_800_000_000_000_000_000,) * 2)
        os.utime(self.framework, ns=(1_800_000_000_000_000_000,) * 2)
        second_result = self._run(second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        # Construct the complete expected archive independently of both the
        # owner and zipfile's writer; source/header changes cannot stale a hash.
        expected_bytes = reference_stored_zip(self.framework)
        self.assertEqual(first.read_bytes(), expected_bytes)
        expected_digest = digest(expected_bytes)
        self.assertEqual(digest(first.read_bytes()), expected_digest)
        self.assertEqual(first_result.stdout.split()[0], expected_digest)
        self.assertEqual(second_result.stdout.split()[0], expected_digest)
        with zipfile.ZipFile(first) as archive:
            self.assertIsNone(archive.testzip())
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            self.assertEqual(names, sorted(names, key=lambda name: name.encode("utf-8")))
            self.assertEqual(names[0], "NoritoBridge.xcframework/")
            for entry in entries:
                self.assertEqual(entry.date_time, NORMALIZED_ZIP_TIME)
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                archived_mode = entry.external_attr >> 16
                self.assertEqual(
                    stat.S_IMODE(archived_mode),
                    0o755 if entry.is_dir() else 0o644,
                )
                archive.read(entry)

    def test_held_shared_publish_lock_rejects_racing_archive(self) -> None:
        lock_path = self.artifact_root / ".NoritoBridge.publish.lockfile"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            output = self.output_root / "racing.zip"
            result = self._run(output, expect_success=False)
            self.assertIn("another publisher holds", result.stderr)
            self.assertFalse(output.exists())
        finally:
            os.close(lock_fd)

        self._run(self.output_root / "after-lock-release.zip")

    def test_authenticated_inherited_output_lock_is_accepted(self) -> None:
        lock_path = self.artifact_root / ".NoritoBridge.publish.lockfile"
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        os.fchmod(lock_fd, 0o644)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._run(
                self.output_root / "inherited-lock.zip",
                environment_updates={"NORITO_BRIDGE_OUTPUT_LOCK_FD": str(lock_fd)},
                pass_fds=(lock_fd,),
            )
        finally:
            os.close(lock_fd)

    def test_forged_inherited_output_lock_is_rejected(self) -> None:
        expected_lock = self.artifact_root / ".NoritoBridge.publish.lockfile"
        expected_lock.write_bytes(b"")
        expected_lock.chmod(0o600)
        unrelated_path = self.root / "unrelated.lock"
        unrelated_fd = os.open(unrelated_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(unrelated_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self._run(
                self.output_root / "forged-lock.zip",
                expect_success=False,
                environment_updates={
                    "NORITO_BRIDGE_OUTPUT_LOCK_FD": str(unrelated_fd)
                },
                pass_fds=(unrelated_fd,),
            )
            self.assertIn("not authenticated", result.stderr)
        finally:
            os.close(unrelated_fd)

    def test_preexisting_destination_is_rejected_without_a_lock_artifact(self) -> None:
        output = self.output_root / "existing.zip"
        output.write_bytes(b"authenticated-existing-release")
        result = self._run(output, expect_success=False)
        self.assertIn("must not already exist", result.stderr)
        self.assertEqual(output.read_bytes(), b"authenticated-existing-release")
        self.assertFalse(
            (self.output_root / ".NoritoBridge.archive.lockfile").exists()
        )

    def test_selected_build_lock_replacement_aborts_before_archive_publication(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        lock_owner = owner._load_source_lock_owner()
        selected = self.root / "selected-Cargo.lock"
        selected.write_bytes(FIXTURE_CARGO_LOCK)
        selected.chmod(0o400)
        self.assertEqual((ROOT / "Cargo.lock").read_bytes(), FIXTURE_CARGO_LOCK)
        selected_digest = digest(selected.read_bytes())
        manifest = self.framework / "NoritoBridge.artifacts.json"
        payload = json.loads(manifest.read_text())
        payload["cargo_lock_sha256"] = selected_digest
        manifest.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        output = self.output_root / "changed-selected-lock.zip"
        original_write = owner._write_archive
        root_lock_before = (ROOT / "Cargo.lock").read_bytes()
        def replace_selected_after_writing(*arguments, **keywords):
            result = original_write(*arguments, **keywords)
            replacement = selected.with_name("replacement-Cargo.lock")
            replacement.write_bytes(selected.read_bytes())
            replacement.replace(selected)
            return result
        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(owner, "_load_source_lock_owner", return_value=lock_owner),
            mock.patch.object(validator, "_load_swift_pin_owner", return_value=lock_owner),
            mock.patch.object(validator, "_validate_repository_provenance", return_value=None),
            mock.patch.object(owner, "_load_generation_validator", return_value=validator),
            mock.patch.object(owner, "_validate_native_binaries", return_value=None),
            mock.patch.object(owner, "_write_archive", side_effect=replace_selected_after_writing),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "selected Cargo lock changed before archive publication"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root), lockfile_path=selected,
                )
        self.assertFalse(output.exists())
        self.assertEqual((ROOT / "Cargo.lock").read_bytes(), root_lock_before)

    def test_replaced_lock_inode_aborts_before_atomic_publication(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "replaced-lock.zip"
        original_write_archive = owner._write_archive

        def replace_lock_after_archive(*args, **kwargs):
            result = original_write_archive(*args, **kwargs)
            lock_path = self.artifact_root / ".NoritoBridge.publish.lockfile"
            lock_path.unlink()
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
            return result

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_write_archive",
                side_effect=replace_lock_after_archive,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "not authenticated"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertFalse(output.exists())
        self.assertEqual(len(list(self.output_root.glob(".replaced-lock.zip.*.tmp"))), 1)

    def test_interrupted_atomic_publication_retains_owned_residue(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "release.zip"
        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_atomic_publish",
                side_effect=owner.ArchiveInterrupted("simulated interruption"),
            ),
        ):
            with self.assertRaises(owner.ArchiveInterrupted):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertFalse(output.exists())
        self.assertEqual(len(list(self.output_root.glob(".release.zip.*.tmp"))), 1)
        self.assertEqual(
            len(list(self.scratch_root.glob(".NoritoBridge.archive-snapshot.*"))),
            1,
        )

    def test_destination_appearing_during_archive_is_never_overwritten(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "existing-race.zip"
        original_write_archive = owner._write_archive

        def mutate_destination_after_archive(*args, **kwargs):
            result = original_write_archive(*args, **kwargs)
            output.write_bytes(b"competing-destination-update")
            return result

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_write_archive",
                side_effect=mutate_destination_after_archive,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "must not already exist"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertEqual(output.read_bytes(), b"competing-destination-update")
        self.assertEqual(
            len(list(self.output_root.glob(".existing-race.zip.*.tmp"))),
            1,
        )

    def test_absent_destination_uses_atomic_no_replace_publication(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "absent-race.zip"
        original_assert_absent = owner._assert_destination_absent
        checks = 0

        def introduce_destination_after_check(path):
            nonlocal checks
            original_assert_absent(path)
            checks += 1
            if checks == 2:
                output.write_bytes(b"competing-atomic-publication")

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_assert_destination_absent",
                side_effect=introduce_destination_after_check,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "appeared"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertEqual(output.read_bytes(), b"competing-atomic-publication")
        self.assertEqual(len(list(self.output_root.glob(".absent-race.zip.*.tmp"))), 1)

    def test_swapped_temporary_path_is_retained_and_never_published(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "swapped-temp.zip"
        original_write_archive = owner._write_archive

        def swap_temporary_after_archive(*args, **kwargs):
            archive = original_write_archive(*args, **kwargs)
            archive.path.unlink()
            archive.path.write_bytes(b"foreign-temporary-inode")
            return archive

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_write_archive",
                side_effect=swap_temporary_after_archive,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "authenticated inode"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertFalse(output.exists())
        residues = list(self.output_root.glob(".swapped-temp.zip.*.tmp"))
        self.assertEqual(len(residues), 1)
        self.assertEqual(residues[0].read_bytes(), b"foreign-temporary-inode")

    def test_source_swap_inside_no_replace_is_detected_without_cleanup(self) -> None:
        owner = load_owner_module()
        validator = load_validator_module()
        output = self.output_root / "rename-source-race.zip"
        original_rename = owner._rename_no_replace

        def swap_source_then_rename(temporary, destination):
            temporary.unlink()
            temporary.write_bytes(b"foreign-late-source")
            original_rename(temporary, destination)

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                validator,
                "_validate_repository_provenance",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=validator,
            ),
            mock.patch.object(
                owner,
                "_validate_native_binaries",
                return_value=None,
            ),
            mock.patch.object(
                owner,
                "_rename_no_replace",
                side_effect=swap_source_then_rename,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "authenticated inode"):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertEqual(output.read_bytes(), b"foreign-late-source")
        self.assertEqual(list(self.output_root.glob(".rename-source-race.zip.*.tmp")), [])

    def test_repository_contained_archive_paths_are_rejected(self) -> None:
        owner = load_owner_module()
        with self.assertRaisesRegex(owner.ArchiveError, "source tree"):
            owner._canonical_output(
                str(ROOT / "NoritoBridge.xcframework.zip"),
                self.framework,
                ROOT,
            )
        with mock.patch.object(owner, "_repository_root", return_value=self.root):
            with self.assertRaisesRegex(owner.ArchiveError, "artifact root"):
                owner.archive_xcframework(
                    str(self.framework),
                    str(self.output_root / "repository-contained.zip"),
                    str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

    def test_manifest_hash_mismatch_fails_before_publication(self) -> None:
        binary = self.framework / "ios-arm64/libNoritoBridge.a"
        binary.write_bytes(binary.read_bytes() + b"tampered")
        output = self.output_root / "tampered.zip"
        result = self._run(output, expect_success=False)
        self.assertIn("slice hash mismatch", result.stderr)
        self.assertFalse(output.exists())

    def test_unexpected_xcframework_entry_is_rejected(self) -> None:
        (self.framework / "legacy-compatibility.txt").write_text(
            "forbidden\n",
            encoding="utf-8",
        )
        output = self.output_root / "unexpected-entry.zip"
        result = self._run(output, expect_success=False)
        self.assertIn("inventory is not exact", result.stderr)
        self.assertFalse(output.exists())

    def test_absent_optional_binary_path_matches_authoritative_validator(self) -> None:
        info_path = self.framework / "Info.plist"
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
        for library in info["AvailableLibraries"]:
            library.pop("BinaryPath")
        with info_path.open("wb") as handle:
            plistlib.dump(info, handle, sort_keys=True)
        self._run(self.output_root / "without-binary-path.zip")

    def test_owner_explicitly_requests_repository_provenance(self) -> None:
        owner = load_owner_module()
        captured: dict[str, object] = {}

        class FakeValidationError(RuntimeError):
            pass

        class CapturingValidator:
            ValidationError = FakeValidationError

            @staticmethod
            def validate(**arguments):
                captured.update(arguments)

        with mock.patch.object(
            owner,
            "_load_generation_validator",
            return_value=CapturingValidator,
        ):
            owner._validate_generation(self.framework, lockfile_path=self.lockfile)

        self.assertIs(captured["verify_repository_provenance"], True)
        self.assertFalse((self.artifact_root / "NoritoBridge.artifacts.json").exists())

    def test_repository_provenance_rejection_blocks_publication(self) -> None:
        owner = load_owner_module()
        output = self.output_root / "rejected-provenance.zip"

        class FakeValidationError(RuntimeError):
            pass

        class RejectingValidator:
            ValidationError = FakeValidationError

            @staticmethod
            def validate(**arguments):
                if arguments.get("verify_repository_provenance") is not True:
                    raise AssertionError("owner did not request repository provenance")
                raise FakeValidationError("simulated repository provenance rejection")

        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
            mock.patch.object(
                owner,
                "_load_generation_validator",
                return_value=RejectingValidator,
            ),
        ):
            with self.assertRaisesRegex(
                owner.ArchiveError,
                "repository provenance rejection",
            ):
                owner.archive_xcframework(
                    str(self.framework), str(output), str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )

        self.assertFalse(output.exists())

    def test_builder_archive_wiring_and_abi_chain_are_exact(self) -> None:
        builder = (ROOT / "scripts/build_norito_xcframework.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("--archive-output)", builder)
        self.assertIn("--archive-output=*)", builder)
        self.assertGreaterEqual(builder.count("--archive-output requires a value"), 2)
        self.assertIn('output.suffix != ".zip"', builder)
        self.assertIn(
            'header_abis != ["30"]',
            builder,
        )
        self.assertIn(
            'bridge_aliases != ["PRIVACY_BRIDGE_ABI_VERSION_V1"]',
            builder,
        )
        self.assertIn("protocol_abis != header_abis", builder)
        self.assertIn(
            '"native_bridge_abi_version": $BRIDGE_ABI_VERSION,',
            builder,
        )
        self.assertIn(
            '"connect_norito_domain_id_validate_v1"', builder
        )
        self.assertIn(
            '"connect_norito_encode_transfer_instruction_box"', builder
        )
        required_inventory = builder.split('"required_symbols": [', 1)[1].split(
            '"forbidden_symbols": [', 1
        )[0]
        wallet_exports = re.findall(r'"(connect_norito_kagemusha_[A-Za-z0-9_]+)"', required_inventory)
        self.assertEqual(wallet_exports, [
            "connect_norito_kagemusha_wallet_" + suffix + "_v1"
            for suffix in ("revision", "open_begin", "open_finish", "open_cancel", "close", "activity", "setup", "execute", "load_original_validate", "request_status", "retry", "resume", "fold", "credit_status", "snapshot", "review", "execute_reviewed", "discard_review", "installation_begin", "installation_register", "installation_close", "registration_source_relocate", "observe", "account_original", "account_display", "enrollment", "enrollment_refusal")
        ])
        self.assertNotIn(
            "CONNECT_NORITO_BRIDGE_ABI_VERSION:[[:space:]]*u32",
            builder,
        )
        bridge = (ROOT / "crates/connect_norito_bridge/src/lib.rs").read_text(
            encoding="utf-8"
        )
        host_jni_cfg = '''#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
))]'''
        self.assertEqual(bridge.count(host_jni_cfg), 2)
        self.assertIn(f"{host_jni_cfg}\nmod platform_jni;", bridge)
        self.assertIn(
            f"{host_jni_cfg}\n#[allow(unused_imports)]\npub use platform_jni::*;",
            bridge,
        )
        for environment_name in (
            "NORITO_BRIDGE_OUTPUT_LOCK_FD",
            "NORITO_BRIDGE_SEAL_HOME",
            "NORITO_BRIDGE_SEAL_CARGO_HOME",
            "NORITO_BRIDGE_SEAL_RUSTUP_HOME",
            "NORITO_BRIDGE_SEAL_TMPDIR",
            "NORITO_BRIDGE_SEAL_CARGO_TARGET_DIR",
            "NORITO_BRIDGE_SEAL_CARGO",
            "NORITO_BRIDGE_SEAL_RUSTC",
            "NORITO_BRIDGE_SEAL_RUSTDOC",
            "NORITO_BRIDGE_SEAL_RUSTUP",
            "NORITO_BRIDGE_SEAL_DEVELOPER_DIR",
        ):
            self.assertIn(f'{environment_name}="$', builder)
        self.assertIn(
            '"$PYTHON_BINARY" -I -S -B "$ARCHIVE_OWNER"',
            builder,
        )
        self.assertIn("must already exist", builder)
        self.assertNotIn("candidate.mkdir(parents=True, exist_ok=True)", builder)
        self.assertIn(
            "live XCFramework requires its canonical public manifest link",
            builder,
        )
        self.assertNotIn("write_embedded_manifest", builder)
        self.assertNotIn("after migration", builder)

    def test_checker_source_authentication_is_no_site_and_no_bytecode(self) -> None:
        checker = (ROOT / "scripts/check_mobile_sdk_artifacts.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"$CHECK_PYTHON_BINARY" -I -S -B "$@"',
            checker,
        )
        self.assertIn("run_source_authenticated_python", checker)
        self.assertIn("--verify-repository-provenance", checker)
        self.assertIn('symbols="$(nm -gUj "$binary"', checker)

    def test_native_architecture_and_export_inventory_is_authenticated(self) -> None:
        owner = load_owner_module()

        class NativePolicy:
            LIBRARY_NAME = "libNoritoBridge.a"
            EXPECTED_SLICES = {
                identifier: {"architectures": architectures}
                for identifier, (_, architectures, _) in SLICE_METADATA.items()
            }
            EXPECTED_REQUIRED_SYMBOLS = [
                "connect_norito_bridge_abi_version",
                "connect_norito_domain_id_validate_v1",
            ]
            EXPECTED_FORBIDDEN_SYMBOLS = [
                "connect_norito_forbidden_symbol"
            ]

        selected_developer = None
        def canonical_output(tool: Path, arguments: list[str], **keywords) -> str:
            self.assertEqual(keywords, {} if selected_developer is None else {"developer_dir": selected_developer})
            identifier = Path(arguments[-1]).parent.name
            if tool.name == "lipo":
                return " ".join(
                    NativePolicy.EXPECTED_SLICES[identifier]["architectures"]
                ) + "\n"
            self.assertEqual(arguments[:-1], ["-gUj"])
            return (
                "_connect_norito_bridge_abi_version\n"
                "_connect_norito_domain_id_validate_v1\n"
            )

        with (
            mock.patch.object(owner.sys, "platform", "darwin"),
            mock.patch.object(
                owner,
                "_pinned_native_tool",
                side_effect=lambda name: Path("/usr/bin") / name,
            ),
            mock.patch.object(
                owner,
                "_run_native_tool",
                side_effect=canonical_output,
            ),
        ):
            owner._validate_native_binaries(self.framework, NativePolicy)
            selected_developer = Path("/Applications/ConsumerXcode.app/Contents/Developer")
            owner._validate_native_binaries(self.framework, NativePolicy, developer_dir=selected_developer)

    def test_native_tool_environment_uses_explicit_consumer_or_sealed_producer_selection(self) -> None:
        owner = load_owner_module()
        tool = Path("/usr/bin/lipo")
        producer = "/Applications/ProducerXcode.app/Contents/Developer"
        consumer = Path("/Applications/ConsumerXcode.app/Contents/Developer")
        with mock.patch.dict(os.environ, {"NORITO_BRIDGE_SEAL_DEVELOPER_DIR": producer}), \
             mock.patch.object(owner.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "arm64\n", "")) as run:
            self.assertEqual(owner._run_native_tool(tool, ["-archs", "archive"]), "arm64\n")
            self.assertEqual(run.call_args.kwargs["env"]["DEVELOPER_DIR"], producer)
            owner._run_native_tool(tool, ["-archs", "archive"], developer_dir=consumer)
            self.assertEqual(run.call_args.kwargs["env"]["DEVELOPER_DIR"], str(consumer))

    def test_reference_only_required_symbol_is_rejected(self) -> None:
        owner = load_owner_module()

        class NativePolicy:
            LIBRARY_NAME = "libNoritoBridge.a"
            EXPECTED_SLICES = {
                identifier: {"architectures": architectures}
                for identifier, (_, architectures, _) in SLICE_METADATA.items()
            }
            EXPECTED_REQUIRED_SYMBOLS = [
                "connect_norito_bridge_abi_version",
                "connect_norito_domain_id_validate_v1",
            ]
            EXPECTED_FORBIDDEN_SYMBOLS = []

        def reference_only_output(tool: Path, arguments: list[str]) -> str:
            identifier = Path(arguments[-1]).parent.name
            if tool.name == "lipo":
                return " ".join(
                    NativePolicy.EXPECTED_SLICES[identifier]["architectures"]
                ) + "\n"
            if arguments[:-1] == ["-gj"]:
                return (
                    "_connect_norito_bridge_abi_version\n"
                    "_connect_norito_domain_id_validate_v1\n"
                )
            self.assertEqual(arguments[:-1], ["-gUj"])
            return "_connect_norito_bridge_abi_version\n"

        with (
            mock.patch.object(owner.sys, "platform", "darwin"),
            mock.patch.object(
                owner,
                "_pinned_native_tool",
                side_effect=lambda name: Path("/usr/bin") / name,
            ),
            mock.patch.object(
                owner,
                "_run_native_tool",
                side_effect=reference_only_output,
            ),
        ):
            with self.assertRaisesRegex(
                owner.ArchiveError,
                "missing required native symbols",
            ):
                owner._validate_native_binaries(self.framework, NativePolicy)

    def test_wrong_architecture_and_missing_export_are_rejected(self) -> None:
        owner = load_owner_module()

        class NativePolicy:
            LIBRARY_NAME = "libNoritoBridge.a"
            EXPECTED_SLICES = {
                identifier: {"architectures": architectures}
                for identifier, (_, architectures, _) in SLICE_METADATA.items()
            }
            EXPECTED_REQUIRED_SYMBOLS = [
                "connect_norito_bridge_abi_version",
                "connect_norito_domain_id_validate_v1",
            ]
            EXPECTED_FORBIDDEN_SYMBOLS = [
                "connect_norito_forbidden_symbol"
            ]

        def wrong_architecture(tool: Path, arguments: list[str]) -> str:
            identifier = Path(arguments[-1]).parent.name
            if tool.name == "lipo":
                return "x86_64\n" if identifier == "ios-arm64" else " ".join(
                    NativePolicy.EXPECTED_SLICES[identifier]["architectures"]
                ) + "\n"
            return (
                "_connect_norito_bridge_abi_version\n"
                "_connect_norito_domain_id_validate_v1\n"
            )

        def missing_export(tool: Path, arguments: list[str]) -> str:
            identifier = Path(arguments[-1]).parent.name
            if tool.name == "lipo":
                return " ".join(
                    NativePolicy.EXPECTED_SLICES[identifier]["architectures"]
                ) + "\n"
            return "_connect_norito_domain_id_validate_v1\n"

        with (
            mock.patch.object(owner.sys, "platform", "darwin"),
            mock.patch.object(
                owner,
                "_pinned_native_tool",
                side_effect=lambda name: Path("/usr/bin") / name,
            ),
            mock.patch.object(
                owner,
                "_run_native_tool",
                side_effect=wrong_architecture,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "architecture mismatch"):
                owner._validate_native_binaries(self.framework, NativePolicy)
        with (
            mock.patch.object(owner.sys, "platform", "darwin"),
            mock.patch.object(
                owner,
                "_pinned_native_tool",
                side_effect=lambda name: Path("/usr/bin") / name,
            ),
            mock.patch.object(
                owner,
                "_run_native_tool",
                side_effect=missing_export,
            ),
        ):
            with self.assertRaisesRegex(owner.ArchiveError, "missing required native symbols"):
                owner._validate_native_binaries(self.framework, NativePolicy)

    def test_missing_source_date_epoch_is_rejected(self) -> None:
        owner = load_owner_module()
        output = self.output_root / "missing-epoch.zip"
        with mock.patch.dict(os.environ):
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            with self.assertRaisesRegex(owner.ArchiveError, "SOURCE_DATE_EPOCH"):
                owner.archive_xcframework(
                    str(self.framework),
                    str(output),
                    str(self.scratch_root),
                    lockfile_path=self.lockfile,
                )
        self.assertFalse(output.exists())

    def test_global_site_initialization_is_rejected(self) -> None:
        output = self.output_root / "site-enabled.zip"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(OWNER),
                "--lockfile-path", str(ROOT / "Cargo.lock"),
                "--xcframework",
                str(self.framework),
                "--output",
                str(output),
                "--scratch-dir",
                str(self.scratch_root),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH},
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolated no-site Python 3.12", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
