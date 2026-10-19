#!/usr/bin/env python3
"""Assemble and verify the exact ABI-31 native inventory for the C# NuGet SDK.

Each native artifact must have been exercised on its matching host and recorded
with ``check_native_sdk_artifact.py``.  This helper deliberately does not
load cross-platform libraries.  It binds the five target-host evidence
manifests to one clean source revision, stages the canonical NuGet RID layout,
and verifies that a produced package contains exactly those native bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_native_sdk_artifact as artifact_checker  # noqa: E402


SCHEMA = "iroha.csharp-native-package.v1"
PACKAGE_MANIFEST_NAME = "native-package-manifest.json"
EVIDENCE_MANIFEST_NAME = "native-sdk-abi31.json"
MAX_TREE_ENTRIES = 128
MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class NativeAsset:
    """One reviewed Rust target to NuGet RID and library-name mapping."""

    target: str
    rid: str
    library_name: str

    @property
    def package_path(self) -> str:
        """Return the canonical forward-slash NuGet package path."""

        return f"runtimes/{self.rid}/native/{self.library_name}"

    @property
    def evidence_path(self) -> str:
        """Return the canonical staged evidence path."""

        return f"evidence/{self.target}.json"


NATIVE_ASSETS: tuple[NativeAsset, ...] = (
    NativeAsset(
        target="x86_64-unknown-linux-gnu",
        rid="linux-x64",
        library_name="libconnect_norito_bridge.so",
    ),
    NativeAsset(
        target="aarch64-unknown-linux-gnu",
        rid="linux-arm64",
        library_name="libconnect_norito_bridge.so",
    ),
    NativeAsset(
        target="x86_64-apple-darwin",
        rid="osx-x64",
        library_name="libconnect_norito_bridge.dylib",
    ),
    NativeAsset(
        target="aarch64-apple-darwin",
        rid="osx-arm64",
        library_name="libconnect_norito_bridge.dylib",
    ),
    NativeAsset(
        target="x86_64-pc-windows-msvc",
        rid="win-x64",
        library_name="connect_norito_bridge.dll",
    ),
)


class CSharpNativePackageError(RuntimeError):
    """Raised when C# native package inputs or outputs violate the hard cut."""


def fail(message: str) -> NoReturn:
    """Raise one stable packaging-contract error."""

    raise CSharpNativePackageError(message)


def _require_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CSharpNativePackageError(f"{label} is unavailable: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be one non-linked directory: {path}")


def _directory_names(path: Path, label: str) -> tuple[str, ...]:
    _require_directory(path, label)
    try:
        with os.scandir(path) as iterator:
            names = tuple(sorted(entry.name for entry in iterator))
    except OSError as error:
        raise CSharpNativePackageError(f"{label} cannot be enumerated: {path}") from error
    if len(names) > MAX_TREE_ENTRIES:
        fail(f"{label} exceeds its entry limit")
    return names


def _require_exact_names(
    path: Path,
    expected: tuple[str, ...],
    *,
    label: str,
) -> None:
    actual = _directory_names(path, label)
    canonical_expected = tuple(sorted(expected))
    if actual != canonical_expected:
        missing = sorted(set(canonical_expected) - set(actual))
        extra = sorted(set(actual) - set(canonical_expected))
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        fail(f"{label} inventory is not exact" + (f": {'; '.join(details)}" if details else ""))


def _regular_file_metadata(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CSharpNativePackageError(f"{label} is unavailable: {path}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        fail(f"{label} must be one non-empty regular file with one hard link")
    return metadata


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _source_commit(
    source_root: Path,
    *,
    source_state: Callable[[Path], tuple[str, bool]],
) -> str:
    commit, clean = source_state(source_root)
    if not clean:
        fail("C# native packages must be assembled from a clean source tree")
    return commit


def _manifest_digest(path: Path) -> str:
    raw = artifact_checker.stable_bounded_file_bytes(
        path,
        label="native artifact evidence manifest",
        maximum_bytes=artifact_checker.MAX_MANIFEST_BYTES,
    )
    return hashlib.sha256(raw).hexdigest()


def _validate_evidence(
    *,
    asset: NativeAsset,
    artifact_path: Path,
    manifest_path: Path,
    source_commit: str,
) -> dict[str, object]:
    manifest = artifact_checker.load_manifest(manifest_path)
    if manifest["sdk"] != "csharp":
        fail(f"{asset.target}: evidence manifest is not for the C# SDK")
    if manifest["target"] != asset.target:
        fail(f"{asset.target}: evidence manifest target does not match its directory")
    if manifest["source_commit"] != source_commit:
        fail(f"{asset.target}: evidence manifest is stale for the current source commit")
    digest, size = artifact_checker.stable_artifact_identity(artifact_path)
    if (
        digest != manifest["artifact_sha256"]
        or size != manifest["artifact_size"]
    ):
        fail(f"{asset.target}: native artifact bytes do not match their ABI-31 evidence")
    return manifest


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _copy_authenticated_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    before = _regular_file_metadata(source, "native package input")
    if before.st_size != expected_size:
        fail("native package input size changed before staging")
    destination.parent.mkdir(parents=True, exist_ok=True)
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    write_flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_descriptor = os.open(source, read_flags)
    except OSError as error:
        raise CSharpNativePackageError(
            f"native package input could not be opened: {source}"
        ) from error
    try:
        opened = os.fstat(source_descriptor)
        if _file_identity(opened) != _file_identity(before):
            fail("native package input changed while it was opened")
        try:
            destination_descriptor = os.open(destination, write_flags, 0o644)
        except OSError as error:
            raise CSharpNativePackageError(
                f"native package output must be fresh: {destination}"
            ) from error
        digest = hashlib.sha256()
        copied = 0
        try:
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                copied += len(chunk)
                offset = 0
                while offset < len(chunk):
                    offset += os.write(destination_descriptor, chunk[offset:])
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        after = os.fstat(source_descriptor)
    finally:
        os.close(source_descriptor)
    current = _regular_file_metadata(source, "native package input")
    if (
        _file_identity(opened) != _file_identity(after)
        or _file_identity(opened) != _file_identity(current)
    ):
        fail("native package input changed while it was staged")
    if copied != expected_size or digest.hexdigest() != expected_sha256:
        fail("native package input bytes changed while they were staged")
    staged_digest, staged_size = artifact_checker.stable_artifact_identity(destination)
    if staged_digest != expected_sha256 or staged_size != expected_size:
        fail("staged native package bytes do not match their evidence")


def _write_fresh(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise CSharpNativePackageError(f"native package output must be fresh: {path}") from error
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _asset_row(
    asset: NativeAsset,
    evidence: Mapping[str, object],
    *,
    evidence_sha256: str,
) -> dict[str, object]:
    return {
        "artifact_sha256": evidence["artifact_sha256"],
        "artifact_size": evidence["artifact_size"],
        "evidence_manifest_sha256": evidence_sha256,
        "evidence_path": asset.evidence_path,
        "package_path": asset.package_path,
        "rid": asset.rid,
        "target": asset.target,
    }


def validate_package_manifest(value: object) -> dict[str, object]:
    """Validate the exact aggregate C# native-package manifest."""

    if type(value) is not dict:
        fail("C# native package manifest must be a JSON object")
    manifest = dict(value)
    expected_keys = {
        "assets",
        "bridge_abi_version",
        "schema",
        "sdk",
        "source_commit",
    }
    if set(manifest) != expected_keys:
        fail("C# native package manifest field inventory is not exact")
    if manifest["schema"] != SCHEMA or manifest["sdk"] != "csharp":
        fail("C# native package manifest schema or SDK is unsupported")
    if manifest["bridge_abi_version"] != artifact_checker.REQUIRED_BRIDGE_ABI_VERSION:
        fail("C# native package manifest does not require exact bridge ABI 31")
    commit = manifest["source_commit"]
    if type(commit) is not str or artifact_checker.COMMIT_RE.fullmatch(commit) is None:
        fail("C# native package source commit is not canonical")
    rows = manifest["assets"]
    if type(rows) is not list or len(rows) != len(NATIVE_ASSETS):
        fail("C# native package asset inventory is not exact")
    expected_row_keys = {
        "artifact_sha256",
        "artifact_size",
        "evidence_manifest_sha256",
        "evidence_path",
        "package_path",
        "rid",
        "target",
    }
    for asset, row_value in zip(NATIVE_ASSETS, rows):
        if type(row_value) is not dict:
            fail("C# native package asset rows must be JSON objects")
        row = dict(row_value)
        if set(row) != expected_row_keys:
            fail(f"{asset.target}: native package asset field inventory is not exact")
        if (
            row["target"] != asset.target
            or row["rid"] != asset.rid
            or row["package_path"] != asset.package_path
            or row["evidence_path"] != asset.evidence_path
        ):
            fail(f"{asset.target}: native package target/RID/path mapping is not exact")
        for digest_field in ("artifact_sha256", "evidence_manifest_sha256"):
            digest = row[digest_field]
            if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
                fail(f"{asset.target}: {digest_field} is not canonical")
        size = row["artifact_size"]
        if type(size) is not int or size <= 0:
            fail(f"{asset.target}: native package artifact size must be positive")
    return manifest


def canonical_package_manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    """Encode one validated aggregate manifest canonically."""

    return _canonical_json_bytes(validate_package_manifest(dict(manifest)))


def _load_package_manifest(path: Path) -> dict[str, object]:
    raw = artifact_checker.stable_bounded_file_bytes(
        path,
        label="C# native package manifest",
        maximum_bytes=artifact_checker.MAX_MANIFEST_BYTES,
    )
    try:
        parsed = json.loads(raw, object_pairs_hook=artifact_checker._reject_duplicate_object_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CSharpNativePackageError(
            f"C# native package manifest is unreadable: {path}"
        ) from error
    validated = validate_package_manifest(parsed)
    if raw != canonical_package_manifest_bytes(validated):
        fail("C# native package manifest JSON is not canonical")
    return validated


def _tree_inventory(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _require_directory(root, "C# native package staging root")
    files: list[str] = []
    directories: list[str] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        for name in _directory_names(directory, "C# native package staging directory"):
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                fail("C# native package staging tree exceeds its entry limit")
            path = directory / name
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                fail(f"C# native package staging path must not be a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(relative)
                pending.append((path, relative_parts))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size > 0:
                files.append(relative)
            else:
                fail(f"C# native package staging path is not a supported regular entry: {relative}")
    return tuple(sorted(files)), tuple(sorted(directories))


def _expected_staging_inventory() -> tuple[tuple[str, ...], tuple[str, ...]]:
    files = [PACKAGE_MANIFEST_NAME]
    files.extend(asset.package_path for asset in NATIVE_ASSETS)
    files.extend(asset.evidence_path for asset in NATIVE_ASSETS)
    directories = {"evidence", "runtimes"}
    for asset in NATIVE_ASSETS:
        directories.add(f"runtimes/{asset.rid}")
        directories.add(f"runtimes/{asset.rid}/native")
    return tuple(sorted(files)), tuple(sorted(directories))


def verify_stage(
    stage_root: Path,
    source_root: Path,
    *,
    source_state: Callable[[Path], tuple[str, bool]] = artifact_checker.source_state,
) -> dict[str, object]:
    """Verify one complete staged five-RID native package tree."""

    source_commit = _source_commit(source_root, source_state=source_state)
    files, directories = _tree_inventory(stage_root)
    expected_files, expected_directories = _expected_staging_inventory()
    if files != expected_files or directories != expected_directories:
        fail("C# native package staging inventory is not exact")
    manifest = _load_package_manifest(stage_root / PACKAGE_MANIFEST_NAME)
    if manifest["source_commit"] != source_commit:
        fail("C# native package staging manifest is stale for the current source commit")
    rows = manifest["assets"]
    assert isinstance(rows, list)
    for asset, row_value in zip(NATIVE_ASSETS, rows):
        assert isinstance(row_value, dict)
        row = row_value
        evidence_path = stage_root / asset.evidence_path
        if _manifest_digest(evidence_path) != row["evidence_manifest_sha256"]:
            fail(f"{asset.target}: staged evidence manifest digest does not match")
        evidence = _validate_evidence(
            asset=asset,
            artifact_path=stage_root / asset.package_path,
            manifest_path=evidence_path,
            source_commit=source_commit,
        )
        if (
            evidence["artifact_sha256"] != row["artifact_sha256"]
            or evidence["artifact_size"] != row["artifact_size"]
        ):
            fail(f"{asset.target}: staged aggregate and target evidence disagree")
    final_commit = _source_commit(source_root, source_state=source_state)
    if final_commit != source_commit:
        fail("source revision changed while C# native package staging was verified")
    return manifest


def stage_package(
    input_root: Path,
    output_root: Path,
    source_root: Path,
    *,
    source_state: Callable[[Path], tuple[str, bool]] = artifact_checker.source_state,
) -> dict[str, object]:
    """Authenticate five target bundles and create a fresh deterministic stage."""

    source_commit = _source_commit(source_root, source_state=source_state)
    _require_exact_names(
        input_root,
        tuple(asset.target for asset in NATIVE_ASSETS),
        label="C# native package input root",
    )
    if output_root.exists() or output_root.is_symlink():
        fail(f"C# native package output must not already exist: {output_root}")
    output_root.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, object]] = []
    for asset in NATIVE_ASSETS:
        target_root = input_root / asset.target
        _require_exact_names(
            target_root,
            (asset.library_name, EVIDENCE_MANIFEST_NAME),
            label=f"{asset.target} native package input",
        )
        artifact_path = target_root / asset.library_name
        evidence_path = target_root / EVIDENCE_MANIFEST_NAME
        evidence = _validate_evidence(
            asset=asset,
            artifact_path=artifact_path,
            manifest_path=evidence_path,
            source_commit=source_commit,
        )
        _copy_authenticated_file(
            artifact_path,
            output_root / asset.package_path,
            expected_sha256=str(evidence["artifact_sha256"]),
            expected_size=int(evidence["artifact_size"]),
        )
        evidence_bytes = artifact_checker.stable_bounded_file_bytes(
            evidence_path,
            label="native artifact evidence manifest",
            maximum_bytes=artifact_checker.MAX_MANIFEST_BYTES,
        )
        _write_fresh(output_root / asset.evidence_path, evidence_bytes)
        rows.append(
            _asset_row(
                asset,
                evidence,
                evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
            )
        )
    manifest = {
        "assets": rows,
        "bridge_abi_version": artifact_checker.REQUIRED_BRIDGE_ABI_VERSION,
        "schema": SCHEMA,
        "sdk": "csharp",
        "source_commit": source_commit,
    }
    _write_fresh(
        output_root / PACKAGE_MANIFEST_NAME,
        canonical_package_manifest_bytes(manifest),
    )
    return verify_stage(
        output_root,
        source_root,
        source_state=source_state,
    )


def _zip_entry_is_symlink(entry: zipfile.ZipInfo) -> bool:
    unix_mode = (entry.external_attr >> 16) & 0xFFFF
    return unix_mode != 0 and stat.S_ISLNK(unix_mode)


def verify_package(
    package_path: Path,
    stage_root: Path,
    source_root: Path,
    *,
    source_state: Callable[[Path], tuple[str, bool]] = artifact_checker.source_state,
) -> None:
    """Require a NuGet package to contain the exact staged five-RID bytes."""

    manifest = verify_stage(stage_root, source_root, source_state=source_state)
    package_metadata = _regular_file_metadata(package_path, "C# NuGet package")
    if package_metadata.st_size > MAX_PACKAGE_BYTES:
        fail("C# NuGet package exceeds its byte limit")
    package_digest_before, package_size_before = artifact_checker.stable_artifact_identity(
        package_path
    )
    try:
        with zipfile.ZipFile(package_path, "r") as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                fail("C# NuGet package contains duplicate ZIP entries")
            runtime_entries = sorted(name for name in names if name.startswith("runtimes/"))
            expected_runtime_entries = sorted(asset.package_path for asset in NATIVE_ASSETS)
            if runtime_entries != expected_runtime_entries:
                fail("C# NuGet package runtime/native inventory is not exact")
            rows = manifest["assets"]
            assert isinstance(rows, list)
            by_path = {
                str(row["package_path"]): row
                for row in rows
                if isinstance(row, dict)
            }
            for asset in NATIVE_ASSETS:
                entry = archive.getinfo(asset.package_path)
                if entry.is_dir() or _zip_entry_is_symlink(entry) or (entry.flag_bits & 0x1):
                    fail(
                        f"{asset.package_path}: NuGet native entry is not a "
                        "regular unencrypted file"
                    )
                row = by_path[asset.package_path]
                expected_size = int(row["artifact_size"])
                if entry.file_size != expected_size:
                    fail(f"{asset.package_path}: NuGet native entry size does not match")
                digest = hashlib.sha256()
                read_size = 0
                with archive.open(entry, "r") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        read_size += len(chunk)
                        if read_size > expected_size:
                            fail(
                                f"{asset.package_path}: NuGet native entry "
                                "exceeds its evidence size"
                            )
                if (
                    read_size != expected_size
                    or digest.hexdigest() != row["artifact_sha256"]
                ):
                    fail(f"{asset.package_path}: NuGet native bytes do not match ABI-31 evidence")
    except zipfile.BadZipFile as error:
        raise CSharpNativePackageError(
            f"C# NuGet package is not a readable ZIP archive: {package_path}"
        ) from error
    package_digest_after, package_size_after = artifact_checker.stable_artifact_identity(
        package_path
    )
    if (
        package_digest_after != package_digest_before
        or package_size_after != package_size_before
    ):
        fail("C# NuGet package changed while it was verified")


def parse_args() -> argparse.Namespace:
    """Parse the C# native package command line."""

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    stage = subparsers.add_parser("stage")
    stage.add_argument("--input-root", required=True, type=Path)
    stage.add_argument("--output-root", required=True, type=Path)
    stage.add_argument("--source-root", required=True, type=Path)

    verify_staged = subparsers.add_parser("verify-stage")
    verify_staged.add_argument("--stage-root", required=True, type=Path)
    verify_staged.add_argument("--source-root", required=True, type=Path)

    verify_nupkg = subparsers.add_parser("verify-package")
    verify_nupkg.add_argument("--package", required=True, type=Path)
    verify_nupkg.add_argument("--stage-root", required=True, type=Path)
    verify_nupkg.add_argument("--source-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    """Run the selected fail-closed C# native package operation."""

    args = parse_args()
    source_root = args.source_root.resolve(strict=True)
    if args.mode == "stage":
        stage_package(
            Path(os.path.abspath(args.input_root)),
            Path(os.path.abspath(args.output_root)),
            source_root,
        )
    elif args.mode == "verify-stage":
        verify_stage(
            Path(os.path.abspath(args.stage_root)),
            source_root,
        )
    else:
        verify_package(
            Path(os.path.abspath(args.package)),
            Path(os.path.abspath(args.stage_root)),
            source_root,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        CSharpNativePackageError,
        artifact_checker.ArtifactContractError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
