#!/usr/bin/env python3
"""Pack and restore authenticated NoritoBridge Apple slice handoffs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import BinaryIO, NoReturn


SCHEMA = "iroha.norito-bridge-apple-slice.v1"
COMMON_SCHEMA = "iroha.norito-bridge-apple-slice-common.v1"
ARCHIVE_NAME = "NoritoBridge.apple-slice.tar"
ATTESTATION_NAME = "NoritoBridge.apple-slice.json"
LIBRARY_NAME = "libconnect_norito_bridge.a"
MAX_ATTESTATION_SIZE = 64 * 1024
MAX_LIBRARY_SIZE = 4 * 1024 * 1024 * 1024
TARGET_PROFILES = {
    "aarch64-apple-ios": "apple-ios-device",
    "aarch64-apple-ios-sim": "apple-ios-simulator",
    "x86_64-apple-ios": "apple-ios-simulator",
    "aarch64-apple-darwin": "apple-macos",
    "x86_64-apple-darwin": "apple-macos",
}
COMMON_KEYS = {
    "schema",
    "source_commit",
    "embedded_source_commit",
    "source_tree_dirty",
    "source_fingerprint_sha256",
    "cargo_lock_sha256",
    "bridge_header_sha256",
    "privacy_production_enabled",
    "cargo_features",
    "build_environment",
}
BUILD_ENVIRONMENT_KEYS = {
    "schema",
    "hermetic_runner_schema",
    "hermetic_runner_sha256",
    "wallet_runtime_authority",
    "wallet_runtime_trust_ed25519_hex",
    "cargo_build_jobs",
    "cargo_incremental",
    "cargo_net_offline",
    "rust_toolchain_channel",
    "cargo_release",
    "cargo_commit_hash",
    "cargo_binary_sha256",
    "rustc_release",
    "rustc_commit_hash",
    "rustc_binary_sha256",
    "rustdoc_release",
    "rustdoc_commit_hash",
    "rustdoc_binary_sha256",
    "python_version",
    "python_binary_sha256",
    "git_version",
    "git_binary_sha256",
    "rustup_version",
    "rustup_binary_sha256",
    "xcode_version",
    "xcode_build_version",
    "iphoneos_sdk_version",
    "iphonesimulator_sdk_version",
    "macosx_sdk_version",
    "iphoneos_deployment_target",
    "iphonesimulator_deployment_target",
    "macosx_deployment_target",
}
ORCHESTRATION_EVIDENCE_KEYS = {
    "python_version",
    "python_binary_sha256",
    "git_version",
    "git_binary_sha256",
    "rustup_version",
    "rustup_binary_sha256",
}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
HEX_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")
XCODE_BUILD = re.compile(r"[A-Za-z0-9.]+")


class HandoffError(RuntimeError):
    """An Apple slice handoff failed authentication."""


def fail(message: str) -> NoReturn:
    """Raise a stable handoff authentication error."""

    raise HandoffError(message)


def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Decode a JSON object while rejecting duplicate members."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json_bytes(payload: bytes, label: str) -> dict[str, object]:
    """Load one UTF-8 JSON object with duplicate-member rejection."""

    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=object_without_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not canonical UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def open_regular(path: Path, label: str) -> tuple[int, os.stat_result]:
    """Open a canonical non-symbolic regular file and bind its identity."""

    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        fail(f"{label} must be an absolute canonical path")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or (metadata.st_mode & 0o022) != 0
    ):
        os.close(descriptor)
        fail(f"{label} must be an owner-controlled regular file with one link")
    try:
        path_metadata = path.lstat()
    except OSError as error:
        os.close(descriptor)
        fail(f"{label} became unavailable: {error}")
    if (
        stat.S_ISLNK(path_metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        os.close(descriptor)
        fail(f"{label} changed while it was opened")
    return descriptor, metadata


def same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    """Return whether two file snapshots describe the same immutable input."""

    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def digest_handle(handle: BinaryIO) -> str:
    """Hash a seekable file from its first byte."""

    handle.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    handle.seek(0)
    return digest.hexdigest()


def require_sha256(value: object, label: str) -> str:
    """Return a canonical lowercase SHA-256 string."""

    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def validate_common(common: dict[str, object]) -> None:
    """Validate the exact cross-runner attestation payload."""

    if set(common) != COMMON_KEYS:
        fail("Apple slice common attestation has a non-canonical field inventory")
    if common["schema"] != COMMON_SCHEMA:
        fail("Apple slice common attestation has the wrong schema")
    commit = common["source_commit"]
    if not isinstance(commit, str) or HEX_COMMIT.fullmatch(commit) is None:
        fail("Apple slice common attestation has a non-canonical source commit")
    embedded_commit = common["embedded_source_commit"]
    if (
        not isinstance(embedded_commit, str)
        or HEX_COMMIT.fullmatch(embedded_commit) is None
    ):
        fail("Apple slice common attestation has a non-canonical embedded source commit")
    if common["source_tree_dirty"] is not False:
        fail("CI Apple slices require a clean source tree")
    for key in (
        "source_fingerprint_sha256",
        "cargo_lock_sha256",
        "bridge_header_sha256",
    ):
        require_sha256(common[key], key)

    if common["privacy_production_enabled"] is not True:
        fail("Apple slice must include mandatory privacy support")
    if common["cargo_features"] != ["privacy-production-enabled"]:
        fail("Apple slice has a non-canonical Cargo feature set")

    environment = common["build_environment"]
    if not isinstance(environment, dict) or set(environment) != BUILD_ENVIRONMENT_KEYS:
        fail("Apple slice build environment has a non-canonical field inventory")
    if not isinstance(environment["wallet_runtime_authority"], str) or environment["wallet_runtime_authority"] not in {"bpng-taira-v7", "cbsi-release-v1"}:
        fail("Apple slice Native runtime authority is not exact")
    public_root = environment["wallet_runtime_trust_ed25519_hex"]
    if not isinstance(public_root, str) or HEX_SHA256.fullmatch(public_root) is None or public_root == "0" * 64:
        fail("Apple slice Native runtime public root is not exact")
    if environment["schema"] != "iroha.mobile-native-build-environment.v1":
        fail("Apple slice build environment has the wrong schema")
    if environment["hermetic_runner_schema"] != "iroha.mobile-hermetic-command.v1":
        fail("Apple slice hermetic runner has the wrong schema")
    if type(environment["cargo_build_jobs"]) is not int or environment[
        "cargo_build_jobs"
    ] != 1:
        fail("Apple slice was not built with exactly one Cargo job")
    if type(environment["cargo_incremental"]) is not int or environment[
        "cargo_incremental"
    ] != 0:
        fail("Apple slice enabled Cargo incremental compilation")
    if environment["cargo_net_offline"] is not True:
        fail("Apple slice was not built in Cargo offline mode")
    if environment["rust_toolchain_channel"] != "1.93.1":
        fail("Apple slice used the wrong Rust toolchain")
    for key in (
        "hermetic_runner_sha256",
        "cargo_binary_sha256",
        "rustc_binary_sha256",
        "rustdoc_binary_sha256",
        "python_binary_sha256",
        "git_binary_sha256",
        "rustup_binary_sha256",
    ):
        require_sha256(environment[key], key)
    for key in ("cargo_commit_hash", "rustc_commit_hash", "rustdoc_commit_hash"):
        value = environment[key]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            fail(f"{key} must be a lowercase 40-character commit hash")
    for key in (
        "cargo_release",
        "rustc_release",
        "rustdoc_release",
        "python_version",
        "git_version",
        "rustup_version",
        "xcode_version",
        "iphoneos_sdk_version",
        "iphonesimulator_sdk_version",
        "macosx_sdk_version",
        "iphoneos_deployment_target",
        "iphonesimulator_deployment_target",
        "macosx_deployment_target",
    ):
        value = environment[key]
        if not isinstance(value, str) or VERSION.fullmatch(value) is None:
            fail(f"{key} has a non-canonical version")
    if environment["cargo_release"] != "1.93.1":
        fail("Apple slice Cargo release differs from the pinned toolchain")
    if environment["rustc_release"] != "1.93.1":
        fail("Apple slice rustc release differs from the pinned toolchain")
    if environment["rustdoc_release"] != "1.93.1":
        fail("Apple slice rustdoc release differs from the pinned toolchain")
    if environment["rustdoc_commit_hash"] != environment["rustc_commit_hash"]:
        fail("Apple slice rustdoc and rustc commits differ")
    xcode_build = environment["xcode_build_version"]
    if not isinstance(xcode_build, str) or XCODE_BUILD.fullmatch(xcode_build) is None:
        fail("Apple slice Xcode build version is non-canonical")


def build_contract(common: dict[str, object]) -> dict[str, object]:
    """Project fields that can affect the static library or final package."""

    contract = dict(common)
    environment = common["build_environment"]
    if not isinstance(environment, dict):
        fail("Apple slice build environment must be an object")
    contract["build_environment"] = {
        key: value
        for key, value in environment.items()
        if key not in ORCHESTRATION_EVIDENCE_KEYS
    }
    return contract


def read_common(path: Path) -> dict[str, object]:
    """Read and validate an exact common attestation file."""

    descriptor, before = open_regular(path, "Apple slice common attestation")
    try:
        if before.st_size <= 0 or before.st_size > MAX_ATTESTATION_SIZE:
            fail("Apple slice common attestation size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(MAX_ATTESTATION_SIZE + 1)
        after = os.fstat(descriptor)
        if not same_identity(before, after):
            fail("Apple slice common attestation changed while being read")
    finally:
        os.close(descriptor)
    common = load_json_bytes(payload, "Apple slice common attestation")
    validate_common(common)
    return common


def tar_info(name: str, size: int) -> tarfile.TarInfo:
    """Create deterministic regular-file tar metadata."""

    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    info.uname = ""
    info.gname = ""
    return info


def fsync_directory(path: Path) -> None:
    """Synchronize one directory entry set."""

    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def pack(arguments: argparse.Namespace) -> None:
    """Pack one static library and its source/tool attestation."""

    target = arguments.target
    profile = arguments.profile
    if TARGET_PROFILES.get(target) != profile:
        fail("Apple slice target and hermetic profile do not match")
    common = read_common(arguments.common)
    descriptor, before = open_regular(arguments.library, "Apple slice library")
    try:
        if before.st_size <= 0 or before.st_size > MAX_LIBRARY_SIZE:
            fail("Apple slice library size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as library_handle:
            library_digest = digest_handle(library_handle)
            attestation = {
                "schema": SCHEMA,
                "target_triple": target,
                "environment_profile": profile,
                "common": common,
                "library": {
                    "name": LIBRARY_NAME,
                    "size": before.st_size,
                    "sha256": library_digest,
                },
            }
            attestation_bytes = (
                json.dumps(attestation, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            if len(attestation_bytes) > MAX_ATTESTATION_SIZE:
                fail("Apple slice attestation exceeds its size limit")

            archive = arguments.archive
            if not archive.is_absolute() or archive != Path(os.path.abspath(archive)):
                fail("Apple slice archive must be an absolute canonical path")
            if archive.name != ARCHIVE_NAME:
                fail(f"Apple slice archive must be named {ARCHIVE_NAME}")
            parent = archive.parent
            try:
                parent_metadata = parent.lstat()
                parent_resolved = parent.resolve(strict=True)
            except OSError as error:
                fail(f"Apple slice archive parent is unavailable: {error}")
            if (
                parent_resolved != parent
                or stat.S_ISLNK(parent_metadata.st_mode)
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.geteuid()
                or (parent_metadata.st_mode & 0o022) != 0
                or not os.access(parent, os.R_OK | os.W_OK | os.X_OK)
            ):
                fail("Apple slice archive parent must be a writable canonical directory")
            try:
                archive.lstat()
            except FileNotFoundError:
                pass
            else:
                fail("Apple slice archive already exists")

            temporary_fd, temporary_name = tempfile.mkstemp(
                prefix=f".{ARCHIVE_NAME}.", suffix=".tmp", dir=parent
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(temporary_fd, 0o600)
                with os.fdopen(temporary_fd, "w+b", closefd=True) as archive_handle:
                    with tarfile.open(
                        fileobj=archive_handle, mode="w", format=tarfile.USTAR_FORMAT
                    ) as output:
                        output.addfile(
                            tar_info(ATTESTATION_NAME, len(attestation_bytes)),
                            fileobj=io.BytesIO(attestation_bytes),
                        )
                        library_handle.seek(0)
                        output.addfile(
                            tar_info(LIBRARY_NAME, before.st_size),
                            fileobj=library_handle,
                        )
                    archive_handle.flush()
                    os.fsync(archive_handle.fileno())
                after = os.fstat(descriptor)
                if not same_identity(before, after):
                    fail("Apple slice library changed while being packed")
                os.link(temporary, archive)
                temporary.unlink()
                fsync_directory(parent)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
    finally:
        os.close(descriptor)


def parse_digests(values: list[str]) -> dict[str, str]:
    """Parse an exact target-to-archive-digest inventory."""

    result: dict[str, str] = {}
    for raw in values:
        target, separator, digest = raw.partition("=")
        if not separator or target not in TARGET_PROFILES:
            fail(f"invalid Apple slice digest mapping: {raw}")
        if target in result:
            fail(f"duplicate Apple slice digest mapping: {target}")
        result[target] = require_sha256(digest, f"{target} archive digest")
    if set(result) != set(TARGET_PROFILES):
        fail("Apple slice digest inventory is not exact")
    return result


def validate_tar_member(member: tarfile.TarInfo, expected_size_limit: int) -> None:
    """Reject links, sparse data, extensions, and non-canonical metadata."""

    if not member.isreg():
        fail(f"Apple slice archive member is not regular: {member.name}")
    if member.linkname:
        fail(f"Apple slice archive member has a link target: {member.name}")
    if member.sparse is not None:
        fail(f"Apple slice archive member is sparse: {member.name}")
    if member.pax_headers:
        fail(f"Apple slice archive member has PAX metadata: {member.name}")
    if (
        member.mode != 0o600
        or member.uid != 0
        or member.gid != 0
        or member.mtime != 0
        or member.uname != ""
        or member.gname != ""
    ):
        fail(f"Apple slice archive member metadata is non-canonical: {member.name}")
    if member.size <= 0 or member.size > expected_size_limit:
        fail(f"Apple slice archive member size is invalid: {member.name}")


def round_up(value: int, alignment: int) -> int:
    """Round an unsigned byte count up to an archive block boundary."""

    return ((value + alignment - 1) // alignment) * alignment


def validate_canonical_archive_layout(
    handle: BinaryIO,
    archive_size: int,
    members: list[tarfile.TarInfo],
) -> None:
    """Require the exact USTAR layout emitted by :func:`pack`."""

    attestation, library = members
    second_header = tarfile.BLOCKSIZE + round_up(
        attestation.size, tarfile.BLOCKSIZE
    )
    data_end = second_header + tarfile.BLOCKSIZE + round_up(
        library.size, tarfile.BLOCKSIZE
    )
    expected_size = round_up(
        data_end + (2 * tarfile.BLOCKSIZE), tarfile.RECORDSIZE
    )
    if (
        attestation.offset != 0
        or attestation.offset_data != tarfile.BLOCKSIZE
        or library.offset != second_header
        or library.offset_data != second_header + tarfile.BLOCKSIZE
        or archive_size != expected_size
    ):
        fail("Apple slice archive layout is non-canonical")

    for member in members:
        handle.seek(member.offset)
        raw_header = handle.read(tarfile.BLOCKSIZE)
        expected_header = tar_info(member.name, member.size).tobuf(
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        )
        if raw_header != expected_header:
            fail(f"Apple slice archive header is non-canonical: {member.name}")

    padding_ranges = (
        (
            attestation.offset_data + attestation.size,
            second_header,
        ),
        (
            library.offset_data + library.size,
            expected_size,
        ),
    )
    for start, end in padding_ranges:
        handle.seek(start)
        remaining = end - start
        while remaining:
            chunk = handle.read(min(remaining, 1024 * 1024))
            if not chunk or any(chunk):
                fail("Apple slice archive padding is non-canonical")
            remaining -= len(chunk)


def authenticate_archive(
    archive: Path,
    expected_digest: str,
    target: str,
    expected_common: dict[str, object],
    destination: Path,
) -> None:
    """Authenticate and restore one archive into a private staging root."""

    descriptor, before = open_regular(archive, f"{target} Apple slice archive")
    try:
        maximum_archive_size = (
            MAX_LIBRARY_SIZE + MAX_ATTESTATION_SIZE + 1024 * 1024
        )
        if before.st_size <= 0 or before.st_size > maximum_archive_size:
            fail(f"{target} Apple slice archive size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            digest_before = digest_handle(handle)
            if digest_before != expected_digest:
                fail(f"{target} Apple slice archive digest mismatch")
            with tarfile.open(fileobj=handle, mode="r:") as archive_reader:
                members = archive_reader.getmembers()
                if [member.name for member in members] != [ATTESTATION_NAME, LIBRARY_NAME]:
                    fail(f"{target} Apple slice archive inventory is not exact")
                if len({member.name for member in members}) != len(members):
                    fail(f"{target} Apple slice archive contains duplicate members")
                attestation_member, library_member = members
                validate_tar_member(attestation_member, MAX_ATTESTATION_SIZE)
                validate_tar_member(library_member, MAX_LIBRARY_SIZE)
                validate_canonical_archive_layout(handle, before.st_size, members)
                attestation_file = archive_reader.extractfile(attestation_member)
                if attestation_file is None:
                    fail(f"{target} Apple slice attestation is unreadable")
                attestation_bytes = attestation_file.read(MAX_ATTESTATION_SIZE + 1)
                if len(attestation_bytes) != attestation_member.size:
                    fail(f"{target} Apple slice attestation size changed")
                attestation = load_json_bytes(
                    attestation_bytes, f"{target} Apple slice attestation"
                )
                if set(attestation) != {
                    "schema",
                    "target_triple",
                    "environment_profile",
                    "common",
                    "library",
                }:
                    fail(f"{target} Apple slice attestation inventory is not exact")
                if attestation["schema"] != SCHEMA:
                    fail(f"{target} Apple slice attestation has the wrong schema")
                if attestation["target_triple"] != target:
                    fail(f"{target} Apple slice attestation binds another target")
                if attestation["environment_profile"] != TARGET_PROFILES[target]:
                    fail(f"{target} Apple slice attestation binds another profile")
                common = attestation["common"]
                if not isinstance(common, dict):
                    fail(f"{target} Apple slice common attestation is not an object")
                validate_common(common)
                if build_contract(common) != build_contract(expected_common):
                    fail(
                        f"{target} Apple slice build contract differs from the assembler"
                    )
                library = attestation["library"]
                if not isinstance(library, dict) or set(library) != {
                    "name",
                    "size",
                    "sha256",
                }:
                    fail(f"{target} Apple slice library attestation is not exact")
                if library["name"] != LIBRARY_NAME:
                    fail(f"{target} Apple slice library has the wrong name")
                if (
                    type(library["size"]) is not int
                    or library["size"] != library_member.size
                ):
                    fail(f"{target} Apple slice library size does not match")
                library_digest = require_sha256(
                    library["sha256"], f"{target} library digest"
                )

                target_directory = destination / target
                target_directory.mkdir(mode=0o700)
                output_path = target_directory / LIBRARY_NAME
                output_descriptor = os.open(
                    output_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    library_file = archive_reader.extractfile(library_member)
                    if library_file is None:
                        fail(f"{target} Apple slice library is unreadable")
                    digest = hashlib.sha256()
                    written = 0
                    with os.fdopen(output_descriptor, "wb", closefd=False) as output:
                        while chunk := library_file.read(1024 * 1024):
                            output.write(chunk)
                            digest.update(chunk)
                            written += len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    if written != library_member.size or digest.hexdigest() != library_digest:
                        fail(f"{target} Apple slice library digest mismatch")
                finally:
                    os.close(output_descriptor)
                fsync_directory(target_directory)

            digest_after = digest_handle(handle)
            after = os.fstat(descriptor)
            if digest_after != expected_digest or not same_identity(before, after):
                fail(f"{target} Apple slice archive changed while being restored")
    finally:
        os.close(descriptor)


def canonical_directory(path: Path, label: str) -> Path:
    """Return an existing canonical, owner-controlled directory."""

    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        fail(f"{label} must be an absolute canonical directory")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (metadata.st_mode & 0o022) != 0
        or not os.access(path, os.R_OK | os.W_OK | os.X_OK)
    ):
        fail(f"{label} must be an owner-controlled canonical directory")
    return path


def restore(arguments: argparse.Namespace) -> None:
    """Authenticate the exact five-archive inventory and restore its libraries."""

    expected_common = read_common(arguments.common)
    digests = parse_digests(arguments.sha256)
    archive_root = canonical_directory(arguments.archive_root, "Apple slice archive root")
    if {entry.name for entry in archive_root.iterdir()} != set(TARGET_PROFILES):
        fail("Apple slice archive root has a non-canonical target inventory")
    archives: dict[str, Path] = {}
    for target in TARGET_PROFILES:
        target_root = canonical_directory(
            archive_root / target, f"{target} Apple slice archive directory"
        )
        if {entry.name for entry in target_root.iterdir()} != {ARCHIVE_NAME}:
            fail(f"{target} Apple slice archive directory has unexpected entries")
        archives[target] = target_root / ARCHIVE_NAME

    destination = arguments.destination
    if not destination.is_absolute() or destination != Path(os.path.abspath(destination)):
        fail("Apple slice restore destination must be an absolute canonical path")
    parent = canonical_directory(destination.parent, "Apple slice restore parent")
    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    else:
        fail("Apple slice restore destination already exists")

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", suffix=".tmp", dir=parent)
    )
    os.chmod(temporary, 0o700)
    try:
        for target in TARGET_PROFILES:
            authenticate_archive(
                archives[target],
                digests[target],
                target,
                expected_common,
                temporary,
            )
        if {entry.name for entry in temporary.iterdir()} != set(TARGET_PROFILES):
            fail("restored Apple slice inventory is not exact")
        fsync_directory(temporary)
        os.rename(temporary, destination)
        fsync_directory(parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser("pack", help="pack one authenticated slice")
    pack_parser.add_argument("--common", type=Path, required=True)
    pack_parser.add_argument("--target", choices=tuple(TARGET_PROFILES), required=True)
    pack_parser.add_argument(
        "--profile",
        choices=tuple(sorted(set(TARGET_PROFILES.values()))),
        required=True,
    )
    pack_parser.add_argument("--library", type=Path, required=True)
    pack_parser.add_argument("--archive", type=Path, required=True)
    pack_parser.set_defaults(handler=pack)

    restore_parser = subparsers.add_parser(
        "restore", help="authenticate and restore all five slices"
    )
    restore_parser.add_argument("--common", type=Path, required=True)
    restore_parser.add_argument("--archive-root", type=Path, required=True)
    restore_parser.add_argument("--destination", type=Path, required=True)
    restore_parser.add_argument("--sha256", action="append", default=[], required=True)
    restore_parser.set_defaults(handler=restore)
    return result


def main() -> int:
    """Run the selected slice handoff operation."""

    arguments = parser().parse_args()
    try:
        arguments.handler(arguments)
    except (HandoffError, OSError, tarfile.TarError) as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
