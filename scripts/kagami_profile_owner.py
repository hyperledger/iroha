#!/usr/bin/env python3
"""Stage and compare complete operator-owned Kagami Iroha 3 profile bundles.

This proposed owner wrapper is intentionally narrower than ``cargo xtask
kagami-profiles``. It requires the exact genesis creation time through
``--genesis-creation-time-ms`` and admits only the complete ``iroha3-dev`` bundle. It builds
the exact current tools into a caller-owned
external Cargo target, always supplies the resulting Kagami binary explicitly,
and publishes only by an atomic no-replace rename to an absent external root.

``--check`` never writes its candidate root.  It creates two separately named
external stages, requires them to be byte-identical, and then compares that
closed inventory with the selected candidate (normally the repository root).
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
ROOT_CARGO_LOCK = REPO_ROOT / "Cargo.lock"
MAX_MANAGED_FILE_BYTES = 64 << 20
MAX_MANAGED_TOTAL_BYTES = 256 << 20
MAX_LOCK_BYTES = 8 << 20

PROFILE_FILES: Mapping[str, tuple[str, ...]] = {
    "iroha3-dev": (
        "README.md",
        "docker-compose.yml",
        "genesis.expected_hash",
        "genesis.json",
        "genesis.public_key",
        "genesis.signed.nrt",
        "peer0.toml",
        "peer1.toml",
        "peer2.toml",
        "peer3.toml",
        "verify.txt",
    ),
}


class OwnerError(RuntimeError):
    """Fail-closed owner contract violation."""


@dataclass(frozen=True)
class LockExpectation:
    byte_length: int
    sha256: str


@dataclass(frozen=True)
class ManagedFile:
    byte_length: int
    sha256: str
    body: bytes


@dataclass(frozen=True)
class BuiltTools:
    xtask: Path
    kagami: Path


def _fail(message: str) -> None:
    raise OwnerError(message)


def _raw_path_is_normalized(raw: str) -> bool:
    if not raw or "\x00" in raw:
        return False
    normalized_separators = raw.replace("\\", "/")
    if any(component in {"", ".", ".."} for component in normalized_separators.split("/")[1:]):
        return False
    return os.path.normpath(raw) == raw


def _normalized_absolute(raw: str, label: str) -> Path:
    path = Path(raw)
    if not path.is_absolute() or not _raw_path_is_normalized(raw):
        _fail(f"{label} must be one normalized absolute path")
    if path == Path(path.anchor):
        _fail(f"{label} must not be a filesystem root")
    return path


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable_regular(path: Path, *, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise OwnerError(f"{label} is missing: {path}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail(f"{label} must be one non-symbolic, single-link regular file: {path}")
    if before.st_size > maximum:
        _fail(f"{label} exceeds the {maximum}-byte bound: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _metadata_identity(opened) != _metadata_identity(before) or opened.st_nlink != 1:
            _fail(f"{label} changed while it was opened: {path}")
        chunks: list[bytes] = []
        byte_length = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, maximum - byte_length + 1))
            if not chunk:
                break
            byte_length += len(chunk)
            if byte_length > maximum:
                _fail(f"{label} exceeds the {maximum}-byte bound: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            _metadata_identity(after) != _metadata_identity(opened)
            or _metadata_identity(path_after) != _metadata_identity(before)
            or byte_length != after.st_size
            or path_after.st_nlink != 1
        ):
            _fail(f"{label} changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _authenticate_lock(path: Path, expectation: LockExpectation) -> bytes:
    body = _read_stable_regular(path, label="root Cargo.lock", maximum=MAX_LOCK_BYTES)
    if len(body) != expectation.byte_length:
        _fail(
            "root Cargo.lock byte length drifted: "
            f"expected {expectation.byte_length}, found {len(body)}"
        )
    actual = hashlib.sha256(body).hexdigest()
    if actual != expectation.sha256:
        _fail(f"root Cargo.lock SHA-256 drifted: expected {expectation.sha256}, found {actual}")
    mode = stat.S_IMODE(path.lstat().st_mode)
    if mode & 0o022:
        _fail("root Cargo.lock must not be group- or world-writable")
    return body


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _overlap(left: Path, right: Path) -> bool:
    return left == right or _is_relative_to(left, right) or _is_relative_to(right, left)


def _reject_git_ancestor(path: Path, label: str) -> None:
    for ancestor in (path, *path.parents):
        try:
            ancestor.joinpath(".git").lstat()
        except FileNotFoundError:
            continue
        _fail(f"{label} must not be inside a Git checkout: {path}")


def _existing_directory(raw: str, label: str, *, external: bool, private: bool) -> Path:
    path = _normalized_absolute(raw, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise OwnerError(f"{label} must be an existing directory: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be an existing non-symbolic directory: {path}")
    canonical = path.resolve(strict=True)
    if canonical != path:
        _fail(f"{label} must not traverse symbolic links: {path}")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        _fail(f"{label} must not grant group or world permissions: {path}")
    repository = REPO_ROOT.resolve(strict=True)
    if external:
        if _is_relative_to(canonical, repository) or _is_relative_to(repository, canonical):
            _fail(f"{label} must be external to the source repository: {path}")
        _reject_git_ancestor(canonical, label)
    return canonical


def _absent_external_root(raw: str, label: str) -> Path:
    path = _normalized_absolute(raw, label)
    parent = _existing_directory(os.fspath(path.parent), f"{label} parent", external=True, private=True)
    canonical = parent / path.name
    if canonical != path:
        _fail(f"{label} must have one canonical non-symbolic parent")
    if os.path.lexists(path):
        _fail(f"{label} must be absent for atomic no-replace publication: {path}")
    return path


def _existing_tool(raw: str, label: str) -> Path:
    path = _normalized_absolute(raw, label)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        _fail(f"{label} must be one non-symbolic, single-link regular file: {path}")
    if not os.access(path, os.X_OK):
        _fail(f"{label} must be executable: {path}")
    if path.resolve(strict=True) != path:
        _fail(f"{label} must not traverse symbolic links: {path}")
    return path


def _expected_paths(profile: str) -> tuple[str, ...]:
    try:
        names = PROFILE_FILES[profile]
    except KeyError as error:
        raise OwnerError(f"unsupported profile {profile!r}") from error
    return tuple(f"defaults/kagami/{profile}/{name}" for name in names)


def _scope_entries(root: Path, profile: str) -> list[Path]:
    scope = root / "defaults" / "kagami" / profile
    try:
        entries = sorted(scope.iterdir(), key=lambda item: item.name)
    except FileNotFoundError as error:
        raise OwnerError(f"profile bundle is missing: {scope}") from error
    for entry in entries:
        metadata = entry.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            _fail(f"profile bundle contains an unexpected directory: {entry}")
    return entries


def _assert_stage_topology(root: Path, profile: str) -> None:
    expected_directories = {
        "defaults",
        "defaults/kagami",
        f"defaults/kagami/{profile}",
    }
    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for name in directory_names:
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                _fail(f"stage contains a non-directory or symbolic directory entry: {path}")
            actual_directories.add(path.relative_to(root).as_posix())
        for name in file_names:
            actual_files.add((current_path / name).relative_to(root).as_posix())
    expected_files = set(_expected_paths(profile))
    if actual_directories != expected_directories:
        _fail(
            f"stage directory topology mismatch: expected {sorted(expected_directories)}, "
            f"found {sorted(actual_directories)}"
        )
    if actual_files != expected_files:
        _fail(
            f"stage file topology mismatch: expected {sorted(expected_files)}, "
            f"found {sorted(actual_files)}"
        )


def _snapshot(root: Path, profile: str, *, closed_stage: bool) -> dict[str, ManagedFile]:
    if closed_stage:
        _assert_stage_topology(root, profile)
    expected = set(_expected_paths(profile))
    actual = {
        entry.relative_to(root).as_posix()
        for entry in _scope_entries(root, profile)
    }
    if actual != expected:
        _fail(
            f"{profile} inventory mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    result: dict[str, ManagedFile] = {}
    total = 0
    for relative in sorted(expected):
        body = _read_stable_regular(
            root / relative,
            label=f"managed {profile} output",
            maximum=MAX_MANAGED_FILE_BYTES,
        )
        total += len(body)
        if total > MAX_MANAGED_TOTAL_BYTES:
            _fail(f"{profile} managed output exceeds the aggregate byte bound")
        result[relative] = ManagedFile(
            byte_length=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            body=body,
        )
    return result


def _compare_snapshots(
    expected: Mapping[str, ManagedFile],
    actual: Mapping[str, ManagedFile],
    label: str,
) -> None:
    if set(expected) != set(actual):
        _fail(f"{label} path inventory differs")
    mismatches = [path for path in sorted(expected) if expected[path].body != actual[path].body]
    if mismatches:
        _fail(f"{label} byte drift: {', '.join(mismatches)}")


def _run_checked(command: Sequence[str], environment: Mapping[str, str]) -> None:
    try:
        subprocess.run(
            list(command),
            cwd=REPO_ROOT,
            env=dict(environment),
            check=True,
        )
    except subprocess.CalledProcessError as error:
        rendered = " ".join(command)
        raise OwnerError(f"profile owner child failed ({error.returncode}): {rendered}") from error


def _cargo_command(cargo: Path, package: str, binary: str, expectation: LockExpectation) -> list[str]:
    return [
        os.fspath(cargo),
        "build",
        "--locked",
        "--offline",
        "--jobs",
        "1",
        "-Z",
        "unstable-options",
        "--lockfile-path",
        os.fspath(ROOT_CARGO_LOCK),
        "-p",
        package,
        "--features",
        "dev-tools",
        "--bin",
        binary,
    ]


def _profile_command(
    tools: BuiltTools,
    profile: str,
    temporary_root: Path,
    xor_allocations: Path,
    genesis_creation_time_ms: int,
) -> list[str]:
    return [
        os.fspath(tools.xtask),
        "kagami-profiles",
        "--profile",
        profile,
        "--xor-allocations-dir",
        os.fspath(xor_allocations),
        "--genesis-creation-time-ms",
        str(genesis_creation_time_ms),
        "--out",
        os.fspath(temporary_root / "defaults" / "kagami"),
        "--kagami",
        os.fspath(tools.kagami),
    ]


def _sealed_child(
    command: Sequence[str],
    environment: Mapping[str, str],
    expectation: LockExpectation,
) -> None:
    before = _authenticate_lock(ROOT_CARGO_LOCK, expectation)
    _run_checked(command, environment)
    after = _authenticate_lock(ROOT_CARGO_LOCK, expectation)
    if before != after:
        _fail("root Cargo.lock changed across an owner child process")


def _build_tools(
    cargo: Path,
    target: Path,
    expectation: LockExpectation,
) -> tuple[BuiltTools, dict[str, str]]:
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_TARGET_DIR": os.fspath(target),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "NORITO_SKIP_BINDINGS_SYNC": "1",
        }
    )
    for package, binary in (("iroha_kagami", "kagami"), ("xtask", "xtask")):
        _sealed_child(_cargo_command(cargo, package, binary, expectation), environment, expectation)
    suffix = ".exe" if os.name == "nt" else ""
    tools = BuiltTools(
        xtask=_existing_tool(os.fspath(target / "debug" / f"xtask{suffix}"), "built xtask"),
        kagami=_existing_tool(os.fspath(target / "debug" / f"kagami{suffix}"), "built Kagami"),
    )
    return tools, environment


def _fsync_stage(root: Path, managed: Mapping[str, ManagedFile]) -> None:
    for relative in sorted(managed):
        descriptor = os.open(
            root / relative,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = sorted(
        [path for path in root.rglob("*") if path.is_dir()],
        key=lambda path: len(path.parts),
        reverse=True,
    )
    directories.append(root)
    for directory in directories:
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _rename_no_replace(source: Path, destination: Path) -> None:
    if source.parent != destination.parent:
        _fail("atomic no-replace publication requires sibling paths")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    directory_fd = os.open(source.parent, flags)
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin" and hasattr(library, "renameatx_np"):
            rename = library.renameatx_np
            rename.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            rename.restype = ctypes.c_int
            result = rename(
                directory_fd,
                os.fsencode(source.name),
                directory_fd,
                os.fsencode(destination.name),
                0x00000004,
            )
        elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
            rename = library.renameat2
            rename.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            rename.restype = ctypes.c_int
            result = rename(
                directory_fd,
                os.fsencode(source.name),
                directory_fd,
                os.fsencode(destination.name),
                0x00000001,
            )
        else:
            _fail("atomic no-replace directory publication is unsupported on this host")
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
                _fail(f"destination appeared before atomic publication: {destination}")
            raise OSError(error_number, os.strerror(error_number), os.fspath(destination))
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _generate_stage(
    destination: Path,
    profile: str,
    tools: BuiltTools,
    environment: Mapping[str, str],
    expectation: LockExpectation,
    xor_allocations: Path,
    genesis_creation_time_ms: int,
) -> dict[str, ManagedFile]:
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.kagami-owner-", dir=destination.parent)
    )
    published = False
    try:
        _sealed_child(
            _profile_command(
                tools, profile, temporary, xor_allocations,
                genesis_creation_time_ms,
            ),
            environment,
            expectation,
        )
        managed = _snapshot(temporary, profile, closed_stage=True)
        _authenticate_lock(ROOT_CARGO_LOCK, expectation)
        _fsync_stage(temporary, managed)
        if os.path.lexists(destination):
            _fail(f"destination appeared before publication: {destination}")
        _rename_no_replace(temporary, destination)
        published = True
        return _snapshot(destination, profile, closed_stage=True)
    finally:
        if not published and temporary.parent == destination.parent and temporary.name.startswith(
            f".{destination.name}.kagami-owner-"
        ):
            shutil.rmtree(temporary, ignore_errors=True)


def _genesis_creation_time(record: str) -> int:
    if not record.isascii() or not record.isdecimal():
        raise argparse.ArgumentTypeError("genesis creation time must be one canonical nonzero u64")
    value = int(record)
    if value == 0 or value > (1 << 64) - 1 or str(value) != record:
        raise argparse.ArgumentTypeError("genesis creation time must be one canonical nonzero u64")
    return value


class _Once(argparse.Action):
    """Admit one explicit selection without silently replacing an earlier value."""

    def __call__(self, parser, namespace, value, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be supplied only once")
        setattr(namespace, self.dest, value)


def _parse_args(arguments: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--profile", required=True, choices=tuple(PROFILE_FILES))
    parser.add_argument("--output-root")
    parser.add_argument("--root")
    parser.add_argument("--stage-a")
    parser.add_argument("--stage-b")
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--cargo-target-dir", required=True)
    parser.add_argument("--xor-allocations-dir", required=True)
    parser.add_argument(
        "--genesis-creation-time-ms", required=True,
        type=_genesis_creation_time, action=_Once,
    )
    parser.add_argument("--cargo-lock-size", required=True, type=int)
    parser.add_argument("--cargo-lock-sha256", required=True)
    parsed = parser.parse_args(arguments)
    if parsed.cargo_lock_size <= 0 or parsed.cargo_lock_size > MAX_LOCK_BYTES:
        parser.error("--cargo-lock-size is outside the admitted bound")
    if (
        len(parsed.cargo_lock_sha256) != 64
        or any(character not in "0123456789abcdef" for character in parsed.cargo_lock_sha256)
    ):
        parser.error("--cargo-lock-sha256 must be 64 lowercase hexadecimal characters")
    if parsed.write:
        if parsed.output_root is None or any(
            value is not None for value in (parsed.root, parsed.stage_a, parsed.stage_b)
        ):
            parser.error("--write requires only --output-root")
    else:
        if parsed.output_root is not None or any(
            value is None for value in (parsed.root, parsed.stage_a, parsed.stage_b)
        ):
            parser.error("--check requires --root, --stage-a, and --stage-b")
    return parsed


def run(parsed: argparse.Namespace) -> None:
    expectation = LockExpectation(parsed.cargo_lock_size, parsed.cargo_lock_sha256)
    _authenticate_lock(ROOT_CARGO_LOCK, expectation)
    cargo = _existing_tool(parsed.cargo, "Cargo executable")
    target = _existing_directory(
        parsed.cargo_target_dir,
        "Cargo target directory",
        external=True,
        private=True,
    )
    xor_allocations = _existing_directory(
        parsed.xor_allocations_dir,
        "XOR genesis allocation directory",
        external=True,
        private=False,
    )
    if parsed.write:
        output = _absent_external_root(parsed.output_root, "output root")
        if _overlap(output, target):
            _fail("output root and Cargo target directory must not overlap")
        tools, environment = _build_tools(cargo, target, expectation)
        _generate_stage(
            output,
            parsed.profile,
            tools,
            environment,
            expectation,
            xor_allocations,
            parsed.genesis_creation_time_ms,
        )
        return

    candidate = _existing_directory(parsed.root, "candidate root", external=False, private=False)
    stage_a = _absent_external_root(parsed.stage_a, "stage A")
    stage_b = _absent_external_root(parsed.stage_b, "stage B")
    for left_label, left, right_label, right in (
        ("stage A", stage_a, "stage B", stage_b),
        ("stage A", stage_a, "Cargo target", target),
        ("stage B", stage_b, "Cargo target", target),
        ("stage A", stage_a, "candidate root", candidate),
        ("stage B", stage_b, "candidate root", candidate),
    ):
        if _overlap(left, right):
            _fail(f"{left_label} and {right_label} must not overlap")
    tools, environment = _build_tools(cargo, target, expectation)
    first = _generate_stage(
        stage_a,
        parsed.profile,
        tools,
        environment,
        expectation,
        xor_allocations,
        parsed.genesis_creation_time_ms,
    )
    second = _generate_stage(
        stage_b,
        parsed.profile,
        tools,
        environment,
        expectation,
        xor_allocations,
        parsed.genesis_creation_time_ms,
    )
    checked = _snapshot(candidate, parsed.profile, closed_stage=False)
    _compare_snapshots(first, second, "two fresh profile generations")
    _compare_snapshots(first, checked, "checked-in profile bundle")


def main(arguments: Iterable[str] | None = None) -> int:
    try:
        run(_parse_args(arguments))
    except (OwnerError, OSError) as error:
        print(f"[kagami-profile-owner] error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
