#!/usr/bin/env python3
"""Compute a deterministic SHA-256 manifest of checkout source files.

The manifest covers tracked and untracked, non-ignored paths reported by Git,
including deletions, symlink targets, and executable bits. Build artifacts and
other ignored files are deliberately excluded. The tracked workspace
``Cargo.lock`` remains an explicit mandatory build input. Unresolved index
entries are rejected because they do not identify one reproducible source
tree. For every enumerated file or symlink entry, the checkout manifest records
all permission bits, not only Git's executable bit. The separate source-seal
check verifies directory modes and rejects source symlinks that escape the
sealed root or enter the writable output. HEAD/tree remains the canonical Git
content-and-executable-mode identity.
"""

from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
import hashlib
import json
import ntpath
import os
from pathlib import Path
import posixpath
import stat
import struct
import subprocess
import sys
from typing import BinaryIO, Iterable, Iterator, Mapping


_DOMAIN = b"iroha-workspace-source-manifest-v2\0"
_PATH_LIST_DOMAIN = b"iroha-workspace-source-path-list-v1\0"
_SOURCE_SEAL_DOMAIN = b"iroha-workspace-source-seal-v1\0"
_WORKSPACE_LOCKFILE = "Cargo.lock"
_MAX_PATH_LIST_BYTES = 64 * 1024 * 1024
_MAX_PATH_COUNT = 1_000_000
_MAX_PATH_BYTES = 1024 * 1024
_MAX_SOURCE_SEAL_BYTES = 16 * 1024 * 1024 * 1024
_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_SYMLINK_TARGET_BYTES = 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_STABLE_FILE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_EXECUTE_PERMISSION_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
_ACTIVE_GIT_OPERATION_PATHS = (
    ("merge", "MERGE_HEAD"),
    ("cherry-pick", "CHERRY_PICK_HEAD"),
    ("revert", "REVERT_HEAD"),
    ("mailbox apply", "AM_HEAD"),
    ("rebase-apply", "rebase-apply"),
    ("rebase-merge", "rebase-merge"),
    ("sequencer", "sequencer"),
    ("bisect", "BISECT_START"),
)


class UnmergedSourceError(RuntimeError):
    """The Git index contains unresolved source entries."""


class ActiveGitOperationError(RuntimeError):
    """The checkout is in a Git operation that can still replace its source."""


class DirtyReleaseSourceError(RuntimeError):
    """A production release source is not one clean committed Git tree."""


class SourcePathListError(RuntimeError):
    """A detached source path list is malformed or unsafe."""


class SourceSealError(RuntimeError):
    """A sealed detached source archive is malformed, unsafe, or inconsistent."""


def _git_read_only_environment() -> dict[str, str]:
    """Return a closed environment for read-only repository inspection."""

    environment = os.environ.copy()
    # Git's environment surface is open-ended. Trace variables can create or
    # append caller-selected files, while discovery, pathspec, object-store,
    # and configuration variables can silently redirect what is inspected.
    # Start with no caller-provided `GIT_*` setting, then add only the closed
    # read-only policy below.
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_COUNT"] = "2"
    environment["GIT_CONFIG_KEY_0"] = "core.hooksPath"
    environment["GIT_CONFIG_VALUE_0"] = os.devnull
    environment["GIT_CONFIG_KEY_1"] = "core.fsmonitor"
    environment["GIT_CONFIG_VALUE_1"] = "false"
    return environment


def _git_command(root: Path, *arguments: str) -> list[str]:
    """Build one Git command pinned to the caller's resolved worktree."""

    return ["git", f"--work-tree={root.resolve()}", *arguments]


def _git_path(root: Path, name: str) -> Path:
    """Resolve one worktree-specific Git administrative path."""

    result = subprocess.run(
        _git_command(root, "rev-parse", "--git-path", name),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
    )
    raw = result.stdout.removesuffix(b"\n")
    if not raw:
        raise RuntimeError(f"git returned an empty administrative path for {name}")
    path = Path(os.fsdecode(raw))
    if not path.is_absolute():
        path = root / path
    # Normalize `..` without following the administrative marker itself. A
    # dangling marker symlink must still count as an active operation.
    return Path(os.path.abspath(path))


def _active_git_operations(root: Path) -> list[str]:
    active = []
    for label, name in _ACTIVE_GIT_OPERATION_PATHS:
        path = _git_path(root, name)
        if os.path.lexists(path):
            active.append(label)
    return active


def _reject_active_git_operations(root: Path) -> None:
    active = _active_git_operations(root)
    if active:
        raise ActiveGitOperationError(
            "workspace has an active Git operation: " + ", ".join(active)
        )


def _git_unmerged_paths(root: Path) -> list[str]:
    result = subprocess.run(
        _git_command(root, "ls-files", "--unmerged", "-z"),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
    )
    paths: set[str] = set()
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        _, separator, raw_path = entry.partition(b"\t")
        if not separator:
            raise RuntimeError("git returned a malformed unmerged index entry")
        paths.add(os.fsdecode(raw_path))
    return sorted(paths, key=os.fsencode)


def _root_excluded_policy_directories(root: Path) -> tuple[list[str], str | None]:
    """Prune discovery only below directories excluded by the tracked root policy.

    Git cannot reinclude a descendant of an excluded directory. Nested policies
    there are ineffective; tracked source files remain included by the separate
    unchanged source inventory. Bind root-policy bytes across this optimization.
    """

    if ".gitignore" not in _git_paths(root, "ls-files", "--cached", "--", ".gitignore"):
        return [], None
    policy_before = _manifest_for_paths(root, [".gitignore"])
    with os.scandir(root) as entries:
        directories = sorted(
            (os.fsencode(entry.name + "/") for entry in entries
             if entry.name != ".git" and entry.is_dir(follow_symlinks=False))
        )
    if not directories:
        return [], policy_before
    result = subprocess.run(
        _git_command(root, "check-ignore", "--no-index", "--verbose", "-z", "--stdin"),
        input=b"".join(path + b"\0" for path in directories), cwd=root,
        env=_git_read_only_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode not in (0, 1):
        result.check_returncode()
    fields = result.stdout.split(b"\0")
    if fields.pop() != b"" or len(fields) % 4:
        raise RuntimeError("git returned malformed root directory ignore rules")
    excluded = []
    for offset in range(0, len(fields), 4):
        policy, _line, pattern, directory = fields[offset:offset + 4]
        if directory not in directories:
            raise RuntimeError("git returned an unexpected root directory")
        if policy == b".gitignore" and pattern and not pattern.startswith(b"!"):
            excluded.append(":(top,exclude,literal)" + os.fsdecode(directory[:-1]))
    return excluded, policy_before


def _git_source_paths(root: Path) -> list[str]:
    unmerged = _git_unmerged_paths(root)
    if unmerged:
        rendered = ", ".join(unmerged)
        raise UnmergedSourceError(
            f"workspace contains unresolved merge entries: {rendered}"
        )
    _reject_active_git_operations(root)
    excluded_policy_directories, root_policy_before = _root_excluded_policy_directories(root)
    untracked_ignore_policy = _git_paths(
        root,
        "ls-files",
        "--others",
        "--",
        ":(top).gitignore",
        ":(glob)**/.gitignore",
        *excluded_policy_directories,
    )
    if (root_policy_before is not None
            and _manifest_for_paths(root, [".gitignore"]) != root_policy_before):
        raise DirtyReleaseSourceError("root ignore policy changed during policy discovery")
    untracked_ignore_policy = _effective_untracked_ignore_policy(
        root, untracked_ignore_policy
    )
    if untracked_ignore_policy:
        raise DirtyReleaseSourceError(
            "workspace has untracked ignore policy: "
            + ", ".join(untracked_ignore_policy)
        )
    result = subprocess.run(
        _git_command(
            root,
            "ls-files",
            "-co",
            "--exclude-per-directory=.gitignore",
            "-z",
        ),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
    )
    paths = {
        os.fsdecode(raw)
        for raw in result.stdout.split(b"\0")
        if raw
    }
    # Cargo.lock is tracked, but keep its mandatory build-input inclusion
    # explicit so future ignore-policy drift cannot remove it from evidence.
    paths.add(_WORKSPACE_LOCKFILE)
    return sorted(paths, key=os.fsencode)


def _effective_untracked_ignore_policy(root: Path, policies: list[str]) -> list[str]:
    """Reject unsigned ignore rules except below already excluded directories.

    Git never reads a nested ignore policy below an excluded parent directory.
    Only exclusions from tracked ignore files establish that boundary here;
    repository-local excludes and an untracked policy cannot authorize it.
    Ignoring just the policy filename does not exclude its parent directory.
    """

    parents = {
        os.fsencode(posixpath.dirname(path) + "/")
        for path in policies
        if posixpath.dirname(path)
    }
    if not parents:
        return policies
    tracked = {
        os.fsencode(path)
        for path in _git_paths(
            root, "ls-files", "--cached", "--",
            ":(top).gitignore", ":(glob)**/.gitignore",
        )
    }
    result = subprocess.run(
        _git_command(
            root, "check-ignore", "--no-index", "--verbose", "-z", "--stdin"
        ),
        input=b"".join(parent + b"\0" for parent in sorted(parents)),
        cwd=root,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode not in (0, 1):
        result.check_returncode()
    fields = result.stdout.split(b"\0")
    if fields.pop() != b"" or len(fields) % 4:
        raise RuntimeError("git returned malformed parent ignore rules")
    excluded = set()
    for offset in range(0, len(fields), 4):
        policy, _line, pattern, parent = fields[offset : offset + 4]
        if parent not in parents:
            raise RuntimeError("git returned an unexpected ignore parent")
        if policy in tracked and pattern and not pattern.startswith(b"!"):
            excluded.add(parent)
    return [
        path for path in policies
        if os.fsencode(posixpath.dirname(path) + "/") not in excluded
    ]


def _git_stdout(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        _git_command(root, *arguments),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _git_paths(root: Path, *arguments: str) -> list[str]:
    if not arguments:
        raise ValueError("a Git subcommand is required")
    command, *rest = arguments
    result = subprocess.run(
        _git_command(root, command, "-z", *rest),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
    )
    return [os.fsdecode(raw) for raw in result.stdout.split(b"\0") if raw]


def _git_index_entries(root: Path) -> list[tuple[bytes, str, str]]:
    """Return the stage-zero index without consulting worktree attributes."""

    result = subprocess.run(
        _git_command(root, "ls-files", "--stage", "-z"),
        cwd=root,
        check=True,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
    )
    entries = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        header, separator, path = raw.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3 or fields[2] != b"0":
            raise UnmergedSourceError("workspace index has a non-stage-zero entry")
        mode = fields[0].decode("ascii", "strict")
        object_id = fields[1].decode("ascii", "strict")
        _validate_source_path_bytes(path)
        entries.append((path, mode, object_id))
    return entries


def _git_blob_hasher(algorithm: str, size: int) -> "hashlib._Hash":
    if algorithm not in {"sha1", "sha256"}:
        raise RuntimeError(f"unsupported Git object format: {algorithm}")
    digest = hashlib.new(algorithm)
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _raw_tracked_worktree_changes(root: Path) -> list[str]:
    """Compare tracked bytes to stage zero without executing Git filters."""

    algorithm = _git_stdout(root, "rev-parse", "--show-object-format")
    expected_oid_length = 40 if algorithm == "sha1" else 64 if algorithm == "sha256" else 0
    if not expected_oid_length:
        raise RuntimeError(f"unsupported Git object format: {algorithm}")
    changes = []
    root_descriptor, root_before = _open_root_directory(root, "workspace root")
    try:
        for member, expected_mode, expected_object_id in _git_index_entries(root):
            relative = os.fsdecode(member)
            if (
                len(expected_object_id) != expected_oid_length
                or any(character not in "0123456789abcdef" for character in expected_object_id)
            ):
                raise RuntimeError("Git returned a malformed stage-zero object ID")
            parent_descriptor = _open_source_parent(root_descriptor, member)
            if parent_descriptor is None:
                changes.append(relative)
                continue
            try:
                leaf = member.rsplit(b"/", 1)[-1]
                try:
                    metadata = os.stat(
                        leaf, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    changes.append(relative)
                    continue

                observed_object_id = ""
                mode_matches = False
                if expected_mode in {"100644", "100755"}:
                    mode_matches = stat.S_ISREG(metadata.st_mode) and bool(
                        metadata.st_mode & 0o111
                    ) == (expected_mode == "100755")
                    if mode_matches:
                        digest = _git_blob_hasher(algorithm, metadata.st_size)
                        with _stable_regular_reader_at(
                            parent_descriptor,
                            leaf,
                            metadata,
                            maximum_size=_MAX_SOURCE_FILE_BYTES,
                            label=f"workspace source {relative}",
                        ) as (source, _):
                            while chunk := source.read(_COPY_CHUNK_BYTES):
                                digest.update(chunk)
                        observed_object_id = digest.hexdigest()
                elif expected_mode == "120000":
                    mode_matches = stat.S_ISLNK(metadata.st_mode)
                    if mode_matches:
                        try:
                            target = os.readlink(leaf, dir_fd=parent_descriptor)
                            after = os.stat(
                                leaf,
                                dir_fd=parent_descriptor,
                                follow_symlinks=False,
                            )
                            repeated_target = os.readlink(
                                leaf, dir_fd=parent_descriptor
                            )
                        except OSError as error:
                            raise SourceSealError(
                                f"workspace symlink changed while inspected: {relative}"
                            ) from error
                        if (
                            _stable_metadata_changed(metadata, after)
                            or target != repeated_target
                        ):
                            raise SourceSealError(
                                f"workspace symlink changed while inspected: {relative}"
                            )
                        target_bytes = (
                            target if isinstance(target, bytes) else os.fsencode(target)
                        )
                        digest = _git_blob_hasher(algorithm, len(target_bytes))
                        digest.update(target_bytes)
                        observed_object_id = digest.hexdigest()
                elif expected_mode == "160000":
                    mode_matches = stat.S_ISDIR(metadata.st_mode)
                    if mode_matches:
                        flags = os.O_RDONLY
                        if hasattr(os, "O_DIRECTORY"):
                            flags |= os.O_DIRECTORY
                        if hasattr(os, "O_NOFOLLOW"):
                            flags |= os.O_NOFOLLOW
                        descriptor = os.open(
                            leaf, flags, dir_fd=parent_descriptor
                        )
                        try:
                            opened = os.fstat(descriptor)
                            if _stable_metadata_changed(metadata, opened):
                                raise SourceSealError(
                                    f"workspace gitlink changed while inspected: {relative}"
                                )
                            # Release source binds only the parent gitlink OID;
                            # a populated submodule is a separate, unsealed
                            # checkout and is therefore never accepted.
                            if os.listdir(descriptor):
                                mode_matches = False
                            after = os.fstat(descriptor)
                            path_after = os.stat(
                                leaf,
                                dir_fd=parent_descriptor,
                                follow_symlinks=False,
                            )
                            if (
                                _stable_metadata_changed(metadata, after)
                                or _stable_metadata_changed(metadata, path_after)
                            ):
                                raise SourceSealError(
                                    f"workspace gitlink changed while inspected: {relative}"
                                )
                        finally:
                            os.close(descriptor)
                        if mode_matches:
                            observed_object_id = expected_object_id
                else:
                    raise RuntimeError(f"unsupported Git index mode: {expected_mode}")

                _require_same_source_parent(root_descriptor, member, parent_descriptor)
                if not mode_matches or observed_object_id != expected_object_id:
                    changes.append(relative)
            finally:
                os.close(parent_descriptor)
        root_after = os.fstat(root_descriptor)
        root_path_after = root.lstat()
        if (
            _stable_metadata_changed(root_before, root_after)
            or _stable_metadata_changed(root_before, root_path_after)
        ):
            raise SourceSealError("workspace root changed while inspected")
    finally:
        os.close(root_descriptor)
    return changes


def _validate_sha256(value: str, label: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SourceSealError(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return value


def _windows_host_semantics() -> bool:
    """Return whether filesystem metadata follows Windows host semantics."""

    return os.name == "nt"


def _stable_metadata_changed(
    before: os.stat_result,
    after: os.stat_result,
    *,
    compare_ctime: bool = True,
    compare_execute_bits: bool = True,
) -> bool:
    for field in _STABLE_FILE_FIELDS:
        if not compare_ctime and field == "st_ctime_ns":
            continue
        if not compare_execute_bits and field == "st_mode":
            if (before.st_mode & ~_EXECUTE_PERMISSION_BITS) != (
                after.st_mode & ~_EXECUTE_PERMISSION_BITS
            ):
                return True
            continue
        if getattr(before, field) != getattr(after, field):
            return True
    return False


@contextmanager
def _stable_regular_reader(
    path: Path,
    *,
    maximum_size: int,
    label: str,
    require_single_link: bool = True,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one bounded regular file without following a replaced pathname."""

    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or (require_single_link and before.st_nlink != 1)
        or before.st_size > maximum_size
    ):
        requirement = (
            "one bounded, singly linked regular file"
            if require_single_link
            else "one bounded regular file"
        )
        raise SourceSealError(
            f"{label} must be {requirement}"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SourceSealError(f"{label} changed before it was opened") from error
    stream = os.fdopen(descriptor, "rb")
    try:
        opened = os.fstat(stream.fileno())
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or _stable_metadata_changed(
                before,
                opened,
                compare_ctime=not _windows_host_semantics(),
                # Windows pathname stat synthesizes execute bits for known
                # executable suffixes, while descriptor stat cannot see the
                # suffix.  Normalize only that triad; the same-API checks
                # below remain strict during the read.
                compare_execute_bits=not _windows_host_semantics(),
            )
        ):
            raise SourceSealError(f"{label} changed before it was opened")
        yield stream, before
        after = os.fstat(stream.fileno())
        if _stable_metadata_changed(opened, after):
            raise SourceSealError(f"{label} changed while it was read")
        try:
            path_after = path.lstat()
        except OSError as error:
            raise SourceSealError(f"{label} changed after it was read") from error
        if _stable_metadata_changed(before, path_after):
            raise SourceSealError(f"{label} was replaced while it was read")
    finally:
        stream.close()


def _stable_file_sha256(
    path: Path,
    *,
    maximum_size: int,
    label: str,
    require_single_link: bool = True,
) -> str:
    digest = hashlib.sha256()
    with _stable_regular_reader(
        path,
        maximum_size=maximum_size,
        label=label,
        require_single_link=require_single_link,
    ) as (stream, _):
        while chunk := stream.read(_COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def release_source_identity(root: Path) -> dict[str, str | int]:
    """Return the exact clean committed source identity for a release run."""

    root = root.resolve()
    _reject_active_git_operations(root)
    unmerged = _git_unmerged_paths(root)
    if unmerged:
        raise UnmergedSourceError(
            "workspace contains unresolved merge entries: " + ", ".join(unmerged)
        )

    head_commit = _git_stdout(root, "rev-parse", "--verify", "HEAD^{commit}")
    head_tree = _git_stdout(
        root, "rev-parse", "--verify", f"{head_commit}^{{tree}}"
    )
    staged = _git_paths(
        root,
        "diff-index",
        "--cached",
        "--name-only",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--ita-visible-in-index",
        head_commit,
        "--",
    )
    if staged:
        raise DirtyReleaseSourceError(
            "release index is not HEAD: " + ", ".join(staged)
        )
    # A stage-zero index with no difference from the captured commit has that
    # commit's exact tree. Reusing the existing object ID avoids `write-tree`,
    # which can write tree objects and update the index cache-tree extension.
    index_tree = head_tree

    tracked_changes = _raw_tracked_worktree_changes(root)
    if tracked_changes:
        raise DirtyReleaseSourceError(
            "release worktree has tracked changes: " + ", ".join(tracked_changes)
        )
    untracked = _git_paths(
        root, "ls-files", "--others", "--exclude-per-directory=.gitignore"
    )
    if untracked:
        raise DirtyReleaseSourceError(
            "release worktree has non-ignored untracked paths: "
            + ", ".join(untracked)
        )

    manifest_sha256, lock_sha256 = _release_workspace_snapshot(root)
    identity = {
        "schema_version": 1,
        "head_commit": head_commit,
        "head_tree": head_tree,
        "index_tree": index_tree,
        "workspace_source_manifest_sha256": manifest_sha256,
        "cargo_lock_sha256": lock_sha256,
    }
    repeated_manifest, repeated_lock_sha256 = _release_workspace_snapshot(root)
    if (
        repeated_manifest != identity["workspace_source_manifest_sha256"]
        or repeated_lock_sha256 != identity["cargo_lock_sha256"]
    ):
        raise DirtyReleaseSourceError(
            "release source changed during identity capture"
        )
    _reject_active_git_operations(root)
    repeated_unmerged = _git_unmerged_paths(root)
    if repeated_unmerged:
        raise UnmergedSourceError(
            "workspace gained unresolved merge entries during identity capture: "
            + ", ".join(repeated_unmerged)
        )
    repeated_staged = _git_paths(
        root,
        "diff-index",
        "--cached",
        "--name-only",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--ita-visible-in-index",
        head_commit,
        "--",
    )
    repeated_tracked = _raw_tracked_worktree_changes(root)
    repeated_untracked = _git_paths(
        root, "ls-files", "--others", "--exclude-per-directory=.gitignore"
    )
    if repeated_staged or repeated_tracked or repeated_untracked:
        raise DirtyReleaseSourceError(
            "release source changed during identity capture"
        )
    if _git_stdout(root, "rev-parse", "--verify", "HEAD^{commit}") != head_commit:
        raise DirtyReleaseSourceError("release HEAD changed during identity capture")
    return identity


def _frame(hasher: "hashlib._Hash", payload: bytes) -> None:
    hasher.update(struct.pack(">Q", len(payload)))
    hasher.update(payload)


def _validate_source_path_bytes(raw: bytes) -> None:
    if (
        not raw
        or len(raw) > _MAX_PATH_BYTES
        or raw.startswith(b"/")
        or b"\0" in raw
        or any(component in (b"", b".", b"..") for component in raw.split(b"/"))
        or raw.split(b"/", 1)[0] == b".git"
    ):
        raise SourcePathListError("source path list contains an unsafe path")


def write_source_path_list(path: Path, paths: Iterable[str]) -> None:
    """Create a fixed binary path list for a detached build context."""

    encoded_paths = sorted({os.fsencode(value) for value in paths})
    if not encoded_paths or len(encoded_paths) > _MAX_PATH_COUNT:
        raise SourcePathListError("source path list count is outside its bound")
    for raw in encoded_paths:
        _validate_source_path_bytes(raw)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(_PATH_LIST_DOMAIN)
            stream.write(struct.pack(">Q", len(encoded_paths)))
            for raw in encoded_paths:
                stream.write(struct.pack(">Q", len(raw)))
                stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def read_source_path_list(path: Path) -> list[str]:
    """Read and validate a fixed path list without consulting Git metadata."""

    try:
        with _stable_regular_reader(
            path,
            maximum_size=_MAX_PATH_LIST_BYTES,
            label="source path list",
        ) as (stream, _):
            payload = stream.read(_MAX_PATH_LIST_BYTES + 1)
    except FileNotFoundError:
        raise
    except (OSError, SourceSealError) as error:
        raise SourcePathListError(str(error)) from error
    if len(payload) > _MAX_PATH_LIST_BYTES:
        raise SourcePathListError("source path list exceeds its byte bound")
    if not payload.startswith(_PATH_LIST_DOMAIN):
        raise SourcePathListError("source path list has the wrong domain")

    offset = len(_PATH_LIST_DOMAIN)

    def take_u64() -> int:
        nonlocal offset
        end = offset + 8
        if end > len(payload):
            raise SourcePathListError("source path list is truncated")
        value = struct.unpack(">Q", payload[offset:end])[0]
        offset = end
        return value

    count = take_u64()
    if count == 0 or count > _MAX_PATH_COUNT:
        raise SourcePathListError("source path list count is outside its bound")
    encoded_paths = []
    for _ in range(count):
        length = take_u64()
        if length == 0 or length > _MAX_PATH_BYTES:
            raise SourcePathListError("source path length is outside its bound")
        end = offset + length
        if end > len(payload):
            raise SourcePathListError("source path list is truncated")
        raw = payload[offset:end]
        offset = end
        _validate_source_path_bytes(raw)
        encoded_paths.append(raw)
    if offset != len(payload):
        raise SourcePathListError("source path list has trailing bytes")
    if encoded_paths != sorted(set(encoded_paths)):
        raise SourcePathListError(
            "source path list must be unique and raw-byte sorted"
        )
    return [os.fsdecode(raw) for raw in encoded_paths]


def _validate_symlink_target(member: bytes, target: bytes) -> None:
    if (
        not target
        or len(target) > _MAX_SYMLINK_TARGET_BYTES
        or b"\0" in target
        or target.startswith(b"/")
        or b"\\" in target
        or bool(ntpath.splitdrive(target)[0])
    ):
        raise SourceSealError("source seal contains an unsafe symlink target")
    parent = member.rpartition(b"/")[0]
    resolved = posixpath.normpath(posixpath.join(parent, target))
    if (
        resolved == b".."
        or resolved.startswith(b"../")
        or resolved == b".git"
        or resolved.startswith(b".git/")
        or resolved.startswith(b"/")
    ):
        raise SourceSealError("source seal contains an out-of-root symlink")


def _validate_symlink_graph(symlinks: Mapping[bytes, bytes]) -> None:
    """Reject chained links that can escape the extracted source root."""

    for member, target in symlinks.items():
        _validate_symlink_target(member, target)
        current = member.split(b"/")[:-1]
        pending = deque(target.split(b"/"))
        followed: set[bytes] = set()
        while pending:
            component = pending.popleft()
            if component in (b"", b"."):
                continue
            if component == b"..":
                if not current:
                    raise SourceSealError(
                        "source seal contains a chained out-of-root symlink"
                    )
                current.pop()
                continue
            current.append(component)
            candidate = b"/".join(current)
            if candidate == b".git" or candidate.startswith(b".git/"):
                raise SourceSealError("source seal symlink resolves into .git")
            replacement = symlinks.get(candidate)
            if replacement is None:
                continue
            if candidate in followed:
                raise SourceSealError("source seal contains a cyclic symlink chain")
            followed.add(candidate)
            current = candidate.split(b"/")[:-1]
            pending.extendleft(reversed(replacement.split(b"/")))


def _open_root_directory(path: Path, label: str) -> tuple[int, os.stat_result]:
    before = path.lstat()
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise SourceSealError(f"{label} must be a real directory")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (
        (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        or opened.st_mode != before.st_mode
    ):
        os.close(descriptor)
        raise SourceSealError(f"{label} changed before it was opened")
    return descriptor, before


def _open_source_parent(root_descriptor: int, member: bytes) -> int | None:
    descriptor = os.dup(root_descriptor)
    try:
        for component in member.split(b"/")[:-1]:
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.close(descriptor)
                return None
            except OSError as error:
                raise SourceSealError(
                    "source member has a non-directory or symlink parent"
                ) from error
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _require_same_source_parent(
    root_descriptor: int,
    member: bytes,
    expected_descriptor: int,
) -> None:
    """Require one member's parent path to still name the opened directory."""

    repeated_descriptor = _open_source_parent(root_descriptor, member)
    if repeated_descriptor is None:
        raise SourceSealError("workspace source parent disappeared while inspected")
    try:
        expected = os.fstat(expected_descriptor)
        repeated = os.fstat(repeated_descriptor)
        if (expected.st_dev, expected.st_ino) != (repeated.st_dev, repeated.st_ino):
            raise SourceSealError("workspace source parent changed while inspected")
    finally:
        os.close(repeated_descriptor)


@contextmanager
def _stable_regular_reader_at(
    parent_descriptor: int,
    leaf: bytes,
    expected: os.stat_result,
    *,
    maximum_size: int,
    label: str,
) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    """Open one regular member relative to an already authenticated parent."""

    if not stat.S_ISREG(expected.st_mode) or expected.st_size > maximum_size:
        raise SourceSealError(f"{label} must be one bounded regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
    except OSError as error:
        raise SourceSealError(f"{label} changed before it was opened") from error
    stream = os.fdopen(descriptor, "rb")
    try:
        opened = os.fstat(stream.fileno())
        if _stable_metadata_changed(
            expected,
            opened,
            compare_ctime=not _windows_host_semantics(),
            compare_execute_bits=not _windows_host_semantics(),
        ):
            raise SourceSealError(f"{label} changed before it was opened")
        yield stream, expected
        after = os.fstat(stream.fileno())
        if _stable_metadata_changed(opened, after):
            raise SourceSealError(f"{label} changed while it was read")
        try:
            path_after = os.stat(
                leaf, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except OSError as error:
            raise SourceSealError(f"{label} changed after it was read") from error
        if _stable_metadata_changed(expected, path_after):
            raise SourceSealError(f"{label} was replaced while it was read")
    finally:
        stream.close()


def _inspect_source_members(
    root: Path, paths: list[str]
) -> list[tuple[bytes, bytes, int, int | bytes, os.stat_result | None]]:
    """Freeze member types and metadata before writing a source seal."""

    records: list[tuple[bytes, bytes, int, int | bytes, os.stat_result | None]] = []
    root_descriptor, root_before = _open_root_directory(root, "source root")
    try:
        kinds: dict[bytes, bytes] = {}
        for relative in paths:
            member = os.fsencode(relative)
            _validate_source_path_bytes(member)
            for offset, value in enumerate(member.split(b"/")[:-1], start=1):
                prefix = b"/".join(member.split(b"/")[:offset])
                if kinds.get(prefix) not in (None, b"G"):
                    raise SourceSealError(
                        "source path is nested below a non-directory member"
                    )
            parent_descriptor = _open_source_parent(root_descriptor, member)
            if parent_descriptor is None:
                repeated_parent = _open_source_parent(root_descriptor, member)
                if repeated_parent is not None:
                    os.close(repeated_parent)
                    raise SourceSealError(
                        "source parent appeared while it was inspected"
                    )
                record = (member, b"D", 0, 0, None)
                records.append(record)
                kinds[member] = b"D"
                continue
            try:
                leaf = member.rsplit(b"/", 1)[-1]
                try:
                    metadata = os.stat(
                        leaf, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    record = (member, b"D", 0, 0, None)
                else:
                    mode = stat.S_IMODE(metadata.st_mode)
                    if stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            raise SourceSealError(
                                "source seal rejects hard-linked regular files"
                            )
                        if metadata.st_size > _MAX_SOURCE_FILE_BYTES:
                            raise SourceSealError(
                                "source member exceeds its size bound"
                            )
                        record = (member, b"F", mode, metadata.st_size, metadata)
                    elif stat.S_ISLNK(metadata.st_mode):
                        target = os.readlink(leaf, dir_fd=parent_descriptor)
                        if isinstance(target, str):
                            target = os.fsencode(target)
                        _validate_symlink_target(member, target)
                        record = (member, b"L", mode, target, metadata)
                    elif stat.S_ISDIR(metadata.st_mode):
                        record = (member, b"G", mode, 0, metadata)
                    else:
                        raise SourceSealError(
                            "source seal rejects device, FIFO, socket, and "
                            "unsupported source members"
                        )
                records.append(record)
                kinds[member] = record[1]
                _require_same_source_parent(
                    root_descriptor, member, parent_descriptor
                )
            finally:
                os.close(parent_descriptor)
        _validate_symlink_graph(
            {
                member: payload
                for member, kind, _, payload, _ in records
                if kind == b"L" and isinstance(payload, bytes)
            }
        )
        root_after = os.fstat(root_descriptor)
        try:
            root_path_after = root.lstat()
        except OSError as error:
            raise SourceSealError(
                "source root changed while it was inspected"
            ) from error
        if (
            _stable_metadata_changed(root_before, root_after)
            or _stable_metadata_changed(root_before, root_path_after)
        ):
            raise SourceSealError("source root changed while it was inspected")
    finally:
        os.close(root_descriptor)
    return records


class _SealWriter:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_written = 0

    def write(self, payload: bytes) -> None:
        self.bytes_written += len(payload)
        if self.bytes_written > _MAX_SOURCE_SEAL_BYTES:
            raise SourceSealError("source seal exceeds its byte bound")
        self.stream.write(payload)
        self.digest.update(payload)

    def hexdigest(self) -> str:
        return self.digest.hexdigest()


def _write_source_file_payload(
    root_descriptor: int,
    record: tuple[bytes, bytes, int, int | bytes, os.stat_result | None],
    writer: _SealWriter,
    manifest: "hashlib._Hash",
) -> None:
    member, _, _, payload_size, expected_metadata = record
    assert isinstance(payload_size, int)
    assert expected_metadata is not None
    parent_descriptor = _open_source_parent(root_descriptor, member)
    if parent_descriptor is None:
        raise SourceSealError("source file disappeared while sealing")
    leaf = member.rsplit(b"/", 1)[-1]
    try:
        with _stable_regular_reader_at(
            parent_descriptor,
            leaf,
            expected_metadata,
            maximum_size=_MAX_SOURCE_FILE_BYTES,
            label="source file",
        ) as (source, _):
            remaining = payload_size
            while remaining:
                chunk = source.read(min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SourceSealError("source file was truncated while sealing")
                writer.write(chunk)
                manifest.update(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise SourceSealError("source file grew while sealing")
        _require_same_source_parent(root_descriptor, member, parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _revalidate_non_file_source_member(
    root_descriptor: int,
    record: tuple[bytes, bytes, int, int | bytes, os.stat_result | None],
) -> None:
    member, kind, _, payload, expected_metadata = record
    parent_descriptor = _open_source_parent(root_descriptor, member)
    if kind == b"D":
        if parent_descriptor is None:
            repeated_parent = _open_source_parent(root_descriptor, member)
            if repeated_parent is not None:
                os.close(repeated_parent)
                raise SourceSealError(
                    "deleted source parent appeared while sealing"
                )
            return
        try:
            leaf = member.rsplit(b"/", 1)[-1]
            try:
                os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                _require_same_source_parent(
                    root_descriptor, member, parent_descriptor
                )
                return
            raise SourceSealError("deleted source member appeared while sealing")
        finally:
            os.close(parent_descriptor)
    if parent_descriptor is None or expected_metadata is None:
        raise SourceSealError("source member disappeared while sealing")
    try:
        leaf = member.rsplit(b"/", 1)[-1]
        metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        if _stable_metadata_changed(expected_metadata, metadata):
            raise SourceSealError("source member changed while sealing")
        if kind == b"L":
            target = os.readlink(leaf, dir_fd=parent_descriptor)
            if isinstance(target, str):
                target = os.fsencode(target)
            if target != payload:
                raise SourceSealError("source symlink changed while sealing")
        _require_same_source_parent(root_descriptor, member, parent_descriptor)
    finally:
        os.close(parent_descriptor)


def create_source_seal(
    root: Path,
    path_list: Path,
    archive: Path,
    expected_manifest: str,
) -> str:
    """Create a deterministic archive for exactly one frozen source closure."""

    expected_manifest = _validate_sha256(
        expected_manifest, "expected workspace manifest"
    )
    root = root.resolve()
    initial_path_list_sha = _stable_file_sha256(
        path_list,
        maximum_size=_MAX_PATH_LIST_BYTES,
        label="source path list",
    )
    paths = read_source_path_list(path_list)
    records = _inspect_source_members(root, paths)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(archive, flags, 0o600)
    succeeded = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            writer = _SealWriter(stream)
            manifest = hashlib.sha256(_DOMAIN)
            writer.write(_SOURCE_SEAL_DOMAIN)
            writer.write(struct.pack(">Q", len(records)))
            root_descriptor, root_before = _open_root_directory(
                root, "source root"
            )
            try:
                for record in records:
                    member, kind, mode, payload, _ = record
                    writer.write(struct.pack(">Q", len(member)))
                    writer.write(member)
                    writer.write(kind)
                    writer.write(struct.pack(">I", mode))
                    payload_size = len(payload) if isinstance(payload, bytes) else payload
                    writer.write(struct.pack(">Q", payload_size))

                    _frame(manifest, member)
                    if kind == b"D":
                        manifest.update(b"D")
                        _revalidate_non_file_source_member(root_descriptor, record)
                    else:
                        manifest.update(struct.pack(">I", mode))
                        manifest.update(kind)
                        if kind == b"F":
                            manifest.update(struct.pack(">Q", payload_size))
                            _write_source_file_payload(
                                root_descriptor, record, writer, manifest
                            )
                        elif kind == b"L":
                            assert isinstance(payload, bytes)
                            writer.write(payload)
                            _frame(manifest, payload)
                            _revalidate_non_file_source_member(
                                root_descriptor, record
                            )
                        elif kind == b"G":
                            _revalidate_non_file_source_member(
                                root_descriptor, record
                            )
                        else:
                            raise AssertionError("unreachable source seal kind")
                root_after = os.fstat(root_descriptor)
                try:
                    root_path_after = root.lstat()
                except OSError as error:
                    raise SourceSealError(
                        "source root changed while sealing"
                    ) from error
                if (
                    _stable_metadata_changed(root_before, root_after)
                    or _stable_metadata_changed(root_before, root_path_after)
                ):
                    raise SourceSealError("source root changed while sealing")
            finally:
                os.close(root_descriptor)
            actual_manifest = manifest.hexdigest()
            if actual_manifest != expected_manifest:
                raise SourceSealError(
                    "source changed after the workspace manifest was frozen"
                )
            stream.flush()
            os.fsync(stream.fileno())
            archive_sha = writer.hexdigest()
        final_path_list_sha = _stable_file_sha256(
            path_list,
            maximum_size=_MAX_PATH_LIST_BYTES,
            label="source path list",
        )
        if final_path_list_sha != initial_path_list_sha:
            raise SourceSealError("source path list changed while sealing")
        if read_source_path_list(path_list) != paths:
            raise SourceSealError("source path list changed while sealing")
        if _manifest_for_paths(root, paths) != expected_manifest:
            raise SourceSealError(
                "source changed after the source seal was written"
            )
        if (
            _stable_file_sha256(
                archive,
                maximum_size=_MAX_SOURCE_SEAL_BYTES,
                label="source seal",
            )
            != archive_sha
        ):
            raise SourceSealError("source seal changed after it was written")
        succeeded = True
        return archive_sha
    finally:
        if not succeeded:
            try:
                archive.unlink()
            except FileNotFoundError:
                pass


class _SealReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def read_exact(self, size: int) -> bytes:
        if size < 0 or self.bytes_read + size > _MAX_SOURCE_SEAL_BYTES:
            raise SourceSealError("source seal exceeds its byte bound")
        payload = self.stream.read(size)
        if len(payload) != size:
            raise SourceSealError("source seal is truncated")
        self.bytes_read += size
        self.digest.update(payload)
        return payload

    def take_u64(self) -> int:
        return struct.unpack(">Q", self.read_exact(8))[0]

    def finish(self) -> str:
        trailing = self.stream.read(1)
        if trailing:
            raise SourceSealError("source seal has trailing bytes")
        return self.digest.hexdigest()


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise SourceSealError("short write while extracting source seal")
        offset += written


class _DestinationExtractor:
    def __init__(self, destination: Path):
        self.destination = destination
        self.root_descriptor, self.root_before = _open_root_directory(
            destination, "source seal destination"
        )
        if os.listdir(self.root_descriptor):
            os.close(self.root_descriptor)
            raise SourceSealError("source seal destination must be empty")
        self.directory_modes: dict[bytes, int] = {}

    def close(self) -> None:
        os.close(self.root_descriptor)

    def _parent(self, member: bytes) -> tuple[int, bytes]:
        descriptor = os.dup(self.root_descriptor)
        prefix: list[bytes] = []
        try:
            components = member.split(b"/")
            for component in components[:-1]:
                prefix.append(component)
                relative = b"/".join(prefix)
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    self.directory_modes.setdefault(relative, 0o755)
                except FileExistsError:
                    pass
                flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    next_descriptor = os.open(
                        component, flags, dir_fd=descriptor
                    )
                except OSError as error:
                    raise SourceSealError(
                        "source seal extraction encountered an unsafe parent"
                    ) from error
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor, components[-1]
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def begin_file(self, member: bytes) -> int:
        parent, leaf = self._parent(member)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            return os.open(leaf, flags, 0o600, dir_fd=parent)
        except OSError as error:
            raise SourceSealError(
                "source seal could not create a unique regular member"
            ) from error
        finally:
            os.close(parent)

    def create_symlink(self, member: bytes, target: bytes) -> None:
        parent, leaf = self._parent(member)
        try:
            os.symlink(target, leaf, dir_fd=parent)
        except OSError as error:
            raise SourceSealError(
                "source seal could not create a unique symlink member"
            ) from error
        finally:
            os.close(parent)

    def create_directory(self, member: bytes, mode: int) -> None:
        parent, leaf = self._parent(member)
        try:
            try:
                os.mkdir(leaf, 0o700, dir_fd=parent)
            except FileExistsError:
                flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(leaf, flags, dir_fd=parent)
                os.close(descriptor)
            self.directory_modes[member] = mode
        except OSError as error:
            raise SourceSealError(
                "source seal could not create a directory member"
            ) from error
        finally:
            os.close(parent)

    def require_deleted(self, member: bytes) -> None:
        parent, leaf = self._parent(member)
        try:
            try:
                os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise SourceSealError("deleted source seal member exists")
        finally:
            os.close(parent)

    def _open_directory(self, member: bytes) -> int:
        descriptor = os.dup(self.root_descriptor)
        try:
            for component in member.split(b"/"):
                flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def finish_directories(self) -> None:
        for member, mode in sorted(
            self.directory_modes.items(),
            key=lambda item: (-item[0].count(b"/"), item[0]),
        ):
            descriptor = self._open_directory(member)
            try:
                os.fchmod(descriptor, mode)
            finally:
                os.close(descriptor)


def _scan_source_seal(
    stream: BinaryIO,
    paths: list[str],
    extractor: _DestinationExtractor | None = None,
) -> tuple[str, str, dict[bytes, bytes]]:
    reader = _SealReader(stream)
    if reader.read_exact(len(_SOURCE_SEAL_DOMAIN)) != _SOURCE_SEAL_DOMAIN:
        raise SourceSealError("source seal has the wrong domain")
    count = reader.take_u64()
    if count == 0 or count > _MAX_PATH_COUNT or count != len(paths):
        raise SourceSealError("source seal member count does not match its path list")

    expected_paths = [os.fsencode(path) for path in paths]
    manifest = hashlib.sha256(_DOMAIN)
    kinds: dict[bytes, bytes] = {}
    symlinks: dict[bytes, bytes] = {}
    pending_symlinks: list[tuple[bytes, bytes]] = []
    for index, expected_member in enumerate(expected_paths):
        path_size = reader.take_u64()
        if path_size == 0 or path_size > _MAX_PATH_BYTES:
            raise SourceSealError("source seal member path exceeds its bound")
        member = reader.read_exact(path_size)
        try:
            _validate_source_path_bytes(member)
        except SourcePathListError as error:
            raise SourceSealError(
                "source seal contains an unsafe path"
            ) from error
        if member != expected_member:
            raise SourceSealError(
                f"source seal member {index} is outside or out of order "
                "for the frozen closure"
            )
        for offset, _ in enumerate(member.split(b"/")[:-1], start=1):
            prefix = b"/".join(member.split(b"/")[:offset])
            if kinds.get(prefix) not in (None, b"G"):
                raise SourceSealError(
                    "source seal member is nested below a non-directory member"
                )

        kind = reader.read_exact(1)
        if kind not in (b"D", b"F", b"G", b"L"):
            raise SourceSealError(
                "source seal rejects hard link, device, FIFO, socket, and "
                "unknown member types"
            )
        mode = struct.unpack(">I", reader.read_exact(4))[0]
        payload_size = reader.take_u64()
        if mode & ~0o7777:
            raise SourceSealError("source seal member mode exceeds its bound")
        if kind == b"D":
            if mode != 0 or payload_size != 0:
                raise SourceSealError("deleted source seal member is malformed")
        elif kind == b"F":
            if payload_size > _MAX_SOURCE_FILE_BYTES:
                raise SourceSealError("source seal file exceeds its size bound")
        elif payload_size != 0 and kind == b"G":
            raise SourceSealError("source seal directory has a payload")
        elif kind == b"L" and (
            payload_size == 0 or payload_size > _MAX_SYMLINK_TARGET_BYTES
        ):
            raise SourceSealError("source seal symlink target exceeds its bound")

        _frame(manifest, member)
        if kind == b"D":
            manifest.update(b"D")
            if extractor is not None:
                extractor.require_deleted(member)
        else:
            manifest.update(struct.pack(">I", mode))
            manifest.update(kind)
            if kind == b"F":
                manifest.update(struct.pack(">Q", payload_size))
                output_descriptor = (
                    extractor.begin_file(member) if extractor is not None else None
                )
                try:
                    remaining = payload_size
                    while remaining:
                        chunk = reader.read_exact(
                            min(_COPY_CHUNK_BYTES, remaining)
                        )
                        manifest.update(chunk)
                        if output_descriptor is not None:
                            _write_all(output_descriptor, chunk)
                        remaining -= len(chunk)
                    if output_descriptor is not None:
                        os.fchmod(output_descriptor, mode)
                        os.fsync(output_descriptor)
                finally:
                    if output_descriptor is not None:
                        os.close(output_descriptor)
            elif kind == b"L":
                target = reader.read_exact(payload_size)
                _validate_symlink_target(member, target)
                _frame(manifest, target)
                symlinks[member] = target
                pending_symlinks.append((member, target))
            elif extractor is not None:
                extractor.create_directory(member, mode)
        kinds[member] = kind
    _validate_symlink_graph(symlinks)
    if extractor is not None:
        for member, target in pending_symlinks:
            extractor.create_symlink(member, target)
    return manifest.hexdigest(), reader.finish(), kinds


def _audit_extracted_closure(
    extractor: _DestinationExtractor, kinds: dict[bytes, bytes]
) -> None:
    allowed_directories: set[bytes] = {
        member for member, kind in kinds.items() if kind == b"G"
    }
    for member in kinds:
        components = member.split(b"/")
        allowed_directories.update(
            b"/".join(components[:count])
            for count in range(1, len(components))
        )
    seen: set[bytes] = set()

    def visit(descriptor: int, prefix: bytes) -> None:
        entries = sorted(os.scandir(descriptor), key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            name = os.fsencode(entry.name)
            member = name if not prefix else prefix + b"/" + name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if member not in allowed_directories:
                    raise SourceSealError(
                        "extracted source contains a directory outside the frozen closure"
                    )
                if kinds.get(member) == b"G":
                    seen.add(member)
                flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    visit(child, member)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1 or kinds.get(member) != b"F":
                    raise SourceSealError(
                        "extracted source contains an extra or hard-linked file"
                    )
                seen.add(member)
            elif stat.S_ISLNK(metadata.st_mode):
                if kinds.get(member) != b"L":
                    raise SourceSealError(
                        "extracted source contains an extra symlink"
                    )
                seen.add(member)
            else:
                raise SourceSealError(
                    "extracted source contains a device, FIFO, socket, or "
                    "unsupported member"
                )

    visit(extractor.root_descriptor, b"")
    expected = {member for member, kind in kinds.items() if kind != b"D"}
    if seen != expected:
        raise SourceSealError("extracted source is missing a non-deleted member")


def workspace_source_manifest_from_exact_path_list(
    root: Path, path_list: Path
) -> str:
    """Audit an exact detached closure, then compute its canonical manifest."""

    paths = read_source_path_list(path_list)
    records = _inspect_source_members(root.resolve(), paths)
    kinds = {member: kind for member, kind, _, _, _ in records}
    extractor = _DestinationExtractor.__new__(_DestinationExtractor)
    extractor.destination = root
    extractor.root_descriptor, extractor.root_before = _open_root_directory(
        root, "detached source root"
    )
    try:
        _audit_extracted_closure(extractor, kinds)
    finally:
        extractor.close()
    return _manifest_for_paths(root.resolve(), paths)


def extract_source_seal(
    archive: Path,
    path_list: Path,
    destination: Path,
    expected_manifest: str,
    expected_archive_sha256: str,
    expected_path_list_sha256: str,
) -> str:
    """Validate fully, then safely extract one sealed source closure."""

    expected_manifest = _validate_sha256(
        expected_manifest, "expected workspace manifest"
    )
    expected_archive_sha256 = _validate_sha256(
        expected_archive_sha256, "expected source archive SHA-256"
    )
    expected_path_list_sha256 = _validate_sha256(
        expected_path_list_sha256, "expected source path-list SHA-256"
    )
    if (
        _stable_file_sha256(
            path_list,
            maximum_size=_MAX_PATH_LIST_BYTES,
            label="source path list",
        )
        != expected_path_list_sha256
    ):
        raise SourceSealError("source path-list SHA-256 mismatch")
    paths = read_source_path_list(path_list)

    with _stable_regular_reader(
        archive,
        maximum_size=_MAX_SOURCE_SEAL_BYTES,
        label="source seal",
    ) as (stream, _):
        manifest, archive_sha, first_kinds = _scan_source_seal(stream, paths)
        if archive_sha != expected_archive_sha256:
            raise SourceSealError("source archive SHA-256 mismatch")
        if manifest != expected_manifest:
            raise SourceSealError("source archive workspace manifest mismatch")

        extractor = _DestinationExtractor(destination)
        try:
            stream.seek(0)
            second_manifest, second_archive_sha, second_kinds = _scan_source_seal(
                stream, paths, extractor
            )
            if (
                second_manifest != expected_manifest
                or second_archive_sha != expected_archive_sha256
                or second_kinds != first_kinds
            ):
                raise SourceSealError("source seal changed during extraction")
            extractor.finish_directories()
            _audit_extracted_closure(extractor, second_kinds)
        finally:
            extractor.close()

    if (
        _stable_file_sha256(
            path_list,
            maximum_size=_MAX_PATH_LIST_BYTES,
            label="source path list",
        )
        != expected_path_list_sha256
        or read_source_path_list(path_list) != paths
    ):
        raise SourceSealError("source path list changed during extraction")
    detached_manifest = workspace_source_manifest_from_exact_path_list(
        destination, path_list
    )
    if detached_manifest != expected_manifest:
        raise SourceSealError(
            "extracted source does not match the frozen workspace manifest"
        )
    return detached_manifest


def _manifest_snapshot_for_paths(
    root: Path,
    paths: Iterable[str],
    *,
    observed_regular_path: str | None = None,
) -> tuple[str, str | None]:
    """Hash one rooted path set and optionally one regular member in one pass."""

    hasher = hashlib.sha256(_DOMAIN)
    observed_digest = (
        hashlib.sha256() if observed_regular_path is not None else None
    )
    observed = False
    root_descriptor, root_before = _open_root_directory(root, "workspace root")
    try:
        for relative in sorted(set(paths), key=os.fsencode):
            member = os.fsencode(relative)
            _validate_source_path_bytes(member)
            _frame(hasher, member)
            parent_descriptor = _open_source_parent(root_descriptor, member)
            if parent_descriptor is None:
                repeated_parent = _open_source_parent(root_descriptor, member)
                if repeated_parent is not None:
                    os.close(repeated_parent)
                    raise SourceSealError(
                        f"workspace source parent appeared while inspected: {relative}"
                    )
                hasher.update(b"D")
                continue
            try:
                leaf = member.rsplit(b"/", 1)[-1]
                try:
                    metadata = os.stat(
                        leaf, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    try:
                        os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        hasher.update(b"D")
                    else:
                        raise SourceSealError(
                            f"workspace source appeared while inspected: {relative}"
                        )
                    _require_same_source_parent(
                        root_descriptor, member, parent_descriptor
                    )
                    continue

                if stat.S_ISLNK(metadata.st_mode):
                    try:
                        target = os.readlink(leaf, dir_fd=parent_descriptor)
                        after = os.stat(
                            leaf, dir_fd=parent_descriptor, follow_symlinks=False
                        )
                        repeated_target = os.readlink(
                            leaf, dir_fd=parent_descriptor
                        )
                    except OSError as error:
                        raise SourceSealError(
                            f"workspace symlink changed while inspected: {relative}"
                        ) from error
                    if (
                        not stat.S_ISLNK(after.st_mode)
                        or _stable_metadata_changed(metadata, after)
                        or repeated_target != target
                    ):
                        raise SourceSealError(
                            f"workspace symlink changed while inspected: {relative}"
                        )
                    hasher.update(
                        struct.pack(">I", stat.S_IMODE(metadata.st_mode))
                    )
                    hasher.update(b"L")
                    _frame(hasher, os.fsencode(target))
                elif stat.S_ISREG(metadata.st_mode):
                    with _stable_regular_reader_at(
                        parent_descriptor,
                        leaf,
                        metadata,
                        maximum_size=_MAX_SOURCE_FILE_BYTES,
                        label=f"workspace source {relative}",
                    ) as (source, stable_metadata):
                        hasher.update(
                            struct.pack(
                                ">I", stat.S_IMODE(stable_metadata.st_mode)
                            )
                        )
                        hasher.update(b"F")
                        hasher.update(struct.pack(">Q", stable_metadata.st_size))
                        while chunk := source.read(_COPY_CHUNK_BYTES):
                            hasher.update(chunk)
                            if relative == observed_regular_path:
                                assert observed_digest is not None
                                observed_digest.update(chunk)
                        if relative == observed_regular_path:
                            observed = True
                elif stat.S_ISDIR(metadata.st_mode):
                    # Gitlinks/submodules appear as directory entries in the parent.
                    after = os.stat(
                        leaf, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISDIR(after.st_mode)
                        or _stable_metadata_changed(metadata, after)
                    ):
                        raise SourceSealError(
                            f"workspace directory changed while inspected: {relative}"
                        )
                    hasher.update(
                        struct.pack(">I", stat.S_IMODE(metadata.st_mode))
                    )
                    hasher.update(b"G")
                else:
                    after = os.stat(
                        leaf, dir_fd=parent_descriptor, follow_symlinks=False
                    )
                    if _stable_metadata_changed(metadata, after):
                        raise SourceSealError(
                            f"workspace special entry changed while inspected: {relative}"
                        )
                    hasher.update(
                        struct.pack(">I", stat.S_IMODE(metadata.st_mode))
                    )
                    hasher.update(b"O")
                _require_same_source_parent(
                    root_descriptor, member, parent_descriptor
                )
            finally:
                os.close(parent_descriptor)
        root_after = os.fstat(root_descriptor)
        try:
            root_path_after = root.lstat()
        except OSError as error:
            raise SourceSealError("workspace root changed while inspected") from error
        if (
            _stable_metadata_changed(root_before, root_after)
            or _stable_metadata_changed(root_before, root_path_after)
        ):
            raise SourceSealError("workspace root changed while inspected")
    finally:
        os.close(root_descriptor)
    return (
        hasher.hexdigest(),
        observed_digest.hexdigest() if observed and observed_digest else None,
    )


def _manifest_for_paths(root: Path, paths: Iterable[str]) -> str:
    return _manifest_snapshot_for_paths(root, paths)[0]


def _descriptor_source_manifest_supported() -> bool:
    """Return whether the strict descriptor-relative manifest walk is available."""

    supported = getattr(os, "supports_dir_fd", ())
    return (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and all(function in supported for function in (os.open, os.stat, os.readlink))
    )


def _git_config_bool(root: Path, name: str) -> bool | None:
    """Read one optional repository-local Git boolean without ambient config."""

    result = subprocess.run(
        _git_command(root, "config", "--type=bool", "--get", name),
        cwd=root,
        check=False,
        env=_git_read_only_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return None
    if result.returncode != 0:
        raise RuntimeError(f"git could not read {name}: {result.stderr.strip()}")
    value = result.stdout.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    raise RuntimeError(f"git returned a malformed boolean for {name}")


def _portable_source_member_path(
    root: Path, member: bytes
) -> tuple[Path, list[tuple[Path, os.stat_result]]]:
    """Resolve one member while rejecting symlink or reparse-point parents."""

    current = root
    parents = []
    for component in member.split(b"/")[:-1]:
        current /= os.fsdecode(component)
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SourceSealError(
                "source member has a missing or replaced parent"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_reparse_tag", 0))
        ):
            raise SourceSealError(
                "source member has a non-directory, symlink, or reparse-point parent"
            )
        parents.append((current, metadata))
    return current / os.fsdecode(member.rsplit(b"/", 1)[-1]), parents


def _require_same_portable_source_parents(
    parents: Iterable[tuple[Path, os.stat_result]],
) -> None:
    """Require every pathname parent to retain its inspected identity."""

    for path, expected in parents:
        try:
            repeated = path.lstat()
        except OSError as error:
            raise SourceSealError(
                "workspace source parent disappeared while inspected"
            ) from error
        if (
            not stat.S_ISDIR(repeated.st_mode)
            or stat.S_ISLNK(repeated.st_mode)
            or bool(getattr(repeated, "st_reparse_tag", 0))
            or _stable_metadata_changed(expected, repeated)
        ):
            raise SourceSealError("workspace source parent changed while inspected")


def _portable_clean_index_manifest_snapshot(
    root: Path,
    entries: Iterable[tuple[bytes, str, str]],
) -> str:
    """Hash one clean stage-zero index through portable pathname operations.

    Windows lacks Python's descriptor-relative ``dir_fd`` APIs.  A clean index
    nevertheless supplies canonical file kinds and modes, while raw worktree
    bytes can still be opened and authenticated against every staged Git blob.
    This keeps the digest identical to a fresh POSIX checkout without weakening
    the descriptor-relative source-seal implementation.
    """

    algorithm = _git_stdout(root, "rev-parse", "--show-object-format")
    expected_oid_length = (
        40 if algorithm == "sha1" else 64 if algorithm == "sha256" else 0
    )
    if not expected_oid_length:
        raise RuntimeError(f"unsupported Git object format: {algorithm}")
    windows_checkout = _windows_host_semantics()
    materialized_symlinks = (
        windows_checkout or _git_config_bool(root, "core.symlinks") is False
    )
    honor_filemode = (
        not windows_checkout
        and _git_config_bool(root, "core.filemode") is not False
    )
    hasher = hashlib.sha256(_DOMAIN)
    root_before = root.lstat()
    if not stat.S_ISDIR(root_before.st_mode) or stat.S_ISLNK(root_before.st_mode):
        raise SourceSealError("workspace root must be a real directory")

    for member, expected_mode, expected_object_id in sorted(entries):
        _validate_source_path_bytes(member)
        relative = os.fsdecode(member)
        if (
            len(expected_object_id) != expected_oid_length
            or any(
                character not in "0123456789abcdef"
                for character in expected_object_id
            )
        ):
            raise RuntimeError("Git returned a malformed stage-zero object ID")
        _frame(hasher, member)
        path, parents = _portable_source_member_path(root, member)

        if expected_mode in {"100644", "100755"}:
            try:
                metadata = path.lstat()
            except OSError as error:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                ) from error
            if (
                not stat.S_ISREG(metadata.st_mode)
                or bool(getattr(metadata, "st_reparse_tag", 0))
                or (
                    honor_filemode
                    and bool(metadata.st_mode & 0o111)
                    != (expected_mode == "100755")
                )
            ):
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                )
            canonical_mode = 0o755 if expected_mode == "100755" else 0o644
            hasher.update(struct.pack(">I", canonical_mode))
            hasher.update(b"F")
            hasher.update(struct.pack(">Q", metadata.st_size))
            object_digest = _git_blob_hasher(algorithm, metadata.st_size)
            with _stable_regular_reader(
                path,
                maximum_size=_MAX_SOURCE_FILE_BYTES,
                label=f"workspace source {relative}",
                require_single_link=False,
            ) as (source, stable_metadata):
                if stable_metadata.st_size != metadata.st_size:
                    raise SourceSealError(
                        f"workspace source changed before it was read: {relative}"
                    )
                while chunk := source.read(_COPY_CHUNK_BYTES):
                    hasher.update(chunk)
                    object_digest.update(chunk)
            if object_digest.hexdigest() != expected_object_id:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                )
            _require_same_portable_source_parents(parents)
            continue

        if expected_mode == "120000":
            try:
                metadata = path.lstat()
            except OSError as error:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(path)
                    after = path.lstat()
                    repeated_target = os.readlink(path)
                except OSError as error:
                    raise SourceSealError(
                        f"workspace symlink changed while inspected: {relative}"
                    ) from error
                if (
                    _stable_metadata_changed(metadata, after)
                    or repeated_target != target
                ):
                    raise SourceSealError(
                        f"workspace symlink changed while inspected: {relative}"
                    )
                target_bytes = target if isinstance(target, bytes) else os.fsencode(target)
            elif (
                stat.S_ISREG(metadata.st_mode)
                and not bool(getattr(metadata, "st_reparse_tag", 0))
                and materialized_symlinks
            ):
                with _stable_regular_reader(
                    path,
                    maximum_size=_MAX_SYMLINK_TARGET_BYTES,
                    label=f"materialized workspace symlink {relative}",
                    require_single_link=False,
                ) as (source, _):
                    target_bytes = source.read(_MAX_SYMLINK_TARGET_BYTES + 1)
                if len(target_bytes) > _MAX_SYMLINK_TARGET_BYTES:
                    raise SourceSealError(
                        f"materialized workspace symlink exceeds its bound: {relative}"
                    )
            else:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                )
            object_digest = _git_blob_hasher(algorithm, len(target_bytes))
            object_digest.update(target_bytes)
            if object_digest.hexdigest() != expected_object_id:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                )
            hasher.update(struct.pack(">I", 0o777))
            hasher.update(b"L")
            _frame(hasher, target_bytes)
            _require_same_portable_source_parents(parents)
            continue

        if expected_mode == "160000":
            try:
                metadata = path.lstat()
                members = os.listdir(path)
                after = path.lstat()
            except OSError as error:
                raise DirtyReleaseSourceError(
                    f"portable clean source has tracked changes: {relative}"
                ) from error
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or bool(getattr(metadata, "st_reparse_tag", 0))
                or members
                or _stable_metadata_changed(metadata, after)
                or bool(getattr(after, "st_reparse_tag", 0))
            ):
                raise DirtyReleaseSourceError(
                    f"portable clean source gitlink must be one empty directory: {relative}"
                )
            hasher.update(struct.pack(">I", 0o755))
            hasher.update(b"G")
            _require_same_portable_source_parents(parents)
            continue

        raise RuntimeError(f"unsupported Git index mode: {expected_mode}")

    try:
        root_after = root.lstat()
    except OSError as error:
        raise SourceSealError("workspace root changed while inspected") from error
    if _stable_metadata_changed(root_before, root_after):
        raise SourceSealError("workspace root changed while inspected")
    return hasher.hexdigest()


def _portable_clean_index_manifest(root: Path) -> str:
    """Return a platform-normalized manifest for one exact clean Git index."""

    root = root.resolve()
    _reject_active_git_operations(root)
    unmerged = _git_unmerged_paths(root)
    if unmerged:
        raise UnmergedSourceError(
            "workspace contains unresolved merge entries: " + ", ".join(unmerged)
        )
    head_commit = _git_stdout(root, "rev-parse", "--verify", "HEAD^{commit}")
    staged = _git_paths(
        root,
        "diff-index",
        "--cached",
        "--name-only",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--ita-visible-in-index",
        head_commit,
        "--",
    )
    if staged:
        raise DirtyReleaseSourceError(
            "portable clean source index is not HEAD: " + ", ".join(staged)
        )
    source_paths = {os.fsencode(path) for path in _git_source_paths(root)}
    entries = _git_index_entries(root)
    index_paths = {member for member, _, _ in entries}
    if source_paths != index_paths:
        differences = sorted(source_paths ^ index_paths)
        rendered = ", ".join(os.fsdecode(path) for path in differences)
        raise DirtyReleaseSourceError(
            "portable clean source is not exactly the stage-zero index: " + rendered
        )

    manifest = _portable_clean_index_manifest_snapshot(root, entries)
    if _git_stdout(root, "rev-parse", "--verify", "HEAD^{commit}") != head_commit:
        raise DirtyReleaseSourceError(
            "portable clean source HEAD changed during manifest capture"
        )
    repeated_staged = _git_paths(
        root,
        "diff-index",
        "--cached",
        "--name-only",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--ita-visible-in-index",
        head_commit,
        "--",
    )
    if repeated_staged or _git_index_entries(root) != entries:
        raise DirtyReleaseSourceError(
            "portable clean source index changed during manifest capture"
        )
    repeated_paths = {os.fsencode(path) for path in _git_source_paths(root)}
    if repeated_paths != source_paths:
        raise DirtyReleaseSourceError(
            "portable clean source paths changed during manifest capture"
        )
    return manifest


def native_artifact_workspace_source_manifest(root: Path) -> str:
    """Return the strongest available manifest for native artifact evidence.

    Source seals keep requiring the strict Unix descriptor walk.  Native
    artifact record/verify also runs on Windows, where Python documents
    ``dir_fd`` as unavailable, so a clean-index-only portable walk is used
    there and authenticates raw bytes against every stage-zero object ID.
    """

    if _descriptor_source_manifest_supported():
        return workspace_source_manifest(root)
    return _portable_clean_index_manifest(root)


def _release_workspace_snapshot(root: Path) -> tuple[str, str]:
    """Bind the checkout manifest and tracked Cargo.lock from the same stream."""

    manifest, lock_sha256 = _manifest_snapshot_for_paths(
        root,
        _git_source_paths(root),
        observed_regular_path=_WORKSPACE_LOCKFILE,
    )
    if lock_sha256 is None:
        raise DirtyReleaseSourceError(
            f"release requires a regular workspace {_WORKSPACE_LOCKFILE}"
        )
    return manifest, lock_sha256


def workspace_source_git_state(root: Path) -> dict[str, str | None]:
    """Observe branch and reject unfinished Git operations without hashing source.

    A detached checkout is valid. HEAD changes alone do not invalidate a dirty
    development candidate whose actual source and branch remain unchanged.
    """

    root = root.resolve()
    _reject_active_git_operations(root)
    unmerged = _git_unmerged_paths(root)
    if unmerged:
        raise UnmergedSourceError(
            "workspace contains unresolved merge entries: " + ", ".join(unmerged)
        )
    result = subprocess.run(
        _git_command(root, "symbolic-ref", "--quiet", "HEAD"), cwd=root,
        env=_git_read_only_environment(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode == 1:
        branch = None
    else:
        result.check_returncode()
        branch = result.stdout.strip()
        if not branch.startswith("refs/heads/"):
            raise RuntimeError("Git did not identify one current branch")
    return {"root": str(root), "branch": branch}


def workspace_source_observation(root: Path) -> dict[str, str | None]:
    """Observe source bytes and branch at a mutable campaign boundary.

    This allows unchanged dirty source, detects persistent boundary drift and
    rejects unfinished Git operations. It is not a hermetic source seal and
    does not prove which inputs Cargo or its compiler actually consumed.
    """

    # All observations belong to this one root, even if a caller's alias moves.
    root = root.resolve()
    before = workspace_source_git_state(root)
    manifest = workspace_source_manifest(root)
    if workspace_source_git_state(root) != before:
        raise RuntimeError("workspace branch changed during source observation")
    return {**before, "workspace_source_manifest_sha256": manifest,
            "cargo_source_consumption": "not_proven"}


def workspace_source_manifest(root: Path) -> str:
    """Return the checkout source manifest rooted at ``root``."""

    root = root.resolve()
    return _manifest_for_paths(root, _git_source_paths(root))


def workspace_source_manifest_from_path_list(root: Path, path_list: Path) -> str:
    """Compute the canonical manifest in a detached context without `.git`."""

    return _manifest_for_paths(root.resolve(), read_source_path_list(path_list))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Git checkout root (defaults to this repository)",
    )
    parser.add_argument(
        "--release-identity-json",
        action="store_true",
        help="require one clean committed source and print its canonical identity",
    )
    parser.add_argument(
        "--native-artifact-manifest",
        action="store_true",
        help="print the strongest host-supported native-artifact source manifest",
    )
    parser.add_argument(
        "--write-path-list",
        type=Path,
        help="create a detached-build path list with O_EXCL and print its manifest",
    )
    parser.add_argument(
        "--path-list",
        type=Path,
        help=(
            "frozen detached-build path list; alone, compute its manifest, or "
            "use it with one source-seal mode"
        ),
    )
    parser.add_argument(
        "--require-exact-closure",
        action="store_true",
        help="with --path-list, reject every extra or unsupported detached member",
    )
    parser.add_argument(
        "--create-sealed-archive",
        type=Path,
        help="create one deterministic source seal with O_EXCL",
    )
    parser.add_argument(
        "--extract-sealed-archive",
        type=Path,
        help="validate twice and safely extract one deterministic source seal",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        help="pre-existing empty, non-symlink source-seal extraction directory",
    )
    parser.add_argument(
        "--expected-manifest",
        help="required canonical workspace manifest for a source-seal operation",
    )
    parser.add_argument(
        "--expected-archive-sha256",
        help="required sealed archive checksum for extraction",
    )
    parser.add_argument(
        "--expected-path-list-sha256",
        help="required frozen path-list checksum for extraction",
    )
    args = parser.parse_args()
    seal_modes = sum(
        value is not None
        for value in (args.create_sealed_archive, args.extract_sealed_archive)
    )
    if seal_modes > 1:
        parser.error("source-seal create and extract modes are mutually exclusive")
    if args.native_artifact_manifest and (
        args.release_identity_json
        or args.write_path_list is not None
        or args.path_list is not None
        or args.require_exact_closure
        or seal_modes
        or any(
            value is not None
            for value in (
                args.destination,
                args.expected_manifest,
                args.expected_archive_sha256,
                args.expected_path_list_sha256,
            )
        )
    ):
        parser.error("--native-artifact-manifest must be used by itself")
    if args.release_identity_json and (
        args.write_path_list is not None
        or args.path_list is not None
        or seal_modes
    ):
        parser.error(
            "--release-identity-json cannot be combined with path-list or "
            "source-seal modes"
        )
    if args.write_path_list is not None and (
        args.path_list is not None
        or args.require_exact_closure
        or seal_modes
    ):
        parser.error("--write-path-list must be used by itself")
    if args.require_exact_closure and (
        args.path_list is None or seal_modes
    ):
        parser.error(
            "--require-exact-closure requires standalone --path-list mode"
        )
    if seal_modes and (args.path_list is None or args.expected_manifest is None):
        parser.error(
            "source-seal modes require --path-list and --expected-manifest"
        )
    if args.create_sealed_archive is not None and (
        args.destination is not None
        or args.expected_archive_sha256 is not None
        or args.expected_path_list_sha256 is not None
    ):
        parser.error("source-seal creation does not accept extraction arguments")
    if args.extract_sealed_archive is not None and (
        args.destination is None
        or args.expected_archive_sha256 is None
        or args.expected_path_list_sha256 is None
    ):
        parser.error(
            "source-seal extraction requires --destination, "
            "--expected-archive-sha256, and --expected-path-list-sha256"
        )
    if seal_modes == 0 and any(
        value is not None
        for value in (
            args.destination,
            args.expected_manifest,
            args.expected_archive_sha256,
            args.expected_path_list_sha256,
        )
    ):
        parser.error("source-seal control arguments require a source-seal mode")
    try:
        if args.native_artifact_manifest:
            print(native_artifact_workspace_source_manifest(args.root))
        elif args.release_identity_json:
            print(
                json.dumps(
                    release_source_identity(args.root),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        elif args.write_path_list is not None:
            paths = _git_source_paths(args.root.resolve())
            write_source_path_list(args.write_path_list, paths)
            print(_manifest_for_paths(args.root.resolve(), paths))
        elif args.create_sealed_archive is not None:
            print(
                create_source_seal(
                    args.root,
                    args.path_list,
                    args.create_sealed_archive,
                    args.expected_manifest,
                )
            )
        elif args.extract_sealed_archive is not None:
            print(
                extract_source_seal(
                    args.extract_sealed_archive,
                    args.path_list,
                    args.destination,
                    args.expected_manifest,
                    args.expected_archive_sha256,
                    args.expected_path_list_sha256,
                )
            )
        elif args.path_list is not None:
            if args.require_exact_closure:
                print(
                    workspace_source_manifest_from_exact_path_list(
                        args.root, args.path_list
                    )
                )
            else:
                print(
                    workspace_source_manifest_from_path_list(
                        args.root, args.path_list
                    )
                )
        else:
            print(workspace_source_manifest(args.root))
    except (
        ActiveGitOperationError,
        DirtyReleaseSourceError,
        SourcePathListError,
        SourceSealError,
        UnmergedSourceError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"workspace source manifest error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
