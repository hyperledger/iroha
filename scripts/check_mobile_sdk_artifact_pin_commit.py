#!/usr/bin/env python3
"""Validate the one-commit mechanical Apple artifact-pin exception."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SHA1 = re.compile(r"[0-9a-f]{40}")
LOADER_PATH = "IrohaSwift/Sources/IrohaSwift/NativeBridge.swift"
PROSPECTIVE_LOADER_NAME = ".NoritoBridge.prospective.NativeBridge.swift"
OPTIONAL_ARTIFACT_METADATA_PATHS = frozenset(
    {
        "dist/NoritoBridge.artifacts.json",
        "dist/NoritoBridge.xcframework/NoritoBridge.artifacts.json",
    }
)


class PinCommitError(RuntimeError):
    """The checkout is not the artifact source or its mechanical pin child."""


def _load_source_seal_module():
    script = Path(__file__).resolve(strict=True).with_name(
        "norito_bridge_source_seal.py"
    )
    spec = importlib.util.spec_from_file_location("norito_bridge_source_seal", script)
    if spec is None or spec.loader is None:
        raise PinCommitError("unable to load the NoritoBridge source-seal rules")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
    }


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=root,
            env=_git_environment(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise PinCommitError(f"Git could not authenticate the pin commit: {detail}") from error


def _canonical_commit(root: Path, revision: str) -> str:
    value = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode(
        "ascii"
    ).strip()
    if SHA1.fullmatch(value) is None:
        raise PinCommitError("Git returned a non-canonical commit identifier")
    return value


def _changed_paths(root: Path, parent: str, head: str) -> dict[str, str]:
    output = _git(
        root,
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "--no-renames",
        "-r",
        "-z",
        parent,
        head,
    )
    fields = [field.decode("utf-8") for field in output.split(b"\0") if field]
    if len(fields) % 2 != 0:
        raise PinCommitError("Git returned a malformed pin-commit path inventory")
    return dict(zip(fields[1::2], fields[0::2]))


def _mechanical_pin_parent(root: Path, commit: str) -> str | None:
    """Return the parent when ``commit`` is an exact mechanical pin child."""

    ancestry = _git(root, "rev-list", "--parents", "-n", "1", commit).decode(
        "ascii"
    ).split()
    if len(ancestry) != 2 or ancestry[0] != commit:
        return None
    parent = ancestry[1]
    changed = _changed_paths(root, parent, commit)
    allowed = OPTIONAL_ARTIFACT_METADATA_PATHS | {LOADER_PATH}
    if set(changed) - allowed or changed.get(LOADER_PATH) != "M":
        return None
    if any(
        changed[path] not in {"A", "M", "T"}
        for path in OPTIONAL_ARTIFACT_METADATA_PATHS & changed.keys()
    ):
        return None

    parent_loader = _git(root, "show", f"{parent}:{LOADER_PATH}")
    child_loader = _git(root, "show", f"{commit}:{LOADER_PATH}")
    if parent_loader == child_loader:
        return None
    source_seal = _load_source_seal_module()
    try:
        normalized_parent = source_seal.normalize_swift_native_bridge_hash_pins(
            parent_loader
        )
        normalized_child = source_seal.normalize_swift_native_bridge_hash_pins(
            child_loader
        )
    except RuntimeError:
        return None
    return parent if normalized_parent == normalized_child else None


def embedded_source_commit(root: Path, revision: str = "HEAD") -> str:
    """Return the real Git commit embedded in one Apple bridge build.

    A rigorously mechanical fallback-pin child embeds its exact parent so the
    pin literals do not recursively change the static-library hashes they
    authenticate. Every other commit embeds its own identity.
    """

    root = root.resolve(strict=True)
    commit = _canonical_commit(root, revision)
    return _mechanical_pin_parent(root, commit) or commit


def validate_pin_relationship(root: Path, manifest_commit: str) -> str:
    """Return ``direct`` or ``pin-parent`` for an authenticated relationship."""

    root = root.resolve(strict=True)
    if SHA1.fullmatch(manifest_commit) is None:
        raise PinCommitError("artifact manifest source_commit is not canonical")
    head = _canonical_commit(root, "HEAD")
    if manifest_commit == head:
        return "direct"

    ancestry = _git(root, "rev-list", "--parents", "-n", "1", head).decode(
        "ascii"
    ).split()
    if len(ancestry) != 2 or ancestry[0] != head or ancestry[1] != manifest_commit:
        raise PinCommitError(
            "artifact source commit must be HEAD or the exact parent of a non-merge "
            "pin-only HEAD"
        )

    changed = _changed_paths(root, manifest_commit, head)
    allowed = OPTIONAL_ARTIFACT_METADATA_PATHS | {LOADER_PATH}
    unexpected = sorted(set(changed) - allowed)
    if unexpected:
        raise PinCommitError(
            "pin-only HEAD changes non-artifact source paths: " + ", ".join(unexpected)
        )
    if changed.get(LOADER_PATH) != "M":
        raise PinCommitError(
            "pin-only HEAD must modify the existing Swift native bridge loader"
        )
    for path in OPTIONAL_ARTIFACT_METADATA_PATHS & changed.keys():
        if changed[path] not in {"A", "M", "T"}:
            raise PinCommitError(
                f"pin-only HEAD has unsupported artifact metadata change {changed[path]}: {path}"
            )

    parent_loader = _git(root, "show", f"{manifest_commit}:{LOADER_PATH}")
    head_loader = _git(root, "show", f"{head}:{LOADER_PATH}")
    source_seal = _load_source_seal_module()
    if parent_loader == head_loader:
        raise PinCommitError("pin-only HEAD does not change any fallback digest")
    try:
        normalized_parent = source_seal.normalize_swift_native_bridge_hash_pins(
            parent_loader
        )
        normalized_head = source_seal.normalize_swift_native_bridge_hash_pins(
            head_loader
        )
    except RuntimeError as error:
        raise PinCommitError(str(error)) from error
    if normalized_parent != normalized_head:
        raise PinCommitError(
            "pin-only HEAD changes Swift loader content beyond the three fallback digests"
        )
    return "pin-parent"


def validate_prospective_loader(
    root: Path,
    manifest_commit: str,
    artifact_root: Path,
    prospective_loader: Path,
) -> str:
    """Authenticate a builder-private loader containing the not-yet-committed pins."""

    root = root.resolve(strict=True)
    if SHA1.fullmatch(manifest_commit) is None:
        raise PinCommitError("artifact manifest source_commit is not canonical")
    current_commit = _canonical_commit(root, "HEAD")
    if (current_commit != manifest_commit
            and not _load_source_seal_module().record_demo_source_drift(
                "prospective Apple loader selected commit", manifest_commit, current_commit)):
        raise PinCommitError(
            "prospective loader validation requires an artifact built directly from HEAD"
        )

    artifact_root = artifact_root.resolve(strict=True)
    raw_loader = prospective_loader
    if not raw_loader.is_absolute():
        raise PinCommitError("prospective loader path must be absolute")
    prospective_loader = raw_loader.resolve(strict=True)
    if prospective_loader != raw_loader or prospective_loader.parent != artifact_root:
        raise PinCommitError(
            "prospective loader must be a canonical direct child of the staged artifact root"
        )
    if prospective_loader.name != PROSPECTIVE_LOADER_NAME:
        raise PinCommitError("prospective loader has a non-canonical file name")
    metadata = prospective_loader.lstat()
    if not stat.S_ISREG(metadata.st_mode) or prospective_loader.is_symlink():
        raise PinCommitError("prospective loader must be a non-symbolic regular file")
    if not artifact_root.name.startswith(".NoritoBridge.publish."):
        raise PinCommitError("prospective loader is not inside a private builder stage")

    checked_in_loader = root / LOADER_PATH
    checked_in_contents = checked_in_loader.read_bytes()
    prospective_contents = prospective_loader.read_bytes()
    source_seal = _load_source_seal_module()
    try:
        normalized_checked_in = source_seal.normalize_swift_native_bridge_hash_pins(
            checked_in_contents
        )
        normalized_prospective = source_seal.normalize_swift_native_bridge_hash_pins(
            prospective_contents
        )
    except RuntimeError as error:
        raise PinCommitError(str(error)) from error
    if normalized_checked_in != normalized_prospective:
        raise PinCommitError(
            "prospective loader changes Swift loader content beyond the three fallback digests"
        )
    return "prospective"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest-commit")
    mode.add_argument("--print-embedded-source-commit", action="store_true")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--prospective-loader", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.print_embedded_source_commit:
            if arguments.artifact_root is not None or arguments.prospective_loader is not None:
                parser.error(
                    "--print-embedded-source-commit does not accept artifact paths"
                )
            result = embedded_source_commit(arguments.root)
        elif arguments.artifact_root is None and arguments.prospective_loader is None:
            result = validate_pin_relationship(arguments.root, arguments.manifest_commit)
        elif (
            arguments.artifact_root is not None
            and arguments.prospective_loader is not None
        ):
            result = validate_prospective_loader(
                arguments.root,
                arguments.manifest_commit,
                arguments.artifact_root,
                arguments.prospective_loader,
            )
        else:
            parser.error(
                "--artifact-root and --prospective-loader must be provided together"
            )
        print(result)
    except (OSError, PinCommitError) as error:
        print(f"[-] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
