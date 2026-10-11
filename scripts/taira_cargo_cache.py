"""Admit source-bound Cargo fingerprints without deleting compiled artifacts.

Cargo 1.93 encodes files below its target directory relative to that directory,
before considering the package root. A fingerprint from another frozen source
can consequently remain fresh forever. Inspect those paths under Cargo's own
profile locks and retain foreign local-package fingerprints outside its lookup
namespace. Registry/git artifacts and compiled outputs remain available.
Retirement stays inside one Cargo profile family: host and cross-target debug
metadata share a family, as do host and cross-target release metadata. Debug
source changes must not invalidate an already admitted release build.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import uuid

from release_artifact_contract import canonical_json_bytes, ensure_private_directory, exclusive_write_bytes


def metadata_stderr_excerpt(stderr: bytes) -> str:
    """Project a short, single-line Cargo error without terminal controls or private paths."""
    text = stderr[:8192].decode("utf-8", "replace")
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    lines = []
    for raw in text.splitlines():
        line = " ".join("".join(char if char.isprintable() else " " for char in raw).split())
        if not line:
            continue
        line = re.sub(r"(?i)\b(?:[a-z+]+)://\S+", "<url>", line)
        line = re.sub(r"(?<![\w])(?:~|/)[^\s`'\"\])}]+", "<path>", line)
        line = re.sub(
            r"(?i)\b(?:bearer\s+|(?:token|password|secret|api[_-]?key|authorization)\s*[:=]\s*)\S+",
            "<credential>", line,
        )
        lines.append(line[:240] + ("..." if len(line) > 240 else ""))
        if len(lines) == 3:
            break
    excerpt = " | ".join(lines)
    return excerpt[:512] + ("..." if len(excerpt) > 512 else "")


def dependency_paths(raw: bytes) -> list[tuple[int, Path]]:
    """Read the pinned Cargo 1.93 version-one dependency record, including EOF."""
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        if size < 0 or offset + size > len(raw):
            raise ValueError("truncated Cargo dependency record")
        value = raw[offset:offset + size]
        offset += size
        return value

    def number() -> int:
        return struct.unpack("<I", take(4))[0]

    def blob() -> bytes:
        return take(number())

    if take(6) != b"\x01\x00\x00\x00\xff\x01":
        raise ValueError("unsupported Cargo dependency record")
    paths = []
    for _ in range(number()):
        kind = take(1)[0]
        if kind not in (0, 1):
            raise ValueError("invalid Cargo dependency path kind")
        value = blob()
        if not value or b"\0" in value:
            raise ValueError("invalid Cargo dependency path")
        paths.append((kind, Path(os.fsdecode(value))))
        checksum = take(1)[0]
        if checksum == 1:
            take(8)
            blob()
        elif checksum != 0:
            raise ValueError("invalid Cargo dependency checksum flag")
    for _ in range(number()):
        blob()  # Names/values are never emitted into diagnostics.
        present = take(1)[0]
        if present == 1:
            blob()
        elif present != 0:
            raise ValueError("invalid Cargo dependency environment flag")
    if offset != len(raw):
        raise ValueError("trailing Cargo dependency record bytes")
    return paths


def local_packages(source: Path, environment: dict[str, str]) -> list[dict[str, object]]:
    """Read the offline Cargo graph with the selected source and environment."""
    try:
        result = subprocess.run(
            [environment["CARGO"], "--config", str(source / ".cargo/config.toml"),
             "metadata", "--manifest-path", str(source / "Cargo.toml"),
             "--locked", "--offline", "--format-version=1"],
            cwd="/", env=environment, stdin=subprocess.DEVNULL, capture_output=True,
            check=False, timeout=60, umask=0o077,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("offline Cargo package preflight timed out after 60s") from error
    if result.returncode != 0:
        excerpt = metadata_stderr_excerpt(result.stderr)
        detail = f"; Cargo stderr: {excerpt}" if excerpt else "; Cargo stderr was empty"
        raise ValueError(f"offline Cargo package preflight failed (exit {result.returncode}){detail}")
    return [package for package in json.loads(result.stdout)["packages"]
            if package["source"] is None]


def local_package_names(source: Path, environment: dict[str, str]) -> set[str]:
    """Select local package names for the captured-source admission path."""
    return {package["name"] for package in local_packages(source, environment)}


def local_package_roots(source: Path, environment: dict[str, str], *,
                        source_paths: set[Path]) -> dict[str, Path]:
    """Bind each local package to its canonical metadata manifest directory."""
    if not source.is_absolute() or source.resolve(strict=True) != source:
        raise ValueError("local package source must be canonical")
    if not isinstance(source_paths, set):
        raise ValueError("local package metadata requires signed regular-file paths")
    roots: dict[str, Path] = {}
    for package in local_packages(source, environment):
        name, manifest = package.get("name"), package.get("manifest_path")
        if not isinstance(name, str) or not name or not isinstance(manifest, str):
            raise ValueError("invalid local package metadata")
        path = Path(manifest)
        if (not path.is_absolute() or path.name != "Cargo.toml"
                or path.resolve(strict=True) != path or not path.is_file()
                or not path.parent.is_relative_to(source)
                or path.parent.is_relative_to(source / "target") or name in roots
                or path not in source_paths):
            raise ValueError("local package metadata has an ambiguous or foreign root")
        roots[name] = path.parent
    return roots


def checked_package_roots(source: Path, target: Path, packages: set[str],
                          package_roots: dict[str, Path]) -> dict[str, Path]:
    """Admit exactly the canonical package roots used by this preparation."""
    if (not source.is_absolute() or source.resolve(strict=True) != source
            or not target.is_absolute() or target.resolve(strict=True) != target
            or not source.is_dir() or not target.is_dir()
            or source.is_relative_to(target)
            or not isinstance(package_roots, dict) or set(package_roots) != packages):
        raise ValueError("canonical package roots differ from the selected source or packages")
    roots = dict(package_roots)
    for name, path in roots.items():
        if (not isinstance(name, str) or not name or not isinstance(path, Path)
                or not path.is_absolute() or path.resolve(strict=True) != path
                or not path.is_dir() or not path.is_relative_to(source)
                or path.is_relative_to(target) or path.is_relative_to(source / "target")):
            raise ValueError("canonical package root is outside the selected source")
    return roots


def checked_source_paths(source: Path, target: Path, source_paths: set[Path] | None) -> set[Path]:
    """Bind canonical source dependencies to selected signed regular files only."""
    if not isinstance(source_paths, set):
        raise ValueError("canonical source admission requires signed regular-file paths")
    paths = set(source_paths)
    for path in paths:
        if (not isinstance(path, Path) or not path.is_absolute()
                or path.resolve(strict=True) != path or not path.is_file()
                or not path.is_relative_to(source) or path.is_relative_to(target)
                or path.is_relative_to(source / "target")):
            raise ValueError("canonical signed source path is not a regular source file")
    return paths


def private_regular(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > maximum):
            raise ValueError("unsafe Cargo dependency record")
        raw = os.pread(fd, info.st_size + 1, 0)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(raw) != info.st_size or identity(os.fstat(fd)) != identity(info)
                or identity(path.lstat()) != identity(info)):
            raise ValueError("Cargo dependency record changed")
        return raw
    finally:
        os.close(fd)


@contextlib.contextmanager
def source_fingerprints(source: Path, target: Path, triple: str,
                        packages: set[str], *, repair: bool = True, before_retire=None,
                        package_roots: dict[str, Path] | None = None,
                        source_paths: set[Path] | None = None):
    """Hold Cargo's profile locks through admission and the caller's capture."""
    profiles = [target / profile for profile in ("debug", "release")]
    profiles += [target / triple / profile for profile in ("debug", "release")]
    profiles = [path for path in profiles if path.is_dir()]
    generated = {family: [profile / name for profile in profiles if profile.name == family
                          for name in ("build", "deps")] for family in ("debug", "release")}
    stale: set[tuple[str, str]] = set()
    directories: list[tuple[Path, str, str]] = []
    roots = (None if package_roots is None
             else checked_package_roots(source, target, packages, package_roots))
    if roots is None and source_paths is not None:
        raise ValueError("signed source paths require canonical package roots")
    signed_paths = (None if roots is None else checked_source_paths(source, target, source_paths))
    if roots is not None and any(path / "Cargo.toml" not in signed_paths for path in roots.values()):
        raise ValueError("canonical package manifest is not a selected signed regular file")
    if roots is None and not source.is_relative_to(target):
        raise ValueError("source admission requires the maintained capture below the Cargo target")
    binding_path = target / ".taira-source-fingerprint-binding.json"
    binding = (None if roots is None else canonical_json_bytes({
        "schema": "taira.canonical-source-fingerprints.v1", "source_root": str(source),
        "package_roots": {name: str(path) for name, path in sorted(roots.items())},
        "source_paths": sorted(str(path) for path in signed_paths),
    }))
    with contextlib.ExitStack() as stack:
        for profile in sorted(profiles):
            if profile.resolve() != profile:
                raise ValueError("Cargo profile must not traverse symlinks")
            fd = os.open(profile / ".cargo-lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError("unsafe Cargo profile lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
        binding_matches = (binding is None or (os.path.lexists(binding_path)
                           and private_regular(binding_path, 16 * 1024**2) == binding))
        if not binding_matches and not repair:
            raise ValueError("canonical Cargo source binding is absent or changed")
        for profile in profiles:
            family = profile.name
            fingerprints = profile / ".fingerprint"
            if not fingerprints.exists():
                continue
            if fingerprints.resolve() != fingerprints:
                raise ValueError("Cargo fingerprints must not traverse symlinks")
            for directory in sorted(fingerprints.iterdir()):
                match = re.fullmatch(r"(.+)-[0-9a-f]{16}", directory.name)
                if match is None or match[1] not in packages:
                    continue
                if directory.is_symlink() or not directory.is_dir():
                    raise ValueError("unsafe local Cargo fingerprint directory")
                name = match[1]
                directories.append((directory, name, family))
                if not binding_matches:
                    # kind=0 carries no prior package-root identity. Retire
                    # every selected local family before first adoption or a
                    # mapping switch, even if its relative paths look valid.
                    stale.add((family, name))
                    continue
                for record in directory.glob("dep-*"):
                    try:
                        paths = dependency_paths(private_regular(record, 16 * 1024**2))
                    except ValueError:
                        stale.add((family, name))
                        continue
                    for kind, path in paths:
                        if kind == 0:
                            if roots is None or path.is_absolute():
                                # Captured source is below target, so its paths
                                # must be target-relative. Canonical source uses
                                # the independently selected package root.
                                stale.add((family, name))
                                continue
                            path = (roots[name] / path).resolve()
                        else:
                            path = (target / path).resolve()
                        source_bound = path.is_relative_to(source)
                        if roots is not None:
                            # Only selected signed regular files are source.
                            # Ignored files, symlink-only targets and old captures
                            # remain foreign even inside the canonical checkout.
                            source_bound = path in signed_paths
                        if source_bound or any(path.is_relative_to(p) for p in generated[family]):
                            continue
                        stale.add((family, name))
        stale_names = sorted({name for _, name in stale})
        if stale and not repair:
            raise ValueError("foreign Cargo source fingerprints after build: "
                             + ", ".join(f"{family}/{name}" for family, name in sorted(stale)))
        if (stale or not binding_matches) and before_retire is not None:
            before_retire()
        if stale:
            parent = target / "taira-release-cache-retired"
            parent.mkdir(mode=0o700, exist_ok=True)
            if parent.resolve() != parent or stat.S_IMODE(parent.stat().st_mode) != 0o700:
                raise ValueError("unsafe Cargo fingerprint archive")
            archive = parent / uuid.uuid4().hex
            archive.mkdir(mode=0o700)
            changed_parents: set[Path] = set()
            for directory, name, family in directories:
                # A host build-script producer and its cross-target consumers
                # share the profile family, but debug and release units have
                # independent Cargo fingerprints and generated output trees.
                if (family, name) not in stale:
                    continue
                destination = archive / directory.relative_to(target)
                ensure_private_directory(destination.parent, anchor=archive)
                os.rename(directory, destination)
                for changed in (directory.parent, destination.parent):
                    while True:
                        changed_parents.add(changed)
                        if changed == target:
                            break
                        changed = changed.parent
            # Durable removal from Cargo lookup must precede the new binding.
            # Flush both rename sides and each newly created archive ancestor;
            # otherwise power loss could restore ambiguous old kind=0 records.
            for changed in sorted(changed_parents, key=lambda p: (len(p.parts), str(p)), reverse=True):
                descriptor = os.open(changed, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            print("[taira-release] retained foreign source fingerprints for "
                  + str(len(stale)) + " local package/profile families; compiled artifacts and dependency caches retained", flush=True)
        if not binding_matches:
            # Publish only after all old selected local metadata is retired,
            # while every existing Cargo profile lock is still held.
            temporary = target / (".taira-source-fingerprint-binding-" + uuid.uuid4().hex)
            exclusive_write_bytes(temporary, binding, mode=0o600)
            os.replace(temporary, binding_path)
            descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        yield stale_names


def admit_source_fingerprints(source: Path, target: Path, triple: str,
                              packages: set[str], *, repair: bool = True, before_retire=None,
                              package_roots: dict[str, Path] | None = None,
                              source_paths: set[Path] | None = None) -> list[str]:
    """Retire only foreign local-package metadata; reject it after a build."""
    with source_fingerprints(source, target, triple, packages, repair=repair,
                             before_retire=before_retire, package_roots=package_roots,
                             source_paths=source_paths) as stale:
        return stale
