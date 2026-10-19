from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import release_artifact_contract as contract


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Keep custody fixtures below the checkout's owned test output directory.

    These contracts reject every shared writable ancestor, so pytest's ambient
    system temporary root cannot supply their positive and race fixtures.
    TemporaryDirectory removes only this test's exclusively created directory.
    Owned setup uses 077; test bodies use ordinary 022 so explicit safe 0755
    anchors and 0644 artifacts retain their intended coverage. The caller mask
    is restored after the test, including failures during creation or cleanup.
    """
    original_umask = os.umask(0o077)
    try:
        parent = Path(__file__).resolve().parents[2]
        for component in ("target", "unit-tests", "script-tests"):
            parent /= component
            parent.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="release-artifact-contract-", dir=parent) as directory:
            os.umask(0o022)
            yield Path(directory).resolve()
    finally:
        os.umask(original_umask)


@pytest.mark.parametrize(
    "raw",
    ("", "-1", "+1", "01", " 1", "1 ", "1.0", str(contract.MAX_SOURCE_DATE_EPOCH + 1)),
)
def test_source_date_epoch_rejects_noncanonical_or_unsupported_values(
    raw: str,
) -> None:
    with pytest.raises(contract.ReleaseArtifactError):
        contract.parse_source_date_epoch(raw)


def test_source_date_epoch_renders_canonical_rfc3339() -> None:
    assert contract.parse_source_date_epoch("0") == 0
    assert contract.format_source_date_epoch(0) == "1970-01-01T00:00:00Z"
    assert contract.format_source_date_epoch(1) == "1970-01-01T00:00:01Z"


def test_private_directory_tree_ignores_permissive_umask_and_reuses_exact_owner(tmp_path: Path) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o755)
    anchor_mode = stat.S_IMODE(anchor.stat().st_mode)
    assert anchor_mode == 0o755
    leaf = anchor / "one" / "two" / "three"
    original_umask = os.umask(0o002)
    try:
        assert contract.ensure_private_directory(leaf, anchor=anchor) == leaf
        assert os.umask(0o002) == 0o002
        before = [(path, path.stat().st_ino, path.stat().st_mode) for path in
                  (anchor / "one", anchor / "one/two", leaf)]
        assert all(stat.S_IMODE(mode) == 0o700 for _, _, mode in before)
        assert contract.ensure_private_directory(leaf, anchor=anchor) == leaf
        assert [(path, path.stat().st_ino, path.stat().st_mode) for path, _, _ in before] == before
        assert stat.S_IMODE(anchor.stat().st_mode) == anchor_mode
    finally:
        os.umask(original_umask)


@pytest.mark.parametrize("mode", (0o755, 0o775))
def test_private_directory_tree_refuses_existing_unsafe_owner_without_repair(tmp_path: Path, mode: int) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    unsafe = anchor / "existing"
    unsafe.mkdir(mode=mode)
    unsafe.chmod(mode)
    with pytest.raises(contract.ReleaseArtifactError):
        contract.ensure_private_directory(unsafe / "child", anchor=anchor)
    assert stat.S_IMODE(unsafe.stat().st_mode) == mode
    assert not (unsafe / "child").exists()


def test_private_directory_tree_refuses_links_and_missing_or_foreign_anchors(tmp_path: Path) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    (anchor / "link").symlink_to(other, target_is_directory=True)
    for path, selected in ((anchor / "link/child", anchor), (other / "child", anchor),
                           (tmp_path / "missing/child", tmp_path / "missing")):
        with pytest.raises(contract.ReleaseArtifactError):
            contract.ensure_private_directory(path, anchor=selected)
    assert list(other.iterdir()) == []
    assert not (tmp_path / "missing").exists()


def test_private_directory_anchor_mode_change_before_open_is_rejected(tmp_path: Path, monkeypatch) -> None:
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o755)
    real_open = contract.os.open
    def change_before_open(path, flags, *args, **kwargs):
        if path == "anchor" and "dir_fd" in kwargs:
            anchor.chmod(0o775)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(contract.os, "open", change_before_open)
    with pytest.raises(contract.ReleaseArtifactError, match="custody changed"):
        contract.ensure_private_directory(anchor / "child", anchor=anchor)
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o775
    assert not (anchor / "child").exists()


def test_stable_hash_rejects_hardlinked_files(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    artifact = root / "artifact.bin"
    artifact.write_bytes(b"bytes")
    os.link(artifact, root / "copy.bin")
    with pytest.raises(contract.ReleaseArtifactError, match="exactly one hard link"):
        contract.stable_hash_relative(root, "artifact.bin")


def test_create_fresh_directory_rejects_links_and_existing_outputs(
    tmp_path: Path,
) -> None:
    created = contract.create_fresh_directory(tmp_path / "new" / "release")
    assert created == tmp_path / "new" / "release"
    assert created.is_dir()
    assert created.stat().st_mode & 0o777 == 0o755
    with pytest.raises(contract.ReleaseArtifactError, match="already exists"):
        contract.create_fresh_directory(created)

    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(tmp_path / "new", target_is_directory=True)
    with pytest.raises(contract.ReleaseArtifactError, match="not a directory"):
        contract.create_fresh_directory(linked_parent / "other")


def test_create_fresh_directory_rejects_writable_ancestor(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o775)
    with pytest.raises(contract.ReleaseArtifactError, match="group- or world-writable"):
        contract.create_fresh_directory(unsafe / "release")


def test_json_loader_rejects_duplicate_keys() -> None:
    with pytest.raises(contract.ReleaseArtifactError, match="duplicate JSON object key"):
        contract.load_json_object(b'{"a":1,"a":2}', "fixture")


def test_exclusive_output_scrubs_hardlink_race(tmp_path: Path) -> None:
    output = tmp_path / "output.bin"
    leaked = tmp_path / "hardlink.bin"
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was written"):
        with contract.exclusive_output_fd(output) as descriptor:
            os.write(descriptor, b"release-secret")
            os.link(output, leaked)
    assert not output.exists()
    assert leaked.read_bytes() == b""


def test_exclusive_output_rejects_target_substitution_without_deleting_it(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output.bin"
    moved = tmp_path / "moved.bin"
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was written"):
        with contract.exclusive_output_fd(output) as descriptor:
            os.write(descriptor, b"release-secret")
            output.rename(moved)
            output.write_bytes(b"attacker")
    assert output.read_bytes() == b"attacker"
    assert moved.read_bytes() == b""


def test_exclusive_output_rejects_parent_substitution(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    output = parent / "output.bin"
    moved_parent = tmp_path / "moved-parent"
    with pytest.raises(contract.ReleaseArtifactError, match="directory .* was replaced"):
        with contract.exclusive_output_fd(output) as descriptor:
            os.write(descriptor, b"release-secret")
            parent.rename(moved_parent)
            parent.mkdir()
    assert not (moved_parent / "output.bin").exists()
    assert list(parent.iterdir()) == []


def test_exclusive_output_rejects_permission_mutation(tmp_path: Path) -> None:
    output = tmp_path / "output.bin"
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was written"):
        with contract.exclusive_output_fd(output, mode=0o644) as descriptor:
            os.write(descriptor, b"release-secret")
            output.chmod(0o666)
    assert not output.exists()


def test_stable_read_rejects_path_replacement_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    artifact = root / "artifact.bin"
    artifact.write_bytes(b"a" * (2 * 1024 * 1024))
    replaced = root / "replaced.bin"
    original_read = contract.os.read
    raced = False

    def replace_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        chunk = original_read(descriptor, size)
        if chunk and not raced:
            raced = True
            artifact.rename(replaced)
            artifact.write_bytes(b"b")
        return chunk

    monkeypatch.setattr(contract.os, "read", replace_after_first_read)
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was read"):
        contract.stable_hash_relative(root, "artifact.bin")


def test_release_manifest_reader_requires_exact_canonical_bytes() -> None:
    manifest = {
        "schema": contract.RELEASE_MANIFEST_SCHEMA,
        "schema_version": contract.RELEASE_MANIFEST_SCHEMA_VERSION,
        "version": "1.0.0",
        "commit": "a" * 40,
        "source_date_epoch": 0,
        "built_at": "1970-01-01T00:00:00Z",
        "os": "linux",
        "arch": "x86_64",
        "artifacts": [
            {
                "profile": "iroha3",
                "target": "x86_64-unknown-linux-gnu",
                "kind": "bundle",
                "format": "tar.zst",
                "path": "iroha3.tar.zst",
                "sha256": "b" * 64,
                "size": 1,
            }
        ],
    }
    canonical = contract.canonical_json_bytes(manifest)
    assert contract.load_canonical_release_manifest(canonical) == manifest
    compact = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(contract.ReleaseArtifactError, match="not in canonical"):
        contract.load_canonical_release_manifest(compact)


def test_stable_open_rechecks_consumed_content_when_timestamps_collide(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    original = b"original content"
    artifact.write_bytes(original)
    expected = contract.stable_hash_path(artifact)
    real_stat, real_fstat = os.stat, os.fstat

    def colliding_times(info):
        if (info.st_dev, info.st_ino) != (expected.device, expected.inode):
            return info
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**(fields | {
            "st_mtime_ns": expected.mtime_ns,
            "st_ctime_ns": expected.ctime_ns,
        }))

    # Deterministically model an allowed filesystem timestamp collision; preserve
    # every other identity field. The original source bytes are already consumed.
    monkeypatch.setattr(contract.os, "stat", lambda *a, **k: colliding_times(real_stat(*a, **k)))
    monkeypatch.setattr(contract.os, "fstat", lambda *a, **k: colliding_times(real_fstat(*a, **k)))
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was streamed"):
        with contract.stable_open_relative(tmp_path, artifact.name, expected=expected) as fd:
            assert os.read(fd, expected.size) == original
            artifact.write_bytes(b"x" * expected.size)
            assert artifact.stat().st_mtime_ns == expected.mtime_ns
            assert artifact.stat().st_ctime_ns == expected.ctime_ns
    assert artifact.read_bytes() != original


def test_stable_open_final_hash_preserves_offset_and_bounds_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact.bin"
    payload = b"a" * (2 * 1024 * 1024 + 17)
    artifact.write_bytes(payload)
    expected = contract.stable_hash_path(artifact)
    original_pread = os.pread
    requests = []

    def bounded_read(fd: int, size: int, offset: int) -> bytes:
        assert os.lseek(fd, 0, os.SEEK_CUR) == 3
        chunk = original_pread(fd, size, offset)
        assert os.lseek(fd, 0, os.SEEK_CUR) == 3
        requests.append((size, offset, len(chunk)))
        return chunk

    monkeypatch.setattr(contract.os, "pread", bounded_read)
    with contract.stable_open_relative(tmp_path, artifact.name, expected=expected) as fd:
        assert os.read(fd, 3) == payload[:3]
    assert all(0 < size <= 1024 * 1024 for size, _, _ in requests)
    assert sum(length for _, _, length in requests) == expected.size
    assert requests[-1] == (1, expected.size, 0)
    assert sum(size for size, _, _ in requests) == expected.size + 1


@pytest.mark.parametrize("replacement", (b"", b"short", b"x" * 64))
def test_stable_open_rejects_truncation_or_growth_with_bounded_final_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bytes,
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"original content")
    expected = contract.stable_hash_path(artifact)
    original_pread = os.pread
    requests = []

    def bounded_read(fd: int, size: int, offset: int) -> bytes:
        requests.append((size, offset))
        return original_pread(fd, size, offset)

    monkeypatch.setattr(contract.os, "pread", bounded_read)
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was streamed"):
        with contract.stable_open_relative(tmp_path, artifact.name, expected=expected) as fd:
            assert os.read(fd, expected.size) == b"original content"
            artifact.write_bytes(replacement)
    assert requests
    assert all(0 < size <= 1024 * 1024 and offset + size <= expected.size + 1
               for size, offset in requests)
    if len(replacement) > expected.size:
        assert sum(size for size, _ in requests) == expected.size + 1


@pytest.mark.parametrize("mutation", ("mode", "path"))
def test_stable_open_keeps_metadata_and_path_checks_after_final_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    artifact = tmp_path / "artifact.bin"
    payload = b"original content"
    artifact.write_bytes(payload)
    expected = contract.stable_hash_path(artifact)
    original_pread = os.pread
    changed = False

    def mutate_after_hash(fd: int, size: int, offset: int) -> bytes:
        nonlocal changed
        chunk = original_pread(fd, size, offset)
        if offset == expected.size and size == 1 and not chunk:
            changed = True
            if mutation == "mode":
                artifact.chmod(0o400)
            else:
                replacement = artifact.with_suffix(".next")
                replacement.write_bytes(payload)
                replacement.chmod(expected.mode)
                os.replace(replacement, artifact)
        return chunk

    monkeypatch.setattr(contract.os, "pread", mutate_after_hash)
    with pytest.raises(contract.ReleaseArtifactError, match="changed while it was streamed"):
        with contract.stable_open_relative(tmp_path, artifact.name, expected=expected) as fd:
            assert os.read(fd, expected.size) == payload
    assert changed


def test_directory_custody_rejects_sticky_shared_ancestor_without_repair(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o1777)
    anchor = shared / "private-anchor"
    anchor.mkdir(mode=0o700)
    for create in (
        lambda: contract.ensure_private_directory(anchor / "private-child", anchor=anchor),
        lambda: contract.create_fresh_directory(anchor / "fresh-child"),
    ):
        with pytest.raises(contract.ReleaseArtifactError, match="group- or world-writable"):
            create()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o1777
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o700
    assert list(anchor.iterdir()) == []


@pytest.mark.parametrize("target,machine", [("aarch64-unknown-linux-gnu", 183), ("x86_64-unknown-linux-gnu", 62)])
def test_linux_elf_header_is_bound_to_exact_target_class_endian_and_machine(target, machine):
    """Accept a requested native ELF, never another target or malformed header."""
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    assert contract.linux_gnu_elf_matches_target(header, target)
    header[16] = 3
    assert contract.linux_gnu_elf_matches_target(header, target)
    other = next(value for value in contract.LINUX_GNU_TARGETS if value != target)
    assert not contract.linux_gnu_elf_matches_target(header, other)
    for index, byte in [(0, 0), (4, 1), (5, 2), (6, 0), (16, 1), (17, 1), (18, 0), (19, 1)]:
        wrong = header.copy()
        wrong[index] = byte
        assert not contract.linux_gnu_elf_matches_target(wrong, target), (index, byte)
    for length in range(20):
        assert not contract.linux_gnu_elf_matches_target(header[:length], target)
    for unsupported in ["", None, [], "x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu.2.17", "aarch64-apple-darwin"]:
        assert not contract.linux_gnu_elf_matches_target(header, unsupported)
