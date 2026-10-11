"""Adversarial tests for independent release-source mirroring and sealing."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

ROOT_DIR = Path(__file__).resolve().parents[2]
SCRIPT = ROOT_DIR / "scripts" / "seal_workspace_source.py"
MANIFEST_SCRIPT = ROOT_DIR / "scripts" / "compute_workspace_source_manifest.py"


def load_module():
    spec = importlib.util.spec_from_file_location("seal_workspace_source", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_manifest_module():
    spec = importlib.util.spec_from_file_location(
        "workspace_source_manifest_for_seal", MANIFEST_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seal_preserves_executable_identity_and_writable_output(tmp_path: Path) -> None:
    module = load_module()
    source = tmp_path / "source"
    nested = source / "scripts"
    output = source / "target"
    nested.mkdir(parents=True)
    output.mkdir()
    regular = nested / "model.tla"
    executable = nested / "runner.sh"
    dist = source / "dist"
    dist.mkdir()
    (dist / ".gitkeep").write_text("", encoding="utf-8")
    dangling_internal = source / "NoritoBridge.xcframework"
    dangling_internal.symlink_to("dist/NoritoBridge.xcframework")
    regular.write_text("---- MODULE Model ----\n", encoding="utf-8")
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)

    module.seal_source_tree(source)
    module.verify_source_tree_sealed(source)

    assert stat.S_IMODE(regular.stat().st_mode) == 0o444
    assert stat.S_IMODE(executable.stat().st_mode) == 0o555
    assert stat.S_IMODE(nested.stat().st_mode) == 0o555
    assert stat.S_IMODE(source.stat().st_mode) == 0o555
    assert dangling_internal.is_symlink()
    assert not dangling_internal.exists()
    assert stat.S_IMODE(output.stat().st_mode) & 0o200
    (output / "evidence.log").write_text("passed\n", encoding="utf-8")

    module.unseal_source_tree(source)
    regular.write_text("restored\n", encoding="utf-8")


def test_ordinary_transient_edit_cannot_start_against_cooperatively_sealed_source(
    tmp_path: Path,
) -> None:
    module = load_module()
    source = tmp_path / "source"
    source.mkdir()
    tracked = source / "consensus.rs"
    original = "pub fn decide() {}\n"
    tracked.write_text(original, encoding="utf-8")
    module.seal_source_tree(source)

    try:
        assert stat.S_IMODE(tracked.stat().st_mode) & 0o222 == 0
        if os.name == "posix" and os.geteuid() != 0:
            with pytest.raises(PermissionError):
                tracked.write_text("malicious transient edit\n", encoding="utf-8")
        assert tracked.read_text(encoding="utf-8") == original
        module.verify_source_tree_sealed(source)
    finally:
        module.unseal_source_tree(source)


def test_no_writable_paths_seals_the_entire_source_tree(tmp_path: Path) -> None:
    module = load_module()
    source = tmp_path / "source"
    target = source / "target"
    target.mkdir(parents=True)
    output = target / "unexpected.log"
    output.write_text("not release evidence\n", encoding="utf-8")

    module.seal_source_tree(source, ())
    try:
        module.verify_source_tree_sealed(source, ())
        assert stat.S_IMODE(source.stat().st_mode) == 0o555
        assert stat.S_IMODE(target.stat().st_mode) == 0o555
        assert stat.S_IMODE(output.stat().st_mode) == 0o444
    finally:
        module.unseal_source_tree(source)


def test_no_writable_paths_cli_is_mutually_exclusive_with_writable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--seal",
            "--root",
            str(source),
            "--no-writable-paths",
            "--writable",
            "target",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 2


def test_independent_mirror_reproduces_identity_without_mutating_candidate_git(
    tmp_path: Path,
) -> None:
    seal = load_module()
    manifest = load_manifest_module()
    repository = tmp_path / "repository"
    sealed = tmp_path / "sealed"
    output = tmp_path / "output"
    repository.mkdir()
    output.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "seal-test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Seal Test"],
        cwd=repository,
        check=True,
    )
    (repository / ".gitignore").write_text("Cargo.lock\ntarget\n", encoding="utf-8")
    runner = repository / "runner.sh"
    runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    runner.chmod(0o755)
    subprocess.run(
        ["git", "add", ".gitignore", "runner.sh"], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "commit", "-qm", "sealed release fixture"],
        cwd=repository,
        check=True,
    )
    (repository / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    candidate = manifest.release_source_identity(repository)
    candidate_git = repository / ".git"

    def git_file_state() -> dict[str, tuple[int, int, int, int, bytes]]:
        return {
            path.relative_to(candidate_git).as_posix(): (
                path.lstat().st_mode,
                path.lstat().st_size,
                path.lstat().st_mtime_ns,
                path.lstat().st_ctime_ns,
                path.read_bytes(),
            )
            for path in candidate_git.rglob("*")
            if path.is_file() and not path.is_symlink()
        }

    original_git_state = git_file_state()

    subprocess.run(
        [
            "git",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            str(repository),
            str(sealed),
        ],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    try:
        subprocess.run(
            ["git", "checkout", "--detach", candidate["head_commit"]],
            cwd=sealed,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "remote", "remove", "origin"],
            cwd=sealed,
            check=True,
        )
        assert not (sealed / ".git/objects/info/alternates").exists()
        for mirror_object in (sealed / ".git/objects").rglob("*"):
            if not mirror_object.is_file() or mirror_object.is_symlink():
                continue
            original_object = (
                candidate_git / "objects" / mirror_object.relative_to(sealed / ".git/objects")
            )
            if original_object.is_file():
                assert (mirror_object.stat().st_dev, mirror_object.stat().st_ino) != (
                    original_object.stat().st_dev,
                    original_object.stat().st_ino,
                )
        (sealed / "Cargo.lock").write_bytes((repository / "Cargo.lock").read_bytes())
        # Git reproduces executable identity, while the seal also authenticates full modes.
        # Restore each original mode explicitly when a private umask narrowed checkout.
        for member in (".gitignore", "runner.sh", "Cargo.lock"):
            shutil.copymode(repository / member, sealed / member)
        reproduced = manifest.release_source_identity(sealed)
        assert reproduced == candidate
        assert git_file_state() == original_git_state

        seal.seal_source_tree(sealed, ())
        seal.verify_source_tree_sealed(sealed, ())
        sealed_identity = manifest.release_source_identity(sealed)
        for field in (
            "head_commit",
            "head_tree",
            "index_tree",
            "cargo_lock_sha256",
        ):
            assert sealed_identity[field] == candidate[field]
        assert (
            sealed_identity["workspace_source_manifest_sha256"]
            != candidate["workspace_source_manifest_sha256"]
        )
        assert stat.S_IMODE((sealed / "runner.sh").stat().st_mode) == 0o555
        if os.name == "posix" and os.geteuid() != 0:
            with pytest.raises(PermissionError):
                (sealed / "runner.sh").write_text("transient edit\n", encoding="utf-8")
        (output / "release.log").write_text("passed\n", encoding="utf-8")
        assert git_file_state() == original_git_state
    finally:
        seal.unseal_source_tree(sealed)
        shutil.rmtree(sealed)


def test_seal_rejects_parent_or_absolute_writable_escape(tmp_path: Path) -> None:
    module = load_module()
    source = tmp_path / "source"
    source.mkdir()

    for invalid in ("../outside", "/absolute", "target/../../outside"):
        with pytest.raises(module.SealError, match="relative child"):
            module.seal_source_tree(source, [invalid])


def test_seal_rejects_external_file_symlink_even_if_external_bytes_change(
    tmp_path: Path,
) -> None:
    seal = load_module()
    manifest = load_manifest_module()
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "generated.rs"
    external.write_text("pub const VALUE: u8 = 1;\n", encoding="utf-8")
    link = source / "generated.rs"
    link.symlink_to(external)
    before = manifest._manifest_for_paths(source, ["generated.rs"])

    with pytest.raises(seal.SealError, match="target escapes"):
        seal.seal_source_tree(source)

    external.write_text("pub const VALUE: u8 = 2;\n", encoding="utf-8")
    assert manifest._manifest_for_paths(source, ["generated.rs"]) == before


def test_seal_rejects_external_directory_symlink(tmp_path: Path) -> None:
    module = load_module()
    source = tmp_path / "source"
    external = tmp_path / "generated"
    source.mkdir()
    external.mkdir()
    (external / "module.rs").write_text("pub fn generated() {}\n", encoding="utf-8")
    (source / "generated").symlink_to(external, target_is_directory=True)

    with pytest.raises(module.SealError, match="target escapes"):
        module.seal_source_tree(source)


def test_seal_rejects_source_symlink_into_writable_output(tmp_path: Path) -> None:
    module = load_module()
    source = tmp_path / "source"
    output = source / "target"
    source.mkdir()
    output.mkdir()
    (output / "generated.rs").write_text("pub fn generated() {}\n", encoding="utf-8")
    (source / "generated.rs").symlink_to("target/generated.rs")

    with pytest.raises(module.SealError, match="target enters a writable output"):
        module.seal_source_tree(source)


def test_seal_rejects_external_hard_link_alias_before_it_can_bypass_modes(
    tmp_path: Path,
) -> None:
    seal = load_module()
    manifest = load_manifest_module()
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external.rs"
    external.write_text("pub const VALUE: u8 = 1;\n", encoding="utf-8")
    tracked = source / "tracked.rs"
    os.link(external, tracked)
    before = manifest._manifest_for_paths(source, ["tracked.rs"])

    with pytest.raises(seal.SealError, match="external hard-link aliases"):
        seal.seal_source_tree(source)

    external.write_text("pub const VALUE: u8 = 2;\n", encoding="utf-8")
    assert manifest._manifest_for_paths(source, ["tracked.rs"]) != before
