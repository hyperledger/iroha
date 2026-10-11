"""File/source admission controls; inert bytes never qualify a native build.

These controls do not compile, install or load native code. The real maintained
gate supplies original clean source, fresh build and ABI evidence separately.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci"))
SPEC = importlib.util.spec_from_file_location("native_source_delivery_controls", ROOT / "ci/python_native_source_delivery.py")
delivery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delivery)


def make_wheel(path: Path, source: Path, native: bytes) -> Path:
    """Produce archive/RECORD control data, with no native execution claim."""
    entries = {"iroha_native/__init__.py": (source / "__init__.py").read_bytes(),
               "iroha_native/_loader.py": (source / "_loader.py").read_bytes(),
               "iroha_native/_crypto.abi3.so": native,
               "iroha_native-0.0.1.dist-info/METADATA": b"Metadata-Version: 2.1\nName: iroha-native\nVersion: 0.0.1\n",
               "iroha_native-0.0.1.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: inert-file-control\nRoot-Is-Purelib: false\nTag: cp39-abi3-linux_x86_64\n"}
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for name, raw in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(raw))])
    record = "iroha_native-0.0.1.dist-info/RECORD"
    writer.writerow([record, "", ""])
    entries[record] = output.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in entries.items():
            archive.writestr(name, raw)
    return path


@pytest.fixture
def originals(tmp_path, monkeypatch):
    root = tmp_path / "source"
    source = root / "python/iroha_native/src/iroha_native"
    source.mkdir(parents=True)
    (source / "__init__.py").write_bytes(b'"""Inert source owner control."""\n')
    (source / "_loader.py").write_bytes(b'"""No native code is loaded in file controls."""\n')
    old = b"original private source artifact control"
    (source / "_crypto.abi3.so").write_bytes(old)
    native = b"fresh native member file-relation control"
    wheel_path = make_wheel(tmp_path / "fresh.whl", source, native)
    wheel_seal = delivery.wheel.seal_wheel(wheel_path).render()
    # This explicit stub isolates file delivery. It is neither Git identity nor
    # genuine native ABI evidence and is never presented as qualification.
    identity = {"head_commit": "1" * 40, "workspace_source_manifest_sha256": "2" * 64}
    pin = "unqualified-source-admission-unit-control"
    monkeypatch.setattr(delivery, "assert_source_pin", lambda root, expected: identity)
    manifest = {"schema": delivery.artifact.SCHEMA, "sdk": "python", "target": "inert-unit-control",
                "source_commit": identity["head_commit"], "source_tree_clean": True,
                "workspace_source_manifest_sha256": identity["workspace_source_manifest_sha256"],
                "artifact_sha256": hashlib.sha256(native).hexdigest(), "artifact_size": len(native),
                "bridge_abi_version": 29, "required_symbols": list(delivery.artifact.REQUIRED_SYMBOLS["python"]),
                "privacy_c_exports": [], "privacy_c_exports_inspected": False}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(delivery.artifact.canonical_manifest_bytes(manifest))
    manifest_seal = delivery.wheel.seal_wheel(manifest_path).render()
    state = delivery._json(delivery.inspect_source(root))
    backup = root / ".codex-native-backup"
    backup.mkdir(mode=0o700)
    return root, source, old, native, pin, state, wheel_path, wheel_seal, manifest_path, manifest_seal, backup


def promote(originals):
    root, _, _, _, pin, state, wheel_path, wheel_seal, manifest_path, manifest_seal, backup = originals
    return delivery.promote_source(root, pin, state, wheel_path, wheel_seal, manifest_path, manifest_seal, backup)


def verify(originals, receipt_seal):
    root, _, _, _, pin, _, wheel_path, wheel_seal, manifest_path, manifest_seal, backup = originals
    delivery.verify_source(root, pin, wheel_path, wheel_seal, manifest_path, manifest_seal,
                           backup / "delivery.json", receipt_seal.render())


def test_exact_original_artifact_moves_and_same_wheel_member_is_retained(originals):
    _, source, old, native, _, _, _, _, _, _, backup = originals
    old_inode = (source / "_crypto.abi3.so").stat().st_ino
    receipt = promote(originals)
    assert (source / "_crypto.abi3.so").read_bytes() == native
    assert (backup / "_crypto.abi3.so").read_bytes() == old
    assert (backup / "_crypto.abi3.so").stat().st_ino == old_inode
    assert (source / "_crypto.abi3.so").stat().st_nlink == 1
    assert (backup / "_crypto.abi3.so").stat().st_nlink == 1
    verify(originals, receipt)
    with pytest.raises(delivery.DeliveryError, match="changed during"):
        promote(originals)
    assert (backup / "_crypto.abi3.so").read_bytes() == old


@pytest.mark.parametrize("mutation", ["old", "owner", "wheel", "manifest", "backup", "sibling", "symlink"])
def test_pre_dispatch_mutation_preserves_original_and_creates_no_new_source(originals, mutation):
    _, source, old, _, _, _, wheel_path, _, manifest_path, _, backup = originals
    original = source / "_crypto.abi3.so"
    if mutation == "old":
        original.write_bytes(old + b"changed")
    elif mutation == "owner":
        (source / "_loader.py").write_bytes(b"changed source")
    elif mutation == "wheel":
        wheel_path.write_bytes(wheel_path.read_bytes() + b"changed")
    elif mutation == "manifest":
        manifest_path.write_bytes(manifest_path.read_bytes() + b"changed")
    elif mutation == "backup":
        (backup / "foreign").write_bytes(b"preserve me")
    elif mutation == "sibling":
        (source / "_crypto.other.so").write_bytes(b"foreign artifact")
    else:
        original.rename(source / "original.bin")
        original.symlink_to(source / "original.bin")
    before = original.read_bytes()
    with pytest.raises((delivery.DeliveryError, delivery.wheel.VerificationError)):
        promote(originals)
    assert original.read_bytes() == before
    assert not (backup / "delivery.json").exists()
    assert not (backup / "_crypto.abi3.so").exists()


def test_competing_source_is_not_overwritten_and_old_original_is_retained(originals, monkeypatch):
    _, source, old, native, _, _, _, _, _, _, backup = originals
    actual_move = delivery._move_no_replace
    old_inode = (source / "_crypto.abi3.so").stat().st_ino

    def competing_move(source_fd, source_name, destination_fd, destination_name):
        if source_name.startswith(".fresh-native-"):
            (source / destination_name).write_bytes(b"competing source artifact")
        return actual_move(source_fd, source_name, destination_fd, destination_name)

    monkeypatch.setattr(delivery, "_move_no_replace", competing_move)
    with pytest.raises(FileExistsError):
        promote(originals)
    assert (source / "_crypto.abi3.so").read_bytes() == b"competing source artifact"
    assert (backup / "_crypto.abi3.so").read_bytes() == old
    assert (backup / "_crypto.abi3.so").stat().st_ino == old_inode
    assert (backup / "intent.json").exists()
    assert not (backup / "delivery.json").exists()
    assert not list(source.glob(".iroha-native-*.so"))
    candidates = list(backup.glob(".fresh-native-*.so"))
    assert len(candidates) == 1 and candidates[0].read_bytes() == native


def test_backup_name_race_is_refused_without_overwriting_any_owner(originals, monkeypatch):
    _, source, old, native, _, _, _, _, _, _, backup = originals
    actual_move = delivery._move_no_replace
    old_inode = (source / "_crypto.abi3.so").stat().st_ino
    competitor = b"competing backup must survive"

    def competing_backup(source_fd, source_name, destination_fd, destination_name):
        if source_name == "_crypto.abi3.so":
            (backup / destination_name).write_bytes(competitor)
        return actual_move(source_fd, source_name, destination_fd, destination_name)

    monkeypatch.setattr(delivery, "_move_no_replace", competing_backup)
    with pytest.raises(FileExistsError):
        promote(originals)
    assert (source / "_crypto.abi3.so").read_bytes() == old
    assert (source / "_crypto.abi3.so").stat().st_ino == old_inode
    assert (backup / "_crypto.abi3.so").read_bytes() == competitor
    assert (backup / "intent.json").exists()
    assert not (backup / "delivery.json").exists()
    candidates = list(backup.glob(".fresh-native-*.so"))
    assert len(candidates) == 1 and candidates[0].read_bytes() == native


@pytest.mark.parametrize("mutation", ["source", "backup", "receipt"])
def test_revalidation_refuses_every_retained_owner_change(originals, mutation):
    _, source, _, _, _, _, _, _, _, _, backup = originals
    receipt = promote(originals)
    path = {"source": source / "_crypto.abi3.so", "backup": backup / "_crypto.abi3.so",
            "receipt": backup / "delivery.json"}[mutation]
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises((delivery.DeliveryError, delivery.wheel.VerificationError)):
        verify(originals, receipt)


def test_before_build_source_pin_is_exact_and_refuses_change_or_dirty_source(tmp_path, monkeypatch):
    identity = {"head_commit": "1" * 40, "cargo_lock_sha256": "2" * 64}
    monkeypatch.setattr(delivery, "release_source_identity", lambda root: dict(identity))
    pin = delivery.source_pin(tmp_path)
    assert delivery.assert_source_pin(tmp_path, pin) == identity
    identity["cargo_lock_sha256"] = "3" * 64
    with pytest.raises(delivery.DeliveryError, match="since the before-build"):
        delivery.assert_source_pin(tmp_path, pin)

    def dirty(root):
        raise RuntimeError("existing clean-source owner refused dirty source")

    monkeypatch.setattr(delivery, "release_source_identity", dirty)
    with pytest.raises(RuntimeError, match="refused dirty source"):
        delivery.source_pin(tmp_path)


def test_original_before_build_shell_refusal_stops_before_builder_dispatch(tmp_path):
    runner = (ROOT / "ci/check_sorafs_python_native_sdk.sh").read_text()
    start = runner.index('SOURCE_DELIVERY=')
    end = runner.index('"${PYTHON_BIN}" -m venv', start)
    command = runner[start:end] + '\nprintf dispatched > "$ROOT_DIR/builder-marker"\n'
    # Explicit dispatch control only; this child produces no source identity.
    child = tmp_path / "refuse-source"
    child.write_text('#!/bin/sh\nexit 78\n')
    child.chmod(0o700)
    result = subprocess.run(["bash", "-eu", "-c", command],
                            env=dict(os.environ, ROOT_DIR=str(tmp_path), PYTHON_BIN=str(child)),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 78
    assert not (tmp_path / "builder-marker").exists()


def test_invalid_closed_control_and_unsupported_directory_operations_refuse(originals, monkeypatch):
    with pytest.raises(delivery.artifact.ArtifactContractError, match="duplicate key"):
        delivery._control(b'{"schema":"x","schema":"x"}', delivery.DELIVERY_SCHEMA)
    monkeypatch.setattr(delivery.os, "supports_dir_fd", set())
    with pytest.raises(delivery.DeliveryError, match="descriptor-relative"):
        promote(originals)
    assert not (originals[-1] / "intent.json").exists()


def test_isolated_source_pin_cli_reaches_existing_clean_owner_without_sdk_imports(tmp_path):
    # The real owner refuses this unqualified root. No synthetic Git identity
    # substitutes for the original owner, and the child never loads native code.
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "ci/python_native_source_delivery.py"),
                             "pin", "--root", str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert "ModuleNotFoundError" not in result.stderr
    assert any(reason in result.stderr for reason in ("git command failed", "not a git repository",
                                                    "release worktree has tracked changes"))
    assert not result.stdout


def test_partial_native_file_write_refusal_removes_only_its_own_temporary(originals, monkeypatch):
    _, source, old, _, _, _, _, _, _, _, backup = originals
    fsync = delivery.os.fsync

    def refuse_native_fsync(descriptor):
        if stat.S_ISREG(delivery.os.fstat(descriptor).st_mode):
            # intent.json is already durable; refuse only the actual new native
            # file. Do not weaken source or wheel admission to reach this point.
            size = delivery.os.fstat(descriptor).st_size
            if size == len(originals[3]):
                raise OSError("actual new native write refused")
        return fsync(descriptor)

    monkeypatch.setattr(delivery.os, "fsync", refuse_native_fsync)
    with pytest.raises(OSError, match="new native write refused"):
        promote(originals)
    assert (source / "_crypto.abi3.so").read_bytes() == old
    assert not list(source.glob(".iroha-native-*.so"))
    assert (backup / "intent.json").exists()
    assert not (backup / "delivery.json").exists()


@pytest.mark.parametrize("mutation", ["omit-backup", "before-identity", "before-fields", "owner-fields"])
def test_rebound_receipt_still_requires_complete_original_custody_graph(originals, mutation):
    receipt = promote(originals)
    path = originals[-1] / "delivery.json"
    value = json.loads(path.read_bytes())
    if mutation == "omit-backup":
        value["original_backup"] = None
    elif mutation == "before-identity":
        original = delivery.wheel.FileSeal.parse(value["source_before"]["native"]["seal"])
        parts = original.render().split(":")
        parts[2] = str(original.inode + 1)
        value["source_before"]["native"]["seal"] = ":".join(parts)
    elif mutation == "before-fields":
        value["source_before"]["unexpected"] = True
    else:
        value["source_before"]["files"][0]["unexpected"] = True
    path.write_text(delivery._json(value))
    # Even a supplied new receipt seal cannot substitute an omitted or partial
    # original custody binding for the complete source graph.
    changed = delivery.wheel.seal_wheel(path)
    with pytest.raises(delivery.DeliveryError):
        verify(originals, changed)


@pytest.mark.parametrize("arguments", [
    ["pin", "--source-pin", "unexpected"],
    ["assert-pin"],
    ["inspect", "--receipt", "unexpected"],
    ["verify", "--source-pin", "missing-original-bindings"],
    ["pin", "--roo", "unexpected-alias"],
])
def test_cli_refuses_incomplete_or_extra_field_inventory_without_source_dispatch(tmp_path, arguments):
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "ci/python_native_source_delivery.py"),
                             *arguments, "--root", str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "exact original field inventory" in result.stderr or "unrecognized arguments" in result.stderr
    assert "release worktree" not in result.stderr
    assert not result.stdout


def test_private_temporary_replacement_is_retained_on_refusal_and_descriptors_close(originals, monkeypatch):
    _, source, old, native, _, _, _, _, _, _, backup = originals
    descriptors = []
    open_directory = delivery._open_directory
    actual_move = delivery._move_no_replace

    def retain_directory(path):
        descriptor = open_directory(path)
        descriptors.append(descriptor)
        return descriptor

    def replace_private_temporary_before_refused_move(source_fd, source_name, destination_fd, destination_name):
        if source_name.startswith(".fresh-native-"):
            path = backup / source_name
            path.rename(backup / "retained-original-native-temporary")
            path.write_bytes(b"competing temporary owner")
            raise OSError("source move refused")
        return actual_move(source_fd, source_name, destination_fd, destination_name)

    monkeypatch.setattr(delivery, "_open_directory", retain_directory)
    monkeypatch.setattr(delivery, "_move_no_replace", replace_private_temporary_before_refused_move)
    with pytest.raises(OSError, match="source move refused"):
        promote(originals)
    competitors = list(backup.glob(".fresh-native-*.so"))
    assert len(competitors) == 1 and competitors[0].read_bytes() == b"competing temporary owner"
    assert (backup / "retained-original-native-temporary").read_bytes() == native
    assert not list(source.glob(".iroha-native-*.so"))
    assert (backup / "_crypto.abi3.so").read_bytes() == old
    assert not (backup / "delivery.json").exists()
    for descriptor in descriptors:
        with pytest.raises(OSError):
            delivery.os.fstat(descriptor)


def test_no_shared_path_unlink_is_used_for_success_or_refusal(originals, monkeypatch):
    def forbidden_unlink(*args, **kwargs):
        raise AssertionError("shared-name unlink would delete an unowned competitor")

    monkeypatch.setattr(delivery.os, "unlink", forbidden_unlink)
    receipt = promote(originals)
    verify(originals, receipt)


def test_equal_byte_native_substitution_cannot_qualify_a_different_inode(originals, monkeypatch):
    _, source, _, native, _, _, _, _, _, _, backup = originals
    actual_move = delivery._move_no_replace

    def replace_after_move(source_fd, source_name, destination_fd, destination_name):
        actual_move(source_fd, source_name, destination_fd, destination_name)
        if source_name.startswith(".fresh-native-"):
            path = source / destination_name
            path.rename(backup / "retained-original-fresh-native")
            path.write_bytes(native)

    monkeypatch.setattr(delivery, "_move_no_replace", replace_after_move)
    with pytest.raises(delivery.DeliveryError, match="original fresh native physical object"):
        promote(originals)
    assert (source / "_crypto.abi3.so").read_bytes() == native
    assert (backup / "retained-original-fresh-native").read_bytes() == native
    assert not (backup / "delivery.json").exists()


def test_unsupported_atomic_move_host_refuses_before_intent(originals, monkeypatch):
    monkeypatch.setattr(delivery.sys, "platform", "unsupported-control-host")
    with pytest.raises(delivery.DeliveryError, match="atomic no-overwrite rename host"):
        promote(originals)
    assert not (originals[-1] / "intent.json").exists()


def test_fresh_backup_and_existing_parent_are_synced_before_old_source_removal(originals, monkeypatch):
    directories = {}
    events = []
    open_directory = delivery._open_directory
    fsync = delivery.os.fsync
    actual_move = delivery._move_no_replace
    backup = originals[-1]

    def capture_directory(path):
        descriptor = open_directory(path)
        directories[descriptor] = path
        return descriptor

    def capture_fsync(descriptor):
        if descriptor in directories:
            events.append(("fsync", directories[descriptor]))
        return fsync(descriptor)

    def capture_move(source_fd, source_name, destination_fd, destination_name):
        if source_name == "_crypto.abi3.so":
            assert ("fsync", backup) in events
            assert ("fsync", backup.parent) in events
        events.append(("move", source_name))
        return actual_move(source_fd, source_name, destination_fd, destination_name)

    monkeypatch.setattr(delivery, "_open_directory", capture_directory)
    monkeypatch.setattr(delivery.os, "fsync", capture_fsync)
    monkeypatch.setattr(delivery, "_move_no_replace", capture_move)
    receipt = promote(originals)
    verify(originals, receipt)
    first_move = next(index for index, event in enumerate(events) if event[0] == "move")
    assert events.index(("fsync", backup)) < events.index(("fsync", backup.parent)) < first_move
    for descriptor in directories:
        with pytest.raises(OSError):
            delivery.os.fstat(descriptor)
