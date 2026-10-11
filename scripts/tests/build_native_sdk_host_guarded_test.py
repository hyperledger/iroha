"""Guarded host emitter failure controls; no mocked run is artifact qualification."""
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_native_sdk_host_guarded as emitter


def test_changes_include_membership_and_value():
    assert emitter.changes({"a": 1, "b": 2}, {"a": 2, "c": 3}) == ["a", "b", "c"]
    assert emitter.changes({"a": 1}, {"a": 1}) == []


def test_identity_refuses_alias_and_detects_edit_restore(tmp_path):
    path = tmp_path / "source"
    path.write_bytes(b"original")
    original = emitter.file_identity(path)
    path.write_bytes(b"changed")
    path.write_bytes(b"original")
    assert emitter.file_identity(path) != original
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(emitter.unit.Refused):
        emitter.file_identity(alias)


def test_source_identity_resolves_declared_external_prefixes(tmp_path):
    local = tmp_path / "local"
    external = tmp_path / "external"
    local.write_text("local")
    external.write_text("external")
    keys = {"local": "x", "registry:" + str(external): "y"}
    values = emitter.source_identities(tmp_path, keys)
    assert values["local"] == emitter.file_identity(local)
    assert values["registry:" + str(external)] == emitter.file_identity(external)


def test_tool_alias_retargeting_is_detected_even_when_bytes_match(tmp_path):
    first, second, alias = (tmp_path / name for name in ["first", "second", "alias"])
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    alias.symlink_to(first)
    before = emitter.tool_identities({str(alias): "same hash"})
    alias.unlink()
    alias.symlink_to(second)
    assert emitter.tool_identities({str(alias): "same hash"}) != before


@pytest.mark.parametrize("name", ["RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_TARGET_DIR", "CARGO_PROFILE_DEV_DEBUG", "CC", "LDFLAGS", "CC_aarch64_apple_darwin", "CARGO_BUILD_TARGET"])
def test_inherited_compiler_overrides_are_not_silently_adopted(monkeypatch, tmp_path, name):
    monkeypatch.setenv(name, "unreviewed")
    with pytest.raises(emitter.unit.Refused, match="unreviewed inherited"):
        emitter.build_environment(tmp_path / "rustc", tmp_path / "target", 2, tmp_path)


def test_run_text_preserves_natural_failure_without_signal(monkeypatch, tmp_path):
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 23, "", "actual failure")
    monkeypatch.setattr(emitter.subprocess, "run", run)
    with pytest.raises(emitter.unit.Refused, match="actual failure"):
        emitter.run_text(["cargo", "build"], root=tmp_path)
    assert len(calls) == 1
    assert calls[0][1]["check"] is False
    assert "timeout" not in calls[0][1]


def test_non_macos_is_refused_before_creating_output(monkeypatch, tmp_path):
    monkeypatch.setattr(emitter.sys, "platform", "linux")
    output = tmp_path / "output"
    with pytest.raises(emitter.unit.Refused, match="macOS"):
        emitter.host_build(tmp_path, output, tmp_path / "target", 2)
    assert not output.exists()


def test_warm_lane_reuse_retains_existing_artifacts_and_is_exclusive(tmp_path):
    lane = tmp_path / "stable-lane"
    lane.mkdir()
    artifact = lane / "retained-original"
    artifact.write_bytes(b"warm compiler output")
    identity = emitter.file_identity(artifact)
    with emitter.warm_target_custody(lane):
        with pytest.raises(emitter.unit.Refused, match="already in use"):
            with emitter.warm_target_custody(lane):
                raise AssertionError("concurrent owner admitted")
    with emitter.warm_target_custody(lane):
        assert emitter.file_identity(artifact) == identity
        assert artifact.read_bytes() == b"warm compiler output"


def test_warm_lane_lock_alias_and_replacement_are_refused(tmp_path):
    lane = tmp_path / "stable-lane"
    lane.mkdir()
    original = tmp_path / "original"
    original.write_bytes(b"original")
    lock = lane / ".guarded-host-sdk.lock"
    lock.symlink_to(original)
    with pytest.raises(emitter.unit.Refused, match="cannot open original"):
        with emitter.warm_target_custody(lane):
            raise AssertionError("alias admitted")
    lock.unlink()
    with pytest.raises(emitter.unit.Refused, match="changed during"):
        with emitter.warm_target_custody(lane):
            lock.unlink()
            lock.write_bytes(b"substitute")
    assert original.read_bytes() == b"original"


def test_default_build_environment_uses_native_jobserver(monkeypatch, tmp_path):
    for key in list(emitter.os.environ):
        if key.startswith(("CARGO_", "RUST", "CC", "CXX", "CPP", "LD", "AR", "RANLIB", "HOST_CC", "HOST_CXX", "TARGET_CC", "TARGET_CXX")):
            monkeypatch.delenv(key)
    environment = emitter.build_environment(tmp_path / "rustc", tmp_path / "target", None, tmp_path)
    assert "CARGO_BUILD_JOBS" not in environment
    assert environment["TMPDIR"] == str(tmp_path)
    assert emitter.build_environment(tmp_path / "rustc", tmp_path / "target", 6, tmp_path)["CARGO_BUILD_JOBS"] == "6"
    monkeypatch.setenv("CARGO_BUILD_JOBS", "1")
    with pytest.raises(emitter.unit.Refused, match="unreviewed inherited"):
        emitter.build_environment(tmp_path / "rustc", tmp_path / "target", None, tmp_path)


@pytest.mark.parametrize("change", ("public", "alias", "file", "missing"))
def test_build_environment_requires_original_private_scratch(monkeypatch, tmp_path, change):
    for key in list(emitter.os.environ):
        if key.startswith(("CARGO_", "RUST", "CC", "CXX", "CPP", "LD", "AR", "RANLIB", "HOST_CC", "HOST_CXX", "TARGET_CC", "TARGET_CXX")):
            monkeypatch.delenv(key)
    temporary = tmp_path / "temporary"
    if change == "public": temporary.mkdir(mode=0o755)
    elif change == "alias": temporary.symlink_to(tmp_path, target_is_directory=True)
    elif change == "file": temporary.write_bytes(b"not a directory")
    with pytest.raises((RuntimeError, FileNotFoundError)):
        emitter.build_environment(tmp_path / "rustc", tmp_path / "target", None, temporary)


def test_lock_replacement_before_admission_never_reaches_admit(monkeypatch, tmp_path):
    lane = tmp_path / "stable-lane"
    calls = []
    monkeypatch.setattr(emitter.unit, "admit", lambda *args: calls.append(args))
    with pytest.raises(emitter.unit.Refused, match="changed during"):
        with emitter.warm_target_custody(lane) as check:
            lock = lane / ".guarded-host-sdk.lock"
            lock.unlink()
            lock.write_bytes(b"replacement")
            emitter.admit_under_custody(tmp_path, {}, check)
    assert calls == []
    assert not (tmp_path / "pins.json").exists()


def test_lock_replacement_during_admission_prevents_pins_publication(monkeypatch, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "target").mkdir()
    lane = root / "target" / "stable-lane"
    parent = root / "target" / "qualification" / "native-sdk"
    parent.mkdir(parents=True, mode=0o700)
    output = parent / "evidence"
    monkeypatch.setattr(emitter.sys, "platform", "darwin")
    monkeypatch.setattr(emitter.platform, "machine", lambda: "arm64")
    calls = []
    def admit(*args):
        calls.append("admit")
        lock = lane / ".guarded-host-sdk.lock"
        lock.unlink()
        lock.write_bytes(b"replacement")
    def last_boundary(root, output, target, jobs, check):
        # Inert local parser data, never a native artifact or qualification claim.
        output.mkdir()
        return emitter.admit_under_custody(root, {}, check)
    monkeypatch.setattr(emitter.unit, "admit", admit)
    monkeypatch.setattr(emitter, "_host_build_locked", last_boundary)
    with pytest.raises(emitter.unit.Refused, match="changed during"):
        emitter.host_build(root, output, lane, None)
    assert calls == ["admit"]
    assert not (output / "pins.json").exists()


@pytest.mark.parametrize("inside_output", [False, True])
def test_artifact_and_warm_cargo_lanes_cannot_overlap(monkeypatch, tmp_path, inside_output):
    root = tmp_path.resolve() / "source"
    parent = root / "target" / "qualification" / "native-sdk"
    parent.mkdir(parents=True, mode=0o700)
    output = parent / "output"
    lane = output / "cargo" if inside_output else parent
    monkeypatch.setattr(emitter.sys, "platform", "darwin")
    monkeypatch.setattr(emitter.platform, "machine", lambda: "arm64")
    with pytest.raises(emitter.unit.Refused, match="disjoint"):
        emitter.host_build(root, output, lane, None)
    assert not output.exists()
