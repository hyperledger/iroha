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


def source_guard_fixture(tmp_path):
    """Use real inert source/dep-info files, never a native build or output claim."""
    root = tmp_path / 'source'; root.mkdir()
    names = ['Cargo.toml', 'source.rs', 'build.rs', 'native/input.c', 'fixtures/runtime.json',
             'crates/iroha_core/src/unused.rs', 'crates/iroha_sumeragi/src/sim/unused.rs']
    for name in names:
        path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('// inert ' + name + '\n')
    metadata = {'workspace_root': str(root), 'workspace_members': ['bridge'],
                'packages': [{'id': 'bridge', 'name': 'connect_norito_bridge', 'source': None,
                              'manifest_path': str(root / 'Cargo.toml'),
                              'targets': [{'kind': ['custom-build'], 'src_path': str(root / 'build.rs')}]}],
                'resolve': {'nodes': [{'id': 'bridge', 'deps': []}]}}
    before = {name: emitter.unit.digest(root / name) for name in names}
    identities = emitter.source_identities(root, before)
    receipts = [{'dep_info': [{'matched_originals': [{'path': 'source.rs', 'sha256': before['source.rs']}]}]}]
    return root, metadata, before, identities, receipts


def guard_fixture(root, metadata, before, identities, receipts):
    after = {name: emitter.unit.digest(root / name) for name in before}
    return emitter.source_guard(metadata, root, before, identities, before, identities,
                                after, emitter.source_identities(root, after), receipts)


def test_unused_core_and_disabled_sim_files_are_broad_diagnostics_only(tmp_path):
    fixture = source_guard_fixture(tmp_path)
    root, _, before, _, _ = fixture
    unused = [name for name in before if name.startswith('crates/')]
    for name in unused:
        (root / name).write_text('// changed unused input\n')
    record = guard_fixture(*fixture)
    assert record['source_changes'] == unused
    assert record['source_identity_changes'] == unused
    assert record['source_before'] == before
    assert record['source_after'] != before
    assert record['consumed_source'].keys() == before.keys() - set(unused)
    assert record['consumed_identities_before'] == record['consumed_identities_after']
    emitter.unit.check_source_record(record)


@pytest.mark.parametrize('name', ('source.rs', 'build.rs', 'native/input.c', 'Cargo.toml', 'fixtures/runtime.json',
                                 'crates/iroha_core/src/unused.rs', 'crates/iroha_sumeragi/src/sim/unused.rs'))
def test_changed_actual_compiler_build_script_native_manifest_or_runtime_input_is_refused(tmp_path, name):
    fixture = source_guard_fixture(tmp_path)
    root, _, before, _, receipts = fixture
    if name.startswith('crates/'):
        # The names themselves are never excluded: an emitted consumer makes
        # either otherwise-unused file mandatory, irrespective of its package.
        receipts[0]['dep_info'][0]['matched_originals'].append({'path': name, 'sha256': before[name]})
    (root / name).write_text('// changed selected input\n')
    with pytest.raises(RuntimeError, match='custody differs'):
        guard_fixture(*fixture)


def test_same_byte_selected_replacement_fails_even_after_hashes_match(tmp_path):
    fixture = source_guard_fixture(tmp_path)
    root, _, before, _, _ = fixture
    replacement = root / 'replacement'; replacement.write_bytes((root / 'source.rs').read_bytes())
    replacement.replace(root / 'source.rs')
    assert emitter.unit.digest(root / 'source.rs') == before['source.rs']
    with pytest.raises(emitter.unit.Refused, match='source identity changed'):
        guard_fixture(*fixture)


@pytest.mark.parametrize('missing', (False, True))
def test_new_actual_dependency_must_have_a_prospective_original(tmp_path, missing):
    fixture = source_guard_fixture(tmp_path)
    root, _, before, _, _ = fixture
    output = root / 'target'; output.mkdir()
    retained = root / 'retained'; retained.mkdir()
    if not missing:
        (root / 'uncaptured.rs').write_text('// arrived after source capture\n')
    (output / 'inert.d').write_text(str(output / 'libinert.rlib') + ': source.rs uncaptured.rs\n')
    message = {'package_id': 'bridge', 'target': {'kind': ['lib']},
               'filenames': [str(output / 'libinert.rlib')]}
    with pytest.raises(RuntimeError, match='original inputs lacked|not a regular file'):
        emitter.custody.reconcile(message, root, before, retained, emitter.unit.digest, output)
