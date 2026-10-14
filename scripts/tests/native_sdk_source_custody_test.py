"""Pure source custody tests; inert dictionaries never qualify a native artifact."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import native_sdk_source_custody as custody


@pytest.fixture(autouse=True)
def no_children(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Pure source custody attempted a compiler or native child')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


def fixture(tmp_path, kind='local', dependency_name='pqcrypto-internals'):
    root = tmp_path / 'worktree'; root.mkdir()
    owner = root / 'crates/iroha_js_host'; owner.mkdir(parents=True)
    manifest = owner / 'Cargo.toml'; manifest.write_text('[package]\nname="iroha_js_host"\n')
    outside = tmp_path / 'external'; outside.mkdir()
    dependency_manifest = outside / 'Cargo.toml'; dependency_manifest.write_text('[package]\nname="inert-dependency"\n')
    source = None if kind == 'local' else ('registry+https://github.com/rust-lang/crates.io-index'
                                          if kind == 'registry' else next(iter(custody.SUPPORTED_GIT_SOURCES)))
    if kind == 'local':
        dependency = root / 'crates/inert-dependency'; dependency.mkdir()
        dependency_manifest = dependency / 'Cargo.toml'; dependency_manifest.write_text('[package]\nname="inert-dependency"\n')
        prefix = 'crates/inert-dependency/'
    else:
        prefix = ('registry:' if kind == 'registry' else 'git:') + str(outside) + '/'
    metadata = {'workspace_root': str(root), 'workspace_members': ['native'],
                'packages': [{'id': 'native', 'name': 'iroha_js_host', 'source': None,
                              'manifest_path': str(manifest)},
                             {'id': 'dependency', 'name': dependency_name, 'source': source,
                              'manifest_path': str(dependency_manifest)}],
                'resolve': {'nodes': [{'id': 'native', 'deps': [{'pkg': 'dependency'}]},
                                      {'id': 'dependency', 'deps': []}]}}
    originals = {'crates/iroha_js_host/Cargo.toml': hashlib.sha256(manifest.read_bytes()).hexdigest(),
                 prefix + 'Cargo.toml': hashlib.sha256(dependency_manifest.read_bytes()).hexdigest(),
                 'crates/iroha_js_host/src/lib.rs': 'a' * 64,
                 'crates/iroha_js_host/README.md': 'b' * 64,
                 'crates/iroha_js_host/src/native_tests.rs': 'c' * 64}
    receipts = [{'dep_info': [{'matched_originals': [{'path': 'crates/iroha_js_host/src/lib.rs', 'sha256': 'a' * 64}]}]}]
    return root, metadata, originals, receipts, prefix


NATIVE_INPUTS = ('pqclean/sign.c', 'pqclean/sign.cc', 'pqclean/sign.cpp', 'pqclean/sign.cxx',
                 'include/native.h', 'include/native.hpp', 'src/feat.S', 'src/feat.s', 'src/feat.asm',
                 'include/native.inc', 'include/native.inl', 'metal/kernel.metal', 'cuda/kernel.cu',
                 'cuda/kernel.cuh', 'src/metal.m', 'src/metal.mm', 'build/generate.pl',
                 'build/common.pm', 'build/generate.py', 'build/native.sh', 'build/native.cmake',
                 'build/native.mk', 'build/native.in', 'build/CMakeLists.txt', 'build/Makefile',
                 'build/configure', 'build/exports.def', 'build/exports.map', 'build/link.ld',
                 'pregenerated/kernel.ptx', 'pregenerated/libnative.a', 'pregenerated/native.o')


@pytest.mark.parametrize('kind', ('local', 'registry', 'git'))
@pytest.mark.parametrize('name', NATIVE_INPUTS)
def test_native_and_build_inputs_outside_rust_dep_info_refuse_changed_originals(tmp_path, kind, name):
    root, metadata, originals, receipts, prefix = fixture(tmp_path, kind)
    key = prefix + name; originals[key] = 'd' * 64
    current = dict(originals); current[key] = 'e' * 64
    with pytest.raises(RuntimeError, match='source custody differs'):
        custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')


@pytest.mark.parametrize('change', ('add', 'remove'))
def test_native_source_membership_changes_cannot_be_resealed(tmp_path, change):
    root, metadata, originals, receipts, prefix = fixture(tmp_path, 'registry')
    key = prefix + 'pqclean/additional.c'; current = dict(originals)
    if change == 'add': current[key] = 'd' * 64
    else: originals[key] = 'd' * 64
    with pytest.raises(RuntimeError, match='source custody differs'):
        custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')


def test_unchanged_native_inputs_are_in_the_consumed_projection_with_docs_and_cfgtest_diagnostic(tmp_path):
    root, metadata, originals, receipts, prefix = fixture(tmp_path, 'registry')
    key = prefix + 'pqclean/sign.c'; originals[key] = 'd' * 64
    current = dict(originals)
    current['crates/iroha_js_host/README.md'] = 'e' * 64
    current['crates/iroha_js_host/src/native_tests.rs'] = 'f' * 64
    selected = custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')
    assert selected[key] == 'd' * 64
    assert 'crates/iroha_js_host/README.md' not in selected
    assert 'crates/iroha_js_host/src/native_tests.rs' not in selected
    assert originals['crates/iroha_js_host/README.md'] == 'b' * 64


def test_native_file_outside_selected_metadata_graph_is_diagnostic_only(tmp_path):
    root, metadata, originals, receipts, prefix = fixture(tmp_path)
    key = 'crates/unselected/native.c'; originals[key] = 'd' * 64
    current = dict(originals); current[key] = 'e' * 64
    selected = custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')
    assert key not in selected


def test_root_package_cannot_claim_external_native_file_outside_selected_graph(tmp_path):
    root, metadata, originals, receipts, prefix = fixture(tmp_path)
    manifest = root / 'Cargo.toml'; manifest.write_text('[package]\nname="iroha_js_host"\n')
    metadata['packages'][0]['manifest_path'] = str(manifest)
    originals['Cargo.toml'] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    key = 'registry:/unselected/native.c'; originals[key] = 'd' * 64
    current = dict(originals); current[key] = 'e' * 64
    selected = custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')
    assert key not in selected


@pytest.mark.parametrize('change', ('changed', 'removed', 'outside-owner'))
def test_actual_custom_build_target_source_is_explicit_and_owned(tmp_path, change):
    root, metadata, originals, receipts, prefix = fixture(tmp_path)
    path = root / 'crates/iroha_js_host/native_build_recipe.rs'; path.write_text('// inert build recipe\n')
    metadata['packages'][0]['targets'] = [{'kind': ['custom-build'], 'src_path': str(path)}]
    key = str(path.relative_to(root)); originals[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    current = dict(originals)
    if change == 'changed': current[key] = 'd' * 64
    elif change == 'removed': del current[key]
    else:
        outside = tmp_path / 'outside-build.rs'; outside.write_text('// inert outside recipe\n')
        metadata['packages'][0]['targets'][0]['src_path'] = str(outside)
    with pytest.raises(RuntimeError):
        custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')


@pytest.mark.parametrize('name,path', (('ivm', 'spec/syscalls.toml'),
                                     ('kotodama_lang', 'grammar/v1.lex'),
                                     ('kotodama_lang', 'src/i18n/translations/messages.v1.tsv'),
                                     ('oid-registry', 'assets/oid_db.txt')))
def test_current_build_script_data_reads_outside_rust_include_cannot_drift(tmp_path, name, path):
    root, metadata, originals, receipts, prefix = fixture(tmp_path, 'registry', name)
    key = prefix + path; originals[key] = 'd' * 64
    current = dict(originals); current[key] = 'e' * 64
    with pytest.raises(RuntimeError, match='source custody differs'):
        custody.consumed_source_projection(metadata, root, originals, current, receipts, 'iroha_js_host')


@pytest.mark.parametrize('state', ('present', 'modified', 'missing', 'symlink'))
def test_sccp_artifact_lock_is_captured_before_compile_and_bound_after(tmp_path, state):
    root, metadata, _, _, _ = fixture(tmp_path)
    metadata['target_directory'] = str(root / 'target')
    (root / 'Cargo.lock').write_text('version = 4\n')
    outside = (
        'norito.md', 'scripts/norito_schema_capture/derive_probe.rs',
        'codec/rans/tables/rans_seed0.toml', 'artifacts/poseidon/constants.ron',
        'fixtures/sm/sm2_fixture.json',
        'tests/interop/soranet/interop/rust/snnet-interop-nk2-v1.json',
        'tests/interop/soranet/interop/rust/snnet-interop-nk3-v1.json',
        'scripts/contract_tooling/artifact-lock.json',
    )
    for relative in outside:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n')
    key = 'scripts/contract_tooling/artifact-lock.json'
    lock = root / key
    digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if state in ('missing', 'symlink'):
        lock.unlink()
        if state == 'symlink':
            lock.symlink_to(root / 'fixtures/sm/sm2_fixture.json')
        with pytest.raises(RuntimeError, match='outside-package input custody'):
            custody.capture(metadata, root, digest, 'iroha_js_host')
        return
    before = custody.capture(metadata, root, digest, 'iroha_js_host')
    assert before[key] == digest(lock)
    receipts = [{'dep_info': [{'matched_originals': [{'path': key, 'sha256': before[key]}]}]}]
    if state == 'modified':
        lock.write_text('{"changed":true}\n')
        current = custody.capture(metadata, root, digest, 'iroha_js_host')
        with pytest.raises(RuntimeError, match='source custody differs'):
            custody.consumed_source_projection(metadata, root, before, current, receipts, 'iroha_js_host')
    else:
        selected = custody.consumed_source_projection(metadata, root, before, before, receipts, 'iroha_js_host')
        assert selected[key] == before[key]
