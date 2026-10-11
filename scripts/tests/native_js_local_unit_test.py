"""Pure local N-API custody/refusal tests; every child is forbidden."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import native_js_local_unit as unit



@pytest.fixture(autouse=True)
def no_children(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Pure custody test attempted a child')
    monkeypatch.setattr(unit.subprocess, 'run', forbidden)
    monkeypatch.setattr(unit.subprocess, 'Popen', forbidden)


@pytest.mark.parametrize('scope,profile', (('release', 'debug'), ('local-integration', 'debug'),
                                         ('local-unit', 'release'), ('local-unit', 'deploy')))
def test_local_unit_scope_never_qualifies_release_or_deploy(scope, profile):
    with pytest.raises(RuntimeError): unit.local_policy(scope, profile)


def test_exact_warm_recipe_keeps_jobserver_incremental_existing_lane_and_real_napi():
    target = ROOT / 'target/cargo-fast/kot'
    argv = unit.expected_build(ROOT, target)
    assert argv == [str(ROOT / 'scripts/cargo_fast.sh'), '--target-dir', str(target),
                    '--stable-local-metadata', '--incremental', '--', 'build', '--locked', '--offline',
                    '-p', 'iroha_js_host', '--lib', '--message-format=json']
    assert '--jobs' not in argv


def artifact_fixture():
    import tomllib
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    target = ROOT / 'target/cargo-fast/kot'; owner = ROOT / 'crates/iroha_js_host'
    row = {'reason': 'compiler-artifact', 'package_id': 'path+' + owner.as_uri() + '#' + version,
           'manifest_path': str(owner / 'Cargo.toml'),
           'target': {'name': 'iroha_js_host', 'src_path': str(owner / 'src/lib.rs'), 'kind': ['cdylib'], 'crate_types': ['cdylib']},
           'features': [], 'executable': None, 'fresh': True,
           'profile': {'opt_level': '0', 'debuginfo': 0, 'debug_assertions': True, 'overflow_checks': True, 'test': False},
           'filenames': [str(target / 'debug/libiroha_js_host.dylib')]}
    return row, target


def test_inert_napi_emitter_parser_positive_is_not_an_artifact_or_execution():
    row, target = artifact_fixture()
    actual, path = unit.artifact([row], ROOT, target, authenticate_file=False)
    assert actual == row and path == target / 'debug/libiroha_js_host.dylib'


@pytest.mark.parametrize('change', ('bridge', 'missing', 'duplicate', 'package', 'manifest', 'source', 'kind',
                                   'features', 'fresh', 'harness', 'release', 'old-output'))
def test_wrong_stale_cabi_or_non_napi_emitter_cannot_substitute_for_real_napi(change):
    row, target = artifact_fixture(); messages = [row]
    if change == 'bridge': row['target']['name'] = 'connect_norito_bridge'
    elif change == 'missing': messages.clear()
    elif change == 'duplicate': messages.append(copy.deepcopy(row))
    elif change == 'package': row['package_id'] = 'old-package'
    elif change == 'manifest': row['manifest_path'] = '/unrelated/Cargo.toml'
    elif change == 'source': row['target']['src_path'] = '/unrelated/lib.rs'
    elif change == 'kind': row['target']['kind'] = ['rlib']
    elif change == 'features': row['features'] = ['compatibility']
    elif change == 'fresh': row['fresh'] = None
    elif change == 'harness': row['profile']['test'] = True
    elif change == 'release': row['profile']['opt_level'] = '3'
    elif change == 'old-output': row['filenames'] = ['/old/libiroha_js_host.dylib']
    with pytest.raises(RuntimeError): unit.artifact(messages, ROOT, target, authenticate_file=False)


def probe_fixture():
    policy = {'required': ['connectNoritoBridgeAbiVersion', 'securePrivateFileAbiVersion'],
              'forbidden': ['retiredMethod'], 'abi_version': 25,
              'required_results': {'connectNoritoBridgeAbiVersion': 25, 'securePrivateFileAbiVersion': 1}}
    proof = {'abi_version': 25, 'exports': policy['required'], 'forbidden': [],
             'required_exports': policy['required'], 'required_results': policy['required_results'],
             'signing_independent_emitted': 'a' * 64, 'signing_independent_artifact': 'a' * 64}
    return proof, policy


def test_inert_native_probe_parser_positive_grants_no_native_qualification():
    unit.check_probe(*probe_fixture())


@pytest.mark.parametrize('change', ('abi', 'missing-export', 'duplicate-export', 'retired', 'pruned-required',
                                   'wrong-result', 'changed-code', 'bad-hash', 'extra-field'))
def test_real_consumer_abi_export_and_signing_only_derivation_cannot_be_relabelled(change):
    proof, policy = probe_fixture()
    if change == 'abi': proof['abi_version'] = 24
    elif change == 'missing-export': proof['exports'] = []
    elif change == 'duplicate-export': proof['exports'] = ['connectNoritoBridgeAbiVersion'] * 2
    elif change == 'retired': proof['forbidden'] = ['retiredMethod']
    elif change == 'pruned-required': proof['required_exports'] = []
    elif change == 'wrong-result': proof['required_results'] = {'securePrivateFileAbiVersion': 0}
    elif change == 'changed-code': proof['signing_independent_artifact'] = 'b' * 64
    elif change == 'bad-hash': proof['signing_independent_emitted'] = proof['signing_independent_artifact'] = 'bad'
    elif change == 'extra-field': proof['release_qualified'] = True
    with pytest.raises(RuntimeError): unit.check_probe(proof, policy)


def test_current_repository_node_policy_combines_all_original_required_methods():
    selected = unit.policy(ROOT)
    assert selected['abi_version'] == 25
    assert {'noritoEncodeInstruction', 'privacyCompiledProfileCatalogV1', 'privateSettlementVerifyCommitteeProofResponseV1',
            'securePrivateFileRead', 'compileKotodama', 'buildKaigiUsageProofV1'} <= set(selected['required'])
    assert selected['required_results'] == {'connectNoritoBridgeAbiVersion': 25, 'securePrivateFileAbiVersion': 1}


def test_alias_receipt_duplicate_and_wrong_digest_refuse(tmp_path):
    real = tmp_path / 'real.json'; real.write_text('{"scope":"local-unit","scope":"release"}')
    alias = tmp_path / 'alias.json'; alias.symlink_to(real)
    with pytest.raises(RuntimeError): unit.load(alias)
    with pytest.raises(RuntimeError): unit.load(real)
    with pytest.raises(RuntimeError): unit.load(real, '0' * 64)


def test_missing_acknowledgement_refuses_before_any_directory_or_child(tmp_path):
    output = tmp_path / 'not-created'
    with pytest.raises(RuntimeError, match='acknowledgement'):
        unit.produce(ROOT, ROOT / 'target/cargo-fast/kot', output, {}, False)
    assert not output.exists()


def test_cli_forwards_exact_local_recipe_acknowledgement_without_running_native(tmp_path, monkeypatch, capsys):
    config = tmp_path / 'config.json'; config.write_text('{"inert":true}')
    output = tmp_path / 'not-created'; target = ROOT / 'target/cargo-fast/kot'
    observed = []
    def observe(root, lane, destination, selected, acknowledge):
        observed.append((root, lane, destination, selected, acknowledge)); return destination
    monkeypatch.setattr(unit, 'produce', observe)
    monkeypatch.setattr(sys, 'argv', ['native_js_local_unit.py', 'produce', '--root', str(ROOT), '--output', str(output),
                                     '--target-dir', str(target), '--config', str(config), '--acknowledge-local-unit-recipe'])
    assert unit.cli() == 0 and observed == [(ROOT, target, output, {'inert': True}, True)]
    assert not output.exists() and str(output) in capsys.readouterr().out


def test_empty_natural_child_log_remains_an_authenticated_empty_regular_file(tmp_path):
    path = tmp_path / 'empty.log'; path.write_bytes(b'')
    assert unit.log_hash(path) == hashlib.sha256(b'').hexdigest()
    alias = tmp_path / 'alias.log'; alias.symlink_to(path)
    with pytest.raises(RuntimeError): unit.log_hash(alias)


def child_fixture(tmp_path):
    log = tmp_path / 'child.log'; log.write_bytes(b'inert retained stdout\n')
    errors = Path(str(log) + '.stderr'); errors.write_bytes(b'')
    argv = ['/inert/repository-owned-child', '--one-exact-argument']
    env = {'LANG': 'C.UTF-8'}
    row = {'argv': argv, 'cwd': str(ROOT), 'environment': env, 'started_unix': 1,
           'finished_unix': 2, 'natural_exit': 0, 'log': str(log),
           'log_sha256': unit.log_hash(log), 'stderr': str(errors), 'stderr_sha256': unit.log_hash(errors)}
    unit.save(log.with_suffix('.record.json'), row)
    return row, argv, env, log


def test_inert_child_parser_positive_requires_exact_original_log_and_sidecar(tmp_path):
    row, argv, env, log = child_fixture(tmp_path)
    unit.check_child(row, argv, ROOT, env, log)


@pytest.mark.parametrize('change', ('argv', 'cwd', 'environment', 'natural-one', 'natural-bool',
                                   'start-bool', 'reversed-time', 'log-path', 'stderr-path', 'extra',
                                   'changed-log', 'changed-stderr', 'changed-sidecar', 'alias-log'))
def test_wrong_or_resealed_child_relationship_refuses_without_any_child(tmp_path, change):
    row, argv, env, log = child_fixture(tmp_path)
    row = copy.deepcopy(row)
    if change == 'argv': row['argv'] = ['/inert/different-child']
    elif change == 'cwd': row['cwd'] = '/different/source-root'
    elif change == 'environment': row['environment']['NODE_OPTIONS'] = '--require=caller-code'
    elif change == 'natural-one': row['natural_exit'] = 1
    elif change == 'natural-bool': row['natural_exit'] = False
    elif change == 'start-bool': row['started_unix'] = True
    elif change == 'reversed-time': row['started_unix'] = 3
    elif change == 'log-path': row['log'] = '/different/log'
    elif change == 'stderr-path': row['stderr'] = '/different/stderr'
    elif change == 'extra': row['release_qualified'] = True
    elif change == 'changed-log': log.write_bytes(b'changed retained stdout\n')
    elif change == 'changed-stderr': Path(str(log) + '.stderr').write_bytes(b'changed retained stderr\n')
    elif change == 'changed-sidecar': log.with_suffix('.record.json').write_text('{"release_qualified":true}')
    else:
        real = log.with_name('real.log'); log.rename(real); log.symlink_to(real)
    with pytest.raises(RuntimeError): unit.check_child(row, argv, ROOT, env, log)


def manifest_fixture(tmp_path):
    output = tmp_path / 'artifact-directory'; output.mkdir(mode=0o700)
    row = {'schema': unit.SCHEMA, 'artifact_scope': 'local-unit', 'build_provenance_version': 4,
           'cargo_profile': 'debug', 'platform': 'darwin-' + ('arm64' if unit.platform.machine() == 'arm64' else 'x64'),
           'source_root': str(ROOT), 'producer_record_sha256': 'a' * 64, 'artifact_sha256': 'b' * 64}
    return output, row


@pytest.mark.parametrize('change', ('schema', 'release-scope', 'integration-scope', 'release-profile',
                                   'deploy-profile', 'old-version', 'platform', 'source-root', 'pin', 'missing', 'extra'))
def test_local_manifest_cannot_admit_release_stale_or_other_scope(tmp_path, change):
    output, row = manifest_fixture(tmp_path)
    if change == 'schema': row['schema'] = 'trusted-local-cargo-v1'
    elif change == 'release-scope': row['artifact_scope'] = 'release'
    elif change == 'integration-scope': row['artifact_scope'] = 'local-integration'
    elif change == 'release-profile': row['cargo_profile'] = 'release'
    elif change == 'deploy-profile': row['cargo_profile'] = 'deploy'
    elif change == 'old-version': row['build_provenance_version'] = 3
    elif change == 'platform': row['platform'] = 'ios-arm64'
    elif change == 'source-root': row['source_root'] = '/old/worktree'
    elif change == 'pin': row['producer_record_sha256'] = 'c' * 64
    elif change == 'missing': del row['artifact_sha256']
    else: row['release_qualified'] = True
    unit.save(output / unit.MANIFEST, row)
    with pytest.raises(RuntimeError, match='manifest is not exact'):
        unit.verify(ROOT, output, 'a' * 64)
    assert not (output / unit.FILENAME).exists()


def test_wrong_producer_digest_is_refused_before_record_or_native_consumer(tmp_path):
    output, row = manifest_fixture(tmp_path); unit.save(output / unit.MANIFEST, row)
    (output / 'producer-record.json').write_text('{"inert":true}')
    with pytest.raises(RuntimeError, match='record hash differs'):
        unit.verify(ROOT, output, 'a' * 64)
    assert not (output / unit.FILENAME).exists()


@pytest.mark.parametrize('change', ('retired-unreported', 'retired-prefix-unreported', 'result-bool', 'export-nonstring'))
def test_probe_parser_rederives_forbidden_inventory_and_typed_results(change):
    proof, selected = probe_fixture()
    if change == 'retired-unreported':
        selected['forbidden'] = ['retiredMethod']; proof['exports'].append('retiredMethod'); proof['exports'].sort()
    elif change == 'retired-prefix-unreported':
        proof['exports'].append('connect_norito_offline_cash_retired'); proof['exports'].sort()
    elif change == 'result-bool': proof['required_results']['securePrivateFileAbiVersion'] = True
    else: proof['exports'] = [1]
    with pytest.raises(RuntimeError): unit.check_probe(proof, selected)


def test_closed_environment_binds_actual_apple_tools_without_serialized_or_caller_configuration():
    config = {'cargo': '/stock/rust/bin/cargo', 'rustc': '/stock/rust/bin/rustc', 'rustdoc': '/stock/rust/bin/rustdoc',
              'clang': '/stock/apple/bin/clang', 'sdk': '/stock/sdk', 'developer_dir': '/stock/developer'}
    selected = unit.environment(config)
    assert selected['CC'] == config['clang'] and selected['CXX'] == '/stock/apple/bin/clang++'
    assert selected['AR'] == '/stock/apple/bin/ar' and selected['RANLIB'] == '/stock/apple/bin/ranlib'
    assert selected['NODE_OPTIONS'] == ''
    assert not {'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'RUSTFLAGS', 'RUSTC_WRAPPER',
                'IROHA_GIT_COMMIT_HASH'} & selected.keys()


def test_tool_alias_is_authenticated_as_exact_resolved_tool_not_rejected_as_source_alias(tmp_path):
    tool = tmp_path / 'tool'; tool.write_bytes(b'inert tool bytes')
    alias = tmp_path / 'tool-alias'; alias.symlink_to(tool)
    assert unit.tool_digest(alias) == unit.digest(tool)
    with pytest.raises(RuntimeError): unit.digest(alias)


@pytest.mark.parametrize('profile', ('release', 'deploy'))
def test_producer_release_or_deploy_request_refuses_before_output_or_compiler(tmp_path, monkeypatch, profile):
    output = tmp_path / 'not-created'
    monkeypatch.setenv('IROHA_JS_NATIVE_BUILD_PROFILE', profile)
    with pytest.raises(RuntimeError, match='Debug local-unit'):
        unit.produce(ROOT, ROOT / 'target/cargo-fast/kot', output, {}, True)
    assert not output.exists()


def test_artifact_retention_refuses_existing_destination_before_cow(tmp_path):
    source = tmp_path / 'inert-original.txt'; source.write_bytes(b'inert original, never a native artifact')
    held = tmp_path / 'existing.txt'; held.write_bytes(b'existing bytes must remain')
    source_sha = unit.digest(source); held_sha = unit.digest(held)
    with pytest.raises(RuntimeError, match='already exists'): unit.clone(source, held)
    assert unit.digest(source) == source_sha and unit.digest(held) == held_sha


def test_nonowned_or_nonstrict_local_artifact_directory_refuses_before_manifest(tmp_path):
    output = tmp_path / 'artifact-directory'; output.mkdir(mode=0o755)
    with pytest.raises(RuntimeError, match='owned canonical mode0700'):
        unit.verify(ROOT, output, 'a' * 64)
    assert not (output / unit.MANIFEST).exists()



def test_empty_original_source_is_bound_without_admitting_empty_native_inputs(tmp_path):
    source = tmp_path / 'empty.rs'; source.write_bytes(b'')
    empty_sha = hashlib.sha256(b'').hexdigest()
    assert unit.source_digest(source) == empty_sha
    for reader in (unit.digest, unit.tool_digest, unit.load):
        with pytest.raises(RuntimeError, match='nonempty'):
            reader(source)
    destination = tmp_path / 'not-created.node'
    with pytest.raises(RuntimeError, match='nonempty'):
        unit.clone(source, destination)
    assert not destination.exists()
    source.write_bytes(b'// current source\n')
    assert unit.source_digest(source) != empty_sha


@pytest.mark.parametrize('ancestor', (False, True))
def test_empty_original_source_cannot_traverse_a_leaf_or_directory_alias(tmp_path, ancestor):
    owner = tmp_path / 'owner'; owner.mkdir()
    source = owner / 'empty.rs'; source.write_bytes(b'')
    if ancestor:
        alias = tmp_path / 'alias'; alias.symlink_to(owner, target_is_directory=True)
        selected = alias / source.name
    else:
        selected = tmp_path / 'alias.rs'; selected.symlink_to(source)
    with pytest.raises(RuntimeError):
        unit.source_digest(selected)


def test_original_source_hashing_refuses_a_directory(tmp_path):
    with pytest.raises(RuntimeError, match='regular'):
        unit.source_digest(tmp_path)


def test_original_source_hashing_detects_a_change_during_read(tmp_path, monkeypatch):
    source = tmp_path / 'empty.rs'; source.write_bytes(b'')
    original = unit.custody.original_file; checks = []
    def observed(path):
        checks.append(path)
        if len(checks) == 2:
            source.write_bytes(b'// changed after the read\n')
        return original(path)
    monkeypatch.setattr(unit.custody, 'original_file', observed)
    with pytest.raises(RuntimeError, match='source changed'):
        unit.source_digest(source)
    assert len(checks) == 2


def test_real_dep_info_binds_empty_source_and_still_refuses_drift_or_empty_receipt(tmp_path):
    root = tmp_path / 'root'; root.mkdir()
    source = root / 'empty.rs'; source.write_bytes(b'')
    target = root / 'target'; target.mkdir()
    emitted = target / 'libfixture.rlib'; emitted.write_bytes(b'inert library owner')
    dep = target / 'fixture.d'
    dep.write_text(f'{emitted}: {source}\n')
    retained = root / 'retained'; retained.mkdir()
    message = {'reason': 'compiler-artifact', 'package_id': 'inert fixture',
               'target': {'name': 'fixture', 'kind': ['rlib']}, 'filenames': [str(emitted)]}
    originals = {'empty.rs': unit.source_digest(source)}
    receipt = unit.custody.reconcile(message, root, originals, retained, unit.source_digest, target)
    assert receipt['dep_info'][0]['matched_originals'] == [
        {'path': 'empty.rs', 'sha256': hashlib.sha256(b'').hexdigest()}]
    unit.custody.verify_dep_info([message], [receipt], root, originals, target, retained, unit.source_digest)
    source.write_bytes(b'// changed source\n')
    with pytest.raises(RuntimeError, match='differs from prospective'):
        unit.custody.verify_dep_info([message], [receipt], root, originals, target, retained, unit.source_digest)
    source.write_bytes(b'')
    held = Path(receipt['dep_info'][0]['retained_dep_info']); held.write_bytes(b'')
    receipt['dep_info'][0]['sha256'] = hashlib.sha256(b'').hexdigest()
    with pytest.raises(RuntimeError, match='no dependency rule'):
        unit.custody.verify_dep_info([message], [receipt], root, originals, target, retained, unit.source_digest)
