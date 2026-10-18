"""Portable local-unit policy tests. Fixtures are inert parser data only.

No framework, native build, native execution, or qualification is simulated.
Synthetic dictionaries below exercise policy parsers only.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import norito_bridge_local_unit as unit
import native_sdk_source_custody as custody



@pytest.fixture(autouse=True)
def no_children(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Pure policy tests attempted child/native execution')
    monkeypatch.setattr(unit.subprocess, 'run', forbidden)
    monkeypatch.setattr(unit.subprocess, 'Popen', forbidden)


@pytest.fixture(scope='module')
def originals():
    """Inert parser fixtures; no native bytes, archive or provenance claim."""
    source = {'Cargo.toml': 'a' * 64}
    tools = {'/inert/rustc': 'b' * 64}
    actual = {'reason': 'compiler-artifact', 'target': {'name': 'connect_norito_bridge',
              'crate_types': ['cdylib', 'staticlib', 'rlib']}, 'fresh': True,
              'features': ['privacy-production-enabled'], 'profile': {'test': False},
              'filenames': ['/owned/warm/debug/libconnect_norito_bridge.a']}
    emitter = {'natural_exit': 0, 'finished_unix': 10, 'capture_errors': [], 'source_changes': [],
               'dep_info_errors': [], 'collector_toolchain_changes': [],
               'source_before': source, 'source_after': source,
               'collector_toolchain_before': tools, 'collector_toolchain_after': tools,
               'dep_info': [{'inert': True}], 'emitted': [{'cargo_artifact': actual,
               'sha256': 'c' * 64, 'snapshot': '/owned/retained/lib.dylib'}]}
    capture = {'emitter': '/owned/emitter.json', 'emitter_sha256': 'd' * 64,
               'actual_cargo_artifact': actual, 'target_triple': 'aarch64-apple-darwin',
               'archive_original': actual['filenames'][0], 'snapshot_method': 'clonefile-cow',
               'source_changes': [], 'source_before': source, 'source_after': source,
               'finished_unix': 12, 'native_companion_sha256': 'c' * 64}
    component = {'emitter_path': '/owned/emitter.json', 'emitter_sha256': 'd' * 64,
                 'qualified': True, 'observed_abi_version': 29,
                 'artifact_path': '/owned/retained/lib.dylib', 'artifact_sha256': 'c' * 64,
                 'source_before': source, 'source_after': source,
                 'toolchain_before': tools, 'toolchain_after': tools,
                 'finished_unix': 11, 'export_count': 1}
    for record in (emitter, capture, component):
        record.update(source_scope=unit.SOURCE_SCOPE, source_identity_changes=[], source_changes=[],
                      consumed_source=source, consumed_identities_before={'Cargo.toml': [1, 2, 3, 4, 5]},
                      consumed_identities_after={'Cargo.toml': [1, 2, 3, 4, 5]})
    pins = {'emitter': {'path': '/owned/emitter.json', 'sha256': 'd' * 64}}
    return pins, {'emitter': emitter, 'static_capture': capture, 'component': component}



def semantic(originals, changes=()):
    pins, records = originals
    values = copy.deepcopy(records)
    for role, key, value in changes:
        values[role][key] = value
    return unit.check_record_semantics(values['emitter'], values['static_capture'], values['component'],
                                      Path(pins['emitter']['path']), pins['emitter']['sha256'],
                                      'aarch64-apple-darwin')


def test_inert_emitter_component_static_relationship_parser_positive(originals):
    actual = semantic(originals)
    assert actual == originals[1]['static_capture']['actual_cargo_artifact']
    assert set(actual['target']['crate_types']) == {'cdylib', 'staticlib', 'rlib'}
    assert type(actual['fresh']) is bool


def test_child_environment_keeps_scratch_inside_original_private_capture(tmp_path, monkeypatch):
    root = tmp_path / 'source'; output = root / 'target/qualification/capture'
    output.mkdir(parents=True, mode=0o700); (output / 'temporary').mkdir(mode=0o700)
    monkeypatch.setenv('TMPDIR', '/unrelated/temporary')
    config = {'developer_dir': '/stock/Developer'}
    selected = unit.child_environment(root, output, config)
    assert selected == {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin',
                        'TMPDIR': str(output / 'temporary'), 'LANG': 'C.UTF-8',
                        'LC_ALL': 'C.UTF-8', 'DEVELOPER_DIR': '/stock/Developer'}


@pytest.mark.parametrize('change', ('missing', 'public', 'alias', 'file', 'external-output'))
def test_child_scratch_rejects_nonprivate_or_redirected_storage(tmp_path, change):
    root = tmp_path / 'source'; output = root / 'target/qualification/capture'
    output.mkdir(parents=True, mode=0o700); temporary = output / 'temporary'
    if change == 'public': temporary.mkdir(mode=0o755)
    elif change == 'alias':
        other = output / 'other'; other.mkdir(mode=0o700)
        temporary.symlink_to(other, target_is_directory=True)
    elif change == 'file': temporary.write_bytes(b'not a directory')
    elif change == 'external-output':
        output = tmp_path / 'external'; output.mkdir(mode=0o700)
        (output / 'temporary').mkdir(mode=0o700)
    with pytest.raises((RuntimeError, FileNotFoundError)):
        unit.child_environment(root, output, {'developer_dir': '/stock/Developer'})



@pytest.mark.parametrize('role,key,value', (
    ('emitter', 'natural_exit', False), ('emitter', 'natural_exit', 1),
    ('emitter', 'finished_unix', None), ('emitter', 'capture_errors', ['inert error']),
    ('emitter', 'source_changes', ['changed']), ('emitter', 'dep_info_errors', ['uncovered']),
    ('emitter', 'collector_toolchain_changes', ['changed']), ('emitter', 'source_before', {}),
    ('emitter', 'collector_toolchain_before', {}), ('emitter', 'dep_info', []),
    ('emitter', 'emitted', []), ('static_capture', 'emitter', '/different/emitter.json'),
    ('static_capture', 'emitter_sha256', '0' * 64),
    ('static_capture', 'actual_cargo_artifact', {}), ('static_capture', 'target_triple', 'aarch64-apple-ios'),
    ('static_capture', 'archive_original', '/old/libconnect_norito_bridge.a'),
    ('static_capture', 'snapshot_method', 'fingerprint-old-archive'),
    ('static_capture', 'source_changes', ['changed']), ('static_capture', 'source_before', {}),
    ('static_capture', 'source_after', {}), ('static_capture', 'finished_unix', 1),
    ('static_capture', 'native_companion_sha256', '0' * 64),
    ('component', 'emitter_sha256', '0' * 64), ('component', 'qualified', False),
    ('component', 'observed_abi_version', 24), ('component', 'artifact_path', '/old/lib.dylib'),
    ('component', 'artifact_sha256', '0' * 64), ('component', 'source_before', {}),
    ('component', 'toolchain_before', {}), ('component', 'export_count', 0),
))
def test_wrong_stale_archive_emitter_source_tool_and_component_relationship_refused(originals, role, key, value):
    with pytest.raises(unit.Refused):
        semantic(originals, [(role, key, value)])


def test_current_repository_owned_c_jni_and_privacy_policy_is_exact():
    policy = unit.native_policy(ROOT)
    assert len(policy['c_jni']) == 108
    assert sum(symbol.startswith('connect_norito_kagemusha_wallet_') for symbol in policy['c_jni']) == 27
    assert sum('offline_wallet_KagemushaWalletNativeV1_' in symbol for symbol in policy['c_jni']) == 15
    for method in ('beginInstallation', 'registerInstallation', 'closeInstallation', 'relocateRegistrationSource'):
        assert 'Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_' + method in policy['c_jni']
    assert 'Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletInstalledRuntimeNativeV1_installRuntime' not in policy['c_jni']
    assert "Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletLoadOriginalNativeV1_validate" in policy["c_jni"]
    assert len(policy['privacy']) == 6
    assert 'connect_norito_kagemusha_wallet_setup_v1' in policy['required']
    assert 'Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_setup' in policy['required']
    assert 'connect_norito_kagemusha_wallet_snapshot_v1' in policy['required']
    assert 'Java_org_hyperledger_iroha_sdk_offline_wallet_KagemushaWalletNativeV1_snapshot' in policy['required']
    assert set(policy['c_jni']) <= set(policy['required'])



@pytest.mark.parametrize('scope,platform,configuration,external', (
    ('local-integration', 'macos', 'debug', False), ('release', 'macos', 'debug', False),
    ('local-unit', 'ios', 'debug', False), ('local-unit', 'macos', 'release', False),
    ('local-unit', 'macos', 'debug', True),
))
def test_release_ios_and_other_scope_refusal(scope, platform, configuration, external):
    with pytest.raises(unit.Refused):
        unit.host_policy(scope, platform, configuration, external)


def test_local_unit_debug_host_is_the_only_policy_positive():
    unit.host_policy('local-unit', 'macos', 'debug')


def artifact_directory(tmp_path):
    """Inert filesystem fixture for artifact path custody, never a copied checkout."""
    root = tmp_path.resolve() / 'root'
    parent = root / 'target' / 'qualification' / 'native-sdk'
    parent.mkdir(parents=True, mode=0o700)
    return root, parent


def test_artifact_output_stays_create_only_inside_owned_checkout_lane(tmp_path):
    root, parent = artifact_directory(tmp_path)
    output = parent / 'host'
    unit.artifact_root(root, output)
    assert not output.exists()
    output.mkdir(mode=0o700)
    with pytest.raises(unit.Refused, match='create-only'):
        unit.artifact_root(root, output)


@pytest.mark.parametrize('relative', ('../outside', 'crates/generated', 'target/other',
                                    'target/qualification'))
def test_artifact_output_refuses_external_and_source_destinations(tmp_path, relative):
    root, _ = artifact_directory(tmp_path)
    output = (root / relative).resolve()
    with pytest.raises(unit.Refused, match='target/qualification'):
        unit.artifact_root(root, output)
    assert not output.exists() or output == root / 'target' / 'qualification'


def test_artifact_output_refuses_public_parent_and_symbolic_ancestors(tmp_path):
    root, parent = artifact_directory(tmp_path)
    parent.chmod(0o755)
    with pytest.raises(unit.Refused, match='mode0700'):
        unit.artifact_root(root, parent / 'host')
    parent.chmod(0o700)
    alias = parent.parent / 'alias'
    alias.symlink_to(parent, target_is_directory=True)
    with pytest.raises(unit.Refused, match='canonical'):
        unit.artifact_root(root, alias / 'host')
    output = parent / 'host'
    output.symlink_to(parent / 'missing')
    with pytest.raises(unit.Refused, match='create-only'):
        unit.artifact_root(root, output)


def test_artifact_output_refuses_noncanonical_and_relative_paths(tmp_path):
    root, parent = artifact_directory(tmp_path)
    with pytest.raises(unit.Refused, match='absolute canonical'):
        unit.artifact_root(root, Path('target/qualification/host'))
    with pytest.raises(unit.Refused, match='absolute canonical'):
        unit.artifact_root(root, parent / '..' / 'host')


def command_fixture():
    output = Path('/owned/inert-output')
    config = {'python': '/tools/python3.12', 'clang': '/tools/clang', 'ranlib': '/tools/ranlib',
              'xcodebuild': '/tools/xcodebuild', 'developer_dir': '/tools/Developer',
              'sdk': '/tools/Developer/MacOSX.sdk', 'deployment_target': '13.0',
              'actual_archive_original': '/owned/warm/debug/libconnect_norito_bridge.a',
              'messages_path': '/owned/actual-cargo.jsonl'}
    environment = {'DEVELOPER_DIR': '/tools/Developer'}
    expected = unit.expected_commands(ROOT, output, 'aarch64-apple-darwin', config)
    commands = [{'argv': argv, 'executable': executable, 'environment': environment,
                 'cwd': str(ROOT), 'started_unix': i + 1, 'finished_unix': i + 1.5,
                 'natural_exit': 0, 'log': str(output / 'staging' / name), 'log_sha256': 'a' * 64}
                for i, (argv, executable, name) in enumerate(expected)]
    tools = {config[name]: 'b' * 64 for name in ('python', 'clang', 'ranlib', 'xcodebuild')}
    return output, config, environment, commands, tools


def test_exact_five_recipe_relationships_are_pure_and_complete():
    output, config, environment, commands, tools = command_fixture()
    unit.verify_commands(ROOT, output, 'aarch64-apple-darwin', config, environment, commands, tools)


@pytest.mark.parametrize('index,field,value', (
    (0, 'argv', ['/tools/python3.12', '/different/normalizer.py']),
    (1, 'executable', '/different/ranlib'), (2, 'argv', ['/tools/clang', 'empty-stub.c']),
    (3, 'argv', ['/different/consumer']), (4, 'argv', ['/tools/xcodebuild', '-archive']),
    (0, 'environment', {}), (1, 'cwd', '/different'), (2, 'natural_exit', 1),
    (3, 'finished_unix', 0), (4, 'started_unix', 0), (4, 'log', '/different/log'),
))
def test_child_argv_tool_environment_natural_order_and_logs_are_not_relabelled(index, field, value):
    output, config, environment, commands, tools = command_fixture()
    commands[index][field] = value
    with pytest.raises(unit.Refused):
        unit.verify_commands(ROOT, output, 'aarch64-apple-darwin', config, environment, commands, tools)


def info_fixture():
    return {'CFBundlePackageType': 'XFWK', 'XCFrameworkFormatVersion': '1.0',
            'AvailableLibraries': [{'HeadersPath': 'Headers', 'LibraryIdentifier': 'macos-arm64',
                                   'LibraryPath': 'libNoritoBridge.a', 'SupportedArchitectures': ['arm64'],
                                   'SupportedPlatform': 'macos'}]}


def test_exact_thin_host_metadata_is_only_an_inert_parser_positive():
    info = info_fixture()
    unit.check_info(info, 'aarch64-apple-darwin')
    info['AvailableLibraries'][0]['BinaryPath'] = 'libNoritoBridge.a'
    unit.check_info(info, 'aarch64-apple-darwin')


@pytest.mark.parametrize('field,value', (
    ('SupportedPlatform', 'ios'), ('SupportedArchitectures', ['arm64', 'x86_64']),
    ('LibraryIdentifier', 'macos-arm64_x86_64'), ('LibraryPath', 'empty.a'),
    ('BinaryPath', 'other.a'), ('HeadersPath', '../Headers'), ('Unexpected', True),
))
def test_plist_cannot_invent_ios_universal_headers_or_other_archive(field, value):
    info = info_fixture(); info['AvailableLibraries'][0][field] = value
    with pytest.raises(unit.Refused):
        unit.check_info(info, 'aarch64-apple-darwin')


def test_tool_alias_resolution_preserves_spelling_without_weakening_archive_policy(tmp_path):
    target = tmp_path / 'real-tool'; target.write_bytes(b'inert tool bytes; never executed')
    alias = tmp_path / 'opt-tool'; alias.symlink_to(target)
    assert unit.tool_digest(alias) == unit.digest(target)
    with pytest.raises(unit.Refused):
        unit.digest(alias)


def test_wrong_receipt_digest_and_duplicate_json_cannot_be_resealed(tmp_path):
    path = tmp_path / 'inert.json'; path.write_bytes(b'{"scope":"local-unit","scope":"release"}')
    with pytest.raises(unit.Refused, match='duplicate'):
        unit.load(path)
    with pytest.raises(unit.Refused, match='digest differs'):
        unit.load(path, '0' * 64)


def test_no_native_packaging_without_explicit_recipe_acknowledgement(tmp_path):
    with pytest.raises(unit.Refused, match='local-unit recipe acknowledgement'):
        unit.produce(ROOT, {}, tmp_path / 'uncreated-output', {}, False)
    assert not (tmp_path / 'uncreated-output').exists()


def test_original_crypto_consumer_is_preserved_under_current_symbol_wrapper():
    source = unit.consumer_source(ROOT)
    assert '#define main iroha_original_crypto_main' in source
    assert 'return iroha_original_crypto_main();' in source
    for check in ('check_mldsa_ffi()', 'sha3_expected', 'shake_expected', 'PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec'):
        assert check in source


@pytest.mark.parametrize('raw', (
    '{"reason":"build-finished","success":false}',
    '{"reason":"build-finished","success":true}\n{"reason":"build-finished","success":true}',
    '{"reason":"compiler-artifact"}\n[cargo-fast] late diagnostics\n{"reason":"build-finished","success":true}',
    'not Cargo JSON', '[]',
))
def test_actual_cargo_stream_needs_one_successful_terminal_and_only_preceding_wrapper_diagnostics(raw):
    with pytest.raises((ValueError, RuntimeError)):
        custody.cargo_messages(raw)


def test_cargo_message_parser_positive_is_inert_data_only():
    raw = '[cargo-fast] inert banner\n{"reason":"compiler-artifact"}\n{"reason":"build-finished","success":true}'
    messages = custody.cargo_messages(raw, unit.duplicates)
    assert len(messages) == 2
    assert messages[-1] == {'reason': 'build-finished', 'success': True}



def test_make_dependency_words_are_not_shell_evaluated():
    assert custody.make_words(r'a\ b.rs c\\d.rs $(literal)') == ['a b.rs', 'c\\d.rs', '$(literal)']
    with pytest.raises(RuntimeError):
        custody.make_words('unfinished\\')


def manifest_fixture():
    return {'schema': unit.SCHEMA, 'artifact_scope': 'local-unit', 'purpose': unit.PURPOSE,
            'version': '0.1.0', 'native_bridge_abi_version': 29,
            'target_triple': 'aarch64-apple-darwin', 'hashes': {'macos-arm64': 'a' * 64},
            'producer_record': '/owned/producer-record.json', 'producer_record_sha256': 'b' * 64,
            'source_inputs': {'inert-source': 'c' * 64}, 'tool_inputs': {'inert-tool': 'd' * 64},
            'receipt_inputs': {'inert-receipt': 'e' * 64}}


@pytest.mark.parametrize('field,value', (
    ('artifact_scope', 'release'), ('artifact_scope', 'local-integration'),
    ('schema', 'historical-schema'), ('purpose', 'publication'), ('native_bridge_abi_version', 24),
    ('target_triple', 'aarch64-apple-ios'), ('producer_record', '/other/producer-record.json'),
    ('producer_record_sha256', '0' * 64), ('source_inputs', {}), ('tool_inputs', {}),
    ('receipt_inputs', {}), ('hashes', {'macos-arm64_x86_64': 'a' * 64}),
))
def test_wrong_local_manifest_scope_abi_producer_and_inventory_refused_early(field, value):
    manifest = manifest_fixture(); manifest[field] = value
    with pytest.raises(unit.Refused):
        unit.check_manifest(manifest, 'aarch64-apple-darwin', Path('/owned/producer-record.json'), 'b' * 64)


def test_native_source_contract_only_selects_repository_owned_bridge_or_real_napi():
    assert custody.NATIVE_PACKAGE_OWNERS == {'connect_norito_bridge', 'iroha_js_host'}
    with pytest.raises(RuntimeError, match='Unreviewed native package owner'):
        custody.capture({}, ROOT, unit.digest, 'caller-selected-private-helper')


def dep_fixture(tmp_path):
    root = tmp_path / 'root'; root.mkdir()
    source = root / 'source.rs'; source.write_bytes(b'// inert pure dependency parser fixture\n')
    output = root / 'target'; output.mkdir()
    retained = tmp_path / 'retained'; retained.mkdir()
    artifact = output / 'libinert.rlib'
    actual = str(output / 'inert.d')
    held = retained / (hashlib.sha256(actual.encode()).hexdigest() + '.d')
    held.write_text(str(artifact) + ': source.rs\n')
    sha = unit.digest(source)
    messages = [{'reason': 'compiler-artifact', 'package_id': 'inert-owner',
                 'target': {'kind': ['lib']}, 'filenames': [str(artifact)]}]
    receipts = [{'package_id': 'inert-owner', 'target': {'kind': ['lib']}, 'dep_info': [
        {'actual_dep_info': actual, 'retained_dep_info': str(held), 'sha256': unit.digest(held),
         'matched_originals': [{'path': 'source.rs', 'sha256': sha}], 'actual_generated_outputs': []}]}]
    return messages, receipts, root, {'source.rs': sha}, output, retained


def test_retained_actual_dependency_projection_rederives_original_source_bytes(tmp_path):
    custody.verify_dep_info(*dep_fixture(tmp_path), unit.digest)


def test_compiler_lexical_include_parent_normalizes_only_after_original_ancestry_checks(tmp_path):
    messages, receipts, root, originals, output, retained = dep_fixture(tmp_path)
    (root / 'nested').mkdir()
    held = Path(receipts[0]['dep_info'][0]['retained_dep_info'])
    held.write_text(messages[0]['filenames'][0] + ': nested/../source.rs\n')
    receipts[0]['dep_info'][0]['sha256'] = unit.digest(held)
    custody.verify_dep_info(messages, receipts, root, originals, output, retained, unit.digest)


@pytest.mark.parametrize('change', ('missing', 'package', 'target', 'owner', 'hash', 'matched', 'generated', 'source'))
def test_retained_depinfo_missing_substituted_stale_or_generated_original_refused(tmp_path, change):
    messages, receipts, root, originals, output, retained = dep_fixture(tmp_path)
    item = receipts[0]['dep_info'][0]
    if change == 'missing': receipts.clear()
    elif change == 'package': receipts[0]['package_id'] = 'foreign'
    elif change == 'target': receipts[0]['target'] = {'kind': ['custom-build']}
    elif change == 'owner': item['actual_dep_info'] = str(output / 'foreign.d')
    elif change == 'hash': item['sha256'] = '0' * 64
    elif change == 'matched': item['matched_originals'] = []
    elif change == 'generated': item['actual_generated_outputs'] = [{'path': 'source.rs', 'sha256': originals['source.rs']}]
    elif change == 'source': (root / 'source.rs').write_bytes(b'changed inert source')
    with pytest.raises(RuntimeError):
        custody.verify_dep_info(messages, receipts, root, originals, output, retained, unit.digest)


@pytest.mark.parametrize('option,value,diagnostic', (
    ('--consumer-platform', 'ios', 'cannot target iOS'),
    ('--consumer-configuration', 'release', 'cannot enter Release'),
))
def test_verifier_cli_refuses_release_ios_before_any_artifact_or_native_use(monkeypatch, capsys, option, value, diagnostic):
    monkeypatch.setattr(sys, 'argv', ['norito_bridge_local_unit.py', 'verify', '--root', str(ROOT), option, value])
    assert unit.cli() == 3
    assert diagnostic in capsys.readouterr().out


def projection_fixture(tmp_path):
    root = tmp_path / 'worktree'; root.mkdir()
    manifest = root / 'Cargo.toml'; manifest.write_text('[package]\nname="connect_norito_bridge"\n')
    originals = {'Cargo.toml': unit.digest(manifest), 'source.rs': 'a' * 64,
                 'README.md': 'b' * 64, 'fixtures/runtime.json': 'c' * 64}
    metadata = {'workspace_root': str(root), 'workspace_members': ['bridge'],
                'packages': [{'id': 'bridge', 'name': 'connect_norito_bridge', 'source': None,
                              'manifest_path': str(manifest)}],
                'resolve': {'nodes': [{'id': 'bridge', 'deps': []}]}}
    receipts = [{'dep_info': [{'matched_originals': [{'path': 'source.rs', 'sha256': 'a' * 64}]}]}]
    return root, metadata, originals, receipts


def test_local_consumed_custody_preserves_broad_docs_change_as_diagnostic_only(tmp_path):
    root, metadata, originals, receipts = projection_fixture(tmp_path)
    current = dict(originals, **{'README.md': 'd' * 64})
    selected = custody.consumed_source_projection(metadata, root, originals, current, receipts)
    assert selected == {name: originals[name] for name in ('Cargo.toml', 'source.rs', 'fixtures/runtime.json')}
    assert originals['README.md'] == 'b' * 64


@pytest.mark.parametrize('change', ('compiled', 'manifest', 'runtime', 'runtime-add', 'runtime-remove', 'workspace', 'owner'))
def test_local_consumed_custody_refuses_runtime_compiler_manifest_or_identity_drift(tmp_path, change):
    root, metadata, originals, receipts = projection_fixture(tmp_path)
    current = dict(originals)
    if change == 'compiled': current['source.rs'] = 'd' * 64
    elif change == 'manifest': current['Cargo.toml'] = 'd' * 64
    elif change == 'runtime': current['fixtures/runtime.json'] = 'd' * 64
    elif change == 'runtime-add': current['fixtures/uncaptured.json'] = 'd' * 64
    elif change == 'runtime-remove': del current['fixtures/runtime.json']
    elif change == 'workspace': metadata['workspace_root'] = '/different/worktree'
    elif change == 'owner': metadata['packages'][0]['name'] = 'other_native_owner'
    with pytest.raises(RuntimeError):
        custody.consumed_source_projection(metadata, root, originals, current, receipts)


def test_all_phases_retain_unused_broad_drift_without_relabelling_consumed_inputs(originals):
    pins, values = originals
    data = copy.deepcopy(values)
    name = 'crates/iroha_core/src/unused.rs'
    for index, record in enumerate(data.values()):
        record['source_before'] = dict(record['source_before'], **{name: str(index) * 64})
        record['source_after'] = dict(record['source_after'], **{name: str(index + 1) * 64})
        record.update(source_changes=[name], source_identity_changes=[name])
    # Parser acceptance grants no admission: actual dep-info and the full
    # compiler/native/runtime/manifest projection must still be independently checked.
    unit.check_record_semantics(data['emitter'], data['static_capture'], data['component'],
                               Path(pins['emitter']['path']), pins['emitter']['sha256'],
                               'aarch64-apple-darwin')
    assert data['emitter']['source_after'] != data['static_capture']['source_after']


@pytest.mark.parametrize('change', ('missing-scope', 'false-delta', 'consumed-byte', 'membership',
                                  'identity', 'hidden-identity', 'missing-projection'))
def test_consumed_contract_refuses_relabelled_broad_or_selected_observations(originals, change):
    pins, values = originals; data = copy.deepcopy(values)
    capture = data['static_capture']
    if change == 'missing-scope': del capture['source_scope']
    elif change == 'false-delta': capture['source_changes'] = ['unrelated.md']
    elif change == 'consumed-byte': capture['source_after'] = {'Cargo.toml': 'e' * 64}
    elif change == 'membership': capture['source_before'] = capture['source_after'] = {}
    elif change == 'identity': capture['consumed_identities_after'] = {'Cargo.toml': [1, 9, 3, 4, 5]}
    elif change == 'hidden-identity': capture.update(source_changes=['Cargo.toml'], source_identity_changes=['Cargo.toml'])
    elif change == 'missing-projection': del capture['consumed_source']
    with pytest.raises(unit.Refused):
        unit.check_record_semantics(data['emitter'], capture, data['component'],
                                   Path(pins['emitter']['path']), pins['emitter']['sha256'],
                                   'aarch64-apple-darwin')


@pytest.mark.parametrize('phase', ('emitter', 'capture', 'component'))
@pytest.mark.parametrize('change', ('drop-compiled', 'drop-manifest', 'drop-runtime', 'invent-unused'))
def test_admission_rederives_each_record_projection_instead_of_trusting_claimed_scope(tmp_path, phase, change):
    root, metadata, originals, receipts = projection_fixture(tmp_path)
    selected = custody.consumed_source_projection(metadata, root, originals, originals, receipts)
    records = {name: {'source_before': originals, 'source_after': originals,
                     'consumed_source': dict(selected), 'dep_info': receipts}
               for name in ('emitter', 'capture', 'component')}
    unit.verify_record_source_projections(metadata, root, *records.values())
    forged = records[phase]['consumed_source']
    if change == 'drop-compiled': del forged['source.rs']
    elif change == 'drop-manifest': del forged['Cargo.toml']
    elif change == 'drop-runtime': del forged['fixtures/runtime.json']
    else: forged['README.md'] = originals['README.md']
    with pytest.raises(unit.Refused, match='projection differs'):
        unit.verify_record_source_projections(metadata, root, *records.values())


def test_current_admission_rejects_same_bytes_with_replaced_consumed_identity(tmp_path, monkeypatch):
    root, metadata, originals, receipts = projection_fixture(tmp_path)
    source = root / 'source.rs'; source.write_bytes(b'// current original\n')
    originals['source.rs'] = unit.digest(source)
    receipts[0]['dep_info'][0]['matched_originals'][0]['sha256'] = originals['source.rs']
    selected = custody.consumed_source_projection(metadata, root, originals, originals, receipts)
    # The mocked broad recapture isolates the real selected-file identity check.
    # Other selected entries have inert identities and are excluded in this test.
    value = unit.regular(source)
    identity = [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    record = {'source_before': originals, 'metadata_sha256': 'a' * 64, 'dep_info': receipts,
              'consumed_source': selected, 'consumed_identities_before': {'source.rs': identity}}
    monkeypatch.setattr(unit, 'recapture_native', lambda *args: dict(originals))
    monkeypatch.setattr(unit, 'load', lambda *args: metadata)
    unit.verify_native_inputs(root, root, record)
    replacement = root / 'replacement'; replacement.write_bytes(source.read_bytes()); replacement.replace(source)
    with pytest.raises(unit.Refused, match='current consumed source identity changed'):
        unit.verify_native_inputs(root, root, record)


@pytest.mark.parametrize('target,accepted', (('../dist/NoritoBridge.xcframework', True), ('../old-native-artifact', False)))
def test_swift_guard_binds_only_declared_release_selector_link_without_adopting_target(tmp_path, monkeypatch, target, accepted):
    root = tmp_path / 'root'; (root / 'IrohaSwift').mkdir(parents=True)
    (root / 'IrohaSwift/NoritoBridge.xcframework').symlink_to(target)
    monkeypatch.setattr(unit, 'POLICY_INPUTS', [])
    monkeypatch.setattr(unit, 'HEADER_INPUTS', {})
    if accepted:
        assert unit.swift_sources(root) == {'@symlink:IrohaSwift/NoritoBridge.xcframework': hashlib.sha256(target.encode()).hexdigest()}
    else:
        with pytest.raises(unit.Refused): unit.swift_sources(root)


def test_producer_cli_forwards_acknowledgement_to_exact_recipe_without_native_execution(tmp_path, monkeypatch, capsys):
    pins = tmp_path / 'pins.json'; pins.write_text('{"inert":true}')
    config = tmp_path / 'config.json'; config.write_text('{"tool":"inert"}')
    output = tmp_path / 'not-created'
    observed = []
    def observe(root, selected_pins, selected_output, selected_config, acknowledge):
        observed.append((root, selected_pins, selected_output, selected_config, acknowledge))
        return selected_output
    monkeypatch.setattr(unit, 'produce', observe)
    monkeypatch.setattr(sys, 'argv', ['norito_bridge_local_unit.py', 'produce', '--root', str(ROOT),
                                     '--pins', str(pins), '--config', str(config), '--output', str(output),
                                     '--acknowledge-local-unit-recipe'])
    assert unit.cli() == 0
    assert observed == [(ROOT, {'inert': True}, output, {'tool': 'inert'}, True)]
    assert not output.exists()
    assert str(output) in capsys.readouterr().out
