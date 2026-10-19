"""Native source containment failure controls; no mocked build qualifies an artifact."""
import io
import json
import tarfile
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_native_source_inputs as audit


@pytest.fixture
def selected(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'Cargo.lock').write_text('')
    monkeypatch.setattr(audit, 'ROOT', root)
    for name, relative in [('BUILD_RS', 'crates/iroha_plonk/build.rs'),
                           ('HELPER', 'crates/iroha_plonk/build_support/source_identity.rs'),
                           ('GENERATED', 'crates/iroha_plonk/src/keys/keygen/builtin/generated.rs'),
                           ('DRIVER', 'scripts/native_source_snapshot.rs')]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
        monkeypatch.setattr(audit, name, path)
    source = root / 'crates/example/src/lib.rs'
    source.parent.mkdir(parents=True)
    source.write_text('pub fn example() {}')
    watched = {audit.BUILD_RS, audit.HELPER, audit.GENERATED, audit.DRIVER, source}
    out = root / 'target/release/build/iroha_plonk-1234/out'
    out.mkdir(parents=True)
    digest = 'ab' * 32
    identity = out / 'native_source_identity.rs'
    identity.write_text('NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;\n'
                        'BUILTIN_TARGET_SUPPORTED: bool = true;\n'
                        'NATIVE_SOURCE_TARGET: &str = "aarch64-apple-darwin";\n'
                        'CURRENT_NATIVE_SOURCE_DIGEST: [u8; 32] = ['
                        + ', '.join(['171'] * 32) + '];\n')
    watcher = out / 'native-source-rescan-required'
    output = out.parent / 'output'
    output.write_text(''.join('cargo:rerun-if-changed=' + str(p) + '\n'
                              for p in sorted(watched | {watcher})))
    depfile = tmp_path / 'selected.d'
    depfile.write_text('artifact: ' + ' '.join(str(p) for p in
                      [source, audit.GENERATED, identity, watcher]) + '\n')
    tool = tmp_path / 'source-snapshot'
    tool.write_text('unused mocked tool')
    tool.with_name('source-snapshot-build.json').write_text('{}')
    monkeypatch.setattr(audit, 'actual_snapshot', lambda _: (digest, watched))
    args = SimpleNamespace(output=tmp_path / 'audit.json')
    def run(events=None):
        return audit.audit(args, events or [], {depfile}, {out}, [], tool,
                           digest, digest, watched)
    return SimpleNamespace(root=root, source=source, watched=watched, out=out,
                           digest=digest, identity=identity, watcher=watcher,
                           build_output=output, depfile=depfile, args=args, run=run)


def test_selected_inputs_and_exact_generated_exceptions_pass(selected):
    selected.run()
    result = json.loads(selected.args.output.read_text())
    assert result['passed'] is True
    assert result['sourceDigest'] == selected.digest
    assert result['canonicalInputs'] == [str(selected.source)]
    assert {x['path'] for x in result['generatedExceptions']} == {
        str(selected.identity), str(audit.GENERATED)}


@pytest.mark.parametrize('relative', ['python/unrelated/input.json',
                                     'target/release/build/unknown/out/source.rs'])
def test_omitted_canonical_or_unknown_generated_input_fails(selected, relative):
    missing = selected.root / relative
    missing.parent.mkdir(parents=True, exist_ok=True)
    missing.write_text('compiler consumed this')
    selected.depfile.write_text(selected.depfile.read_text().rstrip() + ' ' + str(missing) + '\n')
    with pytest.raises(SystemExit, match='1'):
        selected.run()
    result = json.loads(selected.args.output.read_text())
    assert result['passed'] is False
    assert result['omittedCanonicalInputs'] == [str(missing)]


@pytest.mark.parametrize('old,new,message', [
    ('171', '172', 'Compiled digest mismatch'),
    ('NATIVE_SOURCE_CLOSURE_COMPLETE: bool = true;',
     'NATIVE_SOURCE_CLOSURE_COMPLETE: bool = false;', 'incomplete source closure'),
])
def test_compiled_identity_must_match_complete_current_census(selected, old, new, message):
    selected.identity.write_text(selected.identity.read_text().replace(old, new))
    with pytest.raises(ValueError, match=message):
        selected.run()


def test_build_script_census_must_equal_actual_current_census(selected):
    selected.build_output.write_text(selected.build_output.read_text().replace(
        'cargo:rerun-if-changed=' + str(selected.source) + '\n', ''))
    with pytest.raises(ValueError, match='census.*differ'):
        selected.run()


def test_rescan_marker_must_remain_absent(selected):
    selected.watcher.touch()
    with pytest.raises(ValueError, match='absent rescan watcher exists'):
        selected.run()


def test_excluded_owner_symlink_cannot_become_external_dependency(selected, tmp_path):
    external = tmp_path / 'outside.rs'
    external.write_text('external')
    link = selected.root / 'python/omitted-link.rs'
    link.parent.mkdir()
    link.symlink_to(external)
    selected.depfile.write_text('artifact: ' + str(link) + '\n')
    with pytest.raises(ValueError, match='compiler input traverses a symlink'):
        selected.run()


def test_regular_lexical_parent_alias_and_generated_paths_are_preserved(selected):
    alias = selected.source.parent / '../src/lib.rs'
    assert audit.resolved(alias) == selected.source
    assert audit.resolved(selected.identity) == selected.identity


def test_parent_segment_cannot_hide_a_symlink_escape(selected, tmp_path):
    outside = tmp_path / 'outside'
    (outside / 'nested').mkdir(parents=True)
    (outside / 'Cargo.lock').write_text('different input')
    (selected.root / 'link').symlink_to(outside / 'nested', target_is_directory=True)
    with pytest.raises(ValueError, match='compiler input traverses a symlink'):
        audit.resolved(selected.root / 'link/../Cargo.lock')


def test_source_changes_during_audit_fail(selected, monkeypatch):
    monkeypatch.setattr(audit, 'actual_snapshot', lambda _: ('cd' * 32, selected.watched))
    with pytest.raises(ValueError, match='changed during containment'):
        selected.run()


def test_canonical_generated_source_requires_its_generator_and_asset(selected):
    root = selected.root / 'crates/ivm'
    root.mkdir()
    for name in ['build.rs', 'Cargo.toml']:
        (root / name).write_text(name)
        selected.watched.add(root / name)
    out = selected.root / 'target/release/build/ivm-1234/out'
    out.mkdir(parents=True)
    package = 'path+file://' + str(root) + '#0.1.0'
    events = [
        {'reason': 'build-script-executed', 'package_id': package, 'out_dir': str(out)},
        {'reason': 'compiler-artifact', 'package_id': package,
         'target': {'kind': ['custom-build'], 'src_path': str(root / 'build.rs')},
         'manifest_path': str(root / 'Cargo.toml')},
    ]
    with pytest.raises(ValueError, match='generator input omitted'):
        audit.canonical_generated_inputs(events, selected.watched)


def test_external_generated_dependency_version_is_not_silently_upgraded(selected):
    (selected.root / 'Cargo.lock').write_text('')
    with pytest.raises(ValueError, match='Unreviewed generated dependency version'):
        audit.external_generated_inputs([
            {'reason': 'build-script-executed',
             'package_id': 'registry+https://github.com/rust-lang/crates.io-index#serde@9.9.9'}])


def test_snapshot_rejects_changed_maintained_driver(tmp_path, monkeypatch):
    helper, driver, tool = [tmp_path / name for name in ['helper.rs', 'driver.rs', 'source-snapshot']]
    for path in [helper, driver, tool]:
        path.write_text(path.name)
    monkeypatch.setattr(audit, 'HELPER', helper)
    monkeypatch.setattr(audit, 'DRIVER', driver)
    tool.with_name('source-snapshot-build.json').write_text(json.dumps({
        'helperPath': str(helper), 'helperSha256': audit.sha(helper),
        'driverPath': str(driver), 'driverSha256': audit.sha(driver),
        'binarySha256': audit.sha(tool)}))
    driver.write_text('changed driver')
    monkeypatch.setattr(audit.subprocess, 'run', lambda *a, **k: pytest.fail('must not execute'))
    with pytest.raises(ValueError, match='rebuilt from the current maintained helper'):
        audit.actual_snapshot(tool)


def test_snapshot_uses_explicit_root_and_current_pins(tmp_path, monkeypatch):
    helper, driver, tool = [tmp_path / name for name in ['helper.rs', 'driver.rs', 'source-snapshot']]
    for path in [helper, driver, tool]:
        path.write_text(path.name)
    monkeypatch.setattr(audit, 'HELPER', helper)
    monkeypatch.setattr(audit, 'DRIVER', driver)
    tool.with_name('source-snapshot-build.json').write_text(json.dumps({
        'helperPath': str(helper), 'helperSha256': audit.sha(helper),
        'driverPath': str(driver), 'driverSha256': audit.sha(driver),
        'binarySha256': audit.sha(tool)}))
    def execute(command, **kwargs):
        assert command == [str(tool), str(audit.ROOT)]
        return subprocess.CompletedProcess(command, 0, 'digest=' + 'ab' * 32 + '\nwatch=' + str(helper), '')
    monkeypatch.setattr(audit.subprocess, 'run', execute)
    assert audit.actual_snapshot(tool) == ('ab' * 32, {helper})


def test_evaluator_cannot_guess_a_host_dependency(tmp_path):
    with pytest.raises(ValueError, match='exact selected host plonk'):
        audit.build_snapshot_tool(tmp_path, [])


@pytest.fixture
def native_artifact(tmp_path, monkeypatch):
    root = tmp_path / 'workspace'
    monkeypatch.setattr(audit, 'ROOT', root)
    source = root / 'crates/ordinary_sdk/src/lib.rs'
    source.parent.mkdir(parents=True)
    source.write_text('pub fn sdk() {}')
    manifest = source.parent.parent / 'Cargo.toml'
    manifest.write_text('[package]\nname = "ordinary_sdk"\nversion = "0.1.0"\n')
    name = 'ordinary_sdk'
    def arrange(types=('staticlib',), tag='-1234abcd', dynamic='.dylib', external=False):
        profile = tmp_path / 'fixed-native-lane/release' if external else root / 'target/warm/target/release'
        (profile / 'deps').mkdir(parents=True)
        extensions = {'staticlib': '.a', 'cdylib': dynamic, 'rlib': '.rlib'}
        outputs, deps = [], []
        for kind in types:
            output = profile / ('lib' + name + extensions[kind])
            dependency = profile / 'deps' / ('lib' + name + tag + extensions[kind])
            output.write_bytes(b'native fixture for ' + kind.encode())
            dependency.write_bytes(output.read_bytes())
            outputs.append(output)
            deps.append(dependency)
        direct = profile / 'deps' / (name + tag + '.d')
        aggregate = profile / ('lib' + name + '.d')
        direct.write_text(''.join(str(path) + ': ' + str(source) + '\n\n'
                                 for path in [direct, *deps]) + str(source) + ':\n# env-dep:SDKROOT=/sdk\n')
        aggregate.write_text(str(outputs[-1]) + ': ' + str(source) + '\n')
        event = {'reason': 'compiler-artifact', 'manifest_path': str(manifest),
                 'target': {'name': name, 'kind': list(types), 'crate_types': list(types), 'src_path': str(source)},
                 'filenames': [str(path) for path in outputs]}
        return SimpleNamespace(event=event, outputs=outputs, deps=deps, direct=direct,
                               aggregate=aggregate, source=source, profile=profile)
    return arrange


@pytest.mark.parametrize('types,tag,dynamic', [
    (('staticlib',), '-1234abcd', '.dylib'),
    (('cdylib', 'staticlib', 'rlib'), '', '.dylib'),
    (('cdylib', 'staticlib', 'rlib'), '-fedc4321', '.so'),
])
def test_top_level_native_outputs_use_exact_direct_and_aggregate(native_artifact, types, tag, dynamic):
    selected = native_artifact(types, tag, dynamic)
    records = []
    assert audit.artifact_depfiles(selected.event, records) == {selected.direct, selected.aggregate}
    assert len(records) == 1 and len(records[0]['outputs']) == len(types)
    assert {row['output'] for row in records[0]['outputs']} == set(selected.event['filenames'])
    assert audit.native_artifact_depfiles(selected.event)[1] == records[0]


def test_ordinary_depfile_selection_is_unchanged(native_artifact):
    selected = native_artifact()
    selected.event['filenames'] = [str(selected.deps[0])]
    records = []
    assert audit.artifact_depfiles(selected.event, records) == {selected.direct}
    assert records == []


def test_native_outputs_can_use_an_external_fixed_target_directory(native_artifact):
    selected = native_artifact(external=True)
    assert not selected.profile.is_relative_to(audit.ROOT)
    assert audit.artifact_depfiles(selected.event) == {selected.direct, selected.aggregate}


def test_unrelated_nonmatching_native_output_is_not_selected(native_artifact):
    selected = native_artifact()
    (selected.profile / 'deps/libordinary_sdk-deadbeef.a').write_bytes(b'stale')
    assert audit.artifact_depfiles(selected.event) == {selected.direct, selected.aggregate}


@pytest.mark.parametrize('change', ['mismatch', 'missing', 'ambiguous', 'symlink', 'different_family'])
def test_every_native_companion_must_bind_uniquely(native_artifact, change):
    selected = native_artifact(('cdylib', 'staticlib', 'rlib'), '')
    companion = selected.deps[1]
    if change == 'mismatch':
        companion.write_bytes(b'stale archive')
    elif change == 'missing':
        companion.unlink()
    elif change == 'ambiguous':
        companion.with_name('libordinary_sdk-deadbeef.a').write_bytes(companion.read_bytes())
    elif change == 'different_family':
        companion.rename(companion.with_name('libordinary_sdk-deadbeef.a'))
    else:
        companion.unlink()
        companion.symlink_to(selected.outputs[1])
    with pytest.raises(ValueError):
        audit.artifact_depfiles(selected.event)


@pytest.mark.parametrize('change', ['wrong_target', 'missing_source', 'different_inputs', 'extra_rule',
                                  'duplicate_rule', 'malformed', 'unknown_phony', 'missing', 'symlink'])
def test_native_direct_depfile_cannot_drop_or_guess_inputs(native_artifact, change):
    selected = native_artifact()
    text = selected.direct.read_text()
    if change == 'wrong_target':
        text = text.replace(str(selected.deps[0]), str(selected.outputs[0]))
    elif change == 'missing_source':
        text = text.replace(str(selected.source), str(selected.source.with_name('other.rs')))
    elif change == 'different_inputs':
        text = text.replace(str(selected.deps[0]) + ': ' + str(selected.source),
                            str(selected.deps[0]) + ': other.rs')
    elif change == 'extra_rule':
        text += str(selected.outputs[0]) + ': ' + str(selected.source) + '\n'
    elif change == 'duplicate_rule':
        text += str(selected.deps[0]) + ': ' + str(selected.source) + '\n'
    elif change == 'malformed':
        text += 'not a dependency rule\n'
    elif change == 'unknown_phony':
        text += 'not-an-input.rs:\n'
    elif change == 'missing':
        selected.direct.unlink()
    else:
        selected.direct.unlink()
        selected.direct.symlink_to(selected.aggregate)
    if change not in {'missing', 'symlink'}:
        selected.direct.write_text(text)
    with pytest.raises(ValueError):
        audit.artifact_depfiles(selected.event)


@pytest.mark.parametrize('change', ['wrong_target', 'missing_source', 'different_inputs', 'missing'])
def test_native_aggregate_is_supplemental_but_must_match_event(native_artifact, change):
    selected = native_artifact()
    if change == 'missing':
        selected.aggregate.unlink()
    else:
        text = selected.aggregate.read_text()
        if change == 'wrong_target':
            text = text.replace(str(selected.outputs[0]), str(selected.deps[0]))
        elif change == 'missing_source':
            text = text.replace(str(selected.source), 'other.rs')
        else:
            text += str(selected.outputs[0]) + ': other.rs\n'
        selected.aggregate.write_text(text)
    with pytest.raises(ValueError):
        audit.artifact_depfiles(selected.event)


@pytest.mark.parametrize('change', ['extra_filename', 'wrong_kind', 'wrong_name', 'wrong_source'])
def test_native_event_declaration_must_match_all_outputs(native_artifact, change):
    selected = native_artifact()
    if change == 'extra_filename':
        selected.event['filenames'].append(str(selected.aggregate))
    elif change == 'wrong_kind':
        selected.event['target']['kind'] = ['rlib']
    elif change == 'wrong_name':
        selected.event['target']['name'] = 'different_sdk'
    else:
        selected.event['target']['src_path'] = str(selected.source.with_name('missing.rs'))
    with pytest.raises(ValueError):
        audit.artifact_depfiles(selected.event)


def test_native_output_guards_remain_active_with_optimized_python(native_artifact):
    selected = native_artifact()
    selected.deps[0].write_bytes(b'different artifact')
    command = [sys.executable, '-O', '-B', '-c',
               'import json,runpy,sys; from pathlib import Path; '
               'm=runpy.run_path(sys.argv[1]); f=m["artifact_depfiles"]; '
               'f.__globals__["ROOT"]=Path(sys.argv[2]); f(json.loads(sys.argv[3]))',
               str(Path(audit.__file__).resolve()), str(audit.ROOT), json.dumps(selected.event)]
    result = subprocess.run(command, text=True, capture_output=True)
    assert result.returncode != 0 and 'ValueError: Need one byte-identical' in result.stderr


def test_native_mapping_changes_during_containment_are_rejected(native_artifact):
    artifact = native_artifact()
    _, mapping = audit.native_artifact_depfiles(artifact.event)
    artifact.deps[0].write_bytes(b'changed after selection')
    with pytest.raises(ValueError, match='byte-identical'):
        audit.recheck_native_artifact_mappings([mapping])


def test_native_mapping_failure_prevents_a_passing_audit_output(selected, monkeypatch):
    def changed(_event):
        raise ValueError('Native outputs changed during audit')
    monkeypatch.setattr(audit, 'native_artifact_depfiles', changed)
    with pytest.raises(ValueError, match='outputs changed'):
        audit.audit(selected.args, [], {selected.depfile}, {selected.out}, [],
                    selected.args.output.parent / 'source-snapshot',
                    selected.digest, selected.digest, selected.watched, [{'event': {}}])
    assert not selected.args.output.exists()


@pytest.fixture
def kotodama_generator(selected):
    root = selected.root / 'crates/kotodama_lang'
    # Explicit expected originals: do not derive the fixture from the allowlist.
    originals = ['Cargo.toml', 'build.rs', 'grammar/v1.lex',
                 'src/i18n/translations/messages.v1.tsv',
                 'src/assets/diagnostics_v1/diagnostic_explanations_v1.tsv',
                 'src/assets/diagnostics_v1/compile_fail_cases_v1.tsv',
                 'src/assets/diagnostics_v1/secret_reject_cases_v1.tsv']
    for name in originals:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('canonical original: ' + name)
        selected.watched.add(path)
    out = selected.root / 'target/debug/build/kotodama_lang-1234abcd/out'
    out.mkdir(parents=True)
    outputs = [out / name for name in ('kotodama_diagnostic_explanations.rs',
               'kotodama_i18n_v1_offsets.bin', 'kotodama_v1_lexical.rs')]
    for path in outputs:
        path.write_bytes(('actual generated fixture: ' + path.name).encode())
    package = 'path+file://' + str(root) + '#2.0.0-rc.2.0'
    events = [
        {'reason': 'build-script-executed', 'package_id': package,
         'out_dir': str(out), 'cfgs': [], 'env': []},
        {'reason': 'compiler-artifact', 'package_id': package,
         'target': {'kind': ['custom-build'], 'src_path': str(root / 'build.rs')},
         'manifest_path': str(root / 'Cargo.toml'), 'features': [], 'filenames': []},
    ]
    selected.build_output.write_text(''.join('cargo:rerun-if-changed=' + str(p) + '\n'
        for p in sorted(selected.watched | {selected.watcher})))
    selected.depfile.write_text(selected.depfile.read_text().rstrip() + ' '
                               + ' '.join(map(str, outputs)) + '\n')
    return SimpleNamespace(root=root, originals=originals, out=out,
                           outputs=outputs, events=events)


def test_kotodama_exact_outputs_bind_all_generator_originals(selected, kotodama_generator):
    item = kotodama_generator
    selected.run(item.events)
    result = json.loads(selected.args.output.read_text())
    assert result['passed'] and result['omittedCanonicalInputs'] == []
    records = result['canonicalGeneratedInputs']
    assert {Path(row['path']) for row in records} == set(item.outputs)
    for row in records:
        assert row['sha256'] == audit.sha(Path(row['path']))
        assert {Path(value['path']) for value in row['maintainedGeneratorInputs']} == {
            item.root / name for name in item.originals}
    assert result['externalDependencyGeneratedInputs'] == []


@pytest.mark.parametrize('missing', [
    'Cargo.toml', 'build.rs', 'grammar/v1.lex', 'src/i18n/translations/messages.v1.tsv',
    'src/assets/diagnostics_v1/diagnostic_explanations_v1.tsv',
    'src/assets/diagnostics_v1/compile_fail_cases_v1.tsv',
    'src/assets/diagnostics_v1/secret_reject_cases_v1.tsv',
])
def test_kotodama_cannot_admit_output_without_each_original(selected, kotodama_generator, missing):
    selected.watched.remove(kotodama_generator.root / missing)
    with pytest.raises(ValueError, match='generator input omitted'):
        audit.canonical_generated_inputs(kotodama_generator.events, selected.watched)


@pytest.mark.parametrize('change', ['missing-builder', 'wrong-builder', 'wrong-out-dir',
                                  'missing-output', 'symlink-output'])
def test_kotodama_requires_exact_selected_producer_and_regular_output(
        selected, kotodama_generator, tmp_path, change):
    item = kotodama_generator
    if change == 'missing-builder':
        item.events.pop()
    elif change == 'wrong-builder':
        wrong = item.root / 'other.rs'; wrong.write_text('different producer')
        item.events[1]['target']['src_path'] = str(wrong)
    elif change == 'wrong-out-dir':
        item.events[0]['out_dir'] = str(item.root)
    else:
        item.outputs[0].unlink()
        if change == 'symlink-output':
            external = tmp_path / 'other.rs'; external.write_text('outside')
            item.outputs[0].symlink_to(external)
    with pytest.raises(ValueError):
        audit.canonical_generated_inputs(item.events, selected.watched)


def test_kotodama_does_not_admit_other_files_in_same_out_dir(selected, kotodama_generator):
    unexpected = kotodama_generator.out / 'unreviewed.rs'
    unexpected.write_text('not one of the three selected generated inputs')
    selected.depfile.write_text(selected.depfile.read_text().rstrip() + ' ' + str(unexpected) + '\n')
    with pytest.raises(SystemExit, match='1'):
        selected.run(kotodama_generator.events)
    assert json.loads(selected.args.output.read_text())['omittedCanonicalInputs'] == [str(unexpected)]


def test_kotodama_generated_output_cannot_change_during_audit(selected, kotodama_generator, monkeypatch):
    def changed(_tool):
        kotodama_generator.outputs[0].write_text('changed during audit')
        return selected.digest, selected.watched
    monkeypatch.setattr(audit, 'actual_snapshot', changed)
    with pytest.raises(ValueError, match='generated output changed during audit'):
        selected.run(kotodama_generator.events)
    assert not selected.args.output.exists()


@pytest.fixture
def oid_generator(selected, tmp_path):
    root = tmp_path / 'cargo/registry/src/index-fixture/oid-registry-0.8.1'
    originals = ['Cargo.toml', 'build.rs', 'src/load.rs', 'assets/oid_db.txt']
    archive = root.parents[2] / 'cache/index-fixture/oid-registry-0.8.1.crate'
    archive.parent.mkdir(parents=True)
    with tarfile.open(archive, 'w:gz') as package:
        for name in originals:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = ('pinned registry original: ' + name).encode()
            path.write_bytes(data)
            info = tarfile.TarInfo('oid-registry-0.8.1/' + name); info.size = len(data)
            package.addfile(info, io.BytesIO(data))
    checksum = audit.sha(archive)
    (selected.root / 'Cargo.lock').write_text('[[package]]\nname = "oid-registry"\n'
        'version = "0.8.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "' + checksum + '"\n')
    out = selected.root / 'target/debug/build/oid-registry-1234abcd/out'
    out.mkdir(parents=True)
    output = out / 'oid_db.rs'; output.write_text('actual generated OID fixture')
    package = 'registry+https://github.com/rust-lang/crates.io-index#oid-registry@0.8.1'
    events = [
        {'reason': 'build-script-executed', 'package_id': package,
         'out_dir': str(out), 'cfgs': [], 'env': []},
        {'reason': 'compiler-artifact', 'package_id': package,
         'target': {'kind': ['custom-build'], 'src_path': str(root / 'build.rs')},
         'manifest_path': str(root / 'Cargo.toml'), 'features': ['registry'], 'filenames': []},
    ]
    selected.depfile.write_text(selected.depfile.read_text().rstrip() + ' ' + str(output) + '\n')
    return SimpleNamespace(root=root, originals=originals, archive=archive,
                           output=output, events=events, checksum=checksum)


def test_oid_output_binds_exact_archive_build_include_and_data(selected, oid_generator):
    item = oid_generator
    selected.run(item.events)
    result = json.loads(selected.args.output.read_text())
    assert result['passed'] and result['omittedCanonicalInputs'] == []
    [record] = result['externalDependencyGeneratedInputs']
    assert record['path'] == str(item.output)
    assert record['sha256'] == audit.sha(item.output)
    assert record['cargoLockChecksum'] == record['registryArchiveSha256'] == item.checksum
    assert {Path(row['path']) for row in record['maintainedGeneratorInputs']} == {
        item.root / name for name in item.originals}
    assert result['canonicalGeneratedInputs'] == []


@pytest.mark.parametrize('changed', ['Cargo.toml', 'build.rs', 'src/load.rs', 'assets/oid_db.txt'])
def test_oid_cannot_borrow_archive_for_changed_generator_original(oid_generator, changed):
    (oid_generator.root / changed).write_text('changed since pinned archive')
    with pytest.raises(ValueError, match='differs from pinned registry archive'):
        audit.external_generated_inputs(oid_generator.events)


@pytest.mark.parametrize('change', ['checksum', 'version', 'missing-builder', 'missing-output', 'symlink-output'])
def test_oid_requires_pinned_version_archive_producer_and_output(selected, oid_generator, tmp_path, change):
    item = oid_generator
    if change == 'checksum':
        path = selected.root / 'Cargo.lock'
        path.write_text(path.read_text().replace(item.checksum, '00' * 32))
    elif change == 'version':
        item.events[0]['package_id'] = item.events[0]['package_id'].replace('@0.8.1', '@0.8.2')
    elif change == 'missing-builder':
        item.events.pop()
    else:
        item.output.unlink()
        if change == 'symlink-output':
            external = tmp_path / 'other.rs'; external.write_text('outside')
            item.output.symlink_to(external)
    with pytest.raises(ValueError):
        audit.external_generated_inputs(item.events)


def test_oid_does_not_admit_other_files_in_same_out_dir(selected, oid_generator):
    unexpected = oid_generator.output.with_name('unreviewed.rs')
    unexpected.write_text('not the selected OID output')
    selected.depfile.write_text(selected.depfile.read_text().rstrip() + ' ' + str(unexpected) + '\n')
    with pytest.raises(SystemExit, match='1'):
        selected.run(oid_generator.events)
    assert json.loads(selected.args.output.read_text())['omittedCanonicalInputs'] == [str(unexpected)]
