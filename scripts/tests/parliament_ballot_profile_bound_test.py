"""Historical identity and loop/opaque-cost controls for the profile bound."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'scripts/parliament_ballot_profile_bound.py'
SPEC = importlib.util.spec_from_file_location('profile_bound', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture(scope='module')
def dependencies():
    return MODULE.dependencies(ROOT)


@pytest.fixture(scope='module')
def captured(dependencies):
    front, stack, directory, *_ = dependencies
    return {mode: (front.object_json(directory / (mode+'.json')),
                   (directory / mode / 'disassembly.txt').read_text(),
                   (directory / mode / 'starts.txt').read_text(),
                   (directory / mode / 'stubs.txt').read_text(), front, stack)
            for mode in ('portable', 'accel')}


def test_digest_and_dependency_loading(tmp_path):
    path = tmp_path / 'input'
    path.write_bytes(b'abc')
    assert MODULE.digest(path) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    path.write_text('VALUE = 7\n')
    assert MODULE.load('profile_synthetic_dependency', path).VALUE == 7
    path.unlink()
    with pytest.raises(FileNotFoundError):
        MODULE.digest(path)


def test_complete_historical_guards_and_distinct_live_drift(dependencies):
    _, _, _, guards, substitutions, current, sources = dependencies
    assert len(guards) >= 2085 and len(substitutions) == 4
    assert str(ROOT / 'Cargo.lock') in current
    assert sources['src/profile.rs'] in guards
    assert all(MODULE.digest(name) == expected for name, expected in guards.items())


@pytest.mark.parametrize('name', ['FRONTEND_HELPER', 'FRONTEND_REPORT'])
def test_dependency_identity_not_refreshed(monkeypatch, name):
    monkeypatch.setattr(MODULE, name, '0' * 64)
    with pytest.raises(ValueError, match='frontend identity changed'):
        MODULE.dependencies(ROOT)


def test_changed_source_refuses(monkeypatch):
    real = MODULE.digest
    monkeypatch.setattr(MODULE, 'digest', lambda p: '0' * 64 if str(p).endswith('/src/profile.rs') else real(p))
    with pytest.raises(ValueError, match='historical frontend input changed'):
        MODULE.dependencies(ROOT)


@pytest.mark.parametrize('mode', ['portable', 'accel'])
def test_both_actual_images_bound_role_loop_and_keep_callees_opaque(mode, captured):
    r = MODULE.analyze_mode(mode, *captured[mode])
    assert r['reachable_instructions'] == 672
    assert r['local_issued_instruction_bound'] == 834
    assert r['local_frame_bytes'] == 1632 and r['local_stack_including_red_zone_bytes'] == 1760
    assert r['loop_edge_budget'] == 1
    assert r['call_maxima'] == {'crt_digest': 1, 'parameter_concat': 1, 'dimension_concat': 1,
        'descriptor_frame': 1, 'dealloc': 3, 'descriptor_hash': 1, 'namespace_frame_digest': 2}
    assert all(all(v is None for v in costs.values()) for costs in r['opaque_costs'].values())
    assert r['complete_profile_work_bound'] is r['complete_profile_stack_bound'] is None
    assert r['exceptional_costs_discharged'] is False


@pytest.mark.parametrize('address,old,new', [
    ('10000f790:', 'w8, #0x0', 'w8, #0x1'),
    ('10000f80c:', 'x20, x8', 'x20, x9'),
    ('10000fc08:', 'w8, #0x1', 'w8, #0x0'),
    ('10000fc14:', 'tbz', 'tbnz'),
    ('10000f408:', '#-0x60', '#-0x70'),
    ('10000f440:', 'bl', 'b'),
])
def test_loop_frame_or_call_mutation_refuses(address, old, new, captured):
    report, disassembly, *rest = captured['portable']
    line = next(line for line in disassembly.splitlines() if line.startswith(address))
    assert old in line
    with pytest.raises(ValueError, match='body changed|frame capture differs'):
        MODULE.analyze_mode('portable', report, disassembly.replace(line, line.replace(old, new), 1), *rest)


def test_mismatched_frame_report_and_mode_refuse(captured):
    report, *rest = captured['portable']
    altered = copy.deepcopy(report)
    altered['functions'][0]['maximum_sp_decrement_bytes'] += 16
    with pytest.raises(ValueError, match='frame capture differs'):
        MODULE.analyze_mode('portable', altered, *rest)
    with pytest.raises(ValueError, match='unknown mode'):
        MODULE.analyze_mode('other', report, *rest)


def test_unknown_callee_refuses(monkeypatch, captured):
    monkeypatch.setitem(MODULE.TARGETS, 'crt_digest', 'not-the-callee')
    with pytest.raises(ValueError, match='callee target changed'):
        MODULE.analyze_mode('portable', *captured['portable'])


def test_failed_capture_stays_unknown_and_cannot_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, 'FRONTEND_REPORT', '0' * 64)
    output = tmp_path / 'result'
    r = MODULE.run(ROOT, output)
    assert r['verdict'] == 'UNKNOWN' and r['failure']
    assert r['profile_qualified'] is r['applies_to_current_checkout'] is False
    assert json.loads((output / 'report.json').read_text()) == r
    with pytest.raises(FileExistsError):
        MODULE.run(ROOT, output)


def test_guard_mutation_after_analysis_preserves_unknown(tmp_path, monkeypatch):
    analyze = MODULE.analyze_mode
    real = MODULE.digest
    changed = False
    def mark_analyzed(*args):
        nonlocal changed
        result = analyze(*args)
        changed = True
        return result
    def changed_digest(path):
        if changed and str(path).endswith('/src/profile.rs'):
            return '0' * 64
        return real(path)
    monkeypatch.setattr(MODULE, 'analyze_mode', mark_analyzed)
    monkeypatch.setattr(MODULE, 'digest', changed_digest)
    r = MODULE.run(ROOT, tmp_path / 'result')
    assert r['verdict'] == 'UNKNOWN'
    assert set(r['input_changes']) == {str(ROOT / 'crates/iroha_parliament_ballot_proof/src/profile.rs')}
    assert len(r['modes']) == 2 and not r['profile_qualified']


def test_cli_retains_new_historical_result(tmp_path, monkeypatch, capsys):
    output = tmp_path / 'result'
    monkeypatch.setattr(sys, 'argv', [str(PATH), '--root', str(ROOT), '--output', str(output)])
    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out)['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    r = json.loads((output / 'report.json').read_text())
    assert not r['input_changes'] and not r['applies_to_current_checkout']
    assert len(r['historical_substitutions']) == 4
    assert (output / 'source/profile.rs.template').read_bytes() == (ROOT / 'crates/iroha_parliament_ballot_proof/src/profile.rs').read_bytes()
