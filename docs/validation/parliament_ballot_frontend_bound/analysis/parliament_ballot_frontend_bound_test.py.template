"""Fail-closed source identities, finite CFG counts and opaque frontend scope."""
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'scripts/parliament_ballot_frontend_bound.py'
SPEC = importlib.util.spec_from_file_location('frontend_bound', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FROZEN = ROOT / 'docs/validation/parliament_ballot_fatal_stack_eon'
LOADER = importlib.machinery.SourceFileLoader('frontend_test_stack', str(FROZEN / 'parliament_ballot_stack_audit.py.template'))
STACK_SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
STACK = importlib.util.module_from_spec(STACK_SPEC)
LOADER.exec_module(STACK)


@pytest.fixture(scope='module')
def captured():
    return {mode: (json.loads((FROZEN / (mode + '.json')).read_text()),
                   (FROZEN / mode / 'disassembly.txt').read_text(),
                   (FROZEN / mode / 'starts.txt').read_text(),
                   (FROZEN / mode / 'stubs.txt').read_text()) for mode in ('portable', 'accel')}


def test_digest_and_unambiguous_json(tmp_path):
    path = tmp_path / 'input'
    path.write_text('{"n":1}')
    assert MODULE.object_json(path) == {'n': 1}
    before = MODULE.digest(path)
    path.write_text('{"n":1,"n":2}')
    assert MODULE.digest(path) != before
    with pytest.raises(ValueError, match='duplicate'):
        MODULE.object_json(path)
    path.write_text('{"n":NaN}')
    with pytest.raises(ValueError, match='nonfinite'):
        MODULE.object_json(path)


def test_historical_resolution_keeps_live_drift_distinct():
    directory, guards, substitutions, current, sources = MODULE.inputs(ROOT)
    assert directory == FROZEN
    assert len(guards) >= 2081
    assert len(substitutions) == 4
    assert sources['src/test_codec.rs'].endswith('/src/test_codec.rs')
    assert str(ROOT / 'Cargo.lock') in current
    assert current[str(ROOT / 'Cargo.lock')]['historical'] == substitutions[str(ROOT / 'Cargo.lock')]['sha256']


@pytest.mark.parametrize('suffix', ['/src/test_codec.rs', '/validated/source/Cargo.lock.template'])
def test_changed_historical_source_or_recovery_bytes_refuses(monkeypatch, suffix):
    original = MODULE.digest
    monkeypatch.setattr(MODULE, 'digest', lambda path: '0' * 64 if str(path).endswith(suffix) else original(path))
    with pytest.raises(ValueError, match='historical source/tool changed'):
        MODULE.inputs(ROOT)


@pytest.mark.parametrize('pin', ['ADAPTER_REPORT', 'BUILD_RECEIPT', 'EON_MANIFEST', 'RECOVERY_RECEIPT'])
def test_unpinned_history_refuses(monkeypatch, pin):
    monkeypatch.setattr(MODULE, pin, '0' * 64)
    with pytest.raises(ValueError, match='identity changed'):
        MODULE.inputs(ROOT)


def test_recovery_cannot_omit_original_guard(monkeypatch):
    original = MODULE.object_json
    def changed(path):
        value = original(path)
        if str(path).endswith('/validated/receipt.json'):
            value['resolved_inputs'].pop(next(iter(value['resolved_inputs'])))
        return value
    monkeypatch.setattr(MODULE, 'object_json', changed)
    with pytest.raises(ValueError, match='incomplete historical'):
        MODULE.inputs(ROOT)


def test_cfg_all_paths_and_group_counts():
    ins = {0: ('cbz', 'x0, 0xc'), 4: ('bl', '0x100'), 8: ('b', '0x10'),
           12: ('bl', '0x200'), 16: ('ret', '')}
    edges, calls = MODULE.graph(ins, 0, 20, STACK.CONDITIONAL, {4: 'a', 12: 'b'})
    assert MODULE.longest(edges, dict.fromkeys(edges, 1)) == 4
    assert MODULE.longest(edges, dict.fromkeys(calls, 1)) == 1


def test_cycle_requires_explicit_group_bound():
    edges = {0: [4], 4: [8, 0], 8: []}
    with pytest.raises(ValueError, match='cycle'):
        MODULE.order(edges)
    assert MODULE.bounded_longest(edges, dict.fromkeys(edges, 1), {(4, 0)}, 3) == 9
    with pytest.raises(ValueError, match='missing bounded edge'):
        MODULE.order(edges, {(8, 0)})
    with pytest.raises(ValueError, match='edge cap'):
        MODULE.bounded_longest(edges, {}, {(4, 0)}, True)


@pytest.mark.parametrize('instruction,error', [(('bl', '0x100'), 'callee'),
                                             (('blr', 'x0'), 'continuation'),
                                             (('brk', '#1'), 'continuation'),
                                             (('ret', 'x19'), 'continuation'),
                                             (('b', '0x100'), 'escape')])
def test_unknown_control_not_silently_zeroed(instruction, error):
    with pytest.raises(ValueError, match=error):
        MODULE.graph({0: instruction}, 0, 4, STACK.CONDITIONAL, {})


def test_stale_calls_and_invalid_weights_refuse():
    with pytest.raises(ValueError, match='not reachable'):
        MODULE.graph({0: ('ret', '')}, 0, 4, STACK.CONDITIONAL, {0: 'stale'})
    with pytest.raises(ValueError, match='weight'):
        MODULE.longest({0: []}, {0: True})
    with pytest.raises(ValueError, match='weight'):
        MODULE.bounded_longest({0: []}, {0: -1}, set(), 1)


def test_source_size_bounds_are_logical_not_arena_claims():
    result = MODULE.source_bounds()
    assert result['statement_maximum_bytes'] == {'registration': 6016, 'vote': 128576}
    assert result['record_maximum_bytes'] == {'candidate_registration': 166172, 'comparator_registration': 115522,
                                            'candidate_vote': 361596, 'comparator_vote': 286658}
    assert max(result['record_maximum_bytes'].values()) < result['maximum_admitted_record_bytes']
    assert result['successful_statement_owned_vectors'] == {'registration': 7, 'vote': 1}


@pytest.mark.parametrize('mode', ['portable', 'accel'])
def test_actual_frontend_has_finite_local_counts_and_opaque_callees(mode, captured):
    result = MODULE.analyze_mode(mode, *captured[mode], STACK)
    reservation, record, frame = (result['functions'][n] for n in ('reservation', 'record', 'frame'))
    assert reservation['reachable_instructions'] == 186
    assert record['reachable_instructions'] == 55 and record['calls'] == []
    assert record['local_frame_bytes'] == 0
    assert frame['reachable_instructions'] == 114
    assert frame['call_maxima']['registration'] == {'memcmp': 1, 'with_capacity': 1, 'grow_one': 11, 'dealloc': 1}
    assert frame['call_maxima']['vote']['grow_one'] == 10
    assert reservation['combined_role_verifier_maximum'] == 1
    assert reservation['combined_typed_decoder_maximum'] == 1
    assert reservation['combined_cleanup_maximum'] == 2
    assert reservation['call_maxima']['memcpy'] == 2
    assert reservation['maximum_memcpy_bytes'] == 1066
    assert result['reservation_and_record_owned_stack_bytes'] == 2160
    assert result['complete_verification_work_bound'] is None
    assert result['complete_verification_stack_bound_bytes'] is None
    assert result['profile_qualified'] is False


@pytest.mark.parametrize('address,old,new', [
    ('100005d8c:', 'cbz\tw26', 'cbz\tw25'),
    ('10000e610:', 'b.lo', 'b.hs'),
    ('10000e7f0:', 'w5, #0xb', 'w5, #0xc'),
    ('10000e628:', 'b.ne', 'b.eq')])
def test_source_correspondence_instruction_drift_refuses(address, old, new, captured):
    report, disassembly, starts, stubs = captured['portable']
    line = next(line for line in disassembly.splitlines() if line.startswith(address))
    assert old in line
    changed = disassembly.replace(line, line.replace(old, new), 1)
    with pytest.raises(ValueError, match='changed|differs'):
        MODULE.analyze_mode('portable', report, changed, starts, stubs, STACK)


def test_frame_report_and_mode_not_unbound(captured):
    report, disassembly, starts, stubs = captured['portable']
    changed = copy.deepcopy(report)
    changed['functions'][0]['maximum_sp_decrement_bytes'] += 1
    with pytest.raises(ValueError, match='frame report differs'):
        MODULE.analyze_mode('portable', changed, disassembly, starts, stubs, STACK)
    with pytest.raises(ValueError, match='unknown mode'):
        MODULE.analyze_mode('future', report, disassembly, starts, stubs, STACK)


def test_unknown_persists_without_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, 'BUILD_RECEIPT', '0' * 64)
    result = MODULE.run(ROOT, tmp_path / 'result')
    assert result['verdict'] == 'UNKNOWN' and result['failure']
    assert result['applies_to_current_checkout'] is False
    assert json.loads((tmp_path / 'result/report.json').read_text()) == result
    with pytest.raises(FileExistsError):
        MODULE.run(ROOT, tmp_path / 'result')


def test_cli_creates_new_conditional_historical_evidence(tmp_path, monkeypatch, capsys):
    output = tmp_path / 'new'
    monkeypatch.setattr(sys, 'argv', [str(PATH), '--root', str(ROOT), '--output', str(output)])
    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out)['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    result = json.loads((output / 'report.json').read_text())
    assert result['input_changes'] == {}
    assert len(result['historical_substitutions']) == 4
    assert result['applies_to_current_checkout'] is False
