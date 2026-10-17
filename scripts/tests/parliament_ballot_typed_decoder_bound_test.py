"""Guard typed-decoder control, bounded requests, cleanup and opaque costs."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'scripts/parliament_ballot_typed_decoder_bound.py'
SPEC = importlib.util.spec_from_file_location('typed_decoder_bound', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FRONT = MODULE.load(ROOT / 'docs/validation/parliament_ballot_frontend_bound/analysis/parliament_ballot_frontend_bound.py.template', 'typed_test_frontend')
FROZEN = ROOT / 'docs/validation/parliament_ballot_fatal_stack_eon'
STACK = MODULE.load(FROZEN / 'parliament_ballot_stack_audit.py.template', 'typed_test_stack')
PREVIOUS = json.loads((ROOT / 'docs/validation/parliament_ballot_frontend_bound/analysis/report.json').read_text())


@pytest.fixture(scope='module')
def captured():
    return {mode: (json.loads((FROZEN / (mode + '.json')).read_text()),
                   (FROZEN / mode / 'disassembly.txt').read_text(),
                   (FROZEN / mode / 'starts.txt').read_text(),
                   (FROZEN / mode / 'stubs.txt').read_text()) for mode in ('portable', 'accel')}


def test_hash_and_frozen_loader(tmp_path):
    path = tmp_path / 'm.py.template'
    path.write_text('value = 3\n')
    before = MODULE.digest(path)
    assert MODULE.load(path, 'typed_test_module').value == 3
    path.write_text('value = 4\n')
    assert MODULE.digest(path) != before


def test_historical_inputs_are_complete_and_current_scope_distinct():
    capture, guards, substitutions, current, sources, frontend, analyzer, previous = MODULE.inputs(ROOT)
    assert capture == FROZEN
    assert len(guards) >= 2100
    assert len(substitutions) == 4 and len(current) == 4
    assert len(sources) == 8
    assert previous['applies_to_current_checkout'] is False


def test_prior_manifest_and_source_drift_refuse(monkeypatch):
    original = MODULE.digest
    monkeypatch.setattr(MODULE, 'digest', lambda path: '0'*64 if str(path).endswith('/src/test_codec.rs') else original(path))
    with pytest.raises(ValueError, match='guarded input changed'):
        MODULE.inputs(ROOT)
    monkeypatch.setattr(MODULE, 'FRONTEND_MANIFEST', '0'*64)
    with pytest.raises(ValueError, match='manifest changed'):
        MODULE.inputs(ROOT)


def test_call_return_is_retained_before_exceptional_frontier():
    ins = {0: ('bl', '0x200'), 4: ('brk', '#0x1')}
    edges, calls, frontiers = MODULE.graph(ins, 0, 8, STACK.CONDITIONAL, {0: 'opaque'}, {4: ('brk', '#0x1')})
    assert edges == {0: [4], 4: []}
    assert calls == {0: 'opaque'}
    assert frontiers[0]['continuation_work_bound'] is None
    assert frontiers[0]['continuation_stack_bound_bytes'] is None
    assert FRONT.longest(edges, dict.fromkeys(edges, 1)) == 2


@pytest.mark.parametrize('ins,error', [
    ({0: ('brk', '#1')}, 'unknown continuation'),
    ({0: ('blr', 'x0')}, 'unknown continuation'),
    ({0: ('ret', 'x19')}, 'unknown continuation'),
    ({0: ('bl', '0x200')}, 'unknown callee'),
    ({0: ('b', '0x100')}, 'control escape')])
def test_unknown_control_refuses(ins, error):
    with pytest.raises(ValueError, match=error):
        MODULE.graph(ins, 0, 4, STACK.CONDITIONAL, {}, {})


def test_stale_or_changed_terminal_refuses():
    with pytest.raises(ValueError, match='not reachable'):
        MODULE.graph({0: ('ret', '')}, 0, 4, STACK.CONDITIONAL, {}, {4: ('brk', '#1')})
    with pytest.raises(ValueError, match='shape changed'):
        MODULE.graph({0: ('ret', '')}, 0, 4, STACK.CONDITIONAL, {}, {0: ('brk', '#1')})


def test_all_paths_guard_dominance_not_one_trace():
    edges = {0: [4, 8], 4: [12], 8: [], 12: []}
    assert MODULE.edge_dominates(edges, 0, 12, (0, 4))
    edges[8] = [12]
    assert not MODULE.edge_dominates(edges, 0, 12, (0, 4))
    with pytest.raises(ValueError, match='missing guard'):
        MODULE.edge_dominates(edges, 0, 12, (4, 8))


def test_unknown_cycle_not_reported_finite():
    edges, _, _ = MODULE.graph({0: ('b', '0x0')}, 0, 4, STACK.CONDITIONAL, {}, {})
    with pytest.raises(ValueError, match='cycle'):
        FRONT.longest(edges, {0: 1})


def test_source_requests_include_p16_and_frame_prefixes():
    result = MODULE.source_requests()
    assert result['registration']['body_digest_maximum_framed_bytes'] == 4136
    assert result['vote']['list_digest_maximum_framed_bytes'] == 128114
    assert result['registration']['maximum_logical_owned_payload_bytes'] == 5632
    assert result['heap_capacity_or_arena_sufficiency_proved'] is False


@pytest.mark.parametrize('mode', ['portable', 'accel'])
def test_actual_typed_paths_copies_cleanup_and_frontier(mode, captured):
    result = MODULE.analyze_mode(mode, *captured[mode], FRONT, STACK, PREVIOUS['modes'][mode])
    reg, vote = (result['decoders'][name] for name in ['registration', 'vote'])
    assert reg['reachable_instructions'] == 512 and vote['reachable_instructions'] == 422
    assert reg['local_issued_instruction_bound'] == 322 and vote['local_issued_instruction_bound'] == 315
    assert reg['with_parser_local_instruction_bound'] == 621
    assert vote['with_parser_local_instruction_bound'] == 592
    assert reg['with_parser_owned_stack_bytes'] == 1824
    assert vote['with_parser_owned_stack_bytes'] == 1184
    assert reg['call_maxima'] == {'frame': 1, 'dealloc': 7, 'shim': 2, 'alloc': 2,
                                 'memcpy': 4, 'opaque_new': 5, 'statement_new': 1,
                                 'context_drop': 1, 'statement_drop': 1, 'handle_error': 1}
    assert vote['call_maxima'] == {'frame': 1, 'dealloc': 2, 'split': 1, 'validate': 1, 'memcpy': 1}
    assert reg['maximum_direct_memcpy_bytes'] == 5144
    assert vote['maximum_direct_memcpy_bytes'] == 480
    assert len(reg['exceptional_frontiers']) == 1 and vote['exceptional_frontiers'] == []
    assert reg['complete_decoder_work_bound'] is None
    assert vote['complete_decoder_stack_bound_bytes'] is None
    assert result['profile_qualified'] is False


@pytest.mark.parametrize('address,old,new', [
    ('10000e908:', 'b.ls', 'b.hi'),
    ('10000e9b8:', 'b.ls', 'b.hi'),
    ('10000df74:', 'b.eq', 'b.ne'),
    ('10000dfcc:', 'b.hs', 'b.lo'),
    ('10000ea10:', 'mov\tx1, x21', 'mov\tx1, x20'),
    ('10000efac:', 'brk\t#0x1', 'ret')])
def test_changed_pointer_guard_or_terminal_refuses(address, old, new, captured):
    report, disassembly, starts, stubs = captured['portable']
    line = next(line for line in disassembly.splitlines() if line.startswith(address))
    assert old in line
    changed = disassembly.replace(line, line.replace(old, new), 1)
    with pytest.raises(ValueError, match='changed|differs'):
        MODULE.analyze_mode('portable', report, changed, starts, stubs, FRONT, STACK, PREVIOUS['modes']['portable'])


def test_frame_report_or_mode_cannot_supply_unbound_result(captured):
    report, disassembly, starts, stubs = captured['portable']
    changed = copy.deepcopy(report)
    changed['functions'][0]['maximum_sp_decrement_bytes'] += 1
    with pytest.raises(ValueError, match='frame report differs'):
        MODULE.analyze_mode('portable', changed, disassembly, starts, stubs, FRONT, STACK, PREVIOUS['modes']['portable'])
    with pytest.raises(ValueError, match='unknown mode'):
        MODULE.analyze_mode('future', report, disassembly, starts, stubs, FRONT, STACK, PREVIOUS['modes']['portable'])


def test_unknown_persists_and_output_reuse_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, 'FRONTEND_MANIFEST', '0'*64)
    result = MODULE.run(ROOT, tmp_path / 'new')
    assert result['verdict'] == 'UNKNOWN' and result['failure']
    assert json.loads((tmp_path / 'new/report.json').read_text()) == result
    with pytest.raises(FileExistsError):
        MODULE.run(ROOT, tmp_path / 'new')


def test_cli_preserves_historical_scope(tmp_path, monkeypatch, capsys):
    output = tmp_path / 'new'
    monkeypatch.setattr(sys, 'argv', [str(PATH), '--root', str(ROOT), '--output', str(output)])
    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out)['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    result = json.loads((output / 'report.json').read_text())
    assert result['input_changes'] == {} and len(result['historical_substitutions']) == 4
    assert result['applies_to_current_checkout'] is False
