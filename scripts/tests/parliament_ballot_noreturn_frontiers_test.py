"""Independent CFG, native-return, recursion and frozen-frontier checks."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_noreturn_frontiers as nr


@pytest.fixture(scope='module')
def frozen():
    parser = nr.module(nr.ROOT / nr.STACK / 'parliament_ballot_stack_audit.py.template', 'test_nr_stack')
    control = nr.module(nr.ROOT / nr.ACTIVATION / 'parliament_ballot_allocator_activation.py.template', 'test_nr_cfg')
    boundary = json.loads((nr.ROOT / nr.FRONTIERS / 'report.json').read_text())
    modes = {}
    for mode in ('portable', 'accel'):
        stack = json.loads((nr.ROOT / nr.STACK / (mode + '.json')).read_text())
        for key in ('disassembly', 'stubs'):
            stack[key] = (nr.ROOT / nr.STACK / mode / (key + '.txt')).read_text()
        modes[mode] = stack, boundary['modes'][mode]
    return parser, control, modes


def assess_synthetic(control, instructions, known, start=0, end=None):
    """Construct a CFG independently from explicit test instruction dictionaries."""
    end = max(instructions) + 4 if end is None else end
    graph, exits = control.cfg(start, end, instructions, {'mov', 'nop'})
    return nr.assess(control, start, graph, exits, instructions, known)


@pytest.mark.parametrize('ending', [('ret', ''), ('brk', '#0x1'), ('b', '0x2000'), ('nop', '')])
def test_unknown_native_call_cannot_create_vacuous_divergence(frozen, ending):
    _, control, _ = frozen
    result = assess_synthetic(control, {0: ('bl', '0x2000'), 4: ending}, {0x1000})
    assert result['no_normal_return_established'] is False
    assert result['blocking_exits']
    assert not result['normal_return_cuts']


def test_unknown_native_tail_and_closed_loop_are_not_seeds(frozen):
    _, control, _ = frozen
    for instructions in ({0: ('b', '0x2000')}, {0: ('b', '0x0')}):
        result = assess_synthetic(control, instructions, {0x1000})
        assert result['no_normal_return_established'] is False


def test_unknown_native_call_returning_into_known_failure_is_permitted_but_cost_retained(frozen):
    _, control, _ = frozen
    result = assess_synthetic(control, {0: ('bl', '0x2000'), 4: ('bl', '0x1000')}, {0x1000})
    assert result['no_normal_return_established'] is True
    assert result['normal_return_cuts'] == [{'address': '0x4', 'target': '0x1000'}]
    assert len(result['reachable_calls_with_unknown_exceptional_or_native_cost']) == 2
    assert result['termination_or_resource_cost_established'] is False


def test_known_tail_is_allowed_but_conditional_normal_return_blocks(frozen):
    _, control, _ = frozen
    assert assess_synthetic(control, {0: ('b', '0x1000')}, {0x1000})['no_normal_return_established']
    result = assess_synthetic(control, {0: ('cbz', 'x0, 0x1000'), 4: ('ret', '')}, {0x1000})
    assert result['no_normal_return_established'] is False


def test_return_on_other_diamond_arm_blocks_noreturn(frozen):
    _, control, _ = frozen
    instructions = {0: ('cbz', 'x0, 0xc'), 4: ('bl', '0x1000'), 8: ('brk', '#0x1'), 12: ('ret', '')}
    result = assess_synthetic(control, instructions, {0x1000})
    assert result['no_normal_return_established'] is False
    assert result['blocking_exits'] == [{'address': '0xc', 'kind': 'ret', 'detail': ''}]


def test_two_failure_arms_exclude_shared_trap_without_single_call_dominance(frozen):
    _, control, _ = frozen
    instructions = {0: ('cbz', 'x0, 0xc'), 4: ('bl', '0x1000'), 8: ('b', '0x10'),
                    12: ('bl', '0x1000'), 16: ('brk', '#0x1')}
    graph, exits = control.cfg(0, 20, instructions, set())
    assert control.reaches(graph, 0, 16, {4}) and control.reaches(graph, 0, 16, {12})
    reached, stops = nr.normal_reach(control, 0, graph, instructions, {0x1000})
    assert 16 not in reached and set(stops) == {4, 12}
    assert nr.assess(control, 0, graph, exits, instructions, {0x1000})['no_normal_return_established']


def test_missing_cfg_node_and_unknown_instruction_fail(frozen):
    _, control, _ = frozen
    with pytest.raises(ValueError, match='missing'):
        nr.normal_reach(control, 0, {0: [4]}, {0: ('nop', '')}, set())
    with pytest.raises(ValueError, match='unknown'):
        assess_synthetic(control, {0: ('unknown', 'x0')}, {0x1000})


def test_recursive_cycle_cannot_bootstrap_fixed_point(frozen):
    _, control, _ = frozen
    instructions = {0: ('b', '0x10'), 16: ('b', '0x0')}
    candidates = {a: control.cfg(a, a + 4, instructions, set()) for a in (0, 16)}
    result = nr.least_fixed_point(control, candidates, instructions, {0x1000})
    assert result['rounds'] == [] and result['known'] == {0x1000}
    assert len(result['remaining']) == 2


def test_derivations_require_strictly_previous_rounds(frozen):
    _, control, _ = frozen
    instructions = {0: ('bl', '0x10'), 16: ('bl', '0x20'), 32: ('bl', '0x1000')}
    candidates = {a: control.cfg(a, a + 4, instructions, set()) for a in (0, 16, 32)}
    result = nr.least_fixed_point(control, candidates, instructions, {0x1000})
    assert result['rounds'] == [['0x20'], ['0x10'], ['0x0']]
    assert result['proofs']['0x0']['round'] == 3


def test_frozen_counts_distinguish_native_unwind_and_normal_cuts(frozen):
    parser, control, modes = frozen
    for stack, boundary in modes.values():
        result = nr.analyze_mode(parser, control, stack, boundary)
        assert result['candidate_functions'] == 16
        assert [len(x) for x in result['least_fixed_point']['rounds']] == [11, 3, 1]
        assert len(result['least_fixed_point']['remaining']) == 1
        for root, nfall, ntrap in (('reservation', 50, 23), ('worker', 52, 26)):
            details = result['roots'][root]
            assert details['counts']['function_fallthrough'] == {
                'EXCLUDED_CALLEE_NORMAL_RETURN_UNDER_PREMISES': nfall,
                'OUTSIDE_CUT_NORMAL_ENTRY_CFG_NATIVE_EXCEPTIONAL_FLOW_OPEN': 7}
            assert details['counts']['exceptional_terminal'] == {'EXCLUDED_FROM_NORMAL_ENTRY_CFG_UNDER_PREMISES': ntrap}
            assert details['unconditional_original_frontier_count_unchanged']
            native = [x for x in details['classifications'] if x['call_target_name'] == '__Unwind_Resume']
            assert len(native) == 7
            assert all(not x['target_is_original_seed'] and not x['target_is_derived_noreturn'] for x in native)
        exhausted = [p for p in result['least_fixed_point']['proofs'].values() if p['function'].startswith('resource_contract::workspace::exhausted')]
        assert len(exhausted) == 1 and exhausted[0]['round'] == 3
        # Two decimal calls, two slice-failure calls, write and _exit all survive
        # as calls with unknown exceptional/native cost; no source ! seed added.
        assert len(exhausted[0]['reachable_calls_with_unknown_exceptional_or_native_cost']) == 6
        assert len(exhausted[0]['normal_return_cuts']) == 2


def test_added_seed_and_changed_seed_address_are_rejected(frozen):
    parser, control, modes = frozen
    stack, boundary = modes['portable']
    for mutation in ('extra', 'wrong_address'):
        changed = copy.deepcopy(boundary)
        if mutation == 'extra':
            changed['failure_entry_addresses']['native::_exit'] = '0x10005b0f4'
        else:
            changed['failure_entry_addresses']['core::panicking::panic_fmt'] = '0x100003250'
        with pytest.raises(ValueError):
            nr.analyze_mode(parser, control, stack, changed)


@pytest.mark.parametrize('old,new', [('brk\t#0x1', 'ret'), ('10000a628:     \tbl', '10000a628:     \tb')])
def test_changed_frontier_shape_is_unknown(frozen, old, new):
    parser, control, modes = frozen
    stack, boundary = modes['portable']
    changed = dict(stack, disassembly=stack['disassembly'].replace(old, new))
    assert changed['disassembly'] != stack['disassembly']
    with pytest.raises(ValueError):
        nr.analyze_mode(parser, control, changed, boundary)


def test_changed_exhausted_native_exit_to_tail_blocks_its_derivation(frozen):
    parser, control, modes = frozen
    stack, boundary = modes['portable']
    changed = dict(stack, disassembly=stack['disassembly'].replace(
        '100003364:     \tbl\t0x10005b0f4', '100003364:     \tb\t0x10005b0f4'))
    result = nr.analyze_mode(parser, control, changed, boundary)
    assert '0x100003250' in result['least_fixed_point']['remaining']
    assert '0x100003250' not in result['least_fixed_point']['proofs']


def test_run_hash_guard_fresh_output_and_false_qualification(tmp_path):
    report = nr.run(nr.ROOT, tmp_path / 'analysis')
    assert report['status'] == 'PASS_UNDER_PREMISES' and not report['input_changes']
    assert report['complete_workspace_certificate'] is False and report['profile_qualified'] is False
    with pytest.raises(FileExistsError):
        nr.run(nr.ROOT, tmp_path / 'analysis')
    unknown = nr.run(tmp_path / 'missing', tmp_path / 'unknown')
    assert unknown['status'] == 'UNKNOWN'
    assert len(nr.sha(tmp_path / 'analysis/report.json')) == 64


def test_main_missing_evidence_is_nonzero(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(nr, 'ROOT', tmp_path / 'absent')
    monkeypatch.setattr(sys, 'argv', ['nr', '--output', str(tmp_path / 'out')])
    assert nr.main() == 1
    assert json.loads(capsys.readouterr().out)['profile_qualified'] is False
