"""Guard conditional adapter counts, opaque costs and frozen source identities."""
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'scripts/parliament_ballot_adapter_bound.py'
SPEC = importlib.util.spec_from_file_location('adapter_bound', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FROZEN = ROOT / 'docs/validation/parliament_ballot_fatal_stack_eon'
LOADER = importlib.machinery.SourceFileLoader('adapter_test_stack', str(FROZEN / 'parliament_ballot_stack_audit.py.template'))
STACK_SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
STACK = importlib.util.module_from_spec(STACK_SPEC)
LOADER.exec_module(STACK)


@pytest.fixture(scope='module')
def captured():
    """Read the retained source-bound actual-image captures once."""
    return {mode: (json.loads((FROZEN / (mode + '.json')).read_text()),
                   (FROZEN / mode / 'disassembly.txt').read_text(),
                   (FROZEN / mode / 'starts.txt').read_text(),
                   (FROZEN / mode / 'stubs.txt').read_text()) for mode in ('portable', 'accel')}


def test_digest_binds_bytes(tmp_path):
    path = tmp_path / 'input'
    path.write_bytes(b'a')
    before = MODULE.digest(path)
    path.write_bytes(b'b')
    assert MODULE.digest(path) != before


def test_exact_frozen_inputs_and_drift_failure(monkeypatch):
    directory, guards = MODULE.frozen_inputs(ROOT)
    assert directory == FROZEN and len(guards) == 2079
    original = MODULE.digest
    monkeypatch.setattr(MODULE, 'digest', lambda p: '0' * 64 if str(p).endswith('/generated_workspace.rs') else original(p))
    with pytest.raises(ValueError, match='inherited source/tool input changed'):
        MODULE.frozen_inputs(ROOT)


def test_manifest_identity_cannot_be_replaced(monkeypatch):
    monkeypatch.setattr(MODULE, 'FROZEN_MANIFEST', '0' * 64)
    with pytest.raises(ValueError, match='manifest changed'):
        MODULE.frozen_inputs(ROOT)


def test_cfg_bound_counts_segments_not_a_zero_cost_cycle():
    instructions = {0: ('mov', 'x0, #0'), 4: ('cbnz', 'x1, 0x0'), 8: ('ret', '')}
    with pytest.raises(ValueError, match='unbounded adapter CFG cycle'):
        MODULE.walk(instructions, 0, 12, 0, STACK.CONDITIONAL, {}, {}, {}, {})
    result = MODULE.walk(instructions, 0, 12, 0, STACK.CONDITIONAL, {}, {(4, 0): 19}, {}, {})
    assert result['local_instruction_bound'] == 60
    assert result['loop_backedges'] == [{'source': '0x4', 'target': '0x0', 'maximum_taken': 19}]


def test_cfg_cut_is_conditional_and_keeps_its_premise():
    instructions = {0: ('cbz', 'x0, 0x8'), 4: ('ret', ''), 8: ('brk', '#1')}
    result = MODULE.walk(instructions, 0, 12, 0, STACK.CONDITIONAL,
                         {0: (False, 'reviewed private state')}, {}, {}, {})
    assert result['local_instruction_bound'] == 2
    assert result['conditional_cuts'][0]['premise'] == 'reviewed private state'
    with pytest.raises(ValueError, match='opaque adapter continuation'):
        MODULE.walk(instructions, 0, 12, 0, STACK.CONDITIONAL, {}, {}, {}, {})


@pytest.mark.parametrize('loops', [{(0, 4): 19}, {(4, 0): -1}, {(4, 0): True}])
def test_unknown_or_invalid_loop_premises_fail(loops):
    with pytest.raises(ValueError, match='loop edge'):
        MODULE.walk({0: ('ret', '')}, 0, 4, 0, STACK.CONDITIONAL, {}, loops, {}, {})


def test_unknown_calls_control_escape_and_unused_cuts_fail():
    with pytest.raises(ValueError, match='callee'):
        MODULE.walk({0: ('bl', '0x9000')}, 0, 4, 0, STACK.CONDITIONAL, {}, {}, {}, {})
    with pytest.raises(ValueError, match='control escape'):
        MODULE.walk({0: ('b', '0x100')}, 0, 4, 0, STACK.CONDITIONAL, {}, {}, {}, {})
    with pytest.raises(ValueError, match='unused conditional'):
        MODULE.walk({0: ('ret', '')}, 0, 4, 0, STACK.CONDITIONAL, {0: (False, 'unused')}, {}, {}, {})


def test_native_terminal_contract_is_named_not_general_native_pruning():
    result = MODULE.walk({0: ('bl', '0x9000')}, 0, 4, 0, STACK.CONDITIONAL,
                         {}, {}, {}, {0x9000: '__exit'})
    assert result['calls'] == [{'address': '0x0', 'target': '__exit'}]
    with pytest.raises(ValueError, match='control escape'):
        MODULE.walk({0: ('bl', '0x9000')}, 0, 4, 0, STACK.CONDITIONAL,
                    {}, {}, {}, {0x9000: '_memcpy'})


@pytest.mark.parametrize('mode', ['portable', 'accel'])
def test_actual_adapter_retains_opaque_costs_and_finite_local_bounds(mode, captured):
    result = MODULE.analyze_mode(mode, *captured[mode], STACK)
    assert result['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    assert result['adapter_owned_stack_bytes_including_red_zone'] == 336
    assert result['adapter_issued_instruction_bound_excluding_callees'] < 6000
    assert result['maximum_input_owned_block_bytes'] == 524288
    assert {c['target']: c['live_caller_bytes'] for c in result['opaque_callees']} == {
        'OPAQUE_VERIFIER': 176, '_bzero': 176, '_memcpy': 176, '__exit': 208}
    assert all(c['work_bound'] is None and c['additional_stack_bound_bytes'] is None
               for c in result['opaque_callees'])
    assert result['complete_adapter_stack_bound_bytes'] is None
    assert result['complete_adapter_work_bound'] is None
    assert result['complete_workspace_certificate'] is False
    assert result['profile_qualified'] is False


@pytest.mark.parametrize('address,old,new', [
    ('100000fdc:', 'stlrb\tw21, [x10]', 'stlrb\twzr, [x10]'),
    ('100006ca8:', 'casab\tw9, w8, [x10]', 'casab\tw9, wzr, [x10]'),
    ('100001140:', 'mov\tx0, x21', 'mov\tx0, x22'),
    ('100001148:', 'mov\tw2, #0x1', 'mov\tw2, #0x2')])
def test_private_state_lock_and_pointer_layout_instruction_drift_rejected(address, old, new, captured):
    report, disasm, starts, stubs = captured['portable']
    line = next(line for line in disasm.splitlines() if line.startswith(address))
    assert old in line
    with pytest.raises(ValueError, match='changed|differs'):
        MODULE.analyze_mode('portable', report, disasm.replace(line, line.replace(old, new), 1), starts, stubs, STACK)


def test_report_and_mode_cannot_supply_unbound_frames(captured):
    report, disasm, starts, stubs = captured['portable']
    changed = copy.deepcopy(report)
    changed['functions'][0]['maximum_sp_decrement_bytes'] = 0x1000000
    with pytest.raises(ValueError, match='frame report differs'):
        MODULE.analyze_mode('portable', changed, disasm, starts, stubs, STACK)
    with pytest.raises(ValueError, match='mode'):
        MODULE.analyze_mode('future', report, disasm, starts, stubs, STACK)


@pytest.mark.parametrize('failure_kind', ['manifest', 'source'])
def test_run_preserves_unknown_failure_and_refuses_output_reuse(tmp_path, monkeypatch, failure_kind):
    if failure_kind == 'manifest':
        monkeypatch.setattr(MODULE, 'FROZEN_MANIFEST', '0' * 64)
        expected_failure = 'manifest changed'
    else:
        original = MODULE.digest
        monkeypatch.setattr(MODULE, 'digest', lambda p: '0' * 64 if str(p).endswith('/generated_workspace.rs') else original(p))
        expected_failure = 'inherited source/tool input changed'
    result = MODULE.run(ROOT, tmp_path / 'evidence')
    assert result['verdict'] == 'UNKNOWN'
    assert expected_failure in result['failure']
    assert result['profile_qualified'] is False
    assert json.loads((tmp_path / 'evidence/report.json').read_text()) == result
    with pytest.raises(FileExistsError):
        MODULE.run(ROOT, tmp_path / 'evidence')


def test_cli_success_creates_bound_report(tmp_path, monkeypatch, capsys):
    output = tmp_path / 'new'
    monkeypatch.setattr(sys, 'argv', [str(PATH), '--root', str(ROOT), '--output', str(output)])
    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out)['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    assert json.loads((output / 'report.json').read_text())['input_changes'] == {}
