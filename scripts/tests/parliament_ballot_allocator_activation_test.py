"""Independent control-flow, symbol and rejection checks for activation evidence."""
import copy
import json
from pathlib import Path
import struct
import sys
import types

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_allocator_activation as activation


def macho_symbol(*, kind=0x1E, name=None):
    """Construct a minimal symbol image independently of the decoder."""
    name = name or "__ZN17resource_contract9workspace6ACTIVE17h0123456789abcdefE.0"
    strings = b"\0" + name.encode() + b"\0"
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<6I", 2, 24, 56, 1, 72, len(strings))
    symbol = struct.pack("<IBBHQ", 1, kind, 1, 0, 0x10000A123)
    return header + command + symbol + strings


def test_symbol_address_and_private_external_flag():
    value = activation.active_symbol(macho_symbol())
    assert value["address"] == "0x10000a123" and value["n_type"] == 30
    assert activation.active_symbol(macho_symbol(kind=14))["section"] == 1
    for image in (macho_symbol(kind=15), macho_symbol(kind=0), b"short",
                  macho_symbol(name="public_other_name"), macho_symbol()[:-1]):
        with pytest.raises(ValueError):
            activation.active_symbol(image)


def test_symbol_rejects_unknown_cpu_and_bad_command_range():
    for offset, replacement in ((4, 7), (36, 0x10000), (44, 0x100000)):
        image = bytearray(macho_symbol())
        struct.pack_into("<I", image, offset, replacement)
        with pytest.raises(ValueError):
            activation.active_symbol(bytes(image))


def test_branch_target_requires_literal_and_gpr_aliases_are_exact():
    assert activation.target("w8, 0x104 <fixture+0x4>") == 260
    assert activation.register_number("w20") == activation.register_number("x20") == 20
    assert activation.register_number("wzr") is None
    assert activation.register_number("v0") is None
    with pytest.raises(ValueError):
        activation.target("x8")


def test_diamond_dominance_and_bypass_are_not_inferred_from_addresses():
    instructions = {0: ("cbz", "w0, 0xc"), 4: ("mov", "w1, #1"),
                    8: ("b", "0x10"), 12: ("mov", "w1, #0"),
                    16: ("bl", "0x1000"), 20: ("ret", "")}
    graph, exits = activation.cfg(0, 24, instructions, {"mov"})
    assert activation.reaches(graph, 0, 16)
    assert activation.reaches(graph, 0, 16, {4})  # Other arm bypasses activation.
    assert not activation.reaches(graph, 0, 16, {0})
    assert exits[0]["kind"] == "bl" and exits[1]["kind"] == "ret"
    with pytest.raises(ValueError, match="missing"):
        activation.reaches({0: [4]}, 0, 8)


@pytest.mark.parametrize("instruction", [("br", "x8"), ("mystery", "x0"), ("bl", "x8")])
def test_unknown_instruction_or_control_fails_local_proof(instruction):
    with pytest.raises(ValueError):
        activation.cfg(0, 4, {0: instruction}, {"mov"})


def test_tail_trap_and_function_fallthrough_remain_boundaries():
    for instruction, expected in ((('b', '0x1000'), 'tail'), (('brk', '#1'), 'brk'),
                                  (('bl', '0x1000'), 'function_fallthrough')):
        _, exits = activation.cfg(0, 4, {0: instruction}, set())
        assert exits[-1]['kind'] == expected


def test_constants_merge_to_unknown_and_unknown_flag_store_is_refused():
    flag = 0x1000
    instructions = {0: ("cbz", "w0, 0xc"), 4: ("mov", "w1, #1"), 8: ("b", "0x10"),
                    12: ("mov", "w1, #0"), 16: ("stlrb", "w1, [x2]"), 20: ("ret", "")}
    graph, _ = activation.cfg(0, 24, instructions, {"mov", "stlrb"})
    states, _ = activation.propagate(graph, instructions, 0, flag, initial={2: flag})
    assert 1 not in states[16][0]
    with pytest.raises(ValueError, match="unknown flag store value"):
        activation.flag_accesses(instructions, states, flag)


@pytest.mark.parametrize("operation", [("str", "x2, [sp]"), ("add", "x3, x0, x2"),
                                       ("add", "x3, x2, #0, lsl #12"),
                                       ("add", "x3, x0, x2, lsl #0"),
                                       ("sub", "x3, x2, x0, lsl #0"),
                                       ("mov", "x3, x2, lsl #12"),
                                       ("movk", "x2, #0x80"), ("bl", "0x1000"), ("blr", "x9")])
def test_derived_pointer_escape_and_unsupported_arithmetic_are_unknown(operation):
    # The ADR instruction materializes a flag pointer in an argument register.
    instructions = {0: ("adr", "x2, 0x1000"), 4: operation, 8: ("ret", "")}
    graph, _ = activation.cfg(0, 12, instructions, {"adr", "str", "add", "sub", "mov", "movk"})
    _, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert problems


def test_possible_flag_at_merge_cannot_become_an_unchecked_unknown_pointer():
    instructions = {0: ('cbz', 'w0, 0xc'), 4: ('adr', 'x2, 0x1000'),
                    8: ('b', '0x10'), 12: ('mov', 'x2, #0'),
                    16: ('stlrb', 'wzr, [x2]'), 20: ('ret', '')}
    graph, _ = activation.cfg(0, 24, instructions, {'adr', 'mov', 'stlrb'})
    states, _ = activation.propagate(graph, instructions, 0, 0x1000)
    assert 2 not in states[16][0] and 2 in states[16][1]
    with pytest.raises(ValueError, match='unresolved flag-derived'):
        activation.flag_accesses(instructions, states, 0x1000)
    instructions[16] = ('str', 'x0, [x2, #0x8]')
    _, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert any('memory offset' in problem['reason'] for problem in problems)


@pytest.mark.parametrize('opcode', ['ldadd', 'ldaddal', 'ldaddab', 'ldaddl'])
def test_atomic_read_modify_write_does_not_erase_derived_data_escape(opcode):
    instructions = {0: ('adr', 'x2, 0x1000'), 4: (opcode, 'x2, x3, [x4]'), 8: ('ret', '')}
    graph, _ = activation.cfg(0, 12, instructions, {'adr', opcode})
    _, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert any('atomic read-modify-write' in problem['reason'] for problem in problems)


@pytest.mark.parametrize('register', ['x0', 'x1'])
def test_returned_derived_pointer_is_an_escape(register):
    instructions = {0: ('adr', register + ', 0x1000'), 4: ('ret', '')}
    graph, _ = activation.cfg(0, 8, instructions, {'adr'})
    _, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert any('returned in ABI' in problem['reason'] for problem in problems)


@pytest.mark.parametrize('branch', [('b', '0x2000'), ('cbz', 'w3, 0x2000')])
def test_tail_call_also_checks_derived_argument_escape(branch):
    instructions = {0: ('adr', 'x0, 0x1000'), 4: branch, 8: ('ret', '')}
    graph, _ = activation.cfg(0, 12, instructions, {'adr'})
    _, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert any('tail-call' in problem['reason'] for problem in problems)


def test_internal_branch_preserves_pointer_until_a_checked_read():
    instructions = {0: ('adr', 'x0, 0x1000'), 4: ('b', '0x8'),
                    8: ('ldaprb', 'w0, [x0]'), 12: ('ret', '')}
    graph, _ = activation.cfg(0, 16, instructions, {'adr', 'ldaprb'})
    states, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert not problems
    assert activation.flag_accesses(instructions, states, 0x1000)[0]['address'] == '0x8'


def test_callee_saved_flag_pointer_survives_abi_call_but_volatile_does_not():
    instructions = {0: ("adr", "x20, 0x1000"), 4: ("bl", "0x2000"),
                    8: ("stlrb", "wzr, [x20]"), 12: ("ret", "")}
    graph, _ = activation.cfg(0, 16, instructions, {"adr", "stlrb"})
    states, problems = activation.propagate(graph, instructions, 0, 0x1000)
    assert not problems
    assert activation.flag_accesses(instructions, states, 0x1000)[0]['value'] == 0
    bad = dict(states)
    bad[8] = ({20: 0x1000}, {20})
    changed = dict(instructions, **{})
    changed[8] = ("str", "wzr, [x20]")
    with pytest.raises(ValueError, match="unresolved"):
        activation.flag_accesses(changed, bad, 0x1000)


def test_source_extra_access_and_changed_join_order_are_refused():
    text = (activation.ROOT / activation.WORKSPACE).read_text()
    assert len(activation.source_contract(text)['accesses']) == 5
    for changed in (text + '\nlet pointer = &ACTIVE;\n',
                    text.replace('request.result = execute(request);', 'other(request);')):
        with pytest.raises(ValueError):
            activation.source_contract(changed)


@pytest.fixture(scope="module")
def frozen():
    root = activation.ROOT
    analyzer = types.ModuleType('test_frozen_stack')
    template = root / activation.STACK / 'parliament_ballot_stack_audit.py.template'
    exec(compile(template.read_bytes(), str(template), 'exec'), analyzer.__dict__)
    boundary = json.loads((root / activation.FRONTIERS / 'report.json').read_text())
    build = json.loads((root / activation.BUILD / 'build-receipt.json').read_text())
    values = {}
    for mode in ('portable', 'accel'):
        stack = json.loads((root / activation.STACK / (mode + '.json')).read_text())
        stack['disassembly'] = (root / activation.STACK / mode / 'disassembly.txt').read_text()
        binary = Path(build['binaries'][mode]['path'])
        assert activation.sha(binary) == build['binaries'][mode]['sha256']
        values[mode] = stack, boundary['modes'][mode], binary.read_bytes()
    return analyzer, values


def test_exact_frozen_modes_and_retained_unknowns(frozen):
    analyzer, values = frozen
    expected = {'portable': ('0x100002944', '0x100002a58'), 'accel': ('0x100001a8c', '0x100001ba0')}
    for mode, arguments in values.items():
        result = activation.analyze_mode(analyzer, *arguments)
        assert (result['activation_store'], result['reservation_call']) == expected[mode]
        assert result['unconditional_activation'] == 'UNKNOWN'
        assert result['whole_binary_alias_or_callback_proof'] is False
        assert result['conditional_system_frontier_count_before'] == 14
        assert result['conditional_system_frontier_count_after'] == 10
        assert len(result['checked_native_allocation_sites']) == 4
        assert len(result['calls_between_activation_and_verification_requiring_noninterference']) == 3


@pytest.mark.parametrize('replacement', ['stlrb\twzr, [x9]', 'nop', 'strb\tw8, [x9]'])
def test_mutated_true_store_cannot_publish_conditional_pass(frozen, replacement):
    analyzer, values = frozen
    stack, boundary, binary = values['portable']
    changed = dict(stack)
    changed['disassembly'] = stack['disassembly'].replace('stlrb\tw8, [x9]', replacement)
    assert changed['disassembly'] != stack['disassembly']
    with pytest.raises(ValueError):
        activation.analyze_mode(analyzer, changed, boundary, binary)


def test_wrong_branch_polarity_and_reachable_writer_are_refused(frozen):
    analyzer, values = frozen
    stack, boundary, binary = values['portable']
    changed = dict(stack)
    changed['disassembly'] = stack['disassembly'].replace('cbz\tw8, 0x100002290', 'cbnz\tw8, 0x100002290')
    with pytest.raises(ValueError, match='zero-test'):
        activation.analyze_mode(analyzer, changed, boundary, binary)
    changed_boundary = copy.deepcopy(boundary)
    changed_boundary['conditional_boundary_roots']['reservation']['per_function_maximum_entry_sp_bytes']['0x100002778'] = 0
    with pytest.raises(ValueError, match='writer'):
        activation.analyze_mode(analyzer, stack, changed_boundary, binary)


def test_reference_scan_checks_page_and_function_ownership():
    instructions = {0: ('adrp', 'x8, 0x1000'), 4: ('add', 'x8, x8, #0x50'),
                    8: ('adrp', 'x8, 0x2000'), 12: ('add', 'x8, x8, #0x50')}
    fn = {0: {'address': '0x0', 'end': '0x10', 'name': 'fixture'}}
    refs = activation.references(instructions, 0x1050, fn)
    assert len(refs) == 1 and refs[0]['address'] == '0x0'
    with pytest.raises(ValueError, match='owner'):
        activation.references(instructions, 0x1050, {})


def test_new_directory_only_and_missing_evidence_retains_unknown(tmp_path):
    with pytest.raises(FileExistsError):
        activation.run(tmp_path, tmp_path)
    report = activation.run(tmp_path, tmp_path / 'new')
    assert report['status'] == 'UNKNOWN'
    assert report['complete_workspace_certificate'] is False
    assert json.loads((tmp_path / 'new/report.json').read_text()) == report


@pytest.mark.parametrize('status,code', [('PASS_UNDER_PREMISES', 0), ('UNKNOWN', 1)])
def test_cli_exit_does_not_promote_unknown(monkeypatch, capsys, tmp_path, status, code):
    monkeypatch.setattr(sys, 'argv', ['activation', '--output', str(tmp_path / 'new')])
    monkeypatch.setattr(activation, 'run', lambda root, output: {'status': status})
    assert activation.main() == code
    value = json.loads(capsys.readouterr().out)
    assert value['status'] == status and value['complete_workspace_certificate'] is False
