"""Independent arithmetic, CFG-bypass and mutation tests for free predicates."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_free_predicates as free


@pytest.fixture(scope='module')
def frozen():
    parser = free.module(free.ROOT / free.STACK / 'parliament_ballot_stack_audit.py.template', 'test_free_stack')
    control = free.module(free.ROOT / free.ACTIVATION / 'parliament_ballot_allocator_activation.py.template', 'test_free_cfg')
    boundary = json.loads((free.ROOT / free.FRONTIERS / 'report.json').read_text())
    build = json.loads((free.ROOT / free.BUILD).read_text())
    modes = {}
    for mode in ('portable', 'accel'):
        stack = json.loads((free.ROOT / free.STACK / (mode + '.json')).read_text())
        for key in ('disassembly', 'stubs'):
            stack[key] = (free.ROOT / free.STACK / mode / (key + '.txt')).read_text()
        binary = Path(build['binaries'][mode]['path'])
        assert free.sha(binary) == build['binaries'][mode]['sha256']
        modes[mode] = stack, boundary['modes'][mode], binary.read_bytes()
    return parser, control, modes


def test_all_twenty_sites_and_conditional_limits(frozen):
    parser, control, modes = frozen
    for arguments in modes.values():
        result = free.analyze_mode(parser, control, *arguments)
        assert len(result['sites']) == 10
        assert result['free_frontiers_before'] == result['free_frontiers_after'] == 10
        assert result['unconditional_ownership'] == 'UNKNOWN'
        assert result['all_input_allocation_correspondence'] is False
        assert result['arena_symbol']['address'] == '0x1000d4d48'
        origins = [x['pointer_origin'] for x in result['sites']]
        containers = [x['capacity_word'] for x in origins if 'capacity_word' in x]
        assert len(containers) == 8
        assert sum(len(x['guards']) for x in containers) == 11
        assert sorted(x['pointer_word_offset'] for x in containers) == [8, 8, 8, 32, 56, 80, 104, 128]
        assert all(x['unconditional_frontier'] == 'OPEN' for x in result['sites'])


def test_flags_partition_against_independent_subtraction_and_boundaries():
    table = free.range_partition()
    rows = {(r['pointer_below_heap'], r['wrapped_difference_below_bytes']): r for r in table['rows']}
    # Width-four exhaustive model uses extended subtraction carry, independent
    # of the helper's Boolean partition; include every P/H/N triple.
    for bits, values in ((4, range(16)), (64, [0, 1, 2, 15, 16, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1])):
        radix = 1 << bits
        for pointer in values:
            for heap in values:
                subtraction = pointer + ((radix - 1) ^ heap) + 1
                diff, carry = subtraction % radix, subtraction // radix
                for size in values:
                    second = diff + ((radix - 1) ^ size) + 1
                    final_carry = second // radix if carry else 1
                    actual = final_carry == 0
                    assert actual == (heap <= pointer < heap + size)
                    assert rows[(pointer < heap, diff < size)]['B_LO_taken'] == actual


@pytest.mark.parametrize('old,new', [
    ('ccmp\tx10, x11, #0x2, hs', 'ccmp\tx10, x11, #0x0, hs'),
    ('ccmp\tx10, x11, #0x2, hs', 'ccmp\tx10, x11, #0x2, lo'),
    ('subs\tx10, x8, x10', 'subs\tx10, x9, x10'),
    ('subs\tx10, x8, x10', 'sub\tx10, x8, x10'),
    ('stlurb\twzr, [x0, #0x50]', 'cmp\tx8, #0x0'),
    ('ldr\tx11, [x0, #0x10]', 'ldr\tx11, [x0, #0x8]'),
    ('ldapr\tx0, [x10]', 'ldr\tx0, [x10]'),
    ('cbz\tx0, 0x100001b34', 'cbnz\tx0, 0x100001b34'),
    ('b.lo\t0x100001b44', 'b.hs\t0x100001b44'),
    ('mov\tx0, x8', 'mov\tx0, x9'),
    ('casab\tw11, w10, [x12]', 'casab\tw8, w10, [x12]'),
    ('add\tx10, x10, #0xd48', 'add\tx10, x10, #0xd50'),
    ('b\t0x10005b19c', 'b\t0x10005b1e4'),
])
def test_changed_routing_shapes_never_publish_pass(frozen, old, new):
    parser, control, modes = frozen
    stack, boundary, binary = modes['portable']
    changed = dict(stack, disassembly=stack['disassembly'].replace(old, new))
    assert changed['disassembly'] != stack['disassembly']
    with pytest.raises(ValueError):
        free.analyze_mode(parser, control, changed, boundary, binary)


@pytest.mark.parametrize('old,new', [
    ('cbz\tx9, 0x100001b60', 'cbnz\tx9, 0x100001b60'),
    ('cbnz\tx9, 0x100001bf0', 'cbz\tx9, 0x100001bf0'),
    ('ldr\tx9, [x19, #0x18]', 'ldr\tx9, [x19, #0x20]'),
    ('ldr\tx8, [x0, #0x8]', 'ldr\tx8, [x0, #0x10]'),
    ('mov\tx21, x0', 'mov\tx21, x1'),
    ('mov\tx19, x0', 'mov\tx19, x1'),
    ('mov\tx22, x3', 'mov\tx0, x3'),
    ('100002300:     \tadd\tx29, sp, #0x20', '100002300:     \tmov\tx0, x1'),
])
def test_capacity_guard_and_abi_origin_mutations_fail(frozen, old, new):
    parser, control, modes = frozen
    stack, boundary, binary = modes['portable']
    changed = dict(stack, disassembly=stack['disassembly'].replace(old, new))
    assert changed['disassembly'] != stack['disassembly']
    with pytest.raises(ValueError):
        free.analyze_mode(parser, control, changed, boundary, binary)


def test_unlisted_or_missing_free_site_is_unknown(frozen):
    parser, control, modes = frozen
    stack, boundary, binary = modes['portable']
    changed = copy.deepcopy(boundary)
    entries = changed['conditional_boundary_roots']['reservation']['frontiers']
    entries[:] = [x for x in entries if x['address'] != '0x100002368']
    with pytest.raises(ValueError, match='ten'):
        free.analyze_mode(parser, control, stack, changed, binary)


def test_explicit_cfg_bypass_and_arena_arm_cannot_reach_free(frozen):
    parser, control, modes = frozen
    stack, boundary, _ = modes['portable']
    instructions, _ = parser.parse_disassembly(stack['disassembly'])
    start, site = 0x100001ac8, 0x100001b40
    graph, _ = control.cfg(start, 0x100001b6c, instructions, parser.STRAIGHT)
    for source, destination in ((start, site), (start, 0x100001b34), (0x100001b44, site), (start, 0x100001b1c)):
        changed = copy.deepcopy(graph)
        changed[source].append(destination)
        with pytest.raises(ValueError):
            free.local_predicate(control, instructions, changed, start, site)


def test_pointer_register_check_includes_aliases_calls_and_unknown_writes():
    assert free.writes(('mov', 'w8, #0x0'), 'x8')
    assert free.writes(('ldp', 'x7, x8, [sp]'), 'x8')
    assert free.writes(('bl', '0x1000'), 'x8')
    assert not free.writes(('bl', '0x1000'), 'x21')
    assert not free.writes(('str', 'x8, [sp]'), 'x8')
    for instruction in [('movk', 'x8, #0x8'), ('ldp', 'x8, x9, [x10], #0x10'), ('str', 'x8, [x9]!')]:
        with pytest.raises(ValueError):
            free.writes(instruction, 'x8')


def test_preservation_checks_diamond_paths_and_missing_path(frozen):
    _, control, _ = frozen
    graph = {0: [4, 8], 4: [12], 8: [12], 12: []}
    instructions = {0: ('cbz', 'x0, 0x8'), 4: ('mov', 'x1, x2'), 8: ('mov', 'w8, #0x0'), 12: ('ret', '')}
    with pytest.raises(ValueError, match='overwritten'):
        free.preserved(control, graph, instructions, 0, 12, 'x8')
    with pytest.raises(ValueError, match='no path'):
        free.preserved(control, graph, instructions, 4, 8, 'x8')


def test_helper_load_hash_and_missing_instruction(tmp_path):
    source = tmp_path / 'helper.py'
    source.write_text('value = 17\n')
    assert free.module(source, 'synthetic_helper').value == 17
    assert len(free.sha(source)) == 64
    assert free.normalized(('b', '0x100 <symbol>')) == ('b', '0x100')
    with pytest.raises(ValueError, match='missing'):
        free.instruction_at({}, 0)


def test_run_guards_artifacts_and_refuses_existing_output(tmp_path):
    output = tmp_path / 'analysis'
    result = free.run(free.ROOT, output)
    assert result['status'] == 'PASS_UNDER_PREMISES'
    assert result['input_changes'] == {}
    assert result['complete_workspace_certificate'] is False
    assert result['profile_qualified'] is False
    with pytest.raises(FileExistsError):
        free.run(free.ROOT, output)
    missing = free.run(tmp_path / 'missing', tmp_path / 'unknown')
    assert missing['status'] == 'UNKNOWN'
    assert 'FileNotFoundError' in missing['failure']


def test_main_exit_and_output_path_are_explicit(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(free, 'ROOT', tmp_path / 'absent')
    monkeypatch.setattr(sys, 'argv', ['free', '--output', str(tmp_path / 'analysis')])
    assert free.main() == 1
    assert json.loads(capsys.readouterr().out)['profile_qualified'] is False


def test_build_receipt_is_bound_to_frozen_frontier_digest(tmp_path):
    path = tmp_path / 'build.json'
    path.write_text('original')
    boundary = {'inputs': {str(path): free.sha(path)}}
    good = {'build_passed': True, 'source_changes': {}}
    free.verify_build_receipt(boundary, path, good)
    for bad in ({'build_passed': False, 'source_changes': {}},
                {'build_passed': True, 'source_changes': {'changed': 'file'}}):
        with pytest.raises(ValueError):
            free.verify_build_receipt(boundary, path, bad)
    path.write_text('repinned')
    with pytest.raises(ValueError, match='pin'):
        free.verify_build_receipt(boundary, path, good)


def test_capture_binary_and_listing_identity_must_agree(frozen):
    _, _, modes = frozen
    stack, boundary, _ = modes['portable']
    build = json.loads((free.ROOT / free.BUILD).read_text())
    binary = Path(build['binaries']['portable']['path'])
    expected = build['binaries']['portable']['sha256']
    free.verify_image(boundary, stack, expected, binary)
    for field, value in [('binary_sha256', 'f' * 64), ('binary_tool_and_analyzer_unchanged_during_capture', False)]:
        changed = copy.deepcopy(stack)
        changed['identity'][field] = value
        with pytest.raises(ValueError):
            free.verify_image(boundary, changed, expected, binary)
    for key in ('stubs', 'disassembly'):
        changed = dict(stack)
        changed[key] += '\n'
        with pytest.raises(ValueError, match='listing'):
            free.verify_image(boundary, changed, expected, binary)
