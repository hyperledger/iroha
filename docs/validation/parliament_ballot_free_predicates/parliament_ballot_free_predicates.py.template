#!/usr/bin/env python3
"""Check the twenty frozen ARM64 System-free routing predicates, not ownership.

Requires Python 3.11+, the retained stack/frontier/activation artifacts and original
worker executables. No environment variables, rebuild, execution or network access
is needed. Writes only a NEW output directory. Unexpected shapes yield UNKNOWN.
The results never remove an unconditional frontier or qualify a resource profile.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import struct
import types

ROOT = Path(__file__).resolve().parents[1]
STACK = Path('docs/validation/parliament_ballot_compiled_stack')
FRONTIERS = Path('docs/validation/parliament_ballot_stack_frontiers')
ACTIVATION = Path('docs/validation/parliament_ballot_allocator_activation')
BUILD = Path('docs/validation/parliament_ballot_resource_contract/build-receipt.json')
WORKSPACE = Path('crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs')
ARENA = WORKSPACE.with_name('arena.rs')


def sha(path: Path) -> str:
    """Hash exact bytes for before/after guards."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module(path: Path, name: str):
    """Load a previously verified frozen Python helper without importing live code."""
    result = types.ModuleType(name)
    result.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


def normalized(instruction: tuple) -> tuple:
    """Remove LLVM's symbolic annotation; preserve every operand and modifier."""
    op, args = instruction
    return op, re.sub(r' <[^>]*>$', '', args)


def instruction_at(instructions: dict, address: int) -> tuple:
    """Fail closed on a missing machine instruction."""
    if address not in instructions:
        raise ValueError('missing instruction at ' + hex(address))
    return normalized(instructions[address])


def writes(instruction: tuple, register: str) -> bool:
    """Conservative GPR-write check for only the instructions on reviewed paths."""
    op, args = normalized(instruction)
    alias = 'w' + register[1:]
    if op in {'bl', 'blr'}:
        return int(register[1:]) < 19
    if op == 'b' or op.startswith('b.') or op in {'cbz', 'cbnz', 'tbz', 'tbnz', 'ret', 'isb', 'cmp', 'ccmp', 'tst'}:
        return False
    if op in {'str', 'strb', 'stp', 'stlurb', 'stlrb'}:
        if ']!' in args or '],' in args:
            raise ValueError('unmodeled store writeback')
        return False
    if op in {'ldr', 'ldrb', 'ldapr', 'ldp', 'mov', 'adrp', 'add', 'sub', 'subs', 'csel', 'casab'}:
        if ']!' in args or '],' in args:
            raise ValueError('unmodeled load writeback')
        destinations = args.split(', ')[:2 if op == 'ldp' else 1]
        return register in destinations or alias in destinations
    raise ValueError('unmodeled register-writing instruction: ' + op)


def preserved(control, graph: dict, instructions: dict, start: int, end: int, register: str) -> None:
    """Require no register overwrite on any ordinary path between two nodes."""
    if not control.reaches(graph, start, end):
        raise ValueError('pointer flow has no path')
    for address in graph:
        if address == end:
            continue
        if control.reaches(graph, start, address) and control.reaches(graph, address, end):
            if writes(instructions[address], register):
                raise ValueError('register overwritten on pointer path: ' + hex(address))


def local_predicate(control, instructions: dict, graph: dict, start: int, site: int) -> dict:
    """Match the complete acquire/lock/range/null routing block and System tail.

    This establishes the predicate for values observed by this block, conditional
    on valid memory and ordinary instruction semantics. It does not establish
    that a pointer is live, owned by the arena, or within the observed bounds.
    """
    candidates = []
    for load in range(max(start, site - 128), site, 4):
        op, args = instruction_at(instructions, load)
        match = re.fullmatch(r'x0, \[(x\d+)\]', args)
        if op == 'ldapr' and match:
            candidates.append((load, match[1]))
    if len(candidates) != 1:
        raise ValueError('ambiguous arena acquire before free')
    load, base = candidates[0]
    heap = instruction_at(instructions, load + 52)
    size = instruction_at(instructions, load + 56)
    subtract = instruction_at(instructions, load + 60)
    heap_match = re.fullmatch(r'(x\d+), \[x0\]', heap[1])
    size_match = re.fullmatch(r'(x\d+), \[x0, #0x10\]', size[1])
    sub_match = re.fullmatch(r'(x\d+), (x\d+), (x\d+)', subtract[1])
    if heap[0] != 'ldr' or size[0] != 'ldr' or subtract[0] != 'subs' or not all((heap_match, size_match, sub_match)):
        raise ValueError('range load/subtraction shape changed')
    difference, length = heap_match[1], size_match[1]
    pointer = sub_match[2]
    if sub_match[1] != difference or sub_match[3] != difference or len({difference, length, pointer, 'x0'}) != 4:
        raise ValueError('range registers alias or subtract a different pointer')
    lock_old = instruction_at(instructions, load + 8)[1].split(', ')[0]
    lock_ptr = instruction_at(instructions, load + 12)[1].split(', ')[0]
    lock_new = instruction_at(instructions, load + 16)[1].split(', ')[0]
    if not re.fullmatch(r'w\d+', lock_old) or not re.fullmatch(r'w\d+', lock_new) or not re.fullmatch(r'x\d+', lock_ptr):
        raise ValueError('lock registers changed')
    if len({int(lock_old[1:]), int(lock_new[1:]), int(lock_ptr[1:]), int(pointer[1:]), 0}) != 5:
        raise ValueError('lock registers alias pointer/arena')
    system = load + 76
    arena_branch = load + 72
    arena_target = control.target(instructions[arena_branch][1])
    expected = [
        ('ldapr', f'x0, [{base}]'), ('cbz', f'x0, {hex(system)}'),
        ('mov', f'{lock_old}, #0x0'), ('add', f'{lock_ptr}, x0, #0x50'),
        ('mov', f'{lock_new}, #0x1'), ('casab', f'{lock_old}, {lock_new}, [{lock_ptr}]'),
        ('cmp', f'{lock_old}, #0x0'), ('b.eq', hex(load + 52)), ('isb', ''),
        ('mov', f'{lock_old}, #0x0'), ('add', f'{lock_ptr}, x0, #0x50'),
        ('casab', f'{lock_old}, {lock_new}, [{lock_ptr}]'), ('cbnz', f'{lock_old}, {hex(load + 32)}'),
        ('ldr', f'{difference}, [x0]'), ('ldr', f'{length}, [x0, #0x10]'),
        ('subs', f'{difference}, {pointer}, {difference}'), ('stlurb', 'wzr, [x0, #0x50]'),
        ('ccmp', f'{difference}, {length}, #0x2, hs'), ('b.lo', hex(arena_target)),
        ('mov', f'x0, {pointer}'),
    ]
    for index, wanted in enumerate(expected):
        if instruction_at(instructions, load + index * 4) != wanted:
            raise ValueError('routing block changed at ' + hex(load + index * 4))
    # Only reviewed epilogues can occur after passing the same pointer to x0.
    tail = [instruction_at(instructions, a) for a in range(system + 4, site, 4)]
    allowed_tails = [[], [('ldp', 'x29, x30, [sp, #0x20]'), ('add', 'sp, sp, #0x30')],
                     [('ldp', 'x29, x30, [sp, #0x30]'), ('ldp', 'x20, x19, [sp, #0x20]'), ('add', 'sp, sp, #0x40')]]
    if tail not in allowed_tails or instruction_at(instructions, site)[0] != ('bl' if not tail else 'b'):
        raise ValueError('System pointer forwarding/epilogue changed')
    if not control.reaches(graph, start, site):
        raise ValueError('listed System site unreachable')
    for required in (load, load + 4, system):
        if control.reaches(graph, start, site, {required}):
            raise ValueError('routing block bypass reaches System')
    if control.reaches(graph, load + 8, site, {arena_branch}) or control.reaches(graph, arena_target, site):
        raise ValueError('in-range/range-bypass arm reaches System')
    # The machine branch can enter only at the acquire; reject middle-block edges.
    covered = set(range(load, site + 4, 4))
    for source, successors in graph.items():
        for destination in successors:
            if destination in covered - {load} and source not in covered:
                raise ValueError('external edge enters routing block')
    preserved(control, graph, instructions, load, system, pointer)
    return {'arena_load': hex(load), 'arena_symbol_register': base,
            'pointer_register': pointer, 'null_branch': hex(load + 4),
            'heap_offset': 0, 'bytes_offset': 16, 'lock_offset': 80,
            'unsigned_subtract': hex(load + 60), 'conditional_compare': hex(load + 68),
            'in_range_branch': hex(arena_branch), 'in_range_successor': hex(arena_target),
            'system_pointer_move': hex(system), 'same_pointer_forwarded': True,
            'ordinary_cfg_bypass_absent': True,
            'snippet': [{'address': hex(a), 'op': instructions[a][0], 'operands': instructions[a][1]} for a in range(load, site + 4, 4)]}


def pointer_origin(control, instructions: dict, graph: dict, start: int, predicate: dict, name: str) -> dict:
    """Check observed container word loads or ABI input copies, without ownership."""
    load = int(predicate['arena_load'], 16)
    pointer = predicate['pointer_register']
    generic = name in {'__rustc::__rust_dealloc', '__rustc::__rust_realloc'}
    if generic:
        origins = [a for a in graph if instruction_at(instructions, a) == ('mov', f'{pointer}, x0') and a < load]
    else:
        origins = [a for a in graph if a < load and instructions[a][0] == 'ldr' and instructions[a][1].startswith(pointer + ', [')]
    # Later destructor fields are independent; choose the most recent dominating load.
    origins = [a for a in origins if control.reaches(graph, a, load) and not control.reaches(graph, start, load, {a})]
    if not origins:
        raise ValueError('no dominating pointer origin')
    origin = max(origins)
    preserved(control, graph, instructions, origin + 4, load, pointer)
    result = {'instruction': hex(origin), 'op': instructions[origin][0], 'operands': instructions[origin][1],
              'classification': 'allocator_ABI_input' if generic else 'container_pointer_word',
              'allocation_provenance_proved': False}
    if generic:
        preserved(control, graph, instructions, start, origin, 'x0')
        return result
    match = re.fullmatch(r'x8, \[(x0|x19), #0x([0-9a-f]+)\]', instructions[origin][1])
    if not match or int(match[2], 16) not in {8, 32, 56, 80, 104, 128}:
        raise ValueError('unknown container pointer word')
    offset = int(match[2], 16)
    base = match[1]
    if base == 'x0':
        preserved(control, graph, instructions, start, origin, 'x0')
    else:
        copies = [a for a in graph if instruction_at(instructions, a) == ('mov', 'x19, x0')
                  and not control.reaches(graph, start, origin, {a})]
        if len(copies) != 1:
            raise ValueError('container base lacks unique dominating ABI input copy')
        preserved(control, graph, instructions, start, copies[0], 'x0')
        preserved(control, graph, instructions, copies[0] + 4, origin, 'x19')
    result['base_is_original_ABI_input_under_ordinary_call_semantics'] = True
    guards = []
    for branch in graph:
        op, operands = instruction_at(instructions, branch)
        if op not in {'cbz', 'cbnz'} or not operands.startswith('x9, '):
            continue
        destination = control.target(operands)
        nonzero = branch + 4 if op == 'cbz' else destination
        zero = destination if op == 'cbz' else branch + 4
        if not control.reaches(graph, nonzero, origin) or control.reaches(graph, zero, origin):
            continue
        capacity = [a for a in range(max(start, branch - 12), branch, 4)
                    if instruction_at(instructions, a) == ('ldr', 'x9, [x0]' if offset == 8 else f'x9, [x19, #0x{offset - 8:x}]')]
        if len(capacity) != 1:
            raise ValueError('capacity-word load changed')
        if offset == 8:
            preserved(control, graph, instructions, start, capacity[0], 'x0')
        else:
            preserved(control, graph, instructions, copies[0] + 4, capacity[0], 'x19')
        preserved(control, graph, instructions, capacity[0] + 4, branch, 'x9')
        if control.reaches(graph, start, branch, {capacity[0]}):
            raise ValueError('capacity test bypasses its load')
        guards.append({'load': hex(capacity[0]), 'branch': hex(branch), 'opcode': op,
                       'zero_successor': hex(zero), 'nonzero_successor': hex(nonzero)})
    if not guards or control.reaches(graph, start, origin, {int(g['branch'], 16) for g in guards}):
        raise ValueError('nonzero capacity-word guards do not cut every pointer-load path')
    result['capacity_word'] = {'offset': offset - 8, 'pointer_word_offset': offset,
                               'guards': guards, 'zero_branch_cannot_reach_pointer_load': True,
                               'source_layout_correspondence_is_premise': True}
    return result


def range_partition() -> dict:
    """Show the exhaustive comparison partition underlying SUBS/CCMP/B.LO.

    ARM64 SUBS C means no borrow (P>=H); HS tests C=1; #2 fallback
    is NZCV=0010, hence C=1 and LO=false. When HS holds, CCMP's C
    is the no-borrow bit for (P-H)-N. Thus LO holds iff P>=H and P-H<N.
    """
    rows = []
    for below in (False, True):
        for diff_less in (False, True):
            carry_subs = not below
            carry_ccmp = not diff_less if carry_subs else True
            rows.append({'pointer_below_heap': below, 'wrapped_difference_below_bytes': diff_less,
                         'SUBS_C': int(carry_subs), 'CCMP_C': int(carry_ccmp),
                         'B_LO_taken': not carry_ccmp,
                         'expected_contains': not below and diff_less})
    if any(row['B_LO_taken'] != row['expected_contains'] for row in rows):
        raise ValueError('flag partition disagrees')
    return {'word_bits': 64, 'fallback_NZCV': '0010', 'rows': rows,
            'in_range': 'P >= H and P - H < N',
            'system_when_local_block_returns': 'ARENA == null or P < H or P - H >= N',
            'nontermination_fault_unwind_absence_proved': False}


def analyze_mode(parser, control, stack: dict, boundary: dict, data: bytes) -> dict:
    """Check all ten listed free sites without pruning any native frontier."""
    control.FLAG_NAME = re.compile(r'__ZN17resource_contract9workspace5ARENA17h[0-9a-f]{16}E(?:\.0)?')
    symbol = control.active_symbol(data)
    address = int(symbol['address'], 16)
    instructions, _ = parser.parse_disassembly(stack['disassembly'])
    functions = {int(fn['address'], 16): fn for fn in stack['functions']}
    stubs = parser.parse_stubs(stack['stubs'])
    refs = control.references(instructions, address, functions)
    sites = [x for x in boundary['conditional_boundary_roots']['reservation']['frontiers'] if x.get('detail') == '_free']
    if len(sites) != 10:
        raise ValueError('expected ten explicit free frontiers')
    checked = []
    for site in sites:
        owners = [f for f in functions.values() if f['name'] == site['function']]
        if len(owners) != 1:
            raise ValueError('ambiguous free-site owner')
        owner = owners[0]
        if stubs.get(control.target(instructions[int(site['address'], 16)][1])) != '_free':
            raise ValueError('listed site no longer targets native free')
        start, end = int(owner['address'], 16), int(owner['end'], 16)
        graph, _ = control.cfg(start, end, instructions, parser.STRAIGHT)
        item = local_predicate(control, instructions, graph, start, int(site['address'], 16))
        load = int(item['arena_load'], 16)
        materializations = [ref for ref in refs if ref['function_address'] == owner['address']
                            and ref['register'] == item['arena_symbol_register']
                            and control.reaches(graph, int(ref['address'], 16) + 8, load)
                            and not control.reaches(graph, start, load, {int(ref['address'], 16)})]
        if len(materializations) != 1:
            raise ValueError('arena symbol materialization does not dominate acquire')
        materialization = materializations[0]
        preserved(control, graph, instructions, int(materialization['address'], 16) + 8, load, materialization['register'])
        item['symbol_materialization'] = materialization
        item['pointer_origin'] = pointer_origin(control, instructions, graph, start, item, owner['name'])
        checked.append({**site, **item, 'local_predicate_status': 'PASS_UNDER_PREMISES', 'unconditional_frontier': 'OPEN'})
    if sum('capacity_word' in x['pointer_origin'] for x in checked) != 8:
        raise ValueError('expected eight container capacity-word guards')
    return {'local_checks': 'PASS', 'arena_symbol': symbol, 'sites': checked,
            'free_frontiers_before': 10, 'free_frontiers_after': 10,
            'unconditional_ownership': 'UNKNOWN', 'all_input_allocation_correspondence': False}


def verify_build_receipt(boundary: dict, path: Path, build: dict) -> None:
    """Require the original receipt digest pinned by the frozen frontier report."""
    if boundary['inputs'].get(str(path)) != sha(path):
        raise ValueError('original build receipt differs from frozen frontier pin')
    if not build['build_passed'] or build['source_changes']:
        raise ValueError('original build failed or sources changed')


def verify_image(boundary: dict, stack: dict, expected: str, binary: Path) -> None:
    """Connect current executable and captured listings to the same original image."""
    identity = stack['identity']
    if (sha(binary) != expected or boundary['binary_sha256'] != expected
            or identity['binary_sha256'] != expected
            or not identity['binary_tool_and_analyzer_unchanged_during_capture']):
        raise ValueError('original binary/capture identity changed')
    for key in ('disassembly', 'stubs'):
        commands = [entry for entry in identity['commands'] if Path(entry['output']).name == key + '.txt']
        if len(commands) != 1 or hashlib.sha256(stack[key].encode()).hexdigest() != commands[0]['sha256']:
            raise ValueError('captured listing identity changed: ' + key)


def run(root: Path, output: Path) -> dict:
    """Guard frozen inputs and publish a new report; never re-pin old evidence."""
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(Path(__file__).resolve()): sha(Path(__file__).resolve()),
              str(Path(sys.executable).resolve()): sha(Path(sys.executable).resolve())}
    report = {'schema': 'parliament-free-predicates-v1', 'status': 'UNKNOWN', 'inputs': inputs,
              'modes': {}, 'complete_workspace_certificate': False, 'profile_qualified': False,
              'complete_stack_bound_bytes': None, 'no_rebuild_or_execution': True,
              'premises': ['Correct disassembly/source/compiler correspondence and ordinary ARM64 instruction/call semantics.',
                           'Valid memory, immutable live arena bounds, correct GlobalAlloc caller pointer/layout/liveness contract.',
                           'Opaque calls, native callbacks and other threads preserve private state and callee-saved registers; no adversarial reentry.',
                           'Container word identification is source/compiler conditional; Rust field offsets are not stable ABI.'],
              'limitations': ['No pointer ownership, arena non-null lifetime, all-input allocation correspondence or native endpoint bound is proved.',
                              'Lock termination, faults, traps, callbacks, failure paths and unwind behavior remain open.',
                              'Contains checks range only; range membership does not establish a live allocation or a correct layout.',
                              'All ten unconditional free frontiers in each original Reservation graph remain OPEN.']}
    try:
        for directory in (STACK, FRONTIERS, ACTIVATION):
            manifest = root / directory / 'SHA256SUMS'
            inputs[str(manifest)] = sha(manifest)
            for line in manifest.read_text().splitlines():
                expected, relative = line.split('  ', 1)
                path = root / relative
                if sha(path) != expected:
                    raise ValueError('frozen artifact changed: ' + relative)
                inputs[str(path)] = expected
        build_path = root / BUILD
        inputs[str(build_path)] = sha(build_path)
        build = json.loads(build_path.read_text())
        boundary = json.loads((root / FRONTIERS / 'report.json').read_text())
        verify_build_receipt(boundary, build_path, build)
        for relative in (WORKSPACE, ARENA):
            path = root / relative
            if sha(path) != build['started_source_sha256'][str(relative)]:
                raise ValueError('frozen source mismatch: ' + str(relative))
            inputs[str(path)] = sha(path)
            (output / (path.name + '.template')).write_bytes(path.read_bytes())
        source = (root / ARENA).read_text()
        if source.count('address >= start && address - start < inner.bytes') != 1:
            raise ValueError('source contains predicate changed')
        report['source_contains_expression'] = 'address >= start && address - start < inner.bytes'
        report['flag_partition'] = range_partition()
        parser = module(root / STACK / 'parliament_ballot_stack_audit.py.template', 'frozen_free_stack')
        control = module(root / ACTIVATION / 'parliament_ballot_allocator_activation.py.template', 'frozen_free_cfg')
        for mode in ('portable', 'accel'):
            binary = Path(build['binaries'][mode]['path'])
            expected = build['binaries'][mode]['sha256']
            inputs[str(binary)] = expected
            stack = json.loads((root / STACK / (mode + '.json')).read_text())
            stack['disassembly'] = (root / STACK / mode / 'disassembly.txt').read_text()
            stack['stubs'] = (root / STACK / mode / 'stubs.txt').read_text()
            verify_image(boundary['modes'][mode], stack, expected, binary)
            report['modes'][mode] = analyze_mode(parser, control, stack, boundary['modes'][mode], binary.read_bytes())
            report['modes'][mode]['binary_sha256'] = expected
        report['status'] = 'PASS_UNDER_PREMISES'
    except (ValueError, KeyError, OSError, UnicodeError, struct.error) as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    report['input_changes'] = {name: {'before': expected, 'after': sha(Path(name)) if Path(name).is_file() else None}
                               for name, expected in inputs.items() if not Path(name).is_file() or sha(Path(name)) != expected}
    if report['input_changes']:
        report['status'] = 'UNKNOWN'
    report['observed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main() -> int:
    """Expose safe fresh-directory output and a nonzero UNKNOWN outcome."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new output directory; existing paths refused')
    arguments = parser.parse_args()
    report = run(ROOT, arguments.output.resolve())
    print(json.dumps({'status': report['status'], 'failure': report.get('failure'), 'profile_qualified': False}))
    return 0 if report['status'] == 'PASS_UNDER_PREMISES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
