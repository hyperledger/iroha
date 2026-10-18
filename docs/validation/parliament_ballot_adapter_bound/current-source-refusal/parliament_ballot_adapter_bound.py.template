#!/usr/bin/env python3
"""Bound the current in-memory adapter, keeping the verifier/native costs opaque.

Requires Python 3.11+, retained fatal-stack EON evidence and its unchanged build
inputs. No environment variables, builds or executable runs. --output must be
new. This is a conditional source/compiled argument, not a workspace certificate.
"""
import argparse
from collections import deque
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re

FROZEN_MANIFEST = '44f4361b01a7f4d78805055b187a8073448d516391bd407c91c70b658fa0ea48'
PATTERNS = {'worker': 'workspace::worker::', 'allocate': 'arena::Arena::allocate::',
            'dealloc': '__rustc::__rust_dealloc', 'wrapper': 'workspace::exhausted::',
            'fatal': 'fatal::exhausted::', 'shim': '__rustc::__rust_no_alloc_shim_is_unstable_v2'}
BODY_HASHES = {
    'portable': ['575454f9b06c1f84fca4bc0ef1b53424104dcbae49635a3924d80341d5fa49de',
                 '41345e5f647e32d930282a23a51fa5d37b89db153dadc4fbde852574ced3a04f',
                 '0ef3126d02c47da35084b2ba16af2fb41d0fcd92fa1a59e67124c7c1a6d9df2b',
                 '827d82d62c29dfcd3afe860cd4c5c57200b348a3f463ac918391b73fd8b26be4',
                 'df4ff970b883ca10419150440dcd552c120611f4c009502af174fa6a2e29e884',
                 'd26af33cb1a3738fed35878a494508eee027562c70c01e27566da9e9e44d3d38'],
    'accel': ['b5807e54ac5f441a1ca8a8899cee051f5e570dc2962a819899837df32ab3367f',
              '974aacb2f61c26ecace747f4a389addbfa357da22eaa18f64d6324a4971bb591',
              'e7db5b5ca3a4793f2bcbbb378b1572b5449c23d50e1a6380e1d74937942fa997',
              '818816a233b26d0fb9771c354a6daa67b2b85acc180b2f081255925839213fed',
              '6601fc8bc34fc4cba1dec61db0836b81bf49a2d32bd564f5aa1246893d51b092',
              'd26af33cb1a3738fed35878a494508eee027562c70c01e27566da9e9e44d3d38']}
# Offsets identify reviewed conditional predicates, not unconditional reachability.
# False keeps fallthrough; True keeps the branch target. Every cut is conditional
# on a stated source/ABI/private-state premise, and only applies to this image.
CUTS = {
    'worker': {0xb4: (False, 'initialized retained fatal page'),
               0xc0: (False, 'fresh SETUP slot before one admission'),
               0xf0: (False, 'own ACTIVE release-store true dominates acquire-load'),
               0x100: (False, 'published retained nonnull ARENA')},
    'allocate': {0x14: (True, 'uncontended CASAB succeeds; no spurious failure')},
    'dealloc': {0x14: (False, 'published retained nonnull ARENA'),
                0x2c: (True, 'uncontended contains CASAB succeeds'),
                0x58: (True, 'same live arena-owned input pointer lies in arena'),
                0x78: (True, 'uncontended release CASAB succeeds'),
                0xb8: (False, 'layout size N<=425984 align1 makes rounded block nonzero')},
}
# Source tree height is log2((32MiB)/64)=19. Using 19 backedges is conservative
# even where 19 iterations imply only 18 taken backedges.
LOOPS = {'allocate': {(0x104, 0xd8): 19, (0x13c, 0x114): 19},
         'dealloc': {(0x12c, 0xf0): 19}}


def digest(path):
    """Bind exact evidence bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def frozen_inputs(root):
    """Verify the pinned prior artifact and every inherited source/tool guard."""
    directory = root / 'docs/validation/parliament_ballot_fatal_stack_eon'
    manifest = directory / 'SHA256SUMS'
    if digest(manifest) != FROZEN_MANIFEST:
        raise ValueError('frozen EON manifest changed')
    guards = {str(manifest): digest(manifest)}
    names = set()
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None or match[2] in names:
            raise ValueError('invalid frozen manifest')
        names.add(match[2])
        path = (directory / match[2]).resolve()
        if not path.is_relative_to(directory.resolve()) or digest(path) != match[1]:
            raise ValueError('frozen evidence changed')
        guards[str(path)] = match[1]
    receipt = json.loads((directory / 'receipt.json').read_text())
    if receipt['capture_passed'] is not True or receipt['input_changes'] != {}:
        raise ValueError('prior capture failed')
    for name, expected in receipt['input_sha256'].items():
        if digest(name) != expected:
            raise ValueError('inherited source/tool input changed: ' + name)
        if name in guards and guards[name] != expected:
            raise ValueError('conflicting evidence identity')
        guards[name] = expected
    return directory, guards


def walk(instructions, start, end, entry, conditional, cuts, loops, callees, stubs):
    """Check a conditional CFG; bounded backedges must leave an acyclic graph.

    Each acyclic segment visits at most |V| instructions. With at most B declared
    backedges, |V|*(1+B) bounds local issued instructions, excluding callee bodies.
    This needs the separate source loop and edge-feasibility premises.
    """
    pending, graph, calls, applied = [entry], {}, [], []
    while pending:
        address = pending.pop()
        if address in graph:
            continue
        if not start <= address < end or address not in instructions:
            raise ValueError('unexpected adapter control escape')
        op, operands = instructions[address]
        edges = []
        if op == 'ret':
            pass
        elif op == 'bl':
            target = int(re.search(r'0x[0-9a-f]+', operands)[0], 16)
            if target in callees:
                name = callees[target]
            elif target in stubs and stubs[target] in {'_bzero', '_memcpy', '__exit'}:
                name = stubs[target]
            else:
                raise ValueError('unexpected adapter callee')
            calls.append({'address': hex(address), 'target': name})
            if name not in {'wrapper', 'fatal', '__exit'}:
                edges = [address + 4]
        elif op == 'b' or op in conditional:
            target = int(re.search(r'(?:^|,\s*)(0x[0-9a-f]+)', operands)[1], 16)
            edges = [target] if op == 'b' else [target, address + 4]
            if address - start in cuts:
                if op not in conditional:
                    raise ValueError('premise cut is not conditional')
                take, premise = cuts[address - start]
                edges = [target if take else address + 4]
                applied.append({'address': hex(address), 'instruction': [op, operands],
                                'kept_target': hex(edges[0]), 'premise': premise})
        elif op in {'br', 'blr', 'brk', 'udf', 'hlt'}:
            raise ValueError('unexpected opaque adapter continuation')
        else:
            edges = [address + 4]
        graph[address] = edges
        pending.extend(edges)
    if {int(item['address'], 16) - start for item in applied} != set(cuts):
        raise ValueError('unused conditional premise cut')
    capped = {(start + a, start + b): cap for (a, b), cap in loops.items()}
    if any(a not in graph or b not in graph[a] or type(cap) is not int or cap < 0
           for (a, b), cap in capped.items()):
        raise ValueError('missing or invalid bounded loop edge')
    degree = {n: 0 for n in graph}
    for a, edges in graph.items():
        for b in edges:
            if (a, b) not in capped:
                degree[b] += 1
    ready = deque(n for n in degree if degree[n] == 0)
    visited = 0
    while ready:
        a = ready.popleft()
        visited += 1
        for b in graph[a]:
            if (a, b) not in capped:
                degree[b] -= 1
                if degree[b] == 0:
                    ready.append(b)
    if visited != len(graph):
        raise ValueError('unbounded adapter CFG cycle')
    if capped and calls:
        raise ValueError('callee multiplicity inside bounded-loop function not modeled')
    return {'reachable_instructions': len(graph),
            'local_instruction_bound': len(graph) * (1 + sum(capped.values())),
            'conditional_cuts': applied, 'calls': calls,
            'loop_backedges': [{'source': hex(a), 'target': hex(b), 'maximum_taken': cap}
                               for (a, b), cap in capped.items()]}


def analyze_mode(mode, report, disassembly, starts_text, stubs_text, analyzer):
    """Apply reviewed source premises only to six exact retained function bodies."""
    if mode not in BODY_HASHES:
        raise ValueError('unknown compiled mode')
    instructions, _ = analyzer.parse_disassembly(disassembly)
    stubs = analyzer.parse_stubs(stubs_text)
    # Recompute the ordinary frame analysis, not merely trust report numbers.
    fresh = analyzer.audit(disassembly, starts_text, stubs_text,
                           ['workspace::worker::', 'fatal::exhausted::'])
    if fresh['functions'] != report['functions']:
        raise ValueError('frozen frame report differs from actual capture')
    functions = {}
    for key, pattern in PATTERNS.items():
        candidates = [fn for fn in fresh['functions'] if pattern in fn['name']]
        if len(candidates) != 1:
            raise ValueError('ambiguous adapter function')
        fn = candidates[0]
        start, end = int(fn['address'], 16), int(fn['end'], 16)
        body = [[a - start, *instructions[a]] for a in sorted(instructions) if start <= a < end]
        if hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest() != BODY_HASHES[mode][list(PATTERNS).index(key)]:
            raise ValueError('reviewed adapter body changed: ' + key)
        if fn['frame_errors']:
            raise ValueError('unresolved adapter frame')
        functions[key] = fn
    verifier = [fn for fn in fresh['functions'] if 'budget::Reservation::verify::' in fn['name']]
    if len(verifier) != 1:
        raise ValueError('opaque verifier entry ambiguous')
    callees = {int(fn['address'], 16): key for key, fn in functions.items()}
    callees[int(verifier[0]['address'], 16)] = 'OPAQUE_VERIFIER'
    results = {}
    for key, fn in functions.items():
        start, end = int(fn['address'], 16), int(fn['end'], 16)
        # Stack-query setup precedes this entry; the existing 176-byte worker
        # frame remains live and is still included in the adapter stack bound.
        entry = start + (0x5c if key == 'worker' else 0)
        result = walk(instructions, start, end, entry, analyzer.CONDITIONAL,
                      CUTS.get(key, {}), LOOPS.get(key, {}), callees, stubs)
        result.update(address=fn['address'], entry=hex(entry), name=fn['name'],
                      local_frame_bytes=fn['maximum_sp_decrement_bytes'])
        results[key] = result
    expected_calls = {'worker': ['OPAQUE_VERIFIER', '_bzero', '_memcpy', 'allocate', 'dealloc', 'shim', 'wrapper'],
                      'allocate': [], 'dealloc': [], 'wrapper': ['fatal'], 'fatal': ['__exit'], 'shim': []}
    if any(sorted(call['target'] for call in result['calls']) != expected_calls[key]
           for key, result in results.items()):
        raise ValueError('adapter call multiplicity differs')
    # All internal calls have one DAG call site; bounded-loop functions call none.
    # Retained frame reports give exact call-site depths, including fixed worker
    # frame storage for the opaque verifier's returned Receipt.
    native, visited = [], set()

    def bound(key, caller_depth):
        if key in visited:
            raise ValueError('adapter internal call sharing/recursion not modeled')
        visited.add(key)
        fn = functions[key]
        maximum = caller_depth + fn['local_frame_plus_red_zone_bytes']
        sites = {item['address']: item['caller_depth_bytes'] for item in fn['calls'] + fn['gaps']}
        for call in results[key]['calls']:
            depth = caller_depth + sites[call['address']]
            if call['target'] in results:
                maximum = max(maximum, bound(call['target'], depth))
            else:
                native.append({**call, 'live_caller_bytes': depth,
                               'additional_stack_bound_bytes': None, 'work_bound': None})
        return maximum

    stack = bound('worker', 0)
    if visited != set(results):
        raise ValueError('adapter body coverage differs')
    return {'verdict': 'PASS_UNDER_STATED_PREMISES', 'functions': results,
            'adapter_issued_instruction_bound_excluding_callees': sum(r['local_instruction_bound'] for r in results.values()),
            'adapter_owned_stack_bytes_including_red_zone': stack,
            'opaque_callees': native, 'maximum_input_bytes': 425984,
            'maximum_input_owned_block_bytes': 524288,
            'maximum_zeroed_bytes': 425984, 'maximum_copied_bytes': 425984,
            'complete_adapter_stack_bound_bytes': None, 'complete_adapter_work_bound': None,
            'complete_workspace_certificate': False, 'profile_qualified': False}


def run(root, output):
    """Retain a new, guarded conditional result; preserve failures and old evidence."""
    output.mkdir(parents=True, exist_ok=False)
    guards, modes, failure = {}, {}, None
    try:
        guards[str(Path(__file__).resolve())] = digest(__file__)
        test = root / 'scripts/tests/parliament_ballot_adapter_bound_test.py'
        guards[str(test)] = digest(test)
        (output / 'parliament_ballot_adapter_bound.py.template').write_bytes(Path(__file__).read_bytes())
        (output / (test.name + '.template')).write_bytes(test.read_bytes())
        directory, inherited = frozen_inputs(root)
        guards.update(inherited)
        path = directory / 'parliament_ballot_stack_audit.py.template'
        loader = importlib.machinery.SourceFileLoader('frozen_adapter_stack', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        analyzer = importlib.util.module_from_spec(spec)
        loader.exec_module(analyzer)
        for mode in ('portable', 'accel'):
            modes[mode] = analyze_mode(mode, json.loads((directory / (mode + '.json')).read_text()),
                                      (directory / mode / 'disassembly.txt').read_text(),
                                      (directory / mode / 'starts.txt').read_text(),
                                      (directory / mode / 'stubs.txt').read_text(), analyzer)
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for name, before in guards.items():
        after = digest(name) if Path(name).is_file() else None
        if after != before:
            changes[name] = {'before': before, 'after': after}
    result = {'schema': 'parliament-adapter-bound-v1',
              'verdict': 'PASS_UNDER_STATED_PREMISES' if failure is None and not changes and len(modes) == 2 else 'UNKNOWN',
              'failure': failure, 'modes': modes, 'input_sha256': guards, 'input_changes': changes,
              'complete_workspace_certificate': False, 'physical_cost_calibrated': False, 'profile_qualified': False}
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    """Require explicit repository and fresh result location."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.output.resolve())
    print(json.dumps({key: result[key] for key in ('verdict', 'failure', 'input_changes')}, indent=2))
    return 0 if result['verdict'] == 'PASS_UNDER_STATED_PREMISES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
