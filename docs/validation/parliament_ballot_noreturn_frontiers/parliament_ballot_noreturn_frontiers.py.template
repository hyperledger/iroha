#!/usr/bin/env python3
"""Classify frozen fallthrough/trap frontiers using justified normal-return cuts.

Python 3.11+, prior frozen B6 artifacts and original ARM64 executables are required.
No environment variables, compilation, execution or network access is needed.
Only a NEW output directory is written. Existing evidence is never changed.
Three prior pinned Rust `!` declarations are the only seeds. A least fixed point
may derive additional local functions; native endpoints and exceptional effects
remain unknown-cost boundaries. This is not a full resource or termination proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime
import hashlib
import json
from pathlib import Path
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
STACK = Path('docs/validation/parliament_ballot_compiled_stack')
FRONTIERS = Path('docs/validation/parliament_ballot_stack_frontiers')
ACTIVATION = Path('docs/validation/parliament_ballot_allocator_activation')
FREE = Path('docs/validation/parliament_ballot_free_predicates')
BUILD = Path('docs/validation/parliament_ballot_resource_contract/build-receipt.json')
SEEDS = {'alloc::alloc::handle_alloc_error', 'core::panicking::panic_fmt', 'core::panicking::panic_nounwind_fmt'}


def sha(path: Path) -> str:
    """Hash exact bytes before and after analysis."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module(path: Path, name: str):
    """Load only manifest-verified frozen helper code."""
    result = types.ModuleType(name)
    result.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


def normal_reach(control, start: int, graph: dict, instructions: dict, known: set) -> tuple:
    """Walk both outcomes, retaining unknown-call continuations and stopping known BLs."""
    todo, seen, stops = [start], set(), {}
    while todo:
        address = todo.pop()
        if address in seen:
            continue
        if address not in graph:
            raise ValueError('missing normal CFG node')
        seen.add(address)
        op, operands = instructions[address]
        if op == 'bl' and control.target(operands) in known:
            stops[address] = control.target(operands)
        else:
            todo.extend(graph[address])
    return seen, stops


def assess(control, start: int, graph: dict, exits: list, instructions: dict, known: set) -> dict:
    """Require every reachable ordinary return/exit to be a justified failure cut.

    Calls can unwind or act outside ordinary flow; those costs are retained.
    Unknown native tails, BRKs and fallthroughs are not divergence evidence.
    A closed loop alone is deliberately insufficient for this bounded checker.
    """
    seen, stops = normal_reach(control, start, graph, instructions, known)
    bad, tails, calls = [], [], []
    for item in exits:
        address = int(item['address'], 16)
        if address not in seen:
            continue
        kind = item['kind']
        if kind in {'bl', 'blr'}:
            calls.append(item)
        elif kind == 'tail' and int(item['target'], 16) in known:
            tails.append(item)
        elif kind == 'function_fallthrough' and address in stops:
            pass  # Only the normal continuation is excluded; the call remains.
        else:
            bad.append(item)
    established = not bad and bool(stops or tails)
    return {'no_normal_return_established': established,
            'reachable_instructions': [hex(a) for a in sorted(seen)],
            'normal_return_cuts': [{'address': hex(a), 'target': hex(t)} for a, t in sorted(stops.items())],
            'known_noreturn_tails': tails, 'blocking_exits': bad,
            'reachable_calls_with_unknown_exceptional_or_native_cost': calls,
            'termination_or_resource_cost_established': False}


def least_fixed_point(control, candidates: dict, instructions: dict, seeds: set) -> dict:
    """Derive each round using only earlier rounds; recursive assumptions are refused."""
    known, rounds, proofs = set(seeds), [], {}
    while True:
        additions = {}
        for start, (graph, exits) in candidates.items():
            if start in known:
                continue
            proof = assess(control, start, graph, exits, instructions, known)
            if proof['no_normal_return_established']:
                additions[start] = proof
        if not additions:
            break
        round_number = len(rounds) + 1
        rounds.append([hex(a) for a in sorted(additions)])
        for start, proof in additions.items():
            proofs[hex(start)] = {**proof, 'round': round_number}
        known.update(additions)
    remaining = {hex(a): assess(control, a, g, e, instructions, known)
                 for a, (g, e) in candidates.items() if a not in known}
    return {'known': known, 'rounds': rounds, 'proofs': proofs, 'remaining': remaining}


def analyze_mode(parser, control, stack: dict, boundary: dict) -> dict:
    """Classify each original gap under normal semantics; keep all old costs open."""
    instructions, _ = parser.parse_disassembly(stack['disassembly'])
    functions = {int(f['address'], 16): f for f in stack['functions']}
    stubs = parser.parse_stubs(stack['stubs'])
    if set(boundary['failure_entry_addresses']) != SEEDS:
        raise ValueError('only the three original failure seeds are permitted')
    seeds = {int(a, 16) for a in boundary['failure_entry_addresses'].values()}
    for name, address in boundary['failure_entry_addresses'].items():
        if not functions[int(address, 16)]['name'].startswith(name + '::'):
            raise ValueError('failure seed does not resolve to its captured function')
    sites = boundary['conditional_boundary_roots']['worker']['frontiers']
    requested, cache = [], {}

    def graph_for(start):
        """Cache exact original ordinary CFGs, preserving both conditional arms."""
        if start not in cache:
            cache[start] = control.cfg(start, int(functions[start]['end'], 16), instructions, parser.STRAIGHT)
        return cache[start]

    for item in sites:
        if item['kind'] not in {'function_fallthrough', 'exceptional_terminal'}:
            continue
        address = int(item['address'], 16)
        call = address - (4 if item['kind'] == 'exceptional_terminal' else 0)
        if instructions[call][0] != 'bl':
            raise ValueError('frontier is not immediately associated with a literal BL')
        if item['kind'] == 'exceptional_terminal' and instructions[address] != ('brk', '#0x1'):
            raise ValueError('exceptional instruction shape changed')
        requested.append(control.target(instructions[call][1]))
    candidates = {}
    while requested:
        start = requested.pop()
        if start in candidates or start in seeds or start not in functions:
            continue
        graph, exits = graph_for(start)
        candidates[start] = graph, exits
        for item in exits:
            if item['kind'] == 'bl':
                requested.append(control.target(item['detail']))
            elif item['kind'] == 'tail':
                requested.append(int(item['target'], 16))
    fixed = least_fixed_point(control, candidates, instructions, seeds)
    known = fixed.pop('known')
    for key in ('proofs', 'remaining'):
        for address, proof in fixed[key].items():
            proof['function'] = functions[int(address, 16)]['name']
    results = {}
    for root, original in boundary['conditional_boundary_roots'].items():
        classifications, retained_calls = [], {}
        for item in original['frontiers']:
            if item['kind'] not in {'function_fallthrough', 'exceptional_terminal'}:
                continue
            owners = [a for a, f in functions.items() if f['name'] == item['function']]
            if len(owners) != 1:
                raise ValueError('ambiguous original gap owner')
            start = owners[0]
            graph, exits = graph_for(start)
            reachable, stops = normal_reach(control, start, graph, instructions, known)
            address = int(item['address'], 16)
            call = address - (4 if item['kind'] == 'exceptional_terminal' else 0)
            callee = control.target(instructions[call][1])
            target_name = functions[callee]['name'] if callee in functions else stubs.get(callee)
            if target_name is None:
                raise ValueError('unresolved preceding BL target')
            if item['kind'] == 'function_fallthrough':
                if int(item['detail'], 16) != int(functions[start]['end'], 16) or address + 4 != int(item['detail'], 16):
                    raise ValueError('fallthrough is not a final instruction continuation')
                if callee in known:
                    classification = 'EXCLUDED_CALLEE_NORMAL_RETURN_UNDER_PREMISES'
                elif address not in reachable:
                    classification = 'OUTSIDE_CUT_NORMAL_ENTRY_CFG_NATIVE_EXCEPTIONAL_FLOW_OPEN'
                else:
                    classification = 'OPEN'
            else:
                classification = ('EXCLUDED_FROM_NORMAL_ENTRY_CFG_UNDER_PREMISES'
                                  if address not in reachable else 'OPEN')
            for a, target in stops.items():
                retained_calls[hex(a)] = {'target': hex(target), 'function': functions[target]['name'],
                                          'resource_cost': 'UNKNOWN', 'exceptional_effects': 'UNKNOWN'}
            classifications.append({**item, 'preceding_or_terminal_call': hex(call),
                'call_target': hex(callee), 'call_target_name': target_name,
                'target_is_original_seed': callee in seeds,
                'target_is_derived_noreturn': callee in known - seeds,
                'classification': classification,
                'original_frontier_and_exceptional_resource_obligation_retained': True,
                'immediate_call_alone_dominates': not control.reaches(graph, start, address, {call}) if call != address else None,
                'all_justified_call_cuts_in_owner': [{'address': hex(a), 'target': hex(t)} for a, t in sorted(stops.items())],
                'snippet': [{'address': hex(a), 'op': instructions[a][0], 'operands': instructions[a][1]}
                            for a in range(max(start, call - 12), min(int(functions[start]['end'], 16), address + 4), 4)]})
        counts = Counter((x['kind'], x['classification']) for x in classifications)
        results[root] = {'classifications': classifications,
                         'counts': {kind: {status: count for (k, status), count in counts.items() if k == kind}
                                    for kind in ('function_fallthrough', 'exceptional_terminal')},
                         'failure_calls_retained_as_unknown_cost_frontiers': retained_calls,
                         'unconditional_original_frontier_count_unchanged': True,
                         'complete_stack_bound_bytes': None}
    return {'seeds': boundary['failure_entry_addresses'], 'candidate_functions': len(candidates),
            'least_fixed_point': fixed, 'roots': results,
            'native_symbols_never_used_as_seeds': True,
            'unconditional_all_input_termination_or_panic_absence': 'UNKNOWN'}


def run(root: Path, output: Path) -> dict:
    """Verify frozen trust chains and write separate evidence, preserving old artifacts."""
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(Path(__file__).resolve()): sha(Path(__file__).resolve()),
              str(Path(sys.executable).resolve()): sha(Path(sys.executable).resolve())}
    report = {'schema': 'parliament-noreturn-frontiers-v1', 'status': 'UNKNOWN', 'inputs': inputs,
              'modes': {}, 'complete_workspace_certificate': False, 'profile_qualified': False,
              'complete_stack_bound_bytes': None, 'no_rebuild_or_execution': True,
              'premises': ['The original three Rust ! declarations correspond to the captured image; no independently attested std/LLVM build correspondence is claimed.',
                           'Ordinary ARM64 call/control semantics, correct captured disassembly, memory safety and intact return/control state.',
                           'A callee ! declaration forbids normal return, but permits divergence, unwinding, native work, hooks and termination. None is assigned zero resource cost.'],
              'limitations': ['Only ordinary call continuations are analyzed. Unwind/exception handlers, signal callbacks and nonlocal transfers remain outside this CFG and retain unknown resource obligations.',
                              'Native functions are never nonreturn seeds, including _exit and __Unwind_Resume. All unknown calls retain a possible normal continuation; unknown native tails, traps and fallthroughs block a derivation.',
                              'Derived functions can contain loops of unbounded duration. No all-input completion, panic absence, native budget, stack bound or workspace certificate follows.',
                              'Every original frontier is retained unconditionally; conditional continuation exclusions are separate metadata.']}
    try:
        for directory in (STACK, FRONTIERS, ACTIVATION, FREE):
            manifest = root / directory / 'SHA256SUMS'
            inputs[str(manifest)] = sha(manifest)
            for line in manifest.read_text().splitlines():
                expected, relative = line.split('  ', 1)
                path = root / relative
                if sha(path) != expected:
                    raise ValueError('frozen artifact changed: ' + relative)
                inputs[str(path)] = expected
        old = json.loads((root / FRONTIERS / 'report.json').read_text())
        if set(old['boundary_source_evidence']) != SEEDS:
            raise ValueError('source seed inventory changed')
        for name, evidence in old['boundary_source_evidence'].items():
            path = root / evidence['extracted_source']
            if sha(path) != evidence['extracted_source_sha256']:
                raise ValueError('failure declaration source changed')
            line = path.read_text().splitlines()[evidence['signature_line'] - 1]
            if line != evidence['signature'] or '-> !' not in line or evidence['no_normal_return'] is not True:
                raise ValueError('literal failure declaration mismatch')
            html = Path(evidence['installed_html'])
            if sha(html) != evidence['installed_html_sha256']:
                raise ValueError('installed declaration source changed')
            inputs[str(html)] = sha(html)
        report['source_seeds'] = old['boundary_source_evidence']
        free = module(root / FREE / 'parliament_ballot_free_predicates.py.template', 'frozen_noreturn_identity')
        parser = module(root / STACK / 'parliament_ballot_stack_audit.py.template', 'frozen_noreturn_stack')
        control = module(root / ACTIVATION / 'parliament_ballot_allocator_activation.py.template', 'frozen_noreturn_cfg')
        build_path = root / BUILD
        build = json.loads(build_path.read_text())
        free.verify_build_receipt(old, build_path, build)
        inputs[str(build_path)] = sha(build_path)
        for mode in ('portable', 'accel'):
            binary = Path(build['binaries'][mode]['path'])
            expected = build['binaries'][mode]['sha256']
            inputs[str(binary)] = expected
            stack = json.loads((root / STACK / (mode + '.json')).read_text())
            for key in ('disassembly', 'stubs'):
                stack[key] = (root / STACK / mode / (key + '.txt')).read_text()
            free.verify_image(old['modes'][mode], stack, expected, binary)
            report['modes'][mode] = analyze_mode(parser, control, stack, old['modes'][mode])
            report['modes'][mode]['binary_sha256'] = expected
        report['status'] = 'PASS_UNDER_PREMISES'
    except (ValueError, KeyError, OSError, UnicodeError) as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    report['input_changes'] = {name: {'before': expected, 'after': sha(Path(name)) if Path(name).is_file() else None}
                               for name, expected in inputs.items() if not Path(name).is_file() or sha(Path(name)) != expected}
    if report['input_changes']:
        report['status'] = 'UNKNOWN'
    report['observed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main() -> int:
    """Expose safe output selection and nonzero UNKNOWN status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory; existing output refused')
    args = parser.parse_args()
    report = run(ROOT, args.output.resolve())
    print(json.dumps({'status': report['status'], 'failure': report.get('failure'), 'profile_qualified': False}))
    return 0 if report['status'] == 'PASS_UNDER_PREMISES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
