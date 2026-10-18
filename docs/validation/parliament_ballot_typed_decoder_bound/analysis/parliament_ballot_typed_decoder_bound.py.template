#!/usr/bin/env python3
"""Bound historical typed-decoder coordinators, retaining opaque callees.

Python 3.11+ and the frozen frontend/source-recovery artifacts are required. No
builds, worker execution or environment variables. --output must be new. This is
conditional ordinary-control evidence, not current-source or production approval.
"""
import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re

FRONTEND_MANIFEST = '81bae3e341dbb26915dd45d9a24d763705b983d9f6826d99c8a01d152e173b84'
CALLS = {
    'registration': {0x44: 'frame', 0x12c: 'dealloc', 0x1c4: 'shim', 0x1d0: 'alloc',
                     0x1f0: 'memcpy', 0x23c: 'shim', 0x248: 'alloc', 0x264: 'memcpy',
                     0x274: 'opaque_new', 0x2b8: 'dealloc', 0x2cc: 'dealloc',
                     0x2e0: 'opaque_new', 0x324: 'dealloc', 0x340: 'opaque_new',
                     0x384: 'dealloc', 0x3a0: 'opaque_new', 0x3e4: 'dealloc',
                     0x404: 'opaque_new', 0x468: 'dealloc', 0x480: 'dealloc',
                     0x494: 'dealloc', 0x4a8: 'dealloc', 0x4bc: 'dealloc',
                     0x620: 'statement_new', 0x6a0: 'context_drop', 0x6c4: 'memcpy',
                     0x7c0: 'statement_drop', 0x7d4: 'memcpy', 0x7e8: 'handle_error', 0x7f8: 'handle_error'},
    'vote': {0x3c: 'frame', 0x120: 'dealloc', 0x2fc: 'split', 0x5bc: 'validate',
             0x5d8: 'memcpy', 0x688: 'dealloc'}}
TARGETS = {'frame': 'test_codec::parse_frame::', 'dealloc': '__rustc::__rust_dealloc',
           'shim': '__rustc::__rust_no_alloc_shim_is_unstable_v2', 'alloc': '__rustc::__rust_alloc',
           'opaque_new': 'framing::OpaqueField::new::', 'statement_new': 'registration::RegistrationStatement::new::',
           'context_drop': 'drop_in_place$LT$iroha_parliament_ballot_proof..credential..RegistrationContext$GT$',
           'statement_drop': 'drop_in_place$LT$iroha_parliament_ballot_proof..registration..RegistrationStatement$GT$',
           'handle_error': 'alloc::raw_vec::handle_error::', 'split': 'sealed_list::split::',
           'validate': 'vote::VoteStatement::validate::', 'memcpy': '_memcpy'}
# These edges dominate the specified bounded request sites, not the error paths.
GUARDS = {'registration': [
    (0x158, 0x178, [0x1d0, 0x1f0], 'unsigned body length <=4096'),
    (0x208, 0x234, [0x248, 0x264], 'unsigned first opaque-field length <=256')],
    'vote': [
        (0x164, 0x1b0, [0x2fc], 'list length divisible by128'),
        (0x1bc, 0x1c0, [0x2fc], '3<=unsigned list length/128<=1000')]}


def digest(path):
    """Bind exact retained bytes, refusing missing inputs."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    """Load only a hash-verified retained helper."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def inputs(root):
    """Validate frozen frontend evidence and all historical resolved identities."""
    directory = root / 'docs/validation/parliament_ballot_frontend_bound'
    manifest = directory / 'SHA256SUMS'
    if digest(manifest) != FRONTEND_MANIFEST:
        raise ValueError('frozen frontend manifest changed')
    guards = {str(manifest): digest(manifest)}
    names = set()
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in names:
            raise ValueError('invalid frozen manifest')
        names.add(match[2])
        path = (directory / match[2]).resolve()
        if not path.is_relative_to(directory.resolve()) or digest(path) != match[1]:
            raise ValueError('frozen frontend artifact changed')
        guards[str(path)] = match[1]
    frontend = load(directory / 'analysis/parliament_ballot_frontend_bound.py.template', 'typed_frozen_frontend')
    previous = frontend.object_json(directory / 'analysis/report.json')
    if previous['verdict'] != 'PASS_UNDER_STATED_PREMISES' or previous['input_changes']:
        raise ValueError('frontend observation failed')
    for path, expected in previous['input_sha256'].items():
        if digest(path) != expected:
            raise ValueError('frontend guarded input changed: ' + path)
        guards[path] = expected
    capture, inherited, substitutions, current, sources = frontend.inputs(root)
    guards.update(inherited)
    analyzer = load(capture / 'parliament_ballot_stack_audit.py.template', 'typed_frozen_stack')
    return capture, guards, substitutions, current, sources, frontend, analyzer, previous


def graph(instructions, start, end, conditional, labels, terminals):
    """Enumerate ordinary paths and exact exceptional frontier prefixes.

    Every direct call keeps its hypothetical normal continuation. A named BRK is
    a retained exceptional frontier with unknown continuation/cost, never RET or
    proof that a preceding call diverges. Other opaque control shapes refuse.
    """
    pending, edges, calls, frontiers = [start], {}, {}, []
    while pending:
        address = pending.pop()
        if address in edges:
            continue
        if not start <= address < end or address not in instructions:
            raise ValueError('control escape')
        op, operands = instructions[address]
        if address - start in terminals:
            if (op, operands) != terminals[address - start]:
                raise ValueError('exceptional frontier shape changed')
            frontiers.append({'address': hex(address), 'instruction': [op, operands],
                              'continuation_work_bound': None, 'continuation_stack_bound_bytes': None})
            successors = []
        elif op == 'ret' and operands == '':
            successors = []
        elif op == 'bl':
            if address - start not in labels:
                raise ValueError('unknown callee')
            calls[address] = labels[address - start]
            successors = [address + 4]
        elif op == 'b' or op in conditional:
            match = re.search(r'(?:^|,\s*)(0x[0-9a-f]+)', operands)
            if not match:
                raise ValueError('unknown branch target')
            successors = [int(match[1], 16)]
            if op != 'b':
                successors.append(address + 4)
        elif op in {'ret', 'br', 'blr', 'brk', 'udf', 'hlt'}:
            raise ValueError('unknown continuation')
        else:
            successors = [address + 4]
        edges[address] = successors
        pending.extend(successors)
    if {a-start for a in calls} != set(labels) or {int(f['address'], 16)-start for f in frontiers} != set(terminals):
        raise ValueError('declared call/frontier not reachable')
    return edges, calls, frontiers


def edge_dominates(edges, start, target, required):
    """Require every ordinary path to a request to traverse one guarded edge."""
    a, b = required
    if a not in edges or b not in edges[a] or target not in edges:
        raise ValueError('missing guard edge/request')
    pending, seen = [start], set()
    while pending:
        n = pending.pop()
        if n == target:
            return False
        if n in seen:
            continue
        seen.add(n)
        pending.extend(q for q in edges[n] if (n, q) != required)
    return True


def source_requests():
    """Source-derived logical requests; retain lower routine costs separately."""
    return {'registration': {'body_copy_maximum_bytes': 4096,
                              'opaque_field_copies': 6, 'each_opaque_copy_maximum_bytes': 256,
                              'maximum_logical_owned_payload_bytes': 5632,
                              'constructor_calls': 1, 'body_digest_requests': 1,
                              'body_digest_maximum_framed_bytes': 2 + len(b'PARL/BODY/v1') + 2 + 2*4 + 16 + 4096,
                              'returned_owned_vectors_on_success': 7},
            'vote': {'split_calls': 1, 'split_maximum_bytes': 128000, 'split_maximum_entries': 1000,
                     'public_validation_calls': 1, 'maximum_adjacent_comparisons': 999,
                     'list_digest_requests': 1,
                     'list_digest_maximum_framed_bytes': 2 + len(b'PARL/LIST/v1') + 2 + 4*4 + 16 + 64 + 2 + 128000,
                     'returned_owned_vectors_on_success': 1},
            'no_source_visible_owned_vectors_returned_on_error': True,
            'heap_capacity_or_arena_sufficiency_proved': False}


def analyze_mode(mode, report, disassembly, starts, stubs_text, frontend, analyzer, prior):
    """Bound exact typed bodies, all ordinary branches and guard-to-request flow."""
    if mode not in frontend.BODY_HASHES:
        raise ValueError('unknown mode')
    instructions, _ = analyzer.parse_disassembly(disassembly)
    stubs = analyzer.parse_stubs(stubs_text)
    fresh = analyzer.audit(disassembly, starts, stubs_text, ['budget::Reservation::verify::'])
    if fresh['functions'] != report['functions']:
        raise ValueError('frame report differs from capture')
    by_address = {int(fn['address'], 16): fn for fn in fresh['functions']}
    results = {}
    for name, labels in CALLS.items():
        matches = [fn for fn in fresh['functions'] if frontend.PATTERNS[name] in fn['name']]
        if len(matches) != 1 or matches[0]['frame_errors']:
            raise ValueError('unresolved typed decoder frame')
        fn = matches[0]
        start, end = int(fn['address'], 16), int(fn['end'], 16)
        body = [[a-start, *instructions[a]] for a in sorted(instructions) if start <= a < end]
        expected = frontend.BODY_HASHES[mode][list(frontend.PATTERNS).index(name)]
        if hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest() != expected:
            raise ValueError('reviewed typed body changed')
        terminals = {0x7fc: ('brk', '#0x1')} if name == 'registration' else {}
        edges, calls, frontiers = graph(instructions, start, end, analyzer.CONDITIONAL, labels, terminals)
        frontend.order(edges)
        sites = []
        for address, label in sorted(calls.items()):
            target = int(re.search(r'0x[0-9a-f]+', instructions[address][1])[0], 16)
            symbol = stubs.get(target) or by_address.get(target, {}).get('name', '')
            if TARGETS[label] not in symbol:
                raise ValueError('opaque call target differs')
            sites.append({'address': hex(address), 'target': label, 'symbol': symbol})
        guards = []
        for branch, kept, requests, reason in GUARDS[name]:
            for request in requests:
                if not edge_dominates(edges, start, start+request, (start+branch, start+kept)):
                    raise ValueError('bounded request bypasses guard')
            guards.append({'branch': hex(start+branch), 'kept_edge': hex(start+kept),
                           'request_sites': [hex(start+r) for r in requests], 'source_predicate': reason})
        count = lambda metric: frontend.longest(edges, metric)
        maxima = {label: count({a: int(c == label) for a, c in calls.items()}) for label in sorted(set(labels.values()))}
        local = count(dict.fromkeys(edges, 1))
        copies = {0x1f0: 4096, 0x264: 256, 0x6c4: 368, 0x7d4: 424} if name == 'registration' else {0x5d8: 480}
        parser = prior['functions']['frame']
        if maxima['frame'] != 1:
            raise ValueError('parser multiplicity differs')
        results[name] = {
            'address': fn['address'], 'name': fn['name'], 'end': fn['end'],
            'reachable_instructions': len(edges), 'local_issued_instruction_bound': local,
            'local_frame_bytes': fn['maximum_sp_decrement_bytes'],
            'local_frame_plus_red_zone_bytes': fn['local_frame_plus_red_zone_bytes'],
            'calls': sites, 'call_maxima': maxima, 'request_guard_edges': guards,
            'maximum_direct_memcpy_bytes': count({start+a: size for a, size in copies.items()}),
            'maximum_outer_cleanup_calls': count({a: int(c in {'dealloc', 'context_drop', 'statement_drop'}) for a, c in calls.items()}),
            'exceptional_frontiers': frontiers,
            'opaque_callees': {label: {'additional_work_bound': None, 'additional_stack_bound_bytes': None}
                               for label in sorted(set(labels.values()) - {'frame'})},
            'parser_callee_maxima': parser['call_maxima'][name],
            'with_parser_local_instruction_bound': local + parser['local_issued_instruction_bound'][name],
            'with_parser_owned_stack_bytes': max(fn['local_frame_plus_red_zone_bytes'],
                fn['maximum_sp_decrement_bytes'] + parser['local_frame_plus_red_zone_bytes']),
            'parser_callee_live_caller_bytes': fn['maximum_sp_decrement_bytes'] + parser['local_frame_bytes'],
            'complete_decoder_work_bound': None, 'complete_decoder_stack_bound_bytes': None}
    return {'verdict': 'PASS_UNDER_STATED_PREMISES', 'decoders': results,
            'complete_workspace_certificate': False, 'profile_qualified': False}


def run(root, output):
    """Capture new evidence or UNKNOWN without changing a prior artifact."""
    output.mkdir(parents=True, exist_ok=False)
    guards, modes, substitutions, current, failure = {}, {}, {}, {}, None
    try:
        for path in [Path(__file__).resolve(), root / 'scripts/tests/parliament_ballot_typed_decoder_bound_test.py']:
            guards[str(path)] = digest(path)
            (output / (path.name + '.template')).write_bytes(path.read_bytes())
        capture, inherited, substitutions, current, sources, frontend, analyzer, previous = inputs(root)
        guards.update(inherited)
        for mode in ('portable', 'accel'):
            modes[mode] = analyze_mode(mode, frontend.object_json(capture / (mode + '.json')),
                (capture / mode / 'disassembly.txt').read_text(), (capture / mode / 'starts.txt').read_text(),
                (capture / mode / 'stubs.txt').read_text(), frontend, analyzer, previous['modes'][mode])
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for path, expected in guards.items():
        actual = digest(path) if Path(path).is_file() else None
        if actual != expected:
            changes[path] = {'before': expected, 'after': actual}
    result = {'schema': 'parliament-historical-typed-decoder-bound-v1',
              'verdict': 'PASS_UNDER_STATED_PREMISES' if failure is None and not changes and len(modes) == 2 else 'UNKNOWN',
              'failure': failure, 'modes': modes, 'source_requests': source_requests(),
              'input_sha256': guards, 'input_changes': changes, 'historical_substitutions': substitutions,
              'current_source_differences': current, 'applies_to_current_checkout': False,
              'complete_workspace_certificate': False, 'physical_cost_calibrated': False, 'profile_qualified': False}
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    """Require explicit historical repository and fresh output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.output.resolve())
    print(json.dumps({k: result[k] for k in ('verdict', 'failure', 'input_changes')}, indent=2))
    return 0 if result['verdict'] == 'PASS_UNDER_STATED_PREMISES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
