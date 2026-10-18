#!/usr/bin/env python3
"""Bound the historical Profile::new coordinator with explicit opaque callees.

No builds or execution of worker images. Historical recovery and frozen analysis
dependencies must retain their original identities; output must be a new path.
"""
import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re

FRONTEND_HELPER = '70d6f3d864cad96fbd0241dbd79f89f5ff9d5503589614c3f252b6248576d787'
FRONTEND_REPORT = 'd29b4846f90fc230323076ffb570513346ad2751ef4aa9b3b886b78e55b4e91d'
BODY_HASHES = {
    'portable': 'da3287be4612c3fa0a4c90a3298cbde068bc6dc5be55796b5fe2633d4d0316cc',
    'accel': '4d714a8845d329b35925ca72a01b1bf35f72e75be397b2fca5f321c631b0f935',
}
CALLS = {0x38: 'crt_digest', 0xf4: 'parameter_concat', 0x110: 'dimension_concat',
         0x178: 'descriptor_frame', 0x1a4: 'dealloc', 0x1b8: 'dealloc',
         0x1e8: 'dealloc', 0x1fc: 'dealloc', 0xa5c: 'dealloc',
         0x384: 'descriptor_hash', 0x454: 'namespace_frame_digest'}
TARGETS = {'crt_digest': 'profile::crt_table_digest::',
           'parameter_concat': '::concat::', 'dimension_concat': '::concat::',
           'descriptor_frame': 'framing::frame_bytes::', 'dealloc': '__rustc::__rust_dealloc',
           'descriptor_hash': 'hash::sha3_512::', 'namespace_frame_digest': 'framing::frame_digest::'}


def digest(path):
    """Read and hash exact bytes; absent files are errors."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    """Load a separately verified Python analysis dependency."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def dependencies(root):
    """Verify the complete frozen frontend input chain and resolved source bytes."""
    base = root / 'docs/validation/parliament_ballot_frontend_bound/analysis'
    helper, report = base / 'parliament_ballot_frontend_bound.py.template', base / 'report.json'
    for path, expected in [(helper, FRONTEND_HELPER), (report, FRONTEND_REPORT)]:
        if digest(path) != expected:
            raise ValueError('frontend identity changed')
    frontend = load('profile_frozen_frontend', helper)
    prior = frontend.object_json(report)
    if prior['verdict'] != 'PASS_UNDER_STATED_PREMISES' or prior['input_changes']:
        raise ValueError('frontend capture not stable')
    guards = dict(prior['input_sha256'])
    for name, expected in guards.items():
        if digest(name) != expected:
            raise ValueError('historical frontend input changed: ' + name)
    directory, inherited, substitutions, current, sources = frontend.inputs(root)
    guards.update(inherited)
    guards[str(helper)] = FRONTEND_HELPER
    guards[str(report)] = FRONTEND_REPORT
    stack_path = directory / 'parliament_ballot_stack_audit.py.template'
    # This exact analyzer is included in the verified capture and source guards.
    if digest(stack_path) != guards[str(stack_path)]:
        raise ValueError('stack analyzer identity changed')
    stack = load('profile_frozen_stack', stack_path)
    return frontend, stack, directory, guards, substitutions, current, sources


def analyze_mode(mode, report, disassembly, starts, stubs, frontend, stack):
    """Check full body identity, the role loop and every ordinary call path."""
    if mode not in BODY_HASHES:
        raise ValueError('unknown mode')
    instructions, _ = stack.parse_disassembly(disassembly)
    fresh = stack.audit(disassembly, starts, stubs, ['profile::Profile::new::'])
    if fresh['functions'] != report['functions']:
        raise ValueError('frame capture differs')
    matches = [f for f in fresh['functions'] if 'profile::Profile::new::' in f['name']]
    if len(matches) != 1 or matches[0]['frame_errors']:
        raise ValueError('unresolved profile frame')
    fn = matches[0]
    start, end = int(fn['address'], 16), int(fn['end'], 16)
    body = [[a-start, *instructions[a]] for a in sorted(instructions) if start <= a < end]
    if hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest() != BODY_HASHES[mode]:
        raise ValueError('profile body changed')
    edges, calls = frontend.graph(instructions, start, end, stack.CONDITIONAL, CALLS)
    # The only cycle re-enters with x8=1; x20 copies x8 at its header, is
    # callee-saved and otherwise unwritten in the loop; TBZ tests its bit zero.
    predicates = {0x388: ('mov', 'w8, #0x0'), 0x404: ('mov', 'x20, x8'),
                  0x800: ('mov', 'w8, #0x1'), 0x808: ('mov', 'w9, #0x1'),
                  0x80c: ('tbz', f'w20, #0x0, {hex(start+0x404)}')}
    for offset, expected in predicates.items():
        op, operands = instructions[start+offset]
        if (op, operands.split(' <', 1)[0]) != expected:
            raise ValueError('role loop predicate changed')
    loop = {(start+0x80c, start+0x404)}
    frontend.order(edges, loop)
    symbols = {int(f['address'], 16): f['name'] for f in fresh['functions']}
    sites = []
    for address, label in sorted(calls.items()):
        match = re.search(r'0x[0-9a-f]+', instructions[address][1])
        target = int(match[0], 16)
        symbol = symbols.get(target, '')
        if TARGETS[label] not in symbol:
            raise ValueError('callee target changed')
        sites.append({'address': hex(address), 'label': label, 'symbol': symbol})
    maxima = {label: frontend.bounded_longest(edges, {a: int(v == label) for a, v in calls.items()}, loop, 1)
              for label in sorted(set(calls.values()))}
    return {'address': fn['address'], 'end': fn['end'], 'body_sha256': BODY_HASHES[mode],
            'reachable_instructions': len(edges),
            'local_issued_instruction_bound': frontend.bounded_longest(edges, dict.fromkeys(edges, 1), loop, 1),
            'local_frame_bytes': fn['maximum_sp_decrement_bytes'],
            'local_stack_including_red_zone_bytes': fn['local_frame_plus_red_zone_bytes'],
            'bounded_loop_edge': [hex(start+0x80c), hex(start+0x404)], 'loop_edge_budget': 1,
            'call_sites': sites, 'call_maxima': maxima,
            'opaque_costs': {label: {'work': None, 'stack': None, 'allocation': None} for label in maxima},
            'complete_profile_work_bound': None, 'complete_profile_stack_bound': None,
            'exceptional_costs_discharged': False}


def run(root, output):
    """Retain a fresh conditional report or UNKNOWN with guards on both sides."""
    output.mkdir(parents=True, exist_ok=False)
    guards, modes, current, substitutions, failure = {}, {}, {}, {}, None
    try:
        for path in (Path(__file__).resolve(), root / 'scripts/tests/parliament_ballot_profile_bound_test.py'):
            guards[str(path)] = digest(path)
            (output / (path.name + '.template')).write_bytes(path.read_bytes())
        frontend, stack, directory, inherited, substitutions, current, sources = dependencies(root)
        guards.update(inherited)
        source_dir = output / 'source'
        source_dir.mkdir()
        for name in ('src/profile.rs', 'src/framing.rs'):
            (source_dir / (Path(name).name + '.template')).write_bytes(Path(sources[name]).read_bytes())
        for mode in BODY_HASHES:
            modes[mode] = analyze_mode(mode, frontend.object_json(directory / (mode+'.json')),
                (directory / mode / 'disassembly.txt').read_text(), (directory / mode / 'starts.txt').read_text(),
                (directory / mode / 'stubs.txt').read_text(), frontend, stack)
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for name, expected in guards.items():
        path = Path(name)
        actual = digest(path) if path.is_file() else None
        if actual != expected:
            changes[name] = {'before': expected, 'after': actual}
    report = {'schema': 'parliament-historical-profile-coordinator-v1',
              'verdict': 'PASS_UNDER_STATED_PREMISES' if failure is None and not changes and len(modes) == 2 else 'UNKNOWN',
              'failure': failure, 'modes': modes, 'input_sha256': guards, 'input_changes': changes,
              'historical_substitutions': substitutions, 'current_source_differences': current,
              'applies_to_current_checkout': False, 'profile_qualified': False,
              'complete_workspace_certificate': False, 'physical_cost_calibrated': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    """Require explicit source root and a new output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = run(args.root.resolve(), args.output.resolve())
    print(json.dumps({k: report[k] for k in ('verdict', 'failure', 'input_changes')}))
    return int(report['verdict'] != 'PASS_UNDER_STATED_PREMISES')


if __name__ == '__main__':
    raise SystemExit(main())
