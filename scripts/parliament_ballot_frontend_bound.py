#!/usr/bin/env python3
"""Bound historical ballot framing/coordinator code with opaque callees.

Requires Python 3.11+, the frozen EON capture and validated historical source
recovery. No builds, executable runs or environment variables. --output must be
new. The current checkout is not certified: recovered bytes are explicitly
substituted at separate paths, and current-source differences are reported.
"""
import argparse
from collections import deque
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re

EON_MANIFEST = '44f4361b01a7f4d78805055b187a8073448d516391bd407c91c70b658fa0ea48'
ADAPTER_REPORT = '90b67fba04a4c7f1c73ed067eb4a8c8d5478707e05f4b4d51ddc27235da7a471'
BUILD_RECEIPT = '83b90362f008d9cec6edb4a35d247298935b07c73ad1cb171c6e3bebef30b90f'
RECOVERY_RECEIPT = '75d9f36b2a490733c2d5341e475c2b625d86b5aa0a3d8c3f286b520817b6e04d'
PATTERNS = {'reservation': 'budget::Reservation::verify::',
            'record': 'test_codec::decode_record::', 'frame': 'test_codec::parse_frame::',
            'registration': 'test_codec::decode_registration::', 'vote': 'test_codec::decode_vote::'}
BODY_HASHES = {
    'portable': ['fff1cd6cddee0591c3c5e82f0880e77e53e26d35d891a2045dbddd74fdbcbc17',
                 '5e29e53ec11064da4fa79fd71f72bbbe9f7a4396c2c226c6687790b80fdaa413',
                 'c1a70753d6b2a0bf1ba19a61912ab89ea1ad02ebab8fd4db486432651fa347f0',
                 '32ee04267cb8db459ea00833f5cb4e51795d98652fd1210764c4fb957610560e',
                 'd0932653e85eacd01727922b44f090b42dba9e45eea8be8f06c255c6a8e4a56b'],
    'accel': ['95f5aad20844209de10d05fb21e2c1b83a490578ae6c019dd4d48bc479411b67',
              'd112258c15b7b5504c45e89091b010db9218308ac594a366a5d871fc82cfb75a',
              'f1ee59f78cb49b7f1c3427e32ad0043a2cdb1fe8dae90fc0824ba3cbd51de506',
              '065a03d162be1ab95a8921dd83176ca48603dcb844200d9950404beabf309f36',
              'f0b019d125c24ae2fa2376434f98ab49db469b4c987b8c24a88081f5e40fac78']}
# These are call sites, not assumptions that the callees cost zero or return.
CALLS = {
    'reservation': {0x58: 'profile', 0xb4: 'memcpy', 0xe4: 'record',
                    0x10c: 'decode_vote', 0x15c: 'decode_registration',
                    0x19c: 'memcpy', 0x1d0: 'verify_vote', 0x1e4: 'drop_vote',
                    0x204: 'memcpy', 0x238: 'verify_registration',
                    0x24c: 'drop_body', 0x258: 'drop_context', 0x274: 'drop_vote',
                    0x298: 'drop_body', 0x2a4: 'drop_context'},
    'record': {},
    'frame': {0x7c: 'memcmp', 0xe0: 'with_capacity', 0x148: 'grow_one', 0x1a8: 'dealloc'}}
TARGET_PATTERNS = {'profile': 'profile::Profile::new::', 'record': PATTERNS['record'],
                   'decode_vote': PATTERNS['vote'], 'decode_registration': PATTERNS['registration'],
                   'verify_vote': 'vote::verify::', 'verify_registration': 'registration::verify::',
                   'drop_vote': 'raw_vec..RawVec', 'drop_body': 'raw_vec..RawVec',
                   'drop_context': 'credential..RegistrationContext',
                   'with_capacity': '::with_capacity_in::', 'grow_one': '::grow_one::',
                   'dealloc': '__rustc::__rust_dealloc'}
SOURCES = ['examples/resource_contract/budget.rs', 'src/test_codec.rs', 'src/profile.rs',
           'src/framing.rs', 'src/credential.rs', 'src/registration.rs', 'src/vote.rs',
           'src/sealed_list.rs']


def digest(path):
    """Hash exact bytes, refusing absent inputs."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def object_json(path):
    """Reject ambiguous duplicate object keys and nonfinite JSON constants."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    def bad(_):
        raise ValueError('nonfinite JSON')
    return json.loads(Path(path).read_text(), object_pairs_hook=unique, parse_constant=bad)


def inputs(root):
    """Resolve the exact historical identities, never refresh source pins.

    Recovery locations are accepted only when bytes match the original pinned
    adapter report. A missing/mutated byte refuses analysis even if the recovery
    receipt says it succeeded. Live paths are observed separately, not substituted
    into the historical claim. The original source/build/capture chain is kept.
    """
    directory = root / 'docs/validation/parliament_ballot_fatal_stack_eon'
    historical = root / 'docs/validation/parliament_ballot_adapter_bound/report.json'
    recovery = root / 'docs/validation/parliament_ballot_adapter_source_recovery/validated/receipt.json'
    build = root / 'docs/validation/parliament_ballot_fatal_control/build/build-receipt.json'
    guards = {}
    for path, expected in [(historical, ADAPTER_REPORT), (build, BUILD_RECEIPT),
                           (directory / 'SHA256SUMS', EON_MANIFEST), (recovery, RECOVERY_RECEIPT)]:
        if digest(path) != expected:
            raise ValueError('historical evidence identity changed: ' + str(path))
        guards[str(path)] = expected
    names = set()
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] in names:
            raise ValueError('invalid frozen manifest')
        names.add(match[2])
        path = (directory / match[2]).resolve()
        if not path.is_relative_to(directory.resolve()) or digest(path) != match[1]:
            raise ValueError('frozen capture changed')
        guards[str(path)] = match[1]
    old, recovered, built = object_json(historical), object_json(recovery), object_json(build)
    guards[str(recovery)] = digest(recovery)
    expected = old['input_sha256']
    resolved = recovered['resolved_inputs']
    if (old['verdict'] != 'PASS_UNDER_STATED_PREMISES' or old['input_changes'] != {}
            or recovered['historical_report_sha256'] != ADAPTER_REPORT
            or recovered['historical_source_identities_resolved'] is not True
            or recovered['resolution_failures'] or recovered['during_resolution_changes']
            or set(resolved) != set(expected)):
        raise ValueError('incomplete historical resolution')
    substitutions, current_changes = {}, {}
    for original, wanted in expected.items():
        item = resolved[original]
        path = Path(item['resolved_path']).resolve()
        if item['sha256'] != wanted or digest(path) != wanted:
            raise ValueError('historical source/tool changed: ' + original)
        if str(path) != original:
            if not path.is_relative_to(recovery.parent / 'source'):
                raise ValueError('historical substitute outside recovery source directory')
            substitutions[original] = {'path': str(path), 'sha256': wanted}
        guards[str(path)] = wanted
        actual = digest(original) if Path(original).is_file() else None
        if actual != wanted:
            current_changes[original] = {'historical': wanted, 'current': actual}
    # The build receipt and capture were already pinned by the original adapter
    # report; retain an explicit cross-check of their source/binary identities.
    if built['source_stable'] is not True or any(expected.get(p) != sha for p, sha in built['source_files'].items()):
        raise ValueError('build sources not bound by historical report')
    capture = object_json(directory / 'receipt.json')
    for mode, binary in built['binaries'].items():
        if expected.get(binary['path']) != binary['sha256'] or capture['captures'][mode]['binary_sha256'] != binary['sha256']:
            raise ValueError('build/capture binary identity differs')
    sources = {}
    for suffix in SOURCES:
        original = str(root / 'crates/iroha_parliament_ballot_proof' / suffix)
        if original not in built['source_files']:
            raise ValueError('reviewed source not in build')
        sources[suffix] = resolved[original]['resolved_path']
    return directory, guards, substitutions, current_changes, sources


def graph(instructions, start, end, conditional, labels):
    """Retain every ordinary branch/call continuation; reject unknown escapes."""
    pending, edges, calls = [start], {}, {}
    while pending:
        address = pending.pop()
        if address in edges:
            continue
        if not start <= address < end or address not in instructions:
            raise ValueError('control escape')
        op, operands = instructions[address]
        if op == 'ret' and operands == '':
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
            target = int(match[1], 16)
            successors = [target] if op == 'b' else [target, address + 4]
        elif op in {'ret', 'br', 'blr', 'brk', 'udf', 'hlt'}:
            raise ValueError('unknown ordinary continuation')
        else:
            successors = [address + 4]
        edges[address] = successors
        pending.extend(successors)
    if {a - start for a in calls} != set(labels):
        raise ValueError('declared call site not reachable')
    return edges, calls


def order(edges, removed=()):
    """Prove the graph acyclic after exactly the declared loop-edge removal."""
    if any(a not in edges or b not in edges[a] for a, b in removed):
        raise ValueError('missing bounded edge')
    degree = dict.fromkeys(edges, 0)
    for a, successors in edges.items():
        for b in successors:
            if (a, b) not in removed:
                degree[b] += 1
    pending, result = deque(a for a, degree in degree.items() if degree == 0), []
    while pending:
        a = pending.popleft()
        result.append(a)
        for b in edges[a]:
            if (a, b) not in removed:
                degree[b] -= 1
                if degree[b] == 0:
                    pending.append(b)
    if len(result) != len(edges):
        raise ValueError('unbounded CFG cycle')
    return result


def longest(edges, weights):
    """Bound a nonnegative additive metric over all acyclic ordinary paths."""
    maxima = {}
    for a in reversed(order(edges)):
        value = weights.get(a, 0)
        if type(value) is not int or value < 0:
            raise ValueError('invalid path weight')
        maxima[a] = value + max((maxima[b] for b in edges[a]), default=0)
    return maxima[min(edges)]


def bounded_longest(edges, weights, bounded_edges, cap):
    """Unroll one source-proved shared edge budget, retaining all other edges."""
    if type(cap) is not int or cap < 0:
        raise ValueError('invalid bounded edge cap')
    topology = order(edges, bounded_edges)
    previous = {}
    for remaining in range(cap + 1):
        current = {}
        for a in reversed(topology):
            value = weights.get(a, 0)
            if type(value) is not int or value < 0:
                raise ValueError('invalid path weight')
            suffixes = []
            for b in edges[a]:
                if (a, b) in bounded_edges:
                    if remaining:
                        suffixes.append(previous[b])
                else:
                    suffixes.append(current[b])
            current[a] = value + max(suffixes, default=0)
        previous = current
    return previous[min(edges)]


def source_bounds():
    """Arithmetic lemmas for the separately reviewed, hash-pinned source.

    These bound logical lengths/iteration counts, not allocator capacity, hashes,
    cryptography, native work, or instruction counts of the typed decoders.
    """
    registration = 2 + len(b'PARL/TEST/REG/v1') + 2 + 4 * 11 + 4096 + 6 * 256 + 3 * 64 + 128
    vote = 2 + len(b'PARL/TEST/VOTE/v1') + 2 + 4 * 10 + 6 * 64 + 128 + 2 + 1 + 1000 * 128
    return {'field_iterations': {'registration': 11, 'vote': 10},
            'descriptor_slice_payload_bytes': {'registration': 11 * 16, 'vote': 10 * 16},
            'statement_maximum_bytes': {'registration': registration, 'vote': vote},
            'record_maximum_bytes': {
                'candidate_registration': 8 + registration + 160148,
                'comparator_registration': 8 + registration + 109498,
                'candidate_vote': 8 + vote + 233012,
                'comparator_vote': 8 + vote + 158074},
            'successful_statement_owned_vectors': {'registration': 7, 'vote': 1},
            'successful_statement_logical_owned_bytes': {'registration': 4096 + 6 * 256, 'vote': 1000 * 128},
            'vote_split_iterations': 1000, 'vote_order_comparisons': 999,
            'maximum_admitted_record_bytes': 425984}


def analyze_mode(mode, report, disassembly, starts, stubs_text, analyzer):
    """Verify exact bodies, normal CFGs, call multiplicities and frame depths."""
    if mode not in BODY_HASHES:
        raise ValueError('unknown mode')
    instructions, _ = analyzer.parse_disassembly(disassembly)
    stubs = analyzer.parse_stubs(stubs_text)
    fresh = analyzer.audit(disassembly, starts, stubs_text, ['budget::Reservation::verify::'])
    if fresh['functions'] != report['functions']:
        raise ValueError('frame report differs from capture')
    functions = {}
    by_address = {int(fn['address'], 16): fn for fn in fresh['functions']}
    for index, (name, pattern) in enumerate(PATTERNS.items()):
        matches = [fn for fn in fresh['functions'] if pattern in fn['name']]
        if len(matches) != 1 or matches[0]['frame_errors']:
            raise ValueError('ambiguous or unresolved frame')
        fn = matches[0]
        start, end = int(fn['address'], 16), int(fn['end'], 16)
        body = [[a-start, *instructions[a]] for a in sorted(instructions) if start <= a < end]
        if hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest() != BODY_HASHES[mode][index]:
            raise ValueError('reviewed body changed: ' + name)
        functions[name] = fn
    results = {}
    for name, labels in CALLS.items():
        fn = functions[name]
        start, end = int(fn['address'], 16), int(fn['end'], 16)
        edges, calls = graph(instructions, start, end, analyzer.CONDITIONAL, labels)
        sites = []
        for a, label in sorted(calls.items()):
            target = int(re.search(r'0x[0-9a-f]+', instructions[a][1])[0], 16)
            actual = stubs.get(target) or by_address.get(target, {}).get('name', '')
            wanted = '_' + label if label in {'memcmp', 'memcpy'} else TARGET_PATTERNS[label]
            if wanted not in actual:
                raise ValueError('call target differs')
            sites.append({'address': hex(a), 'target': label, 'symbol': actual})
        result = {'address': fn['address'], 'name': fn['name'], 'end': fn['end'],
                  'local_frame_bytes': fn['maximum_sp_decrement_bytes'],
                  'local_frame_plus_red_zone_bytes': fn['local_frame_plus_red_zone_bytes'],
                  'reachable_instructions': len(edges), 'calls': sites,
                  'opaque_callee_costs': {label: {'work': None, 'stack': None}
                                        for label in sorted(set(labels.values()) - {'record'})}}
        if name != 'frame':
            result['local_issued_instruction_bound'] = longest(edges, dict.fromkeys(edges, 1))
            result['call_maxima'] = {label: longest(edges, {a: int(c == label) for a, c in calls.items()})
                                     for label in sorted(set(labels.values()))}
            if name == 'reservation':
                result['combined_typed_decoder_maximum'] = longest(edges, {a: int(c.startswith('decode_')) for a, c in calls.items()})
                result['combined_role_verifier_maximum'] = longest(edges, {a: int(c.startswith('verify_')) for a, c in calls.items()})
                result['combined_cleanup_maximum'] = longest(edges, {a: int(c.startswith('drop_')) for a, c in calls.items()})
                sizes = {start + 0xb4: 642, start + 0x19c: 424, start + 0x204: 368}
                result['maximum_memcpy_bytes'] = longest(edges, sizes)
        else:
            # After each push, x23 increments and is compared to the positive
            # trusted x20=count. The not-equal fallthrough begins another
            # field attempt, so this one cycle edge is taken <=count-1.
            loop_edges = {(start + 0x120, start + 0x124)}
            order(edges, loop_edges)
            result['bounded_edge_group'] = [{'source': hex(a), 'target': hex(b)} for a, b in sorted(loop_edges)]
            result['combined_edge_maximum'] = {'registration': 10, 'vote': 9}
            result['local_issued_instruction_bound'] = {
                role: bounded_longest(edges, dict.fromkeys(edges, 1), loop_edges, count - 1)
                for role, count in source_bounds()['field_iterations'].items()}
            result['call_maxima'] = {role: {
                label: bounded_longest(edges, {a: int(c == label) for a, c in calls.items()}, loop_edges, count - 1)
                for label in sorted(set(labels.values()))}
                for role, count in source_bounds()['field_iterations'].items()}
        results[name] = result
    call_prefixes = {}
    frame_address = functions['frame']['address']
    for name, count, taglen in [('registration', 11, 16), ('vote', 10, 17)]:
        fn = functions[name]
        sites = [c for c in fn['calls'] if c['target'] == frame_address]
        if len(sites) != 1:
            raise ValueError('ambiguous fixed-count parser caller')
        a = int(sites[0]['address'], 16)
        if instructions[a-8] != ('mov', f'w4, #{hex(taglen)}') or instructions[a-4] != ('mov', f'w5, #{hex(count)}'):
            raise ValueError('fixed parser parameters differ')
        call_prefixes[name] = {'address': hex(a), 'tag_bytes': taglen, 'fields': count,
                               'caller_live_stack_bytes': sites[0]['caller_depth_bytes']}
    # Keeping complete typed-decoder costs opaque avoids double-counting parse
    # work in composition. Its separate lemma can replace that part later.
    return {'verdict': 'PASS_UNDER_STATED_PREMISES', 'functions': results,
            'parser_callers': call_prefixes,
            'reservation_plus_record_local_instruction_bound':
                results['reservation']['local_issued_instruction_bound'] + results['record']['local_issued_instruction_bound'],
            'reservation_and_record_owned_stack_bytes': max(results['reservation']['local_frame_plus_red_zone_bytes'],
                results['reservation']['local_frame_bytes'] + results['record']['local_frame_plus_red_zone_bytes']),
            'complete_verification_work_bound': None, 'complete_verification_stack_bound_bytes': None,
            'complete_workspace_certificate': False, 'profile_qualified': False}


def run(root, output):
    """Persist a fresh historical result or UNKNOWN, with before/after guards."""
    output.mkdir(parents=True, exist_ok=False)
    guards, modes, substitutions, current, sources, failure = {}, {}, {}, {}, {}, None
    try:
        for path in [Path(__file__).resolve(), root / 'scripts/tests/parliament_ballot_frontend_bound_test.py']:
            guards[str(path)] = digest(path)
            (output / (path.name + '.template')).write_bytes(path.read_bytes())
        directory, inherited, substitutions, current, sources = inputs(root)
        guards.update(inherited)
        for suffix, source in sources.items():
            destination = output / 'source' / (suffix + '.template')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(Path(source).read_bytes())
        path = directory / 'parliament_ballot_stack_audit.py.template'
        loader = importlib.machinery.SourceFileLoader('frontend_frozen_stack', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        analyzer = importlib.util.module_from_spec(spec)
        loader.exec_module(analyzer)
        for mode in ('portable', 'accel'):
            modes[mode] = analyze_mode(mode, object_json(directory / (mode + '.json')),
                                      (directory / mode / 'disassembly.txt').read_text(),
                                      (directory / mode / 'starts.txt').read_text(),
                                      (directory / mode / 'stubs.txt').read_text(), analyzer)
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for path, before in guards.items():
        after = digest(path) if Path(path).is_file() else None
        if before != after:
            changes[path] = {'before': before, 'after': after}
    result = {'schema': 'parliament-historical-frontend-bound-v1',
              'verdict': 'PASS_UNDER_STATED_PREMISES' if failure is None and not changes and len(modes) == 2 else 'UNKNOWN',
              'failure': failure, 'modes': modes, 'source_bounds': source_bounds(),
              'historical_substitutions': substitutions, 'current_source_differences': current,
              'input_sha256': guards, 'input_changes': changes,
              'applies_to_current_checkout': False, 'complete_workspace_certificate': False,
              'physical_cost_calibrated': False, 'profile_qualified': False}
    (output / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    """Require explicit repository and new output location."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.output.resolve())
    print(json.dumps({key: result[key] for key in ('verdict', 'failure', 'input_changes')}, indent=2))
    return 0 if result['verdict'] == 'PASS_UNDER_STATED_PREMISES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
