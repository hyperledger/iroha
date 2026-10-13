#!/usr/bin/env python3
"""Check the non-Custom io::Error drop guard in two frozen ARM64 workers.

Requires Python 3.11+, retained compiled-stack artifacts/binaries, and Rust
1.93.1 rustdoc source HTML. No environment variables, builds, worker execution,
or network access. Writes only a new --output directory. This local instruction
check plus a pinned source read-path lemma is not whole-worker variant flow,
panic absence, native endpoint coverage, or a complete resource certificate.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
STACK = Path('docs/validation/parliament_ballot_compiled_stack')
FRONTIERS = Path('docs/validation/parliament_ballot_stack_frontiers')
BUILD = Path('docs/validation/parliament_ballot_resource_contract')
WORKSPACE = Path('crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs')
COMMIT = '01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf'
AUDIT_SHA256 = '8e75e5e91576559461ec6a3d74b09d03725e567a3306e92a0a130c86a7dd97fd'
EXTRA_SOURCES = {
    'std/fs.rs': '8e8e9a0afb637414c29163d5703c3c979d548f88b332c40154e1dba7fb7ce570',
    'std/sys/pal/unix/mod.rs': 'a6b69f1cdccab6b8193ac3b0601f99096d7e8c18a4b1571c5700ade9246b691a',
}
# Exact reviewed ranges; whole-file hashes, not snippets, guard source identity.
RANGES = {
    'std/fs.rs': [(1282, 1283), (1294, 1298), (1455, 1476)],
    'std/sys/fs/unix.rs': [(1540, 1542)],
    'std/sys/fd/unix.rs': [(111, 121)],
    'std/sys/pal/unix/mod.rs': [(302, 304)],
    'std/io/mod.rs': [(572, 585), (1044, 1046)],
    'std/io/error.rs': [(1, 12), (82, 83), (186, 190), (620, 622), (648, 650), (680, 682)],
    'std/io/error/repr_bitpacked.rs': [(112, 116), (167, 170), (202, 205), (228, 236), (244, 279), (374, 377)],
}


def sha(path):
    """Hash exact evidence bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_template(path):
    """Load an already hash-checked archived helper without a bytecode cache."""
    module = types.ModuleType('frozen_io_error_helper')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def check_guard(function, instructions):
    """Require the complete literal entry-to-return path for tag != Custom.

    For all 64-bit input words, AND 3 followed by CMP 1 takes the sole branch
    iff the low bits are 1. The other path contains only restores and RET.
    No source-variant assumption is used for this local conditional statement.
    """
    start = int(function['address'], 16)
    expected = [
        ('sub', 'sp, sp, #0x50'), ('stp', 'x22, x21, [sp, #0x20]'),
        ('stp', 'x20, x19, [sp, #0x30]'), ('stp', 'x29, x30, [sp, #0x40]'),
        ('add', 'x29, sp, #0x40'), ('ldr', 'x19, [x0]'),
        ('and', 'x8, x19, #0x3'), ('cmp', 'x8, #0x1'),
        ('b.eq', hex(start + 0x38)), ('ldp', 'x29, x30, [sp, #0x40]'),
        ('ldp', 'x20, x19, [sp, #0x30]'), ('ldp', 'x22, x21, [sp, #0x20]'),
        ('add', 'sp, sp, #0x50'), ('ret', ''),
    ]
    snippet = []
    for i, (op, args) in enumerate(expected):
        address = start + 4 * i
        actual_op, actual_args = instructions.get(address, ('', ''))
        if op == 'b.eq':
            actual_args = actual_args.split(' <', 1)[0]
        if (actual_op, actual_args) != (op, args):
            raise ValueError('changed io::Error guard at ' + hex(address))
        snippet.append({'address': hex(address), 'instruction': ' '.join(instructions[address]).rstrip()})
    gaps = [g for g in function['gaps'] if g['kind'] == 'indirect_call']
    if len(gaps) != 1 or gaps[0]['address'] != hex(start + 0x4c) or instructions.get(start + 0x4c) != ('blr', 'x8'):
        raise ValueError('unexpected io::Error indirect site')
    return {'function': function['name'], 'entry': hex(start), 'instructions': snippet,
            'indirect_site': gaps[0]['address'], 'non_custom_return': hex(start + 0x34),
            'conditional_local_result': 'All valid Error words with low bits 0, 2 or 3 return before any call.',
            'tag_partition': [{'tag': tag, 'enters_custom_body': tag == 1} for tag in range(4)],
            'non_custom_local_sp_bytes': 80, 'unconditional_site_unreachable': False}


def source_evidence(rustdoc, audit, extractor, output, inputs):
    """Retain exact installed-source snapshots and reviewed read-path ranges."""
    expected = dict(EXTRA_SOURCES)
    for entry in audit['external_sources']:
        if entry['kind'] == 'rust':
            if entry['commit'] != COMMIT or not entry['upstream_matches_installed_code']:
                raise ValueError('source audit commit/correspondence differs')
            relative = entry['path'].replace('library/', '', 1).replace('/src/', '/', 1)
            expected[relative] = entry['sha256']
    result = {}
    for relative, ranges in RANGES.items():
        path = rustdoc / (relative + '.html')
        inputs[str(path)] = sha(path)
        code = extractor.rustdoc_source(path.read_text())
        digest = hashlib.sha256(code.encode()).hexdigest()
        if digest != expected[relative]:
            raise ValueError('installed source differs: ' + relative)
        archive = output / (relative.replace('/', '-') + '.template')
        archive.write_text(code)
        crate, rest = relative.split('/', 1)
        lines = code.splitlines()
        result[relative] = {
            'source_sha256': digest, 'installed_html_sha256': inputs[str(path)],
            'snapshot': str(archive),
            'commit_url': f'https://github.com/rust-lang/rust/blob/{COMMIT}/library/{crate}/src/{rest}',
            'reviewed_excerpts': [{'first_line': lo, 'last_line': hi, 'text': '\n'.join(lines[lo-1:hi])} for lo, hi in ranges],
        }
    return result


def run(root, output, rustdoc):
    """Guard immutable evidence, check both entry paths, and retain limitations."""
    output.mkdir(parents=True, exist_ok=False)
    inputs = {str(Path(__file__).resolve()): sha(Path(__file__).resolve())}
    report = {'schema': 'parliament-io-error-guard-v1', 'status': 'UNKNOWN', 'inputs': inputs,
              'modes': {}, 'whole_worker_variant_flow_proved': False,
              'all_inputs_panic_free_proved': False, 'complete_workspace_certificate': False,
              'complete_stack_bound_bytes': None, 'profile_qualified': False,
              'source_lemma_scope': 'Ordinary charged File::read/read_exact error construction only; setup/open/metadata errors, unwind and runtime callbacks excluded.',
              'premises': ['Pinned std source/compiler correspondence and ordinary ARM64 ABI.',
                           'Valid Error representation; memory-safe std/native execution and no corruption or reentry.',
                           'Concrete File implementation and default read_exact dispatch as in the pinned source.'],
              'limitations': ['No compiled whole-worker variant-flow or alias proof; the original indirect frontier remains open.',
                              'No resource bounds on read/errno, dynamic loader, failure handlers, signals or unwinding.',
                              'Read may repeatedly return Interrupted; no universal I/O time/attempt bound follows.',
                              'No old graph, report, binary or qualification flag is rewritten.']}
    try:
        for directory in (STACK, FRONTIERS):
            manifest = root / directory / 'SHA256SUMS'
            inputs[str(manifest)] = sha(manifest)
            for line in manifest.read_text().splitlines():
                expected, relative = line.split('  ', 1)
                path = root / relative
                if sha(path) != expected:
                    raise ValueError('old evidence changed: ' + relative)
                inputs[str(path)] = expected
        build_path = root / BUILD / 'build-receipt.json'
        audit_path = root / BUILD / 'native-runtime-audit.json'
        for path in (build_path, audit_path, root / WORKSPACE):
            inputs[str(path)] = sha(path)
        if inputs[str(audit_path)] != AUDIT_SHA256:
            raise ValueError('frozen native source audit changed')
        build = json.loads(build_path.read_text())
        if not build['build_passed'] or build['source_changes'] or inputs[str(root / WORKSPACE)] != build['started_source_sha256'][str(WORKSPACE)]:
            raise ValueError('frozen worker source/build differs')
        analyzer = load_template(root / STACK / 'parliament_ballot_stack_audit.py.template')
        extractor = load_template(root / FRONTIERS / 'parliament_ballot_stack_frontiers.py.template')
        boundary = json.loads((root / FRONTIERS / 'report.json').read_text())
        build_pins = [h for p, h in boundary['inputs'].items() if p.endswith('/' + str(BUILD / 'build-receipt.json'))]
        if build_pins != [inputs[str(build_path)]]:
            raise ValueError('failure-frontier build identity differs')
        report['source_evidence'] = source_evidence(rustdoc, json.loads(audit_path.read_text()), extractor, output, inputs)
        for mode in ('portable', 'accel'):
            binary = Path(build['binaries'][mode]['path'])
            expected = build['binaries'][mode]['sha256']
            if sha(binary) != expected:
                raise ValueError('frozen executable changed')
            inputs[str(binary)] = expected
            stack = json.loads((root / STACK / (mode + '.json')).read_text())
            if stack['identity']['binary_sha256'] != expected:
                raise ValueError('stack binary identity differs')
            sites = [f for f in boundary['modes'][mode]['conditional_boundary_roots']['worker']['frontiers'] if f['kind'] == 'indirect_call']
            if len(sites) != 1 or boundary['modes'][mode]['binary_sha256'] != expected:
                raise ValueError('remaining worker indirect frontier differs')
            functions = [f for f in stack['functions'] if f['name'] == sites[0]['function'] and re.fullmatch(r'core::ptr::drop_in_place\$LT\$std\.\.io\.\.error\.\.Error\$GT\$::h[0-9a-f]{16}', f['name'])]
            if len(functions) != 1:
                raise ValueError('missing or ambiguous io::Error destructor')
            instructions, _ = analyzer.parse_disassembly((root / STACK / mode / 'disassembly.txt').read_text())
            result = check_guard(functions[0], instructions)
            if result['indirect_site'] != sites[0]['address']:
                raise ValueError('local guard does not cover the retained frontier')
            result['original_frontier'] = sites[0]
            result['binary_sha256'] = expected
            result['all_direct_callers_in_frozen_graph'] = [
                {'function': f['name'], 'call': c}
                for f in stack['functions'] for c in f['calls'] if c['target'] == functions[0]['address']]
            report['modes'][mode] = result
        report['status'] = 'LOCAL_GUARDS_PASS_SOURCE_LEMMA_CONDITIONAL'
    except (OSError, ValueError, KeyError, UnicodeError) as error:
        report['failure'] = f'{type(error).__name__}: {error}'
    report['input_changes'] = {name: {'before': digest, 'after': sha(Path(name)) if Path(name).is_file() else None}
                               for name, digest in inputs.items() if not Path(name).is_file() or sha(Path(name)) != digest}
    if report['input_changes']:
        report['status'] = 'UNKNOWN'
    report['observed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    """Expose a new-directory-only check; unknown or qualification demand fails."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustdoc-src', type=Path, default=Path.home() / '.rustup/toolchains/1.93.1-aarch64-apple-darwin/share/doc/rust/html/src')
    parser.add_argument('--require-qualified', action='store_true')
    args = parser.parse_args()
    report = run(ROOT, args.output.resolve(), args.rustdoc_src.resolve())
    print(json.dumps({k: report.get(k) for k in ('status', 'failure', 'profile_qualified')}))
    return 2 if args.require_qualified else int(report['status'] == 'UNKNOWN')


if __name__ == '__main__':
    sys.exit(main())
