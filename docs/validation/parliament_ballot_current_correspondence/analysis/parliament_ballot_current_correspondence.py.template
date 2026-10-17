#!/usr/bin/env python3
"""Re-evaluate ordinary compiled lemmas for one freshly built ballot candidate.

Python 3.11+, the exact retained historical/current build and stack artifacts,
and their current source inputs are required. No builds, image execution,
environment overrides or historical edits. --output must be new. Any changed
identity or unreviewed image/source difference produces UNKNOWN. Native,
cryptographic, exceptional and complete workspace costs remain unresolved.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import struct

MANIFESTS = {
    'fatal_stack_eon': '44f4361b01a7f4d78805055b187a8073448d516391bd407c91c70b658fa0ea48',
    'adapter_bound': '4e3124e2ab8b757bfb76282064d06edfdf157631fe6c341277cb6791c302e57f',
    'frontend_bound': '81bae3e341dbb26915dd45d9a24d763705b983d9f6826d99c8a01d152e173b84',
    'profile_bound': '300ae6a89b19ef2c99ef27f6ba10e4ad8d981c62150ca12d1c95e1c586dd60cd',
    'typed_decoder_bound': '3b6053c629e21af9331af6b3c86e82adce7513b65b2ab1630400aa5badd8be90',
}
OLD_BUILD = '83b90362f008d9cec6edb4a35d247298935b07c73ad1cb171c6e3bebef30b90f'
NEW_BUILD = '4ef33ae9c643febd2d98904a556cc89fe559b48b4a852193ff3ffd6f7d09bba6'
NEW_CAPTURE = 'd1e6571ba7452584c87e981027020564541d88a4a0b6e1ce17b3e3ed54d30acb'
SOURCE_DIFFERENCES = {
    'Cargo.lock', 'crates/iroha_allocation/src/allocation/shared.rs',
    'crates/iroha_allocation/src/shared.rs',
    'crates/iroha_allocation/src/shared_reservation_tests.rs',
    'crates/iroha_allocation/src/shared_wake_tests.rs',
    'worker/preparation.json', 'worker/root-Cargo.lock.template',
}
ANNOTATIONS = {'registration': (0x30, 0x164), 'vote': (0x28,),
               'profile': (0xf8, 0x11c, 0x12c, 0x150, 0x160, 0x3f0, 0x414, 0x41c, 0x444, 0x570)}
OLD_ANNOTATION = '_anon.78b212c1252edd9235870cc35cbf64cd.6'
NEW_ANNOTATION = '_anon.941969dec3181432166ad0fab5edf2d7.6'


def digest(path):
    """Hash exact file bytes, refusing missing inputs."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    """Load a Python dependency only after its caller verifies the artifact."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    if Path(module.__file__).resolve() != Path(path).resolve():
        raise ValueError('unexpected loaded module path')
    return module


def guard_file(path, expected, guards):
    """Record actual before bytes even when their required identity refuses."""
    path = Path(path).resolve()
    actual = digest(path)
    if str(path) in guards and guards[str(path)] != actual:
        raise ValueError('input changed during validation: ' + str(path))
    guards[str(path)] = actual
    if actual != expected:
        raise ValueError('input identity differs: ' + str(path))


def frozen_manifest(directory, expected, guards):
    """Validate every unique, directory-contained historical manifest entry."""
    guard_file(directory / 'SHA256SUMS', expected, guards)
    seen = set()
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None or match[2] in seen:
            raise ValueError('malformed historical manifest')
        seen.add(match[2])
        path = (directory / match[2]).resolve()
        if not path.is_relative_to(directory.resolve()):
            raise ValueError('historical manifest path escape')
        guard_file(path, match[1], guards)


def macho(data):
    """Parse the narrow little-endian ARM64 executable layout, without loading it."""
    if len(data) < 32:
        raise ValueError('truncated Mach-O header')
    magic, cpu, _, kind, count, size, _, _ = struct.unpack_from('<8I', data)
    if (magic, cpu, kind) != (0xfeedfacf, 0x100000c, 2) or 32 + size > len(data):
        raise ValueError('unreviewed Mach-O header')
    commands, sections, segments = [], [], []
    offset = 32
    for _ in range(count):
        if offset + 8 > 32 + size:
            raise ValueError('truncated load command')
        cmd, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError('invalid load command extent')
        commands.append((cmd, offset, data[offset:offset+length]))
        if cmd == 0x19:
            if length < 72:
                raise ValueError('short segment command')
            fields = struct.unpack_from('<II16sQQQQiiII', data, offset)
            _, _, name, address, vsize, fileoff, filesize, _, _, nsects, _ = fields
            if length != 72 + 80*nsects or fileoff + filesize > len(data):
                raise ValueError('invalid segment extent')
            segments.append((name.rstrip(b'\0').decode(), address, vsize, fileoff, filesize))
            for index in range(nsects):
                row = struct.unpack_from('<16s16sQQ8I', data, offset+72+80*index)
                section, owner, start, extent, position, _, _, _, flags, _, _, _ = row
                zero = flags & 0xff in (1, 12, 18)
                if owner != name:
                    raise ValueError('section owner differs from enclosing segment')
                if not address <= start <= start+extent <= address+vsize:
                    raise ValueError('section outside segment')
                if not zero and not fileoff <= position <= position+extent <= fileoff+filesize:
                    raise ValueError('section outside file segment')
                sections.append((owner.rstrip(b'\0').decode(), section.rstrip(b'\0').decode(),
                                 start, extent, position, zero))
        offset += length
    if offset != 32 + size:
        raise ValueError('load command count/extent mismatch')
    def only(kind, length):
        found = [(p, b) for c, p, b in commands if c == kind]
        if len(found) != 1 or len(found[0][1]) != length:
            raise ValueError('missing/ambiguous required Mach-O command')
        return found[0]
    symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', only(2, 24)[1], 8)
    if symoff+16*nsyms > len(data) or stroff+strsize > len(data):
        raise ValueError('symbol table outside file')
    symbols = []
    for index in range(nsyms):
        string, typ, sect, desc, value = struct.unpack_from('<IBBHQ', data, symoff+index*16)
        # N_INDR would interpret n_value as another string-table index and
        # needs a different resolver. These exact executable images have only
        # undefined externals and the three ordinary section-defined forms.
        if typ not in (0x1, 0xe, 0xf, 0x1e):
            raise ValueError('unreviewed symbol type')
        if string >= strsize:
            raise ValueError('symbol string outside table')
        end = data.find(b'\0', stroff+string, stroff+strsize)
        if end < 0:
            raise ValueError('unterminated symbol')
        symbols.append((data[stroff+string:end].decode(), typ, sect, desc, value,
                        stroff+string, end))
    uuid = only(0x1b, 24)[0] + 8
    signature = struct.unpack_from('<II', only(0x1d, 16)[1], 8)
    if signature[0]+signature[1] != len(data) or signature[1] < 12:
        raise ValueError('unreviewed code signature extent')
    if struct.unpack_from('>I', data, signature[0])[0] != 0xfade0cc0:
        raise ValueError('unreviewed code signature container')
    linkedit = [s for s in segments if s[0] == '__LINKEDIT']
    if len(linkedit) != 1 or signature[0] < linkedit[0][3] or stroff < linkedit[0][3]:
        raise ValueError('symbol/signature metadata outside LINKEDIT')
    metadata = ((symoff, symoff+16*nsyms), (stroff, stroff+strsize),
                (signature[0], len(data)))
    for start, end in metadata:
        if not linkedit[0][3] <= start <= end <= linkedit[0][3]+linkedit[0][4]:
            raise ValueError('metadata outside LINKEDIT extent')
        if any(not zero and max(start, pos) < min(end, pos+size)
               for _, _, _, size, pos, zero in sections):
            raise ValueError('metadata overlaps loaded section')
    if any(max(a, c) < min(b, d) for i, (a, b) in enumerate(metadata)
           for c, d in metadata[i+1:]):
        raise ValueError('symbol/signature metadata overlaps')
    return {'commands': commands, 'sections': sections, 'symbols': symbols,
            'uuid': (uuid, uuid+16), 'signature': (signature[0], len(data)),
            'string_table': (stroff, stroff+strsize), 'symbol_table': (symoff, symoff+16*nsyms)}


def compare_images(old, new):
    """Compare bytes plus resolved symbol identities, UUID and signing excluded.

    Whole-file comparison keeps every load/import/bind/rebase/export record,
    mapped instruction/constant, zero-fill geometry and initial data byte fixed.
    UUID and ad-hoc signature identity are not an execution-cost claim.
    """
    a, b = macho(old), macho(new)
    if len(old) != len(new) or old[:32] != new[:32] or a['sections'] != b['sections']:
        raise ValueError('image geometry changed')
    if len(a['commands']) != len(b['commands']):
        raise ValueError('load command count changed')
    for (cmd, offset, before), (kind, position, after) in zip(a['commands'], b['commands']):
        if (cmd, offset, len(before)) != (kind, position, len(after)):
            raise ValueError('load command geometry changed')
        if cmd != 0x1b and before != after:
            raise ValueError('load/import command changed')
    if len(a['symbols']) != len(b['symbols']):
        raise ValueError('symbol count changed')
    masked_old, masked_new = bytearray(old), bytearray(new)
    exclusions = []
    for name in ('uuid', 'signature', 'string_table'):
        if a[name] != b[name]:
            raise ValueError('excluded metadata extent changed')
        start, end = a[name]
        masked_old[start:end] = masked_new[start:end] = bytes(end-start)
        exclusions.append({'kind': name, 'file_start': start, 'file_end': end})
    renames = []
    for index, (left, right) in enumerate(zip(a['symbols'], b['symbols'])):
        oldname, newname = left[0], right[0]
        if left[1:5] != right[1:5]:
            raise ValueError('nonlocal symbol or target identity changed')
        # n_strx may relocate when the linker reorders strings. Resolve every
        # symbol before excluding this index word; all other nlist bytes stay
        # under the full-file equality check. Undefined/native names must match.
        start = a['symbol_table'][0]+16*index
        masked_old[start:start+4] = masked_new[start:start+4] = bytes(4)
        if oldname == newname:
            continue
        if left[1] != 0x1e:
            raise ValueError('nonlocal symbol name changed')
        anonymous = r'_anon\.[0-9a-f]{32}(\.[0-9]+)'
        drop = r'(__ZN92_\$LT\$iroha_allocation\.\.shared\.\.Shared\$LT\$T\$C\$Charge\$GT\$\$u20\$as\$u20\$core\.\.ops\.\.drop\.\.Drop\$GT\$4drop17h)[0-9a-f]{16}E'
        pairs = [(re.fullmatch(p, oldname), re.fullmatch(p, newname)) for p in (anonymous, drop)]
        if not any(x and y and x.group(1) == y.group(1) for x, y in pairs):
            raise ValueError('unreviewed local symbol rename')
        renames.append({'old': oldname, 'new': newname, 'address': hex(left[4]),
                        'symbol_type': left[1], 'section': left[2]})
    if len(renames) != 11 or masked_old != masked_new:
        raise ValueError('unreviewed instruction/data/loader/metadata byte difference')
    return {'all_other_file_bytes_equal': True, 'symbol_renames': renames,
            'resolved_symbol_rows_checked': len(a['symbols']),
            'symbol_string_index_words_checked': len(a['symbols']),
            'excluded_metadata': exclusions, 'sections': a['sections'],
            'signature_authenticity_proved': False, 'native_library_costs_proved': False}


def source_correspondence(root, old, new):
    """Keep all 2,021 source identities, explicitly classify seven known deltas.

    The source-backed worker/arena/fatal/parser/profile/typed predicates are
    byte-identical. Changed allocation library routines are opaque callees,
    not borrowed ownership proofs from the historical build.
    """
    def indexed(receipt):
        answer = {}
        generated = Path(receipt['generated_dir'])
        for raw, value in receipt['source_files'].items():
            path = Path(raw)
            if path.is_relative_to(generated):
                name = 'worker/' + str(path.relative_to(generated))
            elif path.name == 'build_worker.py.template':
                name = 'build_recipe'
            elif path.is_relative_to(root):
                name = str(path.relative_to(root))
            else:
                name = str(path)
            if name in answer:
                raise ValueError('ambiguous source identity mapping')
            answer[name] = value
        return answer
    a, b = indexed(old), indexed(new)
    if set(a) != set(b) or len(a) != 2021:
        raise ValueError('source inventory changed')
    changed = {name: {'historical': a[name], 'current': b[name]} for name in a if a[name] != b[name]}
    if set(changed) != SOURCE_DIFFERENCES:
        raise ValueError('unreviewed source premise change')
    return {'same_source_identities': len(a)-len(changed), 'changes': changed,
            'scope': 'Only unchanged source premises and exact ordinary machine bodies transfer; changed allocation callees remain opaque.'}


def body_correspondence(mode, old_report, new_report, old_text, new_text, analyzer, patterns, renames):
    """Allow exactly thirteen preidentified anonymous ADRP annotation changes."""
    before, _ = analyzer.parse_disassembly(old_text)
    after, _ = analyzer.parse_disassembly(new_text)
    replacements, rows = [], []
    if mode not in ('portable', 'accel'):
        raise ValueError('unknown compiled mode')
    for label, pattern in patterns.items():
        matches = [[f for f in report['functions'] if pattern in f['name']] for report in (old_report, new_report)]
        if any(len(items) != 1 for items in matches):
            raise ValueError('ambiguous corresponding function')
        left, right = [items[0] for items in matches]
        if (left['address'], left['end']) != (right['address'], right['end']):
            raise ValueError('function range changed')
        start, end = int(left['address'], 16), int(left['end'], 16)
        expected = set(ANNOTATIONS.get(label, ())) if mode == 'accel' else set()
        observed = set()
        for address in range(start, end, 4):
            if address not in before or address not in after:
                raise ValueError('instruction missing from corresponding range')
            if before[address] == after[address]:
                continue
            observed.add(address-start)
            op, operands = after[address]
            oldop, oldoperands = before[address]
            old_suffix = f'0x10005b000 <{OLD_ANNOTATION}+0x49>'
            new_suffix = f'0x10005b000 <{NEW_ANNOTATION}+0x49>'
            symbol_ok = any(x['old'] == OLD_ANNOTATION and x['new'] == NEW_ANNOTATION for x in renames)
            if (address-start not in expected or op != 'adrp' or oldop != op or not symbol_ok
                    or not operands.endswith(new_suffix) or not oldoperands.endswith(old_suffix)
                    or operands.replace(new_suffix, old_suffix) != oldoperands):
                raise ValueError('instruction/branch/target/unreviewed annotation changed')
            replacements.append({'address': hex(address), 'old': oldoperands, 'new': operands})
        if observed != expected:
            raise ValueError('expected annotation correspondence changed')
        rows.append({'function': label, 'address': left['address'], 'end': left['end'],
                     'instruction_count': (end-start)//4, 'label_only_changes': len(observed)})
    normalized = new_text
    for row in replacements:
        # Match one whole decoded instruction line; never strip arbitrary labels.
        pattern = re.compile(r'^(\s*' + row['address'][2:] + r':\s+adrp\s+)' +
                             re.escape(row['new']) + r'(\s*)$', re.MULTILINE)
        normalized, count = pattern.subn(lambda m: m[1]+row['old']+m[2], normalized)
        if count != 1:
            raise ValueError('ambiguous annotation substitution')
    return normalized, {'functions': rows, 'annotation_substitutions': replacements}


def inputs(root, guards):
    """Validate frozen lemmas and the current successful source-bound capture."""
    base = root / 'docs/validation'
    dirs = {name: base / ('parliament_ballot_'+name) for name in MANIFESTS}
    for name, directory in dirs.items():
        frozen_manifest(directory, MANIFESTS[name], guards)
    old_build = base / 'parliament_ballot_fatal_control/build/build-receipt.json'
    new_build = base / 'parliament_ballot_current_candidate/build-v2/build-receipt.json'
    capture = base / 'parliament_ballot_current_candidate/stack'
    for path, expected in ((old_build, OLD_BUILD), (new_build, NEW_BUILD), (capture/'receipt.json', NEW_CAPTURE)):
        guard_file(path, expected, guards)
    checker_path = capture/'check_parliament_ballot_memory_entry.py.template'
    historical_checker = dirs['fatal_stack_eon']/'check_parliament_ballot_memory_entry.py.template'
    guard_file(checker_path, digest(historical_checker), guards)
    # The checker imports its resource/supervisor modules. Use its recorded
    # original scripts path and independently require the loaded paths/bytes.
    import sys
    sys.path.insert(0, str(root/'scripts'))
    checker = load('correspondence_build_checker', checker_path)
    for key in ('resource', 'supervisor'):
        module = getattr(checker, key)
        expected_path = root/'scripts'/('check_parliament_ballot_resource_contract.py' if key == 'resource' else 'parliament_ballot_memory_supervisor.py')
        if Path(module.__file__).resolve() != expected_path.resolve():
            raise ValueError('unexpected loaded checker dependency')
        guard_file(expected_path, digest(dirs['fatal_stack_eon']/(expected_path.name+'.template')), guards)
    read = lambda path: checker.object_json(Path(path).read_text())
    current = read(capture/'receipt.json')
    if current['capture_passed'] is not True or current['failure'] is not None or current['input_changes'] != {}:
        raise ValueError('current capture is not stable')
    for name, expected in current['input_sha256'].items():
        guard_file(name, expected, guards)
    build = read(new_build)
    binaries = {mode: Path(row['path']) for mode, row in build['binaries'].items()}
    validated = checker.validate_build(build, binaries, root)
    for name, expected in validated.items():
        guard_file(name, expected, guards)
    if set(current['captures']) != {'portable', 'accel'} or set(binaries) != {'portable', 'accel'}:
        raise ValueError('both image modes required')
    for mode, row in current['captures'].items():
        path = capture/(mode+'.json')
        if Path(row['path']).resolve() != path.resolve():
            raise ValueError('capture report path differs')
        guard_file(path, row['sha256'], guards)
        report = read(path)
        identity = report['identity']
        if identity['binary'] != str(binaries[mode]) or identity['binary_sha256'] != build['binaries'][mode]['sha256']:
            raise ValueError('capture binary not built by current receipt')
        if identity['binary_tool_and_analyzer_unchanged_during_capture'] is not True:
            raise ValueError('unstable image capture')
        for command in identity['commands']:
            guard_file(command['output'], command['sha256'], guards)
    for command in current['commands']:
        if command['exit'] != 0:
            raise ValueError('capture regression did not pass')
        guard_file(command['log'], command['log_sha256'], guards)
    paths = {'adapter': dirs['adapter_bound']/'parliament_ballot_adapter_bound.py.template',
             'frontend': dirs['frontend_bound']/'analysis/parliament_ballot_frontend_bound.py.template',
             'profile': dirs['profile_bound']/'analysis/parliament_ballot_profile_bound.py.template',
             'typed': dirs['typed_decoder_bound']/'analysis/parliament_ballot_typed_decoder_bound.py.template',
             'stack': dirs['fatal_stack_eon']/'parliament_ballot_stack_audit.py.template'}
    modules = {key: load('correspondence_'+key, path) for key, path in paths.items()}
    source = source_correspondence(root, read(old_build), build)
    return dirs['fatal_stack_eon'], capture, modules, read, source


def analyze_mode(mode, old_dir, new_dir, modules, read, guards):
    """Re-run all four unchanged scoped analyses after strict correspondence."""
    old_report, new_report = [read(d/(mode+'.json')) for d in (old_dir, new_dir)]
    images = []
    for report in (old_report, new_report):
        identity = report['identity']
        guard_file(identity['binary'], identity['binary_sha256'], guards)
        images.append(Path(identity['binary']).read_bytes())
    image_match = compare_images(*images)
    adapter, frontend, profile, typed, stack = [modules[k] for k in ('adapter', 'frontend', 'profile', 'typed', 'stack')]
    patterns = adapter.PATTERNS | frontend.PATTERNS | {'profile': 'profile::Profile::new::'}
    old_text, new_text = [(d/mode/'disassembly.txt').read_text() for d in (old_dir, new_dir)]
    normalized, bodies = body_correspondence(mode, old_report, new_report, old_text, new_text, stack, patterns, image_match['symbol_renames'])
    text_sections = [s for s in image_match['sections'] if s[:2] == ('__TEXT', '__text')]
    if len(text_sections) != 1:
        raise ValueError('ambiguous executable text section')
    _, _, address, size, fileoff, zero = text_sections[0]
    for row in bodies['functions']:
        start, end = int(row['address'], 16), int(row['end'], 16)
        if zero or start % 4 or end % 4 or not address <= start < end <= address+size:
            raise ValueError('body range outside executable text')
        position = fileoff+start-address
        before, after = [image[position:position+end-start] for image in images]
        if before != after:
            raise ValueError('compiled body bytes changed')
        row.update(machine_bytes=end-start, machine_sha256=hashlib.sha256(after).hexdigest())
    starts, stubs = [(new_dir/mode/(name+'.txt')).read_text() for name in ('starts', 'stubs')]
    a = adapter.analyze_mode(mode, new_report, normalized, starts, stubs, stack)
    f = frontend.analyze_mode(mode, new_report, normalized, starts, stubs, stack)
    p = profile.analyze_mode(mode, new_report, normalized, starts, stubs, frontend, stack)
    t = typed.analyze_mode(mode, new_report, normalized, starts, stubs, frontend, stack, f)
    return {'image_correspondence': image_match, 'body_correspondence': bodies,
            'adapter': a, 'frontend': f, 'profile_coordinator': p, 'typed_decoders': t}


def run(root, output):
    """Persist a new conditional report or UNKNOWN without changing old evidence."""
    output.mkdir(parents=True, exist_ok=False)
    guards, modes, source, source_bounds, requests, failure = {}, {}, {}, {}, {}, None
    try:
        for path in (Path(__file__).resolve(), root/'scripts/tests/parliament_ballot_current_correspondence_test.py'):
            guard_file(path, digest(path), guards)
            (output/(path.name+'.template')).write_bytes(path.read_bytes())
        old_dir, new_dir, modules, read, source = inputs(root, guards)
        source_bounds = modules['frontend'].source_bounds()
        requests = modules['typed'].source_requests()
        for mode in ('portable', 'accel'):
            modes[mode] = analyze_mode(mode, old_dir, new_dir, modules, read, guards)
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for name, expected in guards.items():
        actual = digest(name) if Path(name).is_file() else None
        if actual != expected:
            changes[name] = {'before': expected, 'after': actual}
    passed = failure is None and not changes and len(modes) == 2
    result = {'schema': 'parliament-current-compiled-correspondence-v1',
              'verdict': 'PASS_UNDER_STATED_PREMISES' if passed else 'UNKNOWN',
              'failure': failure, 'modes': modes, 'source_correspondence': source,
              'frontend_source_bounds': source_bounds, 'typed_source_requests': requests,
              'input_sha256': guards, 'input_changes': changes,
              'applies_to_guarded_current_candidate': passed,
              'complete_workspace_certificate': False, 'complete_native_cost_certificate': False,
              'complete_crypto_cost_certificate': False, 'physical_cost_calibrated': False,
              'profile_qualified': False, 'production_gate_changed': False}
    (output/'report.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    return result


def main():
    """Require explicit source root and a fresh artifact directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.root.resolve(), args.output.resolve())
    print(json.dumps({key: result[key] for key in ('verdict', 'failure', 'input_changes')}))
    return int(result['verdict'] != 'PASS_UNDER_STATED_PREMISES')


if __name__ == '__main__':
    raise SystemExit(main())
