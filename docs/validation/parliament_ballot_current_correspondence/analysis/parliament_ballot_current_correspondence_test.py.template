"""Adversarial controls for one current candidate's compiled correspondence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct

import pytest

from scripts import parliament_ballot_current_correspondence as check

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def inputs():
    guards = {}
    old, new, modules, read, source = check.inputs(ROOT, guards)
    return old, new, modules, read, source, guards


@pytest.fixture(scope='module', params=('portable', 'accel'))
def pair(request, inputs):
    old, new, modules, read, _, _ = inputs
    mode = request.param
    reports = [read(d/(mode+'.json')) for d in (old, new)]
    images = [Path(r['identity']['binary']).read_bytes() for r in reports]
    texts = [(d/mode/'disassembly.txt').read_text() for d in (old, new)]
    patterns = modules['adapter'].PATTERNS | modules['frontend'].PATTERNS | {'profile': 'profile::Profile::new::'}
    return mode, reports, images, texts, patterns


def test_all_live_current_guards_and_source_inventory(inputs):
    _, _, _, _, source, guards = inputs
    assert source['same_source_identities'] == 2014
    assert set(source['changes']) == check.SOURCE_DIFFERENCES
    assert all(check.digest(path) == value for path, value in guards.items())


def test_current_images_and_exact_body_ranges(pair, inputs):
    mode, reports, images, texts, patterns = pair
    image = check.compare_images(*images)
    normalized, bodies = check.body_correspondence(mode, *reports, *texts,
        inputs[2]['stack'], patterns, image['symbol_renames'])
    assert len(bodies['functions']) == 12
    assert sum(row['instruction_count'] for row in bodies['functions']) == 2530
    assert len(bodies['annotation_substitutions']) == (13 if mode == 'accel' else 0)
    assert len(image['symbol_renames']) == 11
    assert image['signature_authenticity_proved'] is False
    assert normalized != texts[1] if mode == 'accel' else normalized == texts[1]


@pytest.mark.parametrize('kind', ('instruction', 'constant', 'branch', 'symbol_target', 'native_import', 'load_library', 'dyld_bind'))
def test_image_mutations_refuse(pair, kind, inputs):
    _, reports, images, texts, _ = pair
    original, current = images
    layout = check.macho(current)
    altered = bytearray(current)
    if kind in ('instruction', 'branch'):
        section = next(s for s in layout['sections'] if s[:2] == ('__TEXT', '__text'))
        position = section[4]
        if kind == 'branch':
            instructions, _ = inputs[2]['stack'].parse_disassembly(texts[1])
            worker = next(f for f in reports[1]['functions'] if 'workspace::worker::' in f['name'])
            address = next(a for a, (op, _) in instructions.items()
                           if int(worker['address'], 16) <= a < int(worker['end'], 16) and op.startswith('b.'))
            position = section[4]+address-section[2]
    elif kind == 'constant':
        section = next(s for s in layout['sections'] if s[:2] == ('__TEXT', '__const'))
        position = section[4]
    elif kind == 'symbol_target':
        _, _, raw = next(c for c in layout['commands'] if c[0] == 2)
        table = struct.unpack_from('<I', raw, 8)[0]
        index = next(i for i, s in enumerate(layout['symbols']) if s[1] == 0x1e)
        position = table+16*index+8
    elif kind == 'native_import':
        symbol = next(s for s in layout['symbols'] if s[1] & 0xe == 0 and s[0])
        position = symbol[5] + 1
    elif kind == 'load_library':
        _, position, raw = next(c for c in layout['commands'] if c[0] == 0xc)
        position += struct.unpack_from('<I', raw, 8)[0]+1
    else:
        _, _, raw = next(c for c in layout['commands'] if c[0] == 0x80000022)
        position, length = struct.unpack_from('<II', raw, 16)
        assert length > 0
    altered[position] ^= 0x20 if kind == 'branch' else 1
    with pytest.raises(ValueError):
        check.compare_images(original, bytes(altered))


def test_only_declared_nonsemantic_metadata_exclusions(pair):
    _, _, images, _, _ = pair
    layout = check.macho(images[1]); altered = bytearray(images[1])
    altered[layout['uuid'][0]] ^= 1
    altered[layout['signature'][1]-1] ^= 1
    assert check.compare_images(images[0], bytes(altered))['all_other_file_bytes_equal']


@pytest.mark.parametrize('kind', ('cpu', 'command_extent', 'signature_container', 'symbol_string_extent', 'section_owner', 'metadata_overlap', 'indirect_symbol'))
def test_macho_unexpected_shapes_refuse(pair, kind):
    _, _, images, _, _ = pair
    layout = check.macho(images[1]); altered = bytearray(images[1])
    if kind == 'cpu':
        struct.pack_into('<I', altered, 4, 7)
    elif kind == 'command_extent':
        struct.pack_into('<I', altered, 36, 0)
    elif kind == 'signature_container':
        altered[layout['signature'][0]] ^= 1
    elif kind in ('symbol_string_extent', 'indirect_symbol'):
        _, _, raw = next(c for c in layout['commands'] if c[0] == 2)
        symbol_offset = struct.unpack_from('<I', raw, 8)[0]
        if kind == 'indirect_symbol': altered[symbol_offset+4] = 0xa
        else: struct.pack_into('<I', altered, symbol_offset, 0xffffffff)
    elif kind == 'section_owner':
        _, position, _ = next(c for c in layout['commands'] if c[0] == 0x19 and len(c[2]) > 72)
        altered[position+72+16] ^= 1
    else:
        _, position, raw = next(c for c in layout['commands'] if c[0] == 2)
        string_offset = struct.unpack_from('<I', raw, 16)[0]
        struct.pack_into('<I', altered, position+8, string_offset)
    with pytest.raises(ValueError):
        check.macho(bytes(altered))


@pytest.mark.parametrize('kind', ('opcode', 'branch_target', 'constant_address', 'annotation', 'missing_annotation', 'range'))
def test_text_and_target_mutations_refuse(inputs, kind):
    old, new, modules, read, _, _ = inputs
    reports = [read(d/'accel.json') for d in (old, new)]
    texts = [(d/'accel/disassembly.txt').read_text() for d in (old, new)]
    images = [Path(r['identity']['binary']).read_bytes() for r in reports]
    renames = check.compare_images(*images)['symbol_renames']
    patterns = modules['adapter'].PATTERNS | modules['frontend'].PATTERNS | {'profile': 'profile::Profile::new::'}
    if kind == 'range':
        reports = deepcopy(reports)
        fn = next(f for f in reports[1]['functions'] if patterns['vote'] in f['name'])
        fn['end'] = hex(int(fn['end'], 16)+4)
    else:
        lines = texts[1].splitlines(True)
        instructions, _ = modules['stack'].parse_disassembly(texts[1])
        worker = next(f for f in reports[1]['functions'] if patterns['worker'] in f['name'])
        branch = next(a for a, (op, _) in instructions.items()
                      if int(worker['address'], 16) <= a < int(worker['end'], 16) and op.startswith('b.'))
        for index, line in enumerate(lines):
            if kind == 'branch_target' and line.lstrip().startswith(f'{branch:x}:'):
                lines[index] = re.sub(r'0x[0-9a-f]+', lambda m: hex(int(m[0], 16)+4), line, count=1)
                break
            if '10000e7e4:' in line:
                if kind == 'opcode': lines[index] = line.replace('adrp', 'adr')
                elif kind == 'constant_address': lines[index] = line.replace('0x10005b000', '0x10005c000')
                elif kind == 'annotation': lines[index] = line.replace('+0x49', '+0x4a')
                elif kind == 'missing_annotation': lines[index] = line.replace(check.NEW_ANNOTATION, check.OLD_ANNOTATION)
                if kind != 'branch_target': break
        changed = ''.join(lines)
        assert changed != texts[1]
        texts[1] = changed
    with pytest.raises(ValueError):
        check.body_correspondence('accel', *reports, *texts, modules['stack'], patterns, renames)


@pytest.mark.parametrize('kind', ('changed_premise', 'missing_source', 'added_source', 'unapproved_diff_removed'))
def test_source_premise_mutations_refuse(inputs, kind):
    old = json.loads((ROOT/'docs/validation/parliament_ballot_fatal_control/build/build-receipt.json').read_text())
    new = json.loads((ROOT/'docs/validation/parliament_ballot_current_candidate/build-v2/build-receipt.json').read_text())
    source = str(ROOT/'crates/iroha_parliament_ballot_proof/src/test_codec.rs')
    if kind == 'changed_premise': new['source_files'][source] = '0'*64
    elif kind == 'missing_source': del new['source_files'][source]
    elif kind == 'added_source': new['source_files'][str(ROOT/'unreviewed.rs')] = '0'*64
    else:
        name = str(ROOT/'Cargo.lock');new['source_files'][name] = old['source_files'][name]
    with pytest.raises(ValueError): check.source_correspondence(ROOT, old, new)


def test_guard_keeps_actual_drift_identity(tmp_path):
    path = tmp_path/'source.rs';path.write_text('changed');guards = {}
    with pytest.raises(ValueError, match='identity differs'):
        check.guard_file(path, '0'*64, guards)
    assert guards[str(path)] == hashlib.sha256(b'changed').hexdigest()


def test_manifest_cannot_escape(tmp_path):
    manifest = tmp_path/'SHA256SUMS';manifest.write_text('0'*64+'  ../outside\n')
    with pytest.raises(ValueError, match='escape'):
        check.frozen_manifest(tmp_path, check.digest(manifest), {})


def test_all_four_analyses_recomputed_without_changing_historical_pins(inputs):
    old, new, modules, read, _, guards = inputs
    before = deepcopy(modules['frontend'].BODY_HASHES)
    for mode in ('portable', 'accel'):
        result = check.analyze_mode(mode, old, new, modules, read, guards)
        assert result['adapter']['adapter_issued_instruction_bound_excluding_callees'] == 5298
        assert result['adapter']['adapter_owned_stack_bytes_including_red_zone'] == 336
        assert result['frontend']['reservation_plus_record_local_instruction_bound'] == 146
        assert result['profile_coordinator']['local_issued_instruction_bound'] == 834
        assert result['typed_decoders']['decoders']['registration']['with_parser_local_instruction_bound'] == 621
        assert result['typed_decoders']['decoders']['vote']['with_parser_local_instruction_bound'] == 592
        assert result['adapter']['complete_workspace_certificate'] is False
        assert result['frontend']['complete_verification_work_bound'] is None
        assert result['typed_decoders']['decoders']['registration']['exceptional_frontiers']
        assert all(r['machine_bytes'] == 4*r['instruction_count'] and len(r['machine_sha256']) == 64
                   for r in result['body_correspondence']['functions'])
    assert modules['frontend'].BODY_HASHES == before


def test_actual_source_drift_yields_retained_unknown(tmp_path, monkeypatch):
    target = ROOT/'crates/iroha_parliament_ballot_proof/src/test_codec.rs'
    original = Path.read_bytes
    # Alter only the bytes returned for the actual guarded source, without
    # modifying the shared checkout while another evidence lane is running.
    monkeypatch.setattr(Path, 'read_bytes', lambda self: original(self)+b'\n// drift\n' if self == target else original(self))
    result = check.run(ROOT, tmp_path/'failed')
    assert result['verdict'] == 'UNKNOWN'
    assert str(target) in result['failure']
    assert result['applies_to_guarded_current_candidate'] is False
    assert json.loads((tmp_path/'failed/report.json').read_text()) == result


def test_after_validation_drift_yields_unknown(tmp_path, monkeypatch):
    original = check.analyze_mode
    changed = False
    target = ROOT/'crates/iroha_parliament_ballot_proof/src/test_codec.rs'
    read_bytes = Path.read_bytes
    def analyze(*args):
        nonlocal changed
        value = original(*args)
        if args[0] == 'accel': changed = True
        return value
    monkeypatch.setattr(check, 'analyze_mode', analyze)
    monkeypatch.setattr(Path, 'read_bytes', lambda self: read_bytes(self)+b'drift' if changed and self == target else read_bytes(self))
    result = check.run(ROOT, tmp_path/'after-drift')
    assert result['verdict'] == 'UNKNOWN'
    assert str(target) in result['input_changes']
    assert result['applies_to_guarded_current_candidate'] is False


def test_successful_run_and_fresh_output_refusal(tmp_path):
    output = tmp_path/'success'
    result = check.run(ROOT, output)
    assert result['verdict'] == 'PASS_UNDER_STATED_PREMISES'
    assert result['input_changes'] == {}
    for flag in ('complete_workspace_certificate', 'complete_native_cost_certificate',
                 'complete_crypto_cost_certificate', 'physical_cost_calibrated', 'profile_qualified', 'production_gate_changed'):
        assert result[flag] is False
    with pytest.raises(FileExistsError): check.run(ROOT, output)
