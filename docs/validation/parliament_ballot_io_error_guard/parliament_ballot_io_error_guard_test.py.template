"""Fail-closed checks for the frozen I/O error destructor's local tag guard."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

PATH = Path(__file__).resolve().parents[1] / 'parliament_ballot_io_error_guard.py'
SPEC = importlib.util.spec_from_file_location('parliament_io_error_guard', PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(mode='portable'):
    """Use actual frozen entry instructions, selecting the retained frontier."""
    boundary = json.loads((M.ROOT / M.FRONTIERS / 'report.json').read_text())
    site = next(f for f in boundary['modes'][mode]['conditional_boundary_roots']['worker']['frontiers'] if f['kind'] == 'indirect_call')
    stack = json.loads((M.ROOT / M.STACK / (mode + '.json')).read_text())
    function = next(f for f in stack['functions'] if f['name'] == site['function'])
    analyzer = M.load_template(M.ROOT / M.STACK / 'parliament_ballot_stack_audit.py.template')
    instructions, _ = analyzer.parse_disassembly((M.ROOT / M.STACK / mode / 'disassembly.txt').read_text())
    return function, instructions


@pytest.mark.parametrize('mode', ['portable', 'accel'])
def test_actual_paths(mode):
    function, instructions = fixture(mode)
    result = M.check_guard(function, instructions)
    assert result['tag_partition'] == [{'tag': t, 'enters_custom_body': t == 1} for t in range(4)]
    assert result['unconditional_site_unreachable'] is False
    assert result['non_custom_local_sp_bytes'] == 80


@pytest.mark.parametrize('offset', range(0, 56, 4))
def test_every_entry_instruction_is_required(offset):
    function, instructions = fixture()
    instructions[int(function['address'], 16) + offset] = ('nop', '')
    with pytest.raises(ValueError, match='changed io::Error guard'):
        M.check_guard(function, instructions)


@pytest.mark.parametrize('args', ['0x10000165c', '0x100001670garbage', 'x8'])
def test_branch_target_is_literal_and_exact(args):
    function, instructions = fixture()
    instructions[int(function['address'], 16) + 32] = ('b.eq', args)
    with pytest.raises(ValueError):
        M.check_guard(function, instructions)


def test_indirect_site_cannot_disappear_or_change_register():
    function, instructions = fixture()
    changed = copy.deepcopy(function)
    changed['gaps'] = []
    with pytest.raises(ValueError, match='indirect site'):
        M.check_guard(changed, instructions)
    instructions[int(function['address'], 16) + 0x4c] = ('blr', 'x9')
    with pytest.raises(ValueError, match='indirect site'):
        M.check_guard(function, instructions)


def test_source_change_fails_before_retaining_a_snapshot(tmp_path):
    relative = next(iter(M.RANGES))
    path = tmp_path / (relative + '.html')
    path.parent.mkdir(parents=True)
    path.write_text('changed source')
    class Extractor:
        @staticmethod
        def rustdoc_source(text):
            return text
    with pytest.raises(ValueError, match='installed source differs'):
        M.source_evidence(tmp_path, {'external_sources': []}, Extractor, tmp_path, {})


@pytest.mark.parametrize('commit,matched', [('other', True), (M.COMMIT, False)])
def test_source_provenance_cannot_be_relabelled(tmp_path, commit, matched):
    audit = {'external_sources': [{'kind': 'rust', 'commit': commit, 'upstream_matches_installed_code': matched}]}
    with pytest.raises(ValueError, match='commit/correspondence'):
        M.source_evidence(tmp_path, audit, None, tmp_path, {})


def test_missing_evidence_is_unknown_and_never_qualified(tmp_path):
    output = tmp_path / 'result'
    report = M.run(tmp_path / 'missing', output, tmp_path)
    assert report['status'] == 'UNKNOWN'
    assert report['profile_qualified'] is False
    assert report['whole_worker_variant_flow_proved'] is False
    assert report['complete_stack_bound_bytes'] is None
    assert json.loads((output / 'report.json').read_text())['failure']
    with pytest.raises(FileExistsError):
        M.run(tmp_path, output, tmp_path)


def test_hash_and_template_loader(tmp_path):
    path = tmp_path / 'module.template'
    path.write_bytes(b'VALUE = 17\n')
    assert M.sha(path) == hashlib.sha256(path.read_bytes()).hexdigest()
    assert M.load_template(path).VALUE == 17


@pytest.mark.parametrize('status,qualified,expected', [('UNKNOWN', False, 1), ('LOCAL_GUARDS_PASS_SOURCE_LEMMA_CONDITIONAL', False, 0), ('LOCAL_GUARDS_PASS_SOURCE_LEMMA_CONDITIONAL', True, 2)])
def test_cli_never_promotes_to_qualification(tmp_path, status, qualified, expected):
    argv = ['guard', '--output', str(tmp_path / 'new')]
    if qualified:
        argv += ['--require-qualified']
    with patch.object(sys, 'argv', argv), patch.object(M, 'run', return_value={'status': status, 'profile_qualified': False}):
        assert M.main() == expected
