"""Fatal-output regression evidence must preserve exact debit and source identity."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_parliament_ballot_fatal_output as check
import check_parliament_ballot_memory_entry as checker
from parliament_ballot_memory_entry_test import build_fixture


def observation():
    page = os.sysconf('SC_PAGESIZE')
    value = {'outcome': 'resource_exhausted', 'charged_units': 1, 'charged_bytes': 1,
             'fatal_control_reserved_bytes': page, 'arena_enforced': True,
             'complete_workspace_certificate': False, 'profile_qualified': False}
    result = subprocess.CompletedProcess(['worker'], 73, json.dumps(value), '')
    result.supervisor_evidence = {
        'raw_exit': 73, 'raw_stdout': '', 'raw_stderr': '', 'stdout_captured': False,
        'fatal_report_synthesized': True, 'read_after_child_exit': True, 'refund_permitted': False,
        'fatal_control': {'state': 3, 'charged_units': 1, 'charged_bytes': 1, 'reserved_bytes': page},
        'fatal_control_hex': (struct.pack('=4Q', 0x5041524C46415431, 3, 1, 1) + bytes(page - 32)).hex()}
    return result


def test_validation_requires_exact_debit_quiescent_page_and_parent_only_report():
    result = observation()
    page = os.sysconf('SC_PAGESIZE')
    assert check.validate(result, page, checker)['charged_units'] == 1
    for key, value in [('raw_exit', -6), ('raw_stdout', 'child output'), ('raw_stderr', 'error'),
                       ('stdout_captured', True), ('fatal_report_synthesized', False),
                       ('read_after_child_exit', False), ('refund_permitted', True),
                       ('timeout', True), ('failure', 'lost control')]:
        changed = copy.deepcopy(result)
        changed.supervisor_evidence[key] = value
        with pytest.raises(ValueError):
            check.validate(changed, page, checker)
    for replacement in ('00', (bytes(page)).hex(), result.supervisor_evidence['fatal_control_hex'][:-2] + '01'):
        changed = copy.deepcopy(result)
        changed.supervisor_evidence['fatal_control_hex'] = replacement
        with pytest.raises(ValueError):
            check.validate(changed, page, checker)
    for key, value in [('charged_units', True), ('charged_bytes', 2), ('profile_qualified', True),
                       ('charged_units', 1.0), ('arena_enforced', 1), ('profile_qualified', 0)]:
        changed = copy.deepcopy(result)
        report = json.loads(changed.stdout)
        report[key] = value
        changed.stdout = json.dumps(report)
        with pytest.raises(ValueError):
            check.validate(changed, page, checker)
    for key, value in [('state', 2), ('state', 3.0), ('charged_units', True), ('charged_bytes', 1.0)]:
        changed = copy.deepcopy(result)
        changed.supervisor_evidence['fatal_control'][key] = value
        with pytest.raises(ValueError):
            check.validate(changed, page, checker)
    for text in ('{"outcome":"resource_exhausted","outcome":"resource_exhausted"}',
                 '{"charged_units":NaN}', '{"charged_units":1e309}', '[]'):
        changed = copy.deepcopy(result)
        changed.stdout = text
        with pytest.raises(ValueError):
            check.validate(changed, page, checker)


def test_build_inputs_require_unchanged_sources_metadata_logs_and_both_binaries(tmp_path):
    receipt, binaries, path = build_fixture(tmp_path)
    guards, modes = check.guarded_build(path, tmp_path, checker)
    assert set(modes) == {'portable', 'accel'} and modes == binaries
    fatal = tmp_path / checker.PROBE / 'fatal.rs'
    assert str(fatal) in guards
    assert check.digest(fatal) == hashlib.sha256(b'reviewed source').hexdigest()
    files = [fatal, tmp_path / 'generated/fatal.rs', Path(receipt['dependency_metadata_path']),
             *binaries.values(), Path(receipt['commands'][0]['log'])]
    for file in files:
        before = file.read_bytes()
        file.write_bytes(b'changed')
        with pytest.raises(ValueError):
            check.guarded_build(path, tmp_path, checker)
        file.write_bytes(before)
    for field, value in [('source_stable', False), ('profile_qualified', True),
                          ('source_files', {}), ('commands', receipt['commands'][:-1]), ('binaries', {})]:
        changed = copy.deepcopy(receipt)
        changed[field] = value
        path.write_text(json.dumps(changed))
        with pytest.raises(ValueError):
            check.guarded_build(path, tmp_path, checker)
    changed = copy.deepcopy(receipt)
    changed['commands'][0]['exit'] = False
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        check.guarded_build(path, tmp_path, checker)


def test_duplicate_or_non_cargo_commands_and_missing_required_sources_are_rejected(tmp_path):
    receipt, _, path = build_fixture(tmp_path)
    changed = copy.deepcopy(receipt)
    changed['commands'] = [changed['commands'][0]] * 6
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match='both locked feature modes'):
        check.guarded_build(path, tmp_path, checker)
    changed = copy.deepcopy(receipt)
    for command in changed['commands']:
        command['command'][0] = 'not-cargo'
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match='both locked feature modes'):
        check.guarded_build(path, tmp_path, checker)
    for absent in (tmp_path / checker.PROBE / 'fatal.rs', tmp_path / 'generated/fatal.rs',
                   tmp_path / 'registry/package/src/lib.rs', tmp_path / checker.resource.FIXTURES / 'example.proof'):
        changed = copy.deepcopy(receipt)
        del changed['source_files'][str(absent)]
        path.write_text(json.dumps(changed))
        with pytest.raises(ValueError, match='omitted required'):
            check.guarded_build(path, tmp_path, checker)
    original = json.dumps(receipt)
    path.write_text(original.replace('"source_stable": true', '"source_stable": true, "source_stable": true'))
    with pytest.raises(ValueError, match='duplicate'):
        check.guarded_build(path, tmp_path, checker)


def test_missing_build_failure_is_durable_and_existing_output_is_refused(tmp_path):
    output = tmp_path / 'output'
    result = check.campaign(tmp_path, tmp_path / 'missing-receipt', output)
    assert not result['diagnostic_passed'] and result['observations'] == 0 and result['failure']
    assert json.loads((output / 'report.json').read_text()) == result
    assert (output / 'cases.jsonl').read_bytes() == b''
    assert (output / 'check_parliament_ballot_fatal_output.py.template').is_file()
    with pytest.raises(FileExistsError):
        check.campaign(tmp_path, tmp_path / 'missing-receipt', output)


def test_cli_requires_explicit_paths_and_returns_failure(tmp_path, capsys):
    with patch.object(sys, 'argv', ['fatal-output', '--help']):
        with pytest.raises(SystemExit) as exited:
            check.main()
        assert exited.value.code == 0 and '--build-receipt' in capsys.readouterr().out
    with patch.object(sys, 'argv', ['fatal-output', '--root', str(tmp_path),
                                  '--build-receipt', str(tmp_path / 'missing'),
                                  '--output', str(tmp_path / 'cli-output')]):
        assert check.main() == 1
        assert json.loads(capsys.readouterr().out)['diagnostic_passed'] is False
