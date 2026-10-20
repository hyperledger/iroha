"""Reject contradictory canonical-worker evidence without inferring qualification."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_parliament_ballot_canonical_resources as campaign
import parliament_ballot_memory_supervisor as supervisor


def fixture():
    return {'seats': 3, 'variant': 'valid', 'network_id': 'network',
            'status': 'complete', 'stamp_verified': True, 'honest_proof_verified': True,
            'canonical_envelope_roundtrip_checked': True, 'typed_verifier_result': 'Ok(())',
            'alternate_network_id': 'other', 'body_instance_id': '03' * 32,
            'public_fixture_only': True, 'profile_qualified': False,
            'envelope_bytes': 3, 'context_bytes': 4, 'stamp_difficulty_bits': 28, 'stamp_work_bits': 29}


def case(name='original'):
    return next(value for value in campaign.cases(b'abc', b'defg', 'valid', 'other') if value.name == name)


def observed(value, changes=None):
    charged = value.code not in (2, 3)
    units, size = (1, sum(value.lengths)) if charged else (0, 0)
    state = supervisor.EXHAUSTED if value.code == 73 else (supervisor.ADMITTED if charged else supervisor.SETUP)
    page = os.sysconf('SC_PAGESIZE')
    raw = struct.pack('=4Q', supervisor.MAGIC, state, units, size) + bytes(page - 32)
    report = {'outcome': value.outcome, 'verifier_stage': value.stage,
              'charged_units': units, 'charged_bytes': size,
              'envelope_bytes': value.lengths[0], 'context_bytes': value.lengths[1],
              'heap_reserved_bytes': 32 << 20, 'metadata_reserved_bytes': 1 << 20,
              'stack_usable_bytes': 8 << 20, 'guard_bytes': 2 * page,
              'control_reserved_bytes': 64 << 10, 'fatal_control_reserved_bytes': page,
              'workspace_reserved_bytes': (41 << 20) + (64 << 10) + 3 * page,
              'heap_limit_bytes': 32 << 20, 'arena_peak_block_bytes': size + 128 if charged else 0,
              'arena_peak_requested_bytes': size + 99 if charged else 0,
              'arena_live_exit_block_bytes': 0, 'arena_live_exit_requested_bytes': 0,
              'arena_allocations': 2 if charged else 0, 'arena_enforced': value.code != 3,
              'validity_only': True, 'protocol_effect': False, 'acceleration_identity_external': True,
              'complete_workspace_certificate': False, 'profile_qualified': False}
    report.update(changes or {})
    output = '' if value.code == 73 else json.dumps(report)
    return supervisor.finish(subprocess.CompletedProcess(['worker'], value.code, output, ''), raw, sum(value.lengths))


def test_strict_evidence_parser_and_fresh_writes(tmp_path):
    for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'):
        with pytest.raises(ValueError):
            campaign.strict_json(text)
    path = tmp_path / 'record.json'
    campaign.save_json(path, {'x': 1})
    assert campaign.strict_json(path.read_text()) == {'x': 1}
    with pytest.raises(FileExistsError):
        campaign.save_json(path, {'x': 2})
    assert campaign.digest(b'abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def test_fixture_identity_and_full_standard_stamp_required():
    campaign.validate_fixture(fixture(), b'abc', b'defg')
    for changes in ({'seats': True}, {'seats': 4}, {'variant': 'dummy'}, {'stamp_difficulty_bits': 1},
                    {'stamp_work_bits': 27}, {'stamp_work_bits': True},
                    {'stamp_work_bits': 513}, {'status': 'mining'}, {'stamp_verified': False},
                    {'typed_verifier_result': 'rejected'},
                    {'profile_qualified': True}, {'body_instance_id': '04' * 32},
                    {'envelope_bytes': 2}, {'context_bytes': 5}, {'alternate_network_id': 'network'}):
        with pytest.raises(ValueError):
            campaign.validate_fixture({**fixture(), **changes}, b'abc', b'defg')
    with pytest.raises(ValueError):
        campaign.validate_fixture(fixture(), bytes(campaign.ENVELOPE_MAX + 1), b'defg')
    late = {**fixture(), 'variant': 'late-invalid', 'typed_verifier_result': 'BallotProofErrorV1::Rejected',
            'observed_backend_stage': 'ProofError::ChallengeMismatch'}
    campaign.validate_fixture(late, b'abc', b'defg')
    with pytest.raises(ValueError):
        campaign.validate_fixture({**late, 'observed_backend_stage': None}, b'abc', b'defg')


def test_controls_preserve_distinct_bounds_and_failure_meanings():
    values = campaign.cases(b'abc', b'defg', 'valid', 'other')
    assert len(values) == len({value.name for value in values}) == 18
    assert case('envelope_borrow_over_cap').lengths == (campaign.ENVELOPE_MAX + 1, 4)
    assert case('context_borrow_over_cap').lengths == (3, campaign.CONTEXT_MAX + 1)
    assert case('empty_context').code == 4
    assert case('empty_envelope').code == 1
    late = campaign.cases(b'abc', b'defg', 'late-invalid', 'other')
    assert len(late) == 1 and late[0].code == 1 and late[0].stage == 'proof'


@pytest.mark.parametrize('name', [value.name for value in campaign.cases(b'abc', b'defg', 'valid', 'other')])
def test_expected_reports_and_fatal_results(name):
    value = case(name)
    assert campaign.validate(value, observed(value))['outcome'] == value.outcome


@pytest.mark.parametrize('changes', [
    {'charged_units': 0}, {'charged_bytes': 6}, {'profile_qualified': True},
    {'complete_workspace_certificate': True}, {'validity_only': False},
    {'protocol_effect': True}, {'verifier_stage': 'wrong'}, {'envelope_bytes': 4},
    {'heap_reserved_bytes': 1}, {'workspace_reserved_bytes': 0},
    {'arena_peak_requested_bytes': 136}, {'heap_limit_bytes': 127},
    {'arena_peak_requested_bytes': 0}, {'arena_allocations': 0},
    {'arena_live_exit_block_bytes': 1}, {'arena_live_exit_requested_bytes': 1},
    {'arena_allocations': True}, {'arena_enforced': False},
])
def test_contradictory_report_is_refused(changes):
    value = case()
    with pytest.raises(ValueError):
        campaign.validate(value, observed(value, changes))


def test_code_four_requires_exact_charged_failure_evidence():
    value = case('empty_context')
    for changes in ({'charged_units': 0}, {'charged_bytes': 0}, {'outcome': 'rejected'}):
        with pytest.raises(ValueError):
            campaign.validate(value, observed(value, changes))
    result = observed(value)
    result.supervisor_evidence['raw_exit'] = 0
    with pytest.raises(ValueError):
        campaign.validate(value, result)
    result = observed(value)
    result.supervisor_evidence['raw_stdout'] += ' '
    with pytest.raises(ValueError):
        campaign.validate(value, result)


def test_pre_admission_cannot_allocate_or_claim_fatal_success():
    value = case('no_work_budget')
    with pytest.raises(ValueError):
        campaign.validate(value, observed(value, {'arena_allocations': 1}))
    value = case('empty_arena')
    for key, replacement in [('fatal_report_synthesized', False), ('raw_stdout', 'unowned'),
                             ('timeout', True), ('read_after_child_exit', False)]:
        result = observed(value)
        result.supervisor_evidence[key] = replacement
        with pytest.raises(ValueError):
            campaign.validate(value, result)


def test_run_case_retains_raw_failures_and_passes_actual_lengths(tmp_path):
    value = case()
    result = observed(value, {'charged_bytes': 0})
    with patch.object(supervisor, 'run', return_value=result) as run:
        verdict = campaign.run_case(Path('/worker'), tmp_path / 'case', value, fixture(), 2)
    assert not verdict['pass']
    assert run.call_args.kwargs['input_bytes'] == 7
    assert (tmp_path / 'case/envelope.norito').read_bytes() == b'abc'
    assert campaign.strict_json((tmp_path / 'case/raw.json').read_text())['raw_exit'] == 0
    assert campaign.strict_json((tmp_path / 'case/invocation.json').read_text())['input_lengths'] == [3, 4]
    with pytest.raises(FileExistsError):
        campaign.run_case(Path('/worker'), tmp_path / 'case', value, fixture(), 2)
