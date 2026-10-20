#!/usr/bin/env python3
"""Exercise the candidate's canonical-input memory probe with retained raw evidence.

This is a finite engineering campaign. It neither authenticates chain history nor
certifies all native allocations, all possible inputs, or production qualification.
Build identity is supplied separately and checked against the copied executable.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import time

import parliament_ballot_memory_supervisor as supervisor

ENVELOPE_MAX, CONTEXT_MAX = 262144, 163840


def strict_json(text: str):
    """Reject duplicate fields and nonfinite values in evidence."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError('nonfinite JSON value: ' + value)

    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError('nonfinite JSON number')
        return result

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)


def digest(data: bytes) -> str:
    """Identify exact retained bytes."""
    return hashlib.sha256(data).hexdigest()


def save_json(path: Path, value) -> None:
    """Write a fresh evidence member, never replace a previous run."""
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


@dataclass(frozen=True)
class Case:
    """One independently supervised call and its expected accounting result."""
    name: str
    envelope: bytes | None
    context: bytes | None
    options: tuple[str, ...]
    code: int
    outcome: str
    stage: str | None

    @property
    def lengths(self) -> tuple[int, int]:
        return (ENVELOPE_MAX + 1 if self.envelope is None else len(self.envelope),
                CONTEXT_MAX + 1 if self.context is None else len(self.context))


def cases(envelope: bytes, context: bytes, variant: str, alternate_network: str) -> list[Case]:
    """Use genuine positive/late-invalid fixtures and independently bounded controls."""
    expected = (0, 'accepted', 'complete') if variant == 'valid' else (1, 'rejected', 'proof')
    result = [Case('original', envelope, context, (), *expected)]
    if variant != 'valid':
        return result
    result.extend([
        Case('no_work_budget', envelope, context, ('--units', '0'), 2, 'admission_rejected', 'work_budget'),
        Case('short_byte_budget', envelope, context,
             ('--input-bytes', str(len(envelope) + len(context) - 1)), 2, 'admission_rejected', 'byte_budget'),
        Case('empty_arena', envelope, context, ('--heap-limit', '0'), 73, 'resource_exhausted', None),
        Case('envelope_borrow_over_cap', None, context, (), 2, 'admission_rejected', 'envelope_size'),
        Case('context_borrow_over_cap', envelope, None, (), 2, 'admission_rejected', 'context_size'),
        Case('envelope_file_over_cap', bytes(ENVELOPE_MAX + 1), context, (), 3, 'input_error', 'staging_size'),
        Case('context_file_over_cap', envelope, bytes(CONTEXT_MAX + 1), (), 3, 'input_error', 'staging_size'),
        Case('empty_envelope', b'', context, (), 1, 'rejected', 'envelope_decode'),
        Case('truncated_envelope', envelope[:-1], context, (), 1, 'rejected', 'envelope_decode'),
        Case('trailing_envelope', envelope + b'\0', context, (), 1, 'rejected', 'envelope_decode'),
        Case('maximum_zero_envelope', bytes(ENVELOPE_MAX), context, (), 1, 'rejected', 'envelope_decode'),
        Case('empty_context', envelope, b'', (), 4, 'worker_error', 'context_decode'),
        Case('truncated_context', envelope, context[:-1], (), 4, 'worker_error', 'context_decode'),
        Case('trailing_context', envelope, context + b'\0', (), 4, 'worker_error', 'context_decode'),
        Case('maximum_zero_context', envelope, bytes(CONTEXT_MAX), (), 4, 'worker_error', 'context_decode'),
        Case('wrong_trusted_network', envelope, context, ('--network', alternate_network),
             4, 'worker_error', 'context_network'),
        Case('wrong_trusted_body', envelope, context, ('--body', '04' * 32),
             1, 'rejected', 'envelope_scope'),
    ])
    return result


def validate_fixture(manifest: dict, envelope: bytes, context: bytes) -> None:
    """Require public, correctly sized genuine fixture metadata; results are checked later."""
    if (manifest.get('public_fixture_only') is not True
            or manifest.get('status') != 'complete'
            or manifest.get('profile_qualified') is not False
            or manifest.get('variant') not in ('valid', 'late-invalid')
            or type(manifest.get('seats')) is not int or manifest['seats'] not in (3, 500, 1000)
            or manifest.get('body_instance_id') != '03' * 32
            or not isinstance(manifest.get('network_id'), str)
            or not isinstance(manifest.get('alternate_network_id'), str)
            or manifest['network_id'] == manifest['alternate_network_id']):
        raise ValueError('fixture metadata does not identify the public candidate fixture')
    if not (0 < len(envelope) <= ENVELOPE_MAX and 0 < len(context) <= CONTEXT_MAX):
        raise ValueError('fixture inputs exceed their separate caps or are empty')
    for key, length in (('envelope_bytes', len(envelope)), ('context_bytes', len(context))):
        if type(manifest.get(key)) is not int or manifest[key] != length:
            raise ValueError('fixture length metadata differs from retained bytes')
    if (type(manifest.get('stamp_difficulty_bits')) is not int or manifest['stamp_difficulty_bits'] != 28
            or type(manifest.get('stamp_work_bits')) is not int or not 28 <= manifest['stamp_work_bits'] <= 512):
        raise ValueError('fixture does not use the actual standard-tier stamp difficulty')
    if any(manifest.get(key) is not True for key in
           ('stamp_verified', 'honest_proof_verified', 'canonical_envelope_roundtrip_checked')):
        raise ValueError('fixture generation did not finish its cryptographic checks')
    expected = 'Ok(())' if manifest['variant'] == 'valid' else 'BallotProofErrorV1::Rejected'
    if manifest.get('typed_verifier_result') != expected:
        raise ValueError('fixture proof result differs')
    if manifest['variant'] == 'late-invalid' and manifest.get('observed_backend_stage') != 'ProofError::ChallengeMismatch':
        raise ValueError('late-invalid fixture did not reach the recorded backend stage')


def validate(case: Case, result) -> dict:
    """Check raw fatal evidence, exit, full debit, arena partition and limited claims."""
    evidence = result.supervisor_evidence
    if (result.returncode != case.code or evidence.get('raw_exit') != case.code
            or evidence.get('failure') or evidence.get('timeout')
            or result.stderr or evidence.get('raw_stderr')
            or evidence.get('stdout_captured') is not True
            or evidence.get('read_after_child_exit') is not True
            or evidence.get('refund_permitted') is not False):
        raise ValueError('child exit, exclusive output or supervisor evidence differs')
    report = strict_json(result.stdout)
    if not isinstance(report, dict) or report.get('outcome') != case.outcome:
        raise ValueError('unexpected outcome')
    slot = supervisor.decode_slot(bytes.fromhex(evidence['fatal_control_hex']), sum(case.lengths))
    charged = case.code not in (2, 3)
    expected_debit = (1, sum(case.lengths)) if charged else (0, 0)
    expected_state = supervisor.EXHAUSTED if case.code == 73 else (
        supervisor.ADMITTED if charged else supervisor.SETUP)
    if slot['state'] != expected_state:
        raise ValueError('shared accounting state differs')
    for key, value in zip(('charged_units', 'charged_bytes'), expected_debit):
        if type(report.get(key)) is not int or report[key] != value or slot[key] != value:
            raise ValueError('actual-input reservation differs')
    for key in ('complete_workspace_certificate', 'profile_qualified'):
        if report.get(key) is not False:
            raise ValueError('diagnostic claims qualification')
    if case.code == 73:
        if (evidence.get('raw_stdout') or evidence.get('fatal_report_synthesized') is not True
                or report.get('arena_enforced') is not True):
            raise ValueError('resource failure did not use the exclusive fatal channel')
        return report
    if result.stdout != evidence.get('raw_stdout'):
        raise ValueError('ordinary report differs from exact child output')
    if (report.get('validity_only') is not True or report.get('protocol_effect') is not False
            or report.get('verifier_stage') != case.stage
            or evidence.get('fatal_report_synthesized') is not False):
        raise ValueError('validity scope or rejection stage differs')
    if case.code == 3:
        if report.get('arena_enforced') is not False or report.get('arena_allocations') != 0:
            raise ValueError('retrieval failure entered the worker arena')
        return report
    if report.get('arena_enforced') is not True or report.get('acceleration_identity_external') is not True:
        raise ValueError('arena/mode reporting differs')
    if (any(type(report.get(key)) is not int for key in ('envelope_bytes', 'context_bytes'))
            or (report['envelope_bytes'], report['context_bytes']) != case.lengths):
        raise ValueError('worker input lengths differ')
    page = os.sysconf('SC_PAGESIZE')
    partition = {'heap_reserved_bytes': 32 << 20, 'metadata_reserved_bytes': 1 << 20,
                 'stack_usable_bytes': 8 << 20, 'guard_bytes': 2 * page,
                 'control_reserved_bytes': 64 << 10, 'fatal_control_reserved_bytes': page}
    for key, value in partition.items():
        if type(report.get(key)) is not int or report[key] != value:
            raise ValueError('workspace partition differs: ' + key)
    if (type(report.get('workspace_reserved_bytes')) is not int
            or report['workspace_reserved_bytes'] != sum(partition.values())):
        raise ValueError('workspace reservation sum differs')
    names = ('heap_limit_bytes', 'arena_peak_block_bytes', 'arena_peak_requested_bytes',
             'arena_live_exit_block_bytes', 'arena_live_exit_requested_bytes', 'arena_allocations')
    if any(type(report.get(key)) is not int or report[key] < 0 for key in names):
        raise ValueError('invalid arena counters')
    if not (report['arena_peak_requested_bytes'] <= report['arena_peak_block_bytes']
            <= report['heap_limit_bytes'] <= partition['heap_reserved_bytes']):
        raise ValueError('arena peak exceeds reservation')
    configured = dict(zip(case.options[::2], case.options[1::2]))
    if report['heap_limit_bytes'] != int(configured.get('--heap-limit', 32 << 20)):
        raise ValueError('reported arena limit differs from invocation')
    if report['arena_live_exit_block_bytes'] or report['arena_live_exit_requested_bytes']:
        raise ValueError('arena-owned values escaped the charged interval')
    if charged and (report['arena_peak_requested_bytes'] < sum(case.lengths)
                    or report['arena_allocations'] < sum(length > 0 for length in case.lengths)):
        raise ValueError('owned canonical input copies are missing from arena counters')
    if not charged and (report['arena_allocations'] or report['arena_peak_block_bytes']):
        raise ValueError('failed reservation copied or allocated')
    return report


def run_case(worker: Path, root: Path, case: Case, manifest: dict, timeout: float) -> dict:
    """Retain exact inputs and both raw and interpreted child evidence for one call."""
    root.mkdir()
    positional = []
    for name, content in (('envelope', case.envelope), ('context', case.context)):
        if content is None:
            positional.append('--borrowed-oversize')
        else:
            path = root / (name + '.norito')
            path.write_bytes(content)
            positional.append(str(path))
    options = {'--network': manifest['network_id'], '--body': manifest['body_instance_id']}
    options.update(zip(case.options[::2], case.options[1::2]))
    command = [str(worker), *positional, *(part for pair in options.items() for part in pair)]
    save_json(root / 'invocation.json', {'command': command, 'input_lengths': case.lengths,
              'expected_exit': case.code, 'expected_outcome': case.outcome, 'expected_stage': case.stage})
    started = time.monotonic()
    result = supervisor.run(command, input_bytes=sum(case.lengths), timeout=timeout)
    save_json(root / 'raw.json', result.supervisor_evidence)
    (root / 'stdout.txt').write_text(result.stdout)
    (root / 'stderr.txt').write_text(result.stderr)
    verdict = {'case': case.name, 'elapsed_seconds': time.monotonic() - started,
               'returncode': result.returncode, 'pass': False}
    try:
        verdict['report'] = validate(case, result)
        verdict['pass'] = True
    except (ValueError, KeyError, TypeError) as error:
        verdict['failure'] = str(error)
    save_json(root / 'result.json', verdict)
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0 or not args.timeout < float('inf'):
        parser.error('timeout must be finite and positive')
    build_bytes = args.build_record.read_bytes()
    build = strict_json(build_bytes.decode())
    worker_bytes = args.worker.read_bytes()
    if build.get('worker_sha256') != digest(worker_bytes) or build.get('mode') not in ('portable', 'accel'):
        parser.error('build record must identify the supplied executable and selected build mode')
    args.output.mkdir(parents=True, exist_ok=False)
    root = args.output.resolve()
    (root / 'build-record.json').write_bytes(build_bytes)
    worker = root / 'canonical_resource_probe'
    worker.write_bytes(worker_bytes)
    worker.chmod(0o700)
    for script in (Path(__file__), Path(supervisor.__file__)):
        shutil.copyfile(script, root / script.name)
    verdicts, fixture_ids = [], set()
    for source in args.fixture:
        manifest_bytes = (source / 'manifest.json').read_bytes()
        manifest = strict_json(manifest_bytes.decode())
        envelope, context = ((source / name).read_bytes() for name in ('envelope.norito', 'context.norito'))
        validate_fixture(manifest, envelope, context)
        fixture_id = f"s{manifest['seats']}-{manifest['variant']}"
        if fixture_id in fixture_ids:
            raise ValueError('duplicate fixture: ' + fixture_id)
        fixture_ids.add(fixture_id)
        fixture_root = root / fixture_id
        fixture_root.mkdir()
        (fixture_root / 'manifest.json').write_bytes(manifest_bytes)
        for case in cases(envelope, context, manifest['variant'], manifest['alternate_network_id']):
            verdict = run_case(worker, fixture_root / case.name, case, manifest, args.timeout)
            verdicts.append({'fixture': fixture_id, **verdict})
            print(f"{fixture_id}/{case.name}: {'pass' if verdict['pass'] else 'FAIL'}", flush=True)
    binary_stable = digest(worker.read_bytes()) == build['worker_sha256']
    complete = fixture_ids == {'s3-valid', 's500-valid', 's1000-valid', 's1000-late-invalid'}
    supplied_pass = binary_stable and all(verdict['pass'] for verdict in verdicts)
    passed = supplied_pass and complete
    save_json(root / 'summary.json', {'schema': 'parliament-canonical-resource-campaign-v1',
              'pass': passed, 'worker_sha256': build['worker_sha256'], 'worker_unchanged': binary_stable,
              'build_mode_label': build['mode'], 'observations': len(verdicts), 'cases': verdicts,
              'supplied_cases_pass': supplied_pass, 'complete_required_fixture_set': complete,
              'validity_only': True, 'protocol_effect': False, 'chain_history_authenticated': False,
              'all_inputs_covered': False, 'all_native_allocations_covered': False,
              'complete_workspace_certificate': False, 'profile_qualified': False})
    members = sorted(path for path in root.rglob('*') if path.is_file())
    (root / 'SHA256SUMS').write_text(''.join(f'{digest(path.read_bytes())}  {path.relative_to(root)}\n' for path in members))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
