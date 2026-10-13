#!/usr/bin/env python3
"""Check the separately built bounded in-memory ballot entry in both modes.

Requires Python 3.11+, explicit native binaries and their source-stable release
build receipt. Uses existing public fixtures; no network/device/production writes.
Only a NEW output directory is written. Retrieval refusals are outside the
worker, distinct from charged codec/proof rejection. Finite evidence never
qualifies the complete resource service. Inherited loader injection is refused.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile

import check_parliament_ballot_resource_contract as resource
import parliament_ballot_memory_supervisor as supervisor

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path("crates/iroha_parliament_ballot_proof/examples/memory_entry")
RESOURCE = Path("crates/iroha_parliament_ballot_proof/examples/resource_contract")
HEX = re.compile(r"[0-9a-f]{64}")
EXPECTED_CASES = 61


def digest(path):
    """Hash evidence bytes without trusting a path or timestamp."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def object_json(text):
    """Accept exactly one JSON object with unique keys and finite numbers."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError("nonfinite JSON value: " + value)
    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            nonfinite(text)
        return value
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def validate_build(receipt: dict, binaries: dict, root: Path) -> dict[str, str]:
    """Derive required local-source scope from retained Cargo metadata and bind bytes."""
    if (receipt.get("schema") != "parliament-memory-entry-build-v1" or receipt.get("source_stable") is not True
            or receipt.get("failure") is not None
            or receipt.get("profile_qualified") is not False or receipt.get("complete_workspace_certificate") is not False):
        raise ValueError("diagnostic build receipt is not a stable unqualified build")
    sources = receipt.get("source_files")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("build source inventory missing")
    for name, expected in sources.items():
        if not isinstance(name, str) or not Path(name).is_absolute() or not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise ValueError("build source inventory must use absolute paths and SHA256")
        if digest(Path(name)) != expected:
            raise ValueError(f"compiled source changed: {name}")
    metadata_path = Path(receipt["dependency_metadata_path"])
    if not metadata_path.is_absolute() or digest(metadata_path) != receipt.get("dependency_metadata_sha256"):
        raise ValueError("Cargo metadata binding missing")
    metadata = object_json(metadata_path.read_text())
    packages = metadata.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo metadata package inventory missing")
    required = {root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")}
    required.update(root / PROBE / name for name in ("driver.rs", "staging.rs", "fatal.rs"))
    required.update((root / "crates/iroha_parliament_ballot_proof/tests/common").glob("*.rs"))
    for extension in ("*.proof", "*.txt"):
        required.update((root / resource.FIXTURES).glob(extension))
    required.add(root / "scripts/prepare_parliament_ballot_memory_entry.py")
    required.update(root / RESOURCE / f"{name}.rs" for name in ("arena", "budget", "native", "workspace"))
    generated = Path(receipt["generated_dir"])
    if not generated.is_absolute():
        raise ValueError("generated directory must be absolute")
    required.update(generated / name for name in ("driver.rs", "staging.rs", "fatal.rs", "generated_workspace.rs"))
    required.update(generated / name for name in ("Cargo.toml", "Cargo.lock", "preparation.json"))
    for package in packages:
        if not isinstance(package, dict) or "source" not in package:
            raise ValueError("malformed Cargo metadata package")
        manifest = Path(package["manifest_path"])
        if not manifest.is_absolute():
            raise ValueError("package manifest path is not absolute")
        required.add(manifest)
        required.update((manifest.parent / "src").rglob("*.rs"))
        for filename in ("build.rs", ".cargo-checksum.json"):
            if (manifest.parent / filename).exists():
                required.add(manifest.parent / filename)
    if not {str(path.resolve()) for path in required}.issubset({str(Path(path).resolve()) for path in sources}):
        raise ValueError("build omitted required reviewed local dependency/adapter sources")
    for mode, path in binaries.items():
        entry = receipt["binaries"][mode]
        if Path(entry["path"]).resolve() != path.resolve() or entry["sha256"] != digest(path):
            raise ValueError("binary does not match diagnostic build receipt")
    commands = receipt.get("commands")
    if (not isinstance(commands, list) or not commands
            or any(not isinstance(c, dict) or type(c.get("exit")) is not int
                   or c["exit"] != 0 or c.get("source_changes") != {} for c in commands)):
        raise ValueError("build command failure/source drift")
    logs = {}
    for command in commands:
        log = Path(command["log"])
        if not log.is_absolute() or digest(log) != command.get("log_sha256"):
            raise ValueError("build log binding changed")
        logs[str(log)] = digest(log)
    for accelerated in (False, True):
        for action in ("test", "clippy", "build"):
            found = False
            for entry in commands:
                command = entry.get("command")
                if (not isinstance(command, list) or any(not isinstance(arg, str) for arg in command)
                        or len(command) < 2 or Path(command[0]).name != "cargo" or command[1] != action):
                    continue
                split = command.index("--") if "--" in command else len(command)
                tail = command[split + 1:]
                if ((action == "clippy" and tail != ["-D", "warnings"])
                        or (action == "test" and tail not in ([], ["--nocapture"]))
                        or (action == "build" and split != len(command))):
                    continue
                options, index, valid = {}, 2, True
                while index < split:
                    key = command[index]
                    if key in options:
                        valid = False
                        break
                    if key in {"--release", "--locked", "--all-targets"}:
                        options[key] = True
                    elif key in {"--manifest-path", "--target-dir", "--features"} and index + 1 < split:
                        index += 1
                        options[key] = command[index]
                    else:
                        valid = False
                        break
                    index += 1
                if not valid or options.get("--release") is not True or options.get("--locked") is not True:
                    continue
                if (not isinstance(options.get("--manifest-path"), str)
                        or Path(options["--manifest-path"]).resolve() != (generated / "Cargo.toml").resolve()):
                    continue
                if options.get("--features") != ("accel" if accelerated else None):
                    continue
                if action == "clippy" and options.get("--all-targets") is not True:
                    continue
                found = True
            if not found:
                raise ValueError("both locked feature modes require generated-manifest cargo tests, strict all-target clippy and release builds")
    return {**sources, **logs, str(metadata_path): digest(metadata_path)}


def cases(root):
    """Keep the 60 fixture-backed controls plus independent borrowed admission."""
    yield from resource.cases(root)
    yield {"fixture": None, "row": "candidate", "role": "registration", "seats": 0,
           "case": "borrowed_oversized_input", "input": bytes(resource.MAX_INPUT_BYTES + 1),
           "borrowed_oversize": True, "flags": ["--input-bytes", str(resource.MAX_INPUT_BYTES + 1)],
           "expected_outcome": "admission_rejected", "expected_exit": 2, "expected_charge": 0}


def validate_case(case, result, mode):
    """Check staging exclusions or exact worker outcome, debit and containment."""
    if mode not in {'portable', 'accel'} or type(result.returncode) is not int:
        raise ValueError('invalid mode or exit status')
    if result.stderr.strip():
        raise ValueError('unexpected worker stderr')
    value = object_json(result.stdout)
    for key in ('charged_units', 'charged_bytes'):
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError('noninteger debit')
    if (value.get('profile_qualified') is not False or value.get('complete_workspace_certificate') is not False
            or result.returncode != case['expected_exit'] or value.get('outcome') != case['expected_outcome']):
        raise ValueError('outcome/exit/qualification differs')
    if (value['charged_units'] != case['expected_charge']
            or value['charged_bytes'] != (len(case['input']) if case['expected_charge'] else 0)):
        raise ValueError('debit differs from exact admitted input')
    if case['case'] in {'fifo_input', 'oversized_input'}:
        fields = {'outcome', 'verifier_stage', 'charged_units', 'charged_bytes',
                  'arena_allocations', 'arena_enforced', 'profile_qualified', 'complete_workspace_certificate'}
        if set(value) != fields:
            raise ValueError('unexpected staging report fields')
        if (value['charged_units'] or value['charged_bytes'] or type(value.get('arena_allocations')) is not int
                or value['arena_allocations'] != 0 or value.get('arena_enforced') is not False):
            raise ValueError('retrieval refusal spent a verification charge')
        expected = 'staging_size' if case['case'] == 'oversized_input' else 'staging_not_regular'
        if value.get('verifier_stage') != expected:
            raise ValueError('retrieval refusal did not occur before worker entry')
        return value
    if value.get('arena_enforced') is not True:
        raise ValueError('worker arena not enforced')
    if result.returncode == 73:
        fields = {'outcome', 'charged_units', 'charged_bytes', 'arena_enforced',
                  'profile_qualified', 'complete_workspace_certificate', 'fatal_control_reserved_bytes'}
        if set(value) != fields:
            raise ValueError('unexpected terminal resource report fields')
        if type(value['fatal_control_reserved_bytes']) is not int or value['fatal_control_reserved_bytes'] != os.sysconf('SC_PAGESIZE'):
            raise ValueError('fatal control reservation differs')
        return value
    if value.get('accelerated') is not (mode == 'accel'):
        raise ValueError('worker feature identity differs')
    fixed = {'heap_reserved_bytes': 32 * 1024 * 1024,
             'metadata_reserved_bytes': 1024 * 1024, 'stack_usable_bytes': 8 * 1024 * 1024,
             'control_reserved_bytes': 64 * 1024, 'guard_bytes': 2 * os.sysconf('SC_PAGESIZE'),
             'fatal_control_reserved_bytes': os.sysconf('SC_PAGESIZE')}
    numeric = set(fixed) | {'workspace_reserved_bytes', 'heap_limit_bytes', 'arena_allocations',
                           'arena_peak_requested_bytes', 'arena_peak_block_bytes',
                           'arena_live_exit_requested_bytes', 'arena_live_exit_block_bytes'}
    fields = numeric | {'accelerated', 'outcome', 'verifier_stage', 'charged_units', 'charged_bytes',
                        'arena_enforced', 'complete_workspace_certificate', 'profile_qualified'}
    if set(value) != fields:
        raise ValueError('unexpected worker report fields')
    for key in numeric:
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError('invalid worker counter: ' + key)
    if (any(value[key] != expected for key, expected in fixed.items())
            or value['workspace_reserved_bytes'] != sum(fixed.values())
            or value['workspace_reserved_bytes'] > resource.WORKSPACE_LIMIT
            or value['heap_limit_bytes'] != fixed['heap_reserved_bytes']):
        raise ValueError('worker mapping differs from fixed partition')
    if not 0 <= value['arena_peak_requested_bytes'] <= value['arena_peak_block_bytes'] <= value['heap_limit_bytes']:
        raise ValueError('worker peaks exceed heap limit')
    if value['arena_live_exit_requested_bytes'] or value['arena_live_exit_block_bytes']:
        raise ValueError('worker-owned allocation survived cleanup')
    stage = ('reserve' if result.returncode == 2 else 'complete' if result.returncode == 0
             else 'proof' if case['case'] == 'late_invalid_coefficient' else 'codec')
    if value.get('verifier_stage') != stage:
        raise ValueError('worker verifier stage differs')
    if result.returncode == 2 and any(value[key] for key in (
            'arena_allocations', 'arena_peak_requested_bytes', 'arena_peak_block_bytes')):
        raise ValueError('admission refusal copied or allocated caller bytes')
    return value



def validate_supervisor(value, result):
    """Bind observed debits to the post-exit shared slot, including normal paths."""
    evidence = getattr(result, 'supervisor_evidence', None)
    if (not isinstance(evidence, dict) or evidence.get('read_after_child_exit') is not True
            or evidence.get('refund_permitted') is not False or evidence.get('failure')
            or evidence.get('timeout') or type(evidence.get('raw_exit')) is not int
            or evidence['raw_exit'] != result.returncode):
        raise ValueError('missing or unsuccessful supervisor evidence')
    slot = evidence.get('fatal_control')
    expected = supervisor.EXHAUSTED if result.returncode == 73 else (supervisor.ADMITTED if value['charged_units'] else supervisor.SETUP)
    if (not isinstance(slot, dict) or type(slot.get('state')) is not int or slot['state'] != expected
            or type(slot.get('charged_units')) is not int or slot['charged_units'] != value['charged_units']
            or type(slot.get('charged_bytes')) is not int or slot['charged_bytes'] != value['charged_bytes']
            or type(slot.get('reserved_bytes')) is not int or slot['reserved_bytes'] != os.sysconf('SC_PAGESIZE')
            or evidence.get('fatal_report_synthesized') is not (result.returncode == 73)):
        raise ValueError('shared fatal control differs from observed worker debit')
    if result.returncode == 73 and (evidence.get('raw_stdout') != '' or evidence.get('raw_stderr') != ''):
        raise ValueError('fatal path still performed output publication')
    return evidence


def campaign(root, binaries, output, receipt_path, execute=supervisor.run):
    """Retain every attempted case and reject partial, drifted or injected runs."""
    output.mkdir(parents=True, exist_ok=False)
    journal_path = output / 'cases.jsonl'
    journal_path.touch()
    guards, rows, failure, initialized = {}, [], None, False
    try:
        if set(binaries) != {'portable', 'accel'}:
            raise ValueError('both binary modes required')
        if any(os.environ.get(key) for key in ('DYLD_INSERT_LIBRARIES', 'LD_PRELOAD', 'LD_AUDIT')):
            raise ValueError('inherited loader injection is outside this campaign')
        receipt = object_json(receipt_path.read_text())
        guards = validate_build(receipt, binaries, root)
        for path in (receipt_path, Path(__file__).resolve(), Path(resource.__file__).resolve(), Path(supervisor.__file__).resolve(), *binaries.values()):
            guards[str(path)] = digest(path)
        initialized = True
        corpus = list(cases(root))
        if len(corpus) != EXPECTED_CASES or len({(case['fixture'], case['case']) for case in corpus}) != len(corpus):
            raise ValueError('incomplete or duplicate input corpus')
        with tempfile.TemporaryDirectory(prefix='parliament-memory-entry-') as temporary, journal_path.open('a') as journal:
            for case in corpus:
                path = Path(temporary) / 'record.bin'
                if case.get('long_path'):
                    path = Path(temporary).joinpath(*(['x' * 64] * 7), 'record.bin')
                    path.parent.mkdir(parents=True)
                if case.get('borrowed_oversize'):
                    input_argument = '--borrowed-oversize'
                elif case.get('fifo'):
                    path = Path(temporary) / 'record.fifo'
                    os.mkfifo(path)
                    input_argument = str(path)
                else:
                    path.write_bytes(case['input'])
                    input_argument = str(path)
                for mode in ('portable', 'accel'):
                    command = [str(binaries[mode]), case['row'], case['role'], input_argument, *case['flags']]
                    row = {key: value for key, value in case.items() if key != 'input'}
                    row.update(mode=mode, command=command, input_bytes=len(case['input']), input_sha256=hashlib.sha256(case['input']).hexdigest(), check_passed=False)
                    try:
                        result = execute(command, input_bytes=len(case['input']), capture_output=True, text=True, timeout=120)
                        row.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
                        row['supervisor'] = getattr(result, 'supervisor_evidence', None)
                        row['worker'] = validate_case(case, result, mode)
                        row['supervisor'] = validate_supervisor(row['worker'], result)
                        row['check_passed'] = True
                    except (Exception, KeyboardInterrupt) as error:
                        row['failure'] = f'{type(error).__name__}: {error}'
                        if isinstance(error, subprocess.TimeoutExpired):
                            for key, partial in (('stdout', error.stdout), ('stderr', error.stderr)):
                                row[key] = partial.decode(errors='replace') if isinstance(partial, bytes) else partial
                    rows.append(row)
                    journal.write(json.dumps(row, sort_keys=True) + '\n')
                    journal.flush()
                    os.fsync(journal.fileno())
                    if not row['check_passed']:
                        raise ValueError(row['failure'])
    except (Exception, KeyboardInterrupt) as error:
        failure = f'{type(error).__name__}: {error}'
    changes = {}
    for path, before in guards.items():
        try:
            after = digest(path) if Path(path).is_file() else None
        except OSError as error:
            after = None
            failure = failure or f'input recheck failed: {error}'
        if after != before:
            changes[path] = {'before': before, 'after': after}
    pairs = {}
    for row in rows:
        if row['check_passed']:
            value = row['worker']
            key = (row['fixture'], row['case'])
            signature = (row['input_sha256'], value['outcome'], value.get('verifier_stage'), value['charged_units'], value['charged_bytes'])
            if row['mode'] in pairs.setdefault(key, {}):
                failure = failure or 'duplicate observation slot'
            pairs[key][row['mode']] = signature
    if not pairs or len(pairs) * 2 != len(rows) or any(set(p) != {'portable', 'accel'} or p['portable'] != p['accel'] for p in pairs.values()):
        failure = failure or 'incomplete or mismatched mode pairs'
    complete = initialized and failure is None and not changes
    report = {'schema': 'parliament-memory-entry-campaign-v2', 'diagnostic_passed': complete,
              'failure': failure, 'input_sha256': guards, 'input_changes': changes,
              'observations': len(rows), 'mode_pairs': len(pairs), 'records_sha256': digest(journal_path),
              'retrieval_excluded_from_worker': True, 'fatal_publication_outside_worker': True,
              'complete_workspace_certificate': False,
              'physical_cost_calibrated': False, 'profile_qualified': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    """Require explicit new output and separately bound diagnostic binaries."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('portable', 'accel', 'output', 'build-receipt'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = campaign(ROOT, {mode: getattr(args, mode).resolve() for mode in ('portable', 'accel')}, args.output.resolve(), args.build_receipt.resolve())
    print(json.dumps({k: v for k, v in result.items() if k != 'input_sha256'}))
    return 0 if result['diagnostic_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())


