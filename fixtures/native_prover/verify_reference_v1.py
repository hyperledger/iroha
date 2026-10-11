#!/usr/bin/env python3
"""Run the independent full PIPA reference with only Python's standard library.

It verifies genuine frozen full proofs, never calls Rust/native code, and keeps
historical oracle framing explicit and separate from production verification.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_verifier import InvalidProof, require
from reference_verifier.verify import verify, verify_captured_oracle
from reference_verifier.descriptor import Descriptor


def expected_names():
    """The exact supported fixture matrix, independent of the supplied JSON."""
    names = set()
    for curve in ('ep', 'eq'):
        for profile in ('blake', 'poseidon'):
            for k in (6, 8):
                names.add(f'{curve}/oracle/{profile}/{k}')
            for mode in ('Committed', 'Direct'):
                for compression in ('false', 'true'):
                    names.add(f'{curve}/v1/{profile}/{mode}/{compression}')
                names.add(f'{curve}/v2/{profile}/{mode}/field')
        names.add(f'{curve}/v2/base/Direct/field')
        names.add(f'{curve}/v2/base/k6/bits4')
        for k in range(6, 11):
            names.add(f'{curve}/v2/base/k{k}/bounded-or-field')
    return names


def case_identity(case):
    """Bind every required matrix label to the decoded descriptor, not its name alone."""
    require(type(case['descriptor_version']) is int and type(case['k']) is int and
            type(case['curve']) is str and type(case['name']) is str, 'canonical reference metadata')
    d = Descriptor.decode(bytes.fromhex(case['descriptor']), case['descriptor_version'])
    require(case['curve'] == d.curve.name and case['k'] == d['k'], 'reference curve/domain identity')
    parts = case['name'].split('/')
    require(parts[0] == d.curve.name, 'reference curve label')
    profile = ('blake', 'poseidon', 'base')[d['transcript']]
    mode = ('Committed', 'Direct')[d['instance_mode']]
    if parts[1] == 'oracle':
        require(d.version == 1 and parts[2:] == [profile, str(d['k'])], 'oracle profile label')
    elif parts[1] == 'v1':
        require(d.version == 1 and d['k'] == 6 and
                parts[2:] == [profile, mode, str(bool(d['selectors'][0])).lower()] and
                d['proof_suffix'] == d['selectors'][0], 'V1 profile label')
    else:
        require(parts[1] == 'v2' and d.version == 2 and parts[2] == profile, 'V2 profile label')
        if parts[3] == 'Direct' or parts[3] == 'Committed':
            require(parts[3:] == [mode, 'field'] and d['k'] == 6 and
                    d['instance_types'] == [(0, None)], 'V2 retained profile label')
        else:
            kind = (2, 4) if parts[4] == 'bits4' else (1, None) if d['k'] == 6 else (0, None)
            require(parts[3] == f"k{d['k']}" and profile == 'base' and
                    d['instance_types'] == [kind], 'V2 typed profile label')


def check(document):
    """Verify every exact case and enforce the complete positive matrix."""
    require(document['format'] == 'iroha.pipa.reference.v1', 'reference fixture format')
    cases = document['cases']
    require(isinstance(cases, list) and len(cases) == len(expected_names()), 'reference case count')
    require({case['name'] for case in cases} == expected_names(), 'reference case identities')
    parameters = document['parameters']
    require(set(parameters) == {f'{curve}/{k}' for curve in ('ep', 'eq') for k in range(6, 11)},
            'reference parameter matrix')
    for case in cases:
        case_identity(case)
        proof = bytes.fromhex(case['proof'])
        require(hashlib.sha256(proof).hexdigest() == case['proof_sha256'], 'captured proof digest')
        common = dict(descriptor=bytes.fromhex(case['descriptor']), key=bytes.fromhex(case['verifying_key']),
                      parameter_bytes=bytes.fromhex(parameters[f"{case['curve']}/{case['k']}"]),
                      instances=[[int.from_bytes(bytes.fromhex(value), 'little') for value in column]
                                 for column in case['instances']], proof=proof)
        if '/oracle/' in case['name']:
            require(case['descriptor_version'] == 1 and 'oracle_repr' in case, 'explicit oracle case')
            verify_captured_oracle(**common, transcript_repr=int.from_bytes(bytes.fromhex(case['oracle_repr']), 'little'))
        else:
            require('oracle_repr' not in case, 'no production transcript override')
            verify(**common, version=case['descriptor_version'])
    return len(cases)


def main():
    """Read one finite fixture and report only after all complete decisions pass."""
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).with_name('reference_v1.json')
    require(len(sys.argv) <= 2, 'one optional fixture path')
    require(path.stat().st_size <= 16 * 1024 * 1024, 'reference fixture bound')
    count = check(json.loads(path.read_text()))
    print(f'{path}: verified full_proofs={count}, pinned_parameter_sets=10, curves=2, profiles=3')


if __name__ == '__main__':
    try:
        main()
    except (InvalidProof, KeyError, TypeError, ValueError, OSError) as error:
        print(f'reference verifier rejected: {error}', file=sys.stderr)
        raise SystemExit(1) from error
