"""Genuine complete proofs and adversarial boundaries of the independent verifier."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'fixtures/native_prover'))
from reference_verifier import InvalidProof
from reference_verifier.codec import Cursor, crc64
from reference_verifier.curve import Curve, IDENTITY
from reference_verifier.descriptor import Descriptor
from reference_verifier.parameters import Parameters, decide, seed_parameters_k6
from reference_verifier.verify import verify_captured_oracle

DOCUMENT = json.loads((ROOT / 'fixtures/native_prover/succinct_v1.json').read_text())
CASES = [case for case in DOCUMENT['cases'] if case['k'] == 6]


@pytest.fixture(scope='module')
def parameter_bytes():
    """Reconstruct independently; each resulting complete codec matches its pin."""
    return {curve: seed_parameters_k6(Curve(tag)) for curve, tag in [('ep', 0), ('eq', 1)]}


def scalar(text):
    """Decode a fixture's explicit canonical byte spelling."""
    return int.from_bytes(bytes.fromhex(text), 'little')


def inputs(case, params):
    """The reference's byte inputs, without a native module or verifier result."""
    return dict(descriptor=bytes.fromhex(case['descriptor']),
                key=bytes.fromhex(case['verifying_key']), parameter_bytes=params,
                instances=[[scalar(v) for v in column] for column in case['instances']],
                proof=bytes.fromhex(case['proof']), transcript_repr=scalar(case['transcript_repr']))


@pytest.mark.parametrize('case', CASES, ids=lambda c: f"{c['curve']}-{c['seed_byte']}")
def test_full_genuine_sigma_and_every_challenge(case, parameter_bytes):
    result = verify_captured_oracle(**inputs(case, parameter_bytes[case['curve']]))
    curve = Curve(0 if case['curve'] == 'ep' else 1)
    assert result.challenges == tuple(map(scalar, case['challenges']))
    assert result.rounds == tuple(map(scalar, case['u']))
    assert curve.encode(result.generator).hex() == case['g']


@pytest.mark.parametrize('case', CASES, ids=lambda c: f"{c['curve']}-{c['seed_byte']}")
@pytest.mark.parametrize('mutation', ['instance', 'proof', 'suffix', 'trailing', 'truncated', 'key'])
def test_complete_proof_mutations_reject(case, mutation, parameter_bytes):
    args = inputs(case, parameter_bytes[case['curve']])
    curve = Curve(0 if case['curve'] == 'ep' else 1)
    if mutation == 'instance':
        args['instances'][0][0] = (args['instances'][0][0] + 1) % curve.scalar
    elif mutation == 'proof':
        proof = bytearray(args['proof']); proof[32] ^= 1; args['proof'] = bytes(proof)
    elif mutation == 'suffix':
        args['proof'] = args['proof'][:-32] + args['proof'][:32]
    elif mutation == 'trailing':
        args['proof'] += b'\0'
    elif mutation == 'truncated':
        args['proof'] = args['proof'][:-1]
    else:
        key = bytearray(args['key']); key[10:42] = args['proof'][:32]; args['key'] = bytes(key)
    with pytest.raises(InvalidProof):
        verify_captured_oracle(**args)


@pytest.mark.parametrize('tag', [0, 1])
def test_decide_admits_only_pinned_bytes_and_canonical_claim(tag, parameter_bytes):
    curve = Curve(tag)
    raw = parameter_bytes[curve.name]
    case = next(c for c in CASES if c['curve'] == curve.name)
    point, rounds = bytes.fromhex(case['g']), list(map(scalar, case['u']))
    assert curve.encode(decide(raw, tag, 6, point, rounds)) == point
    for malformed in [bytes(32), b'', point + b'\0', (0, 0, curve.base),
                      curve.base.to_bytes(32, 'little')]:
        with pytest.raises(InvalidProof):
            decide(raw, tag, 6, malformed, rounds)
    for bad in [0, curve.scalar, -1, 0.5, True, None, '1']:
        changed = rounds.copy(); changed[0] = bad
        with pytest.raises(InvalidProof):
            decide(raw, tag, 6, point, changed)
    changed = rounds.copy(); changed[0] = (changed[0] + 1) % curve.scalar
    with pytest.raises(InvalidProof):
        decide(raw, tag, 6, point, changed)
    params = Parameters.decode(raw, curve, 6)
    with pytest.raises(InvalidProof):
        decide(params, tag, 6, point, rounds)
    changed = bytearray(raw); changed[4] ^= 1
    with pytest.raises(InvalidProof):
        decide(bytes(changed), tag, 6, point, rounds)
    for bad in [rounds[:-1], rounds + [1], None, 3]:
        with pytest.raises(InvalidProof):
            decide(raw, tag, 6, point, bad)


@pytest.mark.parametrize('tag', [0, 1])
def test_parameter_bounds_precede_hashing(tag, monkeypatch):
    module = importlib.import_module('reference_verifier.parameters')
    def unexpected_hash(_):
        raise AssertionError('oversized input reached hashing')
    monkeypatch.setattr(module.hashlib, 'sha256', unexpected_hash)
    with pytest.raises(InvalidProof, match='parameter framing'):
        Parameters.decode(bytes(4 + 64 * 64 + 65), Curve(tag), 6)


@pytest.mark.parametrize('case', CASES[:1])
def test_descriptor_header_and_authoritative_spans_reject(case):
    raw = bytes.fromhex(case['descriptor'])
    for offset in (0, 4, 6, 22, 23, 31, 39):
        altered = bytearray(raw); altered[offset] ^= 0x80
        with pytest.raises(InvalidProof):
            Descriptor.decode(bytes(altered), 1)
    for altered in (raw[:-1], raw + b'\0'):
        with pytest.raises(InvalidProof):
            Descriptor.decode(altered, 1)
    with pytest.raises(InvalidProof, match='schema'):
        Descriptor.decode(raw, 2)
    # Same semantic first field, nonminimal compact length and an authentic new CRC.
    payload = b'\x82\x00' + raw[41:]
    header = bytearray(raw[:40]); header[23:31] = len(payload).to_bytes(8, 'little')
    header[31:39] = crc64(payload).to_bytes(8, 'little')
    with pytest.raises(InvalidProof, match='nonminimal'):
        Descriptor.decode(bytes(header) + payload, 1)
    with pytest.raises(InvalidProof, match='trailing span'):
        Cursor(b'\x02\x01\0').field(lambda child: child.integer(1))


@pytest.mark.parametrize('tag', [0, 1])
def test_group_identity_opposites_and_noncanonical_points(tag, parameter_bytes):
    curve = Curve(tag)
    params = Parameters.decode(parameter_bytes[curve.name], curve, 6)
    point = params.g[0]
    assert curve.equal(curve.add(point, IDENTITY), point)
    assert curve.equal(curve.add(IDENTITY, point), point)
    assert curve.add(point, curve.multiply(point, -1))[2] == 0
    assert curve.equal(curve.add(point, point), curve.multiply(point, 2))
    assert curve.equal(curve.decode(curve.encode(point)), point)
    for raw in [bytes(32), curve.base.to_bytes(32, 'little'), bytes(31), bytes(33)]:
        with pytest.raises(InvalidProof):
            curve.decode(raw)

@pytest.mark.parametrize('alias', [True, False, 0.0, 1.0, 6.0, None, '1'])
def test_public_metadata_does_not_accept_python_integer_aliases(alias, parameter_bytes):
    case = CASES[0]
    with pytest.raises(InvalidProof):
        Curve(alias)
    with pytest.raises(InvalidProof):
        Descriptor.decode(bytes.fromhex(case['descriptor']), alias)
    with pytest.raises(InvalidProof):
        Parameters.decode(parameter_bytes['ep'], Curve(0), alias)


@pytest.mark.parametrize('shape', [[], [[]], [[1], []], [[1, 2]], None, [None], [[True]], [[1.0]]])
def test_exact_instance_shape_and_scalar_types(shape, parameter_bytes):
    args = inputs(CASES[0], parameter_bytes[CASES[0]['curve']])
    args['instances'] = shape
    with pytest.raises(InvalidProof):
        verify_captured_oracle(**args)


def test_wrong_curve_and_parameter_exponent_reject(parameter_bytes):
    case = CASES[0]
    args = inputs(case, parameter_bytes['eq' if case['curve'] == 'ep' else 'ep'])
    with pytest.raises(InvalidProof, match='unpinned'):
        verify_captured_oracle(**args)
    point, rounds = bytes.fromhex(case['g']), list(map(scalar, case['u']))
    with pytest.raises(InvalidProof):
        decide(parameter_bytes[case['curve']], 1 if case['curve'] == 'ep' else 0, 6, point, rounds)
    with pytest.raises(InvalidProof, match='parameter framing'):
        decide(parameter_bytes[case['curve']], 0 if case['curve'] == 'ep' else 1, 7, point, rounds)

@pytest.mark.parametrize('alias', [True, 1.0, None, '1'])
def test_historical_oracle_binding_requires_a_canonical_integer(alias, parameter_bytes):
    args = inputs(CASES[0], parameter_bytes[CASES[0]['curve']])
    args['transcript_repr'] = alias
    with pytest.raises(InvalidProof):
        verify_captured_oracle(**args)

REFERENCE = json.loads((ROOT / 'fixtures/native_prover/reference_v1.json').read_text())
PROFILES = ('v1/blake/Committed/false', 'v1/poseidon/Direct/true',
            'v2/blake/Direct/field', 'v2/poseidon/Committed/field',
            'v2/base/Direct/field', 'v2/base/k6/bounded-or-field', 'v2/base/k6/bits4')
PRODUCTION = [case for case in REFERENCE['cases'] if case['name'].split('/', 1)[1] in PROFILES]


def production_inputs(case):
    """Only bytes and explicit public inputs cross the production reference API."""
    return dict(descriptor=bytes.fromhex(case['descriptor']), version=case['descriptor_version'],
                key=bytes.fromhex(case['verifying_key']),
                parameter_bytes=bytes.fromhex(REFERENCE['parameters'][f"{case['curve']}/{case['k']}"]),
                instances=[[scalar(value) for value in column] for column in case['instances']],
                proof=bytes.fromhex(case['proof']))


def replace_descriptor_field(raw, index, replacement):
    """Make a canonical new Norito frame for a deliberate semantic mutation."""
    def length(value):
        out = bytearray()
        while value >= 128:
            out.append((value & 127) | 128); value >>= 7
        out.append(value)
        return bytes(out)
    assert raw[39] == 2
    cursor = Cursor(raw[40:])
    fields = []
    while cursor.position < len(cursor.data):
        fields.append(cursor.read(cursor.length()))
    fields[index] = replacement
    payload = b''.join(length(len(field)) + field for field in fields)
    header = bytearray(raw[:40])
    header[23:31] = len(payload).to_bytes(8, 'little')
    header[31:39] = crc64(payload).to_bytes(8, 'little')
    return bytes(header) + payload


@pytest.mark.parametrize('case', PRODUCTION, ids=lambda c: c['name'])
@pytest.mark.parametrize('mutation', ['public', 'commitment', 'key', 'trailing', 'parameters', 'curve', 'schema'])
def test_every_production_profile_rejects_mutation(case, mutation):
    from reference_verifier.verify import verify
    args = production_inputs(case)
    if mutation == 'public':
        args['instances'][0][0] += 1
    elif mutation == 'commitment':
        proof = args['proof']; assert proof[:32] != proof[32:64]
        args['proof'] = proof[32:64] + proof[32:]
    elif mutation == 'key':
        key = bytearray(args['key']); key[10:42] = args['proof'][:32]; args['key'] = bytes(key)
    elif mutation == 'trailing':
        args['proof'] += b'\0'
    elif mutation == 'parameters':
        parameter = bytearray(args['parameter_bytes']); parameter[4] ^= 1
        args['parameter_bytes'] = bytes(parameter)
    elif mutation == 'curve':
        tag = 1 if case['curve'] == 'ep' else 0
        args['descriptor'] = replace_descriptor_field(args['descriptor'], 1, tag.to_bytes(4, 'little'))
    else:
        args['version'] = 3 - args['version']
    with pytest.raises(InvalidProof):
        verify(**args)


@pytest.mark.parametrize('curve', ['ep', 'eq'])
def test_v2_typed_instance_boundaries_and_invalid_type_encodings(curve):
    from reference_verifier.curve import P
    from reference_verifier.verify import verify
    bits = next(case for case in REFERENCE['cases'] if case['name'] == f'{curve}/v2/base/k6/bits4')
    bounded = next(case for case in REFERENCE['cases'] if case['name'] == f'{curve}/v2/base/k6/bounded-or-field')
    for case, maximum in [(bits, 15), (bounded, P - 1)]:
        args = production_inputs(case); d = Descriptor.decode(args['descriptor'], 2)
        d.check_instances([[maximum]])
        args['instances'] = [[maximum + 1]]
        with pytest.raises(InvalidProof, match='instance (type|scalar)'):
            verify(**args)
    for width in (254, 255):
        # One Bits(width) enum in a sequence: fixed count, framed tag + framed u8.
        types = (1).to_bytes(8, 'little') + b'\x06' + (2).to_bytes(4, 'little') + b'\x01' + bytes([width])
        changed = replace_descriptor_field(bytes.fromhex(bits['descriptor']), 24, types)
        with pytest.raises(InvalidProof, match='instance bit type'):
            Descriptor.decode(changed, 2)
    types = (1).to_bytes(8, 'little') + b'\x06' + (2).to_bytes(4, 'little') + b'\x01\x00'
    changed = replace_descriptor_field(bytes.fromhex(bits['descriptor']), 24, types)
    d = Descriptor.decode(changed, 2)
    d.check_instances([[0]])
    with pytest.raises(InvalidProof, match='instance type'):
        d.check_instances([[1]])
    args = production_inputs(bits); args['descriptor'] = changed; args['instances'] = [[0]]
    with pytest.raises(InvalidProof):
        verify(**args)


def test_descriptor_parameter_identity_rejects_even_with_valid_frame():
    case = PRODUCTION[0]
    altered = replace_descriptor_field(bytes.fromhex(case['descriptor']), 4, bytes(32))
    with pytest.raises(InvalidProof, match='descriptor parameter identity'):
        Descriptor.decode(altered, case['descriptor_version'])


def test_complete_reference_cli_uses_only_standard_library_from_other_directory(tmp_path):
    import subprocess
    result = subprocess.run([sys.executable, '-B', '-I', '-S',
                             str(ROOT / 'fixtures/native_prover/verify_reference_v1.py')],
                            cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == (
        f"{ROOT / 'fixtures/native_prover/reference_v1.json'}: "
        'verified full_proofs=46, pinned_parameter_sets=10, curves=2, profiles=3')


SOFT_CASES = [case for case in PRODUCTION if case['name'].split('/', 1)[1] in
              ('v2/blake/Direct/field', 'v2/poseidon/Committed/field', 'v2/base/Direct/field')]


@pytest.mark.parametrize('case', SOFT_CASES, ids=lambda c: c['name'])
def test_false_generator_preserves_soft_equation_but_full_decision_rejects(case):
    """A valid soft equation is deliberately insufficient for full acceptance."""
    from reference_verifier.verify import verify
    args = production_inputs(case)
    genuine = verify(**args)
    d = Descriptor.decode(args['descriptor'], args['version'])
    curve, m = d.curve, d.curve.scalar
    params = Parameters.decode(args['parameter_bytes'], curve, d['k'])
    proof = args['proof']
    assert d['proof_suffix'] == 1 and len(genuine.challenges) == d['k'] + 11
    c, f = scalar(proof[-96:-64].hex()), scalar(proof[-64:-32].hex())
    changed_c = (c + 1) % m
    assert changed_c != 0
    b, power = 1, genuine.challenges[7]  # x3 from the specified multiopen transcript.
    for u in reversed(genuine.rounds):
        b = b * (1 + u * power) % m
        power = power * power % m
    bz = b * genuine.challenges[10] % m  # zeta; final scalars have no later squeeze.
    forged = curve.multiply(curve.sum([(c, genuine.generator),
                                      (-(changed_c - c) * bz, params.u)]), pow(changed_c, -1, m))
    assert not curve.equal(forged, genuine.generator)
    before = curve.sum([(c, genuine.generator), (c * bz, params.u), (f, params.w)])
    after = curve.sum([(changed_c, forged), (changed_c * bz, params.u), (f, params.w)])
    assert curve.equal(before, after), 'the exact soft IPA equation is unchanged'
    args['proof'] = proof[:-96] + changed_c.to_bytes(32, 'little') + proof[-64:-32] + curve.encode(forged)
    assert args['proof'][:-96] == proof[:-96]
    with pytest.raises(InvalidProof, match='generator decision'):
        verify(**args)


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'version_alias', 'curve_label',
                                      'profile_label', 'proof_with_new_digest'])
def test_reference_evidence_matrix_cannot_substitute_missing_or_false_cases(mutation):
    """The fixture labels and hash are not substitutes for cryptographic verification."""
    from copy import deepcopy
    import hashlib
    import verify_reference_v1
    document = deepcopy(REFERENCE)
    case = document['cases'][0]
    if mutation == 'missing':
        document['cases'].pop()
    elif mutation == 'duplicate':
        document['cases'][-1] = deepcopy(case)
    elif mutation == 'version_alias':
        case['descriptor_version'] = True
    elif mutation == 'curve_label':
        case['curve'] = 'eq' if case['curve'] == 'ep' else 'ep'
    elif mutation == 'profile_label':
        # Preserve the complete name set while assigning a genuine proof to the wrong profile.
        case['name'], document['cases'][1]['name'] = document['cases'][1]['name'], case['name']
    else:
        proof = bytes.fromhex(case['proof']) + b'\0'
        case['proof'], case['proof_sha256'] = proof.hex(), hashlib.sha256(proof).hexdigest()
    with pytest.raises(InvalidProof):
        verify_reference_v1.check(document)
