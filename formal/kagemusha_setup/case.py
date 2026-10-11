"""Raw-oracle-derived k6 authority established before descriptor/VK digests.

Every reference Python source is copied verbatim. Only this private copy's
parameter authority data differs; RP57 constants and all verifier checks remain.
The parameter source is the separate fresh-target raw-RO seam. This is not the
release CRS or a claim about concrete BLAKE2b.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import random
import sys

from .custody import ROOT, HERE, REFERENCE, MODULES, require, sha, checked_sources
from . import raw_setup as raw
from .parameters import ParameterFamily
from .public_setup import PublicSetup


def draw(modulus, rng):
    """At most 128 fixed-width trials; uniform conditional on success."""
    require(type(modulus) is int and modulus > 1, 'sampler modulus')
    for _ in range(128):
        value = rng.getrandbits(modulus.bit_length())
        if 0 <= value < modulus:
            return value
    raise ValueError('bounded field sampler exhausted')


def uint(value, width=4):
    """Little-endian fixed width test encoder."""
    return value.to_bytes(width, 'little')


def frame(raw):
    """Canonical field frame used by the unchanged Norito reference parser."""
    size, length = len(raw), bytearray()
    while size >= 128:
        length.append((size & 127) | 128)
        size >>= 7
    length.append(size)
    return bytes(length) + raw


def seq(values):
    """Canonical bounded test sequence."""
    return uint(len(values), 8) + b''.join(map(frame, values))


def expr(nodes):
    """Postfix expression encoding, without a circuit builder."""
    return seq([uint(tag) + (frame(value) if value is not None else b'')
                for tag, value in nodes])



@dataclass(frozen=True)
class Case:
    """One isolated preconstructed setup and its known scalar representations."""
    directory: Path
    package: str
    verifier: object
    transcript: object
    parameters: object
    descriptor: object
    key: bytes
    raw_params: bytes
    params: object
    base: tuple
    logs: dict
    contradictory: bool
    public_setup: object
    source_descriptor_sha256: str
    public_original: bytes


def make_case(directory, curve_tag, parameters_data, contradictory=False):
    """Create a fresh private verifier/authority; no global module patching.

    Parameter points and private logs come from the already constructed raw-RO
    family, with B=isogeny(SWU(1)). This function never samples another family
    or replaces a rejected point. Only the new private authority differs.
    """
    checked_sources()
    require(type(curve_tag) is int and curve_tag in (0, 1), 'curve tag')
    require(type(contradictory) is bool, 'relation kind')
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    package = '_raw_setup_known_log_' + sha(str(directory).encode())[:20]
    require(package not in sys.modules, 'private package already loaded')
    copied = directory / package
    copied.mkdir()
    source_hashes = {}
    for name in MODULES:
        raw = (REFERENCE/name).read_bytes()
        (copied/name).write_bytes(raw)
        source_hashes[name] = sha(raw)
    # Import only package+curve for setup arithmetic, before any authority load.
    spec = importlib.util.spec_from_file_location(package, copied/'__init__.py',
                                                  submodule_search_locations=[str(copied)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[package] = module
    spec.loader.exec_module(module)
    curves = importlib.import_module(package + '.curve')
    curve, k, n = curves.Curve(curve_tag), 6, 64
    m = curve.scalar
    require(parameters_data.curve_tag == curve_tag and parameters_data.k == k,
            'exact preconstructed curve and size')
    base = parameters_data.base
    require(curve.equal(curve.decode(curve.encode(base)), base), 'source-map base point')
    require(set(parameters_data.logs) == {'g', 'lagrange', 'w', 'u'}, 'exact parameter log roles')
    g_logs, lagrange_logs = parameters_data.logs['g'], parameters_data.logs['lagrange']
    w_log, u_log = parameters_data.logs['w'], parameters_data.logs['u']
    require(type(g_logs) is tuple and len(g_logs) == n and
            type(lagrange_logs) is tuple and len(lagrange_logs) == n,
            'exact coefficient and Lagrange log vectors')
    all_logs = (*g_logs, *lagrange_logs, w_log, u_log)
    require(all(type(value) is int and 0 < value < m for value in all_logs),
            'native parameter identity or canonical-scalar stop')
    omega, scale = curve.omega(k), pow(n, -1, m)
    expected_lagrange = tuple(sum(g_logs[i]*pow(omega, (-i*j) % n, m)
                                   for i in range(n))*scale % m for j in range(n))
    require(lagrange_logs == expected_lagrange, 'one-normalization native IFFT logs')
    points = [curve.multiply(base, value) for value in all_logs]
    raw_params = uint(k) + b''.join(map(curve.encode, points))
    require(type(parameters_data.raw) is bytes and parameters_data.raw == raw_params,
            'exact raw-derived parameter wire and every private log')
    parameter_sha = sha(raw_params)
    original_kats = json.loads((ROOT/'fixtures/native_prover/kats_v1.json').read_text())
    toy_kats = json.loads(json.dumps(original_kats))
    toy_kats['params_ipa'] = {'ep': [], 'eq': []}
    toy_kats['params_ipa'][curve.name] = [{'k': k, 'byte_len': len(raw_params), 'sha256': parameter_sha}]
    require({key: value for key, value in toy_kats.items() if key != 'params_ipa'} ==
            {key: value for key, value in original_kats.items() if key != 'params_ipa'},
            'only synthetic parameter authority may differ')
    (directory/'kats_v1.json').write_text(json.dumps(toy_kats, indent=2, sort_keys=True)+'\n')
    (directory/'parameters.bin').write_bytes(raw_params)
    # All verifier modules now load their authority from the newly written file.
    verifier = importlib.import_module(package + '.verify')
    parameters = importlib.import_module(package + '.parameters')
    transcript = importlib.import_module(package + '.transcript')
    codec = importlib.import_module(package + '.codec')
    params = parameters.Parameters.decode(raw_params, curve, k)
    q0, a0, i0 = (1, uint(0)), (2, uint(0)), (3, uint(0))
    difference = [a0, i0, (4, None), (5, None)]
    gates = [[q0, *difference, (6, None)]]
    if contradictory:
        gates.append([q0, *difference, (0, uint(1, 32)), (4, None), (5, None), (6, None)])
    query = frame(uint(0)) + frame(uint(0))
    columns = [frame(uint(kind)) + frame(uint(0)) for kind in (0, 2)]
    lookup = frame(seq([expr([a0])])) + frame(seq([expr([q0])]))
    fields = [uint(1, 2), uint(curve_tag), uint(curve.base, 32), uint(m, 32),
              params.digest, uint(k, 1), uint(2), uint(1), uint(1), uint(4, 1),
              uint(5, 2), uint(2, 1), uint(3, 1), uint(0), uint(1), uint(1),
              seq([uint(1)]), seq([query]), seq([query]), seq([query]),
              frame(uint(0, 1)) + frame(uint(1)) + frame(seq([])),
              seq([seq([expr(gate)]) for gate in gates]), seq(columns), seq([lookup]),
              seq([uint(0)])]
    payload = b''.join(map(frame, fields))
    schema = hashlib.sha256(b'norito:v1:type-name\0iroha.plonk.pipa.circuit_descriptor.v2').digest()[:16]
    raw = (b'NRT0\0\0' + schema + b'\0' + uint(len(payload), 8) +
           uint(codec.crc64(payload), 8) + b'\x02' + payload)
    descriptor = verifier.Descriptor.decode(raw, 2)
    delta = pow(5, 1 << 32, m)
    fixed_logs = ((lagrange_logs[0] + w_log) % m,)
    sigma_logs = tuple((g_logs[1]*pow(delta, j, m)+w_log) % m for j in range(2))
    require(all(value != 0 for value in (*fixed_logs, *sigma_logs)), 'key point identity stop')
    key = b'\x02' + uint(k) + b'\0' + uint(1) + b''.join(
        curve.encode(curve.multiply(base, value)) for value in (*fixed_logs, *sigma_logs))
    verifier.key_points(descriptor, key)
    (directory/'descriptor.bin').write_bytes(raw)
    (directory/'key.bin').write_bytes(key)
    logs = {'g': g_logs, 'lagrange': lagrange_logs, 'w': w_log, 'u': u_log,
            'fixed': fixed_logs, 'sigma': sigma_logs}
    (directory/'known-setup-logs.json').write_text(json.dumps(logs, indent=2)+'\n')
    authority = {'scope': 'Synthetic setup-algebra control; no release parameter admission',
                 'curve': curve.name, 'k': k, 'contradictory': contradictory,
                 'parameter_source': 'Preconstructed exact raw-XMD/SWU family, reused across both relation examples',
                 'parameter_base': curve.encode(base).hex(),
                 'reference_sources': source_hashes, 'parameter_sha256': parameter_sha,
                 'descriptor_sha256': sha(raw), 'key_sha256': sha(key),
                 'toy_kats_sha256': sha((directory/'kats_v1.json').read_bytes()),
                 'authority_difference': 'Only params_ipa replaced before transcript/descriptor/parameters modules loaded',
                 'fixed_poseidon_constants_unchanged': True}
    (directory/'authority.json').write_text(json.dumps(authority, indent=2, sort_keys=True)+'\n')
    # Exact public preprocessing, shared with the generic simulator. The zero
    # copy digest is fixture data; no signed catalog authority is asserted.
    fixed = (1,)+((0,)*(n-1))
    sigma = tuple(tuple(pow(delta, j, m)*pow(omega, i, m) % m for i in range(n))
                  for j in range(len(descriptor['permutation'])))
    public_original = (b'PIPAPK01'+descriptor.digest+uint(len(key))+key+bytes(32)+
                       b''.join(uint(value,32) for column in (fixed,*sigma) for value in column))
    public = PublicSetup.decode(public_original, descriptor, key, sha(public_original))
    with (directory/'public-original.bin').open('xb') as stream:
        stream.write(public_original)
    return Case(directory, package, verifier, transcript, parameters, descriptor,
                key, raw_params, params, base, logs, contradictory, public,
                sha(descriptor.raw), public_original)


def build_families(directory):
    """One shared append-only raw oracle, 132 contexts, no family resampling.

    All retained words/logs here are synthetic diagnostic data. The public
    oracle API returns raw hash words only; these files do not model disclosure
    of the simulator's private log/attempt tables to an adversary.
    """
    checked_sources()
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    coins = random.Random(2026100944)
    sampler = raw.FreshTargetSampler(raw, coins)
    oracle = raw.RawSetupOracle(coins, sampler, query_budget=512, setup_budget=132)
    family = ParameterFamily(raw, oracle, sampler)
    unrelated = b'prior unrelated raw query'
    earlier_answer = oracle.query(unrelated)
    data, early = {}, {}
    try:
        for tag in (0, 1):
            early[tag] = oracle.query(raw.input0(tag, b'\x00'+bytes(4)))
            data[tag] = family.derive(tag, 6)
            (directory/('%d-parameters.bin' % tag)).write_bytes(data[tag].raw)
        before = (dict(oracle.table), dict(oracle.logs), len(sampler.records))
        for tag in (0, 1):
            require(oracle.query(raw.input0(tag, b'\x00'+bytes(4))) == early[tag],
                    'early raw query replay')
            for message in (b'\x00'+bytes(4), b'\x01', b'\x02'):
                family.point(tag, message)
        require(oracle.query(unrelated) == earlier_answer, 'prior raw answer unchanged')
        require((oracle.table, oracle.logs, len(sampler.records)) == before,
                'exact contexts replay without fresh samples')
        expected = {(tag, b'\x00'+i.to_bytes(4, 'little')) for tag in (0, 1) for i in range(64)}
        expected |= {(tag, message) for tag in (0, 1) for message in (b'\x01', b'\x02')}
        require(set(oracle.logs) == expected, 'exact 132 setup contexts')
        require(len(oracle.table) == 397 and len(sampler.records) == 132,
                'exact setup and unrelated raw table sizes')
        observation = {'unique_contexts': len(oracle.logs), 'setup_sampler_calls': len(sampler.records),
                       'raw_entries': len(oracle.table), 'raw_calls': oracle.queries,
                       'query_budget': 512, 'setup_budget': 132,
                       'pair_attempts': raw.PAIR_ATTEMPTS, 'draw_attempts': raw.DRAW_ATTEMPTS,
                       'parameter_sha256': {str(tag): hashlib.sha256(value.raw).hexdigest()
                                            for tag, value in data.items()},
                       'k': 6, 'family_resamples': 0, 'scope': 'Ideal raw-hash setup control only',
                       'simulator_private_tables_are_not_public_API': True}
        (directory/'observation.json').write_text(json.dumps(observation, indent=2, sort_keys=True)+'\n')
        return data, observation
    finally:
        # Preserve a cap, identity or consistency failure as well as successes.
        (directory/'raw-oracle-private.json').write_text(json.dumps(
            {'raw_table': [{'input': query.hex(), 'answer': answer.hex()}
                           for query, answer in oracle.table.items()],
             'private_logs': [{'curve': tag, 'message': message.hex(), 'scalar': scalar}
                              for (tag, message), scalar in oracle.logs.items()],
             'sampler_records': sampler.records, 'raw_calls': oracle.queries,
             'oracle_stopped': oracle.stopped, 'not_public_protocol_data': True},
            indent=2, sort_keys=True)+'\n')
