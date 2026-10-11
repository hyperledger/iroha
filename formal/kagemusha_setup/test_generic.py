"""Prepared small generic fixed-RP57 controls; no automatic k16 execution."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import random
from unittest.mock import patch
import unittest

from .custody import HERE, ROOT, MODULES, REFERENCE, checked_sources, require, sha
from .case import draw, uint, frame, seq, expr, build_families, make_case as toy_case
from .rebind import make_case, reference
from .bounded import scalar_ifft
from .public_setup import PublicSetup, weights
from .simulator import simulate, sample_budget

OUTPUT = None


class CountedCoins:
    """Explicit diagnostic stream with retained invocation counts."""
    def __init__(self, seed):
        self.stream, self.calls = random.Random(seed), 0

    def getrandbits(self, width):
        self.calls += 1
        return self.stream.getrandbits(width)


def source_toy(curve_tag, modules, fixture, contradictory=False):
    """Canonical k6 descriptor with lookup, permutation and three opening sets.

    q=L_0, lookup table=L_0, sigma_j=delta^j X are public setup polynomials.
    The ordinary relation has q*(a-instance)=0. The contradictory relation
    adds q*(a-instance-1)=0, which cannot hold at domain row zero.
    """
    curve = modules['curve'].Curve(curve_tag)
    params_raw = bytes.fromhex(fixture['parameters'][f'{curve.name}/6'])
    params = modules['parameters'].Parameters.decode(params_raw, curve, 6)
    q0, a0, i0 = (1, uint(0)), (2, uint(0)), (3, uint(0))
    difference = [a0, i0, (4, None), (5, None)]
    gates = [[q0, *difference, (6, None)]]
    if contradictory:
        gates.append([q0, *difference, (0, uint(1, 32)), (4, None), (5, None), (6, None)])
    query = frame(uint(0)) + frame(uint(0))
    columns = [frame(uint(kind)) + frame(uint(0)) for kind in (0, 2)]
    lookup = frame(seq([expr([a0])])) + frame(seq([expr([q0])]))
    fields = [uint(1, 2), uint(curve_tag), uint(curve.base, 32), uint(curve.scalar, 32),
              params.digest, uint(6, 1), uint(2), uint(1), uint(1), uint(4, 1),
              uint(5, 2), uint(2, 1), uint(3, 1), uint(0), uint(1), uint(1),
              seq([uint(1)]), seq([query]), seq([query]), seq([query]),
              frame(uint(0, 1)) + frame(uint(1)) + frame(seq([])),
              seq([seq([expr(gate)]) for gate in gates]), seq(columns), seq([lookup]),
              seq([uint(0)])]
    payload = b''.join(map(frame, fields))
    schema = hashlib.sha256(b'norito:v1:type-name\0iroha.plonk.pipa.circuit_descriptor.v2').digest()[:16]
    raw = b'NRT0\0\0' + schema + b'\0' + uint(len(payload), 8) + uint(modules['codec'].crc64(payload), 8) + b'\x02' + payload
    d = modules['descriptor'].Descriptor.decode(raw, 2)
    delta = pow(5, 1 << 32, curve.scalar)
    fixed = curve.add(params.lagrange[0], params.w)
    sigmas = [curve.add(curve.multiply(params.g[1], pow(delta, j, curve.scalar)), params.w)
              for j in range(2)]
    key = b'\x02' + uint(6) + b'\0' + uint(1) + b''.join(curve.encode(p) for p in [fixed, *sigmas])
    modules['verify'].key_points(d, key)
    return d, key, params_raw, params


def frame_descriptor(fields, codec):
    """Encode an explicit V2 descriptor from its canonical field byte strings."""
    payload = b''.join(map(frame, fields))
    schema = hashlib.sha256(b'norito:v1:type-name\0iroha.plonk.pipa.circuit_descriptor.v2').digest()[:16]
    return (b'NRT0\0\0' + schema + b'\0' + uint(len(payload), 8) +
            uint(codec.crc64(payload), 8) + b'\x02' + payload)


def setup_case(tag, modules, fixture, variant='ordinary'):
    """Build only k6 public test tables, including optional extra slot shapes."""
    d, key, raw_params, params = source_toy(tag, modules, fixture)
    r, fields = modules['codec'].Cursor(d.raw[40:]), []
    while r.position < len(r.data):
        fields.append(r.read(r.length()))
    query = lambda index, rotation: frame(uint(index)) + frame(rotation.to_bytes(4, 'little', signed=True))
    if variant == 'public-only':
        fields[17] = seq([query(0, 0), query(0, 2)])
    elif variant == 'multi':
        fields[15] = uint(3)
        fields[18] = seq([query(i, 0) for i in range(3)])
        fields[22] = seq([frame(uint(kind)) + frame(uint(i))
                              for kind, i in [(0, 0), (0, 1), (0, 2), (2, 0)]])
        lookup = (frame(seq([expr([(2, uint(0))])])) +
                  frame(seq([expr([(1, uint(0))])])))
        fields[23] = seq([lookup, lookup])
    elif variant != 'ordinary':
        raise ValueError(variant)
    d = modules['descriptor'].Descriptor.decode(frame_descriptor(fields, modules['codec']), 2)
    curve, m = d.curve, d.curve.scalar
    delta = pow(5, 1 << 32, m)
    sigma = [curve.add(curve.multiply(params.g[1], pow(delta, j, m)), params.w)
             for j in range(len(d['permutation']))]
    fixed_point = curve.add(params.lagrange[0], params.w)
    key = b'\x02' + uint(6) + b'\0' + uint(1) + b''.join(curve.encode(p) for p in [fixed_point, *sigma])
    modules['verify'].key_points(d, key)
    fixed = [1] + [0]*(d.n-1)
    columns = [fixed] + [[pow(delta, j, m) * pow(curve.omega(6), i, m) % m
                          for i in range(d.n)] for j in range(len(sigma))]
    original = (b'PIPAPK01' + d.digest + uint(len(key)) + key + bytes(32) +
                b''.join(uint(v, 32) for column in columns for v in column))
    setup = PublicSetup.decode(original, d, key, hashlib.sha256(original).hexdigest())
    return d, key, raw_params, params, setup, original

def source_cases():
    """Pinned repository small originals only, never a development output."""
    modules = reference(OUTPUT/'source-reference')
    fixture = json.loads((ROOT/'fixtures/native_prover/reference_v1.json').read_text())
    return {(tag, variant):setup_case(tag, modules, fixture, variant) for tag in (0,1)
            for variant in ('ordinary', 'public-only', 'multi')}


class GenericKnownLog(unittest.TestCase):
    verified_toy_proofs = 0
    @classmethod
    def setUpClass(cls):
        require(OUTPUT is not None, 'explicit fresh output required')
        cls.sources = source_cases()
        cls.families, _ = build_families(OUTPUT/'families')
        cls.baselines = {tag:toy_case(OUTPUT/f'baseline-{tag}',tag,cls.families[tag])
                         for tag in (0,1)}
        cls.cases, cls.proofs, cls.chosen, cls.coins = {}, {}, {}, {}
        for identity, (d, key, _, _, _, original) in cls.sources.items():
            tag, variant = identity
            chosen = cls.families[tag]
            cls.chosen[identity] = chosen
            pins = {'descriptor':sha(d.raw), 'key':sha(key), 'original':sha(original)}
            case = make_case(OUTPUT/f'{tag}-{variant}', d.raw, key, original, pins, chosen)
            cls.cases[identity] = case
            cls.coins[identity] = CountedCoins(919+tag)
            cls.proofs[identity] = simulate(case, [[1]], cls.coins[identity])
            cls.verified_toy_proofs += 1

    def failed_rebind(self, name, *, original=None, key=None, descriptor=None, chosen=None, pins=None):
        d, old_key, _, _, _, old_original = self.sources[0, 'ordinary']
        return make_case(OUTPUT/('refusal-'+name), d.raw if descriptor is None else descriptor,
            old_key if key is None else key, old_original if original is None else original,
            {'descriptor':sha(d.raw), 'key':sha(old_key), 'original':sha(old_original)} if pins is None else pins,
            self.chosen[0, 'ordinary'] if chosen is None else chosen)

    def test_six_complete_fixed_rp57_cases(self):
        for identity, case in self.cases.items():
            args, result, metadata = self.proofs[identity]
            with self.subTest(identity=identity):
                self.assertEqual(case.verifier.verify(**args), result)
                self.assertIs(case.verifier.Transcript, case.transcript.Transcript)
                self.assertTrue(metadata['fixed_poseidon'])
                self.assertEqual(metadata['oracle_programs'], 0)
                self.assertEqual(len(result.rounds), 6)

    def test_ordinary_bytes_match_frozen_known_log_simulator(self):
        for tag in (0, 1):
            prior = self.baselines[tag]
            golden = json.loads((HERE/'control_goldens.json').read_text())['cases'][f'{tag}-ordinary']
            case = self.cases[tag, 'ordinary']
            self.assertEqual(case.raw_params, prior.raw_params)
            self.assertEqual(case.descriptor.raw, prior.descriptor.raw)
            self.assertEqual(case.key, prior.key)
            self.assertEqual(sha(self.proofs[tag, 'ordinary'][0]['proof']), golden['proof_sha256'])

    def test_rebinding_preserves_exact_relation_tables_and_originals(self):
        for identity, case in self.cases.items():
            d, key, _, _, old_setup, original = self.sources[identity]
            receipt = json.loads((case.directory/'rebind-receipt.json').read_text())
            self.assertEqual((case.directory/'historical-public-original.bin').read_bytes(), original)
            self.assertEqual((case.directory/'historical-descriptor.norito').read_bytes(), d.raw)
            self.assertEqual((case.directory/'historical-vk.bin').read_bytes(), key)
            self.assertEqual(case.public_setup.fixed, old_setup.fixed)
            self.assertEqual(case.public_setup.sigma, old_setup.sigma)
            self.assertEqual(case.public_setup.copy_digest, old_setup.copy_digest)
            self.assertNotEqual(case.descriptor['params_digest'], d['params_digest'])
            self.assertEqual({k:v for k,v in case.descriptor.values.items() if k != 'params_digest'},
                             {k:v for k,v in d.values.items() if k != 'params_digest'})
            self.assertTrue(receipt['same_copy_digest_and_selector_bytes'])

    def test_public_only_values_are_not_sampled(self):
        for tag in (0, 1):
            case = self.cases[tag, 'public-only']
            record = self.proofs[tag, 'public-only'][2]
            d, m, at = case.descriptor, case.descriptor.curve.scalar, record['opening_point']
            _, _, slots, _, membership = case.verifier.opening_shape(d)
            self.assertTrue(record['public_only_sets'])
            for index in record['public_only_sets']:
                expected = 0
                for family, column in (slot for slot in slots if membership[slot] == index):
                    if family == 'fixed':
                        # The fixture's one fixed polynomial is L_0.
                        self.assertEqual(column, 0)
                        value = (pow(at, d.n, m)-1)*pow(d.n*(at-1), -1, m) % m
                    else:
                        self.assertEqual(family, 'sigma')
                        value = pow(pow(5, 1 << 32, m), column, m)*at % m
                    expected = (expected*record['grouping_challenge']+value) % m
                self.assertEqual(record['point_set_evaluations'][index], expected)

    def test_multiple_products_lookups_and_all_point_logs(self):
        for tag in (0, 1):
            case = self.cases[tag, 'multi']
            self.assertEqual(case.descriptor.permutation_sets, 2)
            self.assertEqual(len(case.descriptor['lookups']), 2)
        for identity, case in self.cases.items():
            for row in self.proofs[identity][2]['derived_logs'].values():
                curve = case.descriptor.curve
                point = curve.decode(bytes.fromhex(row['point']), identity=True)
                self.assertTrue(curve.equal(point, curve.multiply(case.base, row['log'])))

    def test_scalar_ifft_matches_direct_transform(self):
        for tag in (0, 1):
            curve = self.cases[tag, 'ordinary'].descriptor.curve
            self.assertEqual(scalar_ifft((11,), curve, 0), (11,))
            for k in (2, 4, 6):
                n, m, omega = 1 << k, curve.scalar, curve.omega(k)
                values = tuple((i*i+11) % m for i in range(n))
                expected = tuple(sum(values[i]*pow(omega, (-i*j) % n, m) for i in range(n))*
                                 pow(n, -1, m) % m for j in range(n))
                self.assertEqual(scalar_ifft(values, curve, k), expected)
            for values, k in [([0]*4, 3), ([curve.scalar]*4, 2), ([0], -1), ([0], 17)]:
                with self.assertRaises(ValueError):
                    scalar_ifft(values, curve, k)

    def test_original_pin_and_public_binding_refusals(self):
        d, key, _, _, _, original = self.sources[0, 'ordinary']
        for name, kwargs in [('descriptor', {'descriptor':d.raw[:-1]}),
                             ('key', {'key':key[:-1]}), ('original', {'original':original[:-1]})]:
            with self.assertRaisesRegex(ValueError, 'pinned original'):
                self.failed_rebind('pin-'+name, **kwargs)
        changed = original[:8]+bytes(32)+original[40:]
        pins = {'descriptor':sha(d.raw), 'key':sha(key), 'original':sha(changed)}
        with self.assertRaisesRegex(ValueError, 'descriptor binding'):
            self.failed_rebind('pk-header', original=changed, pins=pins)
        case = self.cases[0, 'ordinary']
        foreign = case.key[:10]+case.descriptor.curve.encode(case.params.u)+case.key[42:]
        with self.assertRaisesRegex(ValueError, 'public setup binding'):
            simulate(replace(case, key=foreign), [[1]], random.Random(919))

    def test_wrong_chosen_logs_and_wire_refuse(self):
        original = self.chosen[0, 'ordinary']
        for name in ('g', 'lagrange', 'w'):
            logs = dict(original.logs)
            if name in ('g', 'lagrange'):
                logs[name] = (0,)+logs[name][1:]
            else:
                logs[name] = 0
            with self.assertRaisesRegex(ValueError, 'finite canonical'):
                self.failed_rebind('log-'+name, chosen=SimpleNamespace(**dict(vars(original), logs=logs)))
        logs = dict(original.logs);logs['lagrange'] = logs['lagrange'][1:]+logs['lagrange'][:1]
        with self.assertRaisesRegex(ValueError, 'Lagrange IFFT'):
            self.failed_rebind('lagrange-order', chosen=SimpleNamespace(**dict(vars(original), logs=logs)))
        raw = original.raw[:-1]+bytes([original.raw[-1]^1])
        with self.assertRaisesRegex(ValueError, 'raw parameters'):
            self.failed_rebind('wire', chosen=SimpleNamespace(**dict(vars(original), raw=raw)))

    def test_c_f_generator_and_instance_mutations(self):
        for identity, case in self.cases.items():
            args, result, record = self.proofs[identity]
            proof, curve, m = args['proof'], case.descriptor.curve, case.descriptor.curve.scalar
            for offset, value in [(64, record['f']), (96, record['c'])]:
                raw = proof[:-offset]+((value+1) % m).to_bytes(32, 'little')+proof[-offset+32:]
                with self.assertRaisesRegex(ValueError, 'IPA group equation'):
                    case.verifier.verify(**dict(args, proof=raw))
            foreign = case.params.w if not curve.equal(case.params.w, result.generator) else case.params.u
            self.assertFalse(curve.equal(foreign, result.generator))
            with self.assertRaisesRegex(ValueError, 'generator decision'):
                case.verifier.verify(**dict(args, proof=proof[:-32]+curve.encode(foreign)))
            with self.assertRaises(ValueError):
                case.verifier.verify(**dict(args, instances=[[2]]))

    def test_reference_copy_and_authority_are_explicit(self):
        original = json.loads((ROOT/'fixtures/native_prover/kats_v1.json').read_text())
        for case in self.cases.values():
            for role in ('historical-reference', 'chosen-reference'):
                directory = case.directory/role
                receipt = json.loads((directory/'copy-receipt.json').read_text())
                self.assertIsNone(receipt['exact_k16_descriptor'])
                self.assertTrue(all(row['before_sha256'] == row['after_sha256']
                                    for row in receipt['source_changes']))
                package = next(path for path in directory.iterdir() if path.is_dir())
                for name in MODULES:
                    self.assertEqual((package/name).read_bytes(), (REFERENCE/name).read_bytes())
            selected = json.loads((case.directory/'chosen-reference/kats_v1.json').read_text())
            self.assertEqual({k:v for k,v in selected.items() if k != 'params_ipa'},
                             {k:v for k,v in original.items() if k != 'params_ipa'})
            old_descriptor = next(module for name,module in sys.modules.items()
                                  if name.endswith('.descriptor') and
                                  str(case.directory/'historical-reference') in str(getattr(module,'__file__','')))
            with self.assertRaisesRegex(ValueError, 'descriptor parameter identity'):
                old_descriptor.Descriptor.decode(case.descriptor.raw, 2)

    def test_k16_exception_is_not_general_admission(self):
        d, key, _, _, _, original = self.sources[0, 'ordinary']
        codec = next(module for name,module in sys.modules.items()
                     if name.endswith('.codec') and
                     str(self.cases[0, 'ordinary'].directory/'historical-reference') in str(getattr(module,'__file__','')))
        cursor, fields = codec.descriptor_frame(d.raw, 2), []
        while cursor.position < len(cursor.data):
            fields.append(cursor.read(cursor.length()))
        fields[5] = bytes([16])
        payload = b''.join(map(frame, fields))
        changed = d.raw[:23]+uint(len(payload),8)+uint(codec.crc64(payload),8)+b'\x02'+payload
        pins = {'descriptor':sha(changed), 'key':sha(key), 'original':sha(original)}
        with self.assertRaisesRegex(ValueError, 'reference domain exponent'):
            self.failed_rebind('foreign-k16', descriptor=changed, pins=pins)

    def test_finite_draws_and_output_reuse_refuse(self):
        class Exhausted:
            count = 0
            def getrandbits(self, bits):
                self.count += 1
                return (1 << bits)-1
        rng = Exhausted()
        with self.assertRaisesRegex(ValueError, 'sampler exhausted'):
            draw(17, rng)
        self.assertEqual(rng.count, 128)
        with self.assertRaisesRegex(ValueError, 'fresh proof output'):
            simulate(self.cases[0, 'ordinary'], [[1]], random.Random(919))
        d, key, _, _, _, original = self.sources[0, 'ordinary']
        with self.assertRaises(FileExistsError):
            make_case(self.cases[0, 'ordinary'].directory, d.raw, key, original,
                      {'descriptor':sha(d.raw), 'key':sha(key), 'original':sha(original)},
                      self.chosen[0, 'ordinary'])



    def test_public_table_interpolation_matches_polynomial(self):
        for tag in (0,1):
            curve = self.cases[tag,'ordinary'].descriptor.curve
            for k in (2,4,6):
                n,m,omega = 1 << k,curve.scalar,curve.omega(k)
                coeffs = [(j*j+9) % m for j in range(min(n,9))]
                polynomial = lambda at:sum(c*pow(at,j,m) for j,c in enumerate(coeffs)) % m
                rows = [polynomial(pow(omega,i,m)) for i in range(n)]
                for at in (0,3,77,1,pow(omega,n-1,m)):
                    w = weights(k,curve,at)
                    self.assertEqual(len(w),n)
                    self.assertEqual(sum(w) % m,1)
                    self.assertEqual(sum(a*b for a,b in zip(w,rows)) % m,polynomial(at))

    def test_public_table_extent_binding_and_canonicality(self):
        d,key,_,_,setup,raw = self.sources[0,'ordinary']
        self.assertEqual(setup.copy_digest,bytes(32))
        for changed,error in [(raw[:-1],'extent'),(raw+b'\0','extent'),
                              (b'X'+raw[1:],'descriptor'),(raw[:8]+bytes(32)+raw[40:],'descriptor'),
                              (raw[:40]+uint(len(key)+1)+raw[44:],'key'),
                              (raw[:44]+b'X'+raw[45:],'key'),
                              (raw[:-32]+uint(d.curve.scalar,32),'canonical scalar')]:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError,error):
                PublicSetup.decode(changed,d,key,sha(changed))
        with self.assertRaisesRegex(ValueError,'digest'):
            PublicSetup.decode(raw,d,key,'0'*64)
        case = self.cases[0,'ordinary']
        with self.assertRaisesRegex(ValueError,'public setup binding'):
            simulate(replace(case,public_original=case.public_original+b'changed'),[[1]],random.Random(1))

    def test_public_table_query_rejections(self):
        setup = self.sources[0,'ordinary'][4]
        for slot in [('advice',0),('fixed',-1),('sigma',99)]:
            with self.assertRaises(ValueError):setup.at(29,[slot])
        curve = setup.descriptor.curve
        for k,at in [(0,1),(17,1),(6,-1),(6,curve.scalar)]:
            with self.assertRaises(ValueError):weights(k,curve,at)

    def test_simulated_draw_budget_and_default_owner_caps(self):
        from .requests import Owner
        owner = Owner(OUTPUT/'budget-owner')
        for identity,case in self.cases.items():
            budget = sample_budget(case)
            record = self.proofs[identity][2]
            self.assertEqual(record['simulated_draw_budget'],budget)
            self.assertEqual(len(self.proofs[identity][0]['proof']),budget['expected_proof_bytes'])
            self.assertLessEqual(self.coins[identity].calls,budget['source_calls_max'])
            self.assertGreaterEqual(self.coins[identity].calls,budget['scalar_samples_max']-1)
            self.assertLessEqual(budget['source_calls_max'],128*(10000//32))
            self.assertGreaterEqual(owner.per_request_draws,budget['source_calls_max'])
        self.assertGreaterEqual(owner.per_request_draws,128*(10000//32))
        self.assertGreaterEqual(owner.total_draws,8*128*(10000//32))
        self.assertEqual(sample_budget(self.cases[0,'ordinary'])['scalar_samples_max'],36)
        self.assertFalse(sample_budget(self.cases[0,'ordinary'])['native_polynomial_draws_counted'])

    def test_large_rebinding_and_simulation_require_pre_io_opt_in(self):
        from . import rebind
        from .requests import Owner
        d,key,_,_,_,original = self.sources[0,'ordinary']
        chosen = SimpleNamespace(**dict(vars(self.chosen[0,'ordinary']),k=16))
        directory = OUTPUT/'unadmitted-large'
        with patch.object(rebind,'reference',side_effect=RuntimeError('unexpected private reference')):
            with self.assertRaisesRegex(ValueError,'large historical rebind'):
                rebind.make_case(directory,d.raw,key,original,
                    {'descriptor':sha(d.raw),'key':sha(key),'original':sha(original)},chosen)
        self.assertFalse(directory.exists())
        with self.assertRaisesRegex(ValueError,'large reference'):
            rebind.reference(directory,'0'*64)
        self.assertFalse(directory.exists())
        for digest in (b'0'*64, 7, '0'*63, '0'*65, 'A'*64, 'g'*64, "'"+'0'*63):
            with patch.object(rebind,'sha',side_effect=RuntimeError('unexpected descriptor hash')):
                with self.assertRaisesRegex(ValueError,'canonical exact descriptor digest'):
                    rebind.reference(directory,digest,allow_large=True)
            self.assertFalse(directory.exists())
        for tag,k in ((0,7),(0,16),(1,16)):
            with patch.object(rebind,'sha',side_effect=RuntimeError('unexpected authority hash')):
                with self.assertRaisesRegex(ValueError,'large reference authority'):
                    rebind.reference(directory,parameter_authority=(tag,k,b''))
            self.assertFalse(directory.exists())
        for authority,error in (((0,6,b''),'extent'), ((True,6,b''),'private authority'),
                                ((0,True,b''),'private authority'), ((2,6,b''),'private authority'),
                                ((0,6),'shape')):
            with patch.object(rebind,'sha',side_effect=RuntimeError('unexpected authority hash')):
                with self.assertRaisesRegex(ValueError,error):
                    rebind.reference(directory,parameter_authority=authority)
            self.assertFalse(directory.exists())
        case = replace(self.cases[0,'ordinary'],descriptor={'k':16})
        with self.assertRaisesRegex(ValueError,'large simulation'):
            simulate(case,[[1]],random.Random(1))
        owner = Owner(OUTPUT/'large-owner')
        with self.assertRaisesRegex(ValueError,'large simulation'):
            owner.submit(b'large',case,[[1]])
        self.assertEqual(owner.draws,0)
        self.assertEqual(owner.records,{})
