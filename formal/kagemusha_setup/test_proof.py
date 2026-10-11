"""Small raw-setup/fixed-Poseidon algebra controls; execution awaits review."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import itertools
import json
import random
from pathlib import Path
import sys
import unittest

from .case import HERE, MODULES, REFERENCE, ROOT, checked_sources, draw, make_case, require, build_families
from .simulator import folded_coefficient, rank_collapsed, simulate

OUTPUT = None


def original_reference():
    """Load repository authority unchanged in an additional isolated namespace."""
    name = '_raw_setup_control_original_reference'
    require(name not in sys.modules, 'original comparison already loaded')
    spec = importlib.util.spec_from_file_location(name, REFERENCE/'__init__.py',
                                                  submodule_search_locations=[str(REFERENCE)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return (importlib.import_module(name+'.parameters'),
            importlib.import_module(name+'.descriptor'))


class ProofControls(unittest.TestCase):
    verified_toy_proofs = 0

    @classmethod
    def setUpClass(cls):
        cls.cases, cls.proofs = {}, {}
        require(OUTPUT is not None, 'explicit fresh output required')
        cls.family_data, cls.family_observation = build_families(OUTPUT/'families')
        for tag in (0, 1):
            for contradictory in (False, True):
                identity = (tag, contradictory)
                directory = OUTPUT/('%d-%s' % (tag, 'contradictory' if contradictory else 'ordinary'))
                cls.cases[identity] = make_case(directory, tag, cls.family_data[tag], contradictory)
                # Common seed within each curve deliberately compares the two relation
                # examples under common diagnostic coins; not a multi-request RNG policy.
                cls.proofs[identity] = simulate(cls.cases[identity], [[1]], random.Random(919+tag))
                cls.verified_toy_proofs += 1
        cls.original_parameters, cls.original_descriptor = original_reference()

    def test_one_raw_family_per_curve_reused_across_relations(self):
        self.assertEqual(self.family_observation['unique_contexts'], 132)
        self.assertEqual(self.family_observation['setup_sampler_calls'], 132)
        self.assertEqual(self.family_observation['raw_entries'], 397)
        for tag in (0, 1):
            first, second = self.cases[tag, False], self.cases[tag, True]
            self.assertEqual(first.raw_params, second.raw_params)
            self.assertEqual(first.raw_params, self.family_data[tag].raw)
            self.assertEqual(first.base, second.base)
            self.assertEqual(first.logs, second.logs)

    def test_migrated_control_bytes_match_retained_diagnostic(self):
        golden = json.loads((HERE/'control_goldens.json').read_text())
        self.assertEqual(golden['schema'], 'kagemusha.setup.control-goldens.v1')
        self.assertEqual(set(golden['cases']), {'0-ordinary', '0-contradictory', '1-ordinary', '1-contradictory'})
        for identity, case in self.cases.items():
            tag, contradictory = identity
            name = '%d-%s' % (tag, 'contradictory' if contradictory else 'ordinary')
            expected = golden['cases'][name]
            proof = self.proofs[identity][0]['proof']
            self.assertEqual(hashlib.sha256(proof).hexdigest(), expected['proof_sha256'])
            self.assertEqual(len(proof), expected['proof_bytes'])
            self.assertEqual(hashlib.sha256(case.raw_params).hexdigest(), expected['parameter_sha256'])

    def test_full_fixed_poseidon_verifier_both_curves_and_relations(self):
        for identity, case in self.cases.items():
            args, result, record = self.proofs[identity]
            with self.subTest(identity=identity):
                self.assertEqual(case.verifier.verify(**args), result)
                self.assertIs(case.verifier.Transcript, case.transcript.Transcript)
                self.assertEqual(record['oracle_programs'], 0)
                self.assertTrue(record['fixed_poseidon'])
                self.assertEqual(len(result.rounds), 6)
                self.assertEqual(record['opening_sets'], [[0], [0, 1], [0, 2]])
                self.assertEqual(record['proof_bytes'], 1312)
                self.assertEqual(record['contradictory'], identity[1])

    def test_verifier_sources_and_poseidon_constants_unchanged(self):
        original = json.loads((ROOT/'fixtures/native_prover/kats_v1.json').read_text())
        for case in self.cases.values():
            toy = json.loads((case.directory/'kats_v1.json').read_text())
            for name in MODULES:
                self.assertEqual((case.directory/case.package/name).read_bytes(),
                                 (REFERENCE/name).read_bytes())
            self.assertNotEqual(toy['params_ipa'], original['params_ipa'])
            self.assertEqual({k: v for k, v in toy.items() if k != 'params_ipa'},
                             {k: v for k, v in original.items() if k != 'params_ipa'})
            self.assertEqual(case.transcript.KATS, toy)

    def test_current_pinned_authority_refuses_toy_setup(self):
        for case in self.cases.values():
            with self.assertRaisesRegex(ValueError, 'unpinned parameters'):
                self.original_parameters.Parameters.decode(case.raw_params,
                                                            case.descriptor.curve, 6)
            with self.assertRaisesRegex(ValueError, 'descriptor parameter identity'):
                self.original_descriptor.Descriptor.decode(case.descriptor.raw, 2)
            changed = case.raw_params[:-1]+bytes([case.raw_params[-1] ^ 1])
            with self.assertRaisesRegex(ValueError, 'unpinned parameters'):
                case.parameters.Parameters.decode(changed, case.descriptor.curve, 6)

    def test_setup_lagrange_and_every_derived_point_log(self):
        for identity, case in self.cases.items():
            curve, m = case.descriptor.curve, case.descriptor.curve.scalar
            roots = [pow(curve.omega(6), i, m) for i in range(64)]
            for i, value in enumerate(case.logs['g']):
                # Forward DFT of the independently constructed IFFT coefficients.
                self.assertEqual(sum(case.logs['lagrange'][j]*pow(roots[j], i, m)
                                     for j in range(64)) % m, value)
            for row in self.proofs[identity][2]['derived_logs'].values():
                point = curve.decode(bytes.fromhex(row['point']), identity=True)
                self.assertTrue(curve.equal(point, curve.multiply(case.base, row['log'])))
            self.assertEqual(set(self.proofs[identity][2]['derived_logs']) &
                             {'h_combined', 'qprime', 'opening', 'S', 'ipa_lhs', 'folded_G'},
                             {'h_combined', 'qprime', 'opening', 'S', 'ipa_lhs', 'folded_G'})

    def test_f_c_generator_and_instance_mutations_rejected(self):
        for identity, case in self.cases.items():
            args, result, record = self.proofs[identity]
            proof, curve, m = args['proof'], case.descriptor.curve, case.descriptor.curve.scalar
            for offset, scalar in [(64, record['f']), (96, record['c'])]:
                changed = dict(args)
                changed['proof'] = proof[:-offset] + ((scalar+1) % m).to_bytes(32, 'little') + proof[-offset+32:]
                with self.subTest(identity=identity, scalar_offset=offset), self.assertRaisesRegex(ValueError, 'IPA group equation'):
                    case.verifier.verify(**changed)
            foreign = case.params.w
            if curve.equal(foreign, result.generator):
                foreign = case.params.u
            self.assertFalse(curve.equal(foreign, result.generator))
            changed = dict(args, proof=proof[:-32]+curve.encode(foreign))
            with self.assertRaisesRegex(ValueError, 'generator decision'):
                case.verifier.verify(**changed)
            changed = dict(args, instances=[[2]])
            with self.assertRaises(ValueError):
                case.verifier.verify(**changed)

    def test_relation_examples_have_declared_meaning(self):
        for tag in (0, 1):
            ordinary = self.cases[tag, False].descriptor
            contradictory = self.cases[tag, True].descriptor
            row_zero = ([1], [1], [1])
            self.assertEqual([ordinary.expression(e, row_zero) for gate in ordinary['gates'] for e in gate], [0])
            self.assertEqual([contradictory.expression(e, row_zero) for gate in contradictory['gates'] for e in gate], [0, contradictory.curve.scalar-1])
            # At row zero the two contradictory equations are a-1=0 and a-2=0.
            # Their difference is the nonzero constant one for every possible a.
            for advice in (0, 1, 2, 17, contradictory.curve.scalar-1):
                values = ([1], [advice], [1])
                equations = [contradictory.expression(e, values) for gate in contradictory['gates'] for e in gate]
                self.assertEqual((equations[0]-equations[1]) % contradictory.curve.scalar, 1)

    def test_rank_collapse_algebra_without_forcing_poseidon(self):
        # F17 is only an exhaustive linear algebra control, not a transcript field.
        m, k = 17, 2
        for at in (1, 2, 3):
            collapsed = [pow(pow(at, 1 << (k-1-j), m), -1, m) for j in range(k)]
            self.assertTrue(rank_collapsed(collapsed, at, m))
            for tail in itertools.product(range(m), repeat=3):
                constant = -sum(value*pow(at, j+1, m) for j, value in enumerate(tail)) % m
                self.assertEqual(folded_coefficient([constant, *tail], collapsed, m), 0)
            changed = [collapsed[0], collapsed[1] % (m-1)+1]
            self.assertFalse(rank_collapsed(changed, at, m))
            # A nonzero linear map from K_at has all field elements in its image.
            images = set()
            for tail in itertools.product(range(m), repeat=3):
                constant = -sum(value*pow(at, j+1, m) for j, value in enumerate(tail)) % m
                images.add(folded_coefficient([constant, *tail], changed, m))
            self.assertEqual(images, set(range(m)))

    def test_bounded_sampling_and_existing_output_refusal(self):
        class Exhausted:
            count = 0
            def getrandbits(self, bits):
                self.count += 1
                return (1 << bits)-1
        rng = Exhausted()
        with self.assertRaisesRegex(ValueError, 'sampler exhausted'):
            draw(17, rng)
        self.assertEqual(rng.count, 128)
        with self.assertRaises(FileExistsError):
            make_case(self.cases[0, False].directory, 0, self.family_data[0])

