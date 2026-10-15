"""Fast current-reference algebra and codec checks, without a generated proof corpus.

Synthetic descriptors/parameters below are local equation inputs only. No test
claims a genuine proof or bypasses the public parameter admission boundary.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'fixtures/native_prover'))

from reference_verifier import InvalidProof
from reference_verifier.curve import Curve, IDENTITY, P, Q
from reference_verifier.descriptor import Descriptor
from reference_verifier.parameters import Parameters, _decide
from reference_verifier.transcript import (
    KATS, Transcript, evaluation_challenge, multiopening_challenge, nonzero_challenge,
)
from reference_verifier.verify import evaluate_constraints, key_points, norm_factor
import verify_reference_v1


def descriptor(tag=0, degree=6):
    """Small in-memory expression subject; never a full-proof admission input."""
    curve = Curve(tag)
    params = next(row for row in KATS['params_ipa'][curve.name] if row['k'] == 6)
    values = dict(
        protocol_version=1, curve=tag,
        base_modulus=curve.base.to_bytes(32, 'little'),
        scalar_modulus=curve.scalar.to_bytes(32, 'little'),
        params_digest=bytes.fromhex(params['sha256']), k=6, transcript=0,
        instance_mode=0, proof_suffix=0, degree=degree, blinding_factors=5,
        permutation_chunk_len=(degree - 2) // 2, quotient_pieces=degree - 1,
        lookup_kind=0, num_fixed_columns=0, num_advice_columns=0,
        instance_lengths=[], fixed_queries=[], advice_queries=[], instance_queries=[],
        selectors=(0, 0, []), gates=[], permutation=[], lookups=[], instance_types=None,
    )
    return Descriptor(b'', 1, values)


def masks(subject, x):
    """Independent explicit domain polynomials for the tiny equation controls."""
    m, n = subject.curve.scalar, subject.n
    omega = subject.curve.omega(subject['k'])
    xn = pow(x, n, m)

    def at(row):
        point = pow(omega, row, m)
        return point * (xn - 1) * pow(n * (x - point), -1, m) % m

    first, last = at(0), at(subject.usable)
    active = (1 - last - sum(at(row) for row in range(subject.usable + 1, n))) % m
    return first, last, active, xn


class CurrentReferenceRoles(unittest.TestCase):
    """The role-map ranges and collisions prescribed by the current protocol."""

    def test_total_maps_cover_raw_zero_and_have_the_declared_images(self):
        for m in (P, Q):
            self.assertEqual(pow(5, (m - 1) // 2, m), m - 1)
            for raw in (0, 1, 2, 5, 17, 2**128 - 1, m - 2, m - 1):
                x = evaluation_challenge(raw, m)
                x3 = multiopening_challenge(raw, m)
                self.assertNotEqual(nonzero_challenge(raw, m), 0)
                self.assertEqual(pow(x, (m - 1) // 2, m), m - 1)
                self.assertEqual(pow(x3, (m - 1) // 2, m), 1)
                self.assertNotEqual(pow(x3, (m - 1) // 4, m), 1)
                self.assertNotEqual(norm_factor(raw, m), 0)
            self.assertEqual(evaluation_challenge(0, m), 5)
            self.assertEqual(multiopening_challenge(0, m), 25)
            self.assertEqual(nonzero_challenge(0, m), 1)

    def test_role_collisions_are_explicit_pushforward_fibers(self):
        for m in (P, Q):
            square_fiber = {0, 1, m - 1}
            self.assertEqual(len(square_fiber), 3)
            self.assertEqual({evaluation_challenge(a, m) for a in square_fiber}, {5})
            fourth_root = pow(5, (m - 1) // 4, m)
            self.assertEqual(pow(fourth_root, 2, m), m - 1)
            fourth_fiber = {0, 1, m - 1, fourth_root, (-fourth_root) % m}
            self.assertEqual(len(fourth_fiber), 5)
            self.assertEqual({multiopening_challenge(a, m) for a in fourth_fiber}, {25})
            self.assertEqual({nonzero_challenge(a, m) for a in (0, 1)}, {1})

    def test_supported_rotations_do_not_create_domain_or_opening_collisions(self):
        for tag in (0, 1):
            curve = Curve(tag)
            m = curve.scalar
            for k in (1, 6, 10, 16, 28):
                root = curve.omega(k)
                self.assertEqual(pow(root, (m - 1) // 4, m), 1)
                for raw in (0, 1, 2, m - 1):
                    x = evaluation_challenge(raw, m)
                    self.assertNotEqual(pow(x, 1 << k, m), 1)
                    for other in (0, 1, 2, m - 1):
                        x3 = multiopening_challenge(other, m)
                        for rotation in (0, 1, -1, -6):
                            self.assertNotEqual(x3, x * pow(root, rotation, m) % m)

    def test_role_helpers_refuse_noncanonical_python_values(self):
        for m in (P, Q):
            for raw in (True, 1.0, -1, m, None, '0'):
                for mapper in (nonzero_challenge, evaluation_challenge, multiopening_challenge):
                    with self.assertRaises(InvalidProof):
                        mapper(raw, m)


class CurrentReferenceEquations(unittest.TestCase):
    """Norm-product and descriptor controls that distinguish the older equations."""

    def test_degree_caps_and_norm_permutation_geometry(self):
        for tag in (0, 1):
            for degree in range(4, 15):
                d = descriptor(tag, degree)
                d.validate()
                d.values['permutation'] = [(0, i) for i in range(13)]
                chunk = (degree - 2) // 2
                self.assertEqual(d.permutation_sets, (13 + chunk - 1) // chunk)
            for degree in (3, 15):
                with self.assertRaisesRegex(InvalidProof, 'degree pieces'):
                    descriptor(tag, degree).validate()
            d = descriptor(tag, 8)
            d.values['permutation_chunk_len'] = 6
            with self.assertRaisesRegex(InvalidProof, 'degree pieces'):
                d.validate()

    def test_lookup_requires_doubled_norm_degree(self):
        for tag in (0, 1):
            d = descriptor(tag, 6)
            d.values.update(num_advice_columns=1, advice_queries=[(0, 0)])
            one = [(2, 0)]
            d.values['lookups'] = [([one], [one])]
            d.validate()
            # Cubic input and linear table require degree ten, not the old six.
            cubic = [(2, 0), (2, 0), (6, None), (2, 0), (6, None)]
            d.values['lookups'] = [([cubic], [one])]
            with self.assertRaisesRegex(InvalidProof, 'lookup degree'):
                d.validate()
            d.values.update(degree=10, permutation_chunk_len=4, quotient_pieces=9)
            d.validate()

    def test_permutation_zero_linear_factor_is_nonzero_norm_and_final_product_one(self):
        for tag in (0, 1):
            d = descriptor(tag)
            d.values.update(permutation=[(0, 0)], advice_queries=[(0, 0)])
            m, x, y = d.curve.scalar, 5, 7
            first, last, active, xn = masks(d, x)
            result = evaluate_constraints(d, [], [0], [], [0], [(0, 1, None)], [],
                                          0, 0, 0, x, xn, y)
            expected = (first * y*y - last * y - 5 * active) * pow(xn - 1, -1, m) % m
            old = first * y*y * pow(xn - 1, -1, m) % m
            self.assertEqual(result, expected)
            self.assertNotEqual(result, old)

    def test_lookup_zero_linear_factors_and_terminal_zero_do_not_disappear(self):
        for tag in (0, 1):
            d = descriptor(tag)
            zero = [(0, bytes(32))]
            d.values['lookups'] = [([zero], [zero])]
            m, x, y = d.curve.scalar, 5, 7
            first, last, active, xn = masks(d, x)
            result = evaluate_constraints(d, [], [], [], [], [], [(0, 1, 0, 0, 0)],
                                          0, 0, 0, x, xn, y)
            expected = (first * y**4 - last * y**3 + 25 * active * y*y) * pow(xn - 1, -1, m) % m
            old = first * y**4 * pow(xn - 1, -1, m) % m
            self.assertEqual(result, expected)
            self.assertNotEqual(result, old)

    def test_selector_reconstruction_uses_cap_seven_inside_degree_fourteen(self):
        for tag in (0, 1):
            d = descriptor(tag, 14)
            entries = [(2, 0, i + 1) for i in range(6)] + [(2, 1, 1), (2, 1, 2)]
            d.values.update(num_fixed_columns=2, selectors=(1, 0, entries))
            point = bytes.fromhex(KATS['generators'][d.curve.name]['g'][0])
            header = b'\x02' + (6).to_bytes(4, 'little') + b'\x01' + (2).to_bytes(4, 'little')
            bitmaps = b''.join((1 << i).to_bytes(8, 'little') for i in range(8))
            fixed, sigmas = key_points(d, header + point * 2 + bitmaps)
            self.assertEqual((len(fixed), len(sigmas)), (2, 0))
            with self.assertRaisesRegex(InvalidProof, 'selector compression reconstruction'):
                key_points(d, header + point * 2 + (b'\x01' + bytes(7)) * 8)


class CurrentReferenceCodec(unittest.TestCase):
    """Scoped identity admission never weakens ordinary points or the decision."""

    def test_only_generator_suffix_accepts_identity_without_absorption(self):
        for tag in (0, 1):
            curve = Curve(tag)
            with self.assertRaisesRegex(InvalidProof, 'identity'):
                curve.decode(bytes(32))
            self.assertEqual(curve.decode_generator(bytes(32)), IDENTITY)
            for raw in (bytes(31), bytes(33), curve.base.to_bytes(32, 'little')):
                with self.assertRaises(InvalidProof):
                    curve.decode_generator(raw)
            for profile in (0, 1, 2):
                reader = Transcript(curve, profile, bytes(32))
                empty = Transcript(curve, profile, b'')
                self.assertEqual(reader.generator(), IDENTITY)
                reader.finish()
                self.assertEqual(reader.squeeze(), empty.squeeze())
                with self.assertRaisesRegex(InvalidProof, 'identity'):
                    Transcript(curve, profile, bytes(32)).point()

    def test_identity_claim_still_obeys_full_group_decision(self):
        for tag in (0, 1):
            curve = Curve(tag)
            g = curve.decode(bytes.fromhex(KATS['generators'][curve.name]['g'][0]))
            # Private unit subject, deliberately not a pinned public parameter set.
            subject = Parameters(curve, 1, (g, curve.multiply(g, -1)), (), g, g, bytes(32))
            self.assertEqual(_decide(subject, bytes(32), [1])[2], 0)
            with self.assertRaisesRegex(InvalidProof, 'generator decision'):
                _decide(subject, bytes(32), [2])
            for rounds in ([0], [curve.scalar], [], [1, 1]):
                with self.assertRaisesRegex(InvalidProof, 'generator claim challenges'):
                    _decide(subject, bytes(32), rounds)

    def test_current_reference_matrix_has_no_oracle_profiles_or_format_fallback(self):
        names = verify_reference_v1.expected_names()
        self.assertEqual(len(names), 46)
        self.assertEqual(sum('/native/' in name for name in names), 8)
        self.assertTrue(all('/oracle/' not in name for name in names))
        with self.assertRaisesRegex(InvalidProof, 'fixture format'):
            verify_reference_v1.check({'format': 'iroha.pipa.reference.v1'})
        rows = [{'name': name} for name in sorted(names)]
        for bad in (rows[:-1], rows[:-1] + [copy.deepcopy(rows[0])]):
            with self.assertRaisesRegex(InvalidProof, 'case (count|identities)'):
                verify_reference_v1.check({'format': 'iroha.native_prover.reference.v1', 'cases': bad})


if __name__ == '__main__':
    unittest.main()
