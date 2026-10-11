"""Small algebra/KAT controls; no release setup or security qualification."""
import json
import random
import unittest

from .preimage import ROOT, Swu, quadratic, roots
from ..kagemusha_pasta import auxiliary as arithmetic


class PreimageTests(unittest.TestCase):
    """Independent retained vectors and exact finite-field falsification cases."""

    def test_literal_extent_and_rejection(self):
        self.assertEqual(arithmetic.limbs('1, 0, 0, 0,'), 1)
        for body in ('1, 2', '1 << 3, 0, 0, 0', '-1, 0, 0, 0'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                arithmetic.limbs(body)

    def test_all_quadratics_over_small_prime(self):
        p = 17
        for a in range(p):
            for b in range(p):
                for c in range(p):
                    if a == b == c == 0:
                        with self.assertRaises(ValueError):
                            quadratic(a, b, c, p)
                    else:
                        expected = tuple(x for x in range(p) if (a*x*x + b*x + c) % p == 0)
                        self.assertEqual(quadratic(a, b, c, p), expected)
        self.assertEqual(roots(0, p), (0,))
        self.assertEqual(roots(3, p), ())

    def test_actual_hash_to_curve_originals(self):
        kats = json.loads((ROOT / 'fixtures/native_prover/kats_v1.json').read_text())
        for tag in (0, 1):
            model = Swu(tag)
            originals = kats['generators'][model.curve.name]
            messages = [(bytes([0]) + i.to_bytes(4, 'little'), expected)
                        for i, expected in enumerate(originals['g'])]
            messages += [(bytes([1]), originals['w']), (bytes([2]), originals['u'])]
            self.assertEqual(len(messages), 66)
            for message, expected in messages:
                with self.subTest(curve=tag, message=message.hex()):
                    actual = model.curve.encode(model.hash_to_curve(message)).hex()
                    self.assertEqual(actual, expected)

    def test_source_single_map_inverse_contains_every_original(self):
        for tag in (0, 1):
            model = Swu(tag)
            rng = random.Random(2026100901 + tag)
            values = [0, 1, 2, 3, 7, 42, model.p-1, model.p-2]
            values += [rng.getrandbits(256) % model.p for _ in range(32)]
            for u in values:
                with self.subTest(curve=tag, u=u):
                    point = model.forward(u)
                    fiber = model.inverse(point)
                    self.assertIn(u, fiber)
                    self.assertEqual(fiber, tuple(sorted(set(fiber))))
                    self.assertLessEqual(len(fiber), 9)
                    for member in fiber:
                        self.assertEqual(model.forward(member), point)
            self.assertEqual(model.inverse(None), ())
            self.assertEqual(model.forward(0)[0], model.b * pow(model.a*model.z, -1, model.p) % model.p)
            with self.assertRaises(ValueError):
                model.forward(model.p)
            with self.assertRaises(ValueError):
                model.inverse((model.p, 0))

    def test_auxiliary_group_and_isogeny_known_log_route(self):
        for tag in (0, 1):
            model = Swu(tag)
            point = model.forward(1)
            base = model.isogeny(point)
            self.assertNotEqual(base[2], 0)
            self.assertIsNone(model.add(point, model.negate(point)))
            self.assertEqual(model.add(point, None), point)
            self.assertEqual(model.add(None, point), point)
            for scalar in (0, 1, 2, 3, 17, model.curve.scalar-1, model.curve.scalar):
                with self.subTest(curve=tag, scalar=scalar):
                    source = model.multiply(point, scalar)
                    expected = model.curve.multiply(base, scalar)
                    self.assertTrue(model.curve.equal(model.isogeny(source), expected))
            # The actual auxiliary point has prime-order torsion behavior.
            self.assertIsNone(model.multiply(point, model.curve.scalar))

