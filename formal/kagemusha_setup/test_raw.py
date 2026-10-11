"""Small raw-query consistency controls, never a release privacy qualification."""
import random
import unittest

from . import raw_setup as raw

from .raw_setup import (FreshTargetSampler, RawSetupOracle, Refused, SetupWords, Swu,
                     bounded_uniform, dst, input0, input1, input2, lift, recognize0)


class FixedCoins:
    """Chosen public fault-injection words, not a uniform-coin experiment."""
    def __init__(self, value):
        self.value = value

    def getrandbits(self, bits):
        return self.value & ((1 << bits) - 1)


class AdapterTests(unittest.TestCase):
    """Exercise exact grammar, first-raw-query interception and no overwrite."""

    def test_exact_first_input_recognition_and_disjoint_grammars(self):
        messages = (b'\x01', b'\x02', b'\0' + bytes(4), b'\0' + (65535).to_bytes(4, 'little'))
        classes = []
        for tag in (0, 1):
            for msg in messages:
                self.assertEqual(recognize0(input0(tag, msg)), (tag, msg))
            self.assertIsNone(recognize0(input0(tag, b'\x01') + b'\0'))
            self.assertIsNone(recognize0(input0(tag, b'\x01')[:-1]))
            self.assertIsNone(recognize0(bytes(128) + b'\0' + (65536).to_bytes(4, 'little') + bytes([0, 128, 0]) + dst(tag)))
            # Across both curves and three call kinds, lengths/DST/index suffix
            # make these entire variable-prefix languages pairwise disjoint.
            classes.extend([(len(input0(tag, m)), bytes([0, 128, 0]) + dst(tag)) for m in (b'\x01', b'\0'+bytes(4))])
            classes.extend([(len(input1(tag, bytes(64))), b'\x01' + dst(tag)),
                            (len(input2(tag, bytes(64), bytes(64))), b'\x02' + dst(tag))])
        for i, (size, suffix) in enumerate(classes):
            for other_size, other_suffix in classes[i+1:]:
                self.assertTrue(size != other_size or not
                    (suffix.endswith(other_suffix) or other_suffix.endswith(suffix)))

    def test_early_raw_query_allocates_consistent_known_log_answers_both_curves(self):
        coins = random.Random(2026100917)
        sampler = FreshTargetSampler(raw, coins)
        oracle = RawSetupOracle(coins, sampler)
        for tag in (0, 1):
            model = sampler.models[tag]
            base = model.isogeny(model.forward(1))
            for message in (b'\0'+bytes(4), b'\x01', b'\x02'):
                # Deliberately ask primitive b0 first, before any high-level call.
                b0 = oracle.query(input0(tag, message))
                self.assertIn((tag, message), oracle.logs)
                b1 = oracle.query(input1(tag, b0))
                b2 = oracle.query(input2(tag, b0, b1))
                u, v = (int.from_bytes(b, 'big') % model.p for b in (b1, b2))
                point = model.isogeny(model.add(model.forward(u), model.forward(v)))
                self.assertTrue(model.curve.equal(point, model.curve.multiply(base, oracle.logs[(tag, message)])))
                self.assertEqual(oracle.expand(tag, message), (b1, b2))
                self.assertEqual(oracle.query(input0(tag, message)), b0)
        self.assertEqual(len(oracle.logs), 6)
        self.assertEqual(len(oracle.table), 18)

    def test_prefix_reuse_and_unrelated_raw_queries(self):
        coins = random.Random(2026100918)
        oracle = RawSetupOracle(coins, FreshTargetSampler(raw, coins))
        unknown = b'unrelated public raw input'
        original = oracle.query(unknown)
        g0 = b'\0'+bytes(4)
        first = oracle.expand(0, g0)
        count = len(oracle.table)
        for _ in range(4):
            self.assertEqual(oracle.expand(0, g0), first)
            self.assertEqual(oracle.query(unknown), original)
        self.assertEqual(len(oracle.table), count)
        self.assertEqual(set(oracle.logs), {(0, g0)})

    def test_prequeried_inner_input_refuses_without_overwrite(self):
        # Fault injection fixes fresh b0=0 and a declared word pair. This forces
        # the collision branch; it is not a probability/regularity measurement.
        words = SetupWords(0, bytes([7])*64, bytes([9])*64)
        for tag in (0, 1):
            for key in (input1(tag, bytes(64)), input2(tag, bytes(64), words.b1)):
                oracle = RawSetupOracle(FixedCoins(0), lambda _: words)
                prior = oracle.query(key)
                before = dict(oracle.table)
                with self.assertRaisesRegex(Refused, 'occupied XMD'):
                    oracle.query(input0(tag, b'\x01'))
                self.assertEqual(oracle.table, before)
                self.assertEqual(oracle.table[key], prior)
                self.assertEqual(oracle.logs, {})
                with self.assertRaises(Refused):
                    oracle.query(key)

    def test_sampler_failure_and_budget_are_explicit_terminal_outcomes(self):
        coins = random.Random(2026100919)
        oracle = RawSetupOracle(coins, FreshTargetSampler(raw, coins, pair_attempts=0))
        with self.assertRaisesRegex(Refused, 'pair attempts exhausted'):
            oracle.query(input0(0, b'\x01'))
        self.assertEqual(oracle.table, {})
        self.assertEqual(oracle.logs, {})
        oracle = RawSetupOracle(coins, FreshTargetSampler(raw, coins), query_budget=1)
        oracle.query(b'one')
        with self.assertRaisesRegex(Refused, 'query budget'):
            oracle.query(b'two')
        oracle = RawSetupOracle(coins, FreshTargetSampler(raw, coins), setup_budget=0)
        with self.assertRaisesRegex(Refused, 'setup budget'):
            oracle.query(input0(1, b'\x02'))
        self.assertEqual(oracle.table, {})

    def test_identity_is_retained_not_repaired(self):
        coins = random.Random(2026100920)
        for tag in (0, 1):
            model = Swu(tag)
            # Exact native nonzero opposite inputs, without the retired fixed-target sampler.
            words = SetupWords(0, lift(1, model.p, coins), lift(model.p-1, model.p, coins))
            oracle = RawSetupOracle(coins, lambda _: words)
            b1, b2 = oracle.expand(tag, b'\x02')
            u, v = (int.from_bytes(b, 'big') % model.p for b in (b1, b2))
            self.assertIsNone(model.add(model.forward(u), model.forward(v)))
            self.assertEqual(oracle.logs[(tag, b'\x02')], 0)

    def test_lifts_and_canonical_sampler_bounds(self):
        for tag in (0, 1):
            model = Swu(tag)
            coins = random.Random(2026100921 + tag)
            for residue in (0, 1, model.p-1):
                value = lift(residue, model.p, coins)
                self.assertEqual(len(value), 64)
                self.assertEqual(int.from_bytes(value, 'big') % model.p, residue)
            with self.assertRaises(ValueError):
                lift(model.p, model.p, coins)
            with self.assertRaises(Refused):
                lift(0, model.p, coins, 0)
        for upper in (0, -1):
            with self.assertRaises(ValueError):
                bounded_uniform(random.Random(0), upper)
        with self.assertRaises(Refused):
            bounded_uniform(FixedCoins(255), 17, 2)

    def test_changed_xmd_order_and_word_binding_cannot_reuse_selected_log(self):
        coins = random.Random(2026100922)
        oracle = RawSetupOracle(coins, FreshTargetSampler(raw, coins))
        b0 = oracle.query(input0(0, b'\x01'))
        b1 = oracle.query(input1(0, b0))
        b2 = oracle.query(input2(0, b0, b1))
        wrong_key = input2(0, b0, bytes([b1[0]^1])+b1[1:])
        self.assertNotEqual(wrong_key, input2(0, b0, b1))
        wrong = oracle.query(wrong_key)
        self.assertNotEqual(wrong, b2)
        self.assertEqual(oracle.expand(0, b'\x01'), (b1, b2))
        self.assertEqual(set(oracle.logs), {(0, b'\x01')})

