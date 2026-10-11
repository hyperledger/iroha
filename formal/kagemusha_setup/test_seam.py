"""Prepared small controls; do not execute before independent source review."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
from types import SimpleNamespace
import unittest

from . import raw_setup as RAW
from .parameters import ParameterFamily

OUTPUT = None


class Scripted:
    def __init__(self, values):
        self.values, self.calls = iter(values), []

    def getrandbits(self, bits):
        value = next(self.values)
        if not 0 <= value < 1 << bits:
            raise ValueError('invalid scripted word')
        self.calls.append((bits, value))
        return value


class AdditiveModel:
    """F17 bijection for sampler control flow, not an elliptic-curve model."""
    p = 17
    curve = SimpleNamespace(scalar=17)

    def __init__(self):
        self.targets = []

    def forward(self, value):
        return value

    def multiply(self, point, scalar):
        self.targets.append(scalar)
        return point*scalar % self.p

    def add(self, left, right):
        return (left+right) % self.p

    def negate(self, point):
        return -point % self.p

    def inverse(self, point):
        return (point,)


class SeamTests(unittest.TestCase):
    def test_fresh_target_after_ordinary_miss_and_zero_target_retained(self):
        coins = Scripted([1, 2, 8, 0, 4, 0, 0, 0])
        model = AdditiveModel()
        sampler = RAW.FreshTargetSampler(RAW, coins, models=(model, model))
        words = sampler(0)
        self.assertEqual(model.targets, [1, 0])
        self.assertEqual(words.scalar, 0)
        self.assertEqual([int.from_bytes(x, 'big') % 17 for x in (words.b1, words.b2)], [4, 13])
        self.assertEqual(sampler.records[0]['attempts'], 2)
        self.assertEqual(sampler.records[0]['status'], 'returned')

    def test_caps_abort_immediately_without_resampling(self):
        for values, completed in [([31, 31], 0), ([0, 31, 31], 0), ([0, 0, 15, 15], 0)]:
            coins, model = Scripted(values), AdditiveModel()
            sampler = RAW.FreshTargetSampler(RAW, coins, draw_attempts=2, models=(model, model))
            with self.assertRaisesRegex(RAW.Refused, 'canonical draw exhausted'):
                sampler(0)
            self.assertEqual(len(coins.calls), len(values))
            self.assertEqual(len(model.targets), completed)
            self.assertEqual(sampler.records[0]['attempts'], 1)
            self.assertEqual(sampler.records[0]['status'], 'refused')

    def test_pair_cap_retains_failure_and_fresh_attempt_count(self):
        coins, model = Scripted([1, 2, 8, 3, 4, 8]), AdditiveModel()
        sampler = RAW.FreshTargetSampler(RAW, coins, pair_attempts=2, models=(model, model))
        with self.assertRaisesRegex(RAW.Refused, 'pair attempts exhausted'):
            sampler(0)
        self.assertEqual(model.targets, [1, 3])
        self.assertEqual(sampler.records[0]['attempts'], 2)
        self.assertEqual(sampler.records[0]['status'], 'refused')

    def test_small_actual_source_families_and_shared_contexts(self):
        coins = random.Random(2026100941)
        sampler = RAW.FreshTargetSampler(RAW, coins)
        oracle = RAW.RawSetupOracle(coins, sampler, query_budget=256, setup_budget=20)
        family = ParameterFamily(RAW, oracle, sampler)
        retained = {}
        for tag in (0, 1):
            g0 = b'\x00'+bytes(4)
            early = oracle.query(RAW.input0(tag, g0))
            zero = family.derive(tag, 0)
            self.assertEqual(zero.logs['g'], zero.logs['lagrange'])
            self.assertEqual(len(zero.raw), 132)
            first, second = family.derive(tag, 2), family.derive(tag, 3)
            self.assertEqual(first.logs['g'], second.logs['g'][:4])
            self.assertEqual(first.logs['w'], second.logs['w'])
            self.assertEqual(first.logs['u'], second.logs['u'])
            self.assertEqual(oracle.query(RAW.input0(tag, g0)), early)
            before = (dict(oracle.table), dict(oracle.logs), len(sampler.records))
            self.assertEqual(family.derive(tag, 3), second)
            self.assertEqual((oracle.table, oracle.logs, len(sampler.records)), before)
            curve, r = sampler.models[tag].curve, sampler.models[tag].curve.scalar
            for data in (first, second):
                n = 1 << data.k
                self.assertEqual(len(data.raw), 64*n+68)
                for i, log in enumerate(data.logs['g']):
                    self.assertEqual(sum(data.logs['lagrange'][j]*pow(curve.omega(data.k), i*j, r)
                                         for j in range(n)) % r, log)
                (OUTPUT/('%d-k%d-parameters.bin' % (tag, data.k))).write_bytes(data.raw)
            retained[str(tag)] = {'k2_sha256': hashlib.sha256(first.raw).hexdigest(),
                                  'k3_sha256': hashlib.sha256(second.raw).hexdigest()}
        self.assertEqual(len(oracle.logs), 20)
        self.assertEqual(len(oracle.table), 60)
        self.assertEqual(len(sampler.records), 20)
        (OUTPUT/'small-family-observation.json').write_text(json.dumps(
            {'setups': retained, 'unique_contexts': 20, 'raw_entries': 60,
             'sampler_records': sampler.records, 'proofs': 0}, indent=2, sort_keys=True)+'\n')

    def test_native_identity_is_not_resampled_or_repaired(self):
        # Native SWU is odd for nonzero u. The exact pair (1,-1) sums to O.
        for tag in (0, 1):
            coins = random.Random(2026100942+tag)
            sampler = RAW.FreshTargetSampler(RAW, coins)
            model = sampler.models[tag]
            words = RAW.SetupWords(0, RAW.lift(1, model.p, coins, 256),
                                   RAW.lift(model.p-1, model.p, coins, 256))
            oracle = RAW.RawSetupOracle(coins, lambda _: words, query_budget=32, setup_budget=4)
            family = ParameterFamily(RAW, oracle, sampler)
            with self.assertRaisesRegex(RAW.Refused, 'identity at index 0'):
                family.derive(tag, 2)
            self.assertEqual(set(oracle.logs), {(tag, b'\x00'+i.to_bytes(4, 'little')) for i in range(4)})
            self.assertEqual(set(oracle.logs.values()), {0})
            self.assertEqual(len(oracle.table), 12)

    def test_explicit_small_resource_bounds(self):
        coins = random.Random(2026100943)
        sampler = RAW.FreshTargetSampler(RAW, coins)
        oracle = RAW.RawSetupOracle(coins, sampler)
        with self.assertRaisesRegex(ValueError, 'k<=6'):
            ParameterFamily(RAW, oracle, sampler).derive(0, 16)
        self.assertEqual(oracle.table, {})
        for kwargs in ({'pair_attempts': 4097}, {'draw_attempts': 257}, {'pair_attempts': True}):
            with self.assertRaises(ValueError):
                RAW.FreshTargetSampler(RAW, coins, **kwargs)

