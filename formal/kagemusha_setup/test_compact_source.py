"""Current compact-format algebra controls using explicit small public source rows."""
from dataclasses import replace
import hashlib
import json
import unittest

from . import compact_source as subject
from .custody import ROOT, require, sha
from .rebind import reference
from .test_generic import setup_case

OUTPUT = None


class CompactSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require(OUTPUT is not None, 'explicit fresh output required')
        cls.modules = reference(OUTPUT / 'source-reference')
        fixture = json.loads((ROOT / 'fixtures/native_prover/reference_v1.json').read_text())
        cls.cases = {(tag, variant): setup_case(tag, cls.modules, fixture, variant)
                     for tag in (0, 1) for variant in ('ordinary', 'public-only', 'multi')}

    def inputs(self, identity=(0, 'ordinary')):
        d, key, _, params, public, _ = self.cases[identity]
        source = dict(copy_digest=public.copy_digest, selectors=(), fixed=public.fixed,
                      sigma=public.sigma, parameters=params,
                      key_points=self.modules['verify'].key_points)
        digest = subject.fingerprint(d, public.copy_digest, (), public.fixed, public.sigma)
        raw = b'PIPACPK1' + d.digest + len(key).to_bytes(4, 'little') + key + public.copy_digest + digest
        return d, key, source, raw, public

    def test_six_current_compact_originals_reconstruct_identical_public_polynomials(self):
        for identity in self.cases:
            d, key, source, raw, public = self.inputs(identity)
            with self.subTest(identity=identity):
                actual = subject.reconstruct(raw, d, key, sha(raw), **source)
                self.assertEqual(len(raw), 108 + len(key))
                self.assertEqual(actual.fixed, public.fixed)
                self.assertEqual(actual.sigma, public.sigma)
                self.assertEqual(actual.copy_digest, public.copy_digest)
                for point in (0, 1, 7, d.curve.omega(6), d.curve.scalar - 1):
                    self.assertEqual(actual.query_evaluations(point), public.query_evaluations(point))

    def test_source_fingerprint_matches_independent_native_byte_frame(self):
        for identity in self.cases:
            d, _, source, raw, _ = self.inputs(identity)
            # An independently assembled byte frame, not a second call to the hasher.
            words = (len(source['fixed']), len(source['sigma']), d.n, 0)
            encoded = (b'iroha:pipa:source-lookup:v1\0' + len(d.raw).to_bytes(8, 'little') +
                       d.raw + source['copy_digest'] +
                       b''.join(word.to_bytes(8, 'little') for word in words) +
                       b''.join(value.to_bytes(32, 'little')
                                for col in (*source['fixed'], *source['sigma']) for value in col))
            self.assertEqual(raw[-32:], hashlib.sha256(encoded).digest())

    def test_packed_selector_stream_preserves_every_row_and_rejects_non_booleans(self):
        for rows in (1, 2, 7, 8, 9, 63, 64):
            # Exercise all positions separately, including unused trailing bits.
            for active in range(rows):
                source = tuple(i == active for i in range(rows))
                packed, = subject.packed_selectors((source,), rows)
                self.assertEqual(int.from_bytes(packed, 'little'), 1 << active)
        for selectors, rows in ((([True],), 1), (((1,),), 1), (((True,),), 2), ((), 65), ((), True)):
            with self.assertRaises(ValueError):
                subject.packed_selectors(selectors, rows)

    def test_missing_or_changed_source_rows_do_not_follow_the_declared_digest(self):
        d, key, source, raw, _ = self.inputs()
        variants = [dict(source, fixed=()), dict(source, copy_digest=bytes([1]) * 32)]
        column = source['fixed'][0]
        variants += [dict(source, fixed=((column[0] + 1,) + column[1:],)),
                     dict(source, fixed=((d.curve.scalar,) + column[1:],)),
                     dict(source, fixed=((True,) + column[1:],)),
                     dict(source, sigma=tuple(reversed(source['sigma'])))]
        for changed in variants:
            with self.assertRaises(ValueError):
                subject.reconstruct(raw, d, key, sha(raw), **changed)

    def test_rehashed_foreign_vk_still_requires_every_public_commitment(self):
        for tag in (0, 1):
            d, key, source, raw, _ = self.inputs((tag, 'ordinary'))
            # Keep valid framing, descriptor and source digest, change a canonical point.
            changed = key[:10] + d.curve.encode(source['parameters'].w) + key[42:]
            forged = raw[:44] + changed + raw[44 + len(key):]
            with self.assertRaisesRegex(ValueError, 'compact public commitment'):
                subject.reconstruct(forged, d, changed, sha(forged), **source)

    def test_framing_digest_key_and_parameter_changes_refuse(self):
        d, key, source, raw, _ = self.inputs()
        changes = [raw[:-1], raw + b'\0', b'PIPAPK01' + raw[8:],
                   raw[:8] + bytes(32) + raw[40:], raw[:40] + bytes(4) + raw[44:]]
        for changed in changes:
            with self.assertRaises(ValueError):
                subject.reconstruct(changed, d, key, sha(changed), **source)
        with self.assertRaisesRegex(ValueError, 'compact original digest'):
            subject.reconstruct(raw, d, key, '0' * 64, **source)
        for params in (replace(source['parameters'], k=5),
                       replace(source['parameters'], digest=bytes(32))):
            with self.assertRaisesRegex(ValueError, 'compact parameter binding'):
                subject.reconstruct(raw, d, key, sha(raw), **dict(source, parameters=params))

    def test_rehashed_changed_rows_cannot_be_accepted_by_fingerprint_alone(self):
        d, key, source, raw, _ = self.inputs()
        column = source['fixed'][0]
        changed = dict(source, fixed=((column[0] + 1,) + column[1:],))
        digest = subject.fingerprint(d, changed['copy_digest'], (), changed['fixed'], changed['sigma'])
        forged = raw[:-32] + digest
        with self.assertRaisesRegex(ValueError, 'compact public commitment'):
            subject.reconstruct(forged, d, key, sha(forged), **changed)


if __name__ == '__main__':
    unittest.main()
