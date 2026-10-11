"""Native RP57 schedule/custody controls, with zero fold proof or key generation."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import transcript as subject


class FoldTranscript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subject.checked_sources()

    @classmethod
    def tearDownClass(cls):
        subject.checked_sources()

    def test_exact_inventory_and_canonical_native_tables(self):
        subject.checked_sources()
        constants = subject.reference().KATS['poseidon_constants']
        self.assertEqual((constants['full_rounds'], constants['partial_rounds']), (8, 57))
        for tag, field in ((0, 'fp'), (1, 'fq')):
            c = subject.curve(tag)
            table = constants[field]
            self.assertEqual(len(table['round_constants']), 65)
            self.assertEqual(len(table['mds']), 3)
            rows = table['round_constants'] + table['mds']
            self.assertTrue(all(len(row) == 3 for row in rows))
            words = [bytes.fromhex(word) for row in rows for word in row]
            self.assertTrue(all(len(word) == 32 and int.from_bytes(word, 'little') < c.base
                                for word in words))
            native = subject.ROOT / ('crates/iroha_pasta/src/poseidon/rp57_' + field + '.bin')
            self.assertEqual(b''.join(words), native.read_bytes())

    def test_native_two_curve_prelude_known_answers(self):
        expected = (
            'e55b8d7af07c5f4460cdf4aaadbe7e20da293398ec29d0f509f86131ccf398d6',
            '4a2cf8c915586737505a1d97b8dee219b640077411d287c52b0f16bd09c44a3b',
        )
        for tag in (0, 1):
            buffers = (subject.prelude_words(tag, subject.fixture_inputs(tag, 2), 42), (), ())
            result = subject.trace_script(tag, buffers)
            subject.check_trace(tag, buffers, result)
            encoded = b''.join(value.to_bytes(32, 'little') for value in result['mapped'])
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected[tag])

    def test_canonical_scalar_lanes_and_full_width_maps(self):
        p, q = subject.curve(0).base, subject.curve(0).scalar
        self.assertLess(p, q)
        self.assertLess(q, 2*p)
        for tag in (0, 1):
            c = subject.curve(tag)
            for value in (0, 1, (1 << 128)-1, 1 << 128, c.scalar-1):
                words = subject.scalar_words(tag, value)
                self.assertTrue(all(0 <= word < c.base for word in words))
                self.assertEqual(len(words), 2 if tag == 0 else 1)
                reconstructed = words[0] + ((words[1] << 128) if tag == 0 else 0)
                self.assertEqual(reconstructed, value)
            self.assertEqual(subject.mapped_word(tag, 0), 0)
            self.assertEqual(subject.mapped_word(tag, c.base-1), (c.base-1) % c.scalar)
            for invalid in (-1, c.scalar, True):
                with self.assertRaises(ValueError):
                    subject.scalar_words(tag, invalid)
            for invalid in (-1, c.base, True):
                with self.assertRaises(ValueError):
                    subject.mapped_word(tag, invalid)
        self.assertEqual(subject.scalar_words(0, 0), (0, 0))
        self.assertEqual(subject.scalar_words(0, 1 << 128), (0, 1))
        self.assertEqual([subject.mapped_word(1, v) for v in (p-1, p, p+1, q-1)],
                         [p-1, 0, 1, q-p-1])

    def test_all_nineteen_squeezes_and_exact_primitive_accounting(self):
        for tag in (0, 1):
            for count in (1, 2, 4, 9):
                with self.subTest(tag=tag, count=count):
                    buffers = subject.fold_script(tag, subject.fixture_inputs(tag, count), 42)
                    result = subject.trace_script(tag, buffers)
                    subject.check_trace(tag, buffers, result)
                    self.assertEqual(len(result['mapped']), 19)
                    self.assertEqual(len(result['edges']), subject.expected_positions(tag, count))
                    self.assertEqual(result['edges'][0][0], (1 << 64, subject.DOMAIN, 42))
                    self.assertEqual(tuple(b-a for a, b in zip(result['endpoints'],
                                                               result['endpoints'][1:])),
                                     (1, 1) + (3,) * 16)
        self.assertEqual(subject.expected_positions(1, 4), 90)

    def test_padding_aliases_without_prior_output_tags(self):
        self.assertEqual(subject.padded_blocks(()), ((1, 0),))
        self.assertEqual(subject.padded_blocks((2,)), ((2, 1),))
        self.assertEqual(subject.padded_blocks((2, 3)), ((2, 3), (1, 0)))
        self.assertEqual(subject.padded_blocks((2, 3, 4)), ((2, 3), (4, 1)))
        for tag in (0, 1):
            # The exact native alias also covers a guessed salt1 first block.
            left = subject.trace_script(tag, ((subject.DOMAIN,), ()))
            right = subject.trace_script(tag, ((subject.DOMAIN, 1),))
            self.assertEqual(left['edges'], right['edges'])
            self.assertEqual(left['state'], right['state'])
            self.assertEqual(left['raw'][-1], right['raw'][-1])
            tagged = subject.trace_script(tag, ((subject.DOMAIN,), (left['raw'][0],)))
            self.assertNotEqual(left['state'], tagged['state'])

    def test_transcript_mutations_and_trace_corruption_are_detected(self):
        for tag in (0, 1):
            inputs = subject.fixture_inputs(tag, 2)
            first = subject.prelude_words(tag, inputs, 42)
            original = subject.trace_script(tag, (first, (), ()))
            alternatives = (
                subject.prelude_words(tag, tuple(reversed(inputs)), 42),
                subject.prelude_words(tag, inputs, 43),
                (int.from_bytes(b'pipa-rb1', 'little'),) + first[1:],
            )
            for mutated in alternatives:
                self.assertNotEqual(subject.trace_script(tag, (mutated, (), ()))['mapped'],
                                    original['mapped'])
            reset = subject.trace_script(tag, ((),))
            self.assertNotEqual(original['raw'][1], reset['raw'][0])
            broken = copy.deepcopy(original)
            broken['edges'] = broken['edges'][:-1]
            with self.assertRaises(ValueError):
                subject.check_trace(tag, (first, (), ()), broken)
            broken = copy.deepcopy(original)
            first_input, first_output = broken['edges'][0]
            broken['edges'] = (((first_input[0], first_input[2], first_input[1]), first_output),) + broken['edges'][1:]
            with self.assertRaises(ValueError):
                subject.check_trace(tag, (first, (), ()), broken)
            broken = copy.deepcopy(original)
            broken['raw'] = ((broken['raw'][0] + 1) % subject.curve(tag).base,) + broken['raw'][1:]
            with self.assertRaises(ValueError):
                subject.check_trace(tag, (first, (), ()), broken)

    def test_final_scalar_and_generator_add_no_challenge_or_permutation(self):
        for tag in (0, 1):
            ref, c = subject.reference(), subject.curve(tag)
            buffers = subject.fold_script(tag, subject.fixture_inputs(tag, 1), 42)
            trace = subject.trace_script(tag, buffers)
            for final_c in (0, 7, c.scalar-1):
                # This unmodified reader absorbs c but reads the final G unabsorbed.
                # No verifier acceptance is claimed for these syntactic messages.
                for suffix in ((c.base-1, 2, 1), (c.base-1, c.base-2, 1)):
                    proof = final_c.to_bytes(32, 'little') + c.encode(suffix)
                    reader = ref.Transcript(c, 2, proof)
                    reader.sponge.state = list(trace['state'])
                    reader.sponge.buffer = []
                    self.assertEqual(reader.scalar(), final_c)
                    self.assertEqual(tuple(reader.sponge.buffer), subject.scalar_words(tag, final_c))
                    self.assertEqual(tuple(reader.sponge.state), trace['state'])
                    self.assertTrue(c.equal(reader.point(absorb=False), suffix))
                    reader.finish()
                    self.assertEqual(reader.challenges, [])
                    self.assertEqual(tuple(reader.sponge.state), trace['state'])

    def test_invalid_or_unbounded_schedule_inputs_refuse(self):
        for tag in (-1, 2, True):
            with self.assertRaises(ValueError):
                subject.curve(tag)
        for count in (0, 17, True):
            with self.assertRaises(ValueError):
                subject.fixture_inputs(0, count)
            with self.assertRaises(ValueError):
                subject.expected_positions(0, count)
        for tag in (0, 1):
            c = subject.curve(tag)
            good = subject.fixture_inputs(tag, 2)
            for bad in ((), good[:1], [(good[-1])], (good[-1][:2],)):
                with self.assertRaises(ValueError):
                    subject.prelude_words(tag, bad, 42)
            point, k, challenges = good[-1]
            for row in ((point, True, challenges), (point, k, challenges[:-1]),
                        (point, k, (0,) + challenges[1:]), ((0, 0), k, challenges),
                        (point, k, (c.scalar,) + challenges[1:])):
                with self.assertRaises(ValueError):
                    subject.prelude_words(tag, (row,), 42)
            for salt in (-1, c.base, True):
                with self.assertRaises(ValueError):
                    subject.prelude_words(tag, good, salt)
            for buffers in ((), ((),) * 33, ((0,) * 1025,), ((c.base,),), ((True,),)):
                with self.assertRaises(ValueError):
                    subject.trace_script(tag, buffers)

    def test_source_inventory_mutations_refuse(self):
        manifest = json.loads((subject.HERE / 'transcript_source_manifest.json').read_text())
        for section, name in (('files', 'transcript.py'),
                              ('sources', 'crates/iroha_plonk_recursion/src/tests.rs')):
            absent = copy.deepcopy(manifest)
            del absent[section][name]
            with self.assertRaises(ValueError):
                subject.validate_manifest(absent)
            extra = copy.deepcopy(manifest)
            extra[section]['../foreign.py'] = '0' * 64
            with self.assertRaises(ValueError):
                subject.validate_manifest(extra)
            wrong = copy.deepcopy(manifest)
            wrong[section][name] = 'A' * 64
            with self.assertRaises(ValueError):
                subject.validate_manifest(wrong)
        wrong = copy.deepcopy(manifest)
        wrong['schema'] = 'unknown'
        with self.assertRaises(ValueError):
            subject.validate_manifest(wrong)

    def test_changed_or_missing_retained_source_refuses_before_reference_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            here = Path(temporary)
            for name in (*subject.FILES, 'transcript_source_manifest.json'):
                (here / name).write_bytes((subject.HERE / name).read_bytes())
            (here / 'README.md').write_bytes((here / 'README.md').read_bytes() + b'\nchanged\n')
            with patch.object(subject, 'HERE', here):
                with self.assertRaisesRegex(ValueError, 'changed source README.md'):
                    subject.checked_sources()
                (here / 'README.md').unlink()
                with self.assertRaises(FileNotFoundError):
                    subject.checked_sources()


if __name__ == '__main__':
    unittest.main()
