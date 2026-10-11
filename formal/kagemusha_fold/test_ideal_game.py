"""Exhaustive conditional-model controls; no RP57, proof or key is evaluated."""

import dataclasses
import itertools
import hashlib
import json
from pathlib import Path as FilePath
import unittest
from fractions import Fraction

from ideal_game import Path, PartialPermutation, bad_reasons, first_hit_bound, path


class IdealPathControls(unittest.TestCase):
    def test_exact_model_source_inventory(self):
        here = FilePath(__file__).resolve().parent
        manifest = json.loads((here / "ideal_source_manifest.json").read_text())
        self.assertEqual(set(manifest), {"schema", "files"})
        self.assertEqual(manifest["schema"], "kagemusha.fold.ideal-game-controls.v1")
        self.assertEqual(set(manifest["files"]), {"README.md", "ideal_game.py", "test_ideal_game.py"})
        for name, expected in manifest["files"].items():
            self.assertEqual(hashlib.sha256((here / name).read_bytes()).hexdigest(), expected)

    def test_partial_bijection_replays_both_directions_and_preserves_refusals(self):
        table = PartialPermutation(7)
        x, y, other = (0, 1, 2), (3, 4, 5), (6, 0, 1)
        self.assertEqual(table.propose_forward(x, y), ("created", y))
        self.assertEqual(table.propose_forward(x, other), ("replay", y))
        self.assertEqual(table.propose_inverse(y, other), ("replay", x))
        before = table.snapshot()
        self.assertEqual(table.propose_forward(other, y), ("occupied", None))
        self.assertEqual(table.propose_inverse(other, x), ("occupied", None))
        self.assertEqual(table.snapshot(), before)
        self.assertEqual(len(table.attempts), 5)  # Refusal/replay candidates remain counted.
        self.assertEqual(table.inverse, {y: x})

    def test_all_83521_one_position_tapes_have_the_claimed_bad_count(self):
        size, total, bad, no_bad = 17, 0, 0, 0
        for salt, capacity, other_rate, disclosed in itertools.product(range(size), repeat=4):
            hidden = path(size, 0, 3, salt, ((capacity, disclosed, other_rate),), ())
            # Both public endpoints depend only on the disclosed word. They have
            # no access to salt/capacity/other_rate or hidden occupancy.
            public = (((0, 3, disclosed),
                       ((disclosed + 1) % size, disclosed, (disclosed + 2) % size)),)
            total += 1
            if bad_reasons((hidden,), public):
                bad += 1
                continue
            no_bad += 1
            virtual, real = PartialPermutation(size), PartialPermutation(size)
            real.retain_path(hidden)
            expected = virtual.propose_forward(*public[0])
            actual = real.propose_forward(*public[0])
            if expected != actual or len(real.forward) != 2 or len(real.inverse) != 2:
                self.fail((salt, capacity, other_rate, disclosed, expected, actual))
            # Inspect consistency without adding a second public attempt to Q=1.
            if real.inverse[public[0][1]] != virtual.inverse[public[0][1]]:
                self.fail("inverse table diverged on no-bad tape")
        self.assertEqual(total, 83_521)
        # Independent counting: exclude one salt for each disclosed word;
        # exclude two capacities except at disclosed=16, where exclusions coincide.
        self.assertEqual(no_bad, size * (size - 1) ** 3)
        self.assertEqual(bad, 13_889)
        self.assertGreater(bad, 0)
        self.assertGreater(no_bad, 0)
        self.assertLessEqual(Fraction(bad, total), Fraction(5, 17))
        self.assertEqual(first_hit_bound(17, 1, 1, 1), Fraction(5, 17))

    def test_two_edge_carried_capacity_and_input_output_coalescence(self):
        size, examined, accepted = 3, 0, 0
        # 3^7 complete tapes, including every tape after an earlier bad capacity.
        for salt, c1, w1, t1, c2, w2, t2 in itertools.product(range(size), repeat=7):
            hidden = path(size, 0, 1, salt, ((c1, w1, t1), (c2, w2, t2)), ((0, 0),))
            examined += 1
            self.assertEqual(hidden.edges[1][0], hidden.edges[0][1])
            if bad_reasons((hidden,), ()):
                continue
            accepted += 1
            table = PartialPermutation(size)
            table.retain_path(hidden)
            self.assertEqual(len(table.forward), 2)
            self.assertEqual(len(table.inverse), 2)
            before = table.snapshot()
            table.retain_path(hidden)  # Exact retained replay does not create fresh edges.
            self.assertEqual(table.snapshot(), before)
        self.assertEqual(examined, 2_187)
        self.assertEqual(accepted, 486)
        self.assertEqual(first_hit_bound(3, 1, 2, 0), 1)  # Bound vacuous, invariant is not.

    def test_first_extra_forward_rejection_is_retained_not_overwritten(self):
        hidden = path(7, 0, 2, 3, ((4, 5, 6),), ())
        virtual, real = PartialPermutation(7), PartialPermutation(7)
        real.retain_path(hidden)
        before = real.snapshot()
        candidate = ((1, 2, 3), hidden.edges[0][1])
        self.assertEqual(virtual.propose_forward(*candidate), ("created", candidate[1]))
        self.assertEqual(real.propose_forward(*candidate), ("occupied", None))
        self.assertIn("public_capacity_hit", bad_reasons((hidden,), (candidate,)))
        self.assertEqual(real.snapshot(), before)
        self.assertEqual(real.attempts[-1], ("forward", *candidate))

    def test_inverse_candidates_hit_initial_and_carried_private_inputs(self):
        hidden = path(11, 0, 2, 3, ((4, 5, 6), (7, 8, 9)), ((1, 1),))
        for index, (private_input, _) in enumerate(hidden.edges):
            virtual, real = PartialPermutation(11), PartialPermutation(11)
            real.retain_path(hidden)
            before = real.snapshot()
            chosen_output = (10, 0, index)
            self.assertEqual(virtual.propose_inverse(chosen_output, private_input), ("created", private_input))
            self.assertEqual(real.propose_inverse(chosen_output, private_input), ("occupied", None))
            self.assertTrue(bad_reasons((hidden,), ((private_input, chosen_output),)))
            self.assertEqual(real.snapshot(), before)

    def test_fresh_same_salt_is_a_collision_but_exact_replay_reuses_edges(self):
        first = path(13, 0, 2, 3, ((4, 5, 6),), ())
        changed = path(13, 0, 2, 3, ((7, 8, 9),), ())
        self.assertFalse(bad_reasons((first,), ()))
        self.assertIn("fresh_salt_collision", bad_reasons((first, changed), ()))
        table = PartialPermutation(13)
        table.retain_path(first)
        before = table.snapshot()
        table.retain_path(first)
        self.assertEqual(table.snapshot(), before)
        with self.assertRaises(ValueError):
            table.retain_path(changed)
        self.assertEqual(table.snapshot(), before)
        # Private conflicts cannot be erased by calling the changed attempt a retry.
        self.assertEqual(len(table.attempts), 3)

    def test_leaked_secret_and_hidden_occupancy_break_the_public_interface(self):
        hits = 0
        for salt in range(17):
            hidden = path(17, 0, 3, salt, ((4, 5, 6),), ())
            leaked = ((hidden.edges[0][0], (7, 8, 9)),)
            hits += "initial_input_hit" in bad_reasons((hidden,), leaked)
        self.assertEqual(hits, 17)
        self.assertGreater(Fraction(hits, 17), first_hit_bound(17, 1, 1, 1))
        hidden = path(17, 0, 3, 2, ((4, 5, 6),), ())
        leaked_capacity = (((4, 0, 0), (7, 8, 9)),)
        self.assertIn("public_capacity_hit", bad_reasons((hidden,), leaked_capacity))
        empty, occupied = PartialPermutation(17), PartialPermutation(17)
        occupied.retain_path(hidden)
        # This deliberately invalid public budget sees private table occupancy.
        admit_if_empty = lambda table: not table.snapshot()
        self.assertTrue(admit_if_empty(empty))
        self.assertFalse(admit_if_empty(occupied))
        # Choosing the initial capacity after the virtual output tape also
        # violates the causal premise and forces the charged H/p event.
        forced = 0
        for capacity in range(17):
            chosen_after_tape = path(17, capacity, 3, 2, ((capacity, 5, 6),), ())
            forced += "private_capacity_collision" in bad_reasons((chosen_after_tape,), ())
        self.assertEqual(forced, 17)
        self.assertGreater(Fraction(forced, 17), first_hit_bound(17, 1, 1, 0))
        # Equal declared Q is not enough if a public refusal leaks hidden state.
        self.assertEqual(len(empty.attempts), 0)

    def test_invalid_path_alphabet_and_experiment_bounds_are_rejected(self):
        with self.assertRaises(ValueError):
            path(7, 0, 1, 7, ((1, 2, 3),), ())
        with self.assertRaises(ValueError):
            path(7, 0, 1, 2, (), ())
        valid = path(7, 0, 1, 2, ((3, 4, 5), (4, 5, 6)), ((0, 0),))
        malformed = dataclasses.replace(valid, edges=(valid.edges[0], ((6, 4, 5), valid.edges[1][1])))
        for selected in [malformed, dataclasses.replace(valid, salt=6),
                         dataclasses.replace(valid, initial_capacity=False),
                         dataclasses.replace(path(7, 0, 1, 1, ((3, 4, 5),), ()), salt=True),
                         Path(7, 0, 1, ())]:
            with self.assertRaises(ValueError):
                bad_reasons((selected,), ())
            with self.assertRaises(ValueError):
                PartialPermutation(7).retain_path(selected)
        for malformed_public in [(), (valid.edges[0][0],),
                                 (*valid.edges[0], valid.edges[1][0]), list(valid.edges[0])]:
            with self.assertRaises(ValueError):
                bad_reasons((valid,), (malformed_public,))
        foreign = path(11, 0, 1, 2, ((3, 4, 5),), ())
        with self.assertRaises(ValueError):
            bad_reasons((valid, foreign), ())
        for arguments in [(1, 1, 1, 1), (17, -1, 1, 1), (17, 2, 1, 1), (17, 1, 1, -1)]:
            with self.assertRaises(ValueError):
                first_hit_bound(*arguments)
        self.assertEqual(first_hit_bound(17, 0, 0, 0), 0)


if __name__ == "__main__":
    unittest.main()
