"""Exhaustion, exact counterexample replay and fail-closed schedule search controls."""
from pathlib import Path
import subprocess
import sys
import unittest

import accounting as a
from schedules import Action, Bounds, Fault, OPERATIONS, PROFILES, actions, explore, generate_actions, replay


class MonetaryScheduleTests(unittest.TestCase):
    def test_fee_graph_exhausts_and_reaches_every_operation(self):
        result = explore(PROFILES["fees"])
        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["violation"])
        self.assertEqual(set(result["operations"]), set(OPERATIONS))
        # Captured by the uncached exhaustive implementation. Caching must not
        # drop transitions, collapse distinct worlds or change rejected actions.
        self.assertEqual((result["states"], result["edges"], result["rejected"]),
                         (56_910, 508_958, 575_055))
        self.assertGreater(result["retries"], 0)
        self.assertGreater(result["rejected"], 0)
        self.assertGreater(result["edges"], result["states"])

    def test_unbacked_graph_exhausts_without_funding_or_spend(self):
        result = explore(PROFILES["unbacked"])
        self.assertTrue(result["exhausted"])
        self.assertEqual(set(result["operations"]), {"receive", "fold", "retire", "close_loads"})
        self.assertIsNone(result["violation"])

    def test_every_fault_has_a_reachable_replayable_counterexample(self):
        for fault in Fault:
            if fault == Fault.NONE:
                continue
            with self.subTest(fault=fault.value):
                result = explore(fault=fault)
                self.assertFalse(result["exhausted"])
                self.assertTrue(result["violation"])
                self.assertTrue(result["trace"])
                replay(Bounds(), result["trace"][:-1], fault)
                with self.assertRaises(AssertionError) as raised:
                    replay(Bounds(), result["trace"], fault)
                self.assertEqual(str(raised.exception), result["violation"])
                a.invariant(replay(Bounds(), result["trace"]))

    def test_onward_path_requires_fold_and_preserves_exact_retries(self):
        path = ("issue_load(0,1,charge=0)", "absorb_load(0)", "absorb_load(0)",
                "fold(0)", "send(0,1,1,fee=0)", "receive(1,0,variant=0)",
                "receive(1,0,variant=0)")
        bounds = PROFILES["onward"]
        unfurled = replay(bounds, path)
        with self.assertRaisesRegex(a.Rejected, "must be folded"):
            Action("send", (1, 2, 1), (("fee", 0),)).apply(unfurled)
        completed = replay(bounds, path + (
            "fold(1)", "send(1,2,1,fee=0)", "receive(2,1,variant=0)",
            "fold(2)", "unload(2,1,charge=0)", "pay_unload(0)", "pay_unload(0)",
        ))
        self.assertEqual(completed.online, (0, 0, 1))
        self.assertEqual(completed.reserve, 0)
        self.assertEqual(len(completed.wallets[1].credits), 1)

    def test_action_inventory_is_unique_and_respects_record_bounds(self):
        bounds = Bounds(loads=0, payments=0, claims=0)
        world = a.initial(*bounds.balances)
        inventory = list(actions(world, bounds))
        labels = [action.label() for action in inventory]
        self.assertEqual(len(labels), len(set(labels)))
        self.assertEqual({action.operation for action in inventory}, {"fold", "retire", "close_loads"})
        self.assertEqual(Action("fold", (0,)).apply(world), world)
        self.assertEqual(tuple(inventory), tuple(generate_actions(bounds, 0, (), 0)))
        self.assertIs(actions(world, bounds), actions(world, bounds))

    def test_search_limit_is_an_error_never_a_partial_pass(self):
        with self.assertRaisesRegex(RuntimeError, "before monetary graph exhaustion"):
            explore(state_limit=1)

    def test_invalid_bounds_and_faults_are_refused(self):
        for bounds in (Bounds(balances=[1, 0]), Bounds(balances=(1,)), Bounds(balances=(4, 0)),
                       Bounds(loads=True), Bounds(payments=-1), Bounds(claims=4), Bounds(unbacked=1)):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                bounds.validate()
        for limit in (True, 0, -1, 1.5):
            with self.assertRaises(ValueError):
                explore(state_limit=limit)
        with self.assertRaises(ValueError):
            explore(fault="none")
        with self.assertRaises(ValueError):
            Action("fold", (0,)).apply(a.initial(1, 0), "none")
        with self.assertRaises(ValueError):
            replay(Bounds(), (), "none")
        with self.assertRaisesRegex(ValueError, "unavailable or ambiguous"):
            replay(Bounds(), ("pay_unload(0)",))

    def test_optimized_python_is_refused(self):
        result = subprocess.run([sys.executable, "-B", "-S", "-O", str(Path(__file__).with_name("schedules.py"))],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires unoptimized Python", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
