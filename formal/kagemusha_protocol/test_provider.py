"""Provider publication schedules and deliberately unsafe rule mutations."""
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import unittest

from provider import Edge, Fault, State, edges, explore, invariant, status, transition_invariant


def run(*names, start=State()):
    """Follow one exact schedule, checking every intermediate transition."""
    state = start
    for name in names:
        selected = [edge for edge in edges(state) if edge.name == name]
        if len(selected) != 1:
            raise AssertionError(f"unavailable or ambiguous action {name}")
        transition_invariant(state, selected[0])
        state = selected[0].after
    return state


RELEASE = ("stage_0", "select", "sign_0", "persist_completion", "repair_completion", "publish_released")


class ProviderModelTests(unittest.TestCase):
    def test_complete_graph_exhausts_without_violations(self):
        result = explore()
        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["violation"])
        self.assertGreater(result["states"], 100)
        self.assertGreater(result["edges"], result["states"])

    def test_each_unsafe_rule_has_a_reachable_counterexample(self):
        for fault in Fault:
            if fault == Fault.NONE:
                continue
            with self.subTest(fault=fault.value):
                result = explore(fault)
                self.assertFalse(result["exhausted"])
                self.assertIsNotNone(result["violation"])
                self.assertTrue(result["trace"])
                # Replay the reported shortest trace from the real initial state.
                state = State()
                for name in result["trace"][:-1]:
                    edge, = [edge for edge in edges(state, fault) if edge.name == name]
                    transition_invariant(state, edge)
                    state = edge.after
                final, = [edge for edge in edges(state, fault) if edge.name == result["trace"][-1]]
                with self.assertRaises(AssertionError):
                    transition_invariant(state, final)

    def test_unselected_work_may_be_discarded_and_replaced(self):
        selected = run("stage_0", "discard", "stage_1", "select")
        self.assertEqual(selected.winner, 1)
        self.assertEqual(status(selected), "pending")
        self.assertFalse(any(edge.name.startswith("stage_") for edge in edges(selected)))

    def test_uncertain_selection_survives_crash_and_signer_unavailability(self):
        selected = run("stage_1", "select_uncertain", "crash", "signer_availability")
        self.assertEqual(selected.winner, 1)
        self.assertEqual(status(selected), "pending")
        self.assertFalse(any(edge.name.startswith("sign_") for edge in edges(selected)))
        completed = run("signer_availability", "sign_0", "persist_completion", "repair_completion",
                        "publish_released", "observe", start=selected)
        self.assertEqual(completed.observed, (1, 0))

    def test_crash_before_selection_frees_the_staged_candidate(self):
        interrupted = run("stage_0", "crash")
        self.assertEqual(interrupted, State())
        self.assertEqual(run("stage_1", "select", start=interrupted).winner, 1)

    def test_unreleased_signature_may_be_retried_but_retained_one_is_reused(self):
        selected = run("stage_0", "select", "sign_0", "crash", "sign_1", "persist_completion")
        self.assertEqual(selected.retained_receipt, (0, 1))
        self.assertFalse(any(edge.name.startswith("sign_") for edge in edges(selected)))
        complete = run("crash", "repair_completion", "publish_released", "observe", start=selected)
        self.assertEqual(complete.observed, (0, 1))

    def test_release_requires_redundant_originals(self):
        pending = run("stage_0", "select", "sign_0", "persist_completion")
        self.assertNotIn("publish_released", {edge.name for edge in edges(pending)})
        forged = Edge("publish_released", replace(pending, marker="released", sealed=pending.retained_receipt))
        with self.assertRaisesRegex(AssertionError, "redundant durability"):
            transition_invariant(pending, forged)

    def test_completed_retry_needs_no_signer_and_returns_exact_original(self):
        complete = run(*RELEASE, "observe", "crash", "signer_availability", "observe")
        self.assertEqual(complete.observed, (0, 0))
        self.assertEqual(status(complete), complete.retained_receipt)
        self.assertFalse(any(edge.name.startswith("sign_") for edge in edges(complete)))

    def test_one_copy_repairs_and_total_loss_does_not_regenerate(self):
        complete = run(*RELEASE, "observe", "lose_completion_copy")
        self.assertEqual(status(complete), (0, 0))
        repaired = run("repair_completion", start=complete)
        self.assertEqual(repaired.completion_copies, 2)
        lost = run("lose_completion_copy", "lose_completion_copy", "crash", "observe", start=repaired)
        self.assertEqual(status(lost), "delivery_data_loss")
        self.assertEqual(lost.observed, (0, 0))
        self.assertFalse(any(edge.name in ("repair_completion", "sign_0", "sign_1") for edge in edges(lost)))

    def test_storage_unavailable_never_becomes_absence_or_loss(self):
        phases = [State(), run("stage_0", "select"), run(*RELEASE),
                  run(*RELEASE, "lose_completion_copy", "lose_completion_copy")]
        for phase in phases:
            with self.subTest(marker=phase.marker, copies=phase.completion_copies):
                unavailable = run("storage_availability", start=phase)
                self.assertEqual(status(unavailable), "unavailable")
                restored = run("storage_availability", start=unavailable)
                self.assertEqual(restored, phase)

    def test_missing_selected_capsule_remains_custody_loss(self):
        selected = run("stage_0", "select", "lose_capsule_copy", "lose_capsule_copy", "crash")
        self.assertEqual(status(selected), "custody_loss")
        self.assertEqual(selected.winner, 0)
        self.assertFalse(any(edge.name.startswith(("stage_", "sign_", "repair_")) for edge in edges(selected)))

    def test_foreign_receipt_and_head_rollback_fail_invariants(self):
        selected = run("stage_0", "select")
        with self.assertRaisesRegex(AssertionError, "foreign receipt"):
            invariant(replace(selected, temporary_receipt=(1, 0)))
        with self.assertRaisesRegex(AssertionError, "selected head replaced"):
            transition_invariant(selected, Edge("crash", State()))

    def test_incomplete_search_is_an_error(self):
        with self.assertRaisesRegex(RuntimeError, "before graph exhaustion"):
            explore(state_limit=1)
        for limit in (0, -1, True, 1.0, "100"):
            with self.assertRaises(ValueError):
                explore(state_limit=limit)
        for fault in (None, "none", 0):
            with self.assertRaisesRegex(ValueError, "explicit model fault"):
                explore(fault)

    def test_optimized_python_cannot_disable_the_assertions(self):
        result = subprocess.run([sys.executable, "-B", "-S", "-O", str(Path(__file__).with_name("provider.py"))],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires unoptimized Python", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
