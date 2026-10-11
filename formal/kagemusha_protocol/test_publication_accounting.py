"""Bounded Send/provider composition, exact replay and cross-component mutations."""
from pathlib import Path
import subprocess
import sys
import unittest

from publication_accounting import (
    Fault, edges, explore, funded_world, initial, invariant, retained_payment,
    transition_invariant,
)


def run(*names, start=None):
    """Replay one legal schedule while checking each composed transition."""
    state = initial() if start is None else start
    for name in names:
        event, = [event for event in edges(state) if event.name == name]
        transition_invariant(state, event)
        state = event.after
    return state


RELEASE = ("provider/stage_0", "provider/select", "provider/sign_0",
           "provider/persist_completion", "provider/repair_completion", "provider/publish_released")


class PublicationAccountingTests(unittest.TestCase):
    def test_bounded_product_exhausts(self):
        result = explore()
        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["violation"])
        self.assertGreater(result["states"], 484)
        self.assertGreater(result["edges"], result["states"])

    def test_all_composition_mutations_have_replayable_counterexamples(self):
        for fault in Fault:
            if fault == Fault.NONE:
                continue
            with self.subTest(fault=fault.value):
                result = explore(fault)
                self.assertFalse(result["exhausted"])
                state = initial()
                for name in result["trace"][:-1]:
                    event, = [event for event in edges(state, fault) if event.name == name]
                    transition_invariant(state, event)
                    state = event.after
                event, = [event for event in edges(state, fault) if event.name == result["trace"][-1]]
                with self.assertRaisesRegex(AssertionError, result["violation"]):
                    transition_invariant(state, event)
                # The same schedule is legal with the correct composition.
                run(*result["trace"])

    def test_initial_world_has_only_authentic_folded_funding(self):
        state = initial()
        invariant(state)
        self.assertEqual(state.world, funded_world())
        self.assertEqual(state.world.wallets[0].balance, 3)
        self.assertTrue(state.world.wallets[0].folded())
        self.assertEqual(retained_payment(state.world, False), state.world)

    def test_uncertain_selection_never_refunds_or_delivers(self):
        state = run("provider/stage_1", "provider/select_uncertain", "provider/crash",
                    "provider/signer_availability", "provider/observe")
        self.assertEqual(state.world.wallets[0].balance, 1)
        self.assertEqual(state.world.payments[0].amount, 2)
        self.assertFalse(state.world.payments[0].retained)
        self.assertNotIn("deliver", {e.name for e in edges(state)})
        self.assertNotIn("receive_0", {e.name for e in edges(state)})

    def test_unavailable_storage_does_not_authorize_carrier_copy(self):
        state = run(*RELEASE, "provider/storage_availability")
        self.assertTrue(state.world.payments[0].retained)
        self.assertNotIn("deliver", {e.name for e in edges(state)})

    def test_receive_retries_after_all_delivery_bytes_are_lost(self):
        state = run(*RELEASE, "deliver", "receive_0", "lose_carrier",
                    "provider/lose_completion_copy", "provider/lose_completion_copy",
                    "provider/crash", "receive_0", "fold_receiver", "receive_0")
        self.assertFalse(state.world.payments[0].retained)
        self.assertIsNone(state.carrier)
        self.assertEqual(state.received, (0, 0))
        self.assertEqual(state.world.wallets[1].balance, 1)
        self.assertEqual(len(state.world.wallets[1].credits), 1)
        self.assertTrue(state.world.wallets[1].folded())
        self.assertNotIn("deliver", {e.name for e in edges(state)})

    def test_surviving_carrier_remains_deliverable_after_payer_loss(self):
        state = run(*RELEASE, "deliver", "provider/lose_completion_copy",
                    "provider/lose_completion_copy", "receive_1", "fold_receiver")
        self.assertEqual(state.world.wallets[0].balance, 2)
        self.assertEqual(state.world.wallets[1].burned, 1)
        self.assertEqual(state.world.wallets[1].normalized_balance(), 0)
        self.assertEqual(state.world.reserve, 3)

    def test_completed_retry_cannot_sign_or_debit_again(self):
        state = run(*RELEASE, "provider/observe", "provider/crash",
                    "provider/signer_availability", "provider/observe", "deliver", "deliver")
        self.assertEqual(state.world.wallets[0].next_send, 1)
        self.assertEqual(state.carrier, (0, 0))
        self.assertFalse(any(e.name.startswith("provider/sign_") for e in edges(state)))

    def test_limits_and_invalid_faults_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "state limit"):
            explore(state_limit=1)
        for limit in (0, -1, True, 2.5):
            with self.assertRaises(ValueError):
                explore(state_limit=limit)
        with self.assertRaises(ValueError):
            explore("none")
        with self.assertRaises(ValueError):
            list(edges(initial(), "none"))

    def test_optimized_python_refuses_to_remove_assertions(self):
        result = subprocess.run([sys.executable, "-O", "-B", "-S",
                                 str(Path(__file__).with_name("publication_accounting.py"))],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unoptimized Python", result.stderr)
