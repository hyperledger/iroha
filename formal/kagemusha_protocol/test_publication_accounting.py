"""Bounded Send/provider composition, exact replay and cross-component mutations."""
from pathlib import Path
import subprocess
import sys
import unittest

from publication_accounting import (
    Fault, edges, explore, funded_world, initial, invariant, retained_payment,
    transition_invariant, ReceiveFault, explore_receiver, receiver_edges,
    receiver_initial, receiver_invariant, receiver_status, receiver_transition_invariant,
)
import accounting as money


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


def run_receiver(*names, start=None):
    """Replay exact receiver/payer transitions, checking every composed cut."""
    state = receiver_initial() if start is None else start
    for name in names:
        event, = [event for event in receiver_edges(state) if event.name == name]
        receiver_transition_invariant(state, event)
        state = event.after
    return state


RECEIVER_RELEASE = (
    "receiver/stage_0", "receiver/select", "receiver/sign_0",
    "receiver/persist_completion", "receiver/repair_completion", "receiver/publish_released",
)


class ReceiverPublicationAccountingTests(unittest.TestCase):
    def test_receiver_frontier_exhausts(self):
        result = explore_receiver()
        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["violation"])
        self.assertGreater(result["states"], 484)
        self.assertGreater(result["edges"], result["states"])

    def test_receiver_mutations_have_replayable_counterexamples(self):
        for fault in ReceiveFault:
            if fault == ReceiveFault.NONE:
                continue
            with self.subTest(fault=fault.value):
                result = explore_receiver(fault)
                self.assertFalse(result["exhausted"])
                self.assertIsNotNone(result["violation"])
                state = receiver_initial()
                for name in result["trace"][:-1]:
                    event, = [event for event in receiver_edges(state, fault) if event.name == name]
                    receiver_transition_invariant(state, event)
                    state = event.after
                event, = [event for event in receiver_edges(state, fault)
                          if event.name == result["trace"][-1]]
                with self.assertRaisesRegex(AssertionError, result["violation"]):
                    receiver_transition_invariant(state, event)
                run_receiver(*result["trace"])

    def test_every_payer_output_seam_comes_from_its_actual_released_original(self):
        for capsule in (0, 1):
            for nonce in (0, 1):
                with self.subTest(capsule=capsule, nonce=nonce):
                    state = receiver_initial(capsule, nonce)
                    receiver_invariant(state)
                    self.assertEqual(state.payer.carrier, (capsule, nonce))
                    self.assertEqual(state.payer.carrier, state.payer.publication.retained_receipt)
                    self.assertEqual(state.payer.world.payments[0].amount, capsule + 1)
                    self.assertIsNone(state.input_original)
                    self.assertIsNone(state.payer.received)
                    self.assertEqual(receiver_status(state), "old_head_usable")

    def test_uncertain_receive_selection_never_completes_or_folds(self):
        state = run_receiver("receiver/stage_0", "receiver/select_uncertain",
                             "receiver/crash", "receiver/signer_availability",
                             "receiver/observe", "retry_receive", "duplicate_receive",
                             "fold_pending")
        self.assertEqual(receiver_status(state), "pending")
        self.assertEqual(state.payer.world.wallets[1].balance, 1)
        self.assertEqual(state.payer.world.wallets[1].sequence, 1)
        self.assertEqual(len(state.payer.world.wallets[1].credits), 1)
        self.assertFalse(state.payer.world.wallets[1].folded())
        self.assertNotIn("fold_receiver", {event.name for event in receiver_edges(state)})
        self.assertNotIn("conflicting_receive", {event.name for event in receiver_edges(state)})
        with self.assertRaisesRegex(money.Rejected, "must be folded"):
            money.spend_head(state.payer.world, 1, 1)
        unavailable = run_receiver("receiver/storage_availability", start=state)
        self.assertEqual(receiver_status(unavailable), "unavailable")
        self.assertNotIn("fold_pending", {event.name for event in receiver_edges(unavailable)})
        self.assertNotIn("conflicting_receive", {event.name for event in receiver_edges(unavailable)})

    def test_retained_intake_survives_carrier_and_payer_loss_before_selection(self):
        state = run_receiver("receiver/stage_1", "payer/lose_carrier",
                             "payer/provider/lose_completion_copy",
                             "payer/provider/lose_completion_copy")
        original = state.input_original
        self.assertEqual(original, (0, 0))
        self.assertIsNone(state.payer.carrier)
        self.assertFalse(state.payer.world.payments[0].retained)
        state = run_receiver("receiver/select", "receiver/sign_1",
                             "receiver/persist_completion", "receiver/repair_completion",
                             "receiver/publish_released", "retry_receive", start=state)
        self.assertEqual(state.payer.received, original)
        self.assertEqual(receiver_status(state), (1, 1))
        self.assertEqual(len(state.payer.world.wallets[1].credits), 1)

    def test_lost_staging_does_not_reconstruct_receiver_input_from_payer_ghost(self):
        state = run_receiver("receiver/stage_0", "payer/lose_carrier",
                             "payer/provider/lose_completion_copy",
                             "payer/provider/lose_completion_copy", "receiver/crash")
        self.assertIsNone(state.input_original)
        self.assertIsNotNone(state.payer.publication.sealed)
        names = {event.name for event in receiver_edges(state)}
        self.assertNotIn("receiver/stage_0", names)
        self.assertNotIn("receiver/select", names)
        self.assertIsNone(state.payer.received)

    def test_signature_and_one_completion_copy_do_not_complete_receive(self):
        signed = run_receiver(*RECEIVER_RELEASE[:3])
        self.assertIsNotNone(signed.publication.temporary_receipt)
        self.assertEqual(receiver_status(signed), "pending")
        one_copy = run_receiver("receiver/persist_completion", start=signed)
        self.assertEqual(one_copy.publication.completion_copies, 1)
        self.assertEqual(receiver_status(one_copy), "pending")
        self.assertNotIn("receiver/publish_released",
                         {event.name for event in receiver_edges(one_copy)})
        complete = run_receiver("receiver/repair_completion", "receiver/publish_released",
                                start=one_copy)
        self.assertEqual(receiver_status(complete), (0, 0))
        self.assertFalse(complete.payer.world.wallets[1].folded(),
                         "durable receipt completion does not wait for the lineage fold")

    def test_exact_receiver_retry_and_conflicting_input_never_recredit(self):
        complete = run_receiver(*RECEIVER_RELEASE, "receiver/observe")
        self.assertIn("conflicting_receive", {event.name for event in receiver_edges(complete)})
        unavailable = run_receiver("receiver/storage_availability", start=complete)
        self.assertNotIn("conflicting_receive", {event.name for event in receiver_edges(unavailable)})
        state = run_receiver("receiver/crash", "receiver/signer_availability",
                             "retry_receive", "duplicate_receive", "conflicting_receive",
                             "fold_receiver", "retry_receive", start=complete)
        self.assertEqual(receiver_status(state), receiver_status(complete))
        self.assertEqual(state.payer.received, complete.payer.received)
        self.assertEqual(state.payer.world.wallets[1].credits, complete.payer.world.wallets[1].credits)
        self.assertEqual(state.payer.world.wallets[1].sequence, 1)
        self.assertEqual(state.payer.world.wallets[1].balance, 1)
        self.assertFalse(any(event.name.startswith("receiver/sign_")
                             for event in receiver_edges(state)))
        self.assertTrue(state.payer.world.wallets[1].folded())

    def test_receiver_output_loss_keeps_first_credit_without_reconstructing_receipt(self):
        state = run_receiver(*RECEIVER_RELEASE, "receiver/observe", "fold_receiver")
        credit = state.payer.world.wallets[1].credits
        state = run_receiver("payer/lose_carrier", "payer/provider/lose_completion_copy",
                             "payer/provider/lose_completion_copy",
                             "receiver/lose_completion_copy", "receiver/lose_completion_copy",
                             "receiver/crash", "retry_receive", start=state)
        self.assertEqual(receiver_status(state), "delivery_data_loss")
        self.assertIsNotNone(state.publication.sealed)
        self.assertIsNone(state.publication.retained_receipt)
        self.assertEqual(state.payer.world.wallets[1].credits, credit)
        self.assertEqual(state.payer.world.wallets[1].sequence, 1)
        self.assertTrue(state.payer.world.wallets[1].folded())
        self.assertFalse(any(event.name.startswith("receiver/sign_")
                             for event in receiver_edges(state)))

    def test_fold_refusal_and_cancellation_preserve_both_eventual_verdicts(self):
        for variant in (0, 1):
            with self.subTest(variant=variant):
                state = run_receiver(f"receiver/stage_{variant}", *RECEIVER_RELEASE[1:])
                before = state
                state = run_receiver("fold_refused", "fold_cancelled", start=state)
                self.assertEqual(state, before)
                self.assertFalse(state.payer.world.wallets[1].folded())
                self.assertEqual(receiver_status(state), (variant, 0))
                folded = run_receiver("fold_receiver", start=state)
                self.assertEqual(folded.payer.world.wallets[1].burned, variant)
                self.assertEqual(folded.payer.world.wallets[1].normalized_balance(), 1 - variant)
                self.assertEqual(folded.payer.world.reserve, 3)
                self.assertEqual(money.categories(folded.payer.world)["burned_backing"], variant)
                self.assertEqual(folded.payer.world.wallets[1].credits,
                                 state.payer.world.wallets[1].credits)
                self.assertEqual(receiver_status(folded), receiver_status(state))

    def test_receiver_limits_and_inputs_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "state limit"):
            explore_receiver(state_limit=1)
        for limit in (0, -1, True, 2.5):
            with self.assertRaises(ValueError):
                explore_receiver(state_limit=limit)
        for capsule, nonce in ((True, 0), (0, True), (2, 0), (0, -1)):
            with self.assertRaises(ValueError):
                receiver_initial(capsule, nonce)
        with self.assertRaises(ValueError):
            explore_receiver("none")
        with self.assertRaises(ValueError):
            list(receiver_edges(receiver_initial(), "none"))
        with self.assertRaises(ValueError):
            receiver_status(receiver_initial(), "none")
