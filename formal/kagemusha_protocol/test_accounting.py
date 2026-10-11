"""Accounting schedules and counterexamples to monetary/custody rule omissions."""
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import unittest

import accounting as a


def step(world, operation, *args, **kwargs):
    """Check both ends of one abstract committed transition."""
    a.invariant(world)
    result = operation(world, *args, **kwargs)
    a.invariant(result)
    return result


def funded(amount=2, *others):
    """One absorbed, folded native-authorized Load; no synthetic mint operation."""
    world = a.initial(amount, *(others or (0,)))
    world = step(world, a.issue_load, 0, amount)
    world = step(world, a.absorb_load, 0)
    return step(world, a.fold, 0)


class AccountingTests(unittest.TestCase):
    def test_load_order_replay_and_stale_issuance(self):
        world = a.initial(3, 0)
        world = step(world, a.issue_load, 0, 1, ordinal=0)
        world = step(world, a.issue_load, 0, 1, ordinal=1)
        with self.assertRaisesRegex(a.Rejected, "receipt order"):
            a.absorb_load(world, 1)
        world = step(world, a.absorb_load, 0)
        world = step(world, a.absorb_load, 1)
        self.assertEqual(step(world, a.absorb_load, 0), world)
        with self.assertRaisesRegex(a.Rejected, "stale load ordinal"):
            a.issue_load(world, 0, 1, ordinal=0)
        self.assertEqual(a.categories(world)["wallets"], 2)
        with self.assertRaisesRegex(a.Rejected, "must be folded"):
            a.send(world, 0, 1, 1)

    def test_a_to_b_to_c_unload_and_exact_once_payout(self):
        world = funded(5, 0, 0)
        world = step(world, a.send, 0, 1, 5)
        world = step(world, a.receive, 1, 0)
        with self.assertRaisesRegex(a.Rejected, "must be folded"):
            a.send(world, 1, 2, 5)
        world = step(world, a.fold, 1)
        world = step(world, a.send, 1, 2, 5)
        world = step(world, a.receive, 2, 1)
        world = step(world, a.fold, 2)
        world = step(world, a.unload, 2, 5)
        world = step(world, a.pay_unload, 0)
        self.assertEqual(world.online, (0, 0, 5))
        self.assertEqual(world.reserve, 0)
        self.assertEqual(step(world, a.pay_unload, 0), world)

    def test_split_and_cyclic_transfers_preserve_value(self):
        world = funded(4, 0, 0)
        world = step(world, a.send, 0, 1, 1)
        world = step(world, a.fold, 0)
        world = step(world, a.send, 0, 2, 3)
        world = step(world, a.receive, 1, 0)
        world = step(world, a.fold, 1)
        world = step(world, a.send, 1, 0, 1)
        world = step(world, a.receive, 0, 2)
        world = step(world, a.receive, 2, 1)
        self.assertEqual([w.normalized_balance() for w in world.wallets], [1, 0, 3])
        self.assertEqual(a.categories(world)["in_flight"], 0)

    def test_lost_delivery_data_never_refunds(self):
        world = step(funded(2), a.send, 0, 1, 2)
        world = step(world, a.copy_for_delivery, 0)
        world = step(world, a.lose_delivery_bytes, 0)
        with self.assertRaisesRegex(a.Rejected, "missing delivery bytes"):
            a.receive(world, 1, 0)
        self.assertEqual(world.wallets[0].balance, 0)
        self.assertEqual(a.categories(world)["in_flight"], 2)
        self.assertEqual(world.reserve, 2)

    def test_fee_is_earned_before_receive_and_paid_once(self):
        world = step(funded(4), a.send, 0, 1, 3, fee=1)
        self.assertEqual(a.categories(world)["earned_fees"], 1)
        world = step(world, a.pay_fee, 0)
        self.assertEqual(world.fee_online, 1)
        self.assertEqual(world.payments[0].received_variant, None)
        self.assertEqual(step(world, a.pay_fee, 0), world)
        world = step(world, a.receive, 1, 0)
        world = step(world, a.fold, 1)
        world = step(world, a.unload, 1, 3)
        world = step(world, a.pay_unload, 0)
        self.assertEqual((world.online, world.fee_online, world.reserve), ((0, 3), 1, 0))

    def test_load_charge_and_unload_withholding_are_separate(self):
        world = step(a.initial(7, 0), a.issue_load, 0, 5, charge=1)
        world = step(world, a.absorb_load, 0)
        world = step(world, a.fold, 0)
        world = step(world, a.unload, 0, 5, charge=2)
        world = step(world, a.pay_unload, 0)
        self.assertEqual((world.online, world.fee_online, world.reserve), ((4, 0), 3, 0))
        zero_net = step(funded(1), a.unload, 0, 1, charge=1)
        zero_net = step(zero_net, a.pay_unload, 0)
        self.assertEqual((zero_net.online, zero_net.fee_online), ((0, 0), 1))

    def test_failed_backed_receive_burns_only_that_amount(self):
        world = step(funded(2), a.send, 0, 1, 2)
        world = step(world, a.receive, 1, 0, variant=1)
        self.assertEqual(world.wallets[1].balance, 2)
        self.assertEqual(world.wallets[1].normalized_balance(), 0)
        self.assertEqual(a.categories(world)["burned_backing"], 2)
        world = step(world, a.fold, 1)
        with self.assertRaisesRegex(a.Rejected, "unavailable value"):
            a.unload(world, 1, 1)
        self.assertEqual(step(world, a.receive, 1, 0, variant=1), world)
        with self.assertRaisesRegex(a.Rejected, "conflicting original"):
            a.receive(world, 1, 0, variant=0)

    def test_unbacked_rejected_input_does_not_create_a_real_burn_liability(self):
        world = step(a.initial(0, 0), a.receive, 1, -2, variant=1)
        self.assertEqual(world.wallets[1].balance, 1)
        self.assertEqual(sum(a.categories(world).values()), 0)
        world = step(world, a.fold, 1)
        self.assertEqual(world.wallets[1].burned, 1)
        with self.assertRaises(a.Rejected):
            a.send(world, 1, 0, 1)

    def test_multiple_unbacked_inputs_never_accumulate_spendable_value(self):
        world = a.initial(0, 0)
        for key in (-2, -19, -200):
            world = step(world, a.receive, 1, key, variant=1)
            world = step(world, a.fold, 1)
        self.assertEqual((world.wallets[1].balance, world.wallets[1].burned), (3, 3))
        self.assertEqual(sum(a.categories(world).values()), 0)
        with self.assertRaises(a.Rejected):
            a.receive(world, 1, -300, variant=0)

    def test_archive_collection_requires_covering_fold_and_keeps_fee_original(self):
        world = step(funded(3), a.send, 0, 1, 2, fee=1)
        world = step(world, a.receive, 1, 0)
        world = step(world, a.archive, 0)
        with self.assertRaisesRegex(a.Rejected, "not durably covered"):
            a.collect_payment(world, 0)
        world = step(world, a.fold, 0)
        world = step(world, a.collect_payment, 0)
        self.assertFalse(world.payments[0].retained)
        self.assertTrue(world.payments[0].fee_retained)
        self.assertEqual(step(world, a.receive, 1, 0), world)
        world = step(world, a.pay_fee, 0)
        self.assertFalse(world.payments[0].fee_retained)

    def test_archive_noop_needs_core_resynchronization_before_another_archive(self):
        world = step(funded(2), a.send, 0, 1, 1)
        world = step(world, a.archive, 0, evidence_valid=False)
        self.assertEqual(world.wallets[0].core_pending, frozenset())
        self.assertEqual(world.wallets[0].adjusted_pending, frozenset({0}))
        world = step(world, a.fold, 0)
        with self.assertRaisesRegex(a.Rejected, "retained pending"):
            a.archive(world, 0, evidence_valid=False)
        world = step(world, a.retire, 0)
        self.assertEqual(world.wallets[0].core_pending, frozenset({0}))
        world = step(world, a.receive, 1, 0)
        world = step(world, a.archive, 0)
        world = step(world, a.fold, 0)
        world = step(world, a.collect_payment, 0)
        self.assertEqual(world.wallets[0].balance, 1)

    def test_retirement_race_preserves_preclosure_load(self):
        world = step(a.initial(2, 0), a.retire, 0)
        world = step(world, a.issue_load, 0, 1)
        world = step(world, a.close_loads, 0)
        with self.assertRaisesRegex(a.Rejected, "loads closed"):
            a.issue_load(world, 0, 1)
        world = step(world, a.absorb_load, 0)
        world = step(world, a.fold, 0)
        world = step(world, a.unload, 0, 1)
        world = step(world, a.pay_unload, 0)
        self.assertEqual(world.online[0], 2)

    def test_old_authenticated_request_remains_receivable_after_retirement(self):
        world = step(funded(1), a.retire, 1)
        world = step(world, a.send, 0, 1, 1)
        world = step(world, a.receive, 1, 0)
        world = step(world, a.fold, 1)
        world = step(world, a.unload, 1, 1)
        world = step(world, a.pay_unload, 0)
        self.assertEqual(world.online, (0, 1))
        with self.assertRaises(a.Rejected):
            a.send(world, 1, 0, 1)

    def test_integer_identity_and_capacity_guards(self):
        for balances in ((), (True,), (-1,), (a.MAX, 1)):
            with self.assertRaises(a.Rejected):
                a.initial(*balances)
        world = funded(1)
        for index in (-1, 2, True, "0"):
            with self.assertRaises(a.Rejected):
                a.owner(world, index)
        with self.assertRaises(a.Rejected):
            a.changed((), 0, None)
        with self.assertRaises(a.Rejected):
            a.send(world, 0, 0, 1)
        with self.assertRaises(a.Rejected):
            a.send(world, 0, 1, 1, fee=True)
        with self.assertRaises(a.Rejected):
            a.issue_load(a.initial(1), 0, 1, ordinal=False)
        overflow = funded(a.MAX)
        with self.assertRaisesRegex(a.Rejected, "balance overflow"):
            a.receive(overflow, 0, -1, variant=1)
        stopped = replace(world, wallets=a.changed(world.wallets, 0, replace(world.wallets[0], sequence=a.MAX)))
        with self.assertRaisesRegex(a.Rejected, "sequence overflow"):
            a.advance(stopped, 0)

    def test_mutation_refund_of_irreversible_send_is_detected(self):
        world = step(funded(1), a.send, 0, 1, 1)
        forged = replace(world, wallets=a.changed(world.wallets, 0, replace(world.wallets[0], balance=1)))
        with self.assertRaisesRegex(AssertionError, "reserve conservation"):
            a.invariant(forged)

    def test_mutation_missing_burn_is_detected(self):
        world = step(a.initial(0, 0), a.receive, 1, -2, variant=1)
        forged = replace(world, wallets=a.changed(world.wallets, 1, replace(world.wallets[1], deferred_burn=0)))
        with self.assertRaisesRegex(AssertionError, "reserve conservation"):
            a.invariant(forged)

    def test_mutation_duplicate_credit_is_detected(self):
        world = step(step(funded(1), a.send, 0, 1, 1), a.receive, 1, 0)
        wallet = world.wallets[1]
        forged = replace(world, wallets=a.changed(world.wallets, 1, replace(wallet, balance=wallet.balance + 1,
                                                                        credits=wallet.credits + wallet.credits)))
        with self.assertRaises(AssertionError):
            a.invariant(forged)

    def test_mutation_repeat_unload_payout_is_detected(self):
        world = step(step(funded(2), a.unload, 0, 1), a.pay_unload, 0)
        forged = replace(world, reserve=world.reserve - 1, online=a.changed(world.online, 0, world.online[0] + 1))
        with self.assertRaisesRegex(AssertionError, "reserve conservation"):
            a.invariant(forged)

    def test_mutation_fee_redirect_keeps_supply_but_violates_bound_beneficiary(self):
        world = step(step(funded(2), a.send, 0, 1, 1, fee=1), a.pay_fee, 0)
        forged = replace(world, fee_online=0, online=a.changed(world.online, 0, 1))
        with self.assertRaisesRegex(AssertionError, "fee beneficiary"):
            a.invariant(forged)

    def test_mutation_cross_wallet_value_shift_is_detected_without_inflation(self):
        world = funded(2)
        altered = (replace(world.wallets[0], balance=1), replace(world.wallets[1], balance=1))
        forged = replace(world, wallets=altered)
        self.assertEqual(sum(a.categories(forged).values()), forged.reserve)
        with self.assertRaisesRegex(AssertionError, "wallet effect ownership"):
            a.invariant(forged)

    def test_mutation_archive_noop_cannot_remove_adjusted_descriptor(self):
        world = step(step(funded(1), a.send, 0, 1, 1), a.archive, 0, evidence_valid=False)
        forged = replace(world, wallets=a.changed(world.wallets, 0, replace(world.wallets[0], adjusted_pending=frozenset())))
        with self.assertRaisesRegex(AssertionError, "adjusted pending retention"):
            a.invariant(forged)

    def test_mutation_collection_cannot_drop_unpaid_fee_original(self):
        world = step(step(funded(2), a.send, 0, 1, 1, fee=1), a.receive, 1, 0)
        world = step(step(step(world, a.archive, 0), a.fold, 0), a.collect_payment, 0)
        forged = replace(world, payments=a.changed(world.payments, 0, replace(world.payments[0], fee_retained=False)))
        with self.assertRaisesRegex(AssertionError, "unpaid fee original"):
            a.invariant(forged)

    def test_optimized_python_is_refused(self):
        result = subprocess.run([sys.executable, "-B", "-S", "-O", str(Path(__file__).with_name("accounting.py"))],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires unoptimized Python", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
