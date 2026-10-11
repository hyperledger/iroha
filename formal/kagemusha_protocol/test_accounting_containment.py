"""Defensive duplicate intake and valid burned-credit Archive accounting controls."""
from dataclasses import replace
import unittest

import accounting as a
from test_accounting import funded, step


def received(*, variant=0, fee=0):
    """Two-unit backed first credit, optionally burned, with a separate Send fee."""
    world = step(funded(2 + fee), a.send, 0, 1, 2, fee=fee)
    return step(world, a.receive, 1, 0, variant=variant)


class AccountingContainmentTests(unittest.TestCase):
    def test_burned_first_credit_archives_and_collects_without_releasing_backing(self):
        world = step(received(variant=1, fee=1), a.fold, 1)
        first = world.wallets[1].credits
        world = step(world, a.archive, 0)
        with self.assertRaisesRegex(a.Rejected, "not durably covered"):
            a.collect_payment(world, 0)
        world = step(step(world, a.fold, 0), a.collect_payment, 0)
        self.assertEqual(world.wallets[1].credits, first)
        self.assertFalse(world.payments[0].retained)
        self.assertTrue(world.payments[0].fee_retained)
        world = step(world, a.pay_fee, 0)
        self.assertEqual((world.reserve, a.categories(world)["burned_backing"]), (2, 2))
        self.assertEqual(world.wallets[1].normalized_balance(), 0)

    def test_same_original_duplicate_is_new_committed_effect_but_not_another_credit(self):
        world = received()
        first, categories = world.wallets[1].credits, a.categories(world)
        self.assertEqual(step(world, a.receive, 1, 0), world)
        world = step(world, a.contain_duplicate_receive, 1, 0, 2, digest=0, sequence=2)
        self.assertEqual(world.wallets[1].credits, first)
        self.assertEqual(a.categories(world), categories)
        self.assertEqual((world.wallets[1].balance, world.wallets[1].deferred_burn), (4, 2))
        with self.assertRaisesRegex(a.Rejected, "must be folded"):
            a.unload(world, 1, 1)
        world = step(world, a.fold, 1)
        world = step(step(world, a.unload, 1, 2), a.pay_unload, 0)
        self.assertEqual((world.online, world.reserve), ((0, 2), 0))
        self.assertEqual(world.wallets[1].normalized_balance(), 0)

    def test_changed_digest_duplicate_keeps_first_original_and_replays_exact_operation(self):
        world = received()
        first, payment = world.wallets[1].credits, world.payments[0]
        world = step(world, a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=2)
        self.assertEqual(world.wallets[1].credits, first)
        self.assertEqual(world.payments[0], payment)
        self.assertEqual((world.wallets[1].balance, world.wallets[1].normalized_balance()), (5, 2))
        world = step(world, a.fold, 1)
        self.assertEqual(step(world, a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=2), world)
        self.assertEqual(step(world, a.receive, 1, 0, digest=0), world)
        with self.assertRaisesRegex(a.Rejected, "conflicting original"):
            a.receive(world, 1, 0, digest=1)
        with self.assertRaisesRegex(a.Rejected, "conflicting committed duplicate"):
            a.contain_duplicate_receive(world, 1, 0, 2, digest=1, sequence=2)

    def test_alternate_original_amount_is_permanent_across_duplicate_sequences(self):
        world = step(received(), a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=2)
        first = world.wallets[1].credits
        with self.assertRaisesRegex(a.Rejected, "duplicate original amount"):
            a.contain_duplicate_receive(world, 1, 0, 4, digest=1, sequence=3)
        world = step(world, a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=3)
        self.assertEqual(world.wallets[1].credits, first)
        self.assertEqual((world.wallets[1].balance, world.wallets[1].deferred_burn), (8, 6))
        self.assertEqual(step(world, a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=2), world)

    def test_original_amount_mutation_rejects_even_when_balance_and_burn_conserve_value(self):
        for digest, amount in ((0, 2), (1, 3)):
            with self.subTest(digest=digest):
                world = step(received(), a.contain_duplicate_receive, 1, 0, amount, digest=digest, sequence=2)
                world = step(world, a.contain_duplicate_receive, 1, 0, amount, digest=digest, sequence=3)
                wallet = world.wallets[1]
                forged_effect = replace(wallet.duplicate_receives[-1], amount=amount + 1)
                forged_wallet = replace(wallet, balance=wallet.balance + 1,
                                        deferred_burn=wallet.deferred_burn + 1,
                                        duplicate_receives=wallet.duplicate_receives[:-1] + (forged_effect,))
                forged = replace(world, wallets=a.changed(world.wallets, 1, forged_wallet))
                self.assertEqual(a.categories(forged), a.categories(world))
                with self.assertRaisesRegex(AssertionError, "original amount consistency"):
                    a.invariant(forged)

    def test_other_digest_archive_cannot_replace_first_credit_evidence(self):
        world = step(received(), a.contain_duplicate_receive, 1, 0, 2, digest=1, sequence=2)
        with self.assertRaisesRegex(a.Rejected, "does not bind"):
            a.archive(world, 0, evidence_digest=1)
        world = step(world, a.archive, 0, evidence_valid=False, evidence_digest=1)
        self.assertIn(0, world.wallets[0].adjusted_pending)
        world = step(step(world, a.fold, 0), a.retire, 0)
        world = step(world, a.archive, 0, evidence_digest=0)
        self.assertNotIn(0, world.wallets[0].adjusted_pending)
        self.assertEqual((world.wallets[1].credits[0].digest, world.wallets[1].credits[0].variant), (0, 0))

    def test_duplicate_after_first_burn_adds_no_second_backing_liability(self):
        for digest in (0, 1):
            with self.subTest(digest=digest):
                world = received(variant=1)
                first = world.wallets[1].credits
                amount = 2 + digest
                world = step(world, a.contain_duplicate_receive, 1, 0, amount, digest=digest, sequence=2)
                world = step(world, a.fold, 1)
                self.assertEqual(world.wallets[1].credits, first)
                self.assertEqual((world.wallets[1].balance, world.wallets[1].burned), (2 + amount, 2 + amount))
                self.assertEqual((world.reserve, a.categories(world)["burned_backing"]), (2, 2))
                self.assertEqual(step(world, a.receive, 1, 0, variant=1), world)
                world = step(world, a.archive, 0)
                self.assertEqual(a.categories(world)["burned_backing"], 2)

    def test_unbacked_duplicate_still_creates_no_reserve_or_spendable_value(self):
        world = step(a.initial(0, 0), a.receive, 1, -1, variant=1, digest=7)
        world = step(world, a.contain_duplicate_receive, 1, -1, 3, digest=8, sequence=2)
        world = step(world, a.fold, 1)
        self.assertEqual((world.wallets[1].balance, world.wallets[1].burned), (4, 4))
        self.assertEqual(sum(a.categories(world).values()), 0)
        self.assertEqual((world.wallets[1].credits[0].digest, world.wallets[1].credits[0].variant), (7, 1))
        with self.assertRaises(a.Rejected):
            a.send(world, 1, 0, 1)

    def test_duplicate_requires_existing_credit_distinct_sequence_and_bounded_terms(self):
        world = received()
        for changes in ({"key": 1}, {"receiver": 0, "sequence": 3}, {"sequence": 1},
                        {"sequence": 3}, {"sequence": True}, {"amount": 0},
                        {"amount": True}, {"amount": 3}, {"amount": a.MAX}, {"digest": True}, {"digest": -1}):
            terms = dict(receiver=1, key=0, amount=2, digest=0, sequence=2)
            terms.update(changes)
            with self.subTest(changes=changes), self.assertRaises(a.Rejected):
                a.contain_duplicate_receive(world, **terms)
        overflow = step(funded(a.MAX), a.send, 0, 1, a.MAX)
        overflow = step(overflow, a.receive, 1, 0)
        with self.assertRaisesRegex(a.Rejected, "balance overflow"):
            a.contain_duplicate_receive(overflow, 1, 0, a.MAX, digest=0, sequence=2)
        fresh = step(funded(1), a.send, 0, 1, 1)
        with self.assertRaisesRegex(a.Rejected, "Payment original"):
            a.receive(fresh, 1, 0, digest=1)
        with self.assertRaisesRegex(a.Rejected, "evidence original"):
            a.archive(world, 0, evidence_digest=True)

    def test_mutations_cannot_omit_duplicate_burn_effect_or_overwrite_first_digest_flag(self):
        world = step(received(), a.contain_duplicate_receive, 1, 0, 3, digest=1, sequence=2)
        wallet = world.wallets[1]
        changed_credit = replace(wallet.credits[0], digest=1)
        variants = (
            replace(wallet, deferred_burn=0),
            replace(wallet, duplicate_receives=()),
            replace(wallet, credits=(changed_credit,)),
            replace(wallet, credits=(replace(wallet.credits[0], variant=1),)),
            replace(wallet, duplicate_receives=wallet.duplicate_receives * 2),
        )
        for forged in variants:
            with self.subTest(forged=forged), self.assertRaises(AssertionError):
                a.invariant(replace(world, wallets=a.changed(world.wallets, 1, forged)))


if __name__ == "__main__":
    unittest.main()
