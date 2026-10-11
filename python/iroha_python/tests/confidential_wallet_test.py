"""Wallet API boundary controls; native proving is independently tested in Rust."""

import copy
import importlib.util
import pickle
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def load_wallet():
    name = "_confidential_wallet_fixture"
    package = ModuleType(name)
    package.__path__ = []
    source = Path(__file__).parents[1] / "src/iroha_python/confidential.py"
    spec = importlib.util.spec_from_file_location(name + ".confidential", source)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: package, spec.name: module}):
        spec.loader.exec_module(module)
    return module


wallet = load_wallet()


class NativeError(Exception):
    pass


class NativeWallet:
    def __init__(self, *args):
        self.arguments = args
        self.calls = []
        self.closed = False
        self.failure = None
        self.mutate = lambda result: result

    def close(self):
        self.closed = True

    def _proof(self, operation, args):
        self.calls.append((operation, args))
        if self.failure is not None:
            raise self.failure
        count = (
            len(args["outputs"])
            if operation == "transfer"
            else int(args["change_note"] is not None)
        )
        relation = (
            "transfer"
            if operation == "transfer"
            else ("redemption_with_change" if count else "full_redemption")
        )
        return self.mutate(
            dict(
                relation=relation,
                backend="pipa-r/pasta",
                proof=b"test-proof",
                root=args["root"],
                nullifiers=[bytes([1]) * 32] * len(args["inputs"]),
                output_commitments=[bytes([2]) * 32] * count,
            )
        )

    def prove_transfer(self, **args):
        return self._proof("transfer", args)

    def prove_unshield(self, **args):
        return self._proof("redemption", args)


class ConfidentialWalletTests(unittest.TestCase):
    def setUp(self):
        self.crypto = ModuleType("_confidential_wallet_fixture.crypto")
        self.crypto._crypto = ModuleType("native")
        self.crypto._crypto.ConfidentialProver = NativeWallet
        self.crypto._crypto.ConfidentialWalletError = NativeError
        self.crypto._require_network_id = lambda value: value
        self.crypto.default_confidential_diversifier_v2 = lambda: bytes([1]) + bytes(31)
        patcher = patch.dict(sys.modules, {self.crypto.__name__: self.crypto})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.prover = wallet.ConfidentialProver(object(), "asset", b"k" * 32)
        self.native = self.prover._owner
        self.note = wallet.ConfidentialInput(7, b"r" * 32, b"d" * 32, 0)
        self.tree = wallet.ConfidentialTree(b"t" * 32, commitments=[b"c" * 32])

    def test_change_to_input_retains_opening_and_uses_default_owner(self):
        change = wallet.ConfidentialChange(3, b"c" * 32)
        note = change.to_input(65535)
        self.assertEqual((note.amount, note.rho, note.leaf_index), (3, change.rho, 65535))
        self.assertEqual(note.diversifier, bytes([1]) + bytes(31))
        self.assertNotEqual(note.diversifier, self.note.diversifier)
        for invalid in [-1, 65536, True, "0"]:
            with self.assertRaises(wallet.ConfidentialProverError):
                change.to_input(invalid)

    def test_three_relations_select_keys_in_native_owner_without_dummy_notes(self):
        output = wallet.ConfidentialOutput(7, b"r" * 32, b"o" * 32)
        transfer = self.prover.prove_transfer(tree=self.tree, inputs=[self.note], outputs=[output])
        full = self.prover.prove_unshield(tree=self.tree, inputs=[self.note], public_amount=7)
        change = self.prover.prove_unshield(
            tree=self.tree,
            inputs=[self.note],
            public_amount=5,
            change=wallet.ConfidentialChange(2, b"s" * 32),
        )
        self.assertEqual(
            [transfer.relation, full.relation, change.relation],
            ["transfer", "full_redemption", "redemption_with_change"],
        )
        self.assertEqual(len(full.output_commitments), 0)
        for _, args in self.native.calls:
            self.assertEqual(len(args["inputs"]), 1)
            self.assertNotIn("verifying_key", args)
            self.assertNotIn("circuit_id", args)
            self.assertNotIn("spend_key", args)

    def test_paths_and_complete_tree_at_capacity_preserve_actual_note_count(self):
        full = wallet.ConfidentialTree(b"t" * 32, commitments=[b"c" * 32] * 65536)
        self.prover.prove_unshield(tree=full, inputs=[self.note], public_amount=7)
        self.assertEqual(len(self.native.calls[-1][1]["tree_commitments"]), 65536)
        path = {"root": b"t" * 32, "siblings": [b"s" * 32] * 16, "directions": [0] * 16}
        tree = wallet.ConfidentialTree(b"t" * 32, paths=[path])
        self.prover.prove_unshield(tree=tree, inputs=[self.note], public_amount=7)
        args = self.native.calls[-1][1]
        self.assertEqual(args["input_paths"], [path])
        self.assertNotIn("tree_commitments", args)

    def test_context_manager_disposal_copy_and_debug_contract(self):
        with self.prover as same:
            self.assertIs(same, self.prover)
            self.assertEqual(repr(same), "ConfidentialProver(private_context=[REDACTED])")
            self.assertNotIn("rrrr", repr(self.note))
            for copier in (copy.copy, copy.deepcopy, pickle.dumps):
                with self.assertRaises(TypeError):
                    copier(same)
        self.assertTrue(self.native.closed)
        self.prover.close()
        with self.assertRaises(wallet.ConfidentialProverError) as caught:
            self.prover.prove_unshield(tree=self.tree, inputs=[self.note], public_amount=7)
        self.assertEqual(caught.exception.code, "closed")

    def test_bounded_shape_errors_precede_native_work(self):
        trees = [
            wallet.ConfidentialTree(b"t" * 32),
            wallet.ConfidentialTree(b"t" * 32, commitments=[], paths=[]),
            wallet.ConfidentialTree(b"t" * 32, commitments=[b"c" * 32] * 65537),
        ]
        for tree in trees:
            with self.subTest(tree=tree), self.assertRaises(wallet.ConfidentialProverError):
                self.prover.prove_unshield(tree=tree, inputs=[self.note], public_amount=7)
        for inputs in ([self.note] * 3, [dict(amount=7)], iter([self.note])):
            with self.assertRaises(wallet.ConfidentialProverError):
                self.prover.prove_unshield(tree=self.tree, inputs=inputs, public_amount=7)
        self.assertEqual(self.native.calls, [])

    def test_native_typed_failure_preserves_cause(self):
        self.native.failure = NativeError("invalid_change", "supply exact private change")
        with self.assertRaises(wallet.ConfidentialProverError) as caught:
            self.prover.prove_unshield(tree=self.tree, inputs=[self.note], public_amount=7)
        self.assertEqual(caught.exception.code, "invalid_change")
        self.assertIs(caught.exception.__cause__, self.native.failure)

    def test_output_relation_root_and_cardinality_are_checked(self):
        for mutation in (
            dict(root=b"x" * 32),
            dict(nullifiers=[]),
            dict(output_commitments=[b"x" * 32]),
            dict(relation="transfer"),
            dict(backend="unrelated"),
            dict(proof=b""),
            dict(nullifiers=[b"short"]),
        ):
            self.native.mutate = lambda result, mutation=mutation: result | mutation
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(wallet.ConfidentialProverError) as caught,
            ):
                self.prover.prove_unshield(tree=self.tree, inputs=[self.note], public_amount=7)
            self.assertEqual(caught.exception.code, "native_output")

    def test_unavailable_native_has_actionable_error(self):
        del self.crypto._crypto.ConfidentialProver
        with self.assertRaises(wallet.ConfidentialProverError) as caught:
            wallet.ConfidentialProver(object(), "asset", b"k" * 32)
        self.assertEqual(caught.exception.code, "native_unavailable")
        self.assertIn("rebuild", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
