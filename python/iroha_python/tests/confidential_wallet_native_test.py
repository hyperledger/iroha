"""Installed public wallet integration; missing native support fails instead of skipping.

Run with the installed interpreter in isolated mode, for example
``python -I /path/to/confidential_wallet_native_test.py -v``.
"""

import unittest
from secrets import token_bytes
from threading import Event, Thread

import iroha_python
from iroha_python import (
    ConfidentialChange,
    ConfidentialInput,
    ConfidentialProver,
    ConfidentialProverError,
    ConfidentialTree,
    NetworkId,
)
from iroha_python.crypto import (
    AssetDefinitionId,
    compute_confidential_root_v2,
    derive_confidential_diversifier_v2,
    derive_confidential_note_v2,
    derive_confidential_owner_tag_v2,
    hash_blake2b_32,
)


class InstalledConfidentialWalletTests(unittest.TestCase):
    """Exercise one actual proof through the normal package and extension loader."""

    def test_wallet_public_exports(self):
        for name in (
            "ConfidentialChange", "ConfidentialInput", "ConfidentialOutput", "ConfidentialProof",
            "ConfidentialProver", "ConfidentialProverError", "ConfidentialTree",
        ):
            self.assertIn(name, iroha_python.__all__)
            self.assertIsNotNone(getattr(iroha_python, name))

    def test_private_change_can_be_spent_with_its_default_owner(self):
        network = NetworkId.from_bytes(hash_blake2b_32(b"installed-change-wallet-test"))
        asset = str(AssetDefinitionId.from_domain_and_name("example.is", "change-test"))
        key = token_bytes(32)
        note = ConfidentialInput(7, token_bytes(32), derive_confidential_diversifier_v2(token_bytes(32)), 0)
        owner = derive_confidential_owner_tag_v2(key, note.diversifier)
        commitment = derive_confidential_note_v2(asset, note.amount, note.rho, owner)
        tree = ConfidentialTree(compute_confidential_root_v2([commitment]), commitments=[commitment])
        change = ConfidentialChange(3, token_bytes(32))
        with ConfidentialProver(network, asset, key) as prover:
            proof = prover.prove_unshield(tree=tree, inputs=[note], public_amount=4, change=change)
            self.assertEqual(proof.relation, "redemption_with_change")
            # This is a local proof fixture. Real wallets authenticate the new root and index.
            change_input = change.to_input(1)
            self.assertNotEqual(change_input.diversifier, note.diversifier)
            expected = derive_confidential_note_v2(
                asset, change_input.amount, change_input.rho,
                derive_confidential_owner_tag_v2(key, change_input.diversifier),
            )
            self.assertEqual(proof.output_commitments, (expected,))
            history = [commitment, expected]
            change_tree = ConfidentialTree(compute_confidential_root_v2(history), commitments=history)
            redemption = prover.prove_unshield(tree=change_tree, inputs=[change_input], public_amount=3)
            self.assertEqual(redemption.relation, "full_redemption")
            self.assertTrue(redemption.proof)
            self.assertEqual(redemption.root, change_tree.root)
            self.assertEqual(len(redemption.nullifiers), 1)
            self.assertEqual(redemption.output_commitments, ())
            self.assertNotEqual(proof.nullifiers, redemption.nullifiers)

    def test_one_input_at_full_tree_capacity_proves_and_locally_verifies(self):
        # Fixed disposable openings; no ledger state or erasure promise for Python bytes.
        network = NetworkId.from_bytes(bytes([93]) * 32)
        asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        key = bytes([94]) * 32
        diversifier = derive_confidential_diversifier_v2(bytes([97]) * 32)
        owner = derive_confidential_owner_tag_v2(key, diversifier)
        commitments = [derive_confidential_note_v2(asset, 7, (index + 1).to_bytes(32, "little"), owner)
                       for index in range(65_536)]
        self.assertEqual(len(set(commitments)), 65_536)
        tree = ConfidentialTree(compute_confidential_root_v2(commitments), commitments=commitments)
        note = ConfidentialInput(7, (65_536).to_bytes(32, "little"), diversifier, 65_535)
        with ConfidentialProver(network, asset, key) as prover:
            proof = prover.prove_unshield(tree=tree, inputs=[note], public_amount=7)
        self.assertEqual(proof.relation, "full_redemption")
        self.assertEqual(proof.backend, "pipa-r/pasta")
        self.assertTrue(proof.proof)  # Native Core verifies before returning.
        self.assertEqual(proof.root, tree.root)
        self.assertEqual(len(proof.nullifiers), 1)
        self.assertEqual(len(proof.nullifiers[0]), 32)
        self.assertNotEqual(proof.nullifiers[0], bytes(32))
        self.assertEqual(proof.output_commitments, ())

    def test_actual_wallet_rejects_wrong_root_duplicate_inputs_and_bad_change(self):
        network = NetworkId.from_bytes(bytes([93]) * 32)
        asset = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
        key = bytes([94]) * 32
        diversifier = derive_confidential_diversifier_v2(bytes([97]) * 32)
        owner = derive_confidential_owner_tag_v2(key, diversifier)
        note = ConfidentialInput(7, bytes([95]) * 32, diversifier, 0)
        commitment = derive_confidential_note_v2(asset, 7, note.rho, owner)
        other = derive_confidential_note_v2(asset, 7, bytes([96]) * 32, owner)
        root = compute_confidential_root_v2([commitment])
        wrong_root = compute_confidential_root_v2([other])
        self.assertNotEqual(root, wrong_root)
        tree = ConfidentialTree(root, commitments=[commitment])
        with ConfidentialProver(network, asset, key) as prover:
            for expected_code, arguments in (
                ("proving", dict(tree=ConfidentialTree(wrong_root, commitments=[commitment]), inputs=[note], public_amount=7)),
                ("duplicate_input", dict(tree=tree, inputs=[note, note], public_amount=14)),
                ("invalid_change", dict(tree=tree, inputs=[note], public_amount=4, change=ConfidentialChange(2, bytes([96]) * 32))),
            ):
                with self.subTest(expected_code=expected_code), self.assertRaises(ConfidentialProverError) as failure:
                    prover.prove_unshield(**arguments)
                self.assertEqual(failure.exception.code, expected_code)
            proof = prover.prove_unshield(tree=tree, inputs=[note], public_amount=7)
            self.assertEqual(proof.relation, "full_redemption")
            self.assertEqual(proof.root, root)
            self.assertTrue(proof.proof)
            self.assertEqual(len(proof.nullifiers), 1)
            self.assertEqual(proof.output_commitments, ())

    def test_real_proof_releases_gil_and_closes_native_owner(self):
        network = NetworkId.from_bytes(hash_blake2b_32(b"installed-python-wallet-test"))
        asset = str(AssetDefinitionId.from_domain_and_name("example.is", "native-test"))
        key = token_bytes(32)
        diversifier = derive_confidential_diversifier_v2(token_bytes(32))
        note = ConfidentialInput(7, token_bytes(32), diversifier, 0)
        owner = derive_confidential_owner_tag_v2(key, diversifier)
        commitment = derive_confidential_note_v2(asset, note.amount, note.rho, owner)
        tree = ConfidentialTree(compute_confidential_root_v2([commitment]), commitments=[commitment])
        ready = Event()
        stop = Event()
        progress = []

        def other_python_thread():
            ready.set()
            while not stop.wait(0.01):
                progress.append(None)

        thread = Thread(target=other_python_thread, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(5), "Python progress worker did not start")
        try:
            with ConfidentialProver(network, asset, key) as prover:
                with self.assertRaises(ConfidentialProverError) as failure:
                    prover.prove_unshield(tree=tree, inputs=[note], public_amount=8)
                self.assertEqual(failure.exception.code, "invalid_public_amount")
                before = len(progress)
                proof = prover.prove_unshield(tree=tree, inputs=[note], public_amount=7)
                self.assertGreater(len(progress) - before, 1, "proof blocked Python thread progress")
                self.assertEqual(proof.relation, "full_redemption")
                self.assertEqual(proof.backend, "pipa-r/pasta")
                self.assertTrue(proof.proof)
                self.assertEqual(proof.root, tree.root)
                self.assertEqual(len(proof.nullifiers), 1)
                self.assertEqual(proof.output_commitments, ())
                print(f"Installed native proof: {len(proof.proof)} bytes; Python progress observed.")
            prover.close()
            with self.assertRaises(ConfidentialProverError) as failure:
                prover.prove_unshield(tree=tree, inputs=[note], public_amount=7)
            self.assertEqual(failure.exception.code, "closed")
        finally:
            stop.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
