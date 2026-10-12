"""Current scope/evidence digests against the Model's shared wallet vectors.

These component tests do not authorize a serving issuer, production app or device.
"""
import hashlib
import json
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import AttestationRejected
from iroha_app_attestation.wallet_enrollment import (
    WalletEnrollmentScope, VerifiedWalletEnrollmentEvidence,
)

GENERATOR = bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                          "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")


class CurrentWalletChallengeTests(unittest.TestCase):
    def setUp(self) -> None:
        vectors = json.loads((Path(__file__).resolve().parents[3]
                              / "fixtures/kagemusha/wallet_v1_vectors.json").read_text())
        self.vectors = {item["role"]: item for item in vectors["digests"]}
        self.challenge = WalletEnrollmentScope(
            bytes.fromhex(self.vectors["enrollment-challenge"]["body_hex"]), GENERATOR)

    def test_exact_current_model_challenge_digest_and_preimage(self):
        vector = self.vectors["enrollment-challenge"]
        self.assertEqual(len(self.challenge.challenge_transcript), 194)
        self.assertEqual(self.challenge.challenge_digest().hex(), vector["digest_hex"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(vector["preimage_hex"])).digest(),
                         self.challenge.challenge_digest())
        self.assertNotEqual(hashlib.sha256(self.challenge.challenge_transcript).digest(),
                            self.challenge.challenge_digest())

    def test_exact_current_model_evidence_digest_preserves_original_item_order(self):
        vector = self.vectors["evidence"]
        items = (b"tee-leaf-der", b"tee-intermediate-der")
        self.assertEqual(VerifiedWalletEnrollmentEvidence(1, 1, 0, 0, 0, 0, items).evidence_digest().hex(),
                         vector["digest_hex"])
        self.assertNotEqual(VerifiedWalletEnrollmentEvidence(1, 1, 0, 0, 0, 0, items[::-1]).evidence_digest(),
                            VerifiedWalletEnrollmentEvidence(1, 1, 0, 0, 0, 0, items).evidence_digest())
        self.assertNotEqual(VerifiedWalletEnrollmentEvidence(2, 1, 0, 0, 0, 0, items).evidence_digest(),
                            VerifiedWalletEnrollmentEvidence(1, 1, 0, 0, 0, 0, items).evidence_digest())

    def test_android_digest_is_the_chain_alone_and_key_binding_matches_the_model(self):
        # Android evidence items are exactly the leaf-first chain: no vendor verdict follows.
        items = (b"original-leaf", b"original-intermediate", b"original-root")
        body = b"\2" + len(items).to_bytes(4, "little")
        body += b"".join(len(item).to_bytes(4, "little") + item for item in items)
        expected = hashlib.sha256(b"iroha:kagemusha:wallet:v1:evidence\0"
                                  + len(body).to_bytes(8, "little") + body).digest()
        self.assertEqual(VerifiedWalletEnrollmentEvidence(2, 1, 0, 0, 0, 0, items).evidence_digest(),
                         expected)
        key_vector = self.vectors["enrollment-key-binding"]
        key_body = bytes.fromhex(key_vector["body_hex"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(key_vector["preimage_hex"])).hexdigest(),
                         key_vector["digest_hex"])
        self.assertEqual(len(key_body), 97)
        selected = WalletEnrollmentScope(self.challenge.challenge_transcript, key_body[32:])
        binding_body = selected.challenge_digest() + selected.payment_key_sec1
        binding = hashlib.sha256(b"iroha:kagemusha:wallet:v1:enrollment-key-binding\0"
                                 + len(binding_body).to_bytes(8, "little") + binding_body).digest()
        self.assertEqual(selected.enrollment_key_binding(), binding)

    def test_noncurrent_transcripts_versions_zero_bindings_and_oversize_reject(self):
        invalid = [self.challenge.challenge_transcript[:-1], self.challenge.challenge_transcript + b"\0",
                   b"\x02\0" + self.challenge.challenge_transcript[2:],
                   b"\0\0" + self.challenge.challenge_transcript[2:],
                   bytearray(self.challenge.challenge_transcript)]
        for offset in range(2, 194, 32):
            invalid.append(self.challenge.challenge_transcript[:offset] + b"\0" * 32
                           + self.challenge.challenge_transcript[offset + 32:])
        for value in invalid:
            with self.subTest(length=len(value)), self.assertRaises(AttestationRejected):
                WalletEnrollmentScope(value, GENERATOR).validate()


if __name__ == "__main__":
    unittest.main()
