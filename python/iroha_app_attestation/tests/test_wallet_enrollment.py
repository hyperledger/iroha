"""Current E1 composition on genuinely signed synthetic X509/KeyMint/App Attest originals.

Synthetic roots qualify component code only. They are never physical-device, distributed
app, production issuer or deployment evidence.
"""
import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    AttestationRejected, DurableAppleAssertionCounterStore, EnrollmentRefusal, EvidenceRefused,
    VerificationUnavailable, spki_sha256, verify_apple_wallet_attestation_raw,
    verify_apple_wallet_enrollment_assertion,
)
from iroha_app_attestation.native_time_interval import NativeTimeInterval
from iroha_app_attestation.revocation import (
    AndroidRevocation, GoogleAttestationStatus, GoogleStatusList, OperatorDenylistCustody,
)
from iroha_app_attestation.wallet_enrollment import (
    VerifiedWalletEnrollmentEvidence, WalletEnrollmentScope,
    verify_android_wallet_enrollment, verify_apple_wallet_enrollment,
)
from iroha_app_attestation.wallet_policy import (
    AndroidAppIdentityV1, AndroidEnrollmentPlatformV1, AndroidRootV1, AppleAppIdentityV1,
    AppleEnrollmentPlatformV1, ConfiguredWalletEnrollmentPolicyV1, RegulatoryPolicyV1,
    WalletAppPolicyV1, WalletEnrollmentPolicyV1,
)
from synthetic_pki import (
    APP_ID, PACKAGE, SIGNER, SignedEnvelope, SyntheticPki, apple_assertion, apple_object,
    key_description, now_ms, remote_hierarchy,
)

GENERATOR = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
Code = EnrollmentRefusal


def scope(point: bytes) -> WalletEnrollmentScope:
    return WalletEnrollmentScope(b"\1\0" + b"".join(bytes([i]) * 32 for i in range(1, 7)), point)


def configured_policy(root: bytes, apple: bool, *, roots=None, minimum=7,
                      signers=(SIGNER,)) -> ConfiguredWalletEnrollmentPolicyV1:
    """Synthetic component selection only; no operator approval or installed policy."""
    app = WalletAppPolicyV1(1, b"\1" * 32, AppleAppIdentityV1(APP_ID) if apple else
                           AndroidAppIdentityV1(PACKAGE, minimum, tuple(signers)))
    if apple:
        platform = AppleEnrollmentPlatformV1(hashlib.sha256(root).digest())
    else:
        platform = AndroidEnrollmentPlatformV1(roots or (
            AndroidRootV1("google_rsa", spki_sha256(root), "google_attestation_status"),), 202608)
    enrollment = WalletEnrollmentPolicyV1(1, b"\1" * 32, b"\2" * 32, app.policy_digest(),
        platform, RegulatoryPolicyV1(0, 0), 120_000, 0)
    return ConfiguredWalletEnrollmentPolicyV1(app, enrollment, root if apple else None)


def policy_scope(policy: ConfiguredWalletEnrollmentPolicyV1, point: bytes) -> WalletEnrollmentScope:
    return WalletEnrollmentScope(b"\1\0" + policy.enrollment.scheme_id + policy.enrollment.asset_digest
        + b"\3" * 32 + policy.app.policy_digest() + policy.enrollment.policy_digest() + b"\6" * 32, point)


def custody(directory: Path, original: bytes = b'{"version":1,"sequence":1,"entries":[]}'):
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY)
    held = OperatorDenylistCustody(directory.resolve(), fd)
    held.initialize(original)
    return held, fd


class WalletEnrollmentTests(unittest.TestCase):
    def setUp(self):
        binary = shutil.which("openssl")
        if binary is None:
            self.skipTest("OpenSSL3 unavailable")
        self.openssl = Path(binary).resolve()

    def test_e1_fixed_current_hashes_and_original_evidence_items(self):
        selected = scope(GENERATOR)
        self.assertEqual(selected.challenge_digest().hex(),
                         "9ee9b71a3026e333f8c69d1c5f338bdf8639fbd85644730be5bf5a3bdaf53682")
        self.assertEqual(selected.enrollment_key_binding().hex(),
                         "b4129d2396a72c9288160f28f26f1fc63f6935b8512a37fd722cc2aa5859454e")
        record = VerifiedWalletEnrollmentEvidence(
            1, 1, 0, 0, 0, 0, (b"leaf-der", b"root-der", b"actual-google-response"))
        self.assertEqual(record.evidence_digest().hex(),
                         "fa104a38766fc005595e4095c244607d1203f6bba3e66cbcfd60591a889d61e0")
        for value in (b"", selected.challenge_transcript + b"x",
                      b"\2\0" + selected.challenge_transcript[2:],
                      selected.challenge_transcript[:2] + b"\0" * 32 + selected.challenge_transcript[34:]):
            with self.subTest(value=value[:2]), self.assertRaises(AttestationRejected):
                WalletEnrollmentScope(value, GENERATOR).validate()

    def test_android_composition_records_chain_only_evidence_and_never_bit_nine(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            (base / "pki").mkdir()
            pki = SyntheticPki(base / "pki", self.openssl)
            remote_hierarchy(pki, "ec256")
            root = pki.der("root")
            pki.key("leaf")
            point = pki.point("leaf")
            policy = configured_policy(root, False)
            selected = policy_scope(policy, point)
            held, fd = custody(base / "store")
            self.addCleanup(os.close, fd)
            revocation = AndroidRevocation(GoogleAttestationStatus(
                lambda: GoogleStatusList(frozenset(), 0), lambda: None), held)
            now = now_ms()

            def chain(**changes):
                description = key_description(selected.challenge_digest(), **changes)
                return [pki.leaf("leaf", "attestation", description, new_key=False),
                        pki.der("attestation"), pki.der("intermediate"), root]

            def verify(certificates, *, sample=lambda: NativeTimeInterval(now, now), policy=policy,
                       selected=selected, checker=revocation):
                return verify_android_wallet_enrollment(
                    certificates, selected, policy, checker, self.openssl,
                    evidence_time_ms=now - 5, challenge_created_at_ms=now - 10,
                    trusted_time_interval=sample)

            for level, kind_facts in ((1, 0), (2, 1 << 1)):
                with self.subTest(level=level):
                    certificates = chain(level=level, os_patch_level=202608,
                                         vendor_patch_level=20260805, boot_patch_level=20260901)
                    record = verify(certificates)
                    self.assertEqual(record.kind_tag, level)
                    self.assertEqual(record.facts, 0b10000111101 | kind_facts)
                    self.assertFalse(record.facts & (1 << 9))
                    self.assertEqual(record.original_items, tuple(certificates))
                    self.assertEqual(record.time_ms, now - 5)
                    self.assertEqual((record.os_patch_level, record.vendor_patch_level,
                                      record.boot_patch_level), (202608, 20260805, 20260901))
            unmet = verify(chain(level=1))
            self.assertEqual(unmet.facts, 0b10000101101)
            self.assertEqual((unmet.os_patch_level, unmet.boot_patch_level), (0, 0))
            # Another payment key, an expired window and a revocation outage.
            with self.assertRaises(EvidenceRefused) as raised:
                verify(chain(), selected=WalletEnrollmentScope(selected.challenge_transcript, GENERATOR))
            self.assertEqual(raised.exception.code, Code.EVIDENCE_INVALID)
            samples = iter([now, now + 200_000])

            def expiring():
                moment = next(samples)
                return NativeTimeInterval(moment, moment)
            with self.assertRaises(EvidenceRefused) as raised:
                verify(chain(), sample=expiring)
            self.assertEqual(raised.exception.code, Code.CHALLENGE_EXPIRED)
            with self.assertRaises(VerificationUnavailable):
                verify(chain(), checker=AndroidRevocation(GoogleAttestationStatus(
                    lambda: (_ for _ in ()).throw(VerificationUnavailable("offline")), lambda: None), held))
            # Refusals follow the ordered admission steps.
            for changes, code in (({"locked": False}, Code.BOOTLOADER_UNLOCKED),
                                  ({"packages": ((PACKAGE, 6),)}, Code.APP_VERSION_BELOW_MINIMUM),
                                  ({"signers": (b"\x72" * 32,)}, Code.APP_IDENTITY_MISMATCH)):
                with self.subTest(changes=changes), self.assertRaises(EvidenceRefused) as raised:
                    verify(chain(**changes))
                self.assertEqual(raised.exception.code, code)
            # A policy naming the shipped (unqualified) huawei profile is a configuration failure.
            vendor = configured_policy(root, False, roots=(
                AndroidRootV1("vendor", spki_sha256(root), "operator_denylist", "huawei"),))
            with self.assertRaisesRegex(AttestationRejected, "unqualified") as raised:
                verify(chain(), policy=vendor, selected=policy_scope(vendor, point))
            self.assertNotIsInstance(raised.exception, EvidenceRefused)

    def test_current_apple_uses_prehashed_e1_and_binding_without_extra_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SignedEnvelope(Path(temporary), self.openssl)
            selected = scope(GENERATOR)  # Separate payment key; App Attest key is fixture.point.
            obj, key_id, root = apple_object(fixture, selected.challenge_digest())
            pin = hashlib.sha256(root).digest()
            now = now_ms()
            proof = verify_apple_wallet_attestation_raw(
                obj, key_id, APP_ID, "production", selected.challenge_digest(),
                root, pin, now, self.openssl)
            self.assertEqual(proof.attested_public_key_sec1, fixture.point)
            signed = apple_assertion(fixture, selected.enrollment_key_binding(), 1)
            args = (signed, selected.enrollment_key_binding(), fixture.point, key_id, APP_ID, 0, self.openssl)
            verified = verify_apple_wallet_enrollment_assertion(*args)
            self.assertEqual(verified.counter, 1)
            self.assertEqual(verified.client_data_sha256, selected.enrollment_key_binding())
            for changed, code in (
                ((signed, hashlib.sha256(selected.enrollment_key_binding()).digest(), *args[2:]),
                 Code.EVIDENCE_INVALID),
                ((signed, *args[1:4], "TEAMID.other.app", 0, self.openssl), Code.APP_IDENTITY_MISMATCH),
                ((signed, *args[1:5], 1, self.openssl), Code.EVIDENCE_INVALID),
            ):
                with self.subTest(code=code), self.assertRaises(EvidenceRefused) as raised:
                    verify_apple_wallet_enrollment_assertion(*changed)
                self.assertEqual(raised.exception.code, code)
            for arguments, code in (
                ((obj, key_id, APP_ID, "production", hashlib.sha256(selected.challenge_digest()).digest(),
                  root, pin), Code.EVIDENCE_INVALID),
                ((obj, key_id, "TEAMID.other.app", "production", selected.challenge_digest(), root, pin),
                 Code.APP_IDENTITY_MISMATCH),
                ((obj, key_id, APP_ID, "development", selected.challenge_digest(), root, pin),
                 Code.APP_IDENTITY_MISMATCH),
                ((obj, b"\7" * 32, APP_ID, "production", selected.challenge_digest(), root, pin),
                 Code.EVIDENCE_INVALID),
                ((obj, key_id, APP_ID, "production", selected.challenge_digest(), b"other root",
                  hashlib.sha256(b"other root").digest()), Code.UNTRUSTED_ATTESTATION_ROOT),
                ((obj[:-1], key_id, APP_ID, "production", selected.challenge_digest(), root, pin),
                 Code.EVIDENCE_INVALID),
            ):
                with self.subTest(code=code, app=arguments[2]), self.assertRaises(EvidenceRefused) as raised:
                    verify_apple_wallet_attestation_raw(*arguments, now, self.openssl)
                self.assertEqual(raised.exception.code, code)
            with self.assertRaises(EvidenceRefused) as raised:
                verify_apple_wallet_attestation_raw(obj, key_id, APP_ID, "production",
                                                    selected.challenge_digest(), root, pin,
                                                    now + 3 * 86_400_000, self.openssl)
            self.assertEqual(raised.exception.code, Code.UNTRUSTED_ATTESTATION_ROOT)

    def test_current_apple_composition_preserves_counter_and_consumed_challenge_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            fixture = SignedEnvelope(directory, self.openssl)
            policy = configured_policy(fixture.root_der(), True)
            selected = policy_scope(policy, GENERATOR)
            now = now_ms()
            obj, key_id, root = apple_object(fixture, selected.challenge_digest())
            store = DurableAppleAssertionCounterStore(directory / "counters.sqlite")
            signed = apple_assertion(fixture, selected.enrollment_key_binding(), 1)
            record = verify_apple_wallet_enrollment(
                obj, signed, key_id, selected, policy, store,
                now, self.openssl, challenge_created_at_ms=now - 1)
            self.assertEqual(record.kind_tag, 3)
            self.assertEqual(record.facts, (1 << 6) | (1 << 7) | (1 << 8))
            self.assertEqual((record.os_patch_level, record.vendor_patch_level, record.boot_patch_level), (0, 0, 0))
            self.assertEqual(record.original_items, (obj, signed))
            store = DurableAppleAssertionCounterStore(directory / "counters.sqlite")
            with self.assertRaisesRegex(EvidenceRefused, "counter did not advance"):
                verify_apple_wallet_enrollment(obj, signed, key_id, selected, policy, store,
                                              now, self.openssl, challenge_created_at_ms=now - 1)
            replay = apple_assertion(fixture, selected.enrollment_key_binding(), 2)
            with self.assertRaisesRegex(EvidenceRefused, "already consumed"):
                verify_apple_wallet_enrollment(obj, replay, key_id, selected, policy, store,
                                              now, self.openssl, challenge_created_at_ms=now - 1)
            with self.assertRaises(EvidenceRefused) as raised:
                verify_apple_wallet_enrollment(obj, replay, key_id, selected, policy, store,
                                              now + 200_000, self.openssl, challenge_created_at_ms=now - 1)
            self.assertEqual(raised.exception.code, Code.CHALLENGE_EXPIRED)


if __name__ == "__main__":
    unittest.main()
