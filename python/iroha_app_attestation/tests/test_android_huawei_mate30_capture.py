"""Genuine Huawei Cloud Testing evidence through the existing Google RSA adapter.

The fixed nonce and debug-app identity are diagnostic inputs, not a signed wallet
E1 challenge. Tests exercise the full Android evidence verifier with controlled
Google status responses and real temporary operator-denylist custody. They do not
qualify Huawei vendor roots or issue a wallet credential. Capture provenance and
public artifact hashes are in fixtures/huawei_mate30_cloud_capture/provenance.json.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    GOOGLE_ADAPTER_PROFILE,
    AndroidTrustAnchor,
    EnrollmentRefusal,
    EvidenceRefused,
    _parse_android_certificate,
    android_patch_policy_met,
    der_one,
    p256_point,
    spki_sha256,
    verify_android_key_attestation,
)
from iroha_app_attestation.revocation import (
    AndroidRevocation,
    GoogleAttestationStatus,
    GoogleStatusList,
    OperatorDenylistCustody,
    RevocationUnavailable,
    certificate_serial,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURE = FIXTURES / "huawei_mate30_cloud_capture"
# Independent request selected before the cloud run; never obtained from the leaf.
CHALLENGE = bytes.fromhex("0253567353484b29189d0a58c297ce35ecbecb956e1806b3cf4fdb9933923f83")
PACKAGE = "org.hyperledger.iroha.samples.attestationprobe"
SIGNER = bytes.fromhex("eb2e20a4d49918e1dbd9b78b20b62a7442812cb9d2cd808ff3deff3fb7c35c27")
GOOGLE_RSA_PIN = bytes.fromhex("feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae")
# Cloud Testing's reported execution end, after leaf generation and root expiry.
CAPTURE_TIME_MS = 1792488183000


class HuaweiMate30CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which("openssl")
        if executable is None:
            raise unittest.SkipTest("OpenSSL CLI unavailable")
        cls.openssl = Path(executable).resolve()
        cls.provenance = json.loads((CAPTURE / "provenance.json").read_text())
        cls.chain = [(CAPTURE / f"certificate-{index}.der").read_bytes() for index in range(4)]
        # The probe exported the generated public key separately from its certificate.
        cls.exported_spki = (CAPTURE / "public-key.spki.der").read_bytes()
        cls.payment_point = p256_point(der_one(cls.exported_spki))
        cls.anchor = AndroidTrustAnchor(
            "google_rsa", GOOGLE_RSA_PIN, "google_attestation_status", GOOGLE_ADAPTER_PROFILE)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)
        descriptor = os.open(self.directory, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        self.custody = OperatorDenylistCustody(self.directory, descriptor)
        self.custody.initialize(b'{"version":1,"sequence":1,"entries":[]}')
        self.google_calls = []
        self.google_serials = frozenset()
        self.google_error = None

        def test_status_source():
            self.google_calls.append(True)
            if self.google_error is not None:
                raise self.google_error
            return GoogleStatusList(self.google_serials, 0)

        self.revocation = AndroidRevocation(
            GoogleAttestationStatus(test_status_source, lambda: None), self.custody)

    def verify(self, **changes):
        arguments = {
            "challenge_digest": CHALLENGE,
            "payment_key_sec1": self.payment_point,
            "package_name": PACKAGE,
            "minimum_package_version": 1,
            "signer_set": (SIGNER,),
            "anchors": (self.anchor,),
            "revocation": self.revocation,
            "trusted_time_ms": lambda: CAPTURE_TIME_MS,
            "openssl_path": self.openssl,
        }
        arguments.update(changes)
        return verify_android_key_attestation(self.chain, **arguments)

    def assert_refused(self, code, **changes):
        with self.assertRaises(EvidenceRefused) as raised:
            self.verify(**changes)
        self.assertEqual(raised.exception.code, code, str(raised.exception))

    def test_public_capture_hashes_request_and_challenge_signature_are_intact(self):
        for name, recorded in self.provenance["files"].items():
            with self.subTest(file=name):
                self.assertEqual(Path(name).name, name)
                raw = (CAPTURE / name).read_bytes()
                self.assertEqual(len(raw), recorded["bytes"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), recorded["sha256"])
                if name.startswith("certificate-"):
                    self.assertEqual(spki_sha256(raw).hex(), recorded["spki_sha256"])
        request = self.provenance["independent_request"]
        self.assertEqual((request["challenge_hex"], request["package_name"], request["signer_sha256"]),
                         (CHALLENGE.hex(), PACKAGE, SIGNER.hex()))
        self.assertFalse(request["wallet_e1_challenge"])
        self.assertEqual((CAPTURE / "challenge.bin").read_bytes(), CHALLENGE)
        self.assertEqual(self.chain[-1], (FIXTURES / "google_factory_root_2016.der").read_bytes())
        public_key = self.directory / "public-key.pem"
        public_key.write_bytes(b"-----BEGIN PUBLIC KEY-----\n"
                               + base64.b64encode(self.exported_spki)
                               + b"\n-----END PUBLIC KEY-----\n")
        result = subprocess.run(
            [str(self.openssl), "dgst", "-sha256", "-verify", str(public_key),
             "-signature", str(CAPTURE / "challenge-signature.der"), str(CAPTURE / "challenge.bin")],
            capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_genuine_chain_passes_complete_android_verifier_with_controlled_revocation(self):
        self.assertEqual(spki_sha256(self.chain[-1]), GOOGLE_RSA_PIN)
        self.assertLess(_parse_android_certificate(self.chain[-1]).not_after_ms, CAPTURE_TIME_MS)
        result = self.verify()
        self.assertEqual(result.anchor, self.anchor)
        self.assertEqual((result.attestation_version, result.keymint_version,
                          result.security_level, result.package_version), (2, 3, 1, 1))
        self.assertTrue(result.factory_provisioned)
        self.assertEqual(self.google_calls, [True])
        self.assertEqual(result.patch_levels.os_patch_level, 202011)
        # The selected patch floor is a fact, not an admission gate.
        self.assertFalse(android_patch_policy_met(result.patch_levels, 202501))

    def test_unpinned_root_is_refused_before_revocation(self):
        unknown = AndroidTrustAnchor(
            "google_rsa", b"\x42" * 32, "google_attestation_status", GOOGLE_ADAPTER_PROFILE)
        self.assert_refused(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT, anchors=(unknown,))
        self.assertEqual(self.google_calls, [])

    def test_nonce_app_signer_version_and_payment_key_remain_bound(self):
        other_point = bytes.fromhex(
            "04"
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        for changes, code in (
            ({"challenge_digest": b"\x55" * 32}, EnrollmentRefusal.EVIDENCE_INVALID),
            ({"package_name": "pg.bpng.digitalkina"}, EnrollmentRefusal.APP_IDENTITY_MISMATCH),
            ({"signer_set": (b"\x66" * 32,)}, EnrollmentRefusal.APP_IDENTITY_MISMATCH),
            ({"minimum_package_version": 2}, EnrollmentRefusal.APP_VERSION_BELOW_MINIMUM),
            ({"payment_key_sec1": other_point}, EnrollmentRefusal.EVIDENCE_INVALID),
        ):
            with self.subTest(changes=tuple(changes)):
                self.assert_refused(code, **changes)

    def test_google_revocation_and_unavailability_are_not_exempted_for_factory_chain(self):
        self.google_serials = frozenset({certificate_serial(self.chain[1])})
        self.assert_refused(EnrollmentRefusal.ATTESTATION_REVOKED)
        self.google_error = RevocationUnavailable("controlled test source unavailable")
        with self.assertRaises(RevocationUnavailable):
            self.verify()
        self.assertEqual(self.google_calls, [True, True])

    def test_operator_serial_and_spki_denylists_still_refuse_genuine_chain(self):
        entries = (
            {"serial": format(certificate_serial(self.chain[1]), "x")},
            {"spki_sha256": spki_sha256(self.chain[0]).hex()},
            {"spki_sha256": GOOGLE_RSA_PIN.hex()},
        )
        for sequence, entry in enumerate(entries, 2):
            with self.subTest(entry=tuple(entry)):
                self.custody.offer(json.dumps(
                    {"version": 1, "sequence": sequence, "entries": [entry]},
                    separators=(",", ":")).encode())
                self.assert_refused(EnrollmentRefusal.ATTESTATION_REVOKED)
        self.assertEqual(self.google_calls, [True, True, True])

    def test_factory_profile_does_not_exempt_a_not_yet_valid_leaf(self):
        before_leaf = _parse_android_certificate(self.chain[0]).not_before_ms - 1
        self.assert_refused(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT,
                            trusted_time_ms=lambda: before_leaf)
        self.assertEqual(self.google_calls, [])
