"""A public Android capture cannot turn untrusted claims into hardware proof.

Source and license: fixtures/huawei_p40_untrusted/provenance.json. The publisher
labels the capture as a Huawei P40; the software-rooted evidence cannot itself
authenticate that device identity. These public certificates are rejection
fixtures, never enrollment trust anchors.
"""

import hashlib
import json
import shutil
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    ANDROID_KEY_DESCRIPTION_OID,
    GOOGLE_ADAPTER_PROFILE,
    AndroidTrustAnchor,
    EnrollmentRefusal,
    EvidenceRefused,
    _verify_exact_path,
    certificate_spki_extensions,
    children,
    der_one,
    positive_integer,
    primitive,
    spki_sha256,
    verify_android_key_attestation,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURE = FIXTURES / "huawei_p40_untrusted"
# Immediately after the publisher-reported capture, within all three certificates'
# validity periods; keeps fixture integrity checks independent of wall-clock time.
CAPTURE_TIME_MS = 1712832800000


class AndroidPublicCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which("openssl")
        if executable is None:
            raise unittest.SkipTest("OpenSSL CLI unavailable")
        cls.openssl = Path(executable).resolve()
        cls.provenance = json.loads((CAPTURE / "provenance.json").read_text())
        cls.chain = [(CAPTURE / item["file"]).read_bytes()
                     for item in cls.provenance["certificates"]]

    def test_public_certificates_match_provenance_and_have_valid_signature_links(self):
        for certificate, provenance in zip(self.chain, self.provenance["certificates"]):
            self.assertEqual(hashlib.sha256(certificate).hexdigest(),
                             provenance["certificate_der_sha256"])
            self.assertEqual(spki_sha256(certificate).hex(), provenance["spki_sha256"])
        # Mathematical path validation under the supplied root does not grant that
        # root authority. Production admission below must still refuse the chain.
        _verify_exact_path(self.chain, ["-attime", str(CAPTURE_TIME_MS // 1000)], self.openssl)

    def test_claimed_tee_security_cannot_override_the_untrusted_software_root(self):
        _, extensions = certificate_spki_extensions(self.chain[0])
        fields = children(der_one(extensions[ANDROID_KEY_DESCRIPTION_OID]))
        self.assertEqual((positive_integer(fields[0]), positive_integer(fields[1], 10),
                          positive_integer(fields[2]), positive_integer(fields[3], 10)),
                         (2, 1, 3, 1))
        google_root = (FIXTURES / "google_factory_root_2016.der").read_bytes()
        google_pin = spki_sha256(google_root)
        self.assertEqual(google_pin.hex(),
                         "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae")
        self.assertNotEqual(spki_sha256(self.chain[-1]), google_pin)

        def revocation(*_):
            self.fail("An untrusted root must be refused before checking revocation")

        with self.assertRaises(EvidenceRefused) as raised:
            verify_android_key_attestation(
                self.chain, challenge_digest=primitive(fields[4], 4),
                # The capture's leaf is RSA, not an admissible P-256 payment key.
                # A valid P-256 generator point supplies the independent request;
                # root rejection must take precedence over key/app mismatches.
                payment_key_sec1=bytes.fromhex(
                    "04"
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                package_name="at.asitplus.atttest", minimum_package_version=1,
                signer_set=(bytes.fromhex(
                    "34b9762c4d6c90d48431940c57bde7314258b26420efe16ac7f7274f0d330ad5"),),
                anchors=(AndroidTrustAnchor("google_rsa", google_pin,
                                            "google_attestation_status", GOOGLE_ADAPTER_PROFILE),),
                revocation=revocation, trusted_time_ms=lambda: CAPTURE_TIME_MS,
                openssl_path=self.openssl)
        self.assertEqual(raised.exception.code, EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT)
        self.assertIn("not in the pinned root set", str(raised.exception))
