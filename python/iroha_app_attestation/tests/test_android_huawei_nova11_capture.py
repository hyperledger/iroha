"""Refuse an untrusted, plausibly formed capture from one Huawei cloud-lab device.

This is genuine captured public evidence, not a trusted hardware identity. Its
demo-named root is not pinned and two issuing certificates lack CA constraints.
The lab/probe reports Nova 11 / FOA-LX9; this fixture establishes nothing about
retail Nova 11 provisioning. No vendor profile or production pin is changed.
"""

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    ANDROID_KEY_DESCRIPTION_OID,
    GOOGLE_ADAPTER_PROFILE,
    AndroidTrustAnchor,
    AttestationRejected,
    EnrollmentRefusal,
    EvidenceRefused,
    _authorization_list,
    _integer_set,
    _parse_android_certificate,
    _verify_exact_path,
    children,
    der_boolean,
    der_one,
    p256_point,
    positive_integer,
    primitive,
    spki_sha256,
    verify_android_key_attestation,
)


CAPTURE = Path(__file__).resolve().parent / "fixtures/huawei_nova11_cloud_untrusted"
# Independent probe inputs, chosen before the lab run, not read from the leaf.
CHALLENGE = bytes.fromhex("0253567353484b29189d0a58c297ce35ecbecb956e1806b3cf4fdb9933923f83")
PACKAGE = "org.hyperledger.iroha.samples.attestationprobe"
SIGNER = bytes.fromhex("eb2e20a4d49918e1dbd9b78b20b62a7442812cb9d2cd808ff3deff3fb7c35c27")
CAPTURE_TIME_MS = 1792489459000
GOOGLE_ROOTS = (
    ("google_ca1", "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"),
    ("google_rsa", "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae"),
)


class HuaweiNova11UntrustedCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which("openssl")
        if executable is None:
            raise unittest.SkipTest("OpenSSL CLI unavailable")
        cls.openssl = Path(executable).resolve()
        cls.provenance = json.loads((CAPTURE / "provenance.json").read_text())
        cls.chain = [(CAPTURE / f"certificate-{index}.der").read_bytes() for index in range(4)]
        cls.exported_spki = (CAPTURE / "public-key.spki.der").read_bytes()
        cls.payment_point = p256_point(der_one(cls.exported_spki))

    def test_public_fixture_and_own_key_signature_match_independent_request(self):
        for name, recorded in self.provenance["files"].items():
            with self.subTest(file=name):
                self.assertEqual(Path(name).name, name)
                raw = (CAPTURE / name).read_bytes()
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                                 (recorded["bytes"], recorded["sha256"]))
                if name.startswith("certificate-"):
                    self.assertEqual(spki_sha256(raw).hex(), recorded["spki_sha256"])
        request = self.provenance["independent_request"]
        self.assertEqual((request["challenge_hex"], request["package_name"], request["signer_sha256"]),
                         (CHALLENGE.hex(), PACKAGE, SIGNER.hex()))
        self.assertFalse(request["wallet_e1_challenge"])
        self.assertEqual((CAPTURE / "challenge.bin").read_bytes(), CHALLENGE)
        with tempfile.TemporaryDirectory() as temporary:
            public_key = Path(temporary) / "public-key.pem"
            public_key.write_bytes(b"-----BEGIN PUBLIC KEY-----\n"
                                   + base64.b64encode(self.exported_spki)
                                   + b"\n-----END PUBLIC KEY-----\n")
            signed = subprocess.run(
                [str(self.openssl), "dgst", "-sha256", "-verify", str(public_key),
                 "-signature", str(CAPTURE / "challenge-signature.der"), str(CAPTURE / "challenge.bin")],
                capture_output=True, timeout=10, check=False)
            self.assertEqual(signed.returncode, 0, signed.stderr.decode())

    def test_plausible_key_app_and_boot_fields_remain_untrusted_claims(self):
        leaf = _parse_android_certificate(self.chain[0])
        self.assertEqual(p256_point(leaf.spki), self.payment_point)
        description = children(der_one(leaf.extensions[ANDROID_KEY_DESCRIPTION_OID][1]))
        self.assertEqual(len(description), 8)
        self.assertEqual(tuple(positive_integer(description[i], 10 if i in (1, 3) else 2)
                               for i in range(4)), (3, 1, 4, 1))
        self.assertEqual(primitive(description[4], 4), CHALLENGE)
        software = _authorization_list(description[6])
        hardware = _authorization_list(description[7])
        self.assertEqual(_integer_set(hardware[1]), {2})
        self.assertEqual(_integer_set(hardware[5]), {4})
        self.assertEqual(tuple(positive_integer(hardware[tag]) for tag in (2, 3, 10, 702)),
                         (3, 256, 1, 0))
        self.assertFalse({1, 2, 3, 5, 10, 702} & set(software))
        self.assertFalse({405, 600} & (set(software) | set(hardware)))
        identity = children(der_one(primitive(software[709], 4)))
        packages = [children(item) for item in children(identity[0], number=17)]
        self.assertEqual([(primitive(item[0], 4), positive_integer(item[1])) for item in packages],
                         [(PACKAGE.encode(), 1)])
        self.assertEqual([primitive(item, 4) for item in children(identity[1], number=17)], [SIGNER])
        boot = children(hardware[704])
        self.assertEqual(len(boot), 4)
        self.assertTrue(der_boolean(boot[1]))
        self.assertEqual(positive_integer(boot[2], 10), 0)
        self.assertTrue(any(primitive(boot[0], 4)))
        self.assertEqual(len(primitive(boot[3], 4)), 32)

    def test_actual_unknown_root_is_refused_before_any_revocation_check(self):
        observed_root = spki_sha256(self.chain[-1])
        self.assertEqual(observed_root.hex(),
                         "9088e09e1c9ce45b8519169af96682cec51dea69db1fce64fcff1c16a6b8f8dd")
        anchors = tuple(
            AndroidTrustAnchor(family, bytes.fromhex(pin), "google_attestation_status",
                               GOOGLE_ADAPTER_PROFILE) for family, pin in GOOGLE_ROOTS)
        self.assertNotIn(observed_root, [anchor.spki_sha256 for anchor in anchors])

        def revocation(*_):
            self.fail("An unknown root must be refused before revocation or app claims")

        with self.assertRaises(EvidenceRefused) as raised:
            verify_android_key_attestation(
                self.chain, challenge_digest=CHALLENGE, payment_key_sec1=self.payment_point,
                package_name=PACKAGE, minimum_package_version=1, signer_set=(SIGNER,),
                anchors=anchors, revocation=revocation,
                trusted_time_ms=lambda: CAPTURE_TIME_MS, openssl_path=self.openssl)
        self.assertEqual(raised.exception.code, EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT)
        self.assertIn("not in the pinned root set", str(raised.exception))

    def test_issuing_certificates_lack_ca_constraints_and_supplied_path_fails_pkix(self):
        for index in (1, 2):
            self.assertNotIn("2.5.29.19", _parse_android_certificate(self.chain[index]).extensions)
        # Even a PKIX path check given this untrusted root cannot validate
        # these issuing certificates. Supplying a root here grants no policy trust.
        with self.assertRaisesRegex(AttestationRejected, "certificate chain rejected"):
            _verify_exact_path(self.chain, ["-attime", str(CAPTURE_TIME_MS // 1000)], self.openssl)
