"""Adversarial parsing and fail-closed checks for independent raw evidence."""

import hashlib
import importlib
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    AndroidPatchLevels,
    AttestationRejected,
    EnrollmentRefusal,
    EvidenceRefused,
    _authorization_list,
    _certificate_valid_at,
    android_patch_policy_met,
    cbor_exact,
    certificate_key_extensions,
    certificate_spki_extensions,
    der_encode,
    der_one,
    oid,
    patch_level_yyyymm,
    refusal_stage,
    spki_sha256,
    validate_android_patch_floor,
    verify_apple_wallet_attestation_raw,
    verify_pinned_chain,
)

REPO = Path(__file__).resolve().parents[3]


class AttestationTests(unittest.TestCase):
    def test_cbor_rejects_duplicate_fields_trailing_bytes_and_indefinite_lengths(self) -> None:
        self.assertEqual(cbor_exact(b"\xa1\x61a\x01"), {"a": 1})
        for raw in (b"\xa2\x61a\x01\x61a\x02", b"\xa1\x61a\x01\x00", b"\xbf\xff", b"\xa1\x61a"):
            with self.subTest(raw=raw), self.assertRaises(AttestationRejected):
                cbor_exact(raw)

    def test_der_rejects_trailing_and_nonminimal_lengths(self) -> None:
        self.assertEqual(der_one(b"\x04\x01x").value, b"x")
        for raw in (b"\x04\x01xx", b"\x04\x81\x01x", b"\x04\x82\x00\x01x", b"\x04\x02x"):
            with self.subTest(raw=raw), self.assertRaises(AttestationRejected):
                der_one(raw)
        self.assertEqual(oid(der_one(b"\x06\x03\x2a\x03\x04")), "1.2.3.4")
        for raw in (b"\x06\x02\x80\x2a", b"\x06\x03\x2a\x80\x03"):
            with self.subTest(raw=raw), self.assertRaises(AttestationRejected):
                oid(der_one(raw))

    def test_certificate_parser_rejects_ambiguous_extension_blocks_and_types(self) -> None:
        def tlv(tag: int, content: bytes) -> bytes:
            length = (bytes([len(content)]) if len(content) < 128 else
                      b"\x81" + bytes([len(content)]))
            return bytes([tag]) + length + content

        version = tlv(0xa0, b"\x02\x01\x02")
        mandatory = b"\x02\x01\x01" + b"\x30\x00" * 5
        oid_one, oid_two = b"\x06\x03\x2a\x03\x04", b"\x06\x03\x2a\x03\x05"

        def block(name: bytes, critical: bytes = b"") -> bytes:
            extension = tlv(0x30, name + critical + b"\x04\x01x")
            return tlv(0xa3, tlv(0x30, extension))

        def certificate(optionals: bytes) -> bytes:
            return tlv(0x30, tlv(0x30, version + mandatory + optionals)
                       + b"\x30\x00\x03\x01\x00")

        _, extensions = certificate_spki_extensions(certificate(block(oid_one)))
        self.assertEqual(extensions, {"1.2.3.4": b"x"})
        for malformed in (
            block(oid_one) + block(oid_two),
            block(oid_one) + b"\x81\x02\x00\x01",
            block(oid_one, b"\x02\x01\x01"),
            block(oid_one, b"\x01\x01\x00"),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(AttestationRejected):
                certificate_spki_extensions(certificate(malformed))

    def test_authorization_list_types_known_fields_and_ignores_unknown_tags(self) -> None:
        def wrap(tag: bytes, content: bytes) -> bytes:
            assert len(content) < 128
            return tag + bytes([len(content)]) + content

        def context(number: int, item: bytes) -> bytes:
            chunks = [number & 127]
            number >>= 7
            while number:
                chunks.insert(0, 128 | (number & 127))
                number >>= 7
            return wrap(b"\xbf" + bytes(chunks), item)

        integer = b"\x02\x04\x0c\x06\x7f\x01"
        vendor_patch = context(718, integer)
        brand = context(710, b"\x04\x05Pixel")
        early_boot = context(305, b"\x05\x00")
        future = context(725, b"\x05\x00")
        valid = wrap(b"\x30", early_boot + brand + vendor_patch + future)
        # The unknown future tag is ignored, never admitted as a typed field.
        self.assertEqual(set(_authorization_list(der_one(valid))), {305, 710, 718})
        for body in (
            vendor_patch + brand,  # unsorted
            brand + brand,  # duplicate
            future + future,  # duplicate unknown tag
            context(718, b"\x04\x01x"),  # wrong ASN.1 type
            context(305, b"\x05\x01\x00"),  # nonempty NULL
            context(1, b"\x02\x01\x02"),  # purpose is a SET OF INTEGER
            b"\x02\x01\x01",  # universal element in the list
            context(9000, b"\x05\x00\x05\x00"),  # explicit tag wraps one element
        ):
            with self.subTest(body=body), self.assertRaises(AttestationRejected):
                _authorization_list(der_one(wrap(b"\x30", body)))

    def test_refusal_stage_classifies_only_untyped_rejections(self) -> None:
        with self.assertRaises(EvidenceRefused) as raised:
            with refusal_stage(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT):
                raise AttestationRejected("chain")
        self.assertEqual(raised.exception.code, 5)
        with self.assertRaises(EvidenceRefused) as raised:
            with refusal_stage(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT):
                raise EvidenceRefused(EnrollmentRefusal.ATTESTATION_REVOKED, "listed")
        self.assertEqual(raised.exception.code, 6)
        self.assertEqual([code.value for code in EnrollmentRefusal], list(range(1, 11)))

    def test_root_set_pins_are_spki_digests_covering_reissued_roots(self) -> None:
        rsa_2022 = (REPO / "certs/google_attestation_root_rsa.der").read_bytes()
        rsa_2016 = (Path(__file__).parent / "fixtures" / "google_factory_root_2016.der").read_bytes()
        ca1 = (REPO / "certs/google_attestation_root_ecdsa.der").read_bytes()
        self.assertNotEqual(hashlib.sha256(rsa_2016).digest(), hashlib.sha256(rsa_2022).digest())
        self.assertEqual(spki_sha256(rsa_2016).hex(),
                         "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae")
        self.assertEqual(spki_sha256(rsa_2022), spki_sha256(rsa_2016))
        self.assertEqual(spki_sha256(ca1).hex(),
                         "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec")
        spki, _ = certificate_spki_extensions(ca1)
        self.assertEqual(der_encode(spki)[:2], b"\x30\x76")
        # The 2016 issue has expired; its key still anchors factory chains by SPKI.
        self.assertFalse(_certificate_valid_at(rsa_2016, 1_790_000_000_000))
        self.assertFalse((REPO / "certs/google_play_integrity_root.der").exists())

    def test_retired_play_integrity_oauth_and_retail_modules_are_absent(self) -> None:
        for name in ("play_integrity", "google_oauth", "openssl_private_rsa", "retail_auth_worker"):
            with self.subTest(name=name), self.assertRaises(ModuleNotFoundError):
                importlib.import_module("iroha_app_attestation." + name)
        import iroha_app_attestation.attestation as attestation
        for retired in ("GOOGLE_FACTORY_2016_ROOT_SHA256", "Selection", "verify_android_raw",
                        "verify_android_wallet_payment_key_raw", "encode_android_chain"):
            self.assertFalse(hasattr(attestation, retired), retired)

    def test_fake_apple_evidence_cannot_be_promoted(self) -> None:
        with self.assertRaises(EvidenceRefused) as raised:
            verify_apple_wallet_attestation_raw(
                b"\xa1\x63fmt\x6fapple-appattest", b"\x01" * 32,
                "TEAMID.example.app", "production", b"\x05" * 32,
                b"fake root", b"\x02" * 32, 1_000, Path("/usr/bin/openssl"),
            )
        self.assertEqual(raised.exception.code, EnrollmentRefusal.EVIDENCE_INVALID)

    def test_pinned_chain_checks_real_signatures_and_root_digest(self) -> None:
        executable = shutil.which("openssl")
        if executable is None:
            self.skipTest("OpenSSL CLI unavailable")
        openssl = Path(executable).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def run(*args: str) -> None:
                subprocess.run([str(openssl), *args], cwd=directory, capture_output=True, check=True)

            run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "2",
                "-subj", "/CN=Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=Test Leaf")
            run("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key",
                "-CAcreateserial", "-out", "leaf.pem", "-days", "2")
            run("x509", "-in", "root.pem", "-outform", "DER", "-out", "root.der")
            run("x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der")
            root, leaf = (directory / "root.der").read_bytes(), (directory / "leaf.der").read_bytes()
            point, _ = certificate_key_extensions(leaf)
            self.assertEqual(len(point), 65)
            current = int(time.time() * 1000)
            self.assertTrue(_certificate_valid_at(leaf, current))
            self.assertFalse(_certificate_valid_at(leaf, current + 4 * 86_400_000))
            verify_pinned_chain([leaf, root], root, hashlib.sha256(root).digest(), current, openssl)
            for chain, pin, moment in (([leaf, root], b"\x01" * 32, current),
                                       ([leaf, root], hashlib.sha256(root).digest(),
                                        current + 4 * 86_400_000),
                                       ([root, leaf], hashlib.sha256(root).digest(), current),
                                       ([leaf, leaf], hashlib.sha256(root).digest(), current)):
                with self.subTest(moment=moment), self.assertRaises(AttestationRejected):
                    verify_pinned_chain(chain, root, pin, moment, openssl)

    def test_patch_levels_normalize_only_documented_keymint_forms(self) -> None:
        for value, expected in ((202609, 202609), (20260905, 202609), (20260900, 202609),
                                (190001, 190001), (999912, 999912)):
            with self.subTest(value=value):
                self.assertEqual(patch_level_yyyymm(value), expected)
        for value in (0, 202600, 202613, 189912, 2026, 20261301, 100000000, True, "202609", None, 202609.0):
            with self.subTest(value=value):
                self.assertIsNone(patch_level_yyyymm(value))

    def test_patch_policy_fact_uses_every_reported_hardware_level(self) -> None:
        current = AndroidPatchLevels(300, 150000, 202609, 20260905, 20260901)
        self.assertIs(android_patch_policy_met(current, 202609), True)
        self.assertIs(android_patch_policy_met(current, 202601), True)
        # Vendor and boot levels that are absent or zero are "not reported".
        self.assertIs(android_patch_policy_met(AndroidPatchLevels(3, None, 202609, None, 0), 202609), True)
        # An unmet policy is the recorded PATCH_POLICY_MET fact, never an error.
        for levels in (
            AndroidPatchLevels(300, 150000, None, 20260905, 20260901),  # OS level absent
            AndroidPatchLevels(300, 150000, 0, 20260905, 20260901),     # OS level not reported
            AndroidPatchLevels(300, 150000, 202608, 20260905, 20260901),
            AndroidPatchLevels(300, 150000, 202609, 20260805, 20260901),
            AndroidPatchLevels(300, 150000, 202609, 20260905, 20260801),
            AndroidPatchLevels(300, 150000, 202613, 20260905, 20260901),  # unparsable OS
            AndroidPatchLevels(300, 150000, 202609, 2026, 20260901),      # unparsable vendor
            AndroidPatchLevels(300, 150000, 202609, 20260905, 20261301),  # unparsable boot
        ):
            with self.subTest(levels=levels):
                self.assertIs(android_patch_policy_met(levels, 202609), False)

    def test_bad_patch_floor_or_levels_raise_instead_of_reading_as_unmet(self) -> None:
        current = AndroidPatchLevels(300, 150000, 202609, 20260905, 20260901)
        self.assertEqual(validate_android_patch_floor(202609), 202609)
        for floor in (0, 20260901, 202613, 2026, True, "202609", None):
            with self.subTest(floor=floor):
                with self.assertRaisesRegex(AttestationRejected, "patch floor"):
                    validate_android_patch_floor(floor)
                # A misconfigured floor must not be recorded as policy-not-met.
                with self.assertRaisesRegex(AttestationRejected, "patch floor"):
                    android_patch_policy_met(current, floor)
        for levels in ((300, 150000, 202609, 20260905, 20260901), None,
                       AndroidPatchLevels(300, 150000, "202609", 20260905, 20260901),
                       AndroidPatchLevels(300, 150000, 202609, 20260905.0, 20260901)):
            with self.subTest(levels=levels), self.assertRaisesRegex(AttestationRejected, "patch levels absent"):
                android_patch_policy_met(levels, 202609)



if __name__ == "__main__":
    unittest.main()
