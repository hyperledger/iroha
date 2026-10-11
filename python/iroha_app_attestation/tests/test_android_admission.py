"""Android E1 admission vectors on signed synthetic chains (enrollment policy steps 1–9).

Every root here is a throwaway test key assigned a family by the test policy. Passing these
vectors qualifies component code only, never a Google, Huawei or device root.
"""
import dataclasses
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from iroha_app_attestation.attestation import (
    ANDROID_PROVISIONING_INFORMATION_OID, GOOGLE_ADAPTER_PROFILE, HUAWEI_ADAPTER_PROFILE,
    AndroidTrustAnchor, AttestationRejected, EnrollmentRefusal, EvidenceRefused,
    VerificationUnavailable, spki_sha256, verify_android_key_attestation,
)
from synthetic_pki import (
    DAY_MS, PACKAGE, PROVISIONING_INFORMATION, SIGNER, SyntheticPki, app_identity, boolean,
    cbor, explicit, extension_line, factory_hierarchy, integer, key_description, now_ms, null,
    octets, remote_hierarchy, sequence, set_of,
)

CHALLENGE = hashlib.sha256(b"synthetic E1 challenge digest").digest()
REPO = Path(__file__).resolve().parents[3]
Code = EnrollmentRefusal


def anchor(root: bytes, family: str = "google_rsa", profile=GOOGLE_ADAPTER_PROFILE):
    source = "operator_denylist" if family == "vendor" else "google_attestation_status"
    return AndroidTrustAnchor(family, spki_sha256(root), source, profile)


class Hierarchy:
    def __init__(self, directory: Path, openssl: Path, build, family: str, **arguments):
        directory.mkdir()
        self.pki = SyntheticPki(directory, openssl)
        build(self.pki, **arguments)
        self.root = self.pki.der("root")
        self.intermediate = self.pki.der("intermediate")
        self.attestation = self.pki.der("attestation")
        self.family = family
        self.pki.key("leaf")
        self.point = self.pki.point("leaf")

    def chain(self, description: bytes | None = None, *, extensions=(), **changes) -> list:
        if description is None:
            description = key_description(CHALLENGE, **changes)
        leaf = self.pki.leaf("leaf", "attestation", description, extensions=extensions,
                             new_key=False)
        return [leaf, self.attestation, self.intermediate, self.root]

    def anchors(self, profile=GOOGLE_ADAPTER_PROFILE):
        return (anchor(self.root, self.family, profile),)


class AndroidAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = shutil.which("openssl")
        if executable is None:
            raise unittest.SkipTest("OpenSSL CLI unavailable")
        cls.openssl = Path(executable).resolve()
        cls.temporary = tempfile.TemporaryDirectory()
        base = Path(cls.temporary.name)
        cls.factory = Hierarchy(base / "factory", cls.openssl, factory_hierarchy, "google_rsa")
        cls.remote = Hierarchy(base / "remote", cls.openssl, remote_hierarchy, "google_rsa")
        cls.ca1 = Hierarchy(base / "ca1", cls.openssl, remote_hierarchy, "google_ca1",
                            root_kind="ec384", root_subject="/CN=Key Attestation CA1/O=Google LLC")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def verify(self, hierarchy, chain, *, anchors=None, time_ms=None, signers=(SIGNER,),
               minimum=7, payment=None, challenge=CHALLENGE, revocation=None):
        calls = []

        def revoked(members, selected):
            calls.append((members, selected))
            if revocation is not None:
                revocation(members, selected)
        moment = now_ms() if time_ms is None else time_ms
        result = verify_android_key_attestation(
            chain, challenge_digest=challenge,
            payment_key_sec1=hierarchy.point if payment is None else payment,
            package_name=PACKAGE, minimum_package_version=minimum, signer_set=signers,
            anchors=hierarchy.anchors() if anchors is None else anchors, revocation=revoked,
            trusted_time_ms=lambda: moment, openssl_path=self.openssl)
        self.assertEqual(len(calls), 1)
        return result

    def refused(self, code, hierarchy, chain, **arguments):
        with self.assertRaises(EvidenceRefused) as raised:
            self.verify(hierarchy, chain, **arguments)
        self.assertEqual(raised.exception.code, code, str(raised.exception))
        return raised.exception

    def test_expired_factory_chain_under_rsa_is_accepted_when_not_revoked(self):
        chain = self.factory.chain()
        result = self.verify(self.factory, chain)
        self.assertTrue(result.factory_provisioned)
        self.assertEqual((result.security_level, result.attestation_version), (2, 300))
        expired = self.verify(self.factory, chain, time_ms=now_ms() + 3 * DAY_MS)
        self.assertTrue(expired.factory_provisioned)
        # Expiry is exempt; a certificate that is not yet valid still is not.
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.factory, chain,
                     time_ms=now_ms() - 2 * DAY_MS)

    def test_expired_remote_chain_under_rsa_is_refused(self):
        chain = self.remote.chain()
        self.assertFalse(self.verify(self.remote, chain).factory_provisioned)
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, chain,
                     time_ms=now_ms() + 3 * DAY_MS)

    def test_rsa_chain_without_documented_factory_features_keeps_validity_checks(self):
        pki = self.remote.pki
        pki.issue("plain-intermediate", "root", "/CN=Plain Intermediate")
        pki.issue("plain-attestation", "plain-intermediate", "/CN=Plain Attestation/O=TEE")
        leaf = pki.leaf("leaf", "plain-attestation", key_description(CHALLENGE), new_key=False)
        chain = [leaf, pki.der("plain-attestation"), pki.der("plain-intermediate"), self.remote.root]
        self.assertFalse(self.verify(self.remote, chain).factory_provisioned)
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, chain,
                     time_ms=now_ms() + 3 * DAY_MS)
        # The same factory-shaped chain under a CA1-family pin is never exempt.
        factory = self.factory.chain()
        ca1 = (anchor(self.factory.root, "google_ca1"),)
        self.assertFalse(self.verify(self.factory, factory, anchors=ca1).factory_provisioned)
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.factory, factory, anchors=ca1,
                     time_ms=now_ms() + 3 * DAY_MS)

    def test_ca1_chain_is_accepted_with_validity_checks(self):
        chain = self.ca1.chain(level=1)
        result = self.verify(self.ca1, chain)
        self.assertEqual(result.anchor.family, "google_ca1")
        self.assertEqual(result.security_level, 1)
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.ca1, chain, time_ms=now_ms() + 3 * DAY_MS)

    def test_root_set_matches_spki_and_refuses_unpinned_roots(self):
        chain = self.remote.chain()
        both = tuple(sorted((anchor(self.ca1.root, "google_ca1"), anchor(self.remote.root)),
                            key=lambda item: item.spki_sha256))
        self.assertEqual(self.verify(self.remote, chain, anchors=both).anchor.family, "google_rsa")
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, chain,
                     anchors=(anchor(self.ca1.root, "google_ca1"),))
        # A chain ending at the repository's synthetic HMS test root is refused: unpinned.
        huawei_test_root = (REPO / "certs/huawei_safety_detect_root.der").read_bytes()
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, [chain[0], huawei_test_root])
        # Pinning it does not help: no chain of ours links to it.
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, [chain[0], huawei_test_root],
                     anchors=(anchor(huawei_test_root),))
        # Order, links and a root that is not self-signed.
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote,
                     [chain[0], chain[2], chain[1], chain[3]])
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, chain[:3],
                     anchors=(anchor(chain[2]),))
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, [*chain[:2], chain[1], chain[3]])

    def test_huawei_profile_code_runs_only_under_a_test_qualified_flag(self):
        vendor = dataclasses.replace(HUAWEI_ADAPTER_PROFILE, qualified=True)
        pki = self.factory.pki
        pki.root("vendor-root", "/CN=Synthetic Vendor Root/O=Vendor", "ec256")
        pki.issue("vendor-device", "vendor-root", "/CN=Synthetic Vendor Device CA")
        leaf = pki.leaf("leaf", "vendor-device", key_description(CHALLENGE, level=1),
                        new_key=False)
        chain = [leaf, pki.der("vendor-device"), pki.der("vendor-root")]
        anchors = (anchor(chain[-1], "vendor", vendor),)
        self.assertEqual(self.verify(self.factory, chain, anchors=anchors).anchor.profile.adapter_id,
                         "huawei")
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.factory, chain, anchors=anchors,
                     time_ms=now_ms() + 3 * DAY_MS)
        pki.issue("vendor-provisioned", "vendor-root", "/CN=Synthetic Vendor Device CA",
                  extensions=(PROVISIONING_INFORMATION,))
        provisioned = pki.leaf("leaf", "vendor-provisioned", key_description(CHALLENGE),
                               new_key=False)
        self.refused(Code.EVIDENCE_INVALID, self.factory,
                     [provisioned, pki.der("vendor-provisioned"), pki.der("vendor-root")],
                     anchors=anchors)
        # The shipped profile is unqualified: selecting it is a configuration failure.
        with self.assertRaises(AttestationRejected) as raised:
            self.verify(self.factory, chain,
                        anchors=(anchor(chain[-1], "vendor", HUAWEI_ADAPTER_PROFILE),))
        self.assertNotIsInstance(raised.exception, EvidenceRefused)

    def test_injected_attestation_extensions_are_refused(self):
        pki = self.remote.pki
        description = key_description(CHALLENGE)
        # Key description outside the trusted attestation certificate.
        pki.issue("described", "intermediate", "/CN=7d3a8e01/O=TEE",
                  extensions=(PROVISIONING_INFORMATION,
                              extension_line("1.3.6.1.4.1.11129.2.1.17", description)))
        leaf = pki.leaf("leaf", "described", description, new_key=False)
        self.refused(Code.EVIDENCE_INVALID, self.remote,
                     [leaf, pki.der("described"), self.remote.intermediate, self.remote.root])
        # Provisioning information not immediately above the key description.
        pki.issue("provisioned-intermediate", "root", "/CN=Droid CA2/O=Google LLC",
                  extensions=(PROVISIONING_INFORMATION,))
        pki.issue("bare-attestation", "provisioned-intermediate", "/CN=7d3a8e01/O=TEE")
        leaf = pki.leaf("leaf", "bare-attestation", description, new_key=False)
        self.refused(Code.EVIDENCE_INVALID, self.remote,
                     [leaf, pki.der("bare-attestation"), pki.der("provisioned-intermediate"),
                      self.remote.root])
        leaf = pki.leaf("leaf", "attestation", description, new_key=False,
                        extensions=(PROVISIONING_INFORMATION,))
        self.refused(Code.EVIDENCE_INVALID, self.remote, [leaf, *self.remote.chain()[1:]])
        # An unknown critical extension fails path validation under the profile.
        critical = self.remote.chain(extensions=(extension_line("1.3.6.1.4.1.99999.1", null(),
                                                                critical=True),))
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote, critical)
        # A chain extended below the attested key: the attested certificate is no CA.
        pki.issue("forged", "leaf", "/CN=Attacker Leaf", ca=False)
        self.refused(Code.UNTRUSTED_ATTESTATION_ROOT, self.remote,
                     [pki.der("forged"), *self.remote.chain()])

    def test_documented_version_pairs_and_version_specific_root_of_trust(self):
        pairs = [(2, 3), (3, 4), (4, 41), (100, 100), (200, 200), (300, 300), (400, 400),
                 (500, 500)]
        for version, keymint in pairs:
            for level in ((1,) if version == 2 else (1, 2)):
                with self.subTest(version=version, level=level):
                    chain = self.remote.chain(attestation_version=version,
                                              keymint_version=keymint, level=level)
                    result = self.verify(self.remote, chain)
                    self.assertEqual((result.attestation_version, result.keymint_version,
                                      result.security_level), (version, keymint, level))
        self.refused(Code.KEY_NOT_IN_SECURE_HARDWARE, self.remote,
                     self.remote.chain(attestation_version=2, keymint_version=3, level=2))
        self.refused(Code.ATTESTATION_WITHOUT_APP_IDENTITY, self.remote,
                     self.remote.chain(attestation_version=1, keymint_version=2, level=1,
                                       boot_hash=None))
        for version, keymint in ((3, 3), (100, 4), (600, 600), (2, 4), (4, 4), (100, 200)):
            with self.subTest(undocumented=(version, keymint)):
                self.refused(Code.EVIDENCE_INVALID, self.remote,
                             self.remote.chain(attestation_version=version, keymint_version=keymint))
        # Keymaster 4 with an empty boot hash is accepted; the hash is recorded, not required.
        self.verify(self.remote, self.remote.chain(attestation_version=4, keymint_version=41,
                                                   boot_hash=b""))
        self.verify(self.remote, self.remote.chain(attestation_version=3, keymint_version=4,
                                                   boot_hash=b"\0" * 32))
        # The RootOfTrust DER shape is its version's.
        self.refused(Code.EVIDENCE_INVALID, self.remote,
                     self.remote.chain(attestation_version=2, keymint_version=3, level=1,
                                       boot_hash=b"\x52" * 32))
        self.refused(Code.EVIDENCE_INVALID, self.remote,
                     self.remote.chain(attestation_version=3, keymint_version=4, boot_hash=None))
        self.refused(Code.EVIDENCE_INVALID, self.remote, self.remote.chain(boot_hash=None))
        for boot_hash in (b"", b"\x52" * 31, b"\0" * 32):
            with self.subTest(keymint_hash=len(boot_hash)):
                self.refused(Code.BOOT_NOT_VERIFIED, self.remote, self.remote.chain(boot_hash=boot_hash))

    def test_secure_hardware_boot_and_key_properties(self):
        for changes, code in (
            ({"level": 0}, Code.KEY_NOT_IN_SECURE_HARDWARE),
            ({"keymint_level": 1}, Code.KEY_NOT_IN_SECURE_HARDWARE),
            ({"level": 3}, Code.KEY_NOT_IN_SECURE_HARDWARE),
            ({"locked": False}, Code.BOOTLOADER_UNLOCKED),
            ({"state": 1}, Code.BOOT_NOT_VERIFIED),
            ({"state": 2}, Code.BOOT_NOT_VERIFIED),
            ({"boot_key": b"\0" * 32}, Code.BOOT_NOT_VERIFIED),
            ({"boot_key": b""}, Code.BOOT_NOT_VERIFIED),
            ({"purpose": (2, 3)}, Code.EVIDENCE_INVALID),
            ({"purpose": (3,)}, Code.EVIDENCE_INVALID),
            ({"algorithm": 1}, Code.EVIDENCE_INVALID),
            ({"key_size": 384}, Code.EVIDENCE_INVALID),
            ({"digest": (4, 5)}, Code.EVIDENCE_INVALID),
            ({"curve": 2}, Code.EVIDENCE_INVALID),
            ({"origin": 2}, Code.EVIDENCE_INVALID),
        ):
            with self.subTest(changes=changes):
                self.refused(code, self.remote, self.remote.chain(**changes))
        # Order: the first failing admission step decides.
        self.refused(Code.KEY_NOT_IN_SECURE_HARDWARE, self.remote,
                     self.remote.chain(level=0, locked=False))
        self.refused(Code.BOOTLOADER_UNLOCKED, self.remote,
                     self.remote.chain(locked=False, state=1))

    def test_authorization_tags_405_600_unknown_duplicate_and_order(self):
        for extra in ({"hardware_extra": {405: integer(1)}}, {"software_extra": {405: integer(1)}},
                      {"hardware_extra": {600: null()}}, {"software_extra": {600: null()}},
                      {"software_extra": {3: integer(256)}}, {"software_extra": {704: sequence()}},
                      {"hardware_extra": {706: octets(b"x")}}, {"hardware_extra": {303: integer(0)}}):
            with self.subTest(extra=extra):
                self.refused(Code.EVIDENCE_INVALID, self.remote, self.remote.chain(**extra))
        # Unknown context-specific tags are ignored in either list.
        self.verify(self.remote, self.remote.chain(hardware_extra={725: integer(5), 9000: octets(b"x")},
                                                   software_extra={899: null()}))
        boot = sequence(octets(b"\x51" * 32), boolean(True), integer(0, b"\x0a"),
                        octets(b"\x52" * 32))
        fields = [explicit(1, set_of(integer(2))), explicit(2, integer(3)),
                  explicit(3, integer(256)), explicit(5, set_of(integer(4))),
                  explicit(10, integer(1)), explicit(702, integer(0)), explicit(704, boot)]
        self.verify(self.remote, self.remote.chain(key_description(CHALLENGE, hardware_fields=fields)))
        for broken in (fields[:2] + fields[1:], [fields[1], fields[0], *fields[2:]],
                       fields + [explicit(704, boot)]):
            with self.subTest(broken=len(broken)):
                self.refused(Code.EVIDENCE_INVALID, self.remote,
                             self.remote.chain(key_description(CHALLENGE, hardware_fields=broken)))
        identity = explicit(709, octets(app_identity()))
        self.refused(Code.EVIDENCE_INVALID, self.remote, self.remote.chain(
            key_description(CHALLENGE, software_fields=[identity, identity])))
        # A non-context element inside an authorization list is malformed.
        self.refused(Code.EVIDENCE_INVALID, self.remote, self.remote.chain(
            key_description(CHALLENGE, software_fields=[integer(1), identity])))

    def test_application_identity_signers_and_version_floor(self):
        self.verify(self.remote, self.remote.chain(app_list="hardware"))
        self.refused(Code.EVIDENCE_INVALID, self.remote, self.remote.chain(app_list="both"))
        self.refused(Code.ATTESTATION_WITHOUT_APP_IDENTITY, self.remote, self.remote.chain(app_list=None))
        self.refused(Code.APP_IDENTITY_MISMATCH, self.remote,
                     self.remote.chain(packages=(("org.example.other", 7),)))
        self.refused(Code.APP_IDENTITY_MISMATCH, self.remote,
                     self.remote.chain(packages=((PACKAGE, 7), ("org.example.shared", 7))))
        self.refused(Code.APP_IDENTITY_MISMATCH, self.remote, self.remote.chain(signers=()))
        self.refused(Code.APP_IDENTITY_MISMATCH, self.remote, self.remote.chain(signers=(b"\x72" * 32,)))
        self.refused(Code.APP_IDENTITY_MISMATCH, self.remote,
                     self.remote.chain(signers=(SIGNER, b"\x72" * 32)))
        two = (SIGNER, b"\x72" * 32)
        self.verify(self.remote, self.remote.chain(signers=two), signers=two)
        four = tuple(sorted((SIGNER, b"\x72" * 32, b"\x73" * 32, b"\x01" * 32)))
        self.verify(self.remote, self.remote.chain(), signers=four)
        self.verify(self.remote, self.remote.chain(signers=(b"\x73" * 32,)), signers=four)
        # Version floor: equal and above pass, below refuses; 0 is a valid floor.
        self.assertEqual(self.verify(self.remote, self.remote.chain(), minimum=7).package_version, 7)
        self.verify(self.remote, self.remote.chain(packages=((PACKAGE, 1 << 40),)), minimum=7)
        self.verify(self.remote, self.remote.chain(packages=((PACKAGE, 0),)), minimum=0)
        self.refused(Code.APP_VERSION_BELOW_MINIMUM, self.remote, self.remote.chain(), minimum=8)

    def test_challenge_payment_key_and_shape(self):
        chain = self.remote.chain()
        self.refused(Code.EVIDENCE_INVALID, self.remote, chain,
                     challenge=hashlib.sha256(CHALLENGE).digest())
        other = self.ca1.point
        self.refused(Code.EVIDENCE_INVALID, self.remote, chain, payment=other)
        for shape in ([chain[0]], [*chain, chain[3], chain[3], chain[3], chain[3], chain[3]],
                      [chain[0], b"\x30\x00"], [b"\x30" + b"\x00" * 3, chain[3]],
                      [chain[0], b"x" * 16385]):
            with self.subTest(length=len(shape)):
                self.refused(Code.EVIDENCE_INVALID, self.remote, shape)

    def test_revocation_runs_after_the_path_and_before_the_key_description(self):
        def listed(members, selected):
            self.assertEqual(selected.family, "google_rsa")
            self.assertEqual(len(members), 4)
            raise EvidenceRefused(Code.ATTESTATION_REVOKED, "synthetic listing")
        self.refused(Code.ATTESTATION_REVOKED, self.remote, self.remote.chain(locked=False),
                     revocation=listed)

        def unavailable(members, selected):
            raise VerificationUnavailable("synthetic outage")
        with self.assertRaises(VerificationUnavailable):
            self.verify(self.remote, self.remote.chain(), revocation=unavailable)
        # Path failures precede revocation.
        calls = []
        with self.assertRaises(EvidenceRefused):
            verify_android_key_attestation(
                self.remote.chain(), challenge_digest=CHALLENGE, payment_key_sec1=self.remote.point,
                package_name=PACKAGE, minimum_package_version=7, signer_set=(SIGNER,),
                anchors=self.ca1.anchors(), revocation=lambda *args: calls.append(args),
                trusted_time_ms=now_ms, openssl_path=self.openssl)
        self.assertEqual(calls, [])

    def test_configuration_inputs_are_not_evidence_refusals(self):
        chain = self.remote.chain()
        for changes in ({"signers": ()}, {"signers": (b"\x72" * 32, SIGNER)},
                        {"signers": (b"\0" * 32,)}, {"minimum": -1}, {"anchors": ()},
                        {"challenge": b"\0" * 32}):
            with self.subTest(changes=list(changes)), self.assertRaises(AttestationRejected) as raised:
                self.verify(self.remote, chain, **changes)
            self.assertNotIsInstance(raised.exception, EvidenceRefused)
        self.assertEqual(cbor({1: 1}), bytes.fromhex("a10101"))
        self.assertEqual(ANDROID_PROVISIONING_INFORMATION_OID, "1.3.6.1.4.1.11129.2.1.30")


if __name__ == "__main__":
    unittest.main()
