"""Policy DATA vectors and grammar. No policy approval, platform or issuer qualification."""
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from iroha_app_attestation.attestation import AttestationRejected
from iroha_app_attestation.wallet_policy import (
    AndroidAppIdentityV1, AndroidEnrollmentPlatformV1, AndroidRootV1, AppleAppIdentityV1,
    AppleEnrollmentPlatformV1, ConfiguredWalletEnrollmentPolicyV1, RegulatoryPolicyV1,
    WalletAppPolicyV1, WalletEnrollmentPolicyV1,
)

VECTORS = Path(__file__).resolve().parents[3] / "fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json"


def from_inputs(inputs):
    """Build the Python projection from the shared Model vector inputs."""
    scheme = bytes.fromhex(inputs["scheme_id_hex"])
    selected_app, selected = inputs["app"], inputs["enrollment"]
    if selected_app["platform"] == "android":
        identity = AndroidAppIdentityV1(selected_app["package_name"], selected_app["minimum_package_version"],
                                        tuple(bytes.fromhex(s) for s in selected_app["app_signer_sha256"]))
        platform = AndroidEnrollmentPlatformV1(tuple(
            AndroidRootV1(root["family"], bytes.fromhex(root["spki_sha256"]), root["revocation_source"],
                          root.get("adapter_id")) for root in selected["roots"]), selected["patch_floor_yyyymm"])
    else:
        identity = AppleAppIdentityV1(selected_app["app_id"])
        platform = AppleEnrollmentPlatformV1(bytes.fromhex(selected["root_sha256"]))
    app = WalletAppPolicyV1(inputs["version"], scheme, identity)
    enrollment = WalletEnrollmentPolicyV1(inputs["version"], scheme, bytes.fromhex(inputs["asset_digest_hex"]),
        app.policy_digest(), platform, RegulatoryPolicyV1(**inputs["regulatory_policy"]),
        inputs["challenge_lifetime_ms"], inputs["attestation_lease_lifetime_ms"])
    return app, enrollment


def policies(apple=False, roots=None):
    app = WalletAppPolicyV1(1, b"\1" * 32, AppleAppIdentityV1("TEAMID.org.example.wallet") if apple else
                           AndroidAppIdentityV1("org.example.wallet", 7, (b"\5" * 32,)))
    platform = AppleEnrollmentPlatformV1(b"\4" * 32) if apple else AndroidEnrollmentPlatformV1(
        roots or (AndroidRootV1("google_rsa", b"\4" * 32, "google_attestation_status"),), 202608)
    regulator = RegulatoryPolicyV1(4, 0, 5000) if apple else RegulatoryPolicyV1(0, 0, 0)
    enrollment = WalletEnrollmentPolicyV1(1, b"\1" * 32, b"\2" * 32, app.policy_digest(), platform,
        regulator, 120000, 3600000 if apple else 0)
    return app, enrollment


def challenge(app, enrollment):
    return (b"\1\0" + enrollment.scheme_id + enrollment.asset_digest + b"\3" * 32
            + app.policy_digest() + enrollment.policy_digest() + b"\6" * 32)


class WalletPolicyTests(unittest.TestCase):
    def test_shared_model_vectors_agree_byte_for_byte(self):
        document = json.loads(VECTORS.read_text())
        self.assertIn("unadmitted DATA", document["status"])
        self.assertEqual([case["name"] for case in document["cases"]],
                         ["android", "apple", "android_maximal", "apple_maximal"])
        for row in document["cases"]:
            with self.subTest(case=row["name"]):
                app, enrollment = from_inputs(row["inputs"])
                enrollment.validate_for_app(app)
                e1 = (b"\1\0" + enrollment.scheme_id + enrollment.asset_digest
                      + bytes.fromhex(row["inputs"]["account_digest_hex"]) + app.policy_digest()
                      + enrollment.policy_digest() + bytes.fromhex(row["inputs"]["issuer_nonce_hex"]))
                for key, value in (
                    ("app_policy_transcript_hex", app.transcript()), ("app_policy_digest_hex", app.policy_digest()),
                    ("enrollment_policy_transcript_hex", enrollment.transcript()),
                    ("enrollment_policy_digest_hex", enrollment.policy_digest()),
                    ("challenge_transcript_hex", e1),
                    ("challenge_digest_hex", hashlib.sha256(b"iroha:kagemusha:wallet:v1:enrollment-challenge\0"
                        + len(e1).to_bytes(8, "little") + e1).digest()),
                ):
                    self.assertEqual(value.hex(), row[key], key)
        # The shared vectors carry Native's actual Norito frames; maximal policies fit the cap.
        for row in document["cases"]:
            for key in ("app_policy_frame_hex", "enrollment_policy_frame_hex"):
                self.assertLessEqual(len(bytes.fromhex(row[key])), document["frame_cap_bytes"])
        self.assertEqual(document["frame_cap_bytes"], 1024)
        maximal = {row["name"]: row for row in document["cases"]}["android_maximal"]
        app, enrollment = from_inputs(maximal["inputs"])
        self.assertEqual((len(app.transcript()), len(enrollment.transcript())), (431, 572))

    def test_android_transcript_sizes_follow_the_policy_contract(self):
        app, enrollment = policies()
        self.assertEqual(len(app.transcript()), 48 + len("org.example.wallet") + 32)
        self.assertEqual(len(enrollment.transcript()), 140 + 34)
        vendor = AndroidRootV1("vendor", b"\x09" * 32, "operator_denylist", "huawei")
        _, both = policies(roots=(AndroidRootV1("google_rsa", b"\4" * 32, "google_attestation_status"), vendor))
        self.assertEqual(len(both.transcript()), 140 + 34 + 38 + 6)

    def test_signer_set_root_set_and_adapter_grammar(self):
        app, enrollment = policies()
        identity = app.identity
        for signers in ((), (b"\5" * 32, b"\5" * 32), (b"\6" * 32, b"\5" * 32), (b"\0" * 32,),
                        (b"\5" * 31,), tuple(bytes([n]) * 32 for n in range(1, 6)), [b"\5" * 32]):
            with self.subTest(signers=signers), self.assertRaises(AttestationRejected):
                replace(app, identity=replace(identity, signer_set=signers)).transcript()
        for minimum in (-1, 1 << 64, True):
            with self.subTest(minimum=minimum), self.assertRaises(AttestationRejected):
                replace(app, identity=replace(identity, minimum_package_version=minimum)).transcript()
        replace(app, identity=replace(identity, minimum_package_version=0)).transcript()
        google = AndroidRootV1("google_rsa", b"\4" * 32, "google_attestation_status")
        for roots in (
            (), (google, google), (AndroidRootV1("google_ca1", b"\5" * 32, "google_attestation_status"),
                                   AndroidRootV1("google_rsa", b"\4" * 32, "google_attestation_status")),
            tuple(AndroidRootV1("google_rsa", bytes([n]) * 32, "google_attestation_status") for n in range(1, 10)),
            (AndroidRootV1("google_rsa", b"\4" * 32, "operator_denylist"),),
            (AndroidRootV1("vendor", b"\4" * 32, "google_attestation_status", "huawei"),),
            (AndroidRootV1("vendor", b"\4" * 32, "operator_denylist", None),),
            (AndroidRootV1("vendor", b"\4" * 32, "operator_denylist", "Huawei"),),
            (AndroidRootV1("vendor", b"\4" * 32, "operator_denylist", "a" * 17),),
            (AndroidRootV1("vendor", b"\4" * 32, "operator_denylist", "1vendor"),),
            (AndroidRootV1("google_rsa", b"\4" * 32, "google_attestation_status", "huawei"),),
            (AndroidRootV1("google_rsa", b"\0" * 32, "google_attestation_status"),),
            (AndroidRootV1("samsung", b"\4" * 32, "google_attestation_status"),),
        ):
            with self.subTest(roots=roots), self.assertRaises(AttestationRejected):
                replace(enrollment, platform=replace(enrollment.platform, root_set=roots)).transcript()
        for floor in (202613, 189912, 0, 20260801):
            with self.subTest(floor=floor), self.assertRaises(AttestationRejected):
                replace(enrollment, platform=replace(enrollment.platform, patch_floor_yyyymm=floor)).transcript()

    def test_configured_policy_refuses_unknown_or_unqualified_adapters(self):
        for adapter, message in (("huawei", "unqualified"), ("acme", "unknown")):
            roots = (AndroidRootV1("vendor", b"\x09" * 32, "operator_denylist", adapter),)
            app, enrollment = policies(roots=roots)
            enrollment.transcript()  # Model grammar alone admits the row.
            with self.subTest(adapter=adapter), self.assertRaisesRegex(AttestationRejected, message):
                ConfiguredWalletEnrollmentPolicyV1(app, enrollment).validate()
        app, enrollment = policies()
        configured = ConfiguredWalletEnrollmentPolicyV1(app, enrollment)
        self.assertEqual([anchor.profile.adapter_id for anchor in configured.android_anchors()], ["google"])
        with self.assertRaisesRegex(AttestationRejected, "root original"):
            ConfiguredWalletEnrollmentPolicyV1(app, enrollment, b"android has no root original").validate()

    def test_policy_and_apple_root_substitution_rejected_before_platform_call(self):
        app, enrollment = policies(True)
        raw = b"UNADMITTED DATA root consistency bytes; not a certificate or authority"
        selected = replace(enrollment.platform, attestation_root_sha256=hashlib.sha256(raw).digest())
        enrollment = replace(enrollment, platform=selected)
        configured = ConfiguredWalletEnrollmentPolicyV1(app, enrollment, raw)
        e1 = challenge(app, enrollment)
        configured.validate_scope(e1, 10, 10)
        for index in (2, 34, 98, 130):
            value = bytearray(e1)
            value[index] ^= 1
            with self.assertRaises(AttestationRejected):
                configured.validate_scope(bytes(value), 10, 10)
        for root in (b"", raw + b"x", None):
            with self.assertRaises(AttestationRejected):
                replace(configured, apple_root_der=root).validate_scope(e1, 10, 10)
        with self.assertRaises(AttestationRejected):
            enrollment.validate_for_app(policies()[0])
        with self.assertRaises(AttestationRejected):
            replace(enrollment, platform=policies()[1].platform).validate_for_app(app)

    def test_no_implicit_time_or_lease_and_all_overflow_boundaries(self):
        _, enrollment = policies()
        enrollment.require_live_challenge(10, 10)
        enrollment.require_live_challenge(10, 120009)
        for created, now in ((0, 1), (10, 9), (10, 120010), ((1 << 64) - 1, (1 << 64) - 1)):
            with self.assertRaises(AttestationRejected):
                enrollment.require_live_challenge(created, now)
        self.assertEqual(enrollment.lease_expires_at(10), 0)
        with self.assertRaises(AttestationRejected):
            enrollment.lease_expires_at(0)
        _, apple = policies(True)
        self.assertEqual(apple.lease_expires_at(10), 3600010)
        for candidate in (replace(apple, attestation_lease_lifetime_ms=0),
                          replace(enrollment, attestation_lease_lifetime_ms=1),
                          replace(enrollment, challenge_lifetime_ms=0),
                          replace(enrollment, regulatory_policy=RegulatoryPolicyV1(8, 0, 0))):
            with self.assertRaises(AttestationRejected):
                candidate.transcript()
        with self.assertRaises(AttestationRejected):
            apple.lease_expires_at((1 << 64) - 1)

    def test_current_app_byte_grammar_exact_without_normalization(self):
        app, _ = policies()
        for name in ("", "one", "a..b", "1a.b", "org.exa-mple", "org.é", "a." + "b" * 254):
            with self.assertRaises(AttestationRejected):
                replace(app, identity=replace(app.identity, package_name=name)).transcript()
        apple, _ = policies(True)
        for name in ("", "é" * 128, "\ud800"):
            with self.assertRaises(AttestationRejected):
                replace(apple, identity=AppleAppIdentityV1(name)).transcript()
        replace(apple, identity=AppleAppIdentityV1("é" * 127 + "a")).transcript()
        self.assertNotEqual(replace(apple, identity=AppleAppIdentityV1("é")).policy_digest(),
                            replace(apple, identity=AppleAppIdentityV1("é")).policy_digest())


if __name__ == "__main__":
    unittest.main()
