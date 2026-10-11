"""Native-generated private configuration DATA agrees with the real Python policy parser."""
import base64
import hashlib
import json
from pathlib import Path
import unittest

from iroha_app_attestation.attestation import AttestationRejected
from iroha_app_attestation.wallet_enrollment import WalletEnrollmentScope
from iroha_app_attestation.wallet_enrollment_worker import (
    CONFIG_SCHEMA, MAX_CONFIG, configured_policy, exact_json,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/kagemusha"


class NativeConfigurationTests(unittest.TestCase):
    def test_rust_originals_reconstruct_the_exact_model_policy_and_request(self):
        vectors = json.loads((FIXTURES / "wallet_enrollment_worker_configuration_v1.json").read_text())
        self.assertEqual([v["platform"] for v in vectors], ["android", "apple"])
        for vector in vectors:
            with self.subTest(platform=vector["platform"]):
                self.assertEqual(vector["authority"], "unadmitted DATA only")
                original = base64.b64decode(vector["configuration_base64"], validate=True)
                self.assertEqual(hashlib.sha256(original).hexdigest(), vector["configuration_sha256"])
                value = exact_json(original, MAX_CONFIG)
                self.assertEqual(set(value), {"schema", "version", "platform", "app_policy_hex",
                    "enrollment_policy_hex", "openssl_path", "openssl_sha256", "store_directory", "policy"})
                self.assertEqual(value["schema"], CONFIG_SCHEMA)
                self.assertEqual(value["version"], 1)
                self.assertEqual(value["platform"], vector["platform"])
                policy = configured_policy(value["policy"], value["platform"])
                self.assertEqual(policy.app.policy_digest().hex(), value["app_policy_hex"])
                self.assertEqual(policy.enrollment.policy_digest().hex(), value["enrollment_policy_hex"])
                self.assertEqual(policy.app.transcript(), base64.b64decode(vector["app_transcript_base64"], validate=True))
                self.assertEqual(policy.enrollment.transcript(), base64.b64decode(vector["enrollment_transcript_base64"], validate=True))
                request = exact_json(base64.b64decode(vector["request_base64"], validate=True), MAX_CONFIG)
                scope = WalletEnrollmentScope(base64.b64decode(request["challenge_transcript_base64"], validate=True),
                    base64.b64decode(request["payment_key_base64"], validate=True))
                scope.validate()
                policy.validate_scope(scope.challenge_transcript, request["issued_at_ms"], request["trusted_time_ms"])
                self.assertEqual(request["expires_at_ms"], request["issued_at_ms"] + policy.enrollment.challenge_lifetime_ms)
                if value["platform"] == "android":
                    # Chain-only E5 evidence; Android selects no root original.
                    self.assertEqual(set(request["evidence"]), {"chain_base64"})
                    self.assertIsNone(policy.apple_root_der)
                    for removed in ("root_base64", "root_sha256", "package_version",
                                    "app_certificate_sha256", "security_levels",
                                    "google_policy_base64", "maximum_evidence_age_ms"):
                        with self.assertRaises(AttestationRejected):
                            configured_policy(dict(value["policy"], **{removed: "x"}), "android")
                    changed = dict(value["policy"], roots=[dict(value["policy"]["roots"][0],
                                                                family="vendor", adapter_id="huawei",
                                                                revocation_source="operator_denylist")])
                    with self.assertRaisesRegex(AttestationRejected, "unqualified"):
                        configured_policy(changed, "android")
                else:
                    changed = dict(value["policy"], root_base64=base64.b64encode(b"different DATA root").decode())
                    with self.assertRaises(AttestationRejected):
                        configured_policy(changed, "apple")


if __name__ == "__main__":
    unittest.main()
