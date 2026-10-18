"""Synthetic App Attest assertion signatures and adversarial counter checks."""

import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from iroha_app_attestation.attestation import (
    AttestationRejected,
    DurableAppleAssertionCounterStore,
    RawPlatformProof,
    children,
    der_one,
    device_key_reference,
    primitive,
    require_apple_counter_advance,
    verify_apple_assertion,
)


def cbor(value: object) -> bytes:
    if isinstance(value, bytes):
        major, payload, length = 2, value, len(value)
    elif isinstance(value, str):
        payload = value.encode("utf-8")
        major, length = 3, len(payload)
    elif isinstance(value, dict):
        payload = b"".join(cbor(key) + cbor(item) for key, item in value.items())
        major, length = 5, len(value)
    else:
        raise AssertionError("unsupported synthetic CBOR value")
    if length < 24:
        return bytes([(major << 5) | length]) + payload
    if length < 256:
        return bytes([(major << 5) | 24, length]) + payload
    return bytes([(major << 5) | 25]) + length.to_bytes(2, "big") + payload


class SyntheticAssertion:
    def __init__(self, directory: Path, openssl: Path) -> None:
        self.directory = directory
        self.openssl = openssl
        self.run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "key.pem")
        self.run("pkey", "-in", "key.pem", "-pubout", "-outform", "DER", "-out", "key.spki")
        spki = children(der_one((directory / "key.spki").read_bytes()))
        self.point = primitive(spki[1], 3)[1:]
        self.key_id = hashlib.sha256(self.point).digest()
        self.app_id = "TEAMID.example.app"

    def run(self, *arguments: str) -> None:
        subprocess.run([str(self.openssl), *arguments], cwd=self.directory,
                       stdin=subprocess.DEVNULL, capture_output=True, check=True)

    def auth(self, counter: int, *, flags: int = 0,
             extensions: dict[str, object] | None = None) -> bytes:
        data = (hashlib.sha256(self.app_id.encode()).digest() + bytes([flags])
                + counter.to_bytes(4, "big"))
        if extensions is not None:
            data += cbor(extensions)
        return data

    def assertion(self, auth: bytes, client_data: bytes,
                  *, wrong_single_hash: bool = False) -> bytes:
        message = auth + hashlib.sha256(client_data).digest()
        (self.directory / "signed.bin").write_bytes(
            message if wrong_single_hash else hashlib.sha256(message).digest())
        self.run("dgst", "-sha256", "-sign", "key.pem", "-out", "signature.bin", "signed.bin")
        return cbor({"signature": (self.directory / "signature.bin").read_bytes(),
                     "authenticatorData": auth})

    def verify(self, assertion: bytes, client_data: bytes, previous: int = 0,
               *, category: int | None = None, version: str | None = None,
               expected_client_data: bytes | None = None):
        return verify_apple_assertion(
            assertion, client_data,
            client_data if expected_client_data is None else expected_client_data,
            self.point, self.key_id, self.app_id, previous, self.openssl,
            expected_validation_category=category, expected_bundle_version=version,
        )


class AppleAssertionTests(unittest.TestCase):
    def setUp(self) -> None:
        executable = shutil.which("openssl")
        if executable is None:
            self.skipTest("OpenSSL CLI unavailable")
        self.openssl = Path(executable).resolve()

    def test_signed_assertion_binds_app_challenge_key_and_increasing_counter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SyntheticAssertion(Path(temporary), self.openssl)
            client_data = b"server-generated-once:account:release:operation"
            # A physical iPhone 17 Pro Max produced 37 auth bytes with flag
            # 0x40 and counters 1 then 2. These bytes are synthetic signatures
            # with the same observed shape, not retained physical evidence.
            first = fixture.assertion(fixture.auth(1, flags=0x40), client_data)
            result = fixture.verify(first, client_data)
            self.assertEqual(result.counter, 1)
            self.assertEqual(result.assertion_sha256, hashlib.sha256(first).digest())
            self.assertEqual(result.client_data_sha256, hashlib.sha256(client_data).digest())
            self.assertIsNone(result.validation_category)
            # Apple requires strictly greater than prior, not exactly prior + 1.
            later = fixture.assertion(fixture.auth(3, flags=0x40), client_data + b":next")
            self.assertEqual(fixture.verify(later, client_data + b":next", 1).counter, 3)
            for prior in (1, 3, 4):
                with self.subTest(prior=prior), self.assertRaisesRegex(
                        AttestationRejected, "counter did not advance"):
                    fixture.verify(first, client_data, prior)
            with self.assertRaisesRegex(AttestationRejected, "server challenge"):
                fixture.verify(first, client_data, expected_client_data=client_data + b":other")
            with self.assertRaisesRegex(AttestationRejected, "signature rejected"):
                fixture.verify(first, client_data + b":other")
            wrong_equation = fixture.assertion(fixture.auth(2, flags=0x40),
                                                client_data + b":wrong-equation",
                                                wrong_single_hash=True)
            with self.assertRaisesRegex(AttestationRejected, "signature rejected"):
                fixture.verify(wrong_equation, client_data + b":wrong-equation", 1)
            with self.assertRaisesRegex(AttestationRejected, "App ID"):
                verify_apple_assertion(
                    first, client_data, client_data, fixture.point, fixture.key_id,
                    "TEAMID.other.app", 0, self.openssl,
                    expected_validation_category=None, expected_bundle_version=None,
                )
            with self.assertRaisesRegex(AttestationRejected, "attested key ID"):
                verify_apple_assertion(
                    first, client_data, client_data, fixture.point, b"\x07" * 32,
                    fixture.app_id, 0, self.openssl,
                    expected_validation_category=None, expected_bundle_version=None,
                )

    def test_signed_distribution_extension_requires_exact_governed_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SyntheticAssertion(Path(temporary), self.openssl)
            client_data = b"fresh-server-challenge"
            extension = {"apple_validation_category_01": (4).to_bytes(4, "little"),
                         "apple_bundle_version_01": "27"}
            assertion = fixture.assertion(fixture.auth(2, extensions=extension), client_data)
            result = fixture.verify(assertion, client_data, 1, category=4, version="27")
            self.assertEqual((result.validation_category, result.bundle_version), (4, "27"))
            for category, version in ((2, "27"), (4, "26")):
                with self.subTest(category=category, version=version), self.assertRaisesRegex(
                        AttestationRejected, "distribution policy mismatch"):
                    fixture.verify(assertion, client_data, 1, category=category, version=version)
            for malformed in (
                {"apple_validation_category_01": (0).to_bytes(4, "little"),
                 "apple_bundle_version_01": "27"},
                {"apple_validation_category_01": b"\0\0\0\x04",
                 "apple_bundle_version_01": "27"},
                {"apple_validation_category_01": (4).to_bytes(4, "little")},
                {"validationCategory": (4).to_bytes(4, "little"),
                 "bundleVersion": "27"},
                {**extension, "unknown": b"x"},
            ):
                with self.subTest(malformed=malformed), self.assertRaises(AttestationRejected):
                    fixture.verify(fixture.assertion(fixture.auth(2, extensions=malformed),
                                                     client_data),
                                   client_data, 1, category=4, version="27")
            with self.assertRaisesRegex(AttestationRejected, "incomplete Apple distribution"):
                fixture.verify(assertion, client_data, 1, category=4)
            # The flag byte is signed, but its value alone does not substitute
            # for a governed distribution extension.
            no_extension = fixture.assertion(fixture.auth(2, flags=0x80), client_data)
            with self.assertRaisesRegex(AttestationRejected, "distribution policy mismatch"):
                fixture.verify(no_extension, client_data, 1, category=4, version="27")

    def test_malformed_or_substituted_assertions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SyntheticAssertion(Path(temporary), self.openssl)
            client_data = b"challenge"
            auth = fixture.auth(1)
            valid = fixture.assertion(auth, client_data)
            with self.assertRaisesRegex(AttestationRejected, "assertion outside bound"):
                fixture.verify(valid + b"x" * 4096, client_data)
            with self.assertRaisesRegex(AttestationRejected, "client data differs"):
                fixture.verify(valid, b"x" * 4097)
            for assertion in (
                valid + b"x",
                cbor({"signature": b"\x30\0", "authenticatorData": auth}),
                cbor({"signature": b"\x30\0", "authenticatorData": auth, "extra": b"x"}),
                cbor({"signature": b"\x30\0", "authenticatorData": auth[:36]}),
            ):
                with self.subTest(assertion=assertion[:16]), self.assertRaises(AttestationRejected):
                    fixture.verify(assertion, client_data)
            # A valid 0x40 assertion cannot have its signed flag or counter
            # changed without invalidating the signature.
            flagged_auth = fixture.auth(1, flags=0x40)
            flagged = fixture.assertion(flagged_auth, client_data)
            self.assertEqual(fixture.verify(flagged, client_data).counter, 1)
            signature = (fixture.directory / "signature.bin").read_bytes()
            with self.assertRaisesRegex(AttestationRejected, "signature rejected"):
                fixture.verify(cbor({"signature": signature,
                                     "authenticatorData": auth}), client_data)
            tampered_auth = fixture.auth(2)
            with self.assertRaisesRegex(AttestationRejected, "signature rejected"):
                fixture.verify(cbor({"signature": signature,
                                     "authenticatorData": tampered_auth}), client_data)

    def test_counter_comparator_rejects_rollback_and_accepts_gaps(self) -> None:
        self.assertEqual(require_apple_counter_advance(0, 1), 1)
        self.assertEqual(require_apple_counter_advance(1, 1024), 1024)
        for previous, observed in ((0, 0), (2, 2), (2, 1), (-1, 1),
                                   (0, 1 << 32), (1 << 32, 1), (True, 2), (0, True)):
            with self.subTest(previous=previous, observed=observed), self.assertRaises(
                    AttestationRejected):
                require_apple_counter_advance(previous, observed)

    def test_durable_counter_register_cannot_reset_or_reuse_client_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture = SyntheticAssertion(directory, self.openssl)
            store = DurableAppleAssertionCounterStore(directory / "apple-counters.sqlite")
            proof = RawPlatformProof(b"\x01" * 32, fixture.point,
                                     device_key_reference(fixture.point),
                                     "apple_app_attest")
            self.assertEqual(store.register_verified_key(proof, fixture.app_id,
                                                         "development"), fixture.key_id)
            first_client_data = b"server-prepared-operation-one"
            first = fixture.assertion(fixture.auth(1), first_client_data)
            def advance(assertion: bytes, client_data: bytes,
                        app_id: str = fixture.app_id):
                return store.verify_and_advance(
                    assertion, client_data, client_data, fixture.key_id,
                    app_id, "development", self.openssl,
                    expected_validation_category=None, expected_bundle_version=None,
                )
            self.assertEqual(advance(first, first_client_data).counter, 1)
            # Re-registration and process restart must preserve the prior count.
            store = DurableAppleAssertionCounterStore(directory / "apple-counters.sqlite")
            self.assertEqual(store.register_verified_key(proof, fixture.app_id,
                                                         "development"), fixture.key_id)
            with self.assertRaisesRegex(AttestationRejected, "counter did not advance"):
                advance(first, first_client_data)
            with self.assertRaisesRegex(AttestationRejected, "different scope"):
                store.register_verified_key(proof, "TEAMID.other.app", "development")
            with self.assertRaisesRegex(AttestationRejected, "unregistered Apple assertion"):
                advance(fixture.assertion(fixture.auth(2), b"new"), b"new",
                        "TEAMID.other.app")
            # A higher valid counter still cannot reuse a consumed client challenge.
            replay = fixture.assertion(fixture.auth(2), first_client_data)
            with self.assertRaisesRegex(AttestationRejected, "already consumed"):
                advance(replay, first_client_data)
            second_client_data = b"server-prepared-operation-two"
            second = fixture.assertion(fixture.auth(2), second_client_data)
            self.assertEqual(advance(second, second_client_data).counter, 2)
            with self.assertRaisesRegex(AttestationRejected, "counter did not advance"):
                advance(second, second_client_data)

    def test_server_challenge_is_consumed_across_different_attested_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first_dir, second_dir = directory / "first", directory / "second"
            first_dir.mkdir(mode=0o700)
            second_dir.mkdir(mode=0o700)
            first = SyntheticAssertion(first_dir, self.openssl)
            second = SyntheticAssertion(second_dir, self.openssl)
            store = DurableAppleAssertionCounterStore(directory / "apple-counters.sqlite")
            for fixture in (first, second):
                proof = RawPlatformProof(b"\x01" * 32, fixture.point,
                                         device_key_reference(fixture.point),
                                         "apple_app_attest")
                store.register_verified_key(proof, fixture.app_id, "development")

            challenge = b"one-server-issued-challenge"
            store.verify_and_advance(
                first.assertion(first.auth(1), challenge), challenge, challenge,
                first.key_id, first.app_id, "development", self.openssl,
                expected_validation_category=None, expected_bundle_version=None,
            )
            with self.assertRaisesRegex(AttestationRejected, "already consumed"):
                store.verify_and_advance(
                    second.assertion(second.auth(1), challenge), challenge, challenge,
                    second.key_id, second.app_id, "development", self.openssl,
                    expected_validation_category=None, expected_bundle_version=None,
                )
            fresh = b"distinct-server-issued-challenge"
            accepted = store.verify_and_advance(
                second.assertion(second.auth(1), fresh), fresh, fresh,
                second.key_id, second.app_id, "development", self.openssl,
                expected_validation_category=None, expected_bundle_version=None,
            )
            self.assertEqual(accepted.counter, 1)

    def test_old_per_key_challenge_register_layout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "apple-counters.sqlite"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("""CREATE TABLE apple_client_data (
                    key_id BLOB NOT NULL,
                    client_data_sha256 BLOB NOT NULL,
                    PRIMARY KEY(key_id, client_data_sha256)
                )""")
            path.chmod(0o600)
            with self.assertRaisesRegex(AttestationRejected,
                                        "unsupported Apple challenge register layout"):
                DurableAppleAssertionCounterStore(path)


if __name__ == "__main__":
    unittest.main()
