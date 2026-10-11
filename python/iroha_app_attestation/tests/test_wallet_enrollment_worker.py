"""Real synthetic AppAttest signatures and durable private-process protocol regressions."""
import base64
from dataclasses import replace
import hashlib
import io
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.error
from contextlib import ExitStack, closing
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, wait
from types import SimpleNamespace
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from iroha_app_attestation.attestation import (
    AttestationRejected, EnrollmentRefusal, EvidenceRefused, VerificationUnavailable, spki_sha256,
)
from iroha_app_attestation.wallet_enrollment_worker import (
    CONFIG_SCHEMA, PREPARATION_SCHEMA, SCHEMA, MAX_PACKET, MAX_REQUEST, MAX_ORIGINAL, EXCHANGE_WINDOW, VerifierOwner, DispatchClock,
    E1CounterStore, configured_policy, encode, exact_json, read_packet, serve,
)
from iroha_app_attestation.wallet_enrollment import WalletEnrollmentScope
from iroha_app_attestation import revocation
from iroha_app_attestation.revocation import DENYLIST_CUSTODY, OperatorDenylistCustody
from test_wallet_enrollment import (GENERATOR, configured_policy as fixture_policy, policy_scope)
from synthetic_pki import (APP_ID, PACKAGE, SIGNER, SignedEnvelope, SyntheticPki, apple_assertion,
                           apple_object, key_description, remote_hierarchy)

Code = EnrollmentRefusal


def assertion(fixture, client_data_hash, counter):
    return apple_assertion(fixture, client_data_hash, counter)


# These are private-packet DATA fixtures. Canonical Norito account decoding and Ed25519
# signature authentication are Core responsibilities, never authority supplied by this test.
ACCOUNT_SIGNATURE = b"s" * 64


def preparation_original(owner, original):
    value = exact_json(original, MAX_REQUEST)
    selected = WalletEnrollmentScope(base64.b64decode(value["challenge_transcript_base64"]),
                                     base64.b64decode(value["payment_key_base64"]))
    return encode({"schema": PREPARATION_SCHEMA, "operation_id": selected.challenge_digest().hex(),
        "challenge_transcript_base64": value["challenge_transcript_base64"],
        "account_original_base64": base64.b64encode(b"synthetic canonical account DATA").decode(),
        "account_owner_public_hex": "55" * 32,
        "issued_at_ms": value["issued_at_ms"], "expires_at_ms": value["expires_at_ms"],
        "platform": value["platform"], "app_policy_hex": owner.app_policy.hex(),
        "enrollment_policy_hex": owner.enrollment_policy.hex(), "config_sha256": owner.config_digest.hex()})


def dispatch(owner, original, action):
    preparation = preparation_original(owner, original)
    incarnation = owner.counters.incarnation
    if action == "complete":
        owner.prepare(incarnation, preparation)
    return owner.perform(original, action, incarnation=incarnation, preparation=preparation,
        account_signature=ACCOUNT_SIGNATURE, dispatch_time_ms=exact_json(original, MAX_REQUEST)["trusted_time_ms"])


def packet(action="recover", *, exchange="31" * 32, owner=None, original=b"{}"):
    operation = action in ("complete", "recover", "inspect")
    return encode({"schema": SCHEMA, "version": 1, "exchange_id": exchange, "action": action,
        "journal_incarnation": None if action == "journal" else ("21" * 32 if owner is None else owner.counters.incarnation.hex()),
        "preparation_base64": None if action == "journal" else base64.b64encode(
            b"{}" if owner is None else preparation_original(owner, original)).decode(),
        "original_base64": base64.b64encode(original).decode() if operation else None,
        "account_signature_base64": base64.b64encode(ACCOUNT_SIGNATURE).decode() if operation else None,
        "dispatch_time_ms": (1 if owner is None else exact_json(original, MAX_REQUEST)["trusted_time_ms"]) if operation else None})


class ProtocolOnlyOwner:
    # Only framing/error tests use this inert owner; it cannot produce evidence.
    counters = SimpleNamespace(incarnation=b"!" * 32)
    config_digest = b"c" * 32
    def perform(self, original, action, **arguments): return None



class WorkerTests(unittest.TestCase):
    def setUp(self):
        binary = shutil.which("openssl")
        if binary is None:
            self.skipTest("OpenSSL3 unavailable")
        self.openssl = Path(binary).resolve()
        # Simulated clocks only: this suite runs on macOS and uses certificates
        # whose synthetic verification time is one minute ahead of wall time.
        self.enterContext(patch("iroha_app_attestation.wallet_enrollment_worker._sleep_inclusive_ns",
                                side_effect=time.monotonic_ns))
        self.enterContext(patch("iroha_app_attestation.wallet_enrollment_worker._realtime_ns",
                                side_effect=lambda: time.time_ns() + 61_000_000_000))

    def owner_fixture(self, directory, challenge_lifetime_ms=120000, *, initialize=True):
        directory = directory.resolve(strict=True)
        os.chmod(directory, 0o700)
        fixture = SignedEnvelope(directory, self.openssl)
        policy = fixture_policy(fixture.root_der(), True)
        policy = replace(policy, enrollment=replace(policy.enrollment, challenge_lifetime_ms=challenge_lifetime_ms))
        selected = policy_scope(policy, GENERATOR)
        attestation, key_id, root = apple_object(fixture, selected.challenge_digest())
        now = int(time.time() * 1000) + 60000
        request = encode({"challenge_transcript_base64": base64.b64encode(selected.challenge_transcript).decode(),
            "payment_key_base64": base64.b64encode(GENERATOR).decode(),
            "issued_at_ms": now - 1, "expires_at_ms": now - 1 + challenge_lifetime_ms,
            "trusted_time_ms": now, "platform": "apple", "evidence": {
                "attestation_base64": base64.b64encode(attestation).decode(),
                "assertion_base64": base64.b64encode(assertion(fixture, selected.enrollment_key_binding(), 1)).decode(),
                "key_id_hex": key_id.hex()}})
        config = encode({"schema": CONFIG_SCHEMA, "version": 1, "platform": "apple",
            "app_policy_hex": policy.app.policy_digest().hex(),
            "enrollment_policy_hex": policy.enrollment.policy_digest().hex(),
            "openssl_path": str(self.openssl), "openssl_sha256": hashlib.sha256(self.openssl.read_bytes()).hexdigest(),
            "store_directory": str(directory), "policy": {"app_id": "TEAMID.example.app",
                "scheme_id_hex": policy.enrollment.scheme_id.hex(), "asset_digest_hex": policy.enrollment.asset_digest.hex(),
                "regulatory_policy": {"permitted_controls": 0, "blacklist_max_age_ms": 0,
                                      "time_anchor_max_response_ms": 0},
                "challenge_lifetime_ms": challenge_lifetime_ms, "attestation_lease_lifetime_ms": 0,
                "root_base64": base64.b64encode(root).decode(), "root_sha256": hashlib.sha256(root).hexdigest()}})
        directory_fd = os.open(directory, os.O_RDONLY)
        crypto_fd = os.open(self.openssl, os.O_RDONLY)
        self.addCleanup(os.close, directory_fd)
        self.addCleanup(os.close, crypto_fd)
        if initialize:
            E1CounterStore.initialize(directory, directory_fd).close()
        def open_owner(original=config, **arguments):
            return VerifierOwner(original, directory_fd=directory_fd, crypto_fd=crypto_fd, **arguments)
        open_owner.config = config
        open_owner.fixture = fixture
        return open_owner, request, selected, key_id

    def test_expiry_during_real_apple_assertion_never_commits_counter_or_result(self):
        from iroha_app_attestation import wallet_enrollment_worker as worker
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, key_id = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            source = exact_json(request, MAX_REQUEST)
            wall = [source["trusted_time_ms"] * 1_000_000]
            original_verify = worker._verify_apple_assertion_with_hash
            def delayed_assertion(*args, **kwargs):
                result = original_verify(*args, **kwargs)
                wall[0] = source["expires_at_ms"] * 1_000_000
                return result
            with patch.object(worker, "_realtime_ns", side_effect=lambda: wall[0]), \
                    patch.object(worker, "_verify_apple_assertion_with_hash", side_effect=delayed_assertion):
                with self.assertRaisesRegex(EvidenceRefused, "expired") as raised:
                    dispatch(owner, request, "complete")
            self.assertEqual(raised.exception.code, Code.CHALLENGE_EXPIRED)
            # The refusal is terminal and retained: every retry returns the same code.
            for action in ("recover", "complete", "inspect"):
                with self.subTest(action=action), self.assertRaises(EvidenceRefused) as again:
                    dispatch(owner, request, action)
                self.assertEqual(again.exception.code, Code.CHALLENGE_EXPIRED)
            with sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3") as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT outcome, result, refusal_code FROM wallet_e1_attempts").fetchone(),
                                 ("refused", None, 10))

    def test_verification_starting_after_the_challenge_lifetime_is_refused_and_retained(self):
        from iroha_app_attestation import wallet_enrollment_worker as worker
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            source = exact_json(request, MAX_REQUEST)
            arguments = self.prepared(owner, request)
            with patch.object(worker, "_realtime_ns", return_value=source["expires_at_ms"] * 1_000_000), \
                    patch.object(worker, "verify_apple_wallet_attestation_raw", side_effect=AssertionError("must not verify")):
                with self.assertRaisesRegex(EvidenceRefused, "expired") as raised:
                    owner.perform(request, "recover", **arguments)
                self.assertEqual(raised.exception.code, Code.CHALLENGE_EXPIRED)
                with self.assertRaises(EvidenceRefused):
                    owner.perform(request, "complete", **arguments)
            with sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3") as connection:
                self.assertEqual(connection.execute("SELECT request_sha256 IS NOT NULL, outcome, result, refusal_code FROM wallet_e1_attempts").fetchone(),
                                 (1, "refused", None, 10))

    def test_selected_lifetime_has_no_unconfigured_ten_minute_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, selected, _ = self.owner_fixture(Path(temporary), 600001)
            owner = open_owner()
            try:
                original = dispatch(owner, request, "complete")
                self.assertEqual(exact_json(original, MAX_PACKET)["challenge_digest"],
                                 selected.challenge_digest().hex())
                self.assertEqual(dispatch(owner, request, "recover"), original)
            finally:
                owner.close()

    def test_shortened_issuer_deadline_verifies_real_apple_and_recovers_exact_winner(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, selected, key_id = self.owner_fixture(Path(temporary))
            value = exact_json(request, MAX_REQUEST)
            value["expires_at_ms"] = value["issued_at_ms"] + 30000
            shortened = encode(value)
            owner = open_owner()
            try:
                original = dispatch(owner, shortened, "complete")
                self.assertEqual(exact_json(original, MAX_PACKET)["challenge_digest"],
                                 selected.challenge_digest().hex())
                exact_preparation = preparation_original(owner, shortened)
                with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                    self.assertEqual(connection.execute("SELECT preparation FROM wallet_e1_attempts").fetchone(),
                                     (exact_preparation,))
                    self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (1,))
                # Even a still policy-bounded extension may not replace the retained original.
                extended = encode(dict(value, expires_at_ms=value["expires_at_ms"] + 1))
                with self.assertRaisesRegex(AttestationRejected, "already differs"):
                    owner.prepare(owner.journal(), preparation_original(owner, extended))
            finally:
                owner.close()
            restored = open_owner()
            try:
                self.assertEqual(dispatch(restored, shortened, "recover"), original)
            finally:
                restored.close()

    def test_shortened_window_keeps_positive_exact_integer_and_policy_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            value = exact_json(request, MAX_REQUEST)
            for expires in (value["issued_at_ms"] + 1, value["issued_at_ms"] + 30000, value["expires_at_ms"]):
                candidate = encode(dict(value, expires_at_ms=expires, trusted_time_ms=value["issued_at_ms"]))
                self.assertEqual(owner.request(candidate)[0]["expires_at_ms"], expires)
                self.assertEqual(owner.preparation(preparation_original(owner, candidate))[0]["expires_at_ms"], expires)
            for expires in (0, value["issued_at_ms"] - 1, value["issued_at_ms"], value["expires_at_ms"] + 1, 1 << 64, True):
                candidate = encode(dict(value, expires_at_ms=expires))
                with self.subTest(expires=expires):
                    with self.assertRaises(AttestationRejected):
                        owner.request(candidate)
                    with self.assertRaises(AttestationRejected):
                        owner.preparation(preparation_original(owner, candidate))

    def test_shortened_first_dispatch_deadline_is_not_extended_by_policy_maximum(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            value = exact_json(request, MAX_REQUEST)
            value["expires_at_ms"] = value["issued_at_ms"] + 30000
            shortened = encode(value)
            preparation = preparation_original(owner, shortened)
            incarnation = owner.journal()
            owner.prepare(incarnation, preparation)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("expired first dispatch must not verify")):
                with self.assertRaisesRegex(EvidenceRefused, "after the E1 challenge lifetime") as raised:
                    owner.perform(shortened, "complete", incarnation=incarnation,
                        preparation=preparation, account_signature=ACCOUNT_SIGNATURE,
                        dispatch_time_ms=value["expires_at_ms"])
                self.assertEqual(raised.exception.code, Code.CHALLENGE_EXPIRED)
                with self.assertRaises(EvidenceRefused):
                    dispatch(owner, shortened, "complete")
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT first_dispatch, outcome, refusal_code FROM wallet_e1_attempts").fetchone(),
                                 (value["expires_at_ms"].to_bytes(8, "little"), "refused", 10))

    def test_selected_lifetime_keeps_strict_u64_and_half_open_time_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary), 1 << 63)
            owner = open_owner()
            try:
                value = exact_json(request, MAX_PACKET)
                for now in (value["issued_at_ms"], value["expires_at_ms"] - 1):
                    original = encode(dict(value, trusted_time_ms=now))
                    self.assertEqual(owner.request(original)[0]["trusted_time_ms"], now)
                for changed in (
                    dict(value, trusted_time_ms=value["issued_at_ms"] - 1),
                    dict(value, trusted_time_ms=value["expires_at_ms"]),
                    dict(value, issued_at_ms=1 << 63, expires_at_ms=1 << 64,
                         trusted_time_ms=(1 << 63) + 1),
                    dict(value, expires_at_ms=value["expires_at_ms"] + 1),
                    dict(value, trusted_time_ms=True),
                ):
                    with self.assertRaises(AttestationRejected):
                        owner.request(encode(changed))
            finally:
                owner.close()

    def test_real_apple_result_and_counter_commit_and_recover_after_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, selected, key_id = self.owner_fixture(Path(temporary))
            owner = open_owner()
            original = dispatch(owner, request, "complete")
            projection = exact_json(original, MAX_PACKET)
            self.assertEqual(projection["key_binding"], selected.enrollment_key_binding().hex())
            self.assertEqual(projection["kind_tag"], 3)
            self.assertEqual(projection["facts"], 448)
            self.assertEqual(projection["app_attest_counter"], 1)
            self.assertEqual(projection["app_attest_key_id"], key_id.hex())
            owner.close()
            restarted = open_owner()
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("recovery must not verify again")):
                self.assertEqual(dispatch(restarted, request, "recover"), original)
            self.assertEqual(dispatch(restarted, request, "complete"), original)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (1,))
            restarted.close()

    def test_real_apple_commit_survives_lost_private_pipe(self):
        class LostOutput(io.BytesIO):
            def write(self, _):
                raise BrokenPipeError()
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            owner.prepare(owner.counters.incarnation, preparation_original(owner, request))
            message = packet("complete", owner=owner, original=request)
            with self.assertRaises(BrokenPipeError):
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), LostOutput())
            owner.close()
            restarted = open_owner()
            self.assertIsNotNone(dispatch(restarted, request, "recover"))
            restarted.close()

    def test_unprepared_recovery_is_refused_and_never_verifies_or_inserts_an_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            self.addCleanup(owner.close)
            message = packet("recover", exchange="32" * 32, owner=owner, original=request)
            output = io.BytesIO()
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("recovery must not dispatch verification")):
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
            response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
            self.assertEqual(response["outcome"], "unavailable")
            self.assertIsNone(response["evidence_base64"])
            with sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3") as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (0,))

    def test_failed_apple_assertion_retains_attempt_without_counter_consumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, key_id = self.owner_fixture(Path(temporary))
            value = exact_json(request, MAX_PACKET)
            raw = bytearray(base64.b64decode(value["evidence"]["assertion_base64"]))
            raw[-1] ^= 1
            value["evidence"]["assertion_base64"] = base64.b64encode(raw).decode()
            changed = encode(value)
            owner = open_owner()
            for action in ("complete", "recover", "complete", "inspect"):
                with self.subTest(action=action), self.assertRaises(EvidenceRefused) as raised:
                    dispatch(owner, changed, action)
                self.assertEqual(raised.exception.code, Code.EVIDENCE_INVALID)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (0,))
            owner.close()

    def test_private_packet_bounds_duplicate_unknown_and_exchange_replay(self):
        for malformed in (b"x", b"\1\0\0\0", (MAX_PACKET + 1).to_bytes(4, "little")):
            with self.assertRaises(AttestationRejected):
                read_packet(io.BytesIO(malformed))
        for original in (b'{"version":1,"version":1}', b'{} trailing', b'{"v":NaN}'):
            with self.assertRaises(AttestationRejected):
                exact_json(original, MAX_PACKET)
        message = packet()
        frame = len(message).to_bytes(4, "little") + message
        with self.assertRaises(AttestationRejected):
            serve(ProtocolOnlyOwner(), io.BytesIO(frame + frame), io.BytesIO())
        value = exact_json(message, MAX_PACKET)
        value["issuer_key"] = "forbidden"
        changed = encode(value)
        with self.assertRaises(AttestationRejected):
            serve(ProtocolOnlyOwner(), io.BytesIO(len(changed).to_bytes(4, "little") + changed), io.BytesIO())
        retired = encode({"schema": SCHEMA, "version": 1, "exchange_id": "31" * 32,
                          "action": "verify", "original_base64": "e30="})
        with self.assertRaises(AttestationRejected):
            serve(ProtocolOnlyOwner(), io.BytesIO(len(retired).to_bytes(4, "little") + retired), io.BytesIO())

    def test_retired_deployment_preparation_schema_cannot_create_or_resume_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            current = preparation_original(owner, request)
            retired = exact_json(current, MAX_REQUEST)
            retired["schema"] = "bpng.wallet-e1-worker-preparation.v1"
            retired = encode(retired)
            with self.assertRaises(AttestationRejected):
                owner.prepare(owner.journal(), retired)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))
            owner.prepare(owner.journal(), current)
            with self.assertRaises(AttestationRejected):
                owner.prepare(owner.journal(), retired)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT preparation FROM wallet_e1_attempts").fetchall(), [(current,)])

    def test_fragmented_private_header_and_body_preserve_exact_packet(self):
        class Fragmented(io.BytesIO):
            def read(self, width=-1): return super().read(min(width, 1))
        self.assertEqual(read_packet(Fragmented((3).to_bytes(4, "little") + b"abc")), b"abc")

    def test_private_error_replies_preserve_storage_retry_and_never_expose_secrets(self):
        for error, expected in ((sqlite3.OperationalError("private bearer"), "unavailable"),
                                (FileNotFoundError("private bearer"), "unavailable"),
                                (sqlite3.IntegrityError("private bearer"), "rejected"),
                                (AttestationRejected("private bearer"), "rejected"),
                                (EvidenceRefused(Code.APP_IDENTITY_MISMATCH, "private bearer"), "refused"),
                                (VerificationUnavailable("private bearer"), "unavailable")):
            class FailedOwner(ProtocolOnlyOwner):
                def perform(self, original, action, **arguments): raise error
            message = packet()
            output = io.BytesIO()
            serve(FailedOwner(), io.BytesIO(len(message).to_bytes(4, "little") + message), output)
            response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
            self.assertEqual(response["outcome"], expected)
            self.assertIsNone(response["evidence_base64"])
            self.assertEqual(response["refusal_code"], 7 if expected == "refused" else None)
            self.assertNotIn(b"private bearer", output.getvalue())

    def test_lost_journal_cannot_restart_or_reverify_consumed_apple_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            open_owner, request, _, _ = self.owner_fixture(directory)
            owner = open_owner()
            self.addCleanup(owner.close)
            original = dispatch(owner, request, "complete")
            self.assertIsNotNone(original)
            (directory / "wallet-e1.sqlite3").unlink()
            message = packet("recover", owner=owner, original=request)
            output = io.BytesIO()
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("lost custody must never reverify")):
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
                response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
                self.assertEqual(response["outcome"], "unavailable")
                self.assertIsNone(response["evidence_base64"])
                owner.close()
                with self.assertRaises(FileNotFoundError):
                    open_owner()
            self.assertFalse((directory / "wallet-e1.sqlite3").exists())

    def test_request_cannot_select_policy_or_future_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            for mutate in (lambda v: v.update({"roots": []}),
                           lambda v: v.update({"trusted_time_ms": v["expires_at_ms"]}),
                           lambda v: v.update({"platform": "android"})):
                value = exact_json(request, MAX_PACKET)
                mutate(value)
                with self.assertRaises(AttestationRejected):
                    dispatch(owner, encode(value), "complete")
            owner.close()

    def test_recovery_rechecks_original_custody_after_reading_committed_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            dispatch(owner, request, "complete")
            with patch.object(owner, "recheck", side_effect=[None, AttestationRejected("changed original")]):
                with self.assertRaises(AttestationRejected):
                    dispatch(owner, request, "recover")
            owner.close()


    def test_private_configuration_projection_cannot_select_a_foreign_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, _, _, _ = self.owner_fixture(Path(temporary), initialize=False)
            source = exact_json(open_owner.config, MAX_PACKET)
            for change in (lambda v: v.update({"signer": "forbidden"}),
                           lambda v: v.update({"version": True}),
                           lambda v: v.update({"app_policy_hex": "01" * 32}),
                           lambda v: v["policy"].update({"scheme_id_hex": "00" * 32}),
                           lambda v: v["policy"].update({"asset_digest_hex": "09" * 32}),
                           lambda v: v["policy"].update({"app_id": "FOREIGN.app"}),
                           lambda v: v["policy"].update({"root_base64": "eA=="}),
                           lambda v: v["policy"].update({"attestation_lease_lifetime_ms": True}),
                           lambda v: v["policy"].update({"challenge_lifetime_ms": 600001}),
                           lambda v: v["policy"]["regulatory_policy"].update({"permitted_controls": 8})):
                value = json.loads(json.dumps(source)); change(value)
                with self.subTest(value=value["policy"].get("app_id")), self.assertRaises(AttestationRejected):
                    open_owner(encode(value))
                self.assertFalse((Path(temporary) / "wallet-e1.sqlite3").exists())

    def test_request_requires_bounded_selected_lifetime_scheme_asset_and_raw_integer_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            for change in (lambda v: v.update({"expires_at_ms": v["expires_at_ms"] + 1}),
                           lambda v: v.update({"issued_at_ms": True}),
                           lambda v: v.update({"trusted_time_ms": True})):
                value = exact_json(request, MAX_PACKET); change(value)
                with self.assertRaises(AttestationRejected): dispatch(owner, encode(value), "complete")
            for index in (2, 34):
                value = exact_json(request, MAX_PACKET)
                transcript = bytearray(base64.b64decode(value["challenge_transcript_base64"]))
                transcript[index] ^= 1
                value["challenge_transcript_base64"] = base64.b64encode(transcript).decode()
                with self.assertRaises(AttestationRejected): dispatch(owner, encode(value), "complete")
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts WHERE request_sha256 IS NOT NULL").fetchone(), (0,))

    def test_asset_switch_reuses_exact_store_and_recovers_original_without_cross_asset_verdict(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            open_owner, request_a, _, key_id = self.owner_fixture(directory)
            owner_a = open_owner()
            preparation_a = preparation_original(owner_a, request_a)
            incarnation = owner_a.journal()
            result_a = dispatch(owner_a, request_a, "complete")
            owner_a.close()
            generation = (directory / "wallet-e1.generation").read_bytes()
            config_b = exact_json(open_owner.config, MAX_PACKET)
            config_b["policy"]["asset_digest_hex"] = "83" * 32
            policy_b = configured_policy(config_b["policy"], "apple")
            config_b["enrollment_policy_hex"] = policy_b.enrollment.policy_digest().hex()
            selected_b = policy_scope(policy_b, GENERATOR)
            attestation, key_b, _ = apple_object(open_owner.fixture, selected_b.challenge_digest())
            self.assertEqual(key_b, key_id)
            value_b = exact_json(request_a, MAX_REQUEST)
            value_b["challenge_transcript_base64"] = base64.b64encode(selected_b.challenge_transcript).decode()
            value_b["evidence"] = {
                "attestation_base64": base64.b64encode(attestation).decode(),
                "assertion_base64": base64.b64encode(assertion(open_owner.fixture, selected_b.enrollment_key_binding(), 2)).decode(),
                "key_id_hex": key_b.hex(),
            }
            request_b = encode(value_b)
            owner_b = open_owner(encode(config_b))
            self.assertEqual(owner_b.journal(), incarnation)
            with self.assertRaises(AttestationRejected):
                owner_b.prepare(incarnation, preparation_a)
            with self.assertRaises(AttestationRejected):
                dispatch(owner_b, request_a, "recover")
            result_b = dispatch(owner_b, request_b, "complete")
            self.assertNotEqual(result_a, result_b)
            owner_b.close()
            owner_a = open_owner(); self.addCleanup(owner_a.close)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("Recovery/Inspect must not reverify after asset switch")):
                self.assertEqual(dispatch(owner_a, request_a, "recover"), result_a)
                arguments = dict(incarnation=incarnation, preparation=preparation_a,
                    account_signature=ACCOUNT_SIGNATURE,
                    dispatch_time_ms=exact_json(request_a, MAX_REQUEST)["expires_at_ms"] + 1)
                self.assertEqual(owner_a.perform(request_a, "inspect", **arguments), result_a)
                with self.assertRaises(AttestationRejected):
                    dispatch(owner_a, request_b, "inspect")
            self.assertEqual((directory / "wallet-e1.generation").read_bytes(), generation)
            with closing(sqlite3.connect(directory / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (2,))
                rows = connection.execute("SELECT config_sha256, original, result FROM wallet_e1_attempts ORDER BY original").fetchall()
                self.assertEqual(len(rows), 2)
                self.assertEqual({row[0] for row in rows}, {hashlib.sha256(open_owner.config).digest(), hashlib.sha256(encode(config_b)).digest()})
                self.assertEqual({row[1] for row in rows}, {request_a, request_b})
                self.assertEqual({row[2] for row in rows}, {result_a, result_b})

    def test_recovery_requires_same_complete_configuration_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); original = dispatch(owner, request, "complete"); owner.close()
            # Same semantic policy, different original: signed inventory and result binding differ.
            changed = open_owner.config + b" "
            restored = open_owner(changed); self.addCleanup(restored.close)
            with self.assertRaises(AttestationRejected): dispatch(restored, request, "recover")
            unchanged = open_owner(); self.addCleanup(unchanged.close)
            self.assertEqual(dispatch(unchanged, request, "recover"), original)

    def test_recovery_rejects_replaced_database_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            dispatch(owner, request, "complete")
            path = Path(temporary) / "wallet-e1.sqlite3"
            replacement = Path(temporary) / "replacement.sqlite3"
            shutil.copyfile(path, replacement); replacement.chmod(0o600); replacement.replace(path)
            with self.assertRaises(VerificationUnavailable): dispatch(owner, request, "recover")

    def test_recovery_rejects_hardlinked_database_and_shared_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close); dispatch(owner, request, "complete")
            path = Path(temporary) / "wallet-e1.sqlite3"
            link = Path(temporary) / "other.sqlite3"; os.link(path, link)
            with self.assertRaises(VerificationUnavailable): dispatch(owner, request, "recover")
            link.unlink(); path.chmod(0o640)
            with self.assertRaises(VerificationUnavailable): dispatch(owner, request, "recover")

    def test_held_configuration_original_is_rechecked_before_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            path = Path(temporary) / "config.json"; path.write_bytes(open_owner.config); path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY); self.addCleanup(os.close, fd)
            owner = open_owner(configuration_fd=fd); self.addCleanup(owner.close)
            dispatch(owner, request, "complete")
            path.write_bytes(open_owner.config + b" ")
            with self.assertRaises(VerificationUnavailable): dispatch(owner, request, "recover")

    def test_bound_exchanges_continue_past_4096_and_recent_tags_still_reject(self):
        def frame(n):
            message = packet(exchange=n.to_bytes(32, "big").hex())
            return len(message).to_bytes(4, "little") + message
        output = io.BytesIO()
        serve(ProtocolOnlyOwner(), io.BytesIO(b"".join(frame(n) for n in range(1, EXCHANGE_WINDOW + 4))), output)
        count = 0; replies = io.BytesIO(output.getvalue())
        while read_packet(replies) is not None: count += 1
        self.assertEqual(count, EXCHANGE_WINDOW + 3)
        with self.assertRaises(AttestationRejected):
            serve(ProtocolOnlyOwner(), io.BytesIO(frame(1) + frame(2) + frame(1)), io.BytesIO())

    def test_attempt_original_cannot_be_changed_or_reverified_after_unknown_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            # An interruption during verification leaves the claim in flight: outcome unknown.
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=sqlite3.OperationalError("synthetic interruption")):
                with self.assertRaises(sqlite3.OperationalError): dispatch(owner, request, "complete")
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("ambiguous attempt must only recover")):
                self.assertIsNone(dispatch(owner, request, "recover"))
                self.assertIsNone(dispatch(owner, request, "complete"))
                self.assertIsNone(dispatch(owner, request, "inspect"))
            value = exact_json(request, MAX_PACKET); value["trusted_time_ms"] += 1
            with self.assertRaises(AttestationRejected): dispatch(owner, encode(value), "complete")
            with self.assertRaises(AttestationRejected): dispatch(owner, encode(value), "recover")

    def prepared(self, owner, request):
        original = preparation_original(owner, request)
        arguments = {"incarnation": owner.journal(), "preparation": original,
            "account_signature": ACCOUNT_SIGNATURE,
            "dispatch_time_ms": exact_json(request, MAX_REQUEST)["trusted_time_ms"]}
        owner.prepare(arguments["incarnation"], original)
        return arguments

    def test_outage_before_any_effect_resumes_the_same_apple_claim_while_live(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, key_id = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            arguments = self.prepared(owner, request)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=VerificationUnavailable("synthetic outage")) as external:
                with self.assertRaises(VerificationUnavailable):
                    owner.perform(request, "complete", **arguments)
                # A second outage on the resumed claim stays a recovery state.
                with self.assertRaises(VerificationUnavailable):
                    owner.perform(request, "recover", **dict(arguments, dispatch_time_ms=arguments["dispatch_time_ms"] + 1))
                self.assertEqual(external.call_count, 2)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT outcome, refusal_code, result FROM wallet_e1_attempts").fetchone(),
                                 ("unavailable", None, None))
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), None)
            later = dict(arguments, dispatch_time_ms=arguments["dispatch_time_ms"] + 7)
            result = owner.perform(request, "complete", **later)
            self.assertEqual(exact_json(result, MAX_ORIGINAL)["time_ms"], arguments["dispatch_time_ms"])
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("terminal evidence is never verified again")):
                self.assertEqual(owner.perform(request, "recover", **later), result)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT outcome FROM wallet_e1_attempts").fetchone(), ("evidence",))

    def test_inspect_never_claims_missing_or_prepared_operation_even_when_live(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            preparation = preparation_original(owner, request)
            arguments = {"incarnation": owner.journal(), "preparation": preparation,
                "account_signature": ACCOUNT_SIGNATURE,
                "dispatch_time_ms": exact_json(request, MAX_REQUEST)["trusted_time_ms"]}
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("Inspect must not verify")):
                with self.assertRaises(VerificationUnavailable):
                    owner.perform(request, "inspect", **arguments)
                with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))
                owner.prepare(arguments["incarnation"], preparation)
                for now in (arguments["dispatch_time_ms"], exact_json(request, MAX_REQUEST)["expires_at_ms"] + 1):
                    with self.subTest(now=now), self.assertRaises(VerificationUnavailable):
                        owner.perform(request, "inspect", **dict(arguments, dispatch_time_ms=now))
                with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                    self.assertEqual(connection.execute("SELECT preparation, request_sha256, key_binding, original, account_signature, result FROM wallet_e1_attempts").fetchone(),
                                     (preparation, None, None, None, None, None))
                    self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (0,))

    def test_inspect_returns_exact_verified_original_after_expiry_and_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, key_id = self.owner_fixture(Path(temporary))
            owner = open_owner()
            arguments = self.prepared(owner, request)
            original = owner.perform(request, "complete", **arguments)
            owner.close()
            owner = open_owner(); self.addCleanup(owner.close)
            arguments["dispatch_time_ms"] = exact_json(request, MAX_REQUEST)["expires_at_ms"] + 1
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("Inspect must not verify")):
                self.assertEqual(owner.perform(request, "inspect", **arguments), original)
                for changed in (request + b" ", encode(dict(exact_json(request, MAX_REQUEST), trusted_time_ms=arguments["dispatch_time_ms"] - 2))):
                    with self.subTest(changed=changed), self.assertRaises(AttestationRejected):
                        owner.perform(changed, "inspect", **arguments)
                with self.assertRaises(AttestationRejected):
                    owner.perform(request, "inspect", **dict(arguments, account_signature=b"x" * 64))
                with self.assertRaises(AttestationRejected):
                    owner.perform(request, "inspect", **dict(arguments, incarnation=b"x" * 32))
                with self.assertRaises(AttestationRejected):
                    owner.perform(request, "inspect", **dict(arguments, dispatch_time_ms=True))
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT original, result FROM wallet_e1_attempts").fetchone(), (request, original))

    def test_inspect_unknown_claim_cannot_restart_external_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            arguments = self.prepared(owner, request)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=VerificationUnavailable("lost result")) as verifier:
                with self.assertRaises(VerificationUnavailable):
                    owner.perform(request, "complete", **arguments)
                self.assertEqual(verifier.call_count, 1)
            owner.close()
            owner = open_owner(); self.addCleanup(owner.close)
            arguments["dispatch_time_ms"] = exact_json(request, MAX_REQUEST)["expires_at_ms"] + 1
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("Inspect cannot reclaim")):
                self.assertIsNone(owner.perform(request, "inspect", **arguments))
                value = exact_json(packet("inspect", owner=owner, original=request), MAX_PACKET)
                message = encode(dict(value, dispatch_time_ms=arguments["dispatch_time_ms"]))
                output = io.BytesIO()
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
                response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
                self.assertEqual(response["outcome"], "outcome_unknown")
                self.assertEqual(response["request_sha256"], hashlib.sha256(message).hexdigest())
                self.assertEqual(response["journal_incarnation"], arguments["incarnation"].hex())
                self.assertIsNone(response["evidence_base64"])
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT original, result FROM wallet_e1_attempts").fetchone(), (request, None))

    def test_inspect_packet_unclaimed_is_unavailable_without_changing_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            arguments = self.prepared(owner, request)
            message = packet("inspect", owner=owner, original=request)
            output = io.BytesIO()
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("Inspect cannot claim")):
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
            response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
            self.assertEqual(response["outcome"], "unavailable")
            self.assertEqual(response["request_sha256"], hashlib.sha256(message).hexdigest())
            self.assertEqual(response["journal_incarnation"], arguments["incarnation"].hex())
            self.assertIsNone(response["evidence_base64"])
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT request_sha256, result FROM wallet_e1_attempts").fetchone(), (None, None))

    def test_prepared_restart_closes_core_dispatch_gap_using_fresh_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, key_id = self.owner_fixture(Path(temporary))
            owner = open_owner()
            arguments = self.prepared(owner, request)
            # Core can durably mark Attempted and die here, before delivering any request.
            owner.close()
            restarted = open_owner(); self.addCleanup(restarted.close)
            self.assertEqual(restarted.journal(), arguments["incarnation"])
            arguments["dispatch_time_ms"] += 123
            result = restarted.perform(request, "recover", **arguments)
            projection = exact_json(result, MAX_ORIGINAL)
            self.assertEqual(projection["time_ms"], arguments["dispatch_time_ms"])
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT original, account_signature FROM wallet_e1_attempts").fetchone(),
                                 (request, ACCOUNT_SIGNATURE))
                self.assertEqual(connection.execute("SELECT counter FROM apple_keys WHERE key_id=?", (key_id,)).fetchone(), (1,))
            arguments["dispatch_time_ms"] = exact_json(request, MAX_REQUEST)["expires_at_ms"] + 100000
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("cached recovery must not verify")):
                restarted.prepare(arguments["incarnation"], arguments["preparation"])
                self.assertEqual(restarted.perform(request, "recover", **arguments), result)
                self.assertEqual(restarted.perform(request, "complete", **arguments), result)

    def test_concurrent_complete_and_recover_have_one_real_external_verification(self):
        from iroha_app_attestation.wallet_enrollment_worker import verify_apple_wallet_attestation_raw
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owners = [open_owner() for _ in range(8)]
            for owner in owners: self.addCleanup(owner.close)
            arguments = self.prepared(owners[0], request)
            entered, release = threading.Event(), threading.Event()
            barrier = threading.Barrier(len(owners))
            def verify_once(*args, **kwargs):
                entered.set()
                if not release.wait(10): raise AssertionError("claim race did not finish")
                return verify_apple_wallet_attestation_raw(*args, **kwargs)
            def invoke(index):
                barrier.wait(timeout=10)
                return owners[index].perform(request, "complete" if index == 0 else "recover", **arguments)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=verify_once) as external, ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(invoke, n) for n in range(8)]
                try:
                    self.assertTrue(entered.wait(10))
                    completed, pending = wait(futures, timeout=2)
                    self.assertEqual(len(completed), 7)
                    self.assertEqual(len(pending), 1)
                    self.assertTrue(all(item.result() is None for item in completed))
                finally:
                    release.set()
                results = [item.result(timeout=10) for item in futures]
                self.assertEqual(external.call_count, 1)
                result = next(item for item in results if item is not None)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT result FROM wallet_e1_attempts").fetchone(), (result,))

    def test_claimed_unknown_restart_never_repeats_external_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            arguments = self.prepared(owner, request)
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=VerificationUnavailable("lost external outcome")) as external:
                with self.assertRaises(VerificationUnavailable): owner.perform(request, "recover", **arguments)
                self.assertEqual(external.call_count, 1)
            owner.close()
            restored = open_owner(); self.addCleanup(restored.close)
            arguments["dispatch_time_ms"] += 1000000
            with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                       side_effect=AssertionError("claimed NULL cannot grant another attempt")):
                restored.prepare(arguments["incarnation"], arguments["preparation"])
                for action in ("recover", "complete"):
                    self.assertIsNone(restored.perform(request, action, **arguments))

    def test_unknown_commit_acknowledgement_preserves_preparation_and_claim(self):
        class LostCommitAcknowledgement:
            def __init__(self, actual): self.actual = actual
            def __getattr__(self, name): return getattr(self.actual, name)
            def execute(self, statement, *args):
                result = self.actual.execute(statement, *args)
                if statement == "COMMIT":
                    raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
                return result
        for phase in ("prepare", "claim"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                open_owner, request, _, _ = self.owner_fixture(Path(temporary))
                owner = open_owner()
                epoch, original = owner.journal(), preparation_original(owner, request)
                arguments = {"incarnation": epoch, "preparation": original,
                    "account_signature": ACCOUNT_SIGNATURE,
                    "dispatch_time_ms": exact_json(request, MAX_REQUEST)["trusted_time_ms"]}
                if phase == "claim": owner.prepare(epoch, original)
                connect = owner.counters._connect
                with patch.object(owner.counters, "_connect", side_effect=lambda: LostCommitAcknowledgement(connect())), \
                     patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                           side_effect=AssertionError("unknown commit must not invoke verifier")):
                    with self.assertRaises(sqlite3.OperationalError):
                        if phase == "prepare": owner.prepare(epoch, original)
                        else: owner.perform(request, "recover", **arguments)
                owner.close()
                restarted = open_owner(); self.addCleanup(restarted.close)
                self.assertEqual(restarted.journal(), epoch)
                restarted.prepare(epoch, original)
                if phase == "prepare":
                    self.assertIsNotNone(restarted.perform(request, "recover", **arguments))
                else:
                    with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                               side_effect=AssertionError("claimed unknown never becomes prepared")):
                        self.assertIsNone(restarted.perform(request, "recover", **arguments))

    def test_missing_prepared_row_or_changed_epoch_never_grants_a_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner()
            original = preparation_original(owner, request)
            epoch = owner.journal()
            arguments = {"incarnation": epoch, "preparation": original,
                "account_signature": ACCOUNT_SIGNATURE,
                "dispatch_time_ms": exact_json(request, MAX_REQUEST)["trusted_time_ms"]}
            for action in ("recover", "complete"):
                with self.assertRaisesRegex(VerificationUnavailable, "prepared original unavailable"):
                    owner.perform(request, action, **arguments)
            owner.prepare(epoch, original)
            owner.close()
            (Path(temporary) / "wallet-e1.sqlite3").unlink()
            with self.assertRaises(FileNotFoundError):
                open_owner()
            # Only an explicit fresh installation creates a new generation. Serving
            # startup must never reconstruct a missing journal or its prepared rows.
            (Path(temporary) / "wallet-e1.generation").unlink()
            directory_fd = os.open(temporary, os.O_RDONLY)
            try:
                E1CounterStore.initialize(Path(temporary).resolve(), directory_fd).close()
            finally:
                os.close(directory_fd)
            replacement = open_owner(); self.addCleanup(replacement.close)
            self.assertNotEqual(replacement.journal(), epoch)
            # A delayed pre-crash prepare cannot reconstruct the old epoch or its row.
            with self.assertRaisesRegex(AttestationRejected, "incarnation"):
                replacement.prepare(epoch, original)
            for action in ("recover", "complete"):
                with self.assertRaisesRegex(AttestationRejected, "incarnation"):
                    replacement.perform(request, action, **arguments)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))

    def test_lost_prepared_or_claimed_row_is_unavailable_without_reverification(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed), tempfile.TemporaryDirectory() as temporary:
                open_owner, request, _, _ = self.owner_fixture(Path(temporary))
                owner = open_owner()
                arguments = self.prepared(owner, request)
                if claimed:
                    with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                               side_effect=VerificationUnavailable("synthetic external interruption")):
                        with self.assertRaises(VerificationUnavailable):
                            owner.perform(request, "complete", **arguments)
                owner.close()
                with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                    self.assertEqual(connection.execute("DELETE FROM wallet_e1_attempts").rowcount, 1)
                    connection.commit()
                restarted = open_owner()
                self.addCleanup(restarted.close)
                message = packet("recover", owner=restarted, original=request)
                output = io.BytesIO()
                with patch("iroha_app_attestation.wallet_enrollment_worker.verify_apple_wallet_attestation_raw",
                           side_effect=AssertionError("missing custody cannot reverify")):
                    serve(restarted, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
                result = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
                self.assertEqual(result["outcome"], "unavailable")
                self.assertIsNone(result["evidence_base64"])
                with closing(restarted.counters._connect()) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM wallet_e1_attempts").fetchone(), (0,))
                    self.assertEqual(connection.execute("SELECT count(*) FROM apple_client_data").fetchone(), (0,))

    def test_legacy_partial_or_missing_incarnation_is_never_backfilled(self):
        for state in ("empty", "legacy", "missing_epoch", "missing_counter"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                open_owner, request, _, _ = self.owner_fixture(Path(temporary))
                path = Path(temporary) / "wallet-e1.sqlite3"
                if state in ("missing_epoch", "missing_counter"):
                    owner = open_owner(); self.prepared(owner, request); owner.close()
                    with closing(sqlite3.connect(path)) as connection:
                        connection.execute("DELETE FROM wallet_e1_store" if state == "missing_epoch"
                                           else "DROP TABLE apple_client_data")
                        connection.commit()
                else:
                    path.write_bytes(b"")
                    if state == "legacy":
                        with closing(sqlite3.connect(path)) as connection:
                            connection.execute("CREATE TABLE wallet_e1_attempts (request_sha256 BLOB PRIMARY KEY, result BLOB)")
                            connection.commit()
                before = path.read_bytes()
                with self.assertRaises((VerificationUnavailable, sqlite3.Error)):
                    open_owner()
                self.assertEqual(path.read_bytes(), before)

    def test_preparation_exact_scope_owner_originals_and_epoch_are_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            arguments = self.prepared(owner, request)
            source = exact_json(arguments["preparation"], MAX_PACKET)
            changes = ({"schema": "foreign"}, {"operation_id": "09" * 32},
                {"account_owner_public_hex": "00" * 32}, {"account_owner_public_hex": "66" * 32},
                {"account_original_base64": "eA=="}, {"account_original_base64": "eA"},
                {"platform": "android"}, {"app_policy_hex": "09" * 32},
                {"enrollment_policy_hex": "09" * 32}, {"config_sha256": "09" * 32},
                {"issued_at_ms": True}, {"expires_at_ms": source["expires_at_ms"] + 1}, {"unknown": None})
            for change in changes:
                with self.subTest(change=change), self.assertRaises(AttestationRejected):
                    owner.prepare(arguments["incarnation"], encode(dict(source, **change)))
            with self.assertRaisesRegex(AttestationRejected, "incarnation"):
                owner.prepare(b"\0" * 32, arguments["preparation"])
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT preparation, request_sha256 FROM wallet_e1_attempts").fetchone(),
                                 (arguments["preparation"], None))

    def test_first_claim_requires_fresh_bounded_time_without_rewriting_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            arguments = self.prepared(owner, request)
            source = exact_json(request, MAX_REQUEST)
            for now in (None, True, source["trusted_time_ms"] - 1, 1 << 64):
                with self.subTest(now=now), self.assertRaises(AttestationRejected) as raised:
                    owner.perform(request, "recover", **dict(arguments, dispatch_time_ms=now))
                self.assertNotIsInstance(raised.exception, EvidenceRefused)
            with closing(sqlite3.connect(Path(temporary) / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT request_sha256 FROM wallet_e1_attempts").fetchone(), (None,))
            result = owner.perform(request, "recover", **arguments)
            self.assertEqual(exact_json(result, MAX_ORIGINAL)["time_ms"], source["trusted_time_ms"])

    def test_claim_binds_exact_account_signature_and_every_request_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            arguments = self.prepared(owner, request)
            result = owner.perform(request, "complete", **arguments)
            for signature in (b"x" * 64, b"s" * 63, bytearray(ACCOUNT_SIGNATURE)):
                with self.subTest(signature=signature), self.assertRaises(AttestationRejected):
                    owner.perform(request, "recover", **dict(arguments, account_signature=signature))
            for changed in (request + b" ", encode(dict(exact_json(request, MAX_REQUEST), trusted_time_ms=arguments["dispatch_time_ms"] + 1))):
                with self.assertRaises(AttestationRejected):
                    owner.perform(changed, "recover", **dict(arguments, dispatch_time_ms=arguments["dispatch_time_ms"] + 2))
            self.assertEqual(owner.perform(request, "recover", **arguments), result)

    def test_private_journal_prepare_and_recovery_responses_bind_whole_packet(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_owner, request, _, _ = self.owner_fixture(Path(temporary))
            owner = open_owner(); self.addCleanup(owner.close)
            for action, outcome in (("journal", "journal"), ("prepare", "prepared"), ("recover", "evidence")):
                message = packet(action, owner=owner, original=request)
                output = io.BytesIO()
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
                response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
                self.assertEqual(set(response), {"schema", "version", "exchange_id", "request_sha256",
                    "journal_incarnation", "config_sha256", "outcome", "evidence_base64", "refusal_code"})
                self.assertIsNone(response["refusal_code"])
                self.assertEqual(response["request_sha256"], hashlib.sha256(message).hexdigest())
                self.assertEqual(response["journal_incarnation"], owner.journal().hex())
                self.assertEqual(response["config_sha256"], owner.config_digest.hex())
                self.assertEqual(response["outcome"], outcome)
            # Explicit nulls are part of the contract; a journal/prepare request cannot carry a dispatch.
            for action, change in (("journal", {"journal_incarnation": owner.journal().hex()}),
                                   ("prepare", {"account_signature_base64": base64.b64encode(ACCOUNT_SIGNATURE).decode()}),
                                   ("prepare", {"dispatch_time_ms": 1})):
                message = encode(dict(exact_json(packet(action, owner=owner, original=request), MAX_PACKET), **change))
                output = io.BytesIO()
                serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
                response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
                self.assertEqual(response["outcome"], "rejected")
                self.assertIsNone(response["evidence_base64"])


class AndroidIntegratedWorkerTests(unittest.TestCase):
    """Real signed synthetic KeyMint chains through the private worker; scripted HTTPS originals.

    The synthetic root is a throwaway test key that the test policy pins as a GoogleRsa-family
    root; no genuine Google, Huawei or device claim follows.
    """
    @classmethod
    def setUpClass(cls):
        executable = shutil.which("openssl")
        if executable is None:
            raise unittest.SkipTest("OpenSSL3 unavailable")
        cls.openssl = Path(executable).resolve()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.pki = SyntheticPki(Path(cls.temporary.name).resolve(), cls.openssl)
        remote_hierarchy(cls.pki, "ec256")
        cls.pki.key("leaf")
        cls.point = cls.pki.point("leaf")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.enterContext(patch("iroha_app_attestation.wallet_enrollment_worker._sleep_inclusive_ns",
                                side_effect=time.monotonic_ns))
        self.enterContext(patch("iroha_app_attestation.wallet_enrollment_worker._realtime_ns",
                                side_effect=lambda: time.time_ns() + 61_000_000_000))

    def fixture(self, directory, level=2, payment=None):
        directory = directory.resolve(strict=True); directory.chmod(0o700)
        root = self.pki.der("root")
        policy = fixture_policy(root, False)
        selected = policy_scope(policy, self.point if payment is None else payment)
        description = key_description(selected.challenge_digest(), level=level,
                                      os_patch_level=202608, vendor_patch_level=20260805)
        chain = [self.pki.leaf("leaf", "attestation", description, new_key=False),
                 self.pki.der("attestation"), self.pki.der("intermediate"), root]
        now = int(time.time() * 1000) + 60000
        config = encode({"schema": CONFIG_SCHEMA, "version": 1, "platform": "android",
            "app_policy_hex": policy.app.policy_digest().hex(), "enrollment_policy_hex": policy.enrollment.policy_digest().hex(),
            "openssl_path": str(self.openssl), "openssl_sha256": hashlib.sha256(self.openssl.read_bytes()).hexdigest(),
            "store_directory": str(directory), "policy": {"scheme_id_hex": policy.enrollment.scheme_id.hex(),
                "asset_digest_hex": policy.enrollment.asset_digest.hex(), "regulatory_policy": {
                    "permitted_controls": 0, "blacklist_max_age_ms": 0, "time_anchor_max_response_ms": 0},
                "challenge_lifetime_ms": 120000, "attestation_lease_lifetime_ms": 0,
                "package_name": PACKAGE, "minimum_package_version": 7, "app_signer_sha256": [SIGNER.hex()],
                "roots": [{"family": "google_rsa", "spki_sha256": spki_sha256(root).hex(),
                           "revocation_source": "google_attestation_status"}],
                "patch_floor_yyyymm": 202608}})
        request = encode({"challenge_transcript_base64": base64.b64encode(selected.challenge_transcript).decode(),
            "payment_key_base64": base64.b64encode(selected.payment_key_sec1).decode(), "issued_at_ms": now - 1,
            "expires_at_ms": now - 1 + 120000, "trusted_time_ms": now, "platform": "android", "evidence": {
                "chain_base64": [base64.b64encode(x).decode() for x in chain]}})
        return config, request, chain

    def actual_owner(self, config, directory, stack, *, initialize=True,
                     denylist=b'{"version":1,"sequence":1,"entries":[]}', candidate=None):
        directory = directory.resolve()
        descriptors = [os.open(x, os.O_RDONLY) for x in (directory, self.openssl)]
        for fd in descriptors: stack.callback(os.close, fd)
        if initialize:
            E1CounterStore.initialize(directory, descriptors[0]).close()
        if denylist is not None:
            OperatorDenylistCustody(directory, descriptors[0]).initialize(denylist)
        arguments = {}
        if candidate is not None:
            path = directory.parent / (directory.name + "-candidate.json")
            path.write_bytes(candidate); path.chmod(0o644)
            arguments["denylist_fd"] = os.open(path, os.O_RDONLY)
            stack.callback(os.close, arguments["denylist_fd"])
        owner = VerifierOwner(config, directory_fd=descriptors[0], crypto_fd=descriptors[1], **arguments)
        stack.callback(owner.close)
        return owner

    def transport(self, stack, entries=(), failures=0):
        calls = []
        class Response:
            status = 200
            headers = {"Content-Type": "application/json", "Content-Encoding": "identity",
                       "Cache-Control": "public, max-age=3600"}
            def __init__(self, body): self.body = body
            def geturl(self): return revocation.GOOGLE_STATUS_URL
            def read(self, bound): return self.body[:bound]
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Transport:
            def open(inner, request, timeout):
                calls.append(request.full_url)
                if len(calls) <= failures:
                    raise urllib.error.URLError("synthetic outage")
                return Response(encode({"entries": {"%x" % serial: {"status": "REVOKED"} for serial in entries}}))
        stack.enter_context(patch("urllib.request.build_opener", return_value=Transport()))
        return calls

    def test_tee_and_strongbox_enrollment_records_chain_only_evidence(self):
        for level in (1, 2):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                directory = Path(temporary).resolve()
                config, request, chain = self.fixture(directory, level)
                owner = self.actual_owner(config, directory, stack)
                calls = self.transport(stack)
                result = dispatch(owner, request, "complete")
                projection = exact_json(result, MAX_ORIGINAL)
                self.assertEqual(projection["kind_tag"], level)
                self.assertEqual(projection["facts"], 0b10000111101 | (2 if level == 2 else 0))
                self.assertFalse(projection["facts"] & (1 << 9))
                self.assertEqual([base64.b64decode(x) for x in projection["original_items_base64"]], chain)
                self.assertEqual(projection["time_ms"], exact_json(request, MAX_REQUEST)["trusted_time_ms"])
                self.assertEqual((projection["app_attest_key_id"], projection["app_attest_counter"]), (None, None))
                self.assertEqual(calls, [revocation.GOOGLE_STATUS_URL])
                self.assertEqual(dispatch(owner, request, "recover"), result)
                self.assertEqual(len(calls), 1)

    def test_revoked_chain_is_refused_with_a_retained_code(self):
        attestation_serial = revocation.certificate_serial(self.pki.der("attestation"))
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, _ = self.fixture(directory)
            owner = self.actual_owner(config, directory, stack)
            calls = self.transport(stack, entries=(attestation_serial,))
            owner.prepare(owner.counters.incarnation, preparation_original(owner, request))
            message = packet("complete", owner=owner, original=request)
            output = io.BytesIO()
            serve(owner, io.BytesIO(len(message).to_bytes(4, "little") + message), output)
            response = exact_json(read_packet(io.BytesIO(output.getvalue())), MAX_PACKET)
            self.assertEqual((response["outcome"], response["refusal_code"], response["evidence_base64"]),
                             ("refused", 6, None))
            for action in ("recover", "inspect", "complete"):
                with self.subTest(action=action), self.assertRaises(EvidenceRefused) as raised:
                    dispatch(owner, request, action)
                self.assertEqual(raised.exception.code, Code.ATTESTATION_REVOKED)
            self.assertEqual(len(calls), 1)
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, chain = self.fixture(directory)
            listed = encode({"version": 1, "sequence": 1,
                             "entries": [{"spki_sha256": spki_sha256(chain[0]).hex()}]})
            owner = self.actual_owner(config, directory, stack, denylist=listed)
            self.transport(stack)
            with self.assertRaises(EvidenceRefused) as raised:
                dispatch(owner, request, "complete")
            self.assertEqual(raised.exception.code, Code.ATTESTATION_REVOKED)

    def test_revocation_outage_before_any_effect_resumes_the_same_claim_while_live(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, _ = self.fixture(directory)
            owner = self.actual_owner(config, directory, stack)
            calls = self.transport(stack, failures=1)
            source = exact_json(request, MAX_REQUEST)
            with self.assertRaises(VerificationUnavailable):
                dispatch(owner, request, "complete")
            with closing(sqlite3.connect(directory / "wallet-e1.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT first_dispatch, outcome FROM wallet_e1_attempts").fetchone(),
                                 (source["trusted_time_ms"].to_bytes(8, "little"), "unavailable"))
            # Inspect never resumes a claim.
            self.assertIsNone(owner.perform(request, "inspect", **self.arguments(owner, request)))
            arguments = self.arguments(owner, request, delay=5)
            result = owner.perform(request, "recover", **arguments)
            projection = exact_json(result, MAX_ORIGINAL)
            # The first dispatch stays the recorded verification time.
            self.assertEqual(projection["time_ms"], source["trusted_time_ms"])
            self.assertEqual(len(calls), 2)
            self.assertEqual(owner.perform(request, "inspect", **arguments), result)

    def test_outage_after_the_challenge_lifetime_stays_unknown_and_never_reverifies(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, _ = self.fixture(directory)
            owner = self.actual_owner(config, directory, stack)
            calls = self.transport(stack, failures=1)
            with self.assertRaises(VerificationUnavailable):
                dispatch(owner, request, "complete")
            arguments = self.arguments(owner, request, delay=200_000)
            for action in ("recover", "complete", "inspect"):
                self.assertIsNone(owner.perform(request, action, **arguments))
            self.assertEqual(len(calls), 1)

    def test_missing_denylist_custody_is_unavailable_never_admission(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, _ = self.fixture(directory)
            owner = self.actual_owner(config, directory, stack, denylist=None)
            calls = self.transport(stack)
            with self.assertRaises(VerificationUnavailable):
                dispatch(owner, request, "complete")
            self.assertEqual(calls, [])
            # The explicit installation action restores admission of the same live claim.
            OperatorDenylistCustody(directory, owner.directory_fd).initialize(
                b'{"version":1,"sequence":1,"entries":[]}')
            self.assertIsNotNone(owner.perform(request, "recover", **self.arguments(owner, request, delay=1)))

    def test_inherited_denylist_candidate_follows_rollback_rules(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, chain = self.fixture(directory)
            leaf_spki = spki_sha256(chain[0]).hex()
            current = b'{"version":1,"sequence":2,"entries":[]}'
            newer = encode({"version": 1, "sequence": 3, "entries": [{"spki_sha256": leaf_spki}]})
            owner = self.actual_owner(config, directory, stack, denylist=current, candidate=newer)
            self.assertEqual(owner.denylist_offer, "accepted")
            self.transport(stack)
            with self.assertRaises(EvidenceRefused) as raised:
                dispatch(owner, request, "complete")
            self.assertEqual(raised.exception.code, Code.ATTESTATION_REVOKED)
            custody = OperatorDenylistCustody(directory, owner.directory_fd)
            self.assertEqual(custody.active().sequence, 3)
            owner.close()
            for stale, outcome in ((current, "rejected"), (newer, "unchanged"), (b"not json", "rejected")):
                with self.subTest(outcome=outcome):
                    replacement = self.actual_owner(config, directory, stack, initialize=False,
                                                    denylist=None, candidate=stale)
                    self.assertEqual(replacement.denylist_offer, outcome)
                    self.assertEqual(custody.active().sequence, 3)
            absent = self.actual_owner(config, directory, stack, initialize=False, denylist=None)
            self.assertIsNone(absent.denylist_offer)

    def test_android_configuration_cannot_select_retired_or_unqualified_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            config, _, _ = self.fixture(directory)
            source = exact_json(config, MAX_PACKET)
            for change in (lambda v: v["policy"].update({"security_levels": [1, 2]}),
                           lambda v: v["policy"].update({"google_policy_base64": "e30="}),
                           lambda v: v["policy"].update({"root_base64": "e30="}),
                           lambda v: v["policy"].update({"minimum_package_version": True}),
                           lambda v: v["policy"].update({"app_signer_sha256": []}),
                           lambda v: v["policy"]["roots"][0].update({"family": "vendor", "adapter_id": "huawei",
                                                                     "revocation_source": "operator_denylist"}),
                           lambda v: v["policy"]["roots"][0].update({"family": "vendor", "adapter_id": "acme",
                                                                     "revocation_source": "operator_denylist"})):
                value = json.loads(json.dumps(source)); change(value)
                with self.assertRaises(AttestationRejected): configured_policy(value["policy"], "android")
                with ExitStack() as stack, self.assertRaises(AttestationRejected):
                    self.actual_owner(encode(value), directory, stack, initialize=False, denylist=None)
            self.assertFalse((directory / "wallet-e1.sqlite3").exists())

    def test_attested_key_of_another_payment_key_is_evidence_invalid(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            directory = Path(temporary).resolve()
            config, request, _ = self.fixture(directory, payment=GENERATOR)
            owner = self.actual_owner(config, directory, stack)
            self.transport(stack)
            with self.assertRaises(EvidenceRefused) as raised:
                dispatch(owner, request, "complete")
            self.assertEqual(raised.exception.code, Code.EVIDENCE_INVALID)

    def arguments(self, owner, request, delay=0):
        return {"incarnation": owner.counters.incarnation, "preparation": preparation_original(owner, request),
                "account_signature": ACCOUNT_SIGNATURE,
                "dispatch_time_ms": exact_json(request, MAX_REQUEST)["trusted_time_ms"] + delay}


class UnsignedArchiveTests(unittest.TestCase):
    def builder(self):
        path = Path(__file__).resolve().parents[1] / "tools" / "build_wallet_e1_verifier_zipapp.py"
        spec = importlib.util.spec_from_file_location("wallet_e1_unsigned_archive_builder", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_current_archive_is_deterministic_explicit_and_never_admits_runtime(self):
        builder = self.builder()
        package = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            one, two = Path(temporary).resolve() / "one.pyz", Path(temporary).resolve() / "two.pyz"
            first, second = builder.build(package, one), builder.build(package, two)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            self.assertEqual(first, second)
            self.assertIs(first["signed_runtime_admission"], False)
            with zipfile.ZipFile(one) as archive:
                self.assertEqual(set(archive.namelist()), {"__main__.py"} |
                                 {"iroha_app_attestation/" + name for name in builder.SOURCES})
                self.assertNotIn("iroha_app_attestation/ordinary_worker.py", archive.namelist())
                for retired in ("play_integrity.py", "google_oauth.py", "openssl_private_rsa.py",
                                "retail_auth_worker.py"):
                    self.assertNotIn("iroha_app_attestation/" + retired, archive.namelist())
                self.assertNotIn("iroha_app_attestation/kagemusha_native_signer.py", archive.namelist())
            with self.assertRaises(FileExistsError):
                builder.build(package, one)

    def test_archive_builder_refuses_source_alias_without_creating_output(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary).resolve() / "package"
            source = package / "src" / "iroha_app_attestation"
            source.mkdir(parents=True)
            for name in builder.SOURCES:
                (source / name).write_bytes(b"# bounded original\n")
            (source / "wallet_enrollment_worker.py").unlink()
            (source / "wallet_enrollment_worker.py").symlink_to(source / "__init__.py")
            output = Path(temporary) / "refused.pyz"
            with self.assertRaises(ValueError):
                builder.build(package, output)
            self.assertFalse(output.exists())

    def test_source_change_during_archive_write_is_refused_with_all_inputs_held(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            package = directory / "package"
            source = package / "src" / "iroha_app_attestation"; source.mkdir(parents=True)
            for name in builder.SOURCES: (source / name).write_bytes(b"# inert custody fixture\n")
            original = zipfile.ZipFile.writestr
            changed = False
            def mutate(archive, *args, **arguments):
                nonlocal changed
                if not changed:
                    (source / "wallet_policy.py").write_bytes(b"# changed during archive\n"); changed = True
                return original(archive, *args, **arguments)
            with patch.object(zipfile.ZipFile, "writestr", mutate), self.assertRaisesRegex(ValueError, "source changed"):
                builder.build(package, directory / "refused.pyz")

    def test_isolated_archive_imports_actual_current_policy_and_worker_without_source_tree(self):
        builder = self.builder()
        package = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary).resolve() / "current.pyz"
            builder.build(package, archive)
            code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                    "from iroha_app_attestation.wallet_enrollment_worker import CONFIG_SCHEMA, PREPARATION_SCHEMA, MAX_PREPARATION, VerifierOwner, configured_policy; "
                    "from iroha_app_attestation.wallet_policy import ConfiguredWalletEnrollmentPolicyV1; "
                    "assert CONFIG_SCHEMA == 'iroha.kagemusha.wallet-e1-verifier-config.v1'; "
                    "assert PREPARATION_SCHEMA == 'iroha.kagemusha.wallet-e1-worker-preparation.v1'; "
                    "assert MAX_PREPARATION == 16384; "
                    "assert callable(VerifierOwner.prepare) and callable(VerifierOwner.journal); "
                    "assert callable(configured_policy)")
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(archive)],
                                    cwd=temporary, env={}, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()


class DispatchClockTests(unittest.TestCase):
    """Simulated OS samples exercise timing semantics, never production admission."""
    def test_fresh_wall_and_sleep_inclusive_elapsed_both_bound_the_window(self):
        wall, elapsed = [100_000_000], [3_000_000_000]
        with patch("iroha_app_attestation.wallet_enrollment_worker._realtime_ns", side_effect=lambda: wall[0]), \
                patch("iroha_app_attestation.wallet_enrollment_worker._sleep_inclusive_ns", side_effect=lambda: elapsed[0]):
            clock = DispatchClock(90, 90, 200)
            self.assertEqual(clock.sample().endpoints(), (100, 100))
            wall[0] += 20_000_001
            self.assertEqual(clock.sample().endpoints(), (120, 121))
            elapsed[0] += 100_000_000
            with self.assertRaisesRegex(AttestationRejected, "expired"):
                clock.sample()

    def test_wall_or_elapsed_regression_is_unavailable(self):
        for changed in ("wall", "elapsed"):
            wall, elapsed = [100_000_000], [3_000_000_000]
            with patch("iroha_app_attestation.wallet_enrollment_worker._realtime_ns", side_effect=lambda: wall[0]), \
                    patch("iroha_app_attestation.wallet_enrollment_worker._sleep_inclusive_ns", side_effect=lambda: elapsed[0]):
                clock = DispatchClock(100, 90, 200)
                (wall if changed == "wall" else elapsed)[0] -= 1
                with self.assertRaises(VerificationUnavailable):
                    clock.sample()

    def test_core_dispatch_ahead_of_actual_worker_clock_is_unavailable(self):
        with patch("iroha_app_attestation.wallet_enrollment_worker._realtime_ns", return_value=99_999_999), \
                patch("iroha_app_attestation.wallet_enrollment_worker._sleep_inclusive_ns", return_value=3_000_000_000):
            with self.assertRaises(VerificationUnavailable):
                DispatchClock(100, 90, 200)

    def test_missing_sleep_inclusive_os_clock_has_no_monotonic_fallback(self):
        from iroha_app_attestation import wallet_enrollment_worker as worker
        with patch.object(worker.sys, "platform", "darwin"):
            with self.assertRaises(VerificationUnavailable):
                worker._sleep_inclusive_ns()
