"""Google status list, operator denylist custody and per-family revocation dispatch."""

import dataclasses
import http.client
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from iroha_app_attestation.attestation import (
    GOOGLE_ADAPTER_PROFILE, HUAWEI_ADAPTER_PROFILE, AndroidChainMember, AndroidTrustAnchor,
    AttestationRejected, EnrollmentRefusal, EvidenceRefused, VerificationUnavailable,
)
from iroha_app_attestation.revocation import (
    DENYLIST_CUSTODY, GOOGLE_STATUS_URL, MAX_DENYLIST_ENTRIES, AndroidRevocation,
    DenylistUpdateRejected, GoogleAttestationStatus, GoogleStatusList, OperatorDenylistCustody,
    RevocationUnavailable, cache_freshness_seconds, certificate_serial,
    fetch_google_revocation_status, parse_google_revocation_status, parse_operator_denylist,
)


def der(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes([tag, len(value)]) + value


def certificate(serial: int) -> bytes:
    raw = serial.to_bytes(max(1, (serial.bit_length() + 7) // 8), "big")
    if raw[0] & 128:
        raw = b"\0" + raw
    tbs = der(0x30, der(2, raw) + der(2, b"\x01") * 5)
    return der(0x30, tbs + der(2, b"\x01") * 2)


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, url: str = GOOGLE_STATUS_URL,
                 content_type: str = "application/json", cache_control=None, age=None) -> None:
        self.body = body
        self.status = status
        self.url = url
        self.headers = {"Content-Type": content_type}
        if cache_control is not None:
            self.headers["Cache-Control"] = cache_control
        if age is not None:
            self.headers["Age"] = age

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, length):
        return self.body[:length]


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def open(self, request, timeout):
        assert request.full_url == GOOGLE_STATUS_URL and timeout == 5
        return self.response


def denylist(sequence: int, *entries) -> bytes:
    return json.dumps({"version": 1, "sequence": sequence,
                       "entries": [dict([entry]) for entry in entries]},
                      separators=(",", ":")).encode()


def anchor(family="google_rsa"):
    if family == "vendor":
        profile = dataclasses.replace(HUAWEI_ADAPTER_PROFILE, qualified=True)
        return AndroidTrustAnchor("vendor", b"\x11" * 32, "operator_denylist", profile)
    return AndroidTrustAnchor(family, b"\x11" * 32, "google_attestation_status",
                              GOOGLE_ADAPTER_PROFILE)


MEMBERS = (AndroidChainMember(0x2a, b"\xaa" * 32), AndroidChainMember(0x3b, b"\xbb" * 32),
           AndroidChainMember(0x4c, b"\xcc" * 32))


class GoogleStatusTests(unittest.TestCase):
    def test_strict_status_and_expired_entry_remains_revoked(self) -> None:
        good = {"entries": {"2a": {"status": "REVOKED", "expires": "2020-01-01"},
                            "3b": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"}}}
        self.assertEqual(parse_google_revocation_status(json.dumps(good).encode()),
                         frozenset({0x2a, 0x3b}))
        for bad in (
            b'{"entries":{"2a":{"status":"VALID"}}}',
            b'{"entries":{"2a":{"status":"REVOKED","status":"SUSPENDED"}}}',
            b'{"entries":{"02a":{"status":"REVOKED"}}}',
            b'{"entries":{"2A":{"status":"REVOKED"}}}',
            b'{"entries":{"2a":{"status":"REVOKED","reason":"unknown"}}}',
            b'{"entries":{"2a":{"status":"REVOKED","expires":"2020-02-30"}}}',
            b'{"entries":{},"extra":true}',
            b'{"entries":{}} trailing',
        ):
            with self.subTest(bad=bad), self.assertRaises(AttestationRejected) as raised:
                parse_google_revocation_status(bad)
            # Parsing a supplied body judges that body; only fetching classifies.
            self.assertNotIsInstance(raised.exception, RevocationUnavailable)

    def test_certificate_serial(self) -> None:
        self.assertEqual([certificate_serial(certificate(n)) for n in (0x2a, 0x3b)], [0x2a, 0x3b])
        with self.assertRaises(AttestationRejected):
            certificate_serial(certificate(0))

    def test_cache_control_grants_reuse_only_through_max_age(self) -> None:
        for header, age, expected in (
            ("max-age=3600", None, 3600), ("public, max-age=600", "100", 500),
            ("max-age=600", "700", 0), ("max-age=600, no-cache", None, 0),
            ("no-store", None, 0), (None, None, 0), ("max-age=x", None, 0),
            ("max-age=1, max-age=2", None, 0), ("max-age=999999999", None, 86400),
            ("max-age=60", "x", 0), ("s-maxage=60", None, 0),
        ):
            with self.subTest(header=header, age=age):
                self.assertEqual(cache_freshness_seconds(header, age), expected)

    def test_fetch_rejects_wrong_endpoint_type_and_oversize(self) -> None:
        for response in (
            FakeResponse(b'{"entries":{}}', status=302),
            FakeResponse(b'{"entries":{}}', url="https://other.example/status"),
            FakeResponse(b'{"entries":{}}', content_type="text/plain"),
            FakeResponse(b"x" * (2 * 1024 * 1024 + 1)),
            FakeResponse(b'{"entries":{"2a":{"status":"VALID"}}}'),
            FakeResponse(b'{"entries":{}} trailing'),
        ):
            # No current well-formed list: retryable unavailability, which
            # still fails closed as an AttestationRejected.
            with self.subTest(response=response), patch(
                "iroha_app_attestation.revocation.urllib.request.build_opener", return_value=FakeOpener(response)
            ), self.assertRaises(RevocationUnavailable):
                fetch_google_revocation_status()
        with patch("iroha_app_attestation.revocation.urllib.request.build_opener", return_value=FakeOpener(
            FakeResponse(b'{"entries":{"2a":{"status":"REVOKED"}}}', cache_control="max-age=60")
        )):
            self.assertEqual(fetch_google_revocation_status(), GoogleStatusList(frozenset({0x2a}), 60))
        with patch("iroha_app_attestation.revocation.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = urllib.error.URLError("offline")
            with self.assertRaisesRegex(RevocationUnavailable, "unavailable"):
                fetch_google_revocation_status()

    def test_http_protocol_failures_outside_oserror_are_unavailable(self) -> None:
        self.assertFalse(issubclass(http.client.HTTPException, OSError))

        class TruncatedResponse(FakeResponse):
            def read(self, length):
                raise http.client.IncompleteRead(b"")

        with patch("iroha_app_attestation.revocation.urllib.request.build_opener",
                   return_value=FakeOpener(TruncatedResponse(b'{"entries":{}}'))), \
                self.assertRaisesRegex(RevocationUnavailable, "unavailable"):
            fetch_google_revocation_status()
        for failure in (http.client.BadStatusLine("x"), http.client.LineTooLong("header line")):
            with self.subTest(failure=type(failure).__name__), patch(
                "iroha_app_attestation.revocation.urllib.request.build_opener"
            ) as build:
                build.return_value.open.side_effect = failure
                with self.assertRaisesRegex(RevocationUnavailable, "unavailable"):
                    fetch_google_revocation_status()

    def test_status_reuse_follows_freshness_on_a_suspend_inclusive_clock(self) -> None:
        fetched, clock = [], [1_000]

        def fetch():
            fetched.append(clock[0])
            return GoogleStatusList(frozenset({len(fetched)}), 10)
        status = GoogleAttestationStatus(fetch, lambda: clock[0])
        self.assertEqual(status.listed_serials(), {1})
        clock[0] += 9_999_999_999
        self.assertEqual(status.listed_serials(), {1})
        clock[0] += 1
        self.assertEqual(status.listed_serials(), {2})
        # No freshness lifetime, or no suspend-inclusive clock: fetch for every check.
        uncached = GoogleAttestationStatus(lambda: GoogleStatusList(frozenset(), 0), lambda: 5)
        none_clock = GoogleAttestationStatus(fetch, lambda: None)
        before = len(fetched)
        uncached.listed_serials()
        none_clock.listed_serials()
        none_clock.listed_serials()
        self.assertEqual(len(fetched), before + 2)

        def failing():
            raise RevocationUnavailable("offline")
        with self.assertRaises(RevocationUnavailable):
            GoogleAttestationStatus(failing, lambda: 1).listed_serials()


class OperatorDenylistTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)
        self.fd = os.open(self.directory, os.O_RDONLY)
        self.addCleanup(os.close, self.fd)
        self.custody = OperatorDenylistCustody(self.directory, self.fd)

    def test_exact_format_and_whole_original_rejection(self) -> None:
        parsed = parse_operator_denylist(denylist(3, ("serial", "2a"), ("spki_sha256", "ab" * 32)))
        self.assertEqual((parsed.sequence, parsed.serials, parsed.spki_sha256),
                         (3, frozenset({0x2a}), frozenset({b"\xab" * 32})))
        self.assertEqual(parse_operator_denylist(b'{"version":1,"sequence":1,"entries":[]}').serials,
                         frozenset())
        for bad in (
            b'{"version":1,"sequence":1}',
            b'{"version":1,"sequence":1,"entries":[],"extra":0}',
            b'{"version":2,"sequence":1,"entries":[]}',
            b'{"version":true,"sequence":1,"entries":[]}',
            b'{"version":1,"sequence":0,"entries":[]}',
            b'{"version":1,"sequence":9007199254740992,"entries":[]}',
            b'{"version":1,"sequence":1.0,"entries":[]}',
            b'{"version":1,"sequence":1,"sequence":2,"entries":[]}',
            denylist(1, ("serial", "02a")), denylist(1, ("serial", "2A")),
            denylist(1, ("serial", "0")), denylist(1, ("spki_sha256", "AB" * 32)),
            denylist(1, ("spki_sha256", "ab" * 31)), denylist(1, ("issuer", "2a")),
            denylist(1, ("serial", "2a"), ("serial", "2a")),
            b'{"version":1,"sequence":1,"entries":[{"serial":"2a","spki_sha256":"' + b"ab" * 32 + b'"}]}',
            b'{"version":1,"sequence":1,"entries":[{}]}',
            b'{"version":1,"sequence":1,"entries":[{"serial":42}]}',
            b'{"version":1,"sequence":1,"entries":[]} trailing', b"\xef\xbb\xbf{}", b"",
        ):
            with self.subTest(bad=bad[:60]), self.assertRaises(AttestationRejected):
                parse_operator_denylist(bad)
        entries = ",".join('{"serial":"%x"}' % (n + 1) for n in range(MAX_DENYLIST_ENTRIES + 1))
        with self.assertRaises(AttestationRejected):
            parse_operator_denylist(('{"version":1,"sequence":1,"entries":[%s]}' % entries).encode())

    def test_missing_unreadable_malformed_or_inconsistent_custody_is_unavailable(self) -> None:
        with self.assertRaises(RevocationUnavailable):
            self.custody.active()
        # Serving never creates custody from a candidate: rollback protection needs it.
        with self.assertRaises(RevocationUnavailable):
            self.custody.offer(denylist(1))
        self.custody.initialize(denylist(1))
        path = self.directory / DENYLIST_CUSTODY
        original = path.read_bytes()
        self.assertEqual(self.custody.active().sequence, 1)
        with self.assertRaises(FileExistsError):
            self.custody.initialize(denylist(2))
        second = self.directory / "second-name"
        damages = (
            lambda: path.write_bytes(b""),
            lambda: path.write_bytes(original[:-1]),
            lambda: path.write_bytes(original.replace(b'"sequence":1', b'"sequence":2')),
            lambda: path.write_bytes(original.replace(b'"sha256":"', b'"sha256":"00', 1)),
            lambda: path.chmod(0o640),
            lambda: path.unlink(),
            lambda: os.link(path, second),
        )
        for index, damage in enumerate(damages):
            with self.subTest(damage=index):
                damage()
                with self.assertRaises(RevocationUnavailable):
                    self.custody.active()
                with self.assertRaises(RevocationUnavailable):
                    self.custody.offer(denylist(5))
                if second.exists():
                    second.unlink()
                path.write_bytes(original)
                path.chmod(0o600)
                self.assertEqual(self.custody.active().sequence, 1)

    def test_rollback_protected_updates_keep_the_active_list_in_force(self) -> None:
        self.custody.initialize(denylist(2, ("serial", "3b")))
        self.assertEqual(self.custody.offer(denylist(2, ("serial", "3b"))), "unchanged")
        for stale in (denylist(1), denylist(2), denylist(2, ("serial", "3c")), b"not json"):
            with self.subTest(stale=stale), self.assertRaises(DenylistUpdateRejected):
                self.custody.offer(stale)
            active = self.custody.active()
            self.assertEqual((active.sequence, active.serials), (2, frozenset({0x3b})))
        self.assertEqual(self.custody.offer(denylist(3, ("spki_sha256", "cc" * 32))), "accepted")
        active = self.custody.active()
        self.assertEqual((active.sequence, active.serials, active.spki_sha256),
                         (3, frozenset(), frozenset({b"\xcc" * 32})))
        with self.assertRaises(DenylistUpdateRejected):
            self.custody.offer(denylist(2, ("serial", "3b")))
        self.assertFalse((self.directory / (DENYLIST_CUSTODY + ".pending")).exists())
        self.assertEqual((self.directory / DENYLIST_CUSTODY).stat().st_mode & 0o777, 0o600)

    def test_dispatch_checks_named_source_and_denylist_and_fails_closed(self) -> None:
        self.custody.initialize(denylist(1))
        google = GoogleAttestationStatus(lambda: GoogleStatusList(frozenset(), 0), lambda: None)
        revocation = AndroidRevocation(google, self.custody)
        revocation(MEMBERS, anchor())
        revocation(MEMBERS, anchor("google_ca1"))
        cases = (
            (GoogleStatusList(frozenset({0x3b}), 0), denylist(2), "google_rsa", True),
            (GoogleStatusList(frozenset({0x2a}), 0), denylist(3), "google_ca1", True),
            # Vendor roots never consult Google's list.
            (GoogleStatusList(frozenset({0x3b}), 0), denylist(4), "vendor", False),
            (GoogleStatusList(frozenset(), 0), denylist(5, ("serial", "4c")), "google_rsa", True),
            (GoogleStatusList(frozenset(), 0), denylist(6, ("serial", "4c")), "vendor", True),
            # A denylisted serial matches every chain certificate except the phone-chosen leaf.
            (GoogleStatusList(frozenset(), 0), denylist(7, ("serial", "2a")), "vendor", False),
            (GoogleStatusList(frozenset(), 0), denylist(8, ("spki_sha256", "aa" * 32)), "vendor", True),
            (GoogleStatusList(frozenset(), 0), denylist(9, ("spki_sha256", "cc" * 32)), "google_rsa", True),
        )
        for status, original, family, refused in cases:
            with self.subTest(family=family, original=original):
                self.custody.offer(original)
                checker = AndroidRevocation(GoogleAttestationStatus(lambda status=status: status,
                                                                    lambda: None), self.custody)
                if refused:
                    with self.assertRaises(EvidenceRefused) as raised:
                        checker(MEMBERS, anchor(family))
                    self.assertEqual(raised.exception.code, EnrollmentRefusal.ATTESTATION_REVOKED)
                else:
                    checker(MEMBERS, anchor(family))

        self.custody.offer(denylist(10))

        def offline():
            raise RevocationUnavailable("offline")
        with self.assertRaises(VerificationUnavailable):
            AndroidRevocation(GoogleAttestationStatus(offline, lambda: None), self.custody)(
                MEMBERS, anchor())
        AndroidRevocation(GoogleAttestationStatus(offline, lambda: None), self.custody)(
            MEMBERS, anchor("vendor"))
        (self.directory / DENYLIST_CUSTODY).unlink()
        for family in ("google_rsa", "vendor"):
            with self.subTest(missing=family), self.assertRaises(RevocationUnavailable):
                revocation(MEMBERS, anchor(family))


if __name__ == "__main__":
    unittest.main()
