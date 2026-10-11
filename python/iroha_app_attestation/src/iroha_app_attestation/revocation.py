"""Android E1 revocation: per-family sources plus the operator denylist, failing closed.

Every Android root entry names one revocation source (enrollment policy, Android admission
step 3). GoogleRsa and GoogleCa1 roots name Google's attestation status list; Vendor roots
name the operator denylist only. The operator denylist is checked for every root whatever its
named source. A listed certificate refuses the evidence with code 6 (AttestationRevoked).
A source that cannot be read is ``RevocationUnavailable``: never a refusal or an admission.

Google's list is reused only within the freshness lifetime its HTTP ``Cache-Control`` states,
measured on a suspend-inclusive clock; otherwise it is fetched for the check.

The denylist is one operator-owned original held outside the policy originals. Its active
custody is one owner-only file in the private E1 store directory holding the accepted
original with its sequence and SHA-256. Updates are rollback-protected: a candidate is
accepted only with a greater sequence, or the same sequence and byte-identical content. A
stale or altered candidate is rejected and the intact active list keeps deciding. Missing,
unreadable, malformed or inconsistent active custody makes verification unavailable.
Serving never creates custody; initialization is an explicit operator installation action.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

from .attestation import (
    AndroidChainMember, AndroidTrustAnchor, AttestationRejected, EnrollmentRefusal,
    EvidenceRefused, VerificationUnavailable, children, der_one, positive_integer, require,
)


GOOGLE_STATUS_URL = "https://android.googleapis.com/attestation/status"
MAX_STATUS_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_CHAIN_CERTIFICATES = 8
# Never reuse a status list longer than one day, whatever Cache-Control states.
MAX_STATUS_REUSE_S = 24 * 60 * 60
_SERIAL = re.compile(r"[a-f1-9][a-f0-9]*\Z")
_SPKI = re.compile(r"[0-9a-f]{64}\Z")
_REASONS = frozenset({
    "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "SUPERSEDED", "SOFTWARE_FLAW",
})

DENYLIST_VERSION = 1
MAX_DENYLIST_ENTRIES = 65_536
MAX_DENYLIST_BYTES = 8 * 1024 * 1024
MAX_DENYLIST_SEQUENCE = (1 << 53) - 1
DENYLIST_CUSTODY_SCHEMA = "iroha.kagemusha.wallet-e1-denylist-custody.v1"
DENYLIST_CUSTODY = "wallet-e1-denylist.custody"
_DENYLIST_PENDING = DENYLIST_CUSTODY + ".pending"
MAX_DENYLIST_CUSTODY_BYTES = 12 * 1024 * 1024


class RevocationUnavailable(VerificationUnavailable):
    """A current revocation source or the active operator denylist could not be read."""


class DenylistUpdateRejected(AttestationRejected):
    """A candidate denylist is stale, altered, unauthenticated or malformed.

    The intact active denylist stays in force; this never makes verification unavailable.
    """


def _unique_object(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def _strict_json(original: bytes) -> object:
    try:
        return json.loads(original.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise AttestationRejected("invalid JSON original") from error


# ----------------------------------------------------------------------------------------
# Google attestation status list
# ----------------------------------------------------------------------------------------


def parse_google_revocation_status(body: bytes) -> frozenset:
    """Parse Google's documented status schema; every listed key is disallowed."""
    require(0 < len(body) <= MAX_STATUS_BYTES, "Android revocation status outside bound")
    value = _strict_json(body)
    require(type(value) is dict and set(value) == {"entries"}
            and type(value["entries"]) is dict
            and len(value["entries"]) <= MAX_ENTRIES,
            "invalid Android revocation status envelope")
    result: set = set()
    for serial, entry in value["entries"].items():
        require(type(serial) is str and _SERIAL.fullmatch(serial) is not None
                and len(serial) <= 40, "invalid Android revocation serial")
        require(type(entry) is dict and "status" in entry
                and set(entry) <= {"status", "expires", "reason", "comment"}
                and entry["status"] in ("REVOKED", "SUSPENDED"),
                "invalid Android revocation entry")
        if "expires" in entry:
            expires = entry["expires"]
            require(type(expires) is str and len(expires) == 10,
                    "invalid Android revocation expiry")
            try:
                require(date.fromisoformat(expires).isoformat() == expires,
                        "invalid Android revocation expiry")
            except ValueError as error:
                raise AttestationRejected("invalid Android revocation expiry") from error
        if "reason" in entry:
            require(type(entry["reason"]) is str and entry["reason"] in _REASONS,
                    "invalid Android revocation reason")
        if "comment" in entry:
            require(type(entry["comment"]) is str and len(entry["comment"]) <= 140,
                    "invalid Android revocation comment")
        result.add(int(serial, 16))
    return frozenset(result)


def cache_freshness_seconds(cache_control: str | None, age: str | None) -> int:
    """Remaining HTTP freshness lifetime in whole seconds; zero forbids reuse.

    Only ``max-age`` grants reuse, reduced by any ``Age``; ``no-store`` and ``no-cache``
    forbid it, and a malformed header grants nothing.
    """
    if type(cache_control) is not str:
        return 0
    lifetime = None
    for directive in cache_control.split(","):
        name, _, argument = directive.strip().partition("=")
        name = name.strip().lower()
        if name in ("no-store", "no-cache"):
            return 0
        if name == "max-age":
            argument = argument.strip()
            if lifetime is not None or not argument.isdigit() or len(argument) > 10:
                return 0
            lifetime = int(argument)
    if lifetime is None:
        return 0
    elapsed = 0
    if age is not None:
        age = age.strip()
        if not age.isdigit() or len(age) > 10:
            return 0
        elapsed = int(age)
    return max(0, min(lifetime, MAX_STATUS_REUSE_S) - elapsed)


@dataclass(frozen=True)
class GoogleStatusList:
    serials: frozenset
    freshness_s: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def fetch_google_revocation_status() -> GoogleStatusList:
    """Fetch the exact Google HTTPS resource using system TLS roots, without redirects.

    Transport failures and a changed, mistyped, oversized or malformed response
    all raise ``RevocationUnavailable``.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    request = urllib.request.Request(GOOGLE_STATUS_URL, headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=5) as response:
            require(response.status == 200 and response.geturl() == GOOGLE_STATUS_URL,
                    "Android revocation source changed")
            media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            require(media_type == "application/json"
                    and response.headers.get("Content-Encoding", "identity").lower() == "identity",
                    "invalid Android revocation response type")
            freshness = cache_freshness_seconds(response.headers.get("Cache-Control"),
                                                response.headers.get("Age"))
            body = response.read(MAX_STATUS_BYTES + 1)
        return GoogleStatusList(parse_google_revocation_status(body), freshness)
    except RevocationUnavailable:
        raise
    except AttestationRejected as error:
        raise RevocationUnavailable(str(error)) from error
    except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
        # ``http.client`` raises BadStatusLine, LineTooLong and IncompleteRead
        # outside ``OSError``; they are transport failures too.
        raise RevocationUnavailable("Android revocation status unavailable") from error


def _suspend_inclusive_ns() -> int | None:
    # Freshness must include host suspension. Without such a clock nothing is reused.
    if sys.platform.startswith("linux") and hasattr(time, "CLOCK_BOOTTIME"):
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    return None


class GoogleAttestationStatus:
    """Google's status list for one verifier process, reused only while HTTP-fresh."""

    def __init__(self, fetch: Callable[[], GoogleStatusList] = fetch_google_revocation_status,
                 clock: Callable[[], int | None] = _suspend_inclusive_ns) -> None:
        self._fetch, self._clock = fetch, clock
        self._serials: frozenset | None = None
        self._fresh_until_ns: int | None = None

    def listed_serials(self) -> frozenset:
        now = self._clock()
        if (now is not None and self._serials is not None and self._fresh_until_ns is not None
                and now < self._fresh_until_ns):
            return self._serials
        self._serials = self._fresh_until_ns = None
        fetched = self._fetch()
        require(type(fetched) is GoogleStatusList and type(fetched.serials) is frozenset
                and type(fetched.freshness_s) is int and fetched.freshness_s >= 0,
                "invalid Android revocation status")
        after = self._clock()
        if now is not None and after is not None and after >= now and fetched.freshness_s > 0:
            # Count freshness from before the request so transport time never extends it.
            self._serials = fetched.serials
            self._fresh_until_ns = now + fetched.freshness_s * 1_000_000_000
        return fetched.serials


def certificate_serial(der: bytes) -> int:
    """Read the positive X.509 TBS serial number from bounded strict DER."""
    require(0 < len(der) <= 16 * 1024, "Android attestation certificate outside bound")
    certificate = children(der_one(der))
    require(len(certificate) == 3, "invalid Android attestation certificate")
    tbs = children(certificate[0])
    start = 1 if tbs and tbs[0].tag_class == 2 and tbs[0].number == 0 else 0
    require(len(tbs) >= start + 6, "invalid Android attestation TBS")
    serial = positive_integer(tbs[start])
    require(0 < serial < (1 << 160), "Android attestation serial outside bound")
    return serial


# ----------------------------------------------------------------------------------------
# Operator denylist original and its durable active custody
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OperatorDenylist:
    """One parsed operator denylist original; not an authentication of its source."""

    original: bytes
    sha256: bytes
    sequence: int
    serials: frozenset
    spki_sha256: frozenset


def parse_operator_denylist(original: bytes) -> OperatorDenylist:
    """Parse the exact denylist format; any malformed part rejects the whole original."""
    require(type(original) is bytes and 0 < len(original) <= MAX_DENYLIST_BYTES,
            "operator denylist outside bound")
    value = _strict_json(original)
    require(type(value) is dict and set(value) == {"version", "sequence", "entries"},
            "invalid operator denylist members")
    require(type(value["version"]) is int and value["version"] == DENYLIST_VERSION,
            "unsupported operator denylist version")
    sequence = value["sequence"]
    require(type(sequence) is int and 1 <= sequence <= MAX_DENYLIST_SEQUENCE,
            "invalid operator denylist sequence")
    entries = value["entries"]
    require(type(entries) is list and len(entries) <= MAX_DENYLIST_ENTRIES,
            "invalid operator denylist entries")
    serials, spkis, seen = set(), set(), set()
    for entry in entries:
        require(type(entry) is dict and len(entry) == 1, "invalid operator denylist entry")
        (name, item), = entry.items()
        require(type(item) is str, "invalid operator denylist entry")
        require((name, item) not in seen, "duplicate operator denylist entry")
        seen.add((name, item))
        if name == "serial":
            require(_SERIAL.fullmatch(item) is not None and len(item) <= 40,
                    "invalid operator denylist serial")
            serials.add(int(item, 16))
        else:
            require(name == "spki_sha256" and _SPKI.fullmatch(item) is not None,
                    "invalid operator denylist entry")
            spkis.add(bytes.fromhex(item))
    return OperatorDenylist(original, hashlib.sha256(original).digest(), sequence,
                            frozenset(serials), frozenset(spkis))


def _custody_record(denylist: OperatorDenylist) -> bytes:
    return json.dumps({"schema": DENYLIST_CUSTODY_SCHEMA, "sequence": denylist.sequence,
                       "sha256": denylist.sha256.hex(),
                       "original_base64": base64.b64encode(denylist.original).decode("ascii")},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


class OperatorDenylistCustody:
    """Active denylist custody in the private E1 store directory.

    The record holds the exact accepted original, its sequence and its SHA-256, replaced
    atomically (write, fsync, rename, directory fsync). Every read checks the record,
    the original and their agreement; any failure is ``RevocationUnavailable``.
    """

    def __init__(self, directory: Path, directory_fd: int) -> None:
        self.directory, self.directory_fd = directory, directory_fd

    def _require_directory(self) -> None:
        try:
            held, path = os.fstat(self.directory_fd), self.directory.stat()
        except OSError:
            raise RevocationUnavailable("operator denylist custody unavailable") from None
        if not (self.directory.is_absolute() and stat.S_ISDIR(held.st_mode)
                and held.st_uid == os.getuid() and held.st_mode & 0o077 == 0
                and (held.st_dev, held.st_ino) == (path.st_dev, path.st_ino)):
            raise RevocationUnavailable("operator denylist custody unavailable")

    def _read_record(self) -> bytes:
        self._require_directory()
        try:
            descriptor = os.open(DENYLIST_CUSTODY, os.O_RDONLY | os.O_NOFOLLOW,
                                 dir_fd=self.directory_fd)
        except OSError:
            raise RevocationUnavailable("operator denylist custody unavailable") from None
        try:
            metadata = os.fstat(descriptor)
            if not (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and metadata.st_mode & 0o077 == 0 and metadata.st_nlink == 1
                    and 0 < metadata.st_size <= MAX_DENYLIST_CUSTODY_BYTES):
                raise RevocationUnavailable("operator denylist custody unavailable")
            parts, offset = [], 0
            while offset < metadata.st_size:
                chunk = os.pread(descriptor, min(1 << 20, metadata.st_size - offset), offset)
                if not chunk:
                    raise RevocationUnavailable("operator denylist custody truncated")
                parts.append(chunk)
                offset += len(chunk)
            record = b"".join(parts)
            if os.pread(descriptor, 1, offset) or os.fstat(descriptor).st_size != metadata.st_size:
                raise RevocationUnavailable("operator denylist custody changed")
            return record
        except OSError:
            raise RevocationUnavailable("operator denylist custody unavailable") from None
        finally:
            os.close(descriptor)

    def active(self) -> OperatorDenylist:
        """The authenticated active denylist, or ``RevocationUnavailable``; never empty."""
        record = self._read_record()
        try:
            value = _strict_json(record)
            require(type(value) is dict
                    and set(value) == {"schema", "sequence", "sha256", "original_base64"}
                    and value["schema"] == DENYLIST_CUSTODY_SCHEMA
                    and type(value["original_base64"]) is str
                    and type(value["sha256"]) is str and _SPKI.fullmatch(value["sha256"]),
                    "invalid operator denylist custody")
            original = base64.b64decode(value["original_base64"], validate=True)
            require(base64.b64encode(original).decode("ascii") == value["original_base64"],
                    "noncanonical operator denylist custody")
            denylist = parse_operator_denylist(original)
            require(denylist.sha256.hex() == value["sha256"]
                    and type(value["sequence"]) is int and denylist.sequence == value["sequence"]
                    and _custody_record(denylist) == record,
                    "inconsistent operator denylist custody")
            return denylist
        except (AttestationRejected, ValueError):
            raise RevocationUnavailable("operator denylist custody inconsistent") from None

    def _write(self, denylist: OperatorDenylist, *, create: bool) -> None:
        record = _custody_record(denylist)
        try:
            os.unlink(_DENYLIST_PENDING, dir_fd=self.directory_fd)
        except FileNotFoundError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(_DENYLIST_PENDING, flags, 0o600, dir_fd=self.directory_fd)
        try:
            offset = 0
            while offset < len(record):
                count = os.write(descriptor, record[offset:])
                require(count > 0, "operator denylist custody write failed")
                offset += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if create:
            # An explicit installation never replaces existing custody.
            os.link(_DENYLIST_PENDING, DENYLIST_CUSTODY, src_dir_fd=self.directory_fd,
                    dst_dir_fd=self.directory_fd, follow_symlinks=False)
            os.unlink(_DENYLIST_PENDING, dir_fd=self.directory_fd)
        else:
            os.replace(_DENYLIST_PENDING, DENYLIST_CUSTODY, src_dir_fd=self.directory_fd,
                       dst_dir_fd=self.directory_fd)
        os.fsync(self.directory_fd)

    def initialize(self, original: bytes) -> OperatorDenylist:
        """Explicit installation of the first authenticated denylist; never a serving path."""
        denylist = parse_operator_denylist(original)
        self._require_directory()
        fcntl.flock(self.directory_fd, fcntl.LOCK_EX)
        try:
            try:
                os.stat(DENYLIST_CUSTODY, dir_fd=self.directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                self._write(denylist, create=True)
            else:
                raise FileExistsError("operator denylist custody already exists")
            require(self.active() == denylist, "operator denylist custody differs after write")
        finally:
            fcntl.flock(self.directory_fd, fcntl.LOCK_UN)
        return denylist

    def offer(self, candidate: bytes) -> str:
        """Offer an authenticated candidate; ``accepted`` or ``unchanged``.

        A stale or altered candidate raises ``DenylistUpdateRejected`` and leaves the active
        list in force. Without intact active custody nothing is accepted
        (``RevocationUnavailable``): rollback protection needs the retained sequence.
        """
        try:
            denylist = parse_operator_denylist(candidate)
        except AttestationRejected as error:
            raise DenylistUpdateRejected("malformed operator denylist candidate") from error
        self._require_directory()
        fcntl.flock(self.directory_fd, fcntl.LOCK_EX)
        try:
            active = self.active()
            if denylist.sequence == active.sequence:
                if denylist.original != active.original:
                    raise DenylistUpdateRejected("altered operator denylist at the active sequence")
                return "unchanged"
            if denylist.sequence < active.sequence:
                raise DenylistUpdateRejected("stale operator denylist sequence")
            self._write(denylist, create=False)
            require(self.active() == denylist, "operator denylist custody differs after write")
        finally:
            fcntl.flock(self.directory_fd, fcntl.LOCK_UN)
        return "accepted"


class AndroidRevocation:
    """Admission step 3: the root's named source plus the operator denylist."""

    def __init__(self, google: GoogleAttestationStatus, denylist: OperatorDenylistCustody) -> None:
        self.google, self.denylist = google, denylist

    def __call__(self, members: tuple, anchor: AndroidTrustAnchor) -> None:
        require(type(members) is tuple and 2 <= len(members) <= MAX_CHAIN_CERTIFICATES
                and all(type(member) is AndroidChainMember for member in members)
                and type(anchor) is AndroidTrustAnchor, "invalid Android revocation input")
        require(anchor.revocation_source in ("google_attestation_status", "operator_denylist"),
                "unknown Android revocation source")
        # Obtain every source before deciding: a source that cannot be read is unavailable,
        # never a refusal or an admission.
        denylist = self.denylist.active()
        listed = (self.google.listed_serials()
                  if anchor.revocation_source == "google_attestation_status" else frozenset())
        for index, member in enumerate(members):
            if member.spki_sha256 in denylist.spki_sha256 or (
                    index > 0 and member.serial in denylist.serials):
                raise EvidenceRefused(EnrollmentRefusal.ATTESTATION_REVOKED,
                                      "chain certificate is on the operator denylist")
            if member.serial in listed:
                raise EvidenceRefused(EnrollmentRefusal.ATTESTATION_REVOKED,
                                      "chain certificate is on Google's status list")
