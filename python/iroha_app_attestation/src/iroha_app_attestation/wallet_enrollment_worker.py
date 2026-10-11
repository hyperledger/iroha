"""Private current E1 verifier. No listener, issuer key, credential or money grant.

Native launches the frozen archive/runtime and supplies its admitted operator configuration
only through inherited FD20. Requests travel on private stdin/stdout and carry opaque raw
platform evidence. FD17 retains the protected SQLite directory; FD21 retains the configured
public OpenSSL executable. An Android worker may inherit FD22, the parent-authenticated
candidate operator denylist original (the issuer pins its path and SHA-256 in its root-owned
startup document); it is offered once at startup under the rollback rules. No credential
path or signing key is accepted in a request. The parent must already authenticate all
runtime/policy originals.

Before exposing E1, Core anchors this journal's incarnation and exact prepared operation in
its protected challenge record. Complete and recover can claim only that prepared original.
A claim commits before any external verification and records the first dispatch time. Its
outcome is then exactly one of: ``evidence`` (retained projection) or ``refused`` (one closed
refusal code), the two terminal outcomes; ``unavailable`` (an outage before any effect,
recorded on the claim); or in flight. A Complete or Recover of the exact retained E5 while E1
is live re-claims an ``unavailable`` claim and resumes verification; the first dispatch time
stays the recorded evidence time. A claim left in flight by an interruption, or an outage
claim after E1 expires, stays ``outcome_unknown`` and is never verified again. Inspect reads
only a retained outcome; it never claims a prepared operation, including before E1 expires.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from collections import deque
from pathlib import Path

from .attestation import (
    AttestationRejected, EnrollmentRefusal, EvidenceRefused, VerificationUnavailable,
    _verify_apple_assertion_with_hash, demand, refusal_stage, require,
    verify_apple_wallet_attestation_raw,
    recheck_retained_android_chain_revocation,
)
from .wallet_enrollment import (
    APPLE_ADMITTED_FACTS, WalletEnrollmentScope, _digest,
    VerifiedWalletEnrollmentEvidence, verify_android_wallet_enrollment,
)
from .wallet_policy import (
    AndroidAppIdentityV1, AndroidEnrollmentPlatformV1, AndroidRootV1, AppleAppIdentityV1,
    AppleEnrollmentPlatformV1, ConfiguredWalletEnrollmentPolicyV1,
    RegulatoryPolicyV1, WalletAppPolicyV1, WalletEnrollmentPolicyV1,
)
from .native_time_interval import NativeTimeInterval
from .revocation import (
    MAX_DENYLIST_BYTES, AndroidRevocation, DenylistUpdateRejected, GoogleAttestationStatus,
    OperatorDenylistCustody,
)
from .wallet_enrollment_store import E1CounterStore

SCHEMA = "iroha.kagemusha.wallet-e1-verifier.v1"
CONFIG_SCHEMA = "iroha.kagemusha.wallet-e1-verifier-config.v1"
PREPARATION_SCHEMA = "iroha.kagemusha.wallet-e1-worker-preparation.v1"
MAX_PACKET = 768 * 1024
MAX_REQUEST = 320 * 1024
MAX_ORIGINAL = 360 * 1024
MAX_CONFIG = 128 * 1024
MAX_PREPARATION = 16 * 1024
EXCHANGE_WINDOW = 4096
DENYLIST_FD = 22


def _unique(pairs: list) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "duplicate private packet member")
        result[key] = value
    return result


def exact_json(original: bytes, bound: int) -> dict:
    require(type(original) is bytes and 0 < len(original) <= bound, "private packet outside bound")
    try:
        value = json.loads(original.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AttestationRejected("invalid private packet") from None
    require(type(value) is dict, "invalid private packet")
    return value


def encode(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def b64(value: object, maximum: int, exact: int | None = None) -> bytes:
    require(type(value) is str and 0 < len(value) <= ((maximum + 2) // 3) * 4,
            "invalid private binary field")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise AttestationRejected("invalid private binary field") from None
    require(0 < len(raw) <= maximum and (exact is None or len(raw) == exact)
            and base64.b64encode(raw).decode("ascii") == value, "noncanonical private binary field")
    return raw


def hex32(value: object) -> bytes:
    require(type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value), "invalid private digest")
    return bytes.fromhex(value)


def read_packet(stream) -> bytes | None:
    head = b""
    while len(head) < 4:
        part = stream.read(4 - len(head))
        if not part:
            if not head:
                return None
            raise AttestationRejected("partial private packet header")
        head += part
    width = int.from_bytes(head, "little")
    require(0 < width <= MAX_PACKET, "private packet outside bound")
    parts, remaining = [], width
    while remaining:
        chunk = stream.read(remaining)
        require(bool(chunk), "partial private packet")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def write_packet(stream, value: dict) -> None:
    original = encode(value)
    require(0 < len(original) <= MAX_PACKET, "private response outside bound")
    stream.write(len(original).to_bytes(4, "little") + original)
    stream.flush()


class HeldPublicFile:
    """Descriptor/path identity and complete bytes rechecked before and after each use.

    This local check is not release admission. Native must hold the independently signed
    installed runtime and operator originals; hashing an arbitrary file creates no authority.
    """
    def __init__(self, fd: int, expected: bytes, path: Path | None = None):
        self.fd, self.expected, self.path = fd, expected, path
        self.metadata = self._metadata()
        self.recheck()

    def _metadata(self):
        value = os.fstat(self.fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid in (0, os.getuid())
                and value.st_mode & 0o022 == 0 and value.st_nlink == 1,
                "private original custody unavailable")
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns, value.st_mode, value.st_uid, value.st_gid)

    def recheck(self):
        require(self._metadata() == self.metadata and 0 < self.metadata[2] <= 64 * 1024 * 1024,
                "private original changed")
        digest, offset = hashlib.sha256(), 0
        while offset < self.metadata[2]:
            chunk = os.pread(self.fd, min(65536, self.metadata[2] - offset), offset)
            require(bool(chunk), "private original truncated")
            digest.update(chunk)
            offset += len(chunk)
        require(digest.digest() == self.expected and self._metadata() == self.metadata,
                "private original differs")
        if self.path is not None:
            require(self.path.is_absolute() and self.path.resolve(strict=True) == self.path,
                    "invalid crypto path")
            value = self.path.stat()
            require((value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                     value.st_ctime_ns, value.st_mode, value.st_uid, value.st_gid) == self.metadata,
                    "crypto path differs from held original")


def _uint(value: object, bits: int, name: str) -> int:
    require(type(value) is int and 0 <= value < (1 << bits), name)
    return value


def _android_roots(value: object) -> tuple:
    require(type(value) is list and 1 <= len(value) <= 8, "invalid private Android root set")
    roots = []
    for item in value:
        require(type(item) is dict and type(item.get("family")) is str, "invalid private Android root")
        members = {"family", "spki_sha256", "revocation_source"}
        if item["family"] == "vendor":
            members = members | {"adapter_id"}
        require(set(item) == members and type(item["revocation_source"]) is str,
                "invalid private Android root")
        require(item.get("adapter_id") is None or type(item["adapter_id"]) is str,
                "invalid private Android adapter")
        roots.append(AndroidRootV1(item["family"], hex32(item["spki_sha256"]),
                                   item["revocation_source"], item.get("adapter_id")))
    return tuple(roots)


def configured_policy(value: dict, platform: str) -> ConfiguredWalletEnrollmentPolicyV1:
    """Exact private projection of authenticated current Model policy originals.

    Hashes establish consistency only. Native authenticates this complete configuration,
    selects the current scheme/asset/account and holds its independently signed inventory.
    An Android root naming an unknown or unqualified adapter profile fails configuration.
    """
    common = {"scheme_id_hex", "asset_digest_hex", "regulatory_policy", "challenge_lifetime_ms",
              "attestation_lease_lifetime_ms"}
    apple = {"root_base64", "root_sha256", "app_id"}
    android = {"package_name", "minimum_package_version", "app_signer_sha256", "roots",
               "patch_floor_yyyymm"}
    require(platform in ("android", "apple") and type(value) is dict
            and set(value) == common | (android if platform == "android" else apple),
            "invalid private platform policy")
    scheme, asset = hex32(value["scheme_id_hex"]), hex32(value["asset_digest_hex"])
    require(any(scheme) and any(asset), "empty private policy binding")
    regulator = value["regulatory_policy"]
    require(type(regulator) is dict and set(regulator) == {
        "permitted_controls", "blacklist_max_age_ms", "time_anchor_max_response_ms"}, "invalid regulator projection")
    selected_regulator = RegulatoryPolicyV1(**regulator)
    require(type(value["challenge_lifetime_ms"]) is int and 0 < value["challenge_lifetime_ms"] < (1 << 64),
            "invalid private challenge lifetime")
    root = None
    if platform == "apple":
        pin = hex32(value["root_sha256"])
        root = b64(value["root_base64"], 16384)
        require(any(pin) and hashlib.sha256(root).digest() == pin, "private root differs from policy")
        identity = AppleAppIdentityV1(value["app_id"])
        selected = AppleEnrollmentPlatformV1(pin)
    else:
        signers = value["app_signer_sha256"]
        require(type(signers) is list and 1 <= len(signers) <= 4, "invalid private signer set")
        identity = AndroidAppIdentityV1(value["package_name"],
                                        _uint(value["minimum_package_version"], 64,
                                              "invalid private minimum package version"),
                                        tuple(hex32(signer) for signer in signers))
        selected = AndroidEnrollmentPlatformV1(_android_roots(value["roots"]),
                                               value["patch_floor_yyyymm"])
    app = WalletAppPolicyV1(1, scheme, identity)
    enrollment = WalletEnrollmentPolicyV1(1, scheme, asset, app.policy_digest(), selected,
        selected_regulator, value["challenge_lifetime_ms"], value["attestation_lease_lifetime_ms"])
    policy = ConfiguredWalletEnrollmentPolicyV1(app, enrollment, root)
    policy.validate()
    return policy


def _realtime_ns() -> int:
    return time.time_ns()


def _sleep_inclusive_ns() -> int:
    # This worker is a Linux-only private release executable. A clock excluding
    # suspend would let a sleeping process reuse an expired enrollment window.
    if not sys.platform.startswith("linux") or not hasattr(time, "CLOCK_BOOTTIME"):
        raise VerificationUnavailable("sleep-inclusive private clock unavailable")
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class DispatchClock:
    """Fresh worker clock anchored to the exact Core dispatch and Linux boottime.

    Neither a request field nor a caller callback supplies elapsed time. Realtime and the
    retained sleep-inclusive reference must both stay within the original challenge window:
    reaching its end refuses with ChallengeExpired. Clock loss or regression is unavailable.
    """
    def __init__(self, dispatch_ms: int, issued_ms: int, expires_ms: int):
        self.dispatch_ms, self.issued_ms, self.expires_ms = dispatch_ms, issued_ms, expires_ms
        self.elapsed_start = self.elapsed_last = _sleep_inclusive_ns()
        self.wall_start = self.wall_last = _realtime_ns()
        if self.wall_start // 1_000_000 < dispatch_ms:
            raise VerificationUnavailable("private clock predates Core dispatch")
        self.sample()

    def sample(self) -> NativeTimeInterval:
        elapsed, wall = _sleep_inclusive_ns(), _realtime_ns()
        if elapsed < self.elapsed_last or wall < self.wall_last:
            raise VerificationUnavailable("private clock regressed")
        self.elapsed_last, self.wall_last = elapsed, wall
        delta = elapsed - self.elapsed_start
        # Anchor elapsed duration to the actual worker sample, not the older
        # Core dispatch. Socket or queue latency must never extend this window.
        lower = max(wall, self.wall_start + delta) // 1_000_000
        upper = (max(wall, self.wall_start + delta) + 999_999) // 1_000_000
        if lower < self.issued_ms:
            raise VerificationUnavailable("private clock precedes the E1 challenge")
        demand(upper < self.expires_ms, EnrollmentRefusal.CHALLENGE_EXPIRED,
               "E1 challenge expired before verification completed")
        interval = NativeTimeInterval(lower, upper)
        interval.require_window(self.issued_ms, self.expires_ms)
        return interval


class VerifierOwner:
    """Actual private process owner; its only successful result comes from real verifiers."""
    # Android revocation owner; Apple workers have none.
    revocation = None
    denylist_offer: str | None = None

    def __init__(self, config_original: bytes, *, directory_fd: int = 17,
                 crypto_fd: int = 21, configuration_fd: int | None = None,
                 denylist_fd: int | None = None):
        config = exact_json(config_original, MAX_CONFIG)
        require(set(config) == {"schema", "version", "platform", "app_policy_hex",
                                "enrollment_policy_hex", "openssl_path", "openssl_sha256",
                                "store_directory", "policy"}
                and config["schema"] == CONFIG_SCHEMA and type(config["version"]) is int
                and config["version"] == 1 and type(config["platform"]) is str
                and config["platform"] in ("android", "apple"), "invalid private configuration")
        self.config_digest = hashlib.sha256(config_original).digest()
        self.configuration = (None if configuration_fd is None else
                              HeldPublicFile(configuration_fd, self.config_digest))
        self.platform = config["platform"]
        self.app_policy, self.enrollment_policy = hex32(config["app_policy_hex"]), hex32(config["enrollment_policy_hex"])
        require(any(self.app_policy) and any(self.enrollment_policy), "empty private policy")
        self.openssl = Path(config["openssl_path"])
        self.crypto = HeldPublicFile(crypto_fd, hex32(config["openssl_sha256"]), self.openssl)
        self.policy = configured_policy(config["policy"], self.platform)
        require(self.policy.app.policy_digest() == self.app_policy
                and self.policy.enrollment.policy_digest() == self.enrollment_policy,
                "private policy projection differs from Native pins")
        self.directory = Path(config["store_directory"])
        self.dispatch_clock: DispatchClock | None = None
        self.counters = None
        self.directory_fd = os.dup(directory_fd)
        try:
            held, path = os.fstat(self.directory_fd), self.directory.stat()
            require(self.directory.is_absolute() and self.directory.resolve(strict=True) == self.directory
                    and stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid() and held.st_mode & 0o077 == 0
                    and (held.st_dev, held.st_ino) == (path.st_dev, path.st_ino),
                    "private store directory custody unavailable")
            self.counters = E1CounterStore(self.directory, self.directory_fd)
            if self.platform == "android":
                self.revocation = AndroidRevocation(
                    GoogleAttestationStatus(), OperatorDenylistCustody(self.directory, self.directory_fd))
                if denylist_fd is not None:
                    self.denylist_offer = self._offer_denylist(denylist_fd)
            self.recheck()
        except Exception:
            if self.counters is not None:
                self.counters.close()
            os.close(self.directory_fd)
            self.directory_fd = -1
            raise

    def _offer_denylist(self, fd: int) -> str:
        """Offer an inherited parent-authenticated candidate once; never fatal.

        A stale, altered or unreadable candidate leaves the active list deciding; missing
        active custody leaves every Android verification unavailable.
        """
        try:
            metadata = os.fstat(fd)
        except OSError:
            return "absent"
        try:
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid in (0, os.getuid())
                    and metadata.st_mode & 0o022 == 0 and metadata.st_nlink == 1
                    and 0 < metadata.st_size <= MAX_DENYLIST_BYTES,
                    "candidate denylist custody")
            original = os.pread(fd, MAX_DENYLIST_BYTES + 1, 0)
            require(len(original) == metadata.st_size, "candidate denylist truncated")
            return self.revocation.denylist.offer(original)
        except VerificationUnavailable:
            return "unavailable"
        except (DenylistUpdateRejected, AttestationRejected, OSError):
            return "rejected"

    def _clock(self):
        if self.dispatch_clock is None:
            raise VerificationUnavailable("private dispatch clock unavailable")
        return self.dispatch_clock.sample()

    def recheck(self):
        try:
            self.crypto.recheck()
            if self.configuration is not None:
                self.configuration.recheck()
            self.counters.recheck()
        except (AttestationRejected, OSError):
            # A lost or substituted process original is not a platform-evidence rejection.
            raise VerificationUnavailable("private verifier custody unavailable") from None

    def request(self, original: bytes):
        value = exact_json(original, MAX_REQUEST)
        require(set(value) == {"challenge_transcript_base64", "payment_key_base64", "issued_at_ms",
                               "expires_at_ms", "trusted_time_ms", "platform", "evidence"}
                and value["platform"] == self.platform, "invalid private E1 request")
        scope = WalletEnrollmentScope(b64(value["challenge_transcript_base64"], 194, 194),
                                      b64(value["payment_key_base64"], 65, 65))
        scope.validate()
        require(scope.challenge_transcript[98:130] == self.app_policy
                and scope.challenge_transcript[130:162] == self.enrollment_policy,
                "E1 differs from selected private policy")
        issued, expires, now = (value[k] for k in ("issued_at_ms", "expires_at_ms", "trusted_time_ms"))
        # The authenticated issuer may narrow its selected policy lifetime to its
        # session/proof deadline. Retain those exact endpoints; the worker adds no
        # independent ceiling and cannot extend the original half-open interval.
        require(all(type(t) is int for t in (issued, expires, now))
                and 0 < issued <= now < expires < 1 << 64,
                "private E1 time outside original window")
        require(type(value["evidence"]) is dict, "invalid private platform evidence")
        require(expires <= issued + self.policy.enrollment.challenge_lifetime_ms,
                "private E1 lifetime exceeds selected policy")
        self.policy.validate_scope(scope.challenge_transcript, issued, now)
        return value, scope

    def journal(self) -> bytes:
        self.recheck()
        with closing(self.counters._connect()) as connection:
            self.counters.require_incarnation(connection, self.counters.incarnation)
        self.recheck()
        return self.counters.incarnation

    def preparation(self, original: bytes):
        """Validate private DATA; canonical AccountId and Ed ownership remain Core checks."""
        value = exact_json(original, MAX_PREPARATION)
        require(set(value) == {"schema", "operation_id", "challenge_transcript_base64",
            "account_original_base64", "account_owner_public_hex", "issued_at_ms", "expires_at_ms",
            "platform", "app_policy_hex", "enrollment_policy_hex", "config_sha256"}
            and value["schema"] == PREPARATION_SCHEMA and value["platform"] == self.platform,
            "invalid private preparation")
        transcript = b64(value["challenge_transcript_base64"], 194, 194)
        require(transcript[:2] == b"\x01\0"
                and all(any(transcript[n:n + 32]) for n in range(2, 194, 32))
                and transcript[98:130] == self.app_policy
                and transcript[130:162] == self.enrollment_policy,
                "preparation differs from selected private policy")
        operation = hex32(value["operation_id"])
        require(operation == _digest(b"enrollment-challenge", transcript)
                and hex32(value["app_policy_hex"]) == self.app_policy
                and hex32(value["enrollment_policy_hex"]) == self.enrollment_policy
                and hex32(value["config_sha256"]) == self.config_digest,
                "private preparation binding differs")
        b64(value["account_original_base64"], 4096)
        require(any(hex32(value["account_owner_public_hex"])), "invalid private account owner")
        issued, expires = value["issued_at_ms"], value["expires_at_ms"]
        require(type(issued) is int and type(expires) is int and 0 < issued < expires < 1 << 64
                and expires <= issued + self.policy.enrollment.challenge_lifetime_ms,
                "invalid preparation window")
        self.policy.validate_scope(transcript, issued, issued)
        return value, operation

    def prepare(self, incarnation: bytes, original: bytes) -> None:
        self.recheck()
        _, operation = self.preparation(original)
        with closing(self.counters._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self.counters.require_incarnation(connection, incarnation)
                row = connection.execute("SELECT preparation, config_sha256 FROM wallet_e1_attempts WHERE operation_id=?",
                                         (operation,)).fetchone()
                if row is None:
                    connection.execute("INSERT INTO wallet_e1_attempts (operation_id, preparation, config_sha256) VALUES (?, ?, ?)",
                                       (operation, original, self.config_digest))
                else:
                    require(row == (original, self.config_digest), "private preparation already differs")
                self.recheck()
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        self.recheck()

    def projection(self, scope, evidence):
        # No success boolean, issuer output or transferable admission constructor.
        return {"config_sha256": self.config_digest.hex(),
            "challenge_digest": scope.challenge_digest().hex(),
            "key_binding": scope.enrollment_key_binding().hex(),
            "payment_key_base64": base64.b64encode(scope.payment_key_sec1).decode("ascii"),
            "kind_tag": evidence.kind_tag, "time_ms": evidence.time_ms, "facts": evidence.facts,
            "os_patch_level": evidence.os_patch_level, "vendor_patch_level": evidence.vendor_patch_level,
            "boot_patch_level": evidence.boot_patch_level, "evidence_digest": evidence.evidence_digest().hex(),
            "original_items_base64": [base64.b64encode(item).decode("ascii") for item in evidence.original_items],
            "app_attest_key_id": None if evidence.app_attest_key_id is None else evidence.app_attest_key_id.hex(),
            "app_attest_counter": evidence.app_attest_counter}

    def _settle(self, incarnation: bytes, digest: bytes, outcome: str, code: int | None) -> None:
        """Record a refusal or a pre-effect outage on the in-flight claim."""
        with closing(self.counters._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self.counters.require_incarnation(connection, incarnation)
                require(connection.execute(
                    "UPDATE wallet_e1_attempts SET outcome=?, refusal_code=? "
                    "WHERE request_sha256=? AND outcome IS NULL",
                    (outcome, code, digest)).rowcount == 1, "private outcome changed concurrently")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def perform(self, original: bytes, action: str, *, incarnation: bytes,
                preparation: bytes, account_signature: bytes, dispatch_time_ms: int) -> bytes | None:
        """Return retained evidence, ``None`` for an unknown outcome, or raise.

        ``EvidenceRefused`` is the terminal refusal with its retained code;
        ``VerificationUnavailable`` is a recovery state; any other ``AttestationRejected`` is a
        private protocol or binding violation, never an E1 outcome.
        """
        require(action in ("complete", "recover", "inspect"), "invalid private operation")
        self.recheck()
        prepared, operation = self.preparation(preparation)
        value, scope = self.request(original)
        require(all(value[name] == prepared[name] for name in (
            "challenge_transcript_base64", "platform", "issued_at_ms", "expires_at_ms"))
            and scope.challenge_digest() == operation, "private request differs from preparation")
        require(type(account_signature) is bytes and len(account_signature) == 64,
                "invalid retained account signature")
        require(type(dispatch_time_ms) is int and value["trusted_time_ms"] <= dispatch_time_ms < 1 << 64,
                "invalid private dispatch time")
        digest = hashlib.sha256(original).digest()
        claim = (digest, scope.enrollment_key_binding(), original, account_signature)
        live = dispatch_time_ms < value["expires_at_ms"]
        clock = None
        with closing(self.counters._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self.counters.require_incarnation(connection, incarnation)
                row = connection.execute("""SELECT preparation, config_sha256, request_sha256,
                    key_binding, original, account_signature, first_dispatch, outcome, result,
                    refusal_code FROM wallet_e1_attempts WHERE operation_id=?""", (operation,)).fetchone()
                # Missing custody cannot establish a definitive evidence rejection or
                # authorize a new preparation: this row may have been claimed before loss.
                if row is None:
                    raise VerificationUnavailable("private prepared original unavailable")
                require(row[:2] == (preparation, self.config_digest),
                        "private prepared original differs")
                if row[2] is not None:
                    require(row[2:6] == claim, "private recovery scope differs")
                    first_dispatch = int.from_bytes(row[6], "little")
                    outcome = row[7]
                    if outcome == "evidence":
                        self.recheck()
                        connection.execute("COMMIT")
                        return row[8]
                    if outcome == "refused":
                        self.recheck()
                        connection.execute("COMMIT")
                        raise EvidenceRefused(EnrollmentRefusal(row[9]), "retained E1 refusal")
                    if outcome != "unavailable" or action == "inspect" or not live:
                        # In flight after an interruption, or an outage that can no longer
                        # resume: an effect may have happened, so nothing verifies again.
                        self.recheck()
                        connection.execute("COMMIT")
                        return None
                    # A pre-effect outage on this exact claim resumes while E1 is live.
                    try:
                        clock = DispatchClock(dispatch_time_ms, value["issued_at_ms"], value["expires_at_ms"])
                    except EvidenceRefused as refusal:
                        changed = connection.execute(
                            "UPDATE wallet_e1_attempts SET outcome='refused', refusal_code=? "
                            "WHERE operation_id=? AND outcome='unavailable'",
                            (int(refusal.code), operation)).rowcount
                        require(changed == 1, "private resumed claim changed")
                        self.recheck()
                        connection.execute("COMMIT")
                        raise
                    changed = connection.execute(
                        "UPDATE wallet_e1_attempts SET outcome=NULL "
                        "WHERE operation_id=? AND outcome='unavailable'", (operation,)).rowcount
                    require(changed == 1, "private resumed claim changed")
                else:
                    require(all(item is None for item in row[2:]), "invalid prepared journal state")
                    if action == "inspect":
                        raise VerificationUnavailable("private operation has no claimed outcome")
                    first_dispatch = dispatch_time_ms
                    refusal = None
                    if not live:
                        refusal = EvidenceRefused(EnrollmentRefusal.CHALLENGE_EXPIRED,
                                                  "first dispatch after the E1 challenge lifetime")
                    else:
                        try:
                            clock = DispatchClock(dispatch_time_ms, value["issued_at_ms"], value["expires_at_ms"])
                        except EvidenceRefused as expired:
                            refusal = expired
                    changed = connection.execute("""UPDATE wallet_e1_attempts SET request_sha256=?,
                        key_binding=?, original=?, account_signature=?, first_dispatch=?,
                        outcome=?, refusal_code=?
                        WHERE operation_id=? AND request_sha256 IS NULL""",
                        (*claim, first_dispatch.to_bytes(8, "little"),
                         None if refusal is None else "refused",
                         None if refusal is None else int(refusal.code), operation)).rowcount
                    require(changed == 1, "private first dispatch claim changed")
                    if refusal is not None:
                        self.recheck()
                        connection.execute("COMMIT")
                        raise refusal
                self.recheck()
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        # Only the claim winner reaches verification. The selected first dispatch time
        # becomes the evidence time; the fresh clock only bounds whether it may finish.
        self.dispatch_clock = clock
        try:
            result = self._verify(value, scope, digest, incarnation, first_dispatch)
        except EvidenceRefused as refusal:
            self._settle(incarnation, digest, "refused", int(refusal.code))
            raise
        except VerificationUnavailable:
            self._settle(incarnation, digest, "unavailable", None)
            raise
        # The outcome is committed: a later clock or custody failure must never contradict it.
        self.recheck()
        return result

    def recheck_revocation(self, original: bytes, **arguments) -> None:
        """Read an exact successful E1, refresh its revocation, never change its outcome."""
        require(self.platform == "android", "revocation refresh requires Android evidence")
        result = self.perform(original, "inspect", **arguments)
        if result is None:
            raise VerificationUnavailable("successful retained enrollment unavailable")
        value, _ = self.request(original)
        retained = exact_json(result, MAX_ORIGINAL)
        chain = retained.get("original_items_base64")
        require(type(chain) is list and chain == value["evidence"].get("chain_base64")
                and retained.get("config_sha256") == self.config_digest.hex(),
                "retained chain differs from admitted enrollment")
        recheck_retained_android_chain_revocation(
            [b64(item, 16384) for item in chain], self.policy.android_anchors(), self.revocation)
        self.recheck()

    def _verify(self, value: dict, scope, digest: bytes, incarnation: bytes,
                first_dispatch: int) -> bytes:
        self._clock()
        offered = value["evidence"]
        if self.platform == "android":
            with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
                require(set(offered) == {"chain_base64"} and type(offered["chain_base64"]) is list
                        and 2 <= len(offered["chain_base64"]) <= 8,
                        "invalid private Android evidence")
                chain = [b64(item, 16384) for item in offered["chain_base64"]]
            evidence = verify_android_wallet_enrollment(chain, scope, self.policy, self.revocation,
                self.openssl, evidence_time_ms=first_dispatch,
                challenge_created_at_ms=value["issued_at_ms"], trusted_time_interval=self._clock)
            result = encode(self.projection(scope, evidence))
            require(0 < len(result) <= MAX_ORIGINAL, "private evidence result outside bound")
            self.recheck()
            with closing(self.counters._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self.counters.require_incarnation(connection, incarnation)
                    self._clock()
                    changed = connection.execute("UPDATE wallet_e1_attempts SET outcome='evidence', result=? "
                                                 "WHERE request_sha256=? AND outcome IS NULL",
                                                 (result, digest)).rowcount
                    require(changed == 1, "private result changed concurrently")
                    self._clock()
                    connection.execute("COMMIT")
                except Exception:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            return result
        with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
            require(set(offered) == {"attestation_base64", "assertion_base64", "key_id_hex"},
                    "invalid private Apple evidence")
            attestation = b64(offered["attestation_base64"], 65536)
            assertion = b64(offered["assertion_base64"], 4096)
            key_id = hex32(offered["key_id_hex"])
        app_id = self.policy.app.identity.app_id
        verification_time = self._clock().upper_at_ms
        raw = verify_apple_wallet_attestation_raw(attestation, key_id, app_id,
            "production", scope.challenge_digest(), self.policy.apple_root_der,
            self.policy.enrollment.platform.attestation_root_sha256, verification_time, self.openssl)
        self._clock()
        self.counters.register_verified_key(raw, app_id, "production")
        # Counter/challenge consumption and the exact recoverable verified original are
        # one FULL-synchronous transaction in the existing counter database.
        with closing(self.counters._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self.counters.require_incarnation(connection, incarnation)
                row = connection.execute("SELECT point, app_id, environment, counter FROM apple_keys WHERE key_id=?",
                                         (key_id,)).fetchone()
                require(row is not None and row[1] == app_id and row[2] == "production",
                        "private Apple key scope differs")
                self._clock()
                checked = _verify_apple_assertion_with_hash(assertion, scope.enrollment_key_binding(),
                    row[0], key_id, app_id, row[3], self.openssl,
                    expected_validation_category=None, expected_bundle_version=None)
                demand(connection.execute("SELECT 1 FROM apple_client_data WHERE client_data_sha256=?",
                                          (checked.client_data_sha256,)).fetchone() is None,
                       EnrollmentRefusal.EVIDENCE_INVALID, "private Apple challenge already consumed")
                evidence = VerifiedWalletEnrollmentEvidence(3, first_dispatch,
                    APPLE_ADMITTED_FACTS, 0, 0, 0, (attestation, assertion), key_id, checked.counter)
                result = encode(self.projection(scope, evidence))
                require(0 < len(result) <= MAX_ORIGINAL, "private evidence result outside bound")
                self.recheck()
                self._clock()
                connection.execute("INSERT INTO apple_client_data VALUES (?, ?)",
                                   (checked.client_data_sha256, key_id))
                require(connection.execute("UPDATE apple_keys SET counter=? WHERE key_id=? AND counter=?",
                                           (checked.counter, key_id, row[3])).rowcount == 1,
                        "private Apple counter changed concurrently")
                require(connection.execute("UPDATE wallet_e1_attempts SET outcome='evidence', result=? "
                                           "WHERE request_sha256=? AND outcome IS NULL",
                                           (result, digest)).rowcount == 1, "private result changed concurrently")
                self._clock()
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return result

    def close(self):
        if self.counters is not None:
            self.counters.close()
        if self.directory_fd >= 0:
            os.close(self.directory_fd)
            self.directory_fd = -1


def serve(owner: VerifierOwner, input_stream, output_stream):
    seen, recent = set(), deque()
    while (packet := read_packet(input_stream)) is not None:
        value = exact_json(packet, MAX_PACKET)
        require(set(value) == {"schema", "version", "exchange_id", "action", "journal_incarnation",
                              "preparation_base64", "original_base64", "account_signature_base64",
                              "dispatch_time_ms"}
                and value["schema"] == SCHEMA and type(value["version"]) is int
                and value["version"] == 1, "invalid private exchange")
        exchange = hex32(value["exchange_id"])
        require(any(exchange) and exchange not in seen, "private exchange reused")
        seen.add(exchange)
        recent.append(exchange)
        if len(recent) > EXCHANGE_WINDOW:
            seen.remove(recent.popleft())
        response = {"schema": SCHEMA, "version": 1, "exchange_id": exchange.hex(),
                    "request_sha256": hashlib.sha256(packet).hexdigest(),
                    "journal_incarnation": owner.counters.incarnation.hex(),
                    "config_sha256": owner.config_digest.hex(),
                    "evidence_base64": None, "refusal_code": None}
        try:
            action = value["action"]
            if action == "journal":
                require(all(value[name] is None for name in ("journal_incarnation", "preparation_base64",
                    "original_base64", "account_signature_base64", "dispatch_time_ms")),
                    "journal exchange carries operation inputs")
                response["journal_incarnation"] = owner.journal().hex()
                response["outcome"] = "journal"
            else:
                incarnation = hex32(value["journal_incarnation"])
                preparation = b64(value["preparation_base64"], MAX_PREPARATION)
                if action == "prepare":
                    require(all(value[name] is None for name in (
                        "original_base64", "account_signature_base64", "dispatch_time_ms")),
                        "preparation exchange carries dispatch inputs")
                    owner.prepare(incarnation, preparation)
                    response["outcome"] = "prepared"
                elif action == "recheck_revocation":
                    owner.recheck_revocation(b64(value["original_base64"], MAX_REQUEST),
                        incarnation=incarnation, preparation=preparation,
                        account_signature=b64(value["account_signature_base64"], 64, 64),
                        dispatch_time_ms=value["dispatch_time_ms"])
                    response["outcome"] = "current"
                else:
                    result = owner.perform(b64(value["original_base64"], MAX_REQUEST), action,
                        incarnation=incarnation, preparation=preparation,
                        account_signature=b64(value["account_signature_base64"], 64, 64),
                        dispatch_time_ms=value["dispatch_time_ms"])
                    response.update({"outcome": "evidence" if result is not None else "outcome_unknown",
                        "evidence_base64": None if result is None else base64.b64encode(result).decode("ascii")})
        except EvidenceRefused as refusal:
            response.update({"outcome": "refused", "evidence_base64": None,
                             "refusal_code": int(refusal.code)})
        except VerificationUnavailable:
            response.update({"outcome": "unavailable", "evidence_base64": None, "refusal_code": None})
        except (AttestationRejected, sqlite3.IntegrityError):
            # A private protocol or binding violation: never an E1 refusal or admission.
            response.update({"outcome": "rejected", "evidence_base64": None, "refusal_code": None})
        except (sqlite3.Error, OSError):
            response.update({"outcome": "unavailable", "evidence_base64": None, "refusal_code": None})
        write_packet(output_stream, response)


def main():
    # No environment/provider/argument selector and no public authority intake.
    require(sys.platform.startswith("linux") and len(sys.argv) == 1, "private Linux runtime required")
    metadata = os.fstat(20)
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid in (0, os.getuid())
            and metadata.st_mode & 0o022 == 0 and metadata.st_nlink == 1
            and 0 < metadata.st_size <= MAX_CONFIG,
            "private configuration custody unavailable")
    original = os.pread(20, MAX_CONFIG + 1, 0)
    require(len(original) == metadata.st_size, "private configuration truncated")
    owner = VerifierOwner(original, configuration_fd=20, denylist_fd=DENYLIST_FD)
    try:
        serve(owner, sys.stdin.buffer, sys.stdout.buffer)
    finally:
        owner.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not put raw evidence or source exception text on inherited stderr.
        raise SystemExit(1) from None
