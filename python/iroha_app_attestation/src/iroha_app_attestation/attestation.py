"""Independent, bounded Apple App Attest and Android KeyMint E1 admission checks.

This module issues nothing. Callers select every scope value (challenge, payment key, app
policy, pinned roots) from their own authenticated configuration, never from evidence.

Android admission follows the enrollment policy's ordered steps
(``specs/kagemusha_wallet_enrollment_policy_v1.md`` "Android admission"): chain shape, root
and path under the matched root's adapter profile, revocation, key description, secure
hardware, key properties, app identity, boot and patch. The first failing step raises
``EvidenceRefused`` with its closed design §2.4 code. A revocation source or operator
denylist that cannot be read raises ``VerificationUnavailable``: never a refusal or an
admission. Apple admission is production App Attest plus the key-binding assertion.
"""

from __future__ import annotations

import datetime
import enum
import hashlib
import os
import sqlite3
import stat
import subprocess
import tempfile
import base64
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence


MAX_OBJECT = 64 * 1024
MAX_APPLE_ASSERTION = 4 * 1024
MAX_APPLE_CLIENT_DATA = 4 * 1024
MAX_CERT = 16 * 1024
MAX_CHAIN = 8
MAX_ANDROID_CHAIN_BYTES = 64 * 1024
DEVICE_KEY_REFERENCE_DOMAIN = b"iroha:kagemusha:v1:device-key-reference\0"
APPLE_NONCE_OID = "1.2.840.113635.100.8.2"
ANDROID_KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
ANDROID_PROVISIONING_INFORMATION_OID = "1.3.6.1.4.1.11129.2.1.30"
# The documented attestation/KeyMint version pairs (enrollment policy, Android admission step
# 4). Attestation version 1 (Keymaster 2) has no application identity and is refused with its
# own reason. A newly documented pair is added by a reviewed adapter change with its schema.
# https://source.android.com/docs/security/features/keystore/attestation#schema
ANDROID_ATTESTATION_VERSION_PAIRS = frozenset({
    (2, 3), (3, 4), (4, 41), (100, 100), (200, 200), (300, 300), (400, 400), (500, 500),
})
# KeyMint AuthorizationList OS version and patch-level tags. Only their hardware-enforced
# copies describe the attested device.
ANDROID_OS_VERSION_TAG = 705
ANDROID_OS_PATCH_LEVEL_TAG = 706
ANDROID_VENDOR_PATCH_LEVEL_TAG = 718
ANDROID_BOOT_PATCH_LEVEL_TAG = 719
ANDROID_ATTESTATION_APPLICATION_ID_TAG = 709
ANDROID_ROOT_OF_TRUST_TAG = 704
ANDROID_USAGE_COUNT_LIMIT_TAG = 405
ANDROID_ALL_APPLICATIONS_TAG = 600
# Key properties that must be hardware-enforced: purpose, algorithm, key size, digest, curve,
# origin and RootOfTrust. A software-enforced copy contradicts the hardware claim.
ANDROID_HARDWARE_KEY_PROPERTY_TAGS = frozenset({1, 2, 3, 5, 10, 702, 704})
# Documented AuthorizationList field types. These fields are type-checked when present;
# every other context-specific tag is ignored (Android admission step 6).
_AUTH_SET_OF_INTEGER = frozenset({1, 5, 6, 203})
_AUTH_INTEGER = frozenset({2, 3, 10, 200, 400, 401, 402, 405, 504, 505, 701, 702, 705, 706,
                           718, 719})
_AUTH_NULL = frozenset({303, 305, 503, 506, 507, 508, 509, 600, 720})
_AUTH_OCTET_STRING = frozenset({601, 709, 710, 711, 712, 713, 714, 715, 716, 717, 723, 724})

_BASIC_CONSTRAINTS_OID = "2.5.29.19"
_KEY_USAGE_OID = "2.5.29.15"
_SERIAL_NUMBER_ATTRIBUTE_OID = "2.5.4.5"
_SIGNATURE_ALGORITHMS = frozenset({
    "1.2.840.113549.1.1.11",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13",  # sha512WithRSAEncryption
    "1.2.840.10045.4.3.2",    # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3",    # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4",    # ecdsa-with-SHA512
})
_RSA_SIGNATURE_ALGORITHMS = frozenset({
    "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
})
_OPENSSL_TIMEOUT_S = 5


class AttestationRejected(ValueError):
    """Raw evidence or a private input does not match the independently selected scope."""


class VerificationUnavailable(AttestationRejected):
    """A live verification dependency could not answer.

    Raised when a revocation source, the operator denylist custody, the trusted clock or
    the verifier's own custody is unavailable. The evidence is not known to be bad. It stays
    an ``AttestationRejected`` so every generic handler fails closed; callers report it as a
    retryable unavailability rather than as rejected evidence.
    """


class EnrollmentRefusal(enum.IntEnum):
    """Closed E1 refusal reasons a platform verifier reports (design §2.4, codes 1–10).

    Codes 11 (AccountNotApproved) and 12 (AccountFrozen) are eligibility outcomes the issuer
    owns; an attestation verifier never reports them. Zero and unknown codes are protocol
    errors, never admission.
    """

    KEY_NOT_IN_SECURE_HARDWARE = 1
    ATTESTATION_WITHOUT_APP_IDENTITY = 2
    BOOTLOADER_UNLOCKED = 3
    BOOT_NOT_VERIFIED = 4
    UNTRUSTED_ATTESTATION_ROOT = 5
    ATTESTATION_REVOKED = 6
    APP_IDENTITY_MISMATCH = 7
    APP_VERSION_BELOW_MINIMUM = 8
    EVIDENCE_INVALID = 9
    CHALLENGE_EXPIRED = 10


class EvidenceRefused(AttestationRejected):
    """The evidence fails one admission check; ``code`` is its closed refusal reason."""

    def __init__(self, code: EnrollmentRefusal, message: str) -> None:
        super().__init__(message)
        self.code = EnrollmentRefusal(code)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AttestationRejected(message)


def demand(condition: bool, code: EnrollmentRefusal, message: str) -> None:
    """Refuse the evidence with ``code`` unless ``condition`` holds."""
    if not condition:
        raise EvidenceRefused(code, message)


@contextmanager
def refusal_stage(code: EnrollmentRefusal) -> Iterator[None]:
    """Classify an untyped evidence rejection inside one admission step as ``code``.

    Typed refusals and unavailability pass through unchanged, so the first failing step
    keeps its own reason.
    """
    try:
        yield
    except (EvidenceRefused, VerificationUnavailable):
        raise
    except AttestationRejected as error:
        raise EvidenceRefused(code, str(error)) from None


def fixed32(value: bytes, name: str) -> bytes:
    require(type(value) is bytes and len(value) == 32 and any(value), f"invalid {name}")
    return value


def device_key_reference(public_key_sec1: bytes) -> bytes:
    """Derive the canonical Iroha device-key reference from its P-256 point."""
    require(len(public_key_sec1) == 65 and public_key_sec1[0] == 4,
            "invalid device public key")
    return hashlib.sha256(DEVICE_KEY_REFERENCE_DOMAIN + public_key_sec1).digest()


@dataclass(frozen=True)
class AndroidPatchLevels:
    """Hardware-enforced OS facts of the trusted key description.

    Values are the exact signed integers (``None`` when the hardware list omits the tag).
    They describe the device when the key was generated, not a live examination.
    Software-enforced copies are never read.
    """

    attestation_version: int
    os_version: int | None
    os_patch_level: int | None
    vendor_patch_level: int | None
    boot_patch_level: int | None


@dataclass(frozen=True)
class RawPlatformProof:
    """Checked Apple App Attest key identity; deliberately not an issuance token."""

    evidence_sha256: bytes
    attested_public_key_sec1: bytes
    device_key_reference: bytes
    platform: str
    apple_validation_category: int | None = None
    apple_bundle_version: str | None = None


def patch_level_yyyymm(value: int) -> int | None:
    """Normalize a KeyMint patch level (YYYYMM or YYYYMMDD) to YYYYMM.

    Returns ``None`` for any other value. Zero means "not reported" and is
    handled by the caller.
    """
    if type(value) is not int:
        return None
    if 19000101 <= value <= 99991231:
        value //= 100
    if 190001 <= value <= 999912 and 1 <= value % 100 <= 12:
        return value
    return None


def validate_android_patch_floor(floor_yyyymm: int) -> int:
    """Check a configured enrollment patch floor (YYYYMM) and return it.

    A malformed floor is a configuration fault, so this raises rather than
    letting every device appear to miss the policy.
    """
    require(type(floor_yyyymm) is int and patch_level_yyyymm(floor_yyyymm) == floor_yyyymm,
            "invalid Android patch floor")
    return floor_yyyymm


def android_patch_policy_met(levels: AndroidPatchLevels, floor_yyyymm: int) -> bool:
    """Whether verified patch levels meet an enrollment floor.

    This is the evidence-record fact ``PATCH_POLICY_MET`` (fact bit 4,
    ``specs/kagemusha_wallet_wire_v1.md`` §3.1). An unmet floor is a recorded fact, never
    a refusal. The policy is met when the hardware-enforced OS patch level is present and
    every reported OS, vendor or boot level parses and is at least ``floor_yyyymm``; a
    vendor or boot level of zero or an absent tag means "not reported". Only an invalid
    floor or levels object raises.
    """
    require(type(levels) is AndroidPatchLevels
            and all(level is None or type(level) is int
                    for level in (levels.os_patch_level, levels.vendor_patch_level,
                                  levels.boot_patch_level)),
            "verified Android patch levels absent")
    floor = validate_android_patch_floor(floor_yyyymm)
    if levels.os_patch_level is None or levels.os_patch_level == 0:
        return False
    for level in (levels.os_patch_level, levels.vendor_patch_level, levels.boot_patch_level):
        if level is None or level == 0:
            continue
        normalized = patch_level_yyyymm(level)
        if normalized is None or normalized < floor:
            return False
    return True


@dataclass(frozen=True)
class AppleAssertion:
    """Verified Apple assertion metadata, not a certificate-issuance token.

    The caller must atomically store ``counter`` against its previously attested
    key and consume the independently issued challenge. This value alone does
    not establish a distributed app release or offline monetary state.
    """

    counter: int
    assertion_sha256: bytes
    client_data_sha256: bytes
    validation_category: int | None
    bundle_version: str | None


class CborReader:
    def __init__(self, data: bytes) -> None:
        require(len(data) <= MAX_OBJECT, "CBOR object too large")
        self.data = data
        self.offset = 0

    def read(self, depth: int = 0) -> Any:
        require(depth <= 8 and self.offset < len(self.data), "invalid CBOR nesting")
        initial = self.data[self.offset]
        self.offset += 1
        major, argument = initial >> 5, initial & 31
        require(argument != 31, "indefinite CBOR is unsupported")
        length_bytes = (0, 1, 2, 4, 8)
        if argument < 24:
            length = argument
        else:
            require(argument <= 27, "invalid CBOR length")
            count = length_bytes[argument - 23]
            require(self.offset + count <= len(self.data), "truncated CBOR length")
            length = int.from_bytes(self.data[self.offset : self.offset + count], "big")
            self.offset += count
            require(length >= (24 if count == 1 else 1 << ((count // 2) * 8)), "nonminimal CBOR length")
        if major in (0, 1):
            return length if major == 0 else -1 - length
        if major in (2, 3):
            require(self.offset + length <= len(self.data), "truncated CBOR value")
            raw = self.data[self.offset : self.offset + length]
            self.offset += length
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise AttestationRejected("invalid CBOR text") from error
        if major in (4, 5):
            require(length <= 64, "CBOR container too large")
            if major == 4:
                return [self.read(depth + 1) for _ in range(length)]
            result: dict[Any, Any] = {}
            for _ in range(length):
                key = self.read(depth + 1)
                require(isinstance(key, (str, int, bytes)) and key not in result, "duplicate or invalid CBOR map key")
                result[key] = self.read(depth + 1)
            return result
        raise AttestationRejected("unsupported CBOR type")


def cbor_exact(data: bytes) -> Any:
    reader = CborReader(data)
    value = reader.read()
    require(reader.offset == len(data), "trailing CBOR bytes")
    return value


@dataclass(frozen=True)
class DerValue:
    tag_class: int
    constructed: bool
    number: int
    value: bytes


def der_one(data: bytes) -> DerValue:
    value, end = der_at(data, 0)
    require(end == len(data), "trailing DER bytes")
    return value


def der_at(data: bytes, offset: int) -> tuple[DerValue, int]:
    require(offset < len(data), "truncated DER tag")
    first = data[offset]
    offset += 1
    tag_class, constructed, number = first >> 6, bool(first & 32), first & 31
    if number == 31:
        number = 0
        for index in range(4):
            require(offset < len(data), "truncated DER tag number")
            part = data[offset]
            offset += 1
            require(index != 0 or part != 0x80, "nonminimal DER tag number")
            number = (number << 7) | (part & 127)
            if part < 128:
                break
        else:
            raise AttestationRejected("DER tag number too large")
        require(number >= 31, "nonminimal DER tag number")
    require(offset < len(data), "truncated DER length")
    first_length = data[offset]
    offset += 1
    if first_length < 128:
        length = first_length
    else:
        count = first_length & 127
        require(1 <= count <= 4 and offset + count <= len(data), "invalid DER length")
        require(data[offset] != 0, "nonminimal DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        require(length >= 128, "nonminimal DER length")
    require(offset + length <= len(data), "truncated DER value")
    return DerValue(tag_class, constructed, number, data[offset : offset + length]), offset + length


def der_encode(value: DerValue) -> bytes:
    """Re-encode one parsed DER element; exact because the parser admits only minimal DER."""
    head = (value.tag_class << 6) | (32 if value.constructed else 0)
    if value.number < 31:
        tag = bytes([head | value.number])
    else:
        parts = [value.number & 127]
        number = value.number >> 7
        while number:
            parts.insert(0, 128 | (number & 127))
            number >>= 7
        tag = bytes([head | 31, *parts])
    size = len(value.value)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([128 | len(raw)]) + raw
    return tag + length + value.value


def children(value: DerValue, number: int = 16, tag_class: int = 0) -> list[DerValue]:
    require(value.tag_class == tag_class and value.number == number and value.constructed, "unexpected DER container")
    result = []
    offset = 0
    while offset < len(value.value):
        child, offset = der_at(value.value, offset)
        result.append(child)
        require(len(result) <= 64, "too many DER children")
    return result


def primitive(value: DerValue, number: int) -> bytes:
    require(value.tag_class == 0 and value.number == number and not value.constructed, "unexpected DER primitive")
    return value.value


def positive_integer(value: DerValue, number: int = 2) -> int:
    raw = primitive(value, number)
    require(bool(raw) and raw[0] < 128 and (len(raw) == 1 or raw[0] != 0 or raw[1] >= 128), "invalid DER integer")
    return int.from_bytes(raw, "big")


def der_boolean(value: DerValue) -> bool:
    raw = primitive(value, 1)
    require(raw in (b"\x00", b"\xff"), "invalid DER boolean")
    return raw == b"\xff"


def oid(value: DerValue) -> str:
    raw = primitive(value, 6)
    require(bool(raw), "empty DER OID")
    numbers = []
    current = 0
    component_start = True
    for byte in raw:
        require(not (component_start and byte == 0x80), "nonminimal DER OID component")
        current = (current << 7) | (byte & 127)
        require(current < 1 << 40, "DER OID component too large")
        if byte < 128:
            numbers.append(current)
            current = 0
            component_start = True
        else:
            component_start = False
    require(raw[-1] < 128 and bool(numbers), "truncated DER OID")
    first = numbers.pop(0)
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return ".".join(str(part) for part in (*head, *numbers))


def _x509_extensions(tbs: list[DerValue], start: int, version: int) -> dict[str, tuple[bool, bytes]]:
    extensions: dict[str, tuple[bool, bytes]] = {}
    prior_optional = 0
    for field in tbs[start + 6 :]:
        # RFC 5280 permits issuerUniqueID [1], subjectUniqueID [2], then one
        # extensions [3] field. Accepting a second [3] lets a different X.509
        # parser and this verifier disagree on which attestation claim was signed.
        require(field.tag_class == 2 and field.number in (1, 2, 3)
                and field.number > prior_optional, "duplicate or misplaced X.509 optional field")
        prior_optional = field.number
        if field.number in (1, 2):
            require(not field.constructed and bool(field.value)
                    and field.value[0] <= 7
                    and (len(field.value) > 1 or field.value[0] == 0)
                    and (field.value[0] == 0 or field.value[-1] & ((1 << field.value[0]) - 1) == 0),
                    "invalid X.509 unique identifier")
            continue
        require(version == 2, "X.509 extensions require v3")
        enclosing = children(field, number=3, tag_class=2)
        require(len(enclosing) == 1, "invalid X.509 extensions")
        listed = children(enclosing[0])
        require(bool(listed), "empty X.509 extensions")
        for extension in listed:
            fields = children(extension)
            require(len(fields) in (2, 3), "invalid X.509 extension")
            name = oid(fields[0])
            critical = False
            if len(fields) == 3:
                require(primitive(fields[1], 1) == b"\xff",
                        "invalid X.509 extension critical flag")
                critical = True
            require(name not in extensions, "duplicate X.509 extension")
            extensions[name] = (critical, primitive(fields[-1], 4))
    return extensions


def _x509_tbs(der: bytes) -> tuple[list[DerValue], list[DerValue], int, int]:
    require(0 < len(der) <= MAX_CERT, "certificate outside bound")
    cert = children(der_one(der))
    require(len(cert) == 3, "invalid X.509 certificate")
    tbs = children(cert[0])
    require(bool(tbs), "truncated X.509 TBS")
    start = 1 if tbs[0].tag_class == 2 and tbs[0].number == 0 else 0
    version = 0
    if start:
        encoded_version = children(tbs[0], number=0, tag_class=2)
        require(len(encoded_version) == 1, "invalid X.509 version")
        version = positive_integer(encoded_version[0])
        require(version in (1, 2), "invalid X.509 version")
    require(len(tbs) >= start + 6, "truncated X.509 TBS")
    return cert, tbs, start, version


def certificate_spki_extensions(der: bytes) -> tuple[DerValue, dict[str, bytes]]:
    """Parse a bounded X.509 certificate without assuming its key algorithm."""
    _, tbs, start, version = _x509_tbs(der)
    extensions = _x509_extensions(tbs, start, version)
    return tbs[start + 5], {name: value for name, (_, value) in extensions.items()}


def certificate_key_extensions(der: bytes) -> tuple[bytes, dict[str, bytes]]:
    """Return the P-256 subject point and extensions of one certificate."""
    spki_value, extensions = certificate_spki_extensions(der)
    return p256_point(spki_value), extensions


def p256_point(spki_value: DerValue) -> bytes:
    spki = children(spki_value)
    require(len(spki) == 2, "invalid subject public key")
    algorithm = children(spki[0])
    require(len(algorithm) == 2 and oid(algorithm[0]) == "1.2.840.10045.2.1"
            and oid(algorithm[1]) == "1.2.840.10045.3.1.7", "not P-256 EC public key")
    bit_string = primitive(spki[1], 3)
    require(len(bit_string) == 66 and bit_string[0] == 0 and bit_string[1] == 4, "invalid P-256 point")
    return bit_string[1:]


def spki_sha256(der: bytes) -> bytes:
    """SHA-256 of a certificate's DER ``SubjectPublicKeyInfo``, the root-set pin form."""
    spki, _ = certificate_spki_extensions(der)
    return hashlib.sha256(der_encode(spki)).digest()


def pem(der: bytes) -> bytes:
    encoded = base64.b64encode(der)
    lines = b"\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return b"-----BEGIN CERTIFICATE-----\n" + lines + b"\n-----END CERTIFICATE-----\n"


def public_key_pem(spki_der: bytes) -> bytes:
    encoded = base64.b64encode(spki_der)
    lines = b"\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return b"-----BEGIN PUBLIC KEY-----\n" + lines + b"\n-----END PUBLIC KEY-----\n"


def _x509_instant(value: DerValue) -> int:
    require(value.tag_class == 0 and not value.constructed
            and value.number in (23, 24), "invalid X.509 time type")
    raw = value.value
    digits = raw[:-1]
    expected = 12 if value.number == 23 else 14
    require(len(raw) == expected + 1 and raw[-1:] == b"Z"
            and all(48 <= byte <= 57 for byte in digits), "invalid X.509 time")
    if value.number == 23:
        year = int(digits[:2])
        year += 1900 if year >= 50 else 2000
        offset = 2
    else:
        year = int(digits[:4])
        offset = 4
    try:
        date = datetime.datetime(
            year, *(int(digits[index:index + 2])
                    for index in range(offset, expected, 2)),
            tzinfo=datetime.timezone.utc,
        )
    except ValueError as error:
        raise AttestationRejected("invalid X.509 calendar time") from error
    return int(date.timestamp() * 1000)


def _validity_interval(tbs: list[DerValue], start: int) -> tuple[int, int]:
    interval = children(tbs[start + 3])
    require(len(interval) == 2, "invalid X.509 validity interval")
    before, after = (_x509_instant(value) for value in interval)
    return before, after


def _certificate_valid_at(der: bytes, trusted_time_ms: int) -> bool:
    """Check the two canonical RFC 5280 UTC validity fields at a trusted time."""
    _, tbs, start, _ = _x509_tbs(der)
    before, after = _validity_interval(tbs, start)
    require(before < after, "invalid X.509 validity order")
    return before <= trusted_time_ms <= after


def _openssl(openssl_path: Path, arguments: list[str]) -> bool:
    """Run one bounded OpenSSL check; a tool failure is unavailability, never a verdict."""
    try:
        result = subprocess.run([str(openssl_path), *arguments], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=_OPENSSL_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        raise VerificationUnavailable("OpenSSL verifier unavailable") from None
    return result.returncode == 0


def verify_pinned_chain(
    chain_der: list[bytes], root_der: bytes, root_sha256: bytes,
    trusted_time_ms: int, openssl_path: Path,
) -> None:
    """Verify one exact leaf-to-root path to a DER-pinned root (Apple App Attest)."""
    require(2 <= len(chain_der) <= MAX_CHAIN and all(0 < len(cert) <= MAX_CERT for cert in chain_der), "certificate chain outside bound")
    require(0 < len(root_der) <= MAX_CERT and hashlib.sha256(root_der).digest() == fixed32(root_sha256, "root pin"), "untrusted root")
    require(trusted_time_ms > 0 and openssl_path.is_absolute() and openssl_path.is_file(), "invalid verification environment")
    # X.509 path builders treat -untrusted as a pool, not an ordered chain. Do
    # not interpret an extension from a supplied certificate that OpenSSL could
    # have ignored. Require every supplied certificate to be one exact
    # leaf-to-root path, allowing the pinned root to be supplied or implicit.
    require(len(set(chain_der)) == len(chain_der)
            and root_der not in chain_der[:-1], "duplicate or misplaced certificate")
    path_der = chain_der if chain_der[-1] == root_der else [*chain_der, root_der]
    _verify_exact_path(path_der, ["-attime", str(trusted_time_ms // 1000)], openssl_path)


def _verify_exact_path(path_der: list[bytes], time_option: list[str], openssl_path: Path) -> None:
    """OpenSSL verification of an exact leaf-first path whose last element is the anchor."""
    with tempfile.TemporaryDirectory(prefix="kagemusha-attestation-") as temporary:
        directory = Path(temporary)
        root = directory / "root.pem"
        leaf = directory / "leaf.pem"
        intermediates = directory / "intermediates.pem"
        root.write_bytes(pem(path_der[-1]))
        leaf.write_bytes(pem(path_der[0]))
        intermediates.write_bytes(b"".join(pem(cert) for cert in path_der[1:-1]) or pem(path_der[-1]))
        require(_openssl(openssl_path, [
            "verify", "-no-CAfile", "-no-CApath", "-no-CAstore", "-check_ss_sig",
            "-trusted", str(root), "-untrusted", str(intermediates), *time_option, str(leaf),
        ]), "certificate chain rejected")
        for index, (child_der, issuer_der) in enumerate(zip(path_der, path_der[1:])):
            child_path = directory / f"path-{index}-child.pem"
            issuer_path = directory / f"path-{index}-issuer.pem"
            child_path.write_bytes(pem(child_der))
            issuer_path.write_bytes(pem(issuer_der))
            require(_openssl(openssl_path, [
                "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                "-partial_chain", "-trusted", str(issuer_path), *time_option, str(child_path),
            ]), "certificate chain order or link rejected")


# ----------------------------------------------------------------------------------------
# Android adapter profiles, root anchors and the ordered admission steps
# ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AndroidAdapterProfile:
    """Reviewed issuer code that validates a chain to one pinned root family.

    ``qualified`` is set only by a reviewed release after genuine device chains and
    enrollment tests qualify the profile; the issuer refuses a policy naming an unqualified
    profile at configuration. ``factory_validity_exemption`` admits the documented
    factory-provisioned profile under the GoogleRsa root only.
    """

    adapter_id: str
    qualified: bool
    signature_algorithms: frozenset
    critical_extensions: frozenset
    provisioning_information: bool
    factory_validity_exemption: bool
    documented_deviations: tuple = ()


# Google's verification procedure and AOSP schema:
# https://developer.android.com/privacy-and-security/security-key-attestation
# Every certificate's validity is evaluated, except in the documented factory-provisioned
# profile under the GoogleRsa root: Google recommends trusting certificates that chain to
# SERIALNUMBER=f92009e853b6b045 regardless of validity, while remotely provisioned (RKP)
# certificates keep their validity checks. A chain is factory-provisioned only when it has
# no provisioning information extension, has at least three certificates and the
# certificate the root issued names a subject serialNumber (2.5.4.5) attribute, which is how
# Google's own key attestation verifier identifies factory chains. Any other chain, including
# every other chain to the RSA root, is evaluated as remotely provisioned.
GOOGLE_ADAPTER_PROFILE = AndroidAdapterProfile(
    adapter_id="google",
    qualified=True,
    signature_algorithms=_SIGNATURE_ALGORITHMS,
    critical_extensions=frozenset({_BASIC_CONSTRAINTS_OID, _KEY_USAGE_OID}),
    provisioning_information=True,
    factory_validity_exemption=True,
)
# Candidate Huawei profile; no Huawei-rooted AndroidKeyStore chain has established this
# AOSP key description variant. Huawei HUKS device certificates are a separate evidence
# source, including on Android/EMUI, and their roots alone do not establish this profile.
# TODO: establish the chain shape, extension OIDs, positions and all E1 assertions from
# genuine no-GMS evidence before qualifying this adapter. For this candidate, Android
# admission steps 4–9 apply unchanged, every certificate's validity is evaluated and
# Google's provisioning information extension is not permitted.
HUAWEI_ADAPTER_PROFILE = AndroidAdapterProfile(
    adapter_id="huawei",
    qualified=False,
    signature_algorithms=_SIGNATURE_ALGORITHMS,
    critical_extensions=frozenset({_BASIC_CONSTRAINTS_OID, _KEY_USAGE_OID}),
    provisioning_information=False,
    factory_validity_exemption=False,
)
# Vendor adapter identifiers this verifier implements. Matches Native's
# ANDROID_VENDOR_ADAPTER_PROFILES_V1 qualification table.
ANDROID_VENDOR_ADAPTER_PROFILES = {"huawei": HUAWEI_ADAPTER_PROFILE}

ANDROID_ROOT_FAMILIES = ("google_rsa", "google_ca1", "vendor")
ANDROID_REVOCATION_SOURCES = ("google_attestation_status", "operator_denylist")


def android_adapter_profile(family: str, adapter_id: str | None) -> AndroidAdapterProfile:
    """Select the implemented and qualified profile of one root entry.

    An unknown or unqualified adapter is a configuration failure, never an E1 outcome.
    """
    require(family in ANDROID_ROOT_FAMILIES, "invalid Android root family")
    if family != "vendor":
        require(adapter_id is None, "Google root names an adapter")
        return GOOGLE_ADAPTER_PROFILE
    profile = ANDROID_VENDOR_ADAPTER_PROFILES.get(adapter_id)  # type: ignore[arg-type]
    require(profile is not None, "unknown Android adapter profile")
    require(profile.qualified, "unqualified Android adapter profile")
    return profile


@dataclass(frozen=True)
class AndroidTrustAnchor:
    """One pinned Android root: family, SPKI pin, revocation source and its profile."""

    family: str
    spki_sha256: bytes
    revocation_source: str
    profile: AndroidAdapterProfile

    def validate(self) -> None:
        require(self.family in ANDROID_ROOT_FAMILIES
                and self.revocation_source in ANDROID_REVOCATION_SOURCES
                and type(self.profile) is AndroidAdapterProfile, "invalid Android root anchor")
        fixed32(self.spki_sha256, "Android root SPKI pin")
        require((self.revocation_source == "operator_denylist") == (self.family == "vendor"),
                "Android root family and revocation source differ")
        require((self.profile.adapter_id == "google") == (self.family != "vendor"),
                "Android root family and adapter profile differ")


@dataclass(frozen=True)
class AndroidChainMember:
    """Revocation identity of one chain certificate; index 0 is the leaf."""

    serial: int
    spki_sha256: bytes


@dataclass(frozen=True)
class AndroidKeyAttestation:
    """Facts of one admitted KeyMint chain; never an issuance token."""

    anchor: AndroidTrustAnchor
    security_level: int
    attestation_version: int
    keymint_version: int
    factory_provisioned: bool
    package_version: int
    patch_levels: AndroidPatchLevels


@dataclass(frozen=True)
class _Certificate:
    der: bytes
    serial: int
    signature_algorithm: bytes
    outer_signature_algorithm: bytes
    signature_algorithm_oid: str
    issuer: bytes
    subject: bytes
    subject_attributes: frozenset
    not_before_ms: int
    not_after_ms: int
    spki: DerValue
    spki_sha256: bytes
    extensions: dict


def _name_attributes(name: DerValue) -> frozenset:
    attributes = set()
    for relative in children(name):
        for attribute in children(relative, number=17):
            fields = children(attribute)
            require(len(fields) == 2, "invalid X.509 name attribute")
            attributes.add(oid(fields[0]))
    return frozenset(attributes)


def _parse_android_certificate(der: bytes) -> _Certificate:
    cert, tbs, start, version = _x509_tbs(der)
    serial = positive_integer(tbs[start])
    require(0 < serial < (1 << 160), "X.509 serial outside bound")
    signature = der_encode(tbs[start + 1])
    outer = der_encode(cert[1])
    algorithm = children(tbs[start + 1])
    require(1 <= len(algorithm) <= 2, "invalid X.509 signature algorithm")
    algorithm_oid = oid(algorithm[0])
    primitive(cert[2], 3)
    before, after = _validity_interval(tbs, start)
    spki = tbs[start + 5]
    children(spki)
    return _Certificate(
        der, serial, signature, outer, algorithm_oid,
        der_encode(tbs[start + 2]), der_encode(tbs[start + 4]),
        _name_attributes(tbs[start + 4]), before, after, spki,
        hashlib.sha256(der_encode(spki)).digest(), _x509_extensions(tbs, start, version),
    )


def _basic_constraints(value: bytes) -> tuple[bool, int | None]:
    fields = children(der_one(value))
    require(len(fields) <= 2, "invalid basic constraints")
    ca, path_length = False, None
    for index, field in enumerate(fields):
        if field.number == 1 and index == 0:
            ca = der_boolean(field)
        else:
            require(path_length is None, "invalid basic constraints")
            path_length = positive_integer(field)
    return ca, path_length


def _key_usage(value: bytes) -> int:
    raw = primitive(der_one(value), 3)
    require(bool(raw) and raw[0] <= 7 and (len(raw) > 1 or raw[0] == 0), "invalid key usage")
    bits = 0
    for index, byte in enumerate(raw[1:3]):
        bits |= byte << (8 * (1 - index))
    return bits  # digitalSignature is 0x8000, keyCertSign is 0x0400


def _android_path(certificates: list[_Certificate], anchor: AndroidTrustAnchor,
                  trusted_time_ms: int, openssl_path: Path) -> bool:
    """Admission step 2 under the anchor's profile; returns whether factory-provisioned."""
    profile = anchor.profile
    for index, certificate in enumerate(certificates):
        require(certificate.signature_algorithm == certificate.outer_signature_algorithm
                and certificate.signature_algorithm_oid in profile.signature_algorithms,
                "certificate signature algorithm outside adapter profile")
        algorithm = children(der_one(certificate.signature_algorithm))
        if certificate.signature_algorithm_oid in _RSA_SIGNATURE_ALGORITHMS:
            require(len(algorithm) == 1 or primitive(algorithm[1], 5) == b"",
                    "invalid RSA signature parameters")
        else:
            require(len(algorithm) == 1, "invalid ECDSA signature parameters")
        critical = {name for name, (flag, _) in certificate.extensions.items() if flag}
        require(critical <= profile.critical_extensions,
                "critical extension outside adapter profile")
        constraints = certificate.extensions.get(_BASIC_CONSTRAINTS_OID)
        usage = certificate.extensions.get(_KEY_USAGE_OID)
        if index == 0:
            # The trusted attestation certificate is not a CA and, where it carries key
            # usage, permits digital signatures.
            require(constraints is None or not _basic_constraints(constraints[1])[0],
                    "attestation certificate is a CA")
            require(usage is None or _key_usage(usage[1]) & 0x8000,
                    "attestation certificate key usage forbids signatures")
        else:
            require(constraints is not None, "issuing certificate lacks basic constraints")
            ca, path_length = _basic_constraints(constraints[1])
            require(ca, "issuing certificate is not a CA")
            require(path_length is None or index - 1 <= path_length,
                    "path length constraint exceeded")
            require(usage is None or _key_usage(usage[1]) & 0x0400,
                    "issuing certificate key usage forbids certificate signing")
    factory = (profile.factory_validity_exemption and anchor.family == "google_rsa"
               and len(certificates) >= 3
               and not any(ANDROID_PROVISIONING_INFORMATION_OID in certificate.extensions
                           for certificate in certificates)
               and _SERIAL_NUMBER_ATTRIBUTE_OID in certificates[-2].subject_attributes)
    for certificate in certificates:
        require(certificate.not_before_ms < certificate.not_after_ms,
                "invalid X.509 validity order")
        require(certificate.not_before_ms <= trusted_time_ms, "certificate not yet valid")
        require(factory or trusted_time_ms <= certificate.not_after_ms,
                "certificate expired at trusted verification time")
    time_option = ["-no_check_time"] if factory else ["-attime", str(trusted_time_ms // 1000)]
    _verify_exact_path([certificate.der for certificate in certificates], time_option,
                       openssl_path)
    return factory


def _authorization_list(value: DerValue) -> dict[int, DerValue]:
    """Decode one AuthorizationList: documented fields are type-checked, unknown ignored."""
    result: dict[int, DerValue] = {}
    prior = -1
    for field in children(value):
        require(field.tag_class == 2 and field.constructed,
                "KeyMint authorization is not an explicit context tag")
        require(field.number > prior, "duplicate or out-of-order KeyMint authorization tag")
        prior = field.number
        item = der_one(field.value)
        if field.number in _AUTH_SET_OF_INTEGER:
            for member in children(item, number=17):
                positive_integer(member)
        elif field.number in _AUTH_INTEGER:
            positive_integer(item)
        elif field.number in _AUTH_NULL:
            require(primitive(item, 5) == b"", "invalid KeyMint NULL authorization")
        elif field.number in _AUTH_OCTET_STRING:
            primitive(item, 4)
        elif field.number == ANDROID_ROOT_OF_TRUST_TAG:
            children(item)
        else:
            continue
        result[field.number] = item
    return result


def _integer_set(value: DerValue) -> frozenset:
    return frozenset(positive_integer(member) for member in children(value, number=17))


def recheck_retained_android_chain_revocation(chain_der, anchors, revocation) -> None:
    """Refresh revocation only for originals already authenticated by the private owner.

    This parses the retained chain with the existing certificate parser and selects its
    configured root. It does not admit a key, re-run enrollment, or extend its lifetime.
    """
    chain = tuple(chain_der)
    require(2 <= len(chain) <= MAX_CHAIN
            and all(type(cert) is bytes and 0 < len(cert) <= MAX_CERT for cert in chain)
            and sum(len(cert) for cert in chain) <= MAX_ANDROID_CHAIN_BYTES,
            "retained Android chain outside shape")
    certificates = tuple(_parse_android_certificate(cert) for cert in chain)
    roots = tuple(anchors)
    for anchor in roots:
        anchor.validate()
    matched = tuple(anchor for anchor in roots if anchor.spki_sha256 == certificates[-1].spki_sha256)
    require(len(matched) == 1, "retained Android root differs from selected policy")
    revocation(tuple(AndroidChainMember(cert.serial, cert.spki_sha256) for cert in certificates),
               matched[0])


def verify_android_key_attestation(
    chain_der: Sequence[bytes], *, challenge_digest: bytes, payment_key_sec1: bytes,
    package_name: str, minimum_package_version: int, signer_set: Sequence[bytes],
    anchors: Sequence[AndroidTrustAnchor],
    revocation: Callable[[tuple, AndroidTrustAnchor], None],
    trusted_time_ms: Callable[[], int], openssl_path: Path,
) -> AndroidKeyAttestation:
    """Admit one KeyMint chain under the policy's root set, in Android admission order.

    ``revocation(members, anchor)`` checks the anchor's named source and the operator
    denylist; it raises ``EvidenceRefused`` (code 6) or ``VerificationUnavailable``.
    ``trusted_time_ms`` samples the issuer's trusted verification time. Invalid selected
    inputs are configuration errors and raise an untyped ``AttestationRejected``.
    """
    fixed32(challenge_digest, "E1 challenge digest")
    require(type(payment_key_sec1) is bytes and len(payment_key_sec1) == 65
            and payment_key_sec1[0] == 4, "invalid payment key")
    require(type(package_name) is str and 0 < len(package_name.encode("utf-8")) <= 255
            and type(minimum_package_version) is int and 0 <= minimum_package_version < (1 << 64),
            "invalid Android app policy")
    signers = tuple(signer_set)
    require(1 <= len(signers) <= 4 and all(type(s) is bytes and len(s) == 32 and any(s) for s in signers)
            and all(a < b for a, b in zip(signers, signers[1:])), "invalid Android signer set")
    roots = tuple(anchors)
    require(1 <= len(roots) <= 8, "invalid Android root set")
    for anchor in roots:
        require(type(anchor) is AndroidTrustAnchor, "invalid Android root anchor")
        anchor.validate()
        require(anchor.profile.qualified, "unqualified Android adapter profile")
    require(callable(revocation) and callable(trusted_time_ms)
            and openssl_path.is_absolute() and openssl_path.is_file(),
            "invalid Android verification environment")

    # Step 1, shape: 2–8 DER certificates, leaf first, each 1–16,384 bytes, ≤ 65,536 total.
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        chain = list(chain_der)
        require(2 <= len(chain) <= MAX_CHAIN
                and all(type(cert) is bytes and 0 < len(cert) <= MAX_CERT for cert in chain)
                and sum(len(cert) for cert in chain) <= MAX_ANDROID_CHAIN_BYTES,
                "Android certificate chain outside shape")
        certificates = [_parse_android_certificate(cert) for cert in chain]

    # Step 2, root and path under the matched root's adapter profile.
    with refusal_stage(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT):
        root = certificates[-1]
        require(root.subject == root.issuer, "chain does not end at a self-signed root")
        anchor = next((item for item in roots if item.spki_sha256 == root.spki_sha256), None)
        require(anchor is not None, "chain root is not in the pinned root set")
        require(len(set(chain)) == len(chain), "duplicate certificate in chain")
        # OpenSSL checks each link's names (canonically) and signature, one link at a time.
        factory = _android_path(certificates, anchor, trusted_time_ms(), openssl_path)

    # Step 3, revocation by the root's named source and the operator denylist.
    revocation(tuple(AndroidChainMember(cert.serial, cert.spki_sha256) for cert in certificates),
               anchor)

    # Step 4, key description of the trusted attestation certificate.
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        described = [index for index, cert in enumerate(certificates)
                     if ANDROID_KEY_DESCRIPTION_OID in cert.extensions]
        require(bool(described), "missing KeyMint key description")
        trusted = max(described)
        require(trusted == 0, "key description outside the trusted attestation certificate")
        provisioned = [index for index, cert in enumerate(certificates)
                       if ANDROID_PROVISIONING_INFORMATION_OID in cert.extensions]
        if provisioned:
            require(anchor.profile.provisioning_information,
                    "provisioning information outside adapter profile")
            require(provisioned == [trusted + 1],
                    "provisioning information is not immediately above the key description")
        require(p256_point(certificates[0].spki) == payment_key_sec1,
                "attestation certificate key differs from payment key")
        description = children(der_one(certificates[0].extensions[ANDROID_KEY_DESCRIPTION_OID][1]))
        require(len(description) == 8, "invalid KeyMint key description")
        version = positive_integer(description[0])
        level = positive_integer(description[1], 10)
        keymint_version = positive_integer(description[2])
        keymint_level = positive_integer(description[3], 10)
        require(primitive(description[4], 4) == challenge_digest,
                "attestation challenge differs from E1")
        primitive(description[5], 4)
    demand(version != 1, EnrollmentRefusal.ATTESTATION_WITHOUT_APP_IDENTITY,
           "attestation version 1 carries no application identity")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require((version, keymint_version) in ANDROID_ATTESTATION_VERSION_PAIRS,
                "undocumented attestation version pair")
        software = _authorization_list(description[6])
        hardware = _authorization_list(description[7])

    # Step 5, secure hardware.
    demand(level == keymint_level and level in (1, 2) and (version != 2 or level == 1),
           EnrollmentRefusal.KEY_NOT_IN_SECURE_HARDWARE, "key is not in secure hardware")

    # Step 6, hardware-enforced key properties and forbidden authorizations.
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require(ANDROID_USAGE_COUNT_LIMIT_TAG not in software
                and ANDROID_USAGE_COUNT_LIMIT_TAG not in hardware,
                "usage-count-limited key")
        require(ANDROID_ALL_APPLICATIONS_TAG not in software
                and ANDROID_ALL_APPLICATIONS_TAG not in hardware,
                "key usable by all applications")
        require(not ANDROID_HARDWARE_KEY_PROPERTY_TAGS.intersection(software)
                and ANDROID_HARDWARE_KEY_PROPERTY_TAGS <= set(hardware),
                "key properties are not hardware-enforced")
        require(_integer_set(hardware[1]) == {2} and positive_integer(hardware[2]) == 3
                and positive_integer(hardware[3]) == 256 and _integer_set(hardware[5]) == {4}
                and positive_integer(hardware[10]) == 1 and positive_integer(hardware[702]) == 0,
                "key is not a generated P-256 SIGN/SHA-256 key")

    # Step 7, application identity.
    tag = ANDROID_ATTESTATION_APPLICATION_ID_TAG
    demand(tag in software or tag in hardware, EnrollmentRefusal.ATTESTATION_WITHOUT_APP_IDENTITY,
           "attestation carries no application identity")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require(not (tag in software and tag in hardware), "application identity appears twice")
        identity = children(der_one(primitive(software.get(tag) or hardware[tag], 4)))
        require(len(identity) == 2, "invalid attestation application identity")
        packages = [children(item) for item in children(identity[0], number=17)]
        require(all(len(item) == 2 for item in packages), "invalid attested package")
        package_names = [primitive(item[0], 4) for item in packages]
        package_versions = [positive_integer(item[1]) for item in packages]
        attested_signers = [primitive(item, 4) for item in children(identity[1], number=17)]
    demand(len(packages) == 1 and package_names[0] == package_name.encode("utf-8"),
           EnrollmentRefusal.APP_IDENTITY_MISMATCH, "attested package differs from app policy")
    demand(bool(attested_signers) and all(signer in signers for signer in attested_signers),
           EnrollmentRefusal.APP_IDENTITY_MISMATCH, "attested signer outside the signer set")
    demand(package_versions[0] >= minimum_package_version,
           EnrollmentRefusal.APP_VERSION_BELOW_MINIMUM, "attested package version below minimum")

    # Step 8, hardware-enforced RootOfTrust in its version's exact DER shape.
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        boot = children(hardware[ANDROID_ROOT_OF_TRUST_TAG])
        require(len(boot) == (3 if version == 2 else 4), "RootOfTrust shape differs from its version")
        boot_key = primitive(boot[0], 4)
        locked = der_boolean(boot[1])
        state = positive_integer(boot[2], 10)
        boot_hash = primitive(boot[3], 4) if version != 2 else None
    demand(locked, EnrollmentRefusal.BOOTLOADER_UNLOCKED, "bootloader is unlocked")
    demand(state == 0 and any(boot_key), EnrollmentRefusal.BOOT_NOT_VERIFIED,
           "verified boot state is not Verified")
    demand(version < 100 or (boot_hash is not None and len(boot_hash) == 32 and any(boot_hash)),
           EnrollmentRefusal.BOOT_NOT_VERIFIED, "KeyMint verified boot hash is invalid")

    # Step 9, hardware-enforced patch levels; the floor sets only a fact.
    def hardware_integer(number: int) -> int | None:
        return positive_integer(hardware[number]) if number in hardware else None

    return AndroidKeyAttestation(
        anchor, level, version, keymint_version, factory, package_versions[0],
        AndroidPatchLevels(version, hardware_integer(ANDROID_OS_VERSION_TAG),
                           hardware_integer(ANDROID_OS_PATCH_LEVEL_TAG),
                           hardware_integer(ANDROID_VENDOR_PATCH_LEVEL_TAG),
                           hardware_integer(ANDROID_BOOT_PATCH_LEVEL_TAG)))


# ----------------------------------------------------------------------------------------
# Apple App Attest
# ----------------------------------------------------------------------------------------


def verify_apple_wallet_attestation_raw(
    attestation_object: bytes, key_id: bytes, app_id: str, environment: str,
    challenge_digest: bytes,
    root_der: bytes, root_sha256: bytes, trusted_time_ms: int, openssl_path: Path,
) -> RawPlatformProof:
    """Current E1 attestation; Apple receives challenge_digest unchanged as clientDataHash.

    The native owner supplies the E1 digest, configured App ID/environment/root and trusted
    time. This authenticates the App Attest key, not the separate Secure Enclave payment key.
    Admission order: frame [9], chain to the pinned root [5], App ID and environment [7],
    then key, counter and nonce [9].
    """
    fixed32(challenge_digest, "App Attest clientDataHash")
    require(type(key_id) is bytes and len(key_id) == 32, "invalid App Attest key ID")
    require(type(app_id) is str and app_id and len(app_id.encode("utf-8")) <= 255, "invalid pinned App ID")
    require(environment in ("production", "development"), "invalid pinned App Attest environment")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require(type(attestation_object) is bytes and len(attestation_object) <= MAX_OBJECT,
                "App Attest object outside bound")
        decoded = cbor_exact(attestation_object)
        require(isinstance(decoded, dict) and set(decoded) == {"fmt", "attStmt", "authData"}, "invalid App Attest frame")
        require(decoded["fmt"] == "apple-appattest" and isinstance(decoded["authData"], bytes), "wrong App Attest format")
        statement = decoded["attStmt"]
        require(isinstance(statement, dict) and set(statement) == {"x5c", "receipt"}, "invalid App Attest statement")
        chain = statement["x5c"]
        require(isinstance(chain, list) and all(isinstance(cert, bytes) for cert in chain)
                and isinstance(statement["receipt"], bytes) and bool(statement["receipt"]), "invalid App Attest evidence")
        auth = decoded["authData"]
        require(len(auth) >= 55 + 32, "truncated App Attest authenticator")
    with refusal_stage(EnrollmentRefusal.UNTRUSTED_ATTESTATION_ROOT):
        verify_pinned_chain(chain, root_der, root_sha256, trusted_time_ms, openssl_path)
    demand(auth[:32] == hashlib.sha256(app_id.encode("utf-8")).digest(),
           EnrollmentRefusal.APP_IDENTITY_MISMATCH, "App ID mismatch")
    aaguid = b"appattest" + b"\0" * 7 if environment == "production" else b"appattestdevelop"
    demand(auth[37:53] == aaguid, EnrollmentRefusal.APP_IDENTITY_MISMATCH,
           "App Attest environment mismatch")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        point, extensions = certificate_key_extensions(chain[0])
        require(auth[32] & 0x40 != 0 and auth[33:37] == b"\0" * 4, "invalid App Attest flags or counter")
        credential_length = int.from_bytes(auth[53:55], "big")
        require(credential_length == 32 and auth[55:87] == key_id, "App Attest credential ID mismatch")
        reader = CborReader(auth[87:])
        cose = reader.read()
        validation_category: int | None = None
        bundle_version: str | None = None
        if reader.offset < len(reader.data):
            # Apple's attested extension map can be present even when the ED flag is
            # clear. The entire authData, including this map, is bound by the nonce.
            authenticator_extensions = reader.read()
            require(isinstance(authenticator_extensions, dict)
                    and set(authenticator_extensions) == {"apple_validation_category_01", "apple_bundle_version_01"},
                    "unsupported App Attest authenticator extension")
            raw_category = authenticator_extensions["apple_validation_category_01"]
            bundle_version = authenticator_extensions["apple_bundle_version_01"]
            require(isinstance(raw_category, bytes) and len(raw_category) == 4
                    and isinstance(bundle_version, str) and 0 < len(bundle_version.encode("utf-8")) <= 128,
                    "invalid Apple distribution extension")
            validation_category = int.from_bytes(raw_category, "little")
            require(validation_category in (2, 3, 4, 5), "unapproved Apple app distribution category")
        else:
            require(auth[32] & 0x80 == 0, "missing App Attest authenticator extension")
        require(reader.offset == len(reader.data), "trailing App Attest authenticator bytes")
        require(isinstance(cose, dict) and cose.get(1) == 2 and cose.get(3) == -7 and cose.get(-1) == 1
                and isinstance(cose.get(-2), bytes) and isinstance(cose.get(-3), bytes), "invalid App Attest COSE key")
        require(point == b"\x04" + cose[-2] + cose[-3] and hashlib.sha256(point).digest() == key_id,
                "App Attest key mismatch")
        extension = extensions.get(APPLE_NONCE_OID)
        require(extension is not None, "missing App Attest nonce extension")
        nonce_sequence = children(der_one(extension))
        require(len(nonce_sequence) == 1, "invalid App Attest nonce extension")
        tagged_nonce = children(nonce_sequence[0], number=1, tag_class=2)
        require(len(tagged_nonce) == 1, "invalid App Attest tagged nonce")
        expected_nonce = hashlib.sha256(auth + challenge_digest).digest()
        require(primitive(tagged_nonce[0], 4) == expected_nonce, "App Attest challenge mismatch")
    return RawPlatformProof(hashlib.sha256(attestation_object).digest(), point,
                            device_key_reference(point), "apple_app_attest",
                            validation_category, bundle_version)


def require_apple_counter_advance(previous: int, observed: int) -> int:
    """Accept only a strictly increasing App Attest assertion counter.

    Apple permits gaps between assertions. This check must be paired with an
    atomic, durable compare-and-update keyed by the attested public key when
    assertions are accepted concurrently or across server processes.
    """
    require(type(previous) is int and type(observed) is int
            and 0 <= previous < (1 << 32) and 0 < observed < (1 << 32)
            and observed > previous,
            "App Attest assertion counter did not advance")
    return observed


def verify_apple_assertion(
    assertion_object: bytes, client_data: bytes, expected_client_data: bytes,
    attested_public_key_sec1: bytes, attested_key_id: bytes, app_id: str,
    previous_counter: int, openssl_path: Path,
    *, expected_validation_category: int | None, expected_bundle_version: str | None,
) -> AppleAssertion:
    """Verify a bounded App Attest assertion against a previously attested key.

    ``expected_client_data`` must come from an independently selected,
    single-use server challenge and operation scope. The caller must consume
    that challenge and atomically persist the returned counter; this helper
    neither owns server state nor authenticates Apple receipts or app release.
    """
    require(type(assertion_object) is bytes and 0 < len(assertion_object) <= MAX_APPLE_ASSERTION,
            "App Attest assertion outside bound")
    require(type(client_data) is bytes and type(expected_client_data) is bytes
            and 0 < len(client_data) <= MAX_APPLE_CLIENT_DATA
            and client_data == expected_client_data,
            "App Attest client data differs from server challenge")
    return _verify_apple_assertion_with_hash(
        assertion_object, hashlib.sha256(client_data).digest(),
        attested_public_key_sec1, attested_key_id, app_id, previous_counter, openssl_path,
        expected_validation_category=expected_validation_category,
        expected_bundle_version=expected_bundle_version)


def verify_apple_wallet_enrollment_assertion(
    assertion_object: bytes, enrollment_key_binding: bytes,
    attested_public_key_sec1: bytes, attested_key_id: bytes, app_id: str,
    previous_counter: int, openssl_path: Path,
) -> AppleAssertion:
    """Current E1 assertion over the unchanged Native-computed enrollment-key-binding H value.

    This checks the real signature and a strictly increasing counter. The issuer must pair
    it with atomic challenge consumption/counter advancement before publishing a result.
    """
    return _verify_apple_assertion_with_hash(
        assertion_object, enrollment_key_binding,
        attested_public_key_sec1, attested_key_id, app_id, previous_counter, openssl_path,
        expected_validation_category=None, expected_bundle_version=None)


def _verify_apple_assertion_with_hash(
    assertion_object: bytes, client_data_hash: bytes,
    attested_public_key_sec1: bytes, attested_key_id: bytes, app_id: str,
    previous_counter: int, openssl_path: Path,
    *, expected_validation_category: int | None, expected_bundle_version: str | None,
) -> AppleAssertion:
    fixed32(client_data_hash, "App Attest assertion clientDataHash")
    require(type(attested_public_key_sec1) is bytes and len(attested_public_key_sec1) == 65
            and attested_public_key_sec1[0] == 4 and type(attested_key_id) is bytes
            and hashlib.sha256(attested_public_key_sec1).digest() == attested_key_id,
            "App Attest assertion key differs from attested key ID")
    require(type(app_id) is str and 0 < len(app_id.encode("utf-8")) <= 255,
            "invalid pinned App ID")
    require((expected_validation_category is None) == (expected_bundle_version is None),
            "incomplete Apple distribution policy")
    if expected_validation_category is not None:
        require(type(expected_validation_category) is int
                and expected_validation_category in (2, 3, 4, 5)
                and type(expected_bundle_version) is str
                and 0 < len(expected_bundle_version.encode("utf-8")) <= 128,
                "invalid Apple distribution policy")
    require(openssl_path.is_absolute() and openssl_path.is_file(),
            "invalid assertion verification environment")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require(type(assertion_object) is bytes and 0 < len(assertion_object) <= MAX_APPLE_ASSERTION,
                "App Attest assertion outside bound")
        assertion = cbor_exact(assertion_object)
        require(isinstance(assertion, dict)
                and set(assertion) == {"signature", "authenticatorData"},
                "invalid App Attest assertion frame")
        signature = assertion["signature"]
        auth = assertion["authenticatorData"]
        require(type(signature) is bytes and 8 <= len(signature) <= 72
                and type(auth) is bytes and 37 <= len(auth) <= MAX_APPLE_ASSERTION,
                "invalid App Attest assertion fields")
        signature_fields = children(der_one(signature))
        require(len(signature_fields) == 2
                and all(0 < positive_integer(field) < (1 << 256) for field in signature_fields),
                "invalid App Attest assertion signature")
    # Apple's documented assertion checks bind RP ID and counter, not a fixed
    # flag value. A physical iPhone assertion used flag 0x40 with exactly 37
    # authenticator bytes; the complete signed body remains authenticated.
    demand(auth[:32] == hashlib.sha256(app_id.encode("utf-8")).digest(),
           EnrollmentRefusal.APP_IDENTITY_MISMATCH, "App Attest assertion App ID mismatch")
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        counter = require_apple_counter_advance(previous_counter,
                                                int.from_bytes(auth[33:37], "big"))
        validation_category: int | None = None
        bundle_version: str | None = None
        if len(auth) > 37:
            extensions = cbor_exact(auth[37:])
            require(isinstance(extensions, dict)
                    and set(extensions) == {"validationCategory", "bundleVersion"},
                    "unsupported App Attest assertion extension")
            raw_category = extensions["validationCategory"]
            bundle_version = extensions["bundleVersion"]
            require(type(raw_category) is bytes and len(raw_category) == 4
                    and type(bundle_version) is str
                    and 0 < len(bundle_version.encode("utf-8")) <= 128,
                    "invalid App Attest assertion distribution extension")
            validation_category = int.from_bytes(raw_category, "little")
            require(validation_category in (2, 3, 4, 5),
                    "unapproved Apple app distribution category")
        if expected_validation_category is not None:
            require(validation_category == expected_validation_category
                    and bundle_version == expected_bundle_version,
                    "Apple assertion distribution policy mismatch")
        # SubjectPublicKeyInfo ::= id-ecPublicKey, prime256v1, uncompressed point.
        spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + attested_public_key_sec1
        with tempfile.TemporaryDirectory(prefix="kagemusha-apple-assertion-") as temporary:
            directory = Path(temporary)
            (directory / "public.pem").write_bytes(public_key_pem(spki))
            # App Attest signs the nonce, which is itself the SHA-256 digest of
            # authenticatorData || clientDataHash. ECDSA-SHA256 hashes that nonce
            # once more as its message; verifying the concatenation is a different
            # signature equation and rejects physical App Attest assertions.
            nonce = hashlib.sha256(auth + client_data_hash).digest()
            (directory / "signed.bin").write_bytes(nonce)
            (directory / "signature.bin").write_bytes(signature)
            require(_openssl(openssl_path, [
                "dgst", "-sha256", "-verify", str(directory / "public.pem"),
                "-signature", str(directory / "signature.bin"), str(directory / "signed.bin"),
            ]), "App Attest assertion signature rejected")
    return AppleAssertion(counter, hashlib.sha256(assertion_object).digest(),
                          client_data_hash,
                          validation_category, bundle_version)


class DurableAppleAssertionCounterStore:
    """Single-host, owner-only register for previously verified App Attest keys.

    A trusted caller must supply ``RawPlatformProof`` returned by
    ``verify_apple_wallet_attestation_raw``. The register never resets an existing counter,
    and one exclusive transaction verifies each assertion, consumes its exact client-data
    digest, and advances the counter. It does not authenticate a release, verify Apple's
    receipt, or prevent offline wallet-state rollback. Multi-host services need a shared
    store with equivalent transactions.
    """

    def __init__(self, path: Path) -> None:
        directory = path.parent
        mode = directory.stat()
        require(path.is_absolute() and not directory.is_symlink() and directory.is_dir()
                and stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid()
                and mode.st_mode & 0o077 == 0,
                "Apple counter store directory must be owner-only")
        require(not path.is_symlink(), "Apple counter store cannot be a symlink")
        if path.exists():
            existing = path.stat()
            require(stat.S_ISREG(existing.st_mode) and existing.st_uid == os.getuid()
                    and existing.st_mode & 0o077 == 0,
                    "Apple counter store must be an owner-only regular file")
        else:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        self.path = path
        with closing(self._connect()) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS apple_keys (
                key_id BLOB PRIMARY KEY NOT NULL,
                point BLOB NOT NULL,
                app_id TEXT NOT NULL,
                environment TEXT NOT NULL,
                counter INTEGER NOT NULL CHECK(counter >= 0 AND counter < 4294967296)
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS apple_client_data (
                client_data_sha256 BLOB PRIMARY KEY NOT NULL,
                key_id BLOB NOT NULL
            )""")
            # A server challenge is single-use across the entire register, not
            # merely once per attested key. Reject an older per-key layout.
            columns = connection.execute("PRAGMA table_info(apple_client_data)").fetchall()
            require([(row[1], row[2], row[3], row[5]) for row in columns] == [
                ("client_data_sha256", "BLOB", 1, 1),
                ("key_id", "BLOB", 1, 0),
            ], "unsupported Apple challenge register layout")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def register_verified_key(self, proof: RawPlatformProof, app_id: str,
                              environment: str) -> bytes:
        """Insert one verified Apple key without resetting an existing counter."""
        point = proof.attested_public_key_sec1
        require(proof.platform == "apple_app_attest"
                and type(point) is bytes and len(point) == 65 and point[0] == 4
                and proof.device_key_reference == device_key_reference(point)
                and type(app_id) is str and 0 < len(app_id.encode("utf-8")) <= 255
                and environment in ("production", "development"),
                "invalid verified Apple key registration")
        key_id = hashlib.sha256(point).digest()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT point, app_id, environment FROM apple_keys WHERE key_id = ?",
                    (key_id,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO apple_keys (key_id, point, app_id, environment, counter) "
                        "VALUES (?, ?, ?, ?, 0)",
                        (key_id, point, app_id, environment),
                    )
                else:
                    require(row == (point, app_id, environment),
                            "Apple key already registered with different scope")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return key_id

    def verify_and_advance(
        self, assertion_object: bytes, client_data: bytes,
        expected_client_data: bytes, key_id: bytes, app_id: str,
        environment: str, openssl_path: Path,
        *, expected_validation_category: int | None,
        expected_bundle_version: str | None,
    ) -> AppleAssertion:
        """Verify, consume client data once, and durably advance one key counter."""
        require(type(client_data) is bytes and type(expected_client_data) is bytes
                and 0 < len(client_data) <= MAX_APPLE_CLIENT_DATA
                and client_data == expected_client_data,
                "App Attest client data differs from server challenge")
        return self._verify_and_advance_hash(
            assertion_object, hashlib.sha256(client_data).digest(), key_id,
            app_id, environment, openssl_path,
            expected_validation_category=expected_validation_category,
            expected_bundle_version=expected_bundle_version)

    def verify_wallet_enrollment_and_advance(
        self, assertion_object: bytes, enrollment_key_binding: bytes,
        key_id: bytes, app_id: str, environment: str, openssl_path: Path,
    ) -> AppleAssertion:
        """Current E1 prehashed assertion, one-use challenge and durable increasing counter.

        The Native issuer supplies enrollment_key_binding and retains its exact result in
        its issuance journal before HTTP exposure. This register does not create credentials
        or authorize retrying an external operation when an original result is missing.
        """
        return self._verify_and_advance_hash(
            assertion_object, enrollment_key_binding, key_id, app_id, environment,
            openssl_path, expected_validation_category=None, expected_bundle_version=None)

    def _verify_and_advance_hash(
        self, assertion_object: bytes, client_data_hash: bytes, key_id: bytes,
        app_id: str, environment: str, openssl_path: Path,
        *, expected_validation_category: int | None,
        expected_bundle_version: str | None,
    ) -> AppleAssertion:
        fixed32(client_data_hash, "registered Apple clientDataHash")
        require(type(key_id) is bytes and len(key_id) == 32,
                "invalid registered Apple key ID")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT point, app_id, environment, counter FROM apple_keys WHERE key_id = ?",
                    (key_id,),
                ).fetchone()
                require(row is not None and row[1] == app_id
                        and row[2] == environment,
                        "unregistered Apple assertion key or scope")
                checked = _verify_apple_assertion_with_hash(
                    assertion_object, client_data_hash,
                    row[0], key_id, app_id, row[3], openssl_path,
                    expected_validation_category=expected_validation_category,
                    expected_bundle_version=expected_bundle_version,
                )
                demand(connection.execute(
                    "SELECT 1 FROM apple_client_data WHERE client_data_sha256 = ?",
                    (checked.client_data_sha256,),
                ).fetchone() is None, EnrollmentRefusal.EVIDENCE_INVALID,
                    "App Attest client data already consumed")
                connection.execute(
                    "INSERT INTO apple_client_data (client_data_sha256, key_id) VALUES (?, ?)",
                    (checked.client_data_sha256, key_id),
                )
                changed = connection.execute(
                    "UPDATE apple_keys SET counter = ? WHERE key_id = ? AND counter = ?",
                    (checked.counter, key_id, row[3]),
                ).rowcount
                require(changed == 1, "Apple assertion counter race")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return checked
