"""First-release E1 policy transcripts matching the Native wallet Model.

These unsigned objects identify actual verifier inputs. Construction, validation and hashing
never authenticate operator approval. Native retains the approved canonical Norito policy
originals and supplies their typed projection; Python does not define another wire codec.
No default policy, root, approval, success flag or signer is provided.

``specs/kagemusha_wallet_enrollment_policy_v1.md`` fixes the transcripts: the Android app arm
pins a package, a minimum package version and a signer set; the Android enrollment arm pins
a root set whose entries name their revocation source, plus the patch floor.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .attestation import (
    ANDROID_REVOCATION_SOURCES, ANDROID_ROOT_FAMILIES, MAX_CERT, AndroidTrustAnchor,
    android_adapter_profile, fixed32, require, validate_android_patch_floor,
)

_PREFIX = b"iroha:kagemusha:wallet:v1:"
_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
_ADAPTER = re.compile(r"[a-z][a-z0-9-]*\Z")
_FAMILY_TAGS = {"google_rsa": 1, "google_ca1": 2, "vendor": 3}
_SOURCE_TAGS = {"google_attestation_status": 1, "operator_denylist": 2}
MAX_ANDROID_SIGNERS = 4
MAX_ANDROID_ROOTS = 8
MAX_ADAPTER_ID_BYTES = 16


def _uint(value: int, bits: int, name: str, positive: bool = False) -> int:
    require(type(value) is int and (1 if positive else 0) <= value < (1 << bits), name)
    return value


def _binding(value: bytes, name: str) -> bytes:
    require(type(value) is bytes and any(fixed32(value, name)), name)
    return value


def _text(value: str, name: str) -> bytes:
    require(type(value) is str, name)
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        require(False, name)
    require(0 < len(raw) <= 255, name)
    return len(raw).to_bytes(4, "little") + raw


def _digest(role: bytes, body: bytes) -> bytes:
    return hashlib.sha256(_PREFIX + role + b"\0" + len(body).to_bytes(8, "little") + body).digest()


@dataclass(frozen=True)
class AndroidAppIdentityV1:
    """Package, minimum attested ``versionCode`` and every released channel's signer."""

    package_name: str
    minimum_package_version: int
    signer_set: tuple

    def transcript(self) -> bytes:
        text = _text(self.package_name, "invalid Android package")
        require(_PACKAGE.fullmatch(self.package_name) is not None, "invalid Android package")
        minimum = _uint(self.minimum_package_version, 64, "invalid minimum package version")
        signers = self.signer_set
        require(type(signers) is tuple and 1 <= len(signers) <= MAX_ANDROID_SIGNERS
                and all(type(signer) is bytes for signer in signers), "invalid Android signer set")
        for signer in signers:
            _binding(signer, "invalid Android signer")
        require(all(a < b for a, b in zip(signers, signers[1:])),
                "Android signer set is not strictly ascending")
        return (b"\1" + text + minimum.to_bytes(8, "little") + bytes([len(signers)])
                + b"".join(signers))


@dataclass(frozen=True)
class AppleAppIdentityV1:
    app_id: str

    def transcript(self) -> bytes:
        return b"\2" + _text(self.app_id, "invalid Apple App ID")


@dataclass(frozen=True)
class WalletAppPolicyV1:
    version: int
    scheme_id: bytes
    identity: AndroidAppIdentityV1 | AppleAppIdentityV1

    def transcript(self) -> bytes:
        require(type(self.version) is int and self.version == 1, "invalid app policy version")
        require(type(self.identity) in (AndroidAppIdentityV1, AppleAppIdentityV1), "invalid app platform")
        return b"\1\0" + _binding(self.scheme_id, "invalid app scheme") + self.identity.transcript()

    def policy_digest(self) -> bytes:
        """NEW app-policy domain; does not authenticate this policy."""
        return _digest(b"app-policy", self.transcript())


@dataclass(frozen=True)
class RegulatoryPolicyV1:
    permitted_controls: int
    blacklist_max_age_ms: int
    time_anchor_max_response_ms: int

    def transcript(self) -> bytes:
        controls = _uint(self.permitted_controls, 32, "invalid regulatory controls")
        age = _uint(self.blacklist_max_age_ms, 64, "invalid blacklist age")
        response = _uint(self.time_anchor_max_response_ms, 64, "invalid time anchor response")
        require(controls & ~7 == 0 and (age == 0 or controls & 1), "invalid regulatory policy")
        require((response > 0) == bool(controls & 6 or age > 0), "invalid regulatory time policy")
        return controls.to_bytes(4, "little") + age.to_bytes(8, "little") + response.to_bytes(8, "little")


@dataclass(frozen=True)
class AndroidRootV1:
    """One pinned root: family, optional Vendor adapter identifier, SPKI pin and source."""

    family: str
    spki_sha256: bytes
    revocation_source: str
    adapter_id: str | None = None

    def transcript(self) -> bytes:
        require(type(self.family) is str and self.family in ANDROID_ROOT_FAMILIES,
                "invalid Android root family")
        require(type(self.revocation_source) is str
                and self.revocation_source in ANDROID_REVOCATION_SOURCES,
                "invalid Android revocation source")
        head = bytes([_FAMILY_TAGS[self.family]])
        if self.family == "vendor":
            require(type(self.adapter_id) is str and _ADAPTER.fullmatch(self.adapter_id) is not None
                    and len(self.adapter_id) <= MAX_ADAPTER_ID_BYTES, "invalid Android adapter id")
            require(self.revocation_source == "operator_denylist",
                    "Vendor root must name the operator denylist")
            head += len(self.adapter_id).to_bytes(4, "little") + self.adapter_id.encode("ascii")
        else:
            require(self.adapter_id is None, "Google root names an adapter")
            require(self.revocation_source == "google_attestation_status",
                    "Google root must name Google's attestation status list")
        return (head + _binding(self.spki_sha256, "invalid Android root SPKI pin")
                + bytes([_SOURCE_TAGS[self.revocation_source]]))

    def anchor(self) -> AndroidTrustAnchor:
        """Resolve the implemented, qualified adapter profile; else a configuration failure."""
        self.transcript()
        anchor = AndroidTrustAnchor(self.family, self.spki_sha256, self.revocation_source,
                                    android_adapter_profile(self.family, self.adapter_id))
        anchor.validate()
        return anchor


@dataclass(frozen=True)
class AndroidEnrollmentPlatformV1:
    root_set: tuple
    patch_floor_yyyymm: int

    def transcript(self) -> bytes:
        roots = self.root_set
        require(type(roots) is tuple and 1 <= len(roots) <= MAX_ANDROID_ROOTS
                and all(type(root) is AndroidRootV1 for root in roots), "invalid Android root set")
        entries = [root.transcript() for root in roots]
        require(all(a.spki_sha256 < b.spki_sha256 for a, b in zip(roots, roots[1:])),
                "Android root set is not strictly ascending by SPKI pin")
        validate_android_patch_floor(self.patch_floor_yyyymm)
        return (b"\1" + bytes([len(roots)]) + b"".join(entries)
                + self.patch_floor_yyyymm.to_bytes(4, "little"))

    def anchors(self) -> tuple:
        self.transcript()
        return tuple(root.anchor() for root in self.root_set)


@dataclass(frozen=True)
class AppleEnrollmentPlatformV1:
    attestation_root_sha256: bytes

    def transcript(self) -> bytes:
        return b"\2" + _binding(self.attestation_root_sha256, "invalid Apple root pin")


@dataclass(frozen=True)
class WalletEnrollmentPolicyV1:
    version: int
    scheme_id: bytes
    asset_digest: bytes
    app_policy: bytes
    platform: AndroidEnrollmentPlatformV1 | AppleEnrollmentPlatformV1
    regulatory_policy: RegulatoryPolicyV1
    challenge_lifetime_ms: int
    attestation_lease_lifetime_ms: int

    def transcript(self) -> bytes:
        require(type(self.version) is int and self.version == 1, "invalid enrollment policy version")
        require(type(self.platform) in (AndroidEnrollmentPlatformV1, AppleEnrollmentPlatformV1), "invalid enrollment platform")
        require(type(self.regulatory_policy) is RegulatoryPolicyV1, "invalid regulator type")
        ttl = _uint(self.challenge_lifetime_ms, 64, "invalid challenge lifetime", True)
        lease = _uint(self.attestation_lease_lifetime_ms, 64, "invalid lease lifetime")
        regulator = self.regulatory_policy.transcript()
        require((lease > 0) == bool(self.regulatory_policy.permitted_controls & 4), "inconsistent lease permission")
        return (b"\1\0" + _binding(self.scheme_id, "invalid enrollment scheme")
                + _binding(self.asset_digest, "invalid enrollment asset") + _binding(self.app_policy, "invalid enrollment app")
                + self.platform.transcript() + regulator + ttl.to_bytes(8, "little") + lease.to_bytes(8, "little"))

    def policy_digest(self) -> bytes:
        """NEW enrollment-policy identity; existing opaque digests have no implied mapping."""
        return _digest(b"enrollment-policy", self.transcript())

    def validate_for_app(self, app: WalletAppPolicyV1) -> None:
        self.transcript()
        require(type(app) is WalletAppPolicyV1 and self.scheme_id == app.scheme_id
                and self.app_policy == app.policy_digest(), "policy app binding differs")
        require((type(app.identity) is AndroidAppIdentityV1) == (type(self.platform) is AndroidEnrollmentPlatformV1),
                "policy platform differs")

    def require_live_challenge(self, created_at_ms: int, now_ms: int) -> None:
        self.transcript()
        created = _uint(created_at_ms, 64, "invalid challenge creation", True)
        now = _uint(now_ms, 64, "invalid challenge time", True)
        expires = _uint(created + self.challenge_lifetime_ms, 64, "challenge expiry overflow", True)
        require(created <= now < expires, "challenge expired or not yet live")

    def lease_expires_at(self, issued_at_ms: int) -> int:
        self.transcript()
        issued = _uint(issued_at_ms, 64, "invalid issuance time", True)
        return (0 if self.attestation_lease_lifetime_ms == 0 else
                _uint(issued + self.attestation_lease_lifetime_ms, 64, "lease expiry overflow", True))


@dataclass(frozen=True)
class ConfiguredWalletEnrollmentPolicyV1:
    """Private projection of selected originals, never a public body.

    Native must authenticate operator selection and compare retained Model policy originals
    before creating this input. Android selects no root original: its chain carries its root,
    matched by SPKI. Apple carries its genuine root DER; hashing verifies consistency only.
    """
    app: WalletAppPolicyV1
    enrollment: WalletEnrollmentPolicyV1
    apple_root_der: bytes | None = None

    def validate(self) -> None:
        require(type(self.enrollment) is WalletEnrollmentPolicyV1, "configured policy absent")
        self.enrollment.validate_for_app(self.app)
        if type(self.enrollment.platform) is AppleEnrollmentPlatformV1:
            require(type(self.apple_root_der) is bytes and 0 < len(self.apple_root_der) <= MAX_CERT
                    and hashlib.sha256(self.apple_root_der).digest()
                    == self.enrollment.platform.attestation_root_sha256,
                    "configured root original differs")
        else:
            require(self.apple_root_der is None, "Android policy carries a root original")
            # Every root names an implemented and qualified adapter profile.
            self.enrollment.platform.anchors()

    def android_anchors(self) -> tuple:
        self.validate()
        require(type(self.enrollment.platform) is AndroidEnrollmentPlatformV1,
                "configured Android platform absent")
        return self.enrollment.platform.anchors()

    def validate_scope(self, challenge_transcript: bytes, created_at_ms: int, now_ms: int) -> None:
        self.validate()
        value = challenge_transcript
        require(type(value) is bytes and len(value) == 194 and value[:2] == b"\1\0"
                and all(any(value[offset:offset + 32]) for offset in range(2, 194, 32)), "invalid E1 transcript")
        require(value[2:34] == self.enrollment.scheme_id and value[34:66] == self.enrollment.asset_digest
                and value[98:130] == self.app.policy_digest()
                and value[130:162] == self.enrollment.policy_digest(), "E1 policy bindings differ")
        self.enrollment.require_live_challenge(created_at_ms, now_ms)
