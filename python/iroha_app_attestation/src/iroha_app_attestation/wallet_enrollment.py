"""Current E1 enrollment evidence from the retained real platform verifiers.

The private Native issuer selects the scope and operator policy. Public requests contain raw
platform evidence only: the Android KeyMint certificate chain, or the Apple App Attest
attestation and key-binding assertion. Never roots, policies, a vendor online verdict, an
issuer key or a success flag. These results are evidence records, not signing authority or
monetary grants. Native DATA must retain/consume the original E1 and issuer result before
exposure; credential signing remains the Enrollment-role Native owner.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .native_time_interval import NativeTimeInterval

from .attestation import (
    DurableAppleAssertionCounterStore, EnrollmentRefusal, android_patch_policy_met,
    refusal_stage, require, verify_android_key_attestation, verify_apple_wallet_attestation_raw,
)
from .wallet_policy import (
    AndroidAppIdentityV1, AndroidEnrollmentPlatformV1, AppleAppIdentityV1,
    AppleEnrollmentPlatformV1, ConfiguredWalletEnrollmentPolicyV1,
)

_PREFIX = b"iroha:kagemusha:wallet:v1:"

# Evidence-record fact bits (specs/kagemusha_wallet_wire_v1.md §3.1).
# Bit 9 is reserved zero for all evidence records.
FACT_HARDWARE_BACKED_KEY = 1 << 0
FACT_STRONGBOX = 1 << 1
FACT_BOOTLOADER_LOCKED = 1 << 2
FACT_VERIFIED_BOOT = 1 << 3
FACT_PATCH_POLICY_MET = 1 << 4
FACT_APP_SIGNING_IDENTITY = 1 << 5
FACT_APP_ATTEST_GENUINE_DEVICE = 1 << 6
FACT_APP_ATTEST_KEY_BINDING = 1 << 7
FACT_APP_ATTEST_PRODUCTION = 1 << 8
FACT_REVOCATION_LIST_CLEAR = 1 << 10
ANDROID_ADMITTED_FACTS = (FACT_HARDWARE_BACKED_KEY | FACT_BOOTLOADER_LOCKED | FACT_VERIFIED_BOOT
                          | FACT_APP_SIGNING_IDENTITY | FACT_REVOCATION_LIST_CLEAR)
APPLE_ADMITTED_FACTS = (FACT_APP_ATTEST_GENUINE_DEVICE | FACT_APP_ATTEST_KEY_BINDING
                        | FACT_APP_ATTEST_PRODUCTION)


def _digest(role: bytes, body: bytes) -> bytes:
    return hashlib.sha256(_PREFIX + role + b"\0" + len(body).to_bytes(8, "little") + body).digest()


@dataclass(frozen=True)
class WalletEnrollmentScope:
    """Native-selected exact E1 transcript and separately validated P256 payment public key.

    The transcript is LE16 version then six nonzero32 fields: scheme, asset, canonical
    account digest, app policy, enrollment policy and issuer nonce. The Native owner checks
    its account/current activation and authenticates its configured policy before selection.
    This parser by itself creates none of that authority.
    """
    challenge_transcript: bytes
    payment_key_sec1: bytes

    def validate(self) -> None:
        value = self.challenge_transcript
        require(type(value) is bytes and len(value) == 194 and value[:2] == b"\x01\0"
                and all(any(value[offset:offset + 32]) for offset in range(2, 194, 32)),
                "invalid current E1 transcript")
        require(type(self.payment_key_sec1) is bytes and len(self.payment_key_sec1) == 65
                and self.payment_key_sec1[0] == 4, "invalid current E1 payment key")

    def challenge_digest(self) -> bytes:
        self.validate()
        return _digest(b"enrollment-challenge", self.challenge_transcript)

    def enrollment_key_binding(self) -> bytes:
        return _digest(b"enrollment-key-binding", self.challenge_digest() + self.payment_key_sec1)


@dataclass(frozen=True)
class VerifiedWalletEnrollmentEvidence:
    """Projection plus original checked items; never an HTTP or signer capability.

    Android items are exactly the leaf-first DER chain. Apple items are the original
    attestation object then original assertion. Native must rederive the exact model evidence
    digest and retain these originals before signing.
    """
    kind_tag: int
    time_ms: int
    facts: int
    os_patch_level: int
    vendor_patch_level: int
    boot_patch_level: int
    original_items: tuple
    app_attest_key_id: bytes | None = None
    app_attest_counter: int | None = None

    def evidence_digest(self) -> bytes:
        require(self.kind_tag in (1, 2, 3) and self.original_items
                and all(type(item) is bytes and 0 < len(item) < (1 << 32)
                        for item in self.original_items), "invalid verified evidence items")
        body = bytes([self.kind_tag]) + len(self.original_items).to_bytes(4, "little")
        for item in self.original_items:
            body += len(item).to_bytes(4, "little") + item
        return _digest(b"evidence", body)


def _trusted_time(time_ms: int) -> None:
    require(type(time_ms) is int and 0 < time_ms < (1 << 64), "trusted enrollment time absent")


def verify_android_wallet_enrollment(
    chain_der: list, scope: WalletEnrollmentScope, policy: ConfiguredWalletEnrollmentPolicyV1,
    revocation: Callable, openssl_path: Path,
    *, evidence_time_ms: int, challenge_created_at_ms: int,
    trusted_time_interval: Callable[[], NativeTimeInterval],
) -> VerifiedWalletEnrollmentEvidence:
    """Android admission (enrollment policy steps 1–9) for one E5 KeyMint chain.

    ``revocation`` checks each root's named source and the operator denylist. Each fresh
    clock sample must stay inside the E1 window; leaving it refuses with ChallengeExpired.
    ``evidence_time_ms`` is the selected first dispatch time recorded in the evidence. The
    admitted record carries the chain alone and never fact bit 9.
    """
    scope.validate()
    _trusted_time(evidence_time_ms)
    require(type(policy) is ConfiguredWalletEnrollmentPolicyV1, "configured policy absent")
    app = policy.app.identity
    selected = policy.enrollment.platform
    require(type(app) is AndroidAppIdentityV1 and type(selected) is AndroidEnrollmentPlatformV1,
            "configured Android platform absent")
    anchors = policy.android_anchors()
    # Exact E1 bindings first; afterwards only the challenge window can end.
    policy.validate_scope(scope.challenge_transcript, challenge_created_at_ms,
                          challenge_created_at_ms)

    def current_time() -> int:
        interval = trusted_time_interval()
        require(type(interval) is NativeTimeInterval, "private enrollment clock absent")
        with refusal_stage(EnrollmentRefusal.CHALLENGE_EXPIRED):
            interval.check_both(lambda now: policy.enrollment.require_live_challenge(
                challenge_created_at_ms, now))
        return interval.upper_at_ms

    current_time()
    attested = verify_android_key_attestation(
        chain_der, challenge_digest=scope.challenge_digest(),
        payment_key_sec1=scope.payment_key_sec1, package_name=app.package_name,
        minimum_package_version=app.minimum_package_version, signer_set=app.signer_set,
        anchors=anchors, revocation=revocation, trusted_time_ms=current_time,
        openssl_path=openssl_path)
    current_time()
    facts = ANDROID_ADMITTED_FACTS
    if attested.security_level == 2:
        facts |= FACT_STRONGBOX
    levels = attested.patch_levels
    if android_patch_policy_met(levels, selected.patch_floor_yyyymm):
        facts |= FACT_PATCH_POLICY_MET
    patches = tuple(0 if level is None else level for level in
                    (levels.os_patch_level, levels.vendor_patch_level, levels.boot_patch_level))
    with refusal_stage(EnrollmentRefusal.EVIDENCE_INVALID):
        require(all(type(level) is int and 0 <= level < (1 << 32) for level in patches),
                "Android patch fields exceed credential grammar")
    return VerifiedWalletEnrollmentEvidence(
        attested.security_level, evidence_time_ms, facts, *patches, tuple(chain_der))


def verify_apple_wallet_enrollment(
    attestation_object: bytes, assertion_object: bytes, app_attest_key_id: bytes,
    scope: WalletEnrollmentScope, policy: ConfiguredWalletEnrollmentPolicyV1,
    counters: DurableAppleAssertionCounterStore, trusted_time_ms: int, openssl_path: Path,
    *, challenge_created_at_ms: int,
) -> VerifiedWalletEnrollmentEvidence:
    """Production App Attest plus fresh assertion binding the separate payment public key.

    The existing durable store preserves prior App Attest keys/counters and consumes the
    key-binding challenge once. The Native issuer must durably retain the exact result and
    credential; a lost original never authorizes repeating a consumed assertion. This does
    not independently attest Secure Enclave provenance, boot, patches or jailbreak absence.
    """
    scope.validate()
    _trusted_time(trusted_time_ms)
    require(type(policy) is ConfiguredWalletEnrollmentPolicyV1, "configured policy absent")
    policy.validate_scope(scope.challenge_transcript, challenge_created_at_ms,
                          challenge_created_at_ms)
    with refusal_stage(EnrollmentRefusal.CHALLENGE_EXPIRED):
        policy.enrollment.require_live_challenge(challenge_created_at_ms, trusted_time_ms)
    app = policy.app.identity
    selected = policy.enrollment.platform
    require(type(app) is AppleAppIdentityV1 and type(selected) is AppleEnrollmentPlatformV1,
            "configured Apple platform absent")
    require(isinstance(counters, DurableAppleAssertionCounterStore),
            "durable configured Apple counter owner absent")
    raw = verify_apple_wallet_attestation_raw(
        attestation_object, app_attest_key_id, app.app_id, "production",
        scope.challenge_digest(), policy.apple_root_der,
        selected.attestation_root_sha256, trusted_time_ms, openssl_path)
    counters.register_verified_key(raw, app.app_id, "production")
    assertion = counters.verify_wallet_enrollment_and_advance(
        assertion_object, scope.enrollment_key_binding(), app_attest_key_id,
        app.app_id, "production", openssl_path)
    return VerifiedWalletEnrollmentEvidence(
        3, trusted_time_ms, APPLE_ADMITTED_FACTS, 0, 0, 0,
        (attestation_object, assertion_object), app_attest_key_id, assertion.counter)
