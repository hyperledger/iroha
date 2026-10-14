//! Canonical pre-key dispatch DATA. Only native and issuer owners supply admission authority.

use crate::kagemusha_wallet_advance_v1::LiveEnrollmentReadingV1;
use iroha_crypto::Algorithm;
use iroha_data_model::{account::AccountId, kagemusha::*};

/// Complete dispatch bound, independent of the 10,000-byte monetary Payment limit.
pub const PREKEY_DISPATCH_MAX_BYTES: usize = 16_384;

/// Exact native-selected transport originals and fresh dispatch identifiers.
///
/// A decoded value is DATA: the issuer must independently authenticate its actor and compare
/// every original and scope with its own selected configuration and durable attempt journal.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1")]
pub struct PreKeyDispatchV1 {
    /// Exactly one first-release grammar.
    pub version: u16,
    /// Caller retry identity, bound by the native journal; never an authorization verdict.
    pub request_id: [u8; 32],
    /// Policy-selected hardware platform.
    pub platform: KagemushaEnrollmentPermitPlatformV1,
    /// Fresh creation or observation of the unchanged selected attempt.
    pub purpose: KagemushaEnrollmentPermitPurposeV1,
    /// Native CSPRNG nonce retained before the first issuer dispatch.
    pub client_nonce: [u8; 32],
    /// Fresh native CSPRNG nonce; its live clock remains private and nonserializable.
    pub native_dispatch_nonce: [u8; 32],
    /// Independently selected installed manifest.
    pub manifest_digest: [u8; 32],
    /// Independently approved release-selection scope.
    pub release_digest: [u8; 32],
    /// Independently selected service origin.
    pub service_origin_digest: [u8; 32],
    /// Authenticated FI scope.
    pub fi_digest: [u8; 32],
    /// Authenticated actor scope.
    pub actor_digest: [u8; 32],
    /// Exact selected Scheme original.
    pub scheme: KagemushaWalletSchemeV1,
    /// Exact approved app-policy original.
    pub app: KagemushaWalletAppPolicyV1,
    /// Exact approved enrollment-policy original.
    pub policy: KagemushaWalletEnrollmentPolicyV1,
    /// Exact rooted current Enrollment-role certificate.
    pub enrollment_certificate: KagemushaWalletSignerCertificateV1,
    /// Existing account original, never an eligibility verdict.
    pub account: AccountId,
    /// Exact selected asset original.
    pub asset: KagemushaWalletAssetScopeV1,
    /// First authenticated permit retained unchanged; present only for Resume.
    pub previous_permit: Option<Vec<u8>>,
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::StablePreKeySelectionV1")]
struct StableSelectionV1 {
    version: u16,
    request_id: [u8; 32],
    platform: KagemushaEnrollmentPermitPlatformV1,
    client_nonce: [u8; 32],
    scopes: [[u8; 32]; 5],
    scheme: KagemushaWalletSchemeV1,
    app: KagemushaWalletAppPolicyV1,
    policy: KagemushaWalletEnrollmentPolicyV1,
    enrollment_certificate: KagemushaWalletSignerCertificateV1,
    account: AccountId,
    asset: KagemushaWalletAssetScopeV1,
}

impl PreKeyDispatchV1 {
    /// Validate canonical DATA and self-consistency, without choosing trust or freshness.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || [
                self.request_id,
                self.client_nonce,
                self.native_dispatch_nonce,
                self.manifest_digest,
                self.release_digest,
                self.service_origin_digest,
                self.fi_digest,
                self.actor_digest,
            ]
            .contains(&[0; 32])
        {
            return Err("pre-key dispatch identity");
        }
        self.scheme.validate().map_err(|_| "pre-key scheme")?;
        self.policy
            .validate_for_app(&self.app)
            .map_err(|_| "pre-key policy")?;
        self.enrollment_certificate
            .verify_role(&self.scheme, KagemushaWalletSignerRoleV1::Enrollment)
            .map_err(|_| "pre-key certificate")?;
        self.asset.validate().map_err(|_| "pre-key asset")?;
        if self.policy.scheme_id != self.scheme.scheme_id()
            || self.policy.asset_digest != self.asset.asset_digest()
            || self
                .account
                .try_signatory()
                .is_none_or(|key| key.algorithm() != Algorithm::Ed25519)
            || !matches!(
                (self.platform, &self.policy.platform),
                (
                    KagemushaEnrollmentPermitPlatformV1::Android,
                    KagemushaWalletEnrollmentPlatformV1::Android { .. }
                ) | (
                    KagemushaEnrollmentPermitPlatformV1::Apple,
                    KagemushaWalletEnrollmentPlatformV1::Apple { .. }
                )
            )
        {
            return Err("pre-key original selection");
        }
        match (self.purpose, &self.previous_permit) {
            (KagemushaEnrollmentPermitPurposeV1::Fresh, None) => Ok(()),
            (KagemushaEnrollmentPermitPurposeV1::Resume, Some(bytes)) => {
                let permit = KagemushaEnrollmentPermitV1::decode_canonical(
                    bytes,
                    &self.scheme,
                    &self.enrollment_certificate,
                )
                .map_err(|_| "pre-key retained permit")?;
                if permit.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh {
                    return Err("pre-key first permit purpose");
                }
                self.require_permit_selection(&permit)
            }
            _ => Err("pre-key purpose/original"),
        }
    }

    /// Canonical stable DATA shared with the issuer journal. It excludes exactly purpose,
    /// native dispatch nonce and previous permit; it is never a signature or trust selection.
    pub fn stable_selection(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        norito::encode_canonical(&StableSelectionV1 {
            version: self.version,
            request_id: self.request_id,
            platform: self.platform,
            client_nonce: self.client_nonce,
            scopes: [
                self.manifest_digest,
                self.release_digest,
                self.service_origin_digest,
                self.fi_digest,
                self.actor_digest,
            ],
            scheme: self.scheme,
            app: self.app.clone(),
            policy: self.policy.clone(),
            enrollment_certificate: self.enrollment_certificate,
            account: self.account.clone(),
            asset: self.asset.clone(),
        })
        .map_err(|_| "pre-key stable selection encoding")
    }

    /// Exact seven-frame commitment using the sole data-model grammar, including issuer E1.
    pub fn originals_digest(
        &self,
        challenge: &KagemushaWalletEnrollmentChallengeV1,
    ) -> Result<[u8; 32], &'static str> {
        self.policy
            .verify_challenge(&self.app, challenge)
            .map_err(|_| "pre-key challenge policy")?;
        if challenge.account_digest
            != kagemusha_wallet_account_digest_v1(&self.account).map_err(|_| "pre-key account")?
            || challenge.asset_digest != self.asset.asset_digest()
        {
            return Err("pre-key challenge subject");
        }
        let frames = [
            norito::encode_canonical(challenge),
            norito::encode_canonical(&self.scheme),
            norito::encode_canonical(&self.app),
            norito::encode_canonical(&self.policy),
            norito::encode_canonical(&self.enrollment_certificate),
            norito::encode_canonical(&self.account),
            norito::encode_canonical(&self.asset),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "pre-key original encoding")?;
        kagemusha_enrollment_permit_originals_digest_v1(std::array::from_fn(|index| {
            frames[index].as_slice()
        }))
        .map_err(|_| "pre-key originals commitment")
    }

    /// Check signed permit selection against these DATA originals. Actual native nonce and
    /// clock checks and independent server configuration remain the respective owners' duty.
    pub fn require_permit_selection(
        &self,
        permit: &KagemushaEnrollmentPermitV1,
    ) -> Result<(), &'static str> {
        permit
            .verify(&self.scheme, &self.enrollment_certificate)
            .map_err(|_| "pre-key permit signature")?;
        let body = &permit.body;
        if body.platform != self.platform
            || body.network_id != self.scheme.network_id
            || body.manifest_digest != self.manifest_digest
            || body.release_digest != self.release_digest
            || body.service_origin_digest != self.service_origin_digest
            || body.fi_digest != self.fi_digest
            || body.actor_digest != self.actor_digest
            || body.client_nonce != self.client_nonce
            || body.originals_digest != self.originals_digest(&body.challenge)?
            || body
                .expires_at_ms
                .checked_sub(body.created_at_ms)
                .is_none_or(|duration| {
                    duration == 0 || duration > self.policy.challenge_lifetime_ms
                })
        {
            return Err("pre-key permit selection");
        }
        Ok(())
    }

    /// Encode bounded canonical DATA for issuer transport; this creates no capability.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let bytes = norito::encode_canonical(self).map_err(|_| "pre-key dispatch encoding")?;
        if bytes.len() > PREKEY_DISPATCH_MAX_BYTES {
            return Err("pre-key dispatch bound");
        }
        Ok(bytes)
    }
    /// Decode bounded canonical DATA. Independent scope and current eligibility checks follow.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > PREKEY_DISPATCH_MAX_BYTES {
            return Err("pre-key dispatch bound");
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(PREKEY_DISPATCH_MAX_BYTES),
        )
        .map_err(|_| "pre-key dispatch encoding")?;
        value.validate()?;
        Ok(value)
    }
}

/// Live verified permission consumed by one provider generation operation. Not serializable.
pub(crate) struct GenerationAuthorizationV1 {
    root: [u8; 32],
    request_id: [u8; 32],
    challenge: KagemushaWalletEnrollmentChallengeV1,
    profile: crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyProfileV1,
    slot: crate::kagemusha_wallet_advance_v1::KagemushaWalletSlotIdV1,
    generation_policy: crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyGenerationPolicyV1,
    fresh: bool,
    dates: crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1,
    started: LiveEnrollmentReadingV1,
    observed_at_ms: u64,
    expires_at_ms: u64,
}
impl GenerationAuthorizationV1 {
    pub(crate) fn dates(
        &self,
    ) -> crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
        self.dates
    }
    /// Pre-key request whose durable enrollment phase this generation advances.
    pub(crate) fn request_id(&self) -> [u8; 32] {
        self.request_id
    }
    pub(crate) fn selection(
        &self,
    ) -> (
        KagemushaWalletEnrollmentChallengeV1,
        crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyProfileV1,
        crate::kagemusha_wallet_advance_v1::KagemushaWalletSlotIdV1,
        crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyGenerationPolicyV1,
        bool,
    ) {
        (
            self.challenge,
            self.profile,
            self.slot,
            self.generation_policy,
            self.fresh,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        root: [u8; 32],
        request_id: [u8; 32],
        permit: &KagemushaEnrollmentPermitV1,
        profile: crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyProfileV1,
        slot: crate::kagemusha_wallet_advance_v1::KagemushaWalletSlotIdV1,
        generation_policy: crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyGenerationPolicyV1,
        fresh: bool,
        started: LiveEnrollmentReadingV1,
        session_expires_at_ms: u64,
    ) -> Self {
        Self {
            root,
            request_id,
            challenge: permit.body.challenge,
            profile,
            slot,
            generation_policy,
            fresh,
            dates: crate::kagemusha_wallet_advance_v1::KagemushaWalletEnrollmentDatesV1 {
                issued_at_ms: permit.body.created_at_ms,
                expires_at_ms: permit.body.expires_at_ms,
            },
            started,
            observed_at_ms: permit.body.observed_at_ms,
            expires_at_ms: permit.body.expires_at_ms.min(session_expires_at_ms),
        }
    }
    pub(crate) fn check<F, P, C, R>(
        &self,
        provider: &crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P, C, R>,
    ) -> Result<(), crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1>
    where
        F: crate::kagemusha_wallet_advance_v1::KagemushaWalletFsV1,
        P: crate::kagemusha_wallet_advance_v1::KagemushaWalletPlatformV1,
        C: crate::kagemusha_wallet_advance_v1::KagemushaWalletAdvanceCapsuleV1,
        R: crate::kagemusha_wallet_advance_v1::KagemushaWalletCompletionFrameV1,
    {
        use crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1 as Error;
        if self.root != provider.prekey_root_identity()
            || &self.challenge.scheme_id != provider.scheme_id()
        {
            return Err(Error::Invalid {
                field: "pre-key provider binding",
            });
        }
        require_elapsed(
            &self.started,
            &provider.live_enrollment_reading()?,
            self.observed_at_ms,
            self.expires_at_ms,
        )
        .map_err(|_| Error::Invalid {
            field: "pre-key permit elapsed deadline",
        })
    }
}

pub(super) fn require_elapsed(
    started: &LiveEnrollmentReadingV1,
    now: &LiveEnrollmentReadingV1,
    observed: u64,
    expires: u64,
) -> Result<(), &'static str> {
    let elapsed = now
        .elapsed_since(started)
        .map_err(|_| "pre-key live clock unavailable or changed")?;
    let elapsed_ms =
        u64::try_from(elapsed.as_millis()).map_err(|_| "pre-key elapsed duration overflow")?;
    if observed
        .checked_add(elapsed_ms)
        // Strictly round the suspend-inclusive duration upward, including a whole
        // millisecond boundary, before comparing the exclusive signed deadline.
        .and_then(|upper| upper.checked_add(1))
        .is_none_or(|upper| upper >= expires)
    {
        return Err("pre-key permit elapsed deadline");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reading(domain: [u8; 32], nanos: u128) -> LiveEnrollmentReadingV1 {
        LiveEnrollmentReadingV1::Simulated { domain, nanos }
    }
    #[test]
    fn elapsed_bound_is_strict_and_rejects_overflow_domain_change_and_clock_rollback() {
        let start = reading([1; 32], 100_000_000);
        assert!(require_elapsed(&start, &reading([1; 32], 108_999_999), 10, 20).is_ok());
        assert!(require_elapsed(&start, &reading([1; 32], 109_000_000), 10, 20).is_err());
        assert!(
            require_elapsed(&start, &reading([1; 32], 101_000_000), u64::MAX, u64::MAX).is_err()
        );
        assert!(require_elapsed(&start, &reading([1; 32], 99_999_999), 10, 20).is_err());
        assert!(require_elapsed(&start, &reading([2; 32], 100_000_000), 10, 20).is_err());
        assert!(require_elapsed(&reading([0; 32], 0), &reading([0; 32], 0), 10, 20).is_err());
        assert!(
            require_elapsed(
                &start,
                &reading([1; 32], u128::from(u64::MAX) * 1_000_000 + 100_000_000),
                1,
                u64::MAX
            )
            .is_err()
        );
        assert!(
            require_elapsed(
                &start,
                &reading(
                    [1; 32],
                    (u128::from(u64::MAX) + 1) * 1_000_000 + 100_000_000
                ),
                0,
                u64::MAX
            )
            .is_err()
        );
        assert!(require_elapsed(&start, &start, 19, 20).is_err());
    }
}
