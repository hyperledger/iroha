//! Signed regulatory and fee policy objects and their offline checks (§§6.2, 7; design §6
//! with C6 and C7).
//!
//! Every object here is signed by a RegulatoryPolicy-role key, except the time anchor, which
//! is signed by a TimeAnchor-role key. A control is active only when the credential permits it
//! and the held scheme policy enables it; with every control off, no clock condition, list or
//! quota blocks payment. Policies never undo completed credit (§7).

use core::cmp::Ordering;

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1, KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1, KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1, KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1,
    WalletResult, WalletVersionsV1, decode_frame_v1,
    digest::WalletFieldItemsV1,
    digest::{
        KagemushaWalletObjectDigestDomainV1 as ObjectDomain, KagemushaWalletSignerOutputV1,
        KagemushaWalletSigningDomainV1 as Domain, WalletTranscriptV1,
        kagemusha_wallet_freeze_signature_v1, kagemusha_wallet_signed_object_digest_v1,
        kagemusha_wallet_signing_message_v1, kagemusha_wallet_verify_signature_v1,
    },
    encode_frame_v1,
    identity::{
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1, KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        KagemushaWalletCredentialV1, KagemushaWalletSchemeV1, KagemushaWalletSignerCertificateV1,
        KagemushaWalletSignerRoleV1,
    },
    invalid_v1, is_zero_v1,
    keys::KagemushaDeviceSignatureV1,
    overflow_v1,
    poseidon::{
        KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1, KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1,
        KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1, KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1,
        KagemushaWalletIndexedInsertV1, KagemushaWalletIndexedLeafV1,
        KagemushaWalletIndexedOpeningV1, kagemusha_wallet_integer_cmp_v1, poseidon_items_v1,
    },
    require_canonical_field_v1, require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1,
    require_version_v1,
    state::{
        KagemushaWalletBlacklistHistoryLeafV1, KagemushaWalletEffectV1,
        KagemushaWalletPolicyUpdateKindV1, KagemushaWalletQuotaOpeningV1,
        KagemushaWalletQuotaUsageArrayV1, KagemushaWalletQuotaUsageLeafV1,
        KagemushaWalletStateCoreV1, KagemushaWalletStateRestV1, KagemushaWalletStateV1,
        quota_tree_levels_v1, quota_tree_opening_v1,
    },
};

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;

/// Exact scheme-policy body transcript bytes (signed under `kgwspol1`).
pub const KAGEMUSHA_WALLET_SCHEME_POLICY_BODY_TRANSCRIPT_BYTES_V1: usize =
    2 + 2 * 32 + 8 + 4 + 2 * 32;
/// Exact fee-schedule body transcript bytes (signed under `kgwfsch1`).
pub const KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1: usize =
    2 + 2 * 32 + 8 + 32 + 4 + 3 * 16 + 1 + 32;
/// Basis-point denominator of a proportional fee.
pub const KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1: u32 = 10_000;
/// Exact blacklist body transcript bytes (signed under `kgwblst1`).
pub const KAGEMUSHA_WALLET_BLACKLIST_BODY_TRANSCRIPT_BYTES_V1: usize = 2 + 32 + 8 + 8 + 4 + 2 * 32;
/// Fixed depth of the blacklist gap tree.
pub const KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1: usize = 16;
/// Gap leaves of the fixed-depth blacklist tree.
pub const KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1: u32 = 1 << KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1;
/// Maximum entries of one blacklist: one fewer than its gap leaves.
pub const KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1: u32 = KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1 - 1;
/// Lower sentinel of the gap sequence; never a valid entry.
pub const KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1: [u8; 32] = [0x00; 32];
/// Upper sentinel of the gap sequence; never a valid entry.
pub const KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1: [u8; 32] = [0xff; 32];
/// Exact transcript bytes of one retained blacklist gap opening: `lower || upper || LE32
/// leaf_index || 16 siblings` (580).
pub const KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1: usize =
    2 * 32 + 4 + KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 * 32;
/// Fixed depth of the quota windows tree and of the quota-usage array.
pub const KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1: usize = 6;
/// Window slots of one quota share.
pub const KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1: usize = 1 << KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1;
/// Exact quota-share body transcript bytes (signed under `kgwqshr1`).
pub const KAGEMUSHA_WALLET_QUOTA_SHARE_BODY_TRANSCRIPT_BYTES_V1: usize =
    2 + 3 * 32 + 3 * 8 + 32 + 4 + 32;
/// Exact time-anchor body transcript bytes (signed under `kgwtanc1`).
pub const KAGEMUSHA_WALLET_TIME_ANCHOR_BODY_TRANSCRIPT_BYTES_V1: usize = 2 + 3 * 32 + 8 + 32;
/// Exact charge-quote body transcript bytes (signed under `kgwchgq1`).
pub const KAGEMUSHA_WALLET_CHARGE_QUOTE_BODY_TRANSCRIPT_BYTES_V1: usize =
    2 + 3 * 32 + 1 + 3 * 16 + 32 + 8 + 32;

/// Signer binding of one role-signed body; shared with the ledger and message owners.
pub(super) struct SignerBindingV1<'a> {
    /// Field label of the body's scheme.
    pub(super) scheme_field: &'static str,
    /// Field label of the body's signer certificate digest.
    pub(super) certificate_field: &'static str,
    /// Body scheme.
    pub(super) scheme_id: &'a [u8; 32],
    /// Body signer certificate digest.
    pub(super) certificate: &'a [u8; 32],
    /// Required signer role.
    pub(super) role: KagemushaWalletSignerRoleV1,
    /// Signing domain of the body.
    pub(super) domain: Domain,
}

impl SignerBindingV1<'_> {
    /// Freeze a fresh signer output after checking the signer certificate's binding.
    pub(super) fn freeze(
        &self,
        certificate: &KagemushaWalletSignerCertificateV1,
        transcript: &[u8],
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<KagemushaDeviceSignatureV1> {
        certificate.validate()?;
        if certificate.certificate_digest() != *self.certificate {
            return Err(invalid_v1(self.certificate_field));
        }
        if certificate.body.role != self.role {
            return Err(invalid_v1("certificate.role"));
        }
        require_scheme_v1(
            self.scheme_field,
            self.scheme_id,
            &certificate.body.scheme_id,
        )?;
        kagemusha_wallet_freeze_signature_v1(
            &certificate.body.key,
            self.domain,
            &kagemusha_wallet_signing_message_v1(self.domain, transcript),
            signer_output,
        )
    }

    /// Verify a received signature under the scheme-rooted signer certificate.
    pub(super) fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        certificate: &KagemushaWalletSignerCertificateV1,
        transcript: &[u8],
        signature: &KagemushaDeviceSignatureV1,
    ) -> WalletResult<()> {
        require_scheme_v1(self.scheme_field, self.scheme_id, &scheme.scheme_id())?;
        if certificate.certificate_digest() != *self.certificate {
            return Err(invalid_v1(self.certificate_field));
        }
        certificate.verify_role(scheme, self.role)?;
        kagemusha_wallet_verify_signature_v1(
            &certificate.body.key,
            self.domain,
            &kagemusha_wallet_signing_message_v1(self.domain, transcript),
            signature,
        )
    }
}

// ---------------------------------------------------------------------------------------
// Scheme policy (§7, design §6.1)
// ---------------------------------------------------------------------------------------

/// Body of a scheme policy, signed by a RegulatoryPolicy-role key under `scheme-policy-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSchemePolicyBodyV1"
)]
pub struct KagemushaWalletSchemePolicyBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Policy epoch; strictly increasing from the implicit default epoch zero.
    pub policy_epoch: u64,
    /// Enabled control bits (`KAGEMUSHA_WALLET_CONTROL_*`).
    pub enabled_controls: u32,
    /// Fee schedule digest; zero for no fee.
    pub fee_schedule: [u8; 32],
    /// Certificate digest of the RegulatoryPolicy-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletSchemePolicyBodyV1 {
    /// Exact `scheme-policy-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_SCHEME_POLICY_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .u64(self.policy_epoch)
            .u32(self.enabled_controls)
            .digest(&self.fee_schedule)
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwspol1, transcript)`: the 32 bytes the RegulatoryPolicy-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::SchemePolicy, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, epoch zero (the implicit default), and
    /// undefined control bits.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("scheme_policy.version", self.version)?;
        require_nonzero_v1("scheme_policy.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("scheme_policy.asset_digest", &self.asset_digest)?;
        require_nonzero_field_v1("scheme_policy.signer_certificate", &self.signer_certificate)?;
        require_canonical_field_v1("scheme_policy.fee_schedule", &self.fee_schedule)?;
        if self.policy_epoch == 0 {
            return Err(invalid_v1("scheme_policy.policy_epoch"));
        }
        if self.enabled_controls & !KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 != 0 {
            return Err(invalid_v1("scheme_policy.enabled_controls"));
        }
        Ok(())
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "scheme_policy.scheme_id",
            certificate_field: "scheme_policy.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            domain: Domain::SchemePolicy,
        }
    }
}

/// Signed scheme policy: epoch, enabled controls and fee schedule (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSchemePolicyV1"
)]
pub struct KagemushaWalletSchemePolicyV1 {
    /// Signed body.
    pub body: KagemushaWalletSchemePolicyBodyV1,
    /// RegulatoryPolicy-role signature over `scheme-policy-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletSchemePolicyV1 {
    /// Freeze a RegulatoryPolicy-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a certificate that is not the body's RegulatoryPolicy-role
    /// signer for its scheme, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletSchemePolicyBodyV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self { body, signature })
    }

    /// Scheme policy object digest `P(kgwopol1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn scheme_policy_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::SchemePolicy,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the policy's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the policy under `scheme` and its RegulatoryPolicy-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid policy, another scheme, a certificate that is not its
    /// RegulatoryPolicy-role signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid policy or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1)
    }

    /// Decode one canonical scheme policy frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let policy: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1)?;
        policy.require_versions()?;
        require_scheme_v1(
            "scheme_policy.scheme_id",
            &policy.body.scheme_id,
            expected_scheme_id,
        )?;
        policy.validate()?;
        Ok(policy)
    }
}

// ---------------------------------------------------------------------------------------
// Fee schedule (§6.2, design §6.2)
// ---------------------------------------------------------------------------------------

/// Rounding of the proportional fee part.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeRoundingV1"
)]
pub enum KagemushaWalletFeeRoundingV1 {
    /// Round toward zero.
    #[codec(index = 1)]
    Down,
    /// Round away from zero.
    #[codec(index = 2)]
    Up,
}

impl KagemushaWalletFeeRoundingV1 {
    /// Every rounding rule, in tag order.
    pub const ALL: [Self; 2] = [Self::Down, Self::Up];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Down => 1,
            Self::Up => 2,
        }
    }
}

/// Body of an immutable fee schedule, signed by a RegulatoryPolicy-role key under
/// `fee-schedule-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeScheduleBodyV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletFeeScheduleBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Issuer-assigned schedule identity.
    pub schedule_id: u64,
    /// Account digest of the online fee beneficiary.
    pub beneficiary_account_digest: [u8; 32],
    /// Proportional rate in basis points, at most
    /// [`KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1`].
    pub basis_points: u32,
    /// Fixed fee part.
    pub fixed: u128,
    /// Minimum fee.
    pub minimum: u128,
    /// Maximum fee; at least `minimum`.
    pub maximum: u128,
    /// Rounding of the proportional part.
    pub rounding: KagemushaWalletFeeRoundingV1,
    /// Certificate digest of the RegulatoryPolicy-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletFeeScheduleBodyV1 {
    /// Exact `fee-schedule-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .u64(self.schedule_id)
            .digest(&self.beneficiary_account_digest)
            .u32(self.basis_points)
            .u128(self.fixed)
            .u128(self.minimum)
            .u128(self.maximum)
            .u8(self.rounding.tag())
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwfsch1, transcript)`: the 32 bytes the RegulatoryPolicy-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::FeeSchedule, &self.transcript())
    }

    fn validate_terms(&self) -> WalletResult<()> {
        if self.basis_points > KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1 {
            return Err(invalid_v1("fee_schedule.basis_points"));
        }
        if self.maximum < self.minimum {
            return Err(invalid_v1("fee_schedule.maximum"));
        }
        Ok(())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a rate above 10,000 basis points, or a maximum
    /// below the minimum.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("fee_schedule.version", self.version)?;
        require_nonzero_v1("fee_schedule.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("fee_schedule.asset_digest", &self.asset_digest)?;
        require_nonzero_v1(
            "fee_schedule.beneficiary_account_digest",
            &self.beneficiary_account_digest,
        )?;
        require_nonzero_field_v1("fee_schedule.signer_certificate", &self.signer_certificate)?;
        self.validate_terms()
    }

    /// Exact fee of `amount`: `clamp(fixed + round(amount * bp / 10_000), minimum, maximum)`.
    ///
    /// The proportional part is computed exactly as `q * bp + (r * bp) / 10_000` with
    /// `amount = q * 10_000 + r`, so no intermediate exceeds the true result; `Up` adds one
    /// when `(r * bp) % 10_000` is nonzero.
    ///
    /// # Errors
    ///
    /// Rejects invalid terms and a fee whose unclamped value overflows `u128`.
    pub fn fee(&self, amount: u128) -> WalletResult<u128> {
        self.validate_terms()?;
        let overflow = || overflow_v1("fee_schedule.fee");
        let denominator = u128::from(KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1);
        let basis_points = u128::from(self.basis_points);
        let whole = (amount / denominator)
            .checked_mul(basis_points)
            .ok_or_else(overflow)?;
        let part = (amount % denominator)
            .checked_mul(basis_points)
            .ok_or_else(overflow)?;
        let mut proportional = whole.checked_add(part / denominator).ok_or_else(overflow)?;
        if self.rounding == KagemushaWalletFeeRoundingV1::Up && part % denominator != 0 {
            proportional = proportional.checked_add(1).ok_or_else(overflow)?;
        }
        let fee = self.fixed.checked_add(proportional).ok_or_else(overflow)?;
        Ok(fee.clamp(self.minimum, self.maximum))
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "fee_schedule.scheme_id",
            certificate_field: "fee_schedule.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            domain: Domain::FeeSchedule,
        }
    }
}

/// Signed immutable fee schedule (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeScheduleV1"
)]
pub struct KagemushaWalletFeeScheduleV1 {
    /// Signed body.
    pub body: KagemushaWalletFeeScheduleBodyV1,
    /// RegulatoryPolicy-role signature over `fee-schedule-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletFeeScheduleV1 {
    /// Freeze a RegulatoryPolicy-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a certificate that is not the body's RegulatoryPolicy-role
    /// signer for its scheme, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletFeeScheduleBodyV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self { body, signature })
    }

    /// Fee schedule object digest `P(kgwofee1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn fee_schedule_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::FeeSchedule,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Exact fee of `amount` under this schedule.
    ///
    /// # Errors
    ///
    /// Rejects what [`KagemushaWalletFeeScheduleBodyV1::fee`] rejects.
    pub fn fee(&self, amount: u128) -> WalletResult<u128> {
        self.body.fee(amount)
    }

    /// Validate the schedule's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the schedule under `scheme` and its RegulatoryPolicy-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid schedule, another scheme, a certificate that is not its
    /// RegulatoryPolicy-role signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid schedule or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1)
    }

    /// Decode one canonical fee schedule frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let schedule: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1)?;
        schedule.require_versions()?;
        require_scheme_v1(
            "fee_schedule.scheme_id",
            &schedule.body.scheme_id,
            expected_scheme_id,
        )?;
        schedule.validate()?;
        Ok(schedule)
    }
}

// ---------------------------------------------------------------------------------------
// Blacklist and its fixed-depth gap tree (§7, design §6.3)
// ---------------------------------------------------------------------------------------

/// One listed account digest.
///
/// Entries order by the limb integer `hi · 2^128 + lo` of the digest's two σ limbs, the 32
/// bytes read as one little-endian integer (owner answer A4).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletBlacklistEntryV1"
)]
pub struct KagemushaWalletBlacklistEntryV1 {
    /// Listed account digest (`H("account", AccountId frame)`).
    pub account_digest: [u8; 32],
}

impl Ord for KagemushaWalletBlacklistEntryV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        kagemusha_wallet_integer_cmp_v1(&self.account_digest, &other.account_digest)
    }
}

impl PartialOrd for KagemushaWalletBlacklistEntryV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Gap leaf `P(kgwblkl1, limbs(lower) || limbs(upper))` (§7): the two 32-byte account digests
/// as four 128-bit limbs.
#[must_use]
pub fn kagemusha_wallet_blacklist_leaf_v1(lower: &[u8; 32], upper: &[u8; 32]) -> [u8; 32] {
    poseidon_items_v1(
        KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1,
        &WalletFieldItemsV1::with_capacity(4)
            .digest(lower)
            .digest(upper)
            .finish(),
    )
}

/// Tree node `P(kgwblkn1, [left, right])` over canonical children.
///
/// # Errors
///
/// Rejects a noncanonical child.
pub fn kagemusha_wallet_blacklist_node_v1(
    left: &[u8; 32],
    right: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    require_canonical_field_v1("blacklist.node", left)?;
    require_canonical_field_v1("blacklist.node", right)?;
    Ok(blacklist_node_v1(left, right))
}

/// Tree node over children that are canonical by construction.
fn blacklist_node_v1(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    poseidon_items_v1(KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1, &[*left, *right])
}

/// Validate little-endian integer order: strictly ascending, at most the maximum, no sentinel.
fn validate_blacklist_entries_v1(entries: &[KagemushaWalletBlacklistEntryV1]) -> WalletResult<()> {
    let count = u32::try_from(entries.len()).map_err(|_| overflow_v1("blacklist.entries"))?;
    if count > KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1 {
        return Err(invalid_v1("blacklist.entries"));
    }
    let mut previous: Option<&[u8; 32]> = None;
    for entry in entries {
        let digest = &entry.account_digest;
        if *digest == KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1
            || *digest == KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1
        {
            return Err(invalid_v1("blacklist.sentinel"));
        }
        if previous.is_some_and(|previous| {
            kagemusha_wallet_integer_cmp_v1(previous, digest) != Ordering::Less
        }) {
            return Err(invalid_v1("blacklist.order"));
        }
        previous = Some(digest);
    }
    Ok(())
}

/// Padding subtree root at every level: `padding[0]` is the `FF..FF || FF..FF` leaf.
fn blacklist_padding_v1() -> [[u8; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 + 1] {
    let mut padding = [[0; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 + 1];
    padding[0] = kagemusha_wallet_blacklist_leaf_v1(
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1,
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1,
    );
    for depth in 0..KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 {
        padding[depth + 1] = blacklist_node_v1(&padding[depth], &padding[depth]);
    }
    padding
}

/// Occupied nodes of every tree level (leaves first, root last) and the padding roots.
type BlacklistLevelsV1 = (
    Vec<Vec<[u8; 32]>>,
    [[u8; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 + 1],
);

fn blacklist_levels_v1(
    entries: &[KagemushaWalletBlacklistEntryV1],
) -> WalletResult<BlacklistLevelsV1> {
    validate_blacklist_entries_v1(entries)?;
    let padding = blacklist_padding_v1();
    let mut level = Vec::with_capacity(entries.len().saturating_add(1));
    let mut lower = &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1;
    for entry in entries {
        level.push(kagemusha_wallet_blacklist_leaf_v1(
            lower,
            &entry.account_digest,
        ));
        lower = &entry.account_digest;
    }
    level.push(kagemusha_wallet_blacklist_leaf_v1(
        lower,
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1,
    ));
    let mut levels = Vec::with_capacity(KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1 + 1);
    for pad in padding
        .iter()
        .take(KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1)
    {
        let next = level
            .chunks(2)
            .map(|pair| blacklist_node_v1(&pair[0], pair.get(1).unwrap_or(pad)))
            .collect();
        levels.push(level);
        level = next;
    }
    levels.push(level);
    Ok((levels, padding))
}

/// Gap-tree root of an entry list sorted by little-endian integer order: a Poseidon tree of
/// fixed depth 16 over 65,536 gap leaves (§7); one canonical σ-field value.
///
/// Gap `i` lies between the limb-ordered sentinels `s_0 = 00..00`, the entries, and
/// `s_{n+1} = FF..FF`; unused leaves are the gap leaf of `FF..FF || FF..FF`.
///
/// # Errors
///
/// Rejects unsorted, duplicate, sentinel-valued or too many entries.
pub fn kagemusha_wallet_blacklist_root_v1(
    entries: &[KagemushaWalletBlacklistEntryV1],
) -> WalletResult<[u8; 32]> {
    let (levels, _) = blacklist_levels_v1(entries)?;
    levels
        .last()
        .and_then(|root| root.first())
        .copied()
        .ok_or_else(|| invalid_v1("blacklist.entries"))
}

/// Non-membership opening of one account: the gap leaf `(lower, upper)` with
/// `lower < account < upper` in limb order and its sibling path (§7, design §6.3).
///
/// This is a native helper and in-circuit witness; it is never transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletBlacklistGapOpeningV1 {
    /// Gap leaf index, below [`KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1`].
    pub leaf_index: u32,
    /// Lower sentinel or entry of the gap.
    pub lower: [u8; 32],
    /// Upper entry or sentinel of the gap.
    pub upper: [u8; 32],
    /// Sibling σ-field values from the leaf level upward.
    pub siblings: [[u8; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1],
}

impl KagemushaWalletBlacklistGapOpeningV1 {
    /// Recompute the Poseidon tree root along the sibling path.
    ///
    /// # Errors
    ///
    /// Rejects a leaf index outside the tree and a noncanonical sibling.
    pub fn root(&self) -> WalletResult<[u8; 32]> {
        if self.leaf_index >= KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1 {
            return Err(invalid_v1("blacklist.leaf_index"));
        }
        let mut node = kagemusha_wallet_blacklist_leaf_v1(&self.lower, &self.upper);
        let mut position = self.leaf_index;
        for sibling in &self.siblings {
            node = if position & 1 == 0 {
                kagemusha_wallet_blacklist_node_v1(&node, sibling)?
            } else {
                kagemusha_wallet_blacklist_node_v1(sibling, &node)?
            };
            position >>= 1;
        }
        Ok(node)
    }

    /// Exact retained transcript (580 bytes, owner answer B6): `lower || upper || LE32
    /// leaf_index || siblings`, height 0 first. The receiver retains it with each Request it
    /// issues under an enforced list, for its Receive and any `σ_recv` re-proof.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut transcript = WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1,
        )
        .digest(&self.lower)
        .digest(&self.upper)
        .u32(self.leaf_index);
        for sibling in &self.siblings {
            transcript = transcript.digest(sibling);
        }
        transcript.finish()
    }

    /// Parse one retained transcript ([`Self::transcript`]).
    ///
    /// # Errors
    ///
    /// Rejects another length, a leaf index outside the tree and a noncanonical sibling.
    pub fn from_transcript(bytes: &[u8]) -> WalletResult<Self> {
        if bytes.len() != KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1 {
            return Err(invalid_v1("blacklist_gap.transcript"));
        }
        let mut lower = [0_u8; 32];
        let mut upper = [0_u8; 32];
        let mut index = [0_u8; 4];
        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..64]);
        index.copy_from_slice(&bytes[64..68]);
        let leaf_index = u32::from_le_bytes(index);
        if leaf_index >= KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1 {
            return Err(invalid_v1("blacklist.leaf_index"));
        }
        let mut siblings = [[0_u8; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1];
        for (sibling, chunk) in siblings.iter_mut().zip(bytes[68..].chunks_exact(32)) {
            sibling.copy_from_slice(chunk);
            require_canonical_field_v1("blacklist_gap.sibling", sibling)?;
        }
        Ok(Self {
            leaf_index,
            lower,
            upper,
            siblings,
        })
    }

    /// Verify that `account_digest` lies strictly inside this gap of the tree `entries_root`, in
    /// limb order.
    ///
    /// # Errors
    ///
    /// Rejects an account outside the gap (a listed account or a sentinel) and a path that
    /// does not reach `entries_root`.
    pub fn verify(&self, entries_root: &[u8; 32], account_digest: &[u8; 32]) -> WalletResult<()> {
        if kagemusha_wallet_integer_cmp_v1(&self.lower, account_digest) != Ordering::Less
            || kagemusha_wallet_integer_cmp_v1(account_digest, &self.upper) != Ordering::Less
        {
            return Err(invalid_v1("blacklist.listed"));
        }
        if self.root()? != *entries_root {
            return Err(invalid_v1("blacklist.opening"));
        }
        Ok(())
    }
}

/// Body of a blacklist, signed by a RegulatoryPolicy-role key under `kgwblst1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletBlacklistBodyV1"
)]
pub struct KagemushaWalletBlacklistBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// List version; strictly increasing from the implicit default zero.
    pub list_version: u64,
    /// Issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Number of entries, at most [`KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1`].
    pub entry_count: u32,
    /// Gap-tree root ([`kagemusha_wallet_blacklist_root_v1`]), a canonical σ-field value.
    pub entries_root: [u8; 32],
    /// Certificate digest of the RegulatoryPolicy-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletBlacklistBodyV1 {
    /// Exact `blacklist-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_BLACKLIST_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .u64(self.list_version)
            .u64(self.issued_at_ms)
            .u32(self.entry_count)
            .digest(&self.entries_root)
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwblst1, transcript)`: the 32 bytes the RegulatoryPolicy-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Blacklist, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a noncanonical root, version zero (the implicit
    /// default), and too many entries.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("blacklist.version", self.version)?;
        require_nonzero_v1("blacklist.scheme_id", &self.scheme_id)?;
        require_nonzero_field_v1("blacklist.entries_root", &self.entries_root)?;
        require_nonzero_field_v1("blacklist.signer_certificate", &self.signer_certificate)?;
        if self.list_version == 0 {
            return Err(invalid_v1("blacklist.list_version"));
        }
        if self.entry_count > KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1 {
            return Err(invalid_v1("blacklist.entry_count"));
        }
        Ok(())
    }

    /// Validate `entries` against this body's count and root.
    ///
    /// # Errors
    ///
    /// Rejects invalid entries, another count, or another root.
    pub fn validate_entries(
        &self,
        entries: &[KagemushaWalletBlacklistEntryV1],
    ) -> WalletResult<()> {
        let count = u32::try_from(entries.len()).map_err(|_| overflow_v1("blacklist.entries"))?;
        if count != self.entry_count {
            return Err(invalid_v1("blacklist.entry_count"));
        }
        if kagemusha_wallet_blacklist_root_v1(entries)? != self.entries_root {
            return Err(invalid_v1("blacklist.entries_root"));
        }
        Ok(())
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "blacklist.scheme_id",
            certificate_field: "blacklist.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            domain: Domain::Blacklist,
        }
    }
}

/// Complete signed blacklist with its entries strictly ascending in limb order (§7, owner
/// answer A4).
///
/// The list is not a peer message: a wallet downloads it only while online, from the issuer
/// or ledger, as one standalone canonical frame of at most
/// [`KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1`] bytes ([`Self::to_canonical_bytes`],
/// [`Self::decode_canonical`]), and peers never relay it. Offline, the wallet applies the held
/// list through `RefreshPolicy` and proves a counterparty's non-membership with a local
/// [`KagemushaWalletBlacklistGapOpeningV1`]: the payer proves the receiver's account absent
/// from its own committed list, and the receiver the payer's (owner answer A5). Lists are best
/// effort: different phones can and will hold different lists, each enforces only its own, and
/// a later list never invalidates a completed payment.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletBlacklistV1"
)]
pub struct KagemushaWalletBlacklistV1 {
    /// Signed body.
    pub body: KagemushaWalletBlacklistBodyV1,
    /// RegulatoryPolicy-role signature over `blacklist-body`.
    pub signature: KagemushaDeviceSignatureV1,
    /// Entries strictly ascending in limb order.
    pub entries: Vec<KagemushaWalletBlacklistEntryV1>,
}

impl KagemushaWalletBlacklistV1 {
    /// Freeze a RegulatoryPolicy-role signature over `body` for `entries`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, entries that do not match it, a certificate that is not the
    /// body's RegulatoryPolicy-role signer, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletBlacklistBodyV1,
        entries: Vec<KagemushaWalletBlacklistEntryV1>,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        body.validate_entries(&entries)?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self {
            body,
            signature,
            entries,
        })
    }

    /// Blacklist object digest `P(kgwoblk1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn blacklist_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::Blacklist,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Whether `account_digest` is listed.
    #[must_use]
    pub fn contains(&self, account_digest: &[u8; 32]) -> bool {
        self.entries
            .binary_search_by(|entry| {
                kagemusha_wallet_integer_cmp_v1(&entry.account_digest, account_digest)
            })
            .is_ok()
    }

    /// Non-membership opening of `account_digest`.
    ///
    /// # Errors
    ///
    /// Rejects a listed or sentinel-valued account and invalid entries.
    pub fn gap_opening(
        &self,
        account_digest: &[u8; 32],
    ) -> WalletResult<KagemushaWalletBlacklistGapOpeningV1> {
        if *account_digest == KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1
            || *account_digest == KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1
        {
            return Err(invalid_v1("blacklist.account_digest"));
        }
        let index = self.entries.partition_point(|entry| {
            kagemusha_wallet_integer_cmp_v1(&entry.account_digest, account_digest) == Ordering::Less
        });
        let upper = self
            .entries
            .get(index)
            .map_or(KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1, |entry| {
                entry.account_digest
            });
        if upper == *account_digest {
            return Err(invalid_v1("blacklist.listed"));
        }
        let lower = index
            .checked_sub(1)
            .and_then(|previous| self.entries.get(previous))
            .map_or(KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1, |entry| {
                entry.account_digest
            });
        let (levels, padding) = blacklist_levels_v1(&self.entries)?;
        let mut siblings = [[0; 32]; KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1];
        let mut position = index;
        for ((sibling, level), pad) in siblings.iter_mut().zip(&levels).zip(&padding) {
            *sibling = level.get(position ^ 1).copied().unwrap_or(*pad);
            position >>= 1;
        }
        Ok(KagemushaWalletBlacklistGapOpeningV1 {
            leaf_index: u32::try_from(index).map_err(|_| overflow_v1("blacklist.leaf_index"))?,
            lower,
            upper,
            siblings,
        })
    }

    /// Validate the list's self-contained rules: body, signature encoding, entries and root.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or signature encoding, invalid entries, or a count or root
    /// that differs from the body.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        self.body.validate_entries(&self.entries)
    }

    /// Verify the list under `scheme` and its RegulatoryPolicy-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid list, another scheme, a certificate that is not its
    /// RegulatoryPolicy-role signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid list or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1)
    }

    /// Decode one canonical blacklist frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields, entries or root.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let list: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1)?;
        list.require_versions()?;
        require_scheme_v1(
            "blacklist.scheme_id",
            &list.body.scheme_id,
            expected_scheme_id,
        )?;
        list.validate()?;
        Ok(list)
    }
}

// ---------------------------------------------------------------------------------------
// Time anchor, anchored interval and accepted time (§7, design §6.5 and C6)
// ---------------------------------------------------------------------------------------

/// Conservative real-time interval `[lower_ms, upper_ms]` in Unix milliseconds.
///
/// A deadline counts as passed once the upper end reaches it; a start counts as reached only
/// once the lower end does (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletTimeIntervalV1 {
    /// Lower end `L`.
    pub lower_ms: u64,
    /// Upper end `U`; at least `lower_ms`.
    pub upper_ms: u64,
}

impl KagemushaWalletTimeIntervalV1 {
    /// Construct an interval.
    ///
    /// # Errors
    ///
    /// Rejects `lower_ms > upper_ms`.
    pub fn new(lower_ms: u64, upper_ms: u64) -> WalletResult<Self> {
        if lower_ms > upper_ms {
            return Err(invalid_v1("time_interval"));
        }
        Ok(Self { lower_ms, upper_ms })
    }

    /// Whether `deadline_ms` has passed: `U >= deadline`.
    #[must_use]
    pub const fn deadline_passed(&self, deadline_ms: u64) -> bool {
        self.upper_ms >= deadline_ms
    }

    /// Whether `start_ms` has been reached: `L >= start`.
    #[must_use]
    pub const fn start_reached(&self, start_ms: u64) -> bool {
        self.lower_ms >= start_ms
    }
}

/// One reading of the OS monotonic clock that keeps running in sleep (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletMonotonicReadingV1 {
    /// Identity of the current boot.
    pub boot_id: [u8; 32],
    /// Monotonic milliseconds since boot.
    pub monotonic_ms: u64,
}

/// Body of a time anchor, signed by a TimeAnchor-role key under `time-anchor-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletTimeAnchorBodyV1"
)]
pub struct KagemushaWalletTimeAnchorBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Requesting wallet.
    pub wallet_id: [u8; 32],
    /// Fresh nonce the wallet generated in the current boot.
    pub nonce: [u8; 32],
    /// Issuer's signed time `T` in Unix milliseconds.
    pub issuer_time_ms: u64,
    /// Certificate digest of the TimeAnchor-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletTimeAnchorBodyV1 {
    /// Exact `time-anchor-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_TIME_ANCHOR_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.wallet_id)
            .digest(&self.nonce)
            .u64(self.issuer_time_ms)
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwtanc1, transcript)`: the 32 bytes the TimeAnchor-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::TimeAnchor, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version or zero bindings.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("time_anchor.version", self.version)?;
        require_nonzero_v1("time_anchor.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("time_anchor.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("time_anchor.nonce", &self.nonce)?;
        require_nonzero_field_v1("time_anchor.signer_certificate", &self.signer_certificate)
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "time_anchor.scheme_id",
            certificate_field: "time_anchor.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::TimeAnchor,
            domain: Domain::TimeAnchor,
        }
    }
}

/// Signed issuer time response to one wallet nonce (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletTimeAnchorV1"
)]
pub struct KagemushaWalletTimeAnchorV1 {
    /// Signed body.
    pub body: KagemushaWalletTimeAnchorBodyV1,
    /// TimeAnchor-role signature over `time-anchor-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletTimeAnchorV1 {
    /// Freeze a TimeAnchor-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a certificate that is not the body's TimeAnchor-role signer
    /// for its scheme, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletTimeAnchorBodyV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self { body, signature })
    }

    /// Time anchor object digest `P(kgwotim1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn time_anchor_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::TimeAnchor,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the anchor's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the anchor under `scheme` and its TimeAnchor-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid anchor, another scheme, a certificate that is not its TimeAnchor-role
    /// signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid anchor or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1)
    }

    /// Decode one canonical time anchor frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let anchor: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1)?;
        anchor.require_versions()?;
        require_scheme_v1(
            "time_anchor.scheme_id",
            &anchor.body.scheme_id,
            expected_scheme_id,
        )?;
        anchor.validate()?;
        Ok(anchor)
    }
}

/// Local same-boot anchor: the signed anchor and the monotonic readings at request and
/// response (§7). It is local custody data, never transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAnchoredTimeV1"
)]
pub struct KagemushaWalletAnchoredTimeV1 {
    /// Signed issuer time response.
    pub anchor: KagemushaWalletTimeAnchorV1,
    /// Boot in which the request and response were observed.
    pub boot_id: [u8; 32],
    /// Monotonic reading `m_req` when the request was sent.
    pub request_monotonic_ms: u64,
    /// Monotonic reading `m_rcv` when the response arrived.
    pub receive_monotonic_ms: u64,
}

impl KagemushaWalletAnchoredTimeV1 {
    /// Record a direct anchor exchange and check its response age.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn new(
        anchor: KagemushaWalletTimeAnchorV1,
        boot_id: [u8; 32],
        request_monotonic_ms: u64,
        receive_monotonic_ms: u64,
        max_response_ms: u64,
    ) -> WalletResult<Self> {
        let anchored = Self {
            anchor,
            boot_id,
            request_monotonic_ms,
            receive_monotonic_ms,
        };
        anchored.validate(max_response_ms)?;
        Ok(anchored)
    }

    /// Anchor uncertainty `m_rcv - m_req`.
    ///
    /// # Errors
    ///
    /// Rejects a response observed before its request.
    pub fn response_width_ms(&self) -> WalletResult<u64> {
        self.receive_monotonic_ms
            .checked_sub(self.request_monotonic_ms)
            .ok_or_else(|| invalid_v1("anchored_time.monotonic"))
    }

    /// Validate the anchor and its response age against `max_response_ms`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid anchor, a zero boot identity, a response before its request, and a
    /// response age above `max_response_ms`.
    pub fn validate(&self, max_response_ms: u64) -> WalletResult<()> {
        self.anchor.validate()?;
        require_nonzero_v1("anchored_time.boot_id", &self.boot_id)?;
        if self.response_width_ms()? > max_response_ms {
            return Err(invalid_v1("anchored_time.response_age"));
        }
        Ok(())
    }

    /// Real-time interval at reading `now`: `[T + (m - m_rcv), T + (m - m_req)]`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, a reading from another boot or before the
    /// response, and an interval end that overflows `u64`.
    pub fn interval_at(
        &self,
        now: &KagemushaWalletMonotonicReadingV1,
        max_response_ms: u64,
    ) -> WalletResult<KagemushaWalletTimeIntervalV1> {
        self.validate(max_response_ms)?;
        if now.boot_id != self.boot_id {
            return Err(invalid_v1("anchored_time.boot_id"));
        }
        let since_receive = now
            .monotonic_ms
            .checked_sub(self.receive_monotonic_ms)
            .ok_or_else(|| invalid_v1("anchored_time.monotonic"))?;
        let since_request = now
            .monotonic_ms
            .checked_sub(self.request_monotonic_ms)
            .ok_or_else(|| invalid_v1("anchored_time.monotonic"))?;
        let issuer_time = self.anchor.body.issuer_time_ms;
        let lower = issuer_time
            .checked_add(since_receive)
            .ok_or_else(|| overflow_v1("anchored_time.lower_ms"))?;
        let upper = issuer_time
            .checked_add(since_request)
            .ok_or_else(|| overflow_v1("anchored_time.upper_ms"))?;
        KagemushaWalletTimeIntervalV1::new(lower, upper)
    }
}

// ---------------------------------------------------------------------------------------
// Quota windows and shares (§7, design §6.4 and C6)
// ---------------------------------------------------------------------------------------

/// Kind of one quota window.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaWindowKindV1"
)]
pub enum KagemushaWalletQuotaWindowKindV1 {
    /// Daily window.
    #[codec(index = 1)]
    Daily,
    /// Monthly window.
    #[codec(index = 2)]
    Monthly,
}

impl KagemushaWalletQuotaWindowKindV1 {
    /// Every window kind, in tag order.
    pub const ALL: [Self; 2] = [Self::Daily, Self::Monthly];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Daily => 1,
            Self::Monthly => 2,
        }
    }
}

/// One half-open quota window `[start_ms, end_ms)` and its gross sending limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaWindowV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletQuotaWindowV1 {
    /// Window kind.
    pub kind: KagemushaWalletQuotaWindowKindV1,
    /// Inclusive start in Unix milliseconds.
    pub start_ms: u64,
    /// Exclusive end in Unix milliseconds; after `start_ms`.
    pub end_ms: u64,
    /// Maximum gross `amount + fee` sent in this window.
    pub limit: u128,
}

impl KagemushaWalletQuotaWindowV1 {
    /// Window leaf elements: kind tag, start, end, limit (4).
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        quota_window_items_v1(self.kind.tag(), self.start_ms, self.end_ms, self.limit)
    }

    /// Window leaf `P(kgwqwin1, elements)` (§7).
    #[must_use]
    pub fn leaf_value(&self) -> [u8; 32] {
        poseidon_items_v1(KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1, &self.field_items())
    }

    /// Validate the window's fields.
    ///
    /// # Errors
    ///
    /// Rejects an empty or inverted window.
    pub fn validate(&self) -> WalletResult<()> {
        if self.end_ms <= self.start_ms {
            return Err(invalid_v1("quota_window.end_ms"));
        }
        Ok(())
    }

    /// Whether the window intersects `interval`: `start <= U && L < end` (design C6).
    #[must_use]
    pub const fn intersects(&self, interval: &KagemushaWalletTimeIntervalV1) -> bool {
        self.start_ms <= interval.upper_ms && interval.lower_ms < self.end_ms
    }

    /// Charge `gross` on top of `used` and return the new usage.
    ///
    /// # Errors
    ///
    /// Rejects an overflowing sum and a sum above the limit.
    pub fn charge(&self, used: u128, gross: u128) -> WalletResult<u128> {
        let total = used
            .checked_add(gross)
            .ok_or_else(|| overflow_v1("quota_window.used"))?;
        if total > self.limit {
            return Err(invalid_v1("quota_window.limit"));
        }
        Ok(total)
    }
}

/// Elements of one window slot.
fn quota_window_items_v1(kind: u8, start_ms: u64, end_ms: u64, limit: u128) -> Vec<[u8; 32]> {
    WalletFieldItemsV1::with_capacity(4)
        .integer(u128::from(kind))
        .integer(u128::from(start_ms))
        .integer(u128::from(end_ms))
        .integer(limit)
        .finish()
}

/// Empty window slot: the window leaf of four zero elements, `P(kgwqwin1, [0, 0, 0, 0])`.
#[must_use]
pub fn kagemusha_wallet_quota_empty_window_leaf_v1() -> [u8; 32] {
    poseidon_items_v1(
        KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1,
        &quota_window_items_v1(0, 0, 0, 0),
    )
}

/// Tree node `P(kgwqwnd1, [left, right])` over canonical children.
///
/// # Errors
///
/// Rejects a noncanonical child.
pub fn kagemusha_wallet_quota_node_v1(left: &[u8; 32], right: &[u8; 32]) -> WalletResult<[u8; 32]> {
    require_canonical_field_v1("quota_share.node", left)?;
    require_canonical_field_v1("quota_share.node", right)?;
    Ok(poseidon_items_v1(
        KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1,
        &[*left, *right],
    ))
}

fn quota_window_levels_v1(
    windows: &[KagemushaWalletQuotaWindowV1],
) -> WalletResult<Vec<Vec<[u8; 32]>>> {
    if windows.len() > KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1 {
        return Err(invalid_v1("quota_share.windows"));
    }
    let empty = kagemusha_wallet_quota_empty_window_leaf_v1();
    let leaves = (0..KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1)
        .map(|slot| {
            windows
                .get(slot)
                .map_or(empty, KagemushaWalletQuotaWindowV1::leaf_value)
        })
        .collect();
    Ok(quota_tree_levels_v1(
        leaves,
        KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1,
    ))
}

/// Windows root: a Poseidon tree of fixed depth 6 over 64 slots, windows first, empty slots
/// after (§7); one canonical σ-field value.
///
/// # Errors
///
/// Rejects more than [`KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1`] windows.
pub fn kagemusha_wallet_quota_windows_root_v1(
    windows: &[KagemushaWalletQuotaWindowV1],
) -> WalletResult<[u8; 32]> {
    quota_window_levels_v1(windows)?
        .last()
        .and_then(|root| root.first())
        .copied()
        .ok_or_else(|| invalid_v1("quota_share.windows"))
}

/// Opening of window slot `slot` against [`kagemusha_wallet_quota_windows_root_v1`]: exactly 6
/// siblings, height 0 first (§3.3).
///
/// # Errors
///
/// Rejects more than 64 windows and a slot outside the tree.
pub fn kagemusha_wallet_quota_window_opening_v1(
    windows: &[KagemushaWalletQuotaWindowV1],
    slot: u8,
) -> WalletResult<KagemushaWalletQuotaOpeningV1> {
    quota_tree_opening_v1(&quota_window_levels_v1(windows)?, slot)
}

/// One in-place quota charge of a Send (§3.3 Time; owner answer B5, technical decision Q7):
/// the touched window and its usage leaf open at the same slot, the window against the head's
/// `quota_windows_root` and the usage leaf against the quota-usage root of the preceding charge,
/// and the slot's `used` grows by the Send's gross amount within the window's limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletQuotaChargeV1 {
    /// Touched window.
    pub window: KagemushaWalletQuotaWindowV1,
    /// Opening of the window's slot in the quota-window tree.
    pub window_opening: KagemushaWalletQuotaOpeningV1,
    /// Usage leaf of the slot before the charge.
    pub usage: KagemushaWalletQuotaUsageLeafV1,
    /// Opening of the slot in the quota-usage array before the charge.
    pub usage_opening: KagemushaWalletQuotaOpeningV1,
}

impl KagemushaWalletQuotaChargeV1 {
    /// Slot of the charge.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.window_opening.slot
    }

    /// Verify the charge of `gross` against `windows_root` and the usage root `usage_root`
    /// before it, and return the usage root after it.
    ///
    /// # Errors
    ///
    /// Rejects openings at different slots, a window or usage leaf that does not open, a usage
    /// leaf of another window, and a charge that overflows or exceeds the window's limit.
    pub fn verify(
        &self,
        windows_root: &[u8; 32],
        usage_root: &[u8; 32],
        gross: u128,
    ) -> WalletResult<[u8; 32]> {
        if self.window_opening.slot != self.usage_opening.slot {
            return Err(invalid_v1("quota_charge.slot"));
        }
        if self.window_opening.window_root(&self.window.leaf_value())? != *windows_root {
            return Err(invalid_v1("quota_charge.window"));
        }
        if !self.usage.matches_window(&self.window) {
            return Err(invalid_v1("quota_charge.usage"));
        }
        if self.usage_opening.usage_root(&self.usage.leaf_value())? != *usage_root {
            return Err(invalid_v1("quota_charge.usage_root"));
        }
        let charged = KagemushaWalletQuotaUsageLeafV1 {
            used: self.window.charge(self.usage.used, gross)?,
            ..self.usage
        };
        self.usage_opening.usage_root(&charged.leaf_value())
    }
}

/// Verify a Send's quota charges in canonical witness order and return the successor
/// quota-usage root (§3.3 Time; owner answers B5 and B8, technical decision Q7).
///
/// Each touched window is charged exactly once, in place at its own slot: slots strictly
/// ascend (Daily windows precede Monthly ones because windows are sorted by `(kind, start)`, so
/// this is the order Daily then Monthly, each by ascending slot) and no slot repeats; at most two
/// windows of each kind are charged; and each usage opening is against the root produced by the
/// preceding charge. Distinct in-place updates commute, so the successor root does not depend
/// on the order. Window segment completeness (no touched window outside the charges) is
/// `σ_send`'s and the native pre-check's.
///
/// # Errors
///
/// Rejects slots that do not strictly ascend, more than two charges of one kind, and what
/// [`KagemushaWalletQuotaChargeV1::verify`] rejects.
pub fn kagemusha_wallet_verify_quota_charges_v1(
    windows_root: &[u8; 32],
    usage_root: &[u8; 32],
    charges: &[KagemushaWalletQuotaChargeV1],
    gross: u128,
) -> WalletResult<[u8; 32]> {
    let mut root = *usage_root;
    let mut previous: Option<u8> = None;
    for charge in charges {
        if previous.is_some_and(|previous| previous >= charge.slot()) {
            return Err(invalid_v1("quota_charge.order"));
        }
        previous = Some(charge.slot());
        let same_kind = charges
            .iter()
            .filter(|other| other.window.kind == charge.window.kind)
            .count();
        if same_kind > 2 {
            return Err(invalid_v1("quota_charge.candidates"));
        }
        root = charge.verify(windows_root, &root, gross)?;
    }
    Ok(root)
}

/// Body of a wallet quota share, signed by a RegulatoryPolicy-role key under
/// `quota-share-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaShareBodyV1"
)]
pub struct KagemushaWalletQuotaShareBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Wallet receiving the share.
    pub wallet_id: [u8; 32],
    /// Share identity; strictly increasing from the implicit default zero.
    pub share_id: u64,
    /// Issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Expiry in Unix milliseconds; after `issued_at_ms`.
    pub expires_at_ms: u64,
    /// Windows root ([`kagemusha_wallet_quota_windows_root_v1`]), a canonical σ-field value.
    pub windows_root: [u8; 32],
    /// Number of windows, `1..=64`.
    pub window_count: u32,
    /// Certificate digest of the RegulatoryPolicy-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletQuotaShareBodyV1 {
    /// Exact `quota-share-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_QUOTA_SHARE_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.wallet_id)
            .u64(self.share_id)
            .u64(self.issued_at_ms)
            .u64(self.expires_at_ms)
            .digest(&self.windows_root)
            .u32(self.window_count)
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwqshr1, transcript)`: the 32 bytes the RegulatoryPolicy-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::QuotaShare, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a noncanonical root, share id zero (the implicit
    /// default), an expiry not after issuance, and a window count outside `1..=64`.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("quota_share.version", self.version)?;
        require_nonzero_v1("quota_share.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("quota_share.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("quota_share.wallet_id", &self.wallet_id)?;
        require_nonzero_field_v1("quota_share.windows_root", &self.windows_root)?;
        require_nonzero_field_v1("quota_share.signer_certificate", &self.signer_certificate)?;
        if self.share_id == 0 {
            return Err(invalid_v1("quota_share.share_id"));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(invalid_v1("quota_share.expires_at_ms"));
        }
        let count = usize::try_from(self.window_count)
            .map_err(|_| overflow_v1("quota_share.window_count"))?;
        if count == 0 || count > KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1 {
            return Err(invalid_v1("quota_share.window_count"));
        }
        Ok(())
    }

    /// Validate `windows` against this body (design §6.4, C6).
    ///
    /// # Errors
    ///
    /// Rejects another count, an invalid window, a window outside
    /// `[issued_at_ms, expires_at_ms]`, windows not strictly sorted by `(kind, start)`,
    /// overlapping windows of one kind, and another root.
    pub fn validate_windows(&self, windows: &[KagemushaWalletQuotaWindowV1]) -> WalletResult<()> {
        let count = u32::try_from(windows.len()).map_err(|_| overflow_v1("quota_share.windows"))?;
        if count != self.window_count {
            return Err(invalid_v1("quota_share.window_count"));
        }
        let mut previous: Option<&KagemushaWalletQuotaWindowV1> = None;
        for window in windows {
            window.validate()?;
            if window.start_ms < self.issued_at_ms || window.end_ms > self.expires_at_ms {
                return Err(invalid_v1("quota_share.window_bounds"));
            }
            if let Some(previous) = previous {
                if (previous.kind, previous.start_ms) >= (window.kind, window.start_ms) {
                    return Err(invalid_v1("quota_share.window_order"));
                }
                let overlaps = window.start_ms < previous.end_ms;
                if previous.kind == window.kind && overlaps {
                    return Err(invalid_v1("quota_share.window_overlap"));
                }
            }
            previous = Some(window);
        }
        if kagemusha_wallet_quota_windows_root_v1(windows)? != self.windows_root {
            return Err(invalid_v1("quota_share.windows_root"));
        }
        Ok(())
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "quota_share.scheme_id",
            certificate_field: "quota_share.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            domain: Domain::QuotaShare,
        }
    }
}

/// Slots of the windows that `interval` touches (`start ≤ U` and `L < end`), in ascending
/// order, requiring at least one touched window of every kind `windows` defines and at most two
/// of each kind (design C6, owner answer B8).
fn touched_quota_slots_v1(
    windows: &[KagemushaWalletQuotaWindowV1],
    interval: &KagemushaWalletTimeIntervalV1,
) -> WalletResult<Vec<u8>> {
    let mut slots = Vec::new();
    for (slot, window) in windows.iter().enumerate() {
        if window.intersects(interval) {
            slots.push(u8::try_from(slot).map_err(|_| overflow_v1("quota_share.windows"))?);
        }
    }
    for kind in KagemushaWalletQuotaWindowKindV1::ALL {
        let defined = windows.iter().any(|window| window.kind == kind);
        let touched = slots
            .iter()
            .filter(|slot| windows[usize::from(**slot)].kind == kind)
            .count();
        if defined && touched == 0 {
            return Err(invalid_v1("quota_share.no_window"));
        }
        if touched > 2 {
            return Err(invalid_v1("quota_share.span"));
        }
    }
    Ok(slots)
}

/// Signed quota share of one wallet with its windows (§7).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletQuotaShareV1"
)]
pub struct KagemushaWalletQuotaShareV1 {
    /// Signed body.
    pub body: KagemushaWalletQuotaShareBodyV1,
    /// Windows sorted by `(kind, start)`, non-overlapping per kind.
    pub windows: Vec<KagemushaWalletQuotaWindowV1>,
    /// RegulatoryPolicy-role signature over `quota-share-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletQuotaShareV1 {
    /// Freeze a RegulatoryPolicy-role signature over `body` for `windows`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, windows that do not match it, a certificate that is not the
    /// body's RegulatoryPolicy-role signer, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletQuotaShareBodyV1,
        windows: Vec<KagemushaWalletQuotaWindowV1>,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        body.validate_windows(&windows)?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self {
            body,
            windows,
            signature,
        })
    }

    /// Quota share object digest `P(kgwoqsh1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn quota_share_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::QuotaShare,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the share's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, signature encoding or windows.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        self.body.validate_windows(&self.windows)
    }

    /// Verify the share under `scheme` and its RegulatoryPolicy-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid share, another scheme, a certificate that is not its
    /// RegulatoryPolicy-role signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Require that the share was issued to `wallet_id` for `scheme_id` and `asset_digest`.
    ///
    /// # Errors
    ///
    /// Rejects another scheme, asset or wallet.
    pub fn require_wallet(
        &self,
        scheme_id: &[u8; 32],
        asset_digest: &[u8; 32],
        wallet_id: &[u8; 32],
    ) -> WalletResult<()> {
        require_scheme_v1("quota_share.scheme_id", &self.body.scheme_id, scheme_id)?;
        if self.body.asset_digest != *asset_digest {
            return Err(invalid_v1("quota_share.asset_digest"));
        }
        if self.body.wallet_id != *wallet_id {
            return Err(invalid_v1("quota_share.wallet_id"));
        }
        Ok(())
    }

    /// The share's windows after checking them against the signed body.
    ///
    /// The quota share digest covers the body (and so `windows_root`) and the signature but not
    /// the `windows` vector, so every use of the windows first recomputes their root.
    fn authenticated_windows(&self) -> WalletResult<&[KagemushaWalletQuotaWindowV1]> {
        self.body.validate()?;
        self.body.validate_windows(&self.windows)?;
        Ok(&self.windows)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid share or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1)
    }

    /// Decode one canonical quota share frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields or windows.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let share: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1)?;
        share.require_versions()?;
        require_scheme_v1(
            "quota_share.scheme_id",
            &share.body.scheme_id,
            expected_scheme_id,
        )?;
        share.validate()?;
        Ok(share)
    }
}

// ---------------------------------------------------------------------------------------
// Load and unload charge quotes (§6.2, design C7)
// ---------------------------------------------------------------------------------------

/// Ledger operation priced by a charge quote.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletChargeKindV1"
)]
pub enum KagemushaWalletChargeKindV1 {
    /// Load: the ledger debits `net_amount + online_charge`.
    #[codec(index = 1)]
    Load,
    /// Unload: the ledger pays `net_amount - online_charge` to the account.
    #[codec(index = 2)]
    Unload,
}

impl KagemushaWalletChargeKindV1 {
    /// Every charge kind, in tag order.
    pub const ALL: [Self; 2] = [Self::Load, Self::Unload];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Load => 1,
            Self::Unload => 2,
        }
    }
}

/// Ledger debit of a load: `net_amount + online_charge` (design C7).
///
/// # Errors
///
/// Rejects an overflowing sum.
pub fn kagemusha_wallet_load_ledger_debit_v1(
    net_amount: u128,
    online_charge: u128,
) -> WalletResult<u128> {
    net_amount
        .checked_add(online_charge)
        .ok_or_else(|| overflow_v1("charge.ledger_debit"))
}

/// Account payout of an unload: `net_amount - online_charge` (design C7).
///
/// # Errors
///
/// Rejects an online charge above the net amount.
pub fn kagemusha_wallet_unload_account_payout_v1(
    net_amount: u128,
    online_charge: u128,
) -> WalletResult<u128> {
    net_amount
        .checked_sub(online_charge)
        .ok_or_else(|| invalid_v1("charge.online_charge"))
}

/// Body of a displayed load or unload charge quote, signed by a RegulatoryPolicy-role key
/// under `charge-quote-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletChargeQuoteBodyV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletChargeQuoteBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Charged wallet.
    pub wallet_id: [u8; 32],
    /// Priced operation.
    pub kind: KagemushaWalletChargeKindV1,
    /// Load or redemption ordinal.
    pub ordinal: u128,
    /// Exact net offline value.
    pub net_amount: u128,
    /// Separate online charge; positive.
    pub online_charge: u128,
    /// Account digest of the online charge beneficiary.
    pub beneficiary_account_digest: [u8; 32],
    /// Issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Certificate digest of the RegulatoryPolicy-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletChargeQuoteBodyV1 {
    /// Exact `charge-quote-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CHARGE_QUOTE_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.wallet_id)
            .u8(self.kind.tag())
            .u128(self.ordinal)
            .u128(self.net_amount)
            .u128(self.online_charge)
            .digest(&self.beneficiary_account_digest)
            .u64(self.issued_at_ms)
            .digest(&self.signer_certificate)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwchgq1, transcript)`: the 32 bytes the RegulatoryPolicy-role signer signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::ChargeQuote, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a zero online charge, a load whose ledger
    /// debit overflows, and an unload whose net amount is zero or below its online charge.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("charge_quote.version", self.version)?;
        require_nonzero_v1("charge_quote.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("charge_quote.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("charge_quote.wallet_id", &self.wallet_id)?;
        require_nonzero_v1(
            "charge_quote.beneficiary_account_digest",
            &self.beneficiary_account_digest,
        )?;
        require_nonzero_field_v1("charge_quote.signer_certificate", &self.signer_certificate)?;
        if self.online_charge == 0 {
            return Err(invalid_v1("charge_quote.online_charge"));
        }
        match self.kind {
            KagemushaWalletChargeKindV1::Load => {
                kagemusha_wallet_load_ledger_debit_v1(self.net_amount, self.online_charge)?;
            }
            KagemushaWalletChargeKindV1::Unload => {
                if self.net_amount == 0 {
                    return Err(invalid_v1("charge_quote.net_amount"));
                }
                kagemusha_wallet_unload_account_payout_v1(self.net_amount, self.online_charge)?;
            }
        }
        Ok(())
    }

    fn binding(&self) -> SignerBindingV1<'_> {
        SignerBindingV1 {
            scheme_field: "charge_quote.scheme_id",
            certificate_field: "charge_quote.signer_certificate",
            scheme_id: &self.scheme_id,
            certificate: &self.signer_certificate,
            role: KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            domain: Domain::ChargeQuote,
        }
    }
}

/// Signed load or unload charge quote (§6.2, design C7).
///
/// An Unload effect names it by digest ([`Self::require_unload_effect`]); an ordinary Load receipt names
/// it by digest and must carry its exact terms
/// (`KagemushaWalletLoadReceiptV1::require_charge_quote`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletChargeQuoteV1"
)]
pub struct KagemushaWalletChargeQuoteV1 {
    /// Signed body.
    pub body: KagemushaWalletChargeQuoteBodyV1,
    /// RegulatoryPolicy-role signature over `charge-quote-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletChargeQuoteV1 {
    /// Freeze a RegulatoryPolicy-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a certificate that is not the body's RegulatoryPolicy-role
    /// signer for its scheme, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletChargeQuoteBodyV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        let signature =
            body.binding()
                .freeze(signer_certificate, &body.transcript(), signer_output)?;
        Ok(Self { body, signature })
    }

    /// Charge quote object digest `P(kgwochg1, [m, r_lo, r_hi, s_lo, s_hi])` (owner
    /// answer B1), one canonical σ-field value.
    #[must_use]
    pub fn charge_quote_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::ChargeQuote,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the quote's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the quote under `scheme` and its RegulatoryPolicy-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid quote, another scheme, a certificate that is not its
    /// RegulatoryPolicy-role signer, or a signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.binding().verify(
            scheme,
            signer_certificate,
            &self.body.transcript(),
            &self.signature,
        )
    }

    /// Require that the quote prices exactly the given operation terms.
    ///
    /// # Errors
    ///
    /// Rejects another kind, wallet, ordinal, net amount or online charge.
    pub fn require_terms(
        &self,
        kind: KagemushaWalletChargeKindV1,
        wallet_id: &[u8; 32],
        ordinal: u128,
        net_amount: u128,
        online_charge: u128,
    ) -> WalletResult<()> {
        let body = &self.body;
        if body.kind != kind {
            return Err(invalid_v1("charge_quote.kind"));
        }
        if body.wallet_id != *wallet_id {
            return Err(invalid_v1("charge_quote.wallet_id"));
        }
        if body.ordinal != ordinal {
            return Err(invalid_v1("charge_quote.ordinal"));
        }
        if body.net_amount != net_amount {
            return Err(invalid_v1("charge_quote.net_amount"));
        }
        if body.online_charge != online_charge {
            return Err(invalid_v1("charge_quote.online_charge"));
        }
        Ok(())
    }

    /// Require that an Unload effect of `wallet_id` names this quote and its exact terms.
    ///
    /// # Errors
    ///
    /// Rejects a non-Unload effect, an effect naming another quote, or other terms.
    pub fn require_unload_effect(
        &self,
        effect: &KagemushaWalletEffectV1,
        wallet_id: &[u8; 32],
    ) -> WalletResult<()> {
        match effect {
            KagemushaWalletEffectV1::Unload {
                redeem_ordinal,
                amount,
                online_charge,
                charge_quote,
                ..
            } => {
                if *charge_quote != self.charge_quote_digest() {
                    return Err(invalid_v1("effect.charge_quote"));
                }
                self.require_terms(
                    KagemushaWalletChargeKindV1::Unload,
                    wallet_id,
                    *redeem_ordinal,
                    *amount,
                    *online_charge,
                )
            }
            _ => Err(invalid_v1("effect.kind")),
        }
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid quote or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1)
    }

    /// Decode one canonical charge quote frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let quote: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1)?;
        quote.require_versions()?;
        require_scheme_v1(
            "charge_quote.scheme_id",
            &quote.body.scheme_id,
            expected_scheme_id,
        )?;
        quote.validate()?;
        Ok(quote)
    }
}

// ---------------------------------------------------------------------------------------
// RefreshPolicy and Send-time control checks (§7, design C5 and C6)
// ---------------------------------------------------------------------------------------

/// One authenticated update applied by a `RefreshPolicy` transition.
///
/// The caller verifies each object's signer (scheme root, certificate and role) before
/// applying it; [`KagemushaWalletStateV1::refresh_policy`] applies the state rules.
#[derive(Debug, Clone, Copy)]
pub enum KagemushaWalletPolicyUpdateV1<'a> {
    /// Replacement credential (lease renewal).
    Credential {
        /// Current credential of the state.
        previous: &'a KagemushaWalletCredentialV1,
        /// Replacement credential.
        replacement: &'a KagemushaWalletCredentialV1,
    },
    /// Newer scheme policy.
    SchemePolicy {
        /// Signed scheme policy.
        policy: &'a KagemushaWalletSchemePolicyV1,
    },
    /// Newer blacklist and its insertion into the blacklist history (owner answer B6).
    Blacklist {
        /// Complete signed blacklist.
        list: &'a KagemushaWalletBlacklistV1,
        /// Insertion witness of `(list_version, entries_root)` against the predecessor's
        /// `blacklist_history_root`, from the native history store
        /// ([`super::KagemushaWalletBlacklistHistoryLeafV1::insert_into`]).
        history: &'a KagemushaWalletIndexedInsertV1,
    },
    /// Newer quota share and the predecessor's quota-usage array (owner answers B4, B5).
    QuotaShare {
        /// Signed quota share.
        share: &'a KagemushaWalletQuotaShareV1,
        /// Predecessor's native quota-usage array; its root must be the predecessor's
        /// `quota_usage_root`.
        usage: &'a KagemushaWalletQuotaUsageArrayV1,
    },
    /// Time anchor committed after a boot.
    TimeAnchor {
        /// Signed time anchor.
        anchor: &'a KagemushaWalletTimeAnchorV1,
    },
}

impl KagemushaWalletPolicyUpdateV1<'_> {
    /// Update kind bound in the `RefreshPolicy` effect.
    #[must_use]
    pub const fn kind(&self) -> KagemushaWalletPolicyUpdateKindV1 {
        match self {
            Self::Credential { .. } => KagemushaWalletPolicyUpdateKindV1::Credential,
            Self::SchemePolicy { .. } => KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            Self::Blacklist { .. } => KagemushaWalletPolicyUpdateKindV1::Blacklist,
            Self::QuotaShare { .. } => KagemushaWalletPolicyUpdateKindV1::QuotaShare,
            Self::TimeAnchor { .. } => KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
        }
    }
}

/// Successor policy fields of one `RefreshPolicy` transition.
///
/// `core` and `rest` are the predecessor's with the update applied to the policy fields
/// (credential digest, enabled controls, policy epoch, blacklist version, root and issue time,
/// quota windows root, share expiry and usage root, lease and accepted-time floor in the core;
/// scheme policy, fee schedule, blacklist, quota share, time anchor and blacklist-history root
/// in the rest). Sequence, balance, ordinals, chains, the indexed map roots and nonce are
/// unchanged: the transition owner advances them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletPolicyRefreshV1 {
    /// Successor credential digest; it changes only for a replacement credential.
    pub credential_digest: [u8; 32],
    /// Successor core policy fields.
    pub core: KagemushaWalletStateCoreV1,
    /// Successor rest policy fields.
    pub rest: KagemushaWalletStateRestV1,
    /// Rebuilt quota-usage array of a quota-share refresh, whose root is `core.quota_usage_root`;
    /// `None` for every other update kind, which keeps the predecessor's array.
    pub quota_usage: Option<KagemushaWalletQuotaUsageArrayV1>,
    /// `RefreshPolicy` effect binding the update and the successor floor.
    pub effect: KagemushaWalletEffectV1,
}

impl KagemushaWalletStateV1 {
    /// Apply one authenticated policy update (§7, design C5 and C6; owner answers B4 to B8).
    ///
    /// Epochs, list versions and share ids strictly increase; a time anchor must differ from
    /// the committed one, so no two transitions share an operation ID; a replacement
    /// credential must be the exact successor of the current one; the new floor is
    /// `F = max(old floor, t)` with `t` the update's signed time (the old floor for a scheme
    /// policy). A Blacklist update also inserts `(list_version, entries_root)` into the
    /// blacklist history. A `QuotaShare` update requires every window to be longer than
    /// `time_anchor_max_response_ms`, sets `quota_share_expires_at_ms` to the share's expiry and
    /// rebuilds the quota-usage array from the predecessor's
    /// ([`KagemushaWalletQuotaUsageArrayV1::rebuild_for_share`]); every other update keeps
    /// `quota_usage_root`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid state or update, an update for another scheme, asset or wallet, a
    /// non-increasing epoch, version or share id, the already committed time anchor, an
    /// invalid replacement credential, a history insertion that is not the new list's pair
    /// under the predecessor's history root, a usage array other than the predecessor's, and
    /// what the quota-usage rebuild rejects.
    pub fn refresh_policy(
        &self,
        update: KagemushaWalletPolicyUpdateV1<'_>,
    ) -> WalletResult<KagemushaWalletPolicyRefreshV1> {
        self.validate()?;
        let old_core = self.core;
        let old_rest = self.rest;
        let mut core = old_core;
        let mut rest = old_rest;
        let mut quota_usage = None;
        let (digest, signed_time_ms) = match update {
            KagemushaWalletPolicyUpdateV1::Credential {
                previous,
                replacement,
            } => {
                self.validate_for_credential(previous)?;
                replacement.validate_replacement_of(previous)?;
                core.credential_digest = replacement.credential_digest();
                core.lease_expires_at_ms = replacement.body.lease_expires_at_ms;
                (core.credential_digest, replacement.body.issued_at_ms)
            }
            KagemushaWalletPolicyUpdateV1::SchemePolicy {
                policy: scheme_policy,
            } => {
                scheme_policy.validate()?;
                require_scheme_v1(
                    "scheme_policy.scheme_id",
                    &scheme_policy.body.scheme_id,
                    &old_core.scheme_id,
                )?;
                if scheme_policy.body.asset_digest != old_core.asset_digest {
                    return Err(invalid_v1("scheme_policy.asset_digest"));
                }
                if scheme_policy.body.policy_epoch <= old_core.policy_epoch {
                    return Err(invalid_v1("scheme_policy.policy_epoch"));
                }
                rest.scheme_policy = scheme_policy.scheme_policy_digest();
                core.policy_epoch = scheme_policy.body.policy_epoch;
                core.enabled_controls =
                    scheme_policy.body.enabled_controls & old_rest.permitted_controls;
                rest.fee_schedule = scheme_policy.body.fee_schedule;
                (rest.scheme_policy, old_core.accepted_time_floor_ms)
            }
            KagemushaWalletPolicyUpdateV1::Blacklist { list, history } => {
                list.validate()?;
                require_scheme_v1(
                    "blacklist.scheme_id",
                    &list.body.scheme_id,
                    &old_core.scheme_id,
                )?;
                if list.body.list_version <= old_core.blacklist_version {
                    return Err(invalid_v1("blacklist.list_version"));
                }
                let entry = KagemushaWalletBlacklistHistoryLeafV1 {
                    list_version: list.body.list_version,
                    entries_root: list.body.entries_root,
                };
                rest.blacklist_history_root = history
                    .verify(
                        &old_rest.blacklist_history_root,
                        &entry.key(),
                        &entry.leaf_value()?,
                    )
                    .map_err(|_| invalid_v1("blacklist_history.insert"))?;
                rest.blacklist = list.blacklist_digest();
                core.blacklist_version = list.body.list_version;
                core.blacklist_root = list.body.entries_root;
                core.blacklist_issued_at_ms = list.body.issued_at_ms;
                (rest.blacklist, list.body.issued_at_ms)
            }
            KagemushaWalletPolicyUpdateV1::QuotaShare { share, usage } => {
                share.validate()?;
                share.require_wallet(
                    &old_core.scheme_id,
                    &old_core.asset_digest,
                    &old_core.wallet_id,
                )?;
                if share.body.share_id <= old_rest.quota_share_id {
                    return Err(invalid_v1("quota_share.share_id"));
                }
                if usage.root() != old_core.quota_usage_root {
                    return Err(invalid_v1("state.core.quota_usage_root"));
                }
                let floor = old_core.accepted_time_floor_ms.max(share.body.issued_at_ms);
                let rebuilt = usage.rebuild_for_share(
                    old_rest.quota_share_id == 0,
                    &share.windows,
                    floor,
                    old_core.time_anchor_max_response_ms,
                )?;
                rest.quota_share = share.quota_share_digest();
                rest.quota_share_id = share.body.share_id;
                core.quota_windows_root = share.body.windows_root;
                core.quota_share_expires_at_ms = share.body.expires_at_ms;
                core.quota_usage_root = rebuilt.root();
                quota_usage = Some(rebuilt);
                (rest.quota_share, share.body.issued_at_ms)
            }
            KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor } => {
                anchor.validate()?;
                require_scheme_v1(
                    "time_anchor.scheme_id",
                    &anchor.body.scheme_id,
                    &old_core.scheme_id,
                )?;
                if anchor.body.wallet_id != old_core.wallet_id {
                    return Err(invalid_v1("time_anchor.wallet_id"));
                }
                // Re-committing the held anchor would repeat the earlier transition's
                // operation ID (§4.1); every other update kind strictly increases.
                let anchor_digest = anchor.time_anchor_digest();
                if anchor_digest == old_rest.time_anchor {
                    return Err(invalid_v1("time_anchor.unchanged"));
                }
                rest.time_anchor = anchor_digest;
                (rest.time_anchor, anchor.body.issuer_time_ms)
            }
        };
        core.accepted_time_floor_ms = old_core.accepted_time_floor_ms.max(signed_time_ms);
        Self {
            version: self.version,
            core,
            rest,
        }
        .validate()?;
        Ok(KagemushaWalletPolicyRefreshV1 {
            credential_digest: core.credential_digest,
            core,
            rest,
            quota_usage,
            effect: KagemushaWalletEffectV1::RefreshPolicy {
                update_kind: update.kind(),
                update: digest,
                accepted_time_floor_ms: core.accepted_time_floor_ms,
            },
        })
    }

    /// Effective accepted time `[L, U]` for a Send at reading `now` (§7, design §6.5, C6).
    ///
    /// `L = max(floor, anchor lower, receiver_accepted_time_ms)`; `U = max(anchor upper, L)`
    /// when anchored, else `L`. Pass `anchored` only for a same-boot anchor whose digest the
    /// state committed; the successor floor is `L`. A valid anchor implies
    /// `U − L ≤ time_anchor_max_response_ms` (the Send time span of owner answer B8).
    ///
    /// # Errors
    ///
    /// Rejects a missing anchor while a time-dependent control is active, an anchor for
    /// another scheme or wallet or not committed by the state, and an anchor interval that
    /// is not valid at `now`.
    pub(super) fn effective_accepted_time(
        &self,
        anchored: Option<&KagemushaWalletAnchoredTimeV1>,
        now: Option<&KagemushaWalletMonotonicReadingV1>,
        receiver_accepted_time_ms: u64,
    ) -> WalletResult<KagemushaWalletTimeIntervalV1> {
        let floor = self
            .core
            .accepted_time_floor_ms
            .max(receiver_accepted_time_ms);
        let Some(anchored) = anchored else {
            if self.send_requires_time_anchor() {
                return Err(invalid_v1("time_anchor.missing"));
            }
            return KagemushaWalletTimeIntervalV1::new(floor, floor);
        };
        let anchor = &anchored.anchor;
        require_scheme_v1(
            "time_anchor.scheme_id",
            &anchor.body.scheme_id,
            &self.core.scheme_id,
        )?;
        if anchor.body.wallet_id != self.core.wallet_id {
            return Err(invalid_v1("time_anchor.wallet_id"));
        }
        if anchor.time_anchor_digest() != self.rest.time_anchor {
            return Err(invalid_v1("state.rest.time_anchor"));
        }
        let now = now.ok_or_else(|| invalid_v1("time_anchor.observation_missing"))?;
        let interval = anchored.interval_at(now, self.core.time_anchor_max_response_ms)?;
        let lower = floor.max(interval.lower_ms);
        KagemushaWalletTimeIntervalV1::new(lower, interval.upper_ms.max(lower))
    }

    /// Attestation-lease part of the Send pre-check: `U < lease_expires_at_ms` while the lease
    /// control is active.
    ///
    /// # Errors
    ///
    /// Rejects a Send after the lease deadline.
    pub(super) fn check_lease(&self, interval: &KagemushaWalletTimeIntervalV1) -> WalletResult<()> {
        if self.is_active(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1)
            && interval.deadline_passed(self.core.lease_expires_at_ms)
        {
            return Err(invalid_v1("state.lease_expired"));
        }
        Ok(())
    }

    /// Whether this state enforces its committed blacklist: the BLACKLIST control is enabled
    /// and a list is held (`blacklist_version ≥ 1`). With version 0 no account is refused and no
    /// age rule applies (owner answer A5).
    #[must_use]
    pub const fn enforces_blacklist(&self) -> bool {
        self.is_active(KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1) && self.core.blacklist_version != 0
    }

    /// The receiver blacklist decision a Request issued from this head records (owner answer
    /// B6): the committed `(blacklist_version, blacklist_root)` while the state enforces its
    /// list ([`Self::enforces_blacklist`]), and `(0, 0)` otherwise.
    #[must_use]
    pub const fn request_blacklist_decision(&self) -> (u64, [u8; 32]) {
        if self.enforces_blacklist() {
            (self.core.blacklist_version, self.core.blacklist_root)
        } else {
            (0, [0; 32])
        }
    }

    /// Committed list of an enforcing state: `list` must be the held one.
    fn committed_blacklist<'a>(
        &self,
        list: Option<&'a KagemushaWalletBlacklistV1>,
    ) -> WalletResult<&'a KagemushaWalletBlacklistV1> {
        let list = list.ok_or_else(|| invalid_v1("blacklist.missing"))?;
        if list.blacklist_digest() != self.rest.blacklist {
            return Err(invalid_v1("state.rest.blacklist"));
        }
        Ok(list)
    }

    /// Non-membership of `account_digest` in the committed list, as a verified gap opening
    /// against the head-committed `blacklist_root`.
    fn blacklist_gap(
        &self,
        list: &KagemushaWalletBlacklistV1,
        account_digest: &[u8; 32],
    ) -> WalletResult<KagemushaWalletBlacklistGapOpeningV1> {
        let opening = list.gap_opening(account_digest)?;
        opening.verify(&self.core.blacklist_root, account_digest)?;
        Ok(opening)
    }

    /// Payer-side blacklist part of the Send pre-check (§7, design C6, owner answer A5): the
    /// payer's own committed list must not contain the receiver's account.
    ///
    /// Enforced only while [`Self::enforces_blacklist`]; returns the gap opening that witnesses
    /// non-membership (which `σ_send` proves), or `None` when no list is enforced. The list
    /// issue time and maximum age are core fields, so `σ_send` enforces the age rule too (owner
    /// answer Q5); the age rule applies to Send only.
    ///
    /// # Errors
    ///
    /// Rejects a missing or uncommitted list, a list older than the list-age rule (checked
    /// subtraction; underflow rejects), and a listed receiver.
    pub(super) fn check_send_blacklist(
        &self,
        list: Option<&KagemushaWalletBlacklistV1>,
        receiver_account_digest: &[u8; 32],
        interval: &KagemushaWalletTimeIntervalV1,
    ) -> WalletResult<Option<KagemushaWalletBlacklistGapOpeningV1>> {
        if !self.enforces_blacklist() {
            return Ok(None);
        }
        let list = self.committed_blacklist(list)?;
        let max_age_ms = self.core.blacklist_max_age_ms;
        if max_age_ms > 0 {
            let age_ms = interval
                .upper_ms
                .checked_sub(self.core.blacklist_issued_at_ms)
                .ok_or_else(|| overflow_v1("blacklist.age"))?;
            if age_ms > max_age_ms {
                return Err(invalid_v1("blacklist.age"));
            }
        }
        self.blacklist_gap(list, receiver_account_digest).map(Some)
    }

    /// Receiver-side blacklist part of the Request rule (§7; owner answers A5 and B6): the
    /// receiver's own committed list must not contain the payer's account when it issues a
    /// Request. This is the only time the receiver's list is judged; Receive checks the decision
    /// the Request recorded ([`Self::check_recorded_blacklist`]).
    ///
    /// Enforced only while [`Self::enforces_blacklist`]; no list-age rule applies. Returns the
    /// gap opening that witnesses non-membership, or `None` when no list is enforced.
    ///
    /// # Errors
    ///
    /// Rejects a missing or uncommitted list and a listed payer.
    pub(super) fn check_request_blacklist(
        &self,
        list: Option<&KagemushaWalletBlacklistV1>,
        payer_account_digest: &[u8; 32],
    ) -> WalletResult<Option<KagemushaWalletBlacklistGapOpeningV1>> {
        if !self.enforces_blacklist() {
            return Ok(None);
        }
        let list = self.committed_blacklist(list)?;
        self.blacklist_gap(list, payer_account_digest).map(Some)
    }

    /// Receive rule against the blacklist decision a Request recorded (§3.4; owner answer B6,
    /// technical decision Q9), run on the head that receives.
    ///
    /// A recorded `(0, 0)` needs no check. For a nonzero `(version, root)`, `proof` must carry
    /// the authenticated history lookup of `version` against this head's
    /// `blacklist_history_root`, finding exactly `root`, and the gap opening retained with the
    /// Request, showing `payer_account_digest` absent from `root`. The head's current list and
    /// controls neither excuse the check nor add one.
    ///
    /// # Errors
    ///
    /// Rejects an inconsistent recorded pair, a missing proof for a nonzero pair, a history
    /// lookup of another version or root or that does not open under this head's history root,
    /// and a gap opening that does not show the payer absent from the recorded root.
    pub(super) fn check_recorded_blacklist(
        &self,
        version: u64,
        root: &[u8; 32],
        payer_account_digest: &[u8; 32],
        proof: Option<&KagemushaWalletRecordedBlacklistProofV1>,
    ) -> WalletResult<()> {
        if (version == 0) != is_zero_v1(root) {
            return Err(invalid_v1("request.receiver_blacklist"));
        }
        if version == 0 {
            return Ok(());
        }
        let proof = proof.ok_or_else(|| invalid_v1("blacklist.recorded"))?;
        KagemushaWalletBlacklistHistoryLeafV1 {
            list_version: version,
            entries_root: *root,
        }
        .verify_membership(
            &self.rest.blacklist_history_root,
            &proof.history_leaf,
            &proof.history_opening,
        )?;
        proof.gap.verify(root, payer_account_digest)
    }

    /// Quota part of the Send pre-check for gross `amount + fee` (§§3.3, 7; owner answers B5,
    /// B7 and B8, technical decision Q7).
    ///
    /// `usage` is the native quota-usage array; its root must be the head's `quota_usage_root`.
    /// Without an active quota control it returns no charges and `usage` unchanged. Otherwise
    /// the held share must be the committed one with its windows authenticated against the signed
    /// root and `usage` aligned with them; `U < quota_share_expires_at_ms`; the Send time span
    /// `U − L ≤ time_anchor_max_response_ms`; every window kind the share defines is touched and
    /// at most two windows of each kind; and each touched window is charged in place at its slot,
    /// in ascending slot order, within its limit. Returns the charges with their openings and the
    /// successor array.
    ///
    /// # Errors
    ///
    /// Rejects a usage array other than the head's, a missing, uncommitted or foreign share, an
    /// invalid share or windows that do not match its signed root, an unaligned array, an expired
    /// share, a time span above the bound, an interval missing a window kind or touching more
    /// than two windows of one kind, and a charge above any touched window's limit.
    pub(super) fn check_send_quota(
        &self,
        share: Option<&KagemushaWalletQuotaShareV1>,
        usage: &KagemushaWalletQuotaUsageArrayV1,
        interval: &KagemushaWalletTimeIntervalV1,
        gross: u128,
    ) -> WalletResult<(
        Vec<KagemushaWalletQuotaChargeV1>,
        KagemushaWalletQuotaUsageArrayV1,
    )> {
        if usage.root() != self.core.quota_usage_root {
            return Err(invalid_v1("state.core.quota_usage_root"));
        }
        if !self.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
            return Ok((Vec::new(), *usage));
        }
        let share = share.ok_or_else(|| invalid_v1("quota_share.missing"))?;
        if self.rest.quota_share_id == 0 || share.quota_share_digest() != self.rest.quota_share {
            return Err(invalid_v1("state.rest.quota_share"));
        }
        share.require_wallet(
            &self.core.scheme_id,
            &self.core.asset_digest,
            &self.core.wallet_id,
        )?;
        let windows = share.authenticated_windows()?;
        if share.body.windows_root != self.core.quota_windows_root {
            return Err(invalid_v1("state.core.quota_windows_root"));
        }
        usage.validate_aligned(windows)?;
        if interval.deadline_passed(self.core.quota_share_expires_at_ms) {
            return Err(invalid_v1("quota_share.expired"));
        }
        let span = interval.upper_ms.saturating_sub(interval.lower_ms);
        if span > self.core.time_anchor_max_response_ms {
            return Err(invalid_v1("quota_share.time_span"));
        }
        let mut next_usage = *usage;
        let mut charges = Vec::new();
        for slot in touched_quota_slots_v1(windows, interval)? {
            let window = windows[usize::from(slot)];
            let usage_leaf = next_usage
                .leaf(slot)
                .ok_or_else(|| invalid_v1("quota_usage.alignment"))?;
            let usage_opening = next_usage.opening(slot)?;
            next_usage.charge(slot, gross, window.limit)?;
            charges.push(KagemushaWalletQuotaChargeV1 {
                window,
                window_opening: kagemusha_wallet_quota_window_opening_v1(windows, slot)?,
                usage: usage_leaf,
                usage_opening,
            });
        }
        Ok((charges, next_usage))
    }
}

/// Native proof of a Request's recorded receiver blacklist decision at Receive (§3.4; owner
/// answer B6, technical decision Q9): the history lookup of the recorded version in the
/// receiving head's blacklist history and the gap opening the receiver retained with the
/// Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletRecordedBlacklistProofV1 {
    /// Blacklist-history leaf of the recorded version.
    pub history_leaf: KagemushaWalletIndexedLeafV1,
    /// Opening of that leaf against the receiving head's `blacklist_history_root`.
    pub history_opening: KagemushaWalletIndexedOpeningV1,
    /// Gap opening of the payer's account in the recorded root, retained with the Request.
    pub gap: KagemushaWalletBlacklistGapOpeningV1,
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletSchemePolicyV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("scheme_policy.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletFeeScheduleV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("fee_schedule.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletBlacklistBodyV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("blacklist.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletBlacklistV1 {
    fn require_versions(&self) -> WalletResult<()> {
        self.body.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletTimeAnchorV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("time_anchor.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletQuotaShareV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("quota_share.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletChargeQuoteV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("charge_quote.version", self.body.version)
    }
}
