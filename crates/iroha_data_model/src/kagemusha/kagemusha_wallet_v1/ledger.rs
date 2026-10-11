//! Ledger boundary objects: ordinary Load receipts, unload and fee claims, and wallet-key ledger
//! controls (§§3.2, 6; design §7 with C7 and C10).
//!
//! The ledger enables loads only after verifying and recording the complete Bootstrap package
//! of an incarnation (activation), closes loads atomically from a package proving `Retiring`,
//! and permanently disables activation and loads after an unused enrollment is abandoned. Every
//! payout keyed by an unload nullifier or a credit identity is paid exactly once; that
//! uniqueness is ledger state owned by the instruction executor.
// TODO(G6): the ledger instruction family records activation, load closure, abandonment,
// nullifiers and fee payouts and enforces the C10 ordering with these objects.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1, KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1, KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_VERSION_V1, WalletResult, WalletVersionsV1,
    custody::{
        KagemushaWalletMarkerStateV1, KagemushaWalletMarkerV1, KagemushaWalletTerminalReasonV1,
    },
    decode_frame_v1,
    digest::{
        KagemushaWalletSignerOutputV1, KagemushaWalletSigningDomainV1 as Domain,
        WalletTranscriptV1, kagemusha_wallet_freeze_signature_v1,
        kagemusha_wallet_signing_message_v1, kagemusha_wallet_verify_signature_v1,
    },
    encode_frame_v1,
    identity::{
        KagemushaWalletAssetScopeV1, KagemushaWalletCertificateSetV1, KagemushaWalletCredentialV1,
        KagemushaWalletSchemeV1, KagemushaWalletSignerRoleV1, kagemusha_wallet_account_digest_v1,
        kagemusha_wallet_enrollment_id_v1, kagemusha_wallet_id_v1,
    },
    invalid_v1, is_zero_v1,
    keys::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    messages::{
        KagemushaWalletPaymentV1, KagemushaWalletRequestV1, require_exact_certificates_v1,
        verify_credential_with_set_v1,
    },
    policy::{
        KagemushaWalletChargeQuoteV1, KagemushaWalletFeeScheduleV1,
        kagemusha_wallet_unload_account_payout_v1,
    },
    require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1, require_version_v1,
    state::{KagemushaWalletEffectV1, KagemushaWalletLifecycleV1, KagemushaWalletPackageV1},
};
use crate::account::AccountId;

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod ledger_tests;

const DIGEST_BYTES: usize = 32;
const U128_BYTES: usize = 16;

const ACTIVATE_FIELDS_BYTES: usize = DIGEST_BYTES;
const CLOSE_LOADS_FIELDS_BYTES: usize = DIGEST_BYTES + U128_BYTES;
const ABANDON_FIELDS_BYTES: usize = DIGEST_BYTES + U128_BYTES + DIGEST_BYTES;
/// Fixed field widths of every ledger-control action, in tag order.
const LEDGER_CONTROL_FIELDS_BYTES: [usize; 3] = [
    ACTIVATE_FIELDS_BYTES,
    CLOSE_LOADS_FIELDS_BYTES,
    ABANDON_FIELDS_BYTES,
];

const fn max_width_v1(widths: &[usize]) -> usize {
    let mut max = 0;
    let mut index = 0;
    while index < widths.len() {
        if widths[index] > max {
            max = widths[index];
        }
        index += 1;
    }
    max
}

/// Zero-filled union width of every ledger-control action: the largest action (Abandon).
pub const KAGEMUSHA_WALLET_LEDGER_CONTROL_UNION_BYTES_V1: usize =
    max_width_v1(&LEDGER_CONTROL_FIELDS_BYTES);
/// Exact `ledger-control-body` transcript bytes.
pub const KAGEMUSHA_WALLET_LEDGER_CONTROL_BODY_TRANSCRIPT_BYTES_V1: usize =
    2 + 3 * DIGEST_BYTES + 1 + KAGEMUSHA_WALLET_LEDGER_CONTROL_UNION_BYTES_V1 + DIGEST_BYTES;

// ---------------------------------------------------------------------------------------
// Unload claim and fee claim (§§6.1, 6.2, design §7.2 and C7)
// ---------------------------------------------------------------------------------------

/// Payout of one verified unload claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(16))]
pub struct KagemushaWalletUnloadPayoutV1 {
    /// Unload nullifier; the ledger pays it exactly once.
    pub nullifier: [u8; 32],
    /// Redemption ordinal.
    pub redeem_ordinal: u128,
    /// Net offline value subtracted from the wallet.
    pub amount: u128,
    /// Online charge paid to the charge quote's beneficiary.
    pub online_charge: u128,
    /// Account payout `amount - online_charge`.
    pub account_payout: u128,
    /// Charge quote digest; zero without one.
    pub charge_quote: [u8; 32],
    /// Account digest of the charge beneficiary; zero without a charge quote.
    pub beneficiary_account_digest: [u8; 32],
    /// Digest of the complete Unload package.
    pub package: [u8; 32],
}

/// Online charge of an unload claim (§6.2, design C7): none, or the signed quote the Unload
/// effect names together with the beneficiary account its online charge is paid to.
///
/// The quote's `beneficiary_account_digest` fixes the beneficiary; the claim carries the
/// account itself because the ledger cannot pay a digest.
// The quote is a fixed-size signed value; boxing it would only add an allocation to a bounded
// ledger claim while the wire shape stays the same.
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed-size signed quote stays inline in the canonical wire value"
)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletUnloadChargeV1"
)]
pub enum KagemushaWalletUnloadChargeV1 {
    /// No charge quote; the account receives the full amount.
    #[codec(index = 0)]
    None,
    /// The charge quote named by the Unload effect.
    #[codec(index = 1)]
    Quoted {
        /// Signed Unload charge quote.
        quote: KagemushaWalletChargeQuoteV1,
        /// Account receiving the online charge; its digest is the quote's beneficiary.
        beneficiary: AccountId,
    },
}

impl KagemushaWalletUnloadChargeV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Quoted { .. } => 1,
        }
    }

    /// The carried quote, if any.
    #[must_use]
    pub const fn quote(&self) -> Option<&KagemushaWalletChargeQuoteV1> {
        match self {
            Self::None => None,
            Self::Quoted { quote, .. } => Some(quote),
        }
    }

    /// The carried beneficiary account, if any.
    #[must_use]
    pub const fn beneficiary(&self) -> Option<&AccountId> {
        match self {
            Self::None => None,
            Self::Quoted { beneficiary, .. } => Some(beneficiary),
        }
    }
}

/// Ledger-directed redemption claim carrying the complete Unload package (§6.1).
///
/// `certificates` is exactly the credential's issuer certificate and, with a charge quote, the
/// quote's RegulatoryPolicy-role signer certificate. The ledger checks
/// `H("account", account) == credential.account_digest`, pays the account
/// `amount - online_charge` once per nullifier, and pays a quoted online charge to
/// `charge.beneficiary` (design C7).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletUnloadClaimV1"
)]
pub struct KagemushaWalletUnloadClaimV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Credential the Unload ran under.
    pub credential: KagemushaWalletCredentialV1,
    /// Complete committed Unload package.
    pub package: KagemushaWalletPackageV1,
    /// Paid account; its digest is the credential's account digest.
    pub account: AccountId,
    /// Online charge: present exactly when the Unload effect names a charge quote.
    pub charge: KagemushaWalletUnloadChargeV1,
    /// Exactly the credential's issuer certificate and the charge quote's signer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
}

impl KagemushaWalletUnloadClaimV1 {
    /// Fully validate the claim and return its payout.
    ///
    /// The package is verified complete, including Ω of its predecessor and the §3.2 consumer
    /// checks against the claim's credential (§6.1); σ and Ω are verified by the proof owner.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid credential, a certificate set other than exactly its
    /// issuer certificate and quote signer certificate, an account other than the credential's,
    /// a package that is not an Unload carrying Ω(pred) or does not verify, an online charge
    /// above the amount, a charge quote present or absent against the effect, a quote for
    /// another scheme, asset, wallet, digest or terms, and a beneficiary other than the
    /// quote's.
    pub fn payout(&self) -> WalletResult<KagemushaWalletUnloadPayoutV1> {
        require_version_v1("unload_claim.version", self.version)?;
        let credential = &self.credential;
        credential.validate()?;
        let mut required = vec![(
            credential.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )];
        if let Some(quote) = self.charge.quote() {
            required.push((
                quote.body.signer_certificate,
                KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            ));
        }
        require_exact_certificates_v1(&self.certificates, &credential.body.scheme_id, &required)?;
        if kagemusha_wallet_account_digest_v1(&self.account)? != credential.body.account_digest {
            return Err(invalid_v1("unload_claim.account"));
        }
        let effect = self.package.statement.effect;
        let KagemushaWalletEffectV1::Unload {
            nullifier,
            redeem_ordinal,
            amount,
            online_charge,
            charge_quote,
        } = effect
        else {
            return Err(invalid_v1("unload_claim.effect"));
        };
        let beneficiary_account_digest = match (&self.charge, is_zero_v1(&charge_quote)) {
            (KagemushaWalletUnloadChargeV1::None, true) => [0; 32],
            (KagemushaWalletUnloadChargeV1::None, false)
            | (KagemushaWalletUnloadChargeV1::Quoted { .. }, true) => {
                return Err(invalid_v1("unload_claim.charge"));
            }
            (KagemushaWalletUnloadChargeV1::Quoted { quote, beneficiary }, false) => {
                quote.validate()?;
                require_scheme_v1(
                    "charge_quote.scheme_id",
                    &quote.body.scheme_id,
                    &credential.body.scheme_id,
                )?;
                if quote.body.asset_digest != credential.body.asset_digest {
                    return Err(invalid_v1("charge_quote.asset_digest"));
                }
                quote.require_unload_effect(&effect, &credential.body.wallet_id)?;
                let digest = kagemusha_wallet_account_digest_v1(beneficiary)?;
                if digest != quote.body.beneficiary_account_digest {
                    return Err(invalid_v1("unload_claim.beneficiary"));
                }
                digest
            }
        };
        let digests = self.package.verify(credential)?;
        Ok(KagemushaWalletUnloadPayoutV1 {
            nullifier,
            redeem_ordinal,
            amount,
            online_charge,
            account_payout: kagemusha_wallet_unload_account_payout_v1(amount, online_charge)?,
            charge_quote,
            beneficiary_account_digest,
            package: digests.package,
        })
    }

    /// Fully validate the claim.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::payout`] rejects.
    pub fn validate(&self) -> WalletResult<()> {
        self.payout().map(|_| ())
    }

    /// Validate the claim and verify the credential, the certificates, the charge quote and the
    /// relation under `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::payout`] rejects, another scheme or relation, and issuer, quote or
    /// root signatures that do not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
    ) -> WalletResult<KagemushaWalletUnloadPayoutV1> {
        let payout = self.payout()?;
        verify_credential_with_set_v1(&self.credential, scheme, &self.certificates)?;
        if let Some(quote) = self.charge.quote() {
            let signer = self.certificates.certificate(
                &quote.body.signer_certificate,
                KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            )?;
            quote.verify(scheme, signer)?;
        }
        self.package.statement.validate_for_scheme(scheme)?;
        Ok(payout)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1)
    }

    /// Decode one canonical unload claim frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::payout`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let claim: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1)?;
        claim.require_versions()?;
        require_scheme_v1(
            "unload_claim.scheme_id",
            &claim.credential.body.scheme_id,
            expected_scheme_id,
        )?;
        claim.validate()?;
        Ok(claim)
    }
}

/// Payout of one verified fee claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(16))]
pub struct KagemushaWalletFeePayoutV1 {
    /// Credit identity; the ledger pays one fee per credit.
    pub credit_id: [u8; 32],
    /// Earned fee.
    pub fee: u128,
    /// Historical fee schedule digest.
    pub fee_schedule: [u8; 32],
    /// Beneficiary account digest fixed by the schedule.
    pub beneficiary_account_digest: [u8; 32],
    /// Digest of the complete Payment.
    pub payment: [u8; 32],
}

/// Online fee claim relaying a complete committed Payment (§6.2).
///
/// Anyone may relay it; the ledger verifies Ω(pred), `σ_send`, `τ_send` and the fee terms, with
/// the schedule and credentials taken from its own records by the digests the Payment binds,
/// checks `H("account", beneficiary)` against the schedule's beneficiary and pays once per
/// `credit_id`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeClaimV1"
)]
pub struct KagemushaWalletFeeClaimV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Complete committed Payment.
    pub payment: KagemushaWalletPaymentV1,
    /// Beneficiary account fixed by the fee schedule.
    pub beneficiary: AccountId,
}

impl KagemushaWalletFeeClaimV1 {
    /// Structurally validate the claim: a valid Payment with a nonzero fee under a named fee
    /// schedule.
    ///
    /// # Errors
    ///
    /// Rejects another version, what [`KagemushaWalletPaymentV1::digests`] rejects, and a
    /// Payment without a fee schedule or with a zero fee.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("fee_claim.version", self.version)?;
        self.payment.digests()?;
        let body = &self.payment.request.body;
        if is_zero_v1(&body.fee_schedule) {
            return Err(invalid_v1("fee_claim.fee_schedule"));
        }
        if body.fee == 0 {
            return Err(invalid_v1("fee_claim.fee"));
        }
        Ok(())
    }

    /// Validate the claim against the historical `schedule` the Payment names and return its
    /// payout.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, an invalid schedule or one with another digest,
    /// scheme or asset, a fee other than the schedule's fee of the amount, and a beneficiary
    /// other than the schedule's.
    pub fn payout(
        &self,
        schedule: &KagemushaWalletFeeScheduleV1,
    ) -> WalletResult<KagemushaWalletFeePayoutV1> {
        self.validate()?;
        let digests = self.payment.digests()?;
        let body = &self.payment.request.body;
        schedule.validate()?;
        if schedule.fee_schedule_digest() != body.fee_schedule {
            return Err(invalid_v1("fee_claim.fee_schedule"));
        }
        require_scheme_v1(
            "fee_schedule.scheme_id",
            &schedule.body.scheme_id,
            &body.scheme_id,
        )?;
        if schedule.body.asset_digest != body.asset_digest {
            return Err(invalid_v1("fee_schedule.asset_digest"));
        }
        if schedule.fee(body.amount)? != body.fee {
            return Err(invalid_v1("fee_claim.fee"));
        }
        let beneficiary = kagemusha_wallet_account_digest_v1(&self.beneficiary)?;
        if beneficiary != schedule.body.beneficiary_account_digest {
            return Err(invalid_v1("fee_claim.beneficiary"));
        }
        Ok(KagemushaWalletFeePayoutV1 {
            credit_id: digests.credit_id,
            fee: body.fee,
            fee_schedule: body.fee_schedule,
            beneficiary_account_digest: beneficiary,
            payment: digests.payment,
        })
    }

    /// Validate the claim and verify its Payment under `scheme` with the ledger's records:
    /// the receiver's `request` (its credential, fee schedule and certificates by the digests
    /// the Payment binds) and the payer's credential and certificates.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::payout`] and [`KagemushaWalletPaymentV1::verify`] reject and a
    /// Request without the fee schedule.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        request: &KagemushaWalletRequestV1,
        payer_credential: &KagemushaWalletCredentialV1,
        payer_certificates: &KagemushaWalletCertificateSetV1,
    ) -> WalletResult<KagemushaWalletFeePayoutV1> {
        let schedule = request
            .fee_schedule
            .schedule()
            .ok_or_else(|| invalid_v1("fee_claim.fee_schedule"))?;
        let payout = self.payout(schedule)?;
        self.payment
            .verify(scheme, payer_credential, payer_certificates, request)?;
        Ok(payout)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid claim or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1)
    }

    /// Decode one canonical fee claim frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::payout`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let claim: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1)?;
        claim.require_versions()?;
        require_scheme_v1(
            "fee_claim.scheme_id",
            &claim.payment.request.body.scheme_id,
            expected_scheme_id,
        )?;
        claim.validate()?;
        Ok(claim)
    }
}

// ---------------------------------------------------------------------------------------
// Ledger control (§§3.2, 6.3, design §7.3 and C10)
// ---------------------------------------------------------------------------------------

/// Wallet-key ledger control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLedgerControlActionV1"
)]
#[repr(align(16))]
pub enum KagemushaWalletLedgerControlActionV1 {
    /// Record the complete Bootstrap package and enable load issuance (§3.2).
    #[codec(index = 1)]
    Activate {
        /// Digest of the complete Bootstrap package.
        package_digest: [u8; 32],
    },
    /// Permanently close loads from a package proving `Retiring` (§6.3).
    #[codec(index = 2)]
    CloseLoads {
        /// Digest of the complete Retiring (or later) package.
        package_digest: [u8; 32],
        /// `next_load` proved by that package.
        next_load: u128,
    },
    /// Abandon an unused enrollment; the signed control is the terminal receipt (§3.2).
    #[codec(index = 3)]
    Abandon {
        /// Enrollment identity of the abandoned incarnation.
        enrollment_id: [u8; 32],
        /// Generation of the durable terminal marker.
        marker_generation: u128,
        /// Digest of the durable terminal marker.
        terminal_marker_digest: [u8; 32],
    },
}

impl KagemushaWalletLedgerControlActionV1 {
    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Activate { .. } => 1,
            Self::CloseLoads { .. } => 2,
            Self::Abandon { .. } => 3,
        }
    }

    /// Fixed field width of this action before zero fill.
    const fn fields_bytes(&self) -> usize {
        match self {
            Self::Activate { .. } => ACTIVATE_FIELDS_BYTES,
            Self::CloseLoads { .. } => CLOSE_LOADS_FIELDS_BYTES,
            Self::Abandon { .. } => ABANDON_FIELDS_BYTES,
        }
    }

    /// Append the tag, the fixed fields and the zero fill of the union.
    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        let transcript = transcript.u8(self.tag());
        let transcript = match self {
            Self::Activate { package_digest } => transcript.digest(package_digest),
            Self::CloseLoads {
                package_digest,
                next_load,
            } => transcript.digest(package_digest).u128(*next_load),
            Self::Abandon {
                enrollment_id,
                marker_generation,
                terminal_marker_digest,
            } => transcript
                .digest(enrollment_id)
                .u128(*marker_generation)
                .digest(terminal_marker_digest),
        };
        transcript.zeros(
            KAGEMUSHA_WALLET_LEDGER_CONTROL_UNION_BYTES_V1.saturating_sub(self.fields_bytes()),
        )
    }

    /// Validate the action's fields.
    ///
    /// # Errors
    ///
    /// Rejects zero digests and an abandonment marker at generation zero.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Activate { package_digest } | Self::CloseLoads { package_digest, .. } => {
                require_nonzero_field_v1("ledger_control.package_digest", package_digest)
            }
            Self::Abandon {
                enrollment_id,
                marker_generation,
                terminal_marker_digest,
            } => {
                require_nonzero_v1("ledger_control.enrollment_id", enrollment_id)?;
                require_nonzero_v1(
                    "ledger_control.terminal_marker_digest",
                    terminal_marker_digest,
                )?;
                if *marker_generation == 0 {
                    return Err(invalid_v1("ledger_control.marker_generation"));
                }
                Ok(())
            }
        }
    }
}

/// Body of a ledger control, signed by the wallet payment key under `ledger-control-body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLedgerControlBodyV1"
)]
pub struct KagemushaWalletLedgerControlBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Controlled wallet.
    pub wallet_id: [u8; 32],
    /// Action.
    pub action: KagemushaWalletLedgerControlActionV1,
    /// Fresh nonce.
    pub nonce: [u8; 32],
}

impl KagemushaWalletLedgerControlBodyV1 {
    /// Exact `ledger-control-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let transcript = WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_LEDGER_CONTROL_BODY_TRANSCRIPT_BYTES_V1,
        )
        .u16(self.version)
        .digest(&self.scheme_id)
        .digest(&self.asset_digest)
        .digest(&self.wallet_id);
        self.action.write(transcript).digest(&self.nonce).finish()
    }

    /// Signing message `m = P_bytes(kgwlctl1, transcript)`: the 32 bytes the wallet payment key signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::LedgerControl, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings and an invalid action.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("ledger_control.version", self.version)?;
        require_nonzero_v1("ledger_control.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("ledger_control.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("ledger_control.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("ledger_control.nonce", &self.nonce)?;
        self.action.validate()
    }
}

/// Ledger control signed by the wallet payment key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLedgerControlV1"
)]
pub struct KagemushaWalletLedgerControlV1 {
    /// Signed body.
    pub body: KagemushaWalletLedgerControlBodyV1,
    /// Payment-key signature over `ledger-control-body`.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletLedgerControlV1 {
    /// Freeze the payment-key signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a signature that does not verify under `payment_key`.
    pub fn sign(
        body: KagemushaWalletLedgerControlBodyV1,
        payment_key: &KagemushaDevicePublicKeyV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            payment_key,
            Domain::LedgerControl,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self { body, signature })
    }

    /// Validate the control's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the control under `payment_key`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid control or a signature that does not verify.
    pub fn verify(&self, payment_key: &KagemushaDevicePublicKeyV1) -> WalletResult<()> {
        self.validate()?;
        kagemusha_wallet_verify_signature_v1(
            payment_key,
            Domain::LedgerControl,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Verify the control as `credential`'s wallet control.
    fn verify_for_credential(&self, credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        self.validate()?;
        let body = &self.body;
        let wallet = &credential.body;
        require_scheme_v1(
            "ledger_control.scheme_id",
            &body.scheme_id,
            &wallet.scheme_id,
        )?;
        if body.asset_digest != wallet.asset_digest {
            return Err(invalid_v1("ledger_control.asset_digest"));
        }
        if body.wallet_id != wallet.wallet_id {
            return Err(invalid_v1("ledger_control.wallet_id"));
        }
        self.verify(&wallet.payment_key)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid control or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1)
    }

    /// Decode one canonical ledger control frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let control: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1)?;
        control.require_versions()?;
        require_scheme_v1(
            "ledger_control.scheme_id",
            &control.body.scheme_id,
            expected_scheme_id,
        )?;
        control.validate()?;
        Ok(control)
    }
}

/// Bootstrap activation: the ledger verifies and records the complete Bootstrap package, which
/// enables load issuance for the incarnation (§3.2). Idempotent; rejected after abandonment.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletActivationV1"
)]
pub struct KagemushaWalletActivationV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Signed Activate control.
    pub control: KagemushaWalletLedgerControlV1,
    /// Credential of the incarnation.
    pub credential: KagemushaWalletCredentialV1,
    /// Complete Bootstrap package.
    pub bootstrap: KagemushaWalletPackageV1,
    /// Asset scope whose digest the credential binds.
    pub asset: KagemushaWalletAssetScopeV1,
    /// Exactly the credential's issuer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
}

impl KagemushaWalletActivationV1 {
    /// Fully validate the activation.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid credential, certificate set or asset scope, an
    /// asset other than the credential's, a control other than this wallet's Activate, a
    /// package that is not Bootstrap or does not verify, a package digest other than the
    /// control's, and a control signature that does not verify under the payment key.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("activation.version", self.version)?;
        let credential = &self.credential;
        credential.validate()?;
        require_exact_certificates_v1(
            &self.certificates,
            &credential.body.scheme_id,
            &[(
                credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )],
        )?;
        self.asset.validate()?;
        if self.asset.asset_digest() != credential.body.asset_digest {
            return Err(invalid_v1("activation.asset"));
        }
        let KagemushaWalletLedgerControlActionV1::Activate { package_digest } =
            self.control.body.action
        else {
            return Err(invalid_v1("activation.action"));
        };
        if !matches!(
            self.bootstrap.statement.effect,
            KagemushaWalletEffectV1::Bootstrap { .. }
        ) {
            return Err(invalid_v1("activation.bootstrap"));
        }
        if self.bootstrap.verify(credential)?.package != package_digest {
            return Err(invalid_v1("activation.package_digest"));
        }
        self.control.verify_for_credential(credential)
    }

    /// Validate the activation and verify the credential, certificate and relation under
    /// `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme or relation, and issuer or root
    /// signatures that do not verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        verify_credential_with_set_v1(&self.credential, scheme, &self.certificates)?;
        self.bootstrap.statement.validate_for_scheme(scheme)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid activation or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1)
    }

    /// Decode one canonical activation frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::validate`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let activation: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1)?;
        activation.require_versions()?;
        require_scheme_v1(
            "activation.scheme_id",
            &activation.credential.body.scheme_id,
            expected_scheme_id,
        )?;
        activation.validate()?;
        Ok(activation)
    }
}

/// Load closure: the complete Retiring package, or a later complete Send or Unload package,
/// proving the Retiring lifecycle and its `next_load` from a folded head with its predecessor
/// Ω (§6.3).
///
/// In one transaction the ledger checks that no successful Load at or above `next_load` exists and
/// permanently disables further loads. Repeating closure is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCloseLoadsV1"
)]
pub struct KagemushaWalletCloseLoadsV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Signed `CloseLoads` control.
    pub control: KagemushaWalletLedgerControlV1,
    /// Credential the package runs under.
    pub credential: KagemushaWalletCredentialV1,
    /// Complete Retiring or later package.
    pub package: KagemushaWalletPackageV1,
    /// Exactly the credential's issuer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
}

impl KagemushaWalletCloseLoadsV1 {
    /// Fully validate the closure.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid credential or certificate set, a control other than
    /// this wallet's `CloseLoads`, a package that is not a Retiring, Send or Unload carrying
    /// Ω(pred), whose lifecycle is not Retiring or whose `next_load` differs from the
    /// control's, a package that does not verify (including the §3.2 consumer checks) or whose
    /// digest differs from the control's, and a control signature that does not verify.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("close_loads.version", self.version)?;
        let credential = &self.credential;
        credential.validate()?;
        require_exact_certificates_v1(
            &self.certificates,
            &credential.body.scheme_id,
            &[(
                credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )],
        )?;
        let KagemushaWalletLedgerControlActionV1::CloseLoads {
            package_digest,
            next_load,
        } = self.control.body.action
        else {
            return Err(invalid_v1("close_loads.action"));
        };
        let statement = &self.package.statement;
        // Only a Retiring, Send or Unload package proves the lifecycle from a folded head with
        // its predecessor Ω (§6.3 step 2).
        if !statement.effect.kind().consumes_lineage() {
            return Err(invalid_v1("close_loads.effect"));
        }
        if statement.lifecycle != KagemushaWalletLifecycleV1::Retiring {
            return Err(invalid_v1("close_loads.lifecycle"));
        }
        if statement.next_load != next_load {
            return Err(invalid_v1("close_loads.next_load"));
        }
        if self.package.verify(credential)?.package != package_digest {
            return Err(invalid_v1("close_loads.package_digest"));
        }
        self.control.verify_for_credential(credential)
    }

    /// Validate the closure and verify the credential, certificate and relation under
    /// `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme or relation, and issuer or root
    /// signatures that do not verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        verify_credential_with_set_v1(&self.credential, scheme, &self.certificates)?;
        self.package.statement.validate_for_scheme(scheme)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid closure or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1)
    }

    /// Decode one canonical closure frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::validate`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let close: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1)?;
        close.require_versions()?;
        require_scheme_v1(
            "close_loads.scheme_id",
            &close.credential.body.scheme_id,
            expected_scheme_id,
        )?;
        close.validate()?;
        Ok(close)
    }
}

/// Abandonment of an unused enrollment (§3.2, design C10).
///
/// The signed Abandon control is the terminal receipt; it is signed only after the terminal
/// marker is durable. The ledger recomputes `enrollment_id` and `wallet_id` from `payment_key`
/// and `challenge_digest`, rejects abandonment after activation, and afterwards rejects
/// activation and every load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAbandonmentV1"
)]
pub struct KagemushaWalletAbandonmentV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Signed Abandon control.
    pub control: KagemushaWalletLedgerControlV1,
    /// Payment key of the abandoned incarnation.
    pub payment_key: KagemushaDevicePublicKeyV1,
    /// Enrollment challenge digest of the incarnation.
    pub challenge_digest: [u8; 32],
}

impl KagemushaWalletAbandonmentV1 {
    /// Abandon control body naming the durable terminal marker `terminal`; the payment key
    /// signs its [`signing_message`](KagemushaWalletLedgerControlBodyV1::signing_message).
    ///
    /// # Errors
    ///
    /// Rejects an invalid marker and an invalid body.
    pub fn control_body(
        terminal: &KagemushaWalletMarkerV1,
        challenge_digest: &[u8; 32],
        nonce: [u8; 32],
    ) -> WalletResult<KagemushaWalletLedgerControlBodyV1> {
        let body = KagemushaWalletLedgerControlBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: terminal.scheme_id,
            asset_digest: terminal.asset_digest,
            wallet_id: terminal.wallet_id,
            action: KagemushaWalletLedgerControlActionV1::Abandon {
                enrollment_id: kagemusha_wallet_enrollment_id_v1(
                    challenge_digest,
                    &terminal.payment_key,
                ),
                marker_generation: terminal.generation,
                terminal_marker_digest: terminal.marker_digest()?,
            },
            nonce,
        };
        body.validate()?;
        Ok(body)
    }

    /// Sign the abandonment of the incarnation whose durable terminal marker is `terminal`.
    ///
    /// # Errors
    ///
    /// Rejects a marker that is not an abandonment terminal marker of `challenge_digest`'s
    /// enrollment, and what [`Self::validate`] rejects.
    pub fn sign(
        terminal: &KagemushaWalletMarkerV1,
        challenge_digest: [u8; 32],
        nonce: [u8; 32],
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        let body = Self::control_body(terminal, &challenge_digest, nonce)?;
        let abandonment = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            control: KagemushaWalletLedgerControlV1::sign(
                body,
                &terminal.payment_key,
                signer_output,
            )?,
            payment_key: terminal.payment_key,
            challenge_digest,
        };
        abandonment.require_terminal_marker(terminal)?;
        Ok(abandonment)
    }

    /// Validate the abandonment and verify its control signature.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid key, a zero challenge, a control other than
    /// Abandon, an enrollment or wallet identity that does not recompute, and a signature that
    /// does not verify under the payment key.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("abandonment.version", self.version)?;
        self.payment_key.validate()?;
        require_nonzero_v1("abandonment.challenge_digest", &self.challenge_digest)?;
        self.control.validate()?;
        let body = &self.control.body;
        let KagemushaWalletLedgerControlActionV1::Abandon { enrollment_id, .. } = body.action
        else {
            return Err(invalid_v1("abandonment.action"));
        };
        if enrollment_id
            != kagemusha_wallet_enrollment_id_v1(&self.challenge_digest, &self.payment_key)
        {
            return Err(invalid_v1("abandonment.enrollment_id"));
        }
        let wallet_id = kagemusha_wallet_id_v1(
            &body.scheme_id,
            &body.asset_digest,
            &self.payment_key,
            &enrollment_id,
        );
        if body.wallet_id != wallet_id {
            return Err(invalid_v1("abandonment.wallet_id"));
        }
        self.control.verify(&self.payment_key)
    }

    /// Require that `marker` is the durable abandonment terminal marker this control names.
    ///
    /// # Errors
    ///
    /// Rejects an invalid abandonment or marker, a marker for another incarnation, a marker that
    /// is not an abandonment terminal, and another generation or digest.
    pub fn require_terminal_marker(&self, marker: &KagemushaWalletMarkerV1) -> WalletResult<()> {
        self.validate()?;
        marker.validate()?;
        let body = &self.control.body;
        require_scheme_v1("marker.scheme_id", &marker.scheme_id, &body.scheme_id)?;
        if marker.asset_digest != body.asset_digest
            || marker.wallet_id != body.wallet_id
            || marker.payment_key != self.payment_key
        {
            return Err(invalid_v1("marker.identity"));
        }
        if !matches!(
            marker.state,
            KagemushaWalletMarkerStateV1::Terminal {
                reason: KagemushaWalletTerminalReasonV1::Abandoned,
                ..
            }
        ) {
            return Err(invalid_v1("marker.state"));
        }
        let KagemushaWalletLedgerControlActionV1::Abandon {
            marker_generation,
            terminal_marker_digest,
            ..
        } = body.action
        else {
            return Err(invalid_v1("abandonment.action"));
        };
        if marker.generation != marker_generation {
            return Err(invalid_v1("abandonment.marker_generation"));
        }
        if marker.marker_digest()? != terminal_marker_digest {
            return Err(invalid_v1("abandonment.terminal_marker_digest"));
        }
        Ok(())
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid abandonment or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1)
    }

    /// Decode one canonical abandonment frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::validate`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let abandonment: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1)?;
        abandonment.require_versions()?;
        require_scheme_v1(
            "abandonment.scheme_id",
            &abandonment.control.body.scheme_id,
            expected_scheme_id,
        )?;
        abandonment.validate()?;
        Ok(abandonment)
    }
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletUnloadChargeV1 {
    fn require_versions(&self) -> WalletResult<()> {
        self.quote()
            .map_or(Ok(()), WalletVersionsV1::require_versions)
    }
}

impl WalletVersionsV1 for KagemushaWalletUnloadClaimV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("unload_claim.version", self.version)?;
        self.credential.require_versions()?;
        self.package.require_versions()?;
        self.charge.require_versions()?;
        self.certificates.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletFeeClaimV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("fee_claim.version", self.version)?;
        self.payment.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletLedgerControlV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("ledger_control.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletActivationV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("activation.version", self.version)?;
        self.control.require_versions()?;
        self.credential.require_versions()?;
        self.bootstrap.require_versions()?;
        self.asset.require_versions()?;
        self.certificates.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletCloseLoadsV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("close_loads.version", self.version)?;
        self.control.require_versions()?;
        self.credential.require_versions()?;
        self.package.require_versions()?;
        self.certificates.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletAbandonmentV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("abandonment.version", self.version)?;
        self.control.require_versions()
    }
}
