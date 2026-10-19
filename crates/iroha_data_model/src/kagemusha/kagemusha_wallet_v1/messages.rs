//! Peer messages of the offline exchange (§§5.1, 8; design §6).
//!
//! Request, session controls and policy data carry no monetary authority. The receiver issues
//! an open Request whose signature covers only its terms; the payer completes it with its own
//! wallet, account and next send ordinal. A Payment carries the unique signed Request fields
//! and the Send package `{statement, Ω(pred), σ_send, τ_send}`. Its exact signed Request is
//! reconstructed from that context, and the payer key and credential digest come from Ω(pred).
//! The receiver's credential, fee schedule and certificates are bound by digest in the Request
//! body, which the receiver holds; the payer's credential and certificates travel beside the
//! Payment in its carrier (`KWPYPC1`, §6). Every component is
//! bound and canonical decoding is unique, so the Payment digest binds every byte of the
//! canonical Payment. Credited is optional delivery evidence in one of two forms: the
//! receiver's Receive package, or a read-only `CreditStatus` against a folded receiver head.
//! Every message travels in one canonical envelope whose complete frame is bounded per kind,
//! and whose `kgm1:` text form is strict unpadded base64url.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1, KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1,
    KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1, KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1,
    KAGEMUSHA_WALLET_TEXT_PREFIX_V1, KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletValidationErrorV1,
    WalletResult, WalletVersionsV1, decode_frame_v1,
    digest::{
        KagemushaWalletObjectDigestDomainV1 as ObjectDomain, KagemushaWalletSignerOutputV1,
        KagemushaWalletSigningDomainV1 as Domain, WalletFieldItemsV1, WalletTranscriptV1,
        kagemusha_wallet_freeze_signature_v1, kagemusha_wallet_signed_object_digest_v1,
        kagemusha_wallet_signing_message_v1, kagemusha_wallet_verify_signature_v1,
    },
    encode_frame_v1,
    identity::{
        KagemushaWalletCertificateSetV1, KagemushaWalletCredentialV1, KagemushaWalletSchemeV1,
        KagemushaWalletSignerCertificateV1, KagemushaWalletSignerRoleV1,
    },
    invalid_v1, is_zero_v1,
    keys::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    overflow_v1,
    policy::{
        KagemushaWalletAnchoredTimeV1, KagemushaWalletBlacklistV1, KagemushaWalletFeeScheduleV1,
        KagemushaWalletMonotonicReadingV1, KagemushaWalletQuotaChargeV1,
        KagemushaWalletQuotaShareV1, KagemushaWalletSchemePolicyV1, KagemushaWalletTimeIntervalV1,
        kagemusha_wallet_local_block_v1,
    },
    poseidon::{
        KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1, KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1, KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
        KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1, KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
        KagemushaWalletIndexedLeafV1, KagemushaWalletIndexedOpeningV1,
        kagemusha_wallet_integer_cmp_v1, kagemusha_wallet_poseidon_bytes_v1, poseidon_items_v1,
    },
    require_canonical_field_v1, require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1,
    require_version_v1,
    state::{
        KagemushaWalletConsumedCreditLeafV1, KagemushaWalletCreditDigestLeafV1,
        KagemushaWalletEffectV1, KagemushaWalletFeeClaimLeafV1, KagemushaWalletLineagePublicV1,
        KagemushaWalletLineageV1, KagemushaWalletOperationKindV1, KagemushaWalletPackageDigestsV1,
        KagemushaWalletPackageV1, KagemushaWalletPendingOutgoingLeafV1,
        KagemushaWalletQuotaUsageArrayV1, KagemushaWalletReceiptSignerV1, KagemushaWalletReceiptV1,
        KagemushaWalletRecvChainEntryV1, KagemushaWalletSendChainEntryV1, KagemushaWalletStateV1,
        KagemushaWalletStatementV1,
    },
};

#[cfg(test)]
#[path = "messages_tests.rs"]
pub(super) mod messages_tests;

const DIGEST_BYTES: usize = 32;
const U16_BYTES: usize = 2;
const U32_BYTES: usize = 4;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

/// Exact Request body transcript bytes; its 19 terms elements are signed under `kgwrqst2`.
pub const KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1: usize =
    U16_BYTES + 11 * DIGEST_BYTES + 3 * U128_BYTES + 2 * U64_BYTES;
/// σ-field elements of the Request body hashed into `credit_id` (§5.1, owner answers A5 and
/// B1).
pub const KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1: usize = 24;
/// Exact `payment` transcript bytes:
/// `LE16 version || request_digest || payer_payment_key || payer_credential_digest ||
/// package_digest`.
pub const KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1: usize = U16_BYTES
    + DIGEST_BYTES
    + super::keys::KAGEMUSHA_DEVICE_PUBLIC_KEY_SEC1_BYTES_V1
    + 2 * DIGEST_BYTES;
/// Exact credit-status transcript bytes:
/// `LE16 version || statement_digest || proof_digest || receipt_digest || lineage_digest ||
/// opening_digest`.
pub const KAGEMUSHA_WALLET_CREDIT_STATUS_TRANSCRIPT_BYTES_V1: usize = U16_BYTES + 5 * DIGEST_BYTES;
/// Exact credited transcript bytes:
/// `LE16 version || u8 tag || credit_id || payment_digest || evidence_digest`.
pub const KAGEMUSHA_WALLET_CREDITED_TRANSCRIPT_BYTES_V1: usize = U16_BYTES + 1 + 3 * DIGEST_BYTES;
/// Exact credit-opening transcript bytes:
/// `credit_id || payment_digest || u8 burned || next_key || LE32 slot || siblings`, with exactly
/// 32 siblings (owner answer A2).
pub const KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1: usize =
    3 * DIGEST_BYTES + 1 + U32_BYTES + KAGEMUSHA_WALLET_INDEXED_SIBLINGS_BYTES_V1;

const SETUP_DECLINED_FIELDS_BYTES: usize = U16_BYTES;
const RECEIVE_DEFERRED_FIELDS_BYTES: usize = U16_BYTES + DIGEST_BYTES;
const CLOSE_FIELDS_BYTES: usize = 0;
/// Kind-dependent field widths of every session control kind, in tag order.
const SESSION_CONTROL_FIELDS_BYTES: [usize; 3] = [
    SETUP_DECLINED_FIELDS_BYTES,
    RECEIVE_DEFERRED_FIELDS_BYTES,
    CLOSE_FIELDS_BYTES,
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

/// Width of the kind-dependent session-control fields `LE16 reason || credit_id`: the largest
/// kind (`ReceiveDeferred`). Unused fields are zero.
pub const KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1: usize =
    max_width_v1(&SESSION_CONTROL_FIELDS_BYTES);
/// Exact `session-control-body` transcript bytes.
pub const KAGEMUSHA_WALLET_SESSION_CONTROL_BODY_TRANSCRIPT_BYTES_V1: usize =
    U16_BYTES + 5 * DIGEST_BYTES + 1 + KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1;

// ---------------------------------------------------------------------------------------
// Shared certificate helpers
// ---------------------------------------------------------------------------------------

/// Require that `certificates` holds exactly the certificates named by `required` — complete
/// and minimal — each with its role and under `scheme_id` (design §4.3).
pub(super) fn require_exact_certificates_v1(
    certificates: &KagemushaWalletCertificateSetV1,
    scheme_id: &[u8; 32],
    required: &[([u8; 32], KagemushaWalletSignerRoleV1)],
) -> WalletResult<()> {
    certificates.validate()?;
    let mut expected: Vec<[u8; 32]> = required.iter().map(|(digest, _)| *digest).collect();
    expected.sort_unstable();
    expected.dedup();
    if certificates.digests() != expected {
        return Err(invalid_v1("certificates.set"));
    }
    for (digest, role) in required {
        let certificate = certificates.certificate(digest, *role)?;
        require_scheme_v1(
            "certificate.scheme_id",
            &certificate.body.scheme_id,
            scheme_id,
        )?;
    }
    Ok(())
}

/// Verify a credential under `scheme` with its Enrollment-role issuer from `certificates`.
pub(super) fn verify_credential_with_set_v1(
    credential: &KagemushaWalletCredentialV1,
    scheme: &KagemushaWalletSchemeV1,
    certificates: &KagemushaWalletCertificateSetV1,
) -> WalletResult<()> {
    certificates.verify(scheme)?;
    let issuer = certificates.certificate(
        &credential.body.issuer_certificate,
        KagemushaWalletSignerRoleV1::Enrollment,
    )?;
    credential.verify(scheme, issuer)
}

// ---------------------------------------------------------------------------------------
// Request (§§5.1, 6.2, design §4.2 and C5)
// ---------------------------------------------------------------------------------------

/// Signed fee schedule named by a Request, or none for a zero fee.
// The schedule is a fixed-size signed value; boxing it would only add an allocation to a
// short-lived quote while the wire shape stays the same.
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed-size signed schedule stays inline in the canonical wire value"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletFeeScheduleSlotV1"
)]
pub enum KagemushaWalletFeeScheduleSlotV1 {
    /// No fee schedule; the fee is zero.
    #[codec(index = 0)]
    None,
    /// The signed fee schedule whose digest the Request body names.
    #[codec(index = 1)]
    Present {
        /// Signed immutable fee schedule.
        schedule: KagemushaWalletFeeScheduleV1,
    },
}

impl KagemushaWalletFeeScheduleSlotV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Present { .. } => 1,
        }
    }

    /// The carried schedule, if any.
    #[must_use]
    pub const fn schedule(&self) -> Option<&KagemushaWalletFeeScheduleV1> {
        match self {
            Self::None => None,
            Self::Present { schedule } => Some(schedule),
        }
    }

    /// Digest of the carried schedule, or zero.
    #[must_use]
    pub fn fee_schedule_digest(&self) -> [u8; 32] {
        self.schedule()
            .map_or([0; 32], KagemushaWalletFeeScheduleV1::fee_schedule_digest)
    }

    /// Certificate digest of the carried schedule's signer, or zero.
    #[must_use]
    pub fn signer_certificate(&self) -> [u8; 32] {
        self.schedule()
            .map_or([0; 32], |schedule| schedule.body.signer_certificate)
    }
}

/// Body of a receiver Request. The receiver payment key signs its 19 terms elements under
/// `kgwrqst2`.
///
/// Its 24 σ-field elements define `credit_id = P(kgwcrdt1, elements)` (§5.1). It carries both
/// parties' account digests (owner answer A5), which bind each party's credential account
/// through `credit_id`; the payer's destination review and each side's local blacklist block
/// read them. The receiver credential, fee schedule, scheme policy and certificate-set digests
/// are `P` values, one element each (owner answer B1).
///
/// The receiver issues it open: payer wallet, payer account and send ordinal are zero, and the
/// signature leaves them out. The payer completes them for its own wallet, account and next
/// send ordinal, so one open Request can be paid without a payer-first message. The signature
/// and the Request digest stay the same; `credit_id` over the completed fields is unique per
/// payer and ordinal (owner, 2026-10-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRequestBodyV1"
)]
#[repr(align(16))]
pub struct KagemushaWalletRequestBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Paying wallet; zero while open.
    pub payer_wallet_id: [u8; 32],
    /// Payer account digest: the `account_digest` of the paying credential; zero while open.
    pub payer_account_digest: [u8; 32],
    /// Receiving wallet; the receiver credential's wallet.
    pub receiver_wallet_id: [u8; 32],
    /// Receiver account digest: the receiver credential's `account_digest`.
    pub receiver_account_digest: [u8; 32],
    /// Payer send ordinal `s` the completed Request is scoped to; zero while open.
    pub send_ordinal: u128,
    /// Object digest `P(kgwocrd1, ·)` of the receiver credential carried beside the body.
    pub receiver_credential_digest: [u8; 32],
    /// Exact positive amount credited to the receiver.
    pub amount: u128,
    /// Fee schedule object digest `P(kgwofee1, ·)`; zero for no fee.
    pub fee_schedule: [u8; 32],
    /// Exact fee under the schedule; zero without one.
    pub fee: u128,
    /// Receiver's scheme policy epoch; zero when none is held.
    pub policy_epoch: u64,
    /// Receiver's scheme policy object digest `P(kgwopol1, ·)`; zero when none is held.
    pub scheme_policy: [u8; 32],
    /// Receiver's authenticated accepted time in Unix milliseconds.
    pub receiver_accepted_time_ms: u64,
    /// Certificate-set digest `P(kgwcset1, ·)` of the Request's certificates.
    pub certificates: [u8; 32],
    /// Fresh 256-bit nonce.
    pub nonce: [u8; 32],
}

impl KagemushaWalletRequestBodyV1 {
    /// Exact Request body transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.payer_wallet_id)
            .digest(&self.payer_account_digest)
            .digest(&self.receiver_wallet_id)
            .digest(&self.receiver_account_digest)
            .u128(self.send_ordinal)
            .digest(&self.receiver_credential_digest)
            .u128(self.amount)
            .digest(&self.fee_schedule)
            .u128(self.fee)
            .u64(self.policy_epoch)
            .digest(&self.scheme_policy)
            .u64(self.receiver_accepted_time_ms)
            .digest(&self.certificates)
            .digest(&self.nonce)
            .finish()
    }

    /// Signing message `m = P(kgwrqst2, terms)`: the 32 bytes the receiver payment key signs
    /// with ECDSA-P256-SHA256. It covers the 19 terms elements and leaves out payer wallet,
    /// payer account and send ordinal, so the open body and every completion of it share one
    /// message ([`kagemusha_wallet_signing_message_v1`]).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Request, &self.transcript())
    }

    /// This body with payer wallet, payer account and send ordinal zero: the open form the
    /// receiver issues and signs.
    #[must_use]
    pub const fn open(&self) -> Self {
        Self {
            payer_wallet_id: [0; 32],
            payer_account_digest: [0; 32],
            send_ordinal: 0,
            ..*self
        }
    }

    /// Whether payer wallet, payer account and send ordinal are all zero.
    #[must_use]
    pub fn is_open(&self) -> bool {
        *self == self.open()
    }

    /// This body completed for one payer wallet, payer account and send ordinal.
    #[must_use]
    pub const fn completed(
        &self,
        payer_wallet_id: [u8; 32],
        payer_account_digest: [u8; 32],
        send_ordinal: u128,
    ) -> Self {
        Self {
            payer_wallet_id,
            payer_account_digest,
            send_ordinal,
            ..*self
        }
    }

    /// σ-field elements of the body in transcript order (§5.1): version; scheme id (2); asset
    /// digest (2); payer wallet (2); payer account (2); receiver wallet (2); receiver account
    /// (2); send ordinal; receiver credential digest; amount; fee schedule; fee; policy epoch;
    /// scheme policy; receiver accepted time; certificate-set digest; nonce (2) — 24 elements.
    #[must_use]
    pub fn field_items(&self) -> Vec<[u8; 32]> {
        let items = WalletFieldItemsV1::with_capacity(KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1)
            .integer(u128::from(self.version))
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.payer_wallet_id)
            .digest(&self.payer_account_digest)
            .digest(&self.receiver_wallet_id)
            .digest(&self.receiver_account_digest)
            .integer(self.send_ordinal)
            .field(&self.receiver_credential_digest)
            .integer(self.amount)
            .field(&self.fee_schedule)
            .integer(self.fee)
            .integer(u128::from(self.policy_epoch))
            .field(&self.scheme_policy)
            .integer(u128::from(self.receiver_accepted_time_ms))
            .field(&self.certificates)
            .digest(&self.nonce);
        debug_assert_eq!(items.len(), KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1);
        items.finish()
    }

    /// Credit identity `P(kgwcrdt1, request body elements)`: one canonical σ-field value
    /// (§5.1, owner answer Q1).
    #[must_use]
    pub fn credit_id(&self) -> [u8; 32] {
        poseidon_items_v1(KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1, &self.field_items())
    }

    /// Validate a completed body: the terms, nonzero payer wallet and account, and a payer
    /// other than the receiver.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_terms`] rejects, a zero payer wallet or account, and a payer
    /// equal to the receiver.
    pub fn validate(&self) -> WalletResult<()> {
        self.validate_terms()?;
        require_nonzero_v1("request.payer_wallet_id", &self.payer_wallet_id)?;
        require_nonzero_v1("request.payer_account_digest", &self.payer_account_digest)?;
        if self.payer_wallet_id == self.receiver_wallet_id {
            return Err(invalid_v1("request.payer_wallet_id"));
        }
        Ok(())
    }

    /// Validate the open body a receiver issues: the terms, with payer wallet, payer account
    /// and send ordinal all zero.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_terms`] rejects and any nonzero payer field.
    pub fn validate_open(&self) -> WalletResult<()> {
        self.validate_terms()?;
        if !self.is_open() {
            return Err(invalid_v1("request.payer_wallet_id"));
        }
        Ok(())
    }

    /// Validate the receiver terms: every self-contained rule except the payer fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings (the receiver account digest included), a zero
    /// or noncanonical receiver credential or certificate-set digest, a noncanonical fee
    /// schedule or scheme policy, a zero amount, an overflowing gross debit, a policy epoch
    /// that disagrees with its scheme-policy digest, and a nonzero fee without a fee schedule.
    pub fn validate_terms(&self) -> WalletResult<()> {
        require_version_v1("request.version", self.version)?;
        for (field, digest) in [
            ("request.scheme_id", &self.scheme_id),
            ("request.asset_digest", &self.asset_digest),
            ("request.receiver_wallet_id", &self.receiver_wallet_id),
            (
                "request.receiver_account_digest",
                &self.receiver_account_digest,
            ),
            ("request.nonce", &self.nonce),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        require_nonzero_field_v1(
            "request.receiver_credential_digest",
            &self.receiver_credential_digest,
        )?;
        require_nonzero_field_v1("request.certificates", &self.certificates)?;
        for (field, value) in [
            ("request.fee_schedule", &self.fee_schedule),
            ("request.scheme_policy", &self.scheme_policy),
        ] {
            require_canonical_field_v1(field, value)?;
        }
        if self.amount == 0 {
            return Err(invalid_v1("request.amount"));
        }
        self.amount
            .checked_add(self.fee)
            .ok_or_else(|| overflow_v1("request.gross"))?;
        if (self.policy_epoch == 0) != is_zero_v1(&self.scheme_policy) {
            return Err(invalid_v1("request.scheme_policy"));
        }
        if is_zero_v1(&self.fee_schedule) && self.fee != 0 {
            return Err(invalid_v1("request.fee"));
        }
        Ok(())
    }

    /// Request rule of the receiver, run before it signs this open body (§§3.4, 7).
    ///
    /// `receiver_credential` and `receiver_state` are the receiver's own current credential and
    /// head state. The body must be open and name the receiver's own scheme, asset, wallet,
    /// account and credential. No payer is known yet: the receiver's local blacklist applies at
    /// Receive (Receive rule) and the payer's at Send, both on the completed Request.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or completed body, a receiver state that does not belong to
    /// `receiver_credential`, and a body for another scheme, asset, receiver wallet, account or
    /// credential.
    pub fn check_request_rule(
        &self,
        receiver_credential: &KagemushaWalletCredentialV1,
        receiver_state: &KagemushaWalletStateV1,
    ) -> WalletResult<()> {
        self.validate_open()?;
        receiver_state.validate_for_credential(receiver_credential)?;
        let receiver = &receiver_credential.body;
        require_scheme_v1("request.scheme_id", &self.scheme_id, &receiver.scheme_id)?;
        for (field, matches) in [
            (
                "request.asset_digest",
                self.asset_digest == receiver.asset_digest,
            ),
            (
                "request.receiver_wallet_id",
                self.receiver_wallet_id == receiver.wallet_id,
            ),
            (
                "request.receiver_account_digest",
                self.receiver_account_digest == receiver.account_digest,
            ),
            (
                "request.receiver_credential_digest",
                self.receiver_credential_digest == receiver_credential.credential_digest(),
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        Ok(())
    }
}

/// Receiver-signed nonmonetary setup quote (§5.1). On the wire it is open; a Send, Receive or
/// capsule holds its completion for one payer.
///
/// It creates no state transition, receiver ordinal or receive slot. `certificates` is exactly
/// the receiver issuer certificate and, with a fee schedule, the schedule's signer certificate.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRequestV1"
)]
pub struct KagemushaWalletRequestV1 {
    /// Signed body.
    pub body: KagemushaWalletRequestBodyV1,
    /// Receiver credential.
    pub receiver_credential: KagemushaWalletCredentialV1,
    /// Fee schedule named by the body, if any.
    pub fee_schedule: KagemushaWalletFeeScheduleSlotV1,
    /// Receiver issuer certificate and fee-schedule signer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
    /// Receiver payment-key signature over the Request terms (`kgwrqst2`).
    pub signature: KagemushaDeviceSignatureV1,
}

fn validate_request_parts_v1(
    body: &KagemushaWalletRequestBodyV1,
    credential: &KagemushaWalletCredentialV1,
    fee_schedule: &KagemushaWalletFeeScheduleSlotV1,
    certificates: &KagemushaWalletCertificateSetV1,
) -> WalletResult<()> {
    body.validate_terms()?;
    credential.validate()?;
    let receiver = &credential.body;
    require_scheme_v1("request.scheme_id", &body.scheme_id, &receiver.scheme_id)?;
    if body.asset_digest != receiver.asset_digest {
        return Err(invalid_v1("request.asset_digest"));
    }
    if body.receiver_wallet_id != receiver.wallet_id {
        return Err(invalid_v1("request.receiver_wallet_id"));
    }
    if body.receiver_account_digest != receiver.account_digest {
        return Err(invalid_v1("request.receiver_account_digest"));
    }
    if body.receiver_credential_digest != credential.credential_digest() {
        return Err(invalid_v1("request.receiver_credential_digest"));
    }
    let mut required = vec![(
        receiver.issuer_certificate,
        KagemushaWalletSignerRoleV1::Enrollment,
    )];
    match fee_schedule {
        KagemushaWalletFeeScheduleSlotV1::None => {
            if !is_zero_v1(&body.fee_schedule) {
                return Err(invalid_v1("request.fee_schedule"));
            }
        }
        KagemushaWalletFeeScheduleSlotV1::Present { schedule } => {
            schedule.validate()?;
            require_scheme_v1(
                "fee_schedule.scheme_id",
                &schedule.body.scheme_id,
                &body.scheme_id,
            )?;
            if schedule.body.asset_digest != body.asset_digest {
                return Err(invalid_v1("fee_schedule.asset_digest"));
            }
            if schedule.fee_schedule_digest() != body.fee_schedule {
                return Err(invalid_v1("request.fee_schedule"));
            }
            if schedule.fee(body.amount)? != body.fee {
                return Err(invalid_v1("request.fee"));
            }
            required.push((
                schedule.body.signer_certificate,
                KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            ));
        }
    }
    require_exact_certificates_v1(certificates, &body.scheme_id, &required)?;
    if certificates.digest()? != body.certificates {
        return Err(invalid_v1("request.certificates"));
    }
    Ok(())
}

/// Bind a payer credential to a Request body and a distinct receiver key.
fn require_request_payer_v1(
    body: &KagemushaWalletRequestBodyV1,
    receiver_payment_key: &KagemushaDevicePublicKeyV1,
    payer_credential: &KagemushaWalletCredentialV1,
) -> WalletResult<()> {
    payer_credential.validate()?;
    let payer = &payer_credential.body;
    require_scheme_v1(
        "request.payer_credential.scheme_id",
        &payer.scheme_id,
        &body.scheme_id,
    )?;
    if payer.asset_digest != body.asset_digest {
        return Err(invalid_v1("request.payer_credential.asset_digest"));
    }
    if payer.wallet_id != body.payer_wallet_id {
        return Err(invalid_v1("request.payer_wallet_id"));
    }
    if payer.account_digest != body.payer_account_digest {
        return Err(invalid_v1("request.payer_account_digest"));
    }
    if payer.payment_key == *receiver_payment_key {
        return Err(invalid_v1("request.payment_key"));
    }
    Ok(())
}

impl KagemushaWalletRequestV1 {
    /// Accept the receiver payment-key signer output over an open body.
    ///
    /// The output is already produced: this constructor enforces context before freezing the
    /// signature. The receiver platform must authenticate this context before invoking its key.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_open`] rejects before the signature, a body for another
    /// scheme than `scheme`, and a signature that does not verify under the receiver payment
    /// key.
    pub fn sign(
        scheme: &KagemushaWalletSchemeV1,
        body: KagemushaWalletRequestBodyV1,
        receiver_credential: KagemushaWalletCredentialV1,
        fee_schedule: KagemushaWalletFeeScheduleSlotV1,
        certificates: KagemushaWalletCertificateSetV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate_open()?;
        validate_request_parts_v1(&body, &receiver_credential, &fee_schedule, &certificates)?;
        require_scheme_v1("request.scheme_id", &body.scheme_id, &scheme.scheme_id())?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &receiver_credential.body.payment_key,
            Domain::Request,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self {
            body,
            receiver_credential,
            fee_schedule,
            certificates,
            signature,
        })
    }

    /// Credit identity of this Request.
    #[must_use]
    pub fn credit_id(&self) -> [u8; 32] {
        self.body.credit_id()
    }

    /// Request object digest `P(kgworeq1, [m, r_lo, r_hi, s_lo, s_hi])` (owner answer B1), one
    /// canonical σ-field value.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate a completed Request and verify its receiver signature (§5.1, design §4.2 and
    /// C5).
    ///
    /// The body's receiver account digest must be the receiver credential's.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or open body or credential, a body that does not name the receiver
    /// credential's wallet, scheme, asset or digest, a fee-schedule slot that disagrees with
    /// the body or prices another fee, a schedule for another scheme or asset, a certificate
    /// set other than exactly the receiver issuer and fee signer, a set digest that differs
    /// from the body, and a signature that does not verify under the receiver payment key.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.validate_signed_terms()
    }

    /// Validate the open Request a receiver sends and verify its receiver signature.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, with an open body in place of a completed one.
    pub fn validate_open(&self) -> WalletResult<()> {
        self.body.validate_open()?;
        self.validate_signed_terms()
    }

    fn validate_signed_terms(&self) -> WalletResult<()> {
        validate_request_parts_v1(
            &self.body,
            &self.receiver_credential,
            &self.fee_schedule,
            &self.certificates,
        )?;
        kagemusha_wallet_verify_signature_v1(
            &self.receiver_credential.body.payment_key,
            Domain::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate a completed Request and verify its credential, fee schedule and certificates
    /// under `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme, and issuer, policy or root
    /// signatures that do not verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        self.verify_originals(scheme)
    }

    /// Validate an open Request and verify its credential, fee schedule and certificates under
    /// `scheme`: the payer's check of a Request it received.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_open`] rejects, another scheme, and issuer, policy or root
    /// signatures that do not verify.
    pub fn verify_open(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate_open()?;
        self.verify_originals(scheme)
    }

    /// Complete this Request for the payer `payer_credential` at its next send ordinal, or
    /// check that it already is that completion. Signature, receiver originals and Request
    /// digest are unchanged.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Request, a payer credential for another scheme or asset, a payer whose
    /// wallet or key is the receiver's, and a completed Request for another payer or ordinal.
    pub fn complete(
        &self,
        payer_credential: &KagemushaWalletCredentialV1,
        send_ordinal: u128,
    ) -> WalletResult<Self> {
        let payer = &payer_credential.body;
        let body = self
            .body
            .completed(payer.wallet_id, payer.account_digest, send_ordinal);
        if !self.body.is_open() && self.body != body {
            return Err(invalid_v1("request.payer_wallet_id"));
        }
        let completed = Self {
            body,
            ..self.clone()
        };
        completed.validate()?;
        completed.require_payer(payer_credential)?;
        Ok(completed)
    }

    /// Complete this issued open Request with the payer fields of `signed`, the Request a
    /// Payment carries: the receiver's step at Receive. `signed` must carry exactly these terms
    /// and this signature. A Request that is already completed must equal `signed`.
    ///
    /// # Errors
    ///
    /// Rejects other terms, another signature or another completion, and a completion that is
    /// not a valid Request.
    pub fn complete_with(&self, signed: &KagemushaWalletSignedRequestV1) -> WalletResult<Self> {
        if signed.signature != self.signature
            || signed.body.open() != self.body.open()
            || (!self.body.is_open() && signed.body != self.body)
        {
            return Err(invalid_v1("request.terms"));
        }
        let completed = Self {
            body: signed.body,
            ..self.clone()
        };
        completed.validate()?;
        Ok(completed)
    }

    fn verify_originals(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        verify_credential_with_set_v1(&self.receiver_credential, scheme, &self.certificates)?;
        if let Some(schedule) = self.fee_schedule.schedule() {
            let signer = self.certificates.certificate(
                &schedule.body.signer_certificate,
                KagemushaWalletSignerRoleV1::RegulatoryPolicy,
            )?;
            schedule.verify(scheme, signer)?;
        }
        Ok(())
    }

    /// The signed Request body that a Payment carries (§5.1).
    #[must_use]
    pub const fn signed(&self) -> KagemushaWalletSignedRequestV1 {
        KagemushaWalletSignedRequestV1 {
            body: self.body,
            signature: self.signature,
        }
    }

    /// The one complete native Send pre-check of the payer (§§3.2, 3.4, 5.1, 7; owner answers
    /// B5, B7 and B8, technical decision Q8).
    ///
    /// It authenticates its inputs against the payer's head, derives one accepted interval
    /// `[L, U]` (§3.3, Time), and applies every part of
    /// the Send rule: the ordinal, spendable, epoch, fee-schedule, key and account checks against
    /// the Ω recorded for the head; the payer's local blacklist block on the receiver's account
    /// ([`kagemusha_wallet_local_block_v1`]); with the lease enabled, `U < lease_expires_at_ms`;
    /// with the quota control enabled, `U < quota_share_expires_at_ms`, the Send time span
    /// `U − L ≤ time_anchor_max_response_ms` and the in-place charges of every touched window.
    /// It returns the Send effect and `σ_send`'s control witnesses (the quota charges with their
    /// window and usage openings, and the successor quota-usage array). The partial checks are
    /// not separate entry points.
    ///
    /// # Errors
    ///
    /// Rejects what the Send rule, the local block, the lease and quota checks and the Send
    /// effect reject; a Send that fails changes no state.
    pub fn check_send(
        &self,
        inputs: &KagemushaWalletSendInputsV1<'_>,
    ) -> WalletResult<KagemushaWalletSendCheckV1> {
        let state = inputs.payer_state;
        self.check_send_rule(inputs.payer_credential, state, inputs.omega)?;
        kagemusha_wallet_local_block_v1(
            inputs.blacklist,
            "request.receiver_account_digest",
            &self.body.receiver_account_digest,
        )?;
        let interval = state.effective_accepted_time(
            inputs.anchored,
            inputs.now,
            self.body.receiver_accepted_time_ms,
        )?;
        state.check_lease(&interval)?;
        let gross = self
            .body
            .amount
            .checked_add(self.body.fee)
            .ok_or_else(|| overflow_v1("request.gross"))?;
        let (quota_charges, quota_usage) =
            state.check_send_quota(inputs.quota_share, inputs.quota_usage, &interval, gross)?;
        let effect = self.send_effect(inputs.payer_credential, &interval)?;
        Ok(KagemushaWalletSendCheckV1 {
            interval,
            effect,
            quota_charges,
            quota_usage,
        })
    }

    /// Send-rule part of [`Self::check_send`] against the folded head (§§3.2, 5.1, design §6.2).
    ///
    /// `omega` is the Ω recorded as self-verified when the payer's current head was folded
    /// (§3.1 step 5); its `head` must be the commitment of `payer_state`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Request or payer state, an Ω of another head, wallet, credential or
    /// payment key, another scheme or asset, a Request for another payer or ordinal, a payment
    /// to the payer itself or to the same key, a payer account digest other than the payer
    /// credential's (the receiver account digest is the receiver credential's by
    /// [`Self::validate`]), a payer policy epoch below the Request's, a different scheme policy
    /// at the same epoch, a different fee schedule, and a gross debit above
    /// `balance − burned_total` with Ω's lineage-adjusted `burned_total`.
    pub(super) fn check_send_rule(
        &self,
        payer_credential: &KagemushaWalletCredentialV1,
        payer_state: &KagemushaWalletStateV1,
        omega: &KagemushaWalletLineagePublicV1,
    ) -> WalletResult<()> {
        self.validate()?;
        payer_state.validate_for_credential(payer_credential)?;
        if omega.payment_key != payer_credential.body.payment_key {
            return Err(invalid_v1("lineage.payment_key"));
        }
        let spendable = payer_state.spendable_with(omega)?;
        let body = &self.body;
        let core = &payer_state.core;
        let rest = &payer_state.rest;
        require_scheme_v1("request.scheme_id", &body.scheme_id, &core.scheme_id)?;
        if body.asset_digest != core.asset_digest {
            return Err(invalid_v1("request.asset_digest"));
        }
        if body.payer_wallet_id != core.wallet_id {
            return Err(invalid_v1("request.payer_wallet_id"));
        }
        if body.receiver_wallet_id == core.wallet_id {
            return Err(invalid_v1("request.receiver_wallet_id"));
        }
        if payer_credential.body.payment_key == self.receiver_credential.body.payment_key {
            return Err(invalid_v1("request.payment_key"));
        }
        if body.payer_account_digest != payer_credential.body.account_digest {
            return Err(invalid_v1("request.payer_account_digest"));
        }
        if body.send_ordinal != core.next_send {
            return Err(invalid_v1("request.send_ordinal"));
        }
        if core.policy_epoch < body.policy_epoch {
            return Err(invalid_v1("request.policy_epoch"));
        }
        if core.policy_epoch == body.policy_epoch && rest.scheme_policy != body.scheme_policy {
            return Err(invalid_v1("request.scheme_policy"));
        }
        if body.fee_schedule != rest.fee_schedule {
            return Err(invalid_v1("request.fee_schedule"));
        }
        let gross = body
            .amount
            .checked_add(body.fee)
            .ok_or_else(|| overflow_v1("request.gross"))?;
        if spendable < gross {
            return Err(invalid_v1("state.spendable"));
        }
        Ok(())
    }

    /// Require the Request's exact payer credential account and a distinct payment key.
    fn require_payer(&self, payer_credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        require_request_payer_v1(
            &self.body,
            &self.receiver_credential.body.payment_key,
            payer_credential,
        )
    }

    /// Send effect of this Request at the effective accepted time `interval` (§7), the effect
    /// part of [`Self::check_send`].
    ///
    /// The Send binds the exact signed Request by its digest, which binds the receiver
    /// credential, fee schedule and certificates by digest (§8). The payer credential must be
    /// the payer the Request names.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Request or payer credential, a credential for another scheme, asset
    /// or payer wallet, a payer key equal to the receiver's, an inverted interval, and a lower
    /// bound below the receiver's accepted time.
    pub(super) fn send_effect(
        &self,
        payer_credential: &KagemushaWalletCredentialV1,
        interval: &KagemushaWalletTimeIntervalV1,
    ) -> WalletResult<KagemushaWalletEffectV1> {
        self.validate()?;
        payer_credential.validate()?;
        self.require_payer(payer_credential)?;
        if interval.lower_ms > interval.upper_ms
            || interval.lower_ms < self.body.receiver_accepted_time_ms
        {
            return Err(invalid_v1("effect.accepted_time"));
        }
        let effect = KagemushaWalletEffectV1::Send {
            credit_id: self.credit_id(),
            receiver_wallet_id: self.body.receiver_wallet_id,
            send_ordinal: self.body.send_ordinal,
            amount: self.body.amount,
            fee: self.body.fee,
            request: self.request_digest(),
            accepted_lower_ms: interval.lower_ms,
            accepted_upper_ms: interval.upper_ms,
        };
        effect.validate()?;
        Ok(effect)
    }
}

/// Inputs of the one native Send pre-check ([`KagemushaWalletRequestV1::check_send`]): the
/// payer's credential, head state and the Ω recorded for that head, its committed same-boot time
/// anchor and the current monotonic reading, its local blacklist, and the native stores of its
/// held quota share and quota-usage array.
#[derive(Debug, Clone, Copy)]
pub struct KagemushaWalletSendInputsV1<'a> {
    /// Payer's current credential.
    pub payer_credential: &'a KagemushaWalletCredentialV1,
    /// Payer's head state.
    pub payer_state: &'a KagemushaWalletStateV1,
    /// Public outputs of the Ω recorded for the payer's head.
    pub omega: &'a KagemushaWalletLineagePublicV1,
    /// Committed same-boot anchor, if the wallet holds one.
    pub anchored: Option<&'a KagemushaWalletAnchoredTimeV1>,
    /// Current native monotonic reading; required whenever a committed anchor is held.
    /// Absence is permitted only for the floor-only path without an anchor.
    pub now: Option<&'a KagemushaWalletMonotonicReadingV1>,
    /// Local blacklist, if one is held; never committed or proved.
    pub blacklist: Option<&'a KagemushaWalletBlacklistV1>,
    /// Held quota share, if any.
    pub quota_share: Option<&'a KagemushaWalletQuotaShareV1>,
    /// Native quota-usage array; its root must be the head's `quota_usage_root`.
    pub quota_usage: &'a KagemushaWalletQuotaUsageArrayV1,
}

/// Result of the one native Send pre-check: the accepted interval, the Send effect and
/// `σ_send`'s control witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KagemushaWalletSendCheckV1 {
    /// Accepted interval `[L, U]`; the successor floor is `L`.
    pub interval: KagemushaWalletTimeIntervalV1,
    /// Send effect of the Request at `interval`.
    pub effect: KagemushaWalletEffectV1,
    /// In-place quota charges in canonical order (Daily then Monthly, each by ascending slot),
    /// empty without the quota control.
    pub quota_charges: Vec<KagemushaWalletQuotaChargeV1>,
    /// Successor quota-usage array; its root is the successor's `quota_usage_root`.
    pub quota_usage: KagemushaWalletQuotaUsageArrayV1,
}

/// The receiver-signed Request body that a Payment carries (§5.1): the canonical signed
/// Request fields with their dependencies bound by digest, and the receiver's signature.
///
/// Its digest equals the digest of the Request message it was taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSignedRequestV1"
)]
pub struct KagemushaWalletSignedRequestV1 {
    /// Signed body.
    pub body: KagemushaWalletRequestBodyV1,
    /// Receiver payment-key signature over the Request terms (`kgwrqst2`).
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletSignedRequestV1 {
    /// Validate the body and the signature encoding.
    ///
    /// The signature is verified by [`Self::verify`] under the receiver's key, which the
    /// signed body binds only by its credential digest.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()
    }

    /// Credit identity of the Request (§5.1).
    #[must_use]
    pub fn credit_id(&self) -> [u8; 32] {
        self.body.credit_id()
    }

    /// Request object digest `P(kgworeq1, [m, r_lo, r_hi, s_lo, s_hi])` (owner answer B1), one
    /// canonical σ-field value.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Verify the receiver signature under `receiver_credential`, whose digest the body binds.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or credential, a credential other than the body's receiver
    /// credential, a receiver account digest other than the credential's, and a signature that
    /// does not verify.
    pub fn verify(&self, receiver_credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        self.validate()?;
        receiver_credential.validate()?;
        if receiver_credential.credential_digest() != self.body.receiver_credential_digest {
            return Err(invalid_v1("request.receiver_credential_digest"));
        }
        if receiver_credential.body.account_digest != self.body.receiver_account_digest {
            return Err(invalid_v1("request.receiver_account_digest"));
        }
        kagemusha_wallet_verify_signature_v1(
            &receiver_credential.body.payment_key,
            Domain::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }
}

// ---------------------------------------------------------------------------------------
// Payer companion (§6, owner 2026-10-18)
// ---------------------------------------------------------------------------------------

/// Maximum canonical payer-companion frame: a credential of at most 1,024 bytes, its one
/// issuer certificate and the framing.
pub const KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1: usize = 2_048;

/// The payer credential and its issuer certificate, carried beside a Payment.
///
/// Receive needs both, and the receiver has no earlier payer message to take them from: the
/// payer pays an open Request directly. The companion carries no authority. The credential's
/// digest and payment key must be Ω(pred)'s and its account digest the completed Request's;
/// Receive checks those and verifies the credential under the scheme with this certificate set.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPayerCompanionV1"
)]
pub struct KagemushaWalletPayerCompanionV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Payer credential of the Payment's Ω(pred).
    pub payer_credential: KagemushaWalletCredentialV1,
    /// Exactly the payer credential's issuer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
}

impl KagemushaWalletPayerCompanionV1 {
    /// Companion of `payer_credential` with its Enrollment-role issuer `issuer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn new(
        payer_credential: KagemushaWalletCredentialV1,
        issuer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<Self> {
        let companion = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            payer_credential,
            certificates: KagemushaWalletCertificateSetV1::new(vec![*issuer_certificate])?,
        };
        companion.validate()?;
        Ok(companion)
    }

    /// Validate the structure: version, a bounded valid credential and exactly its issuer
    /// certificate.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid or oversized credential, and a certificate set
    /// other than exactly the credential's issuer certificate.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("payer_companion.version", self.version)?;
        self.payer_credential.validate()?;
        self.payer_credential.to_canonical_bytes()?;
        let payer = &self.payer_credential.body;
        require_exact_certificates_v1(
            &self.certificates,
            &payer.scheme_id,
            &[(
                payer.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )],
        )
    }

    /// Check that this companion belongs to `payment`: the credential digest and payment key
    /// are Ω(pred)'s and the wallet and account are the reconstructed Request's payer. The
    /// Payment itself is verified by Receive ([`KagemushaWalletPaymentV1::prepare_receive`]).
    ///
    /// # Errors
    ///
    /// Rejects an invalid companion, a Payment without Ω(pred) or a Send effect, and every
    /// mismatch above.
    pub fn check_payment(&self, payment: &KagemushaWalletPaymentV1) -> WalletResult<()> {
        self.validate()?;
        let omega = &payment
            .send
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?
            .public;
        let request = payment.signed_request()?;
        let payer = &self.payer_credential.body;
        for (field, matches) in [
            (
                "payer_companion.credential_digest",
                self.payer_credential.credential_digest() == omega.credential_digest,
            ),
            (
                "payer_companion.payment_key",
                payer.payment_key == omega.payment_key,
            ),
            (
                "payer_companion.wallet_id",
                payer.wallet_id == request.body.payer_wallet_id,
            ),
            (
                "payer_companion.account_digest",
                payer.account_digest == request.body.payer_account_digest,
            ),
            (
                "payer_companion.scheme_id",
                payer.scheme_id == request.body.scheme_id,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        Ok(())
    }

    /// Canonical companion bytes, bounded by [`KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1`].
    ///
    /// # Errors
    ///
    /// Rejects an invalid companion and an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1)
    }

    /// Decode canonical companion bytes and validate them.
    ///
    /// # Errors
    ///
    /// Rejects an oversized or noncanonical frame, another version and an invalid companion.
    pub fn decode_canonical(bytes: &[u8]) -> WalletResult<Self> {
        let companion: Self =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1)?;
        companion.require_versions()?;
        companion.validate()?;
        Ok(companion)
    }
}

// ---------------------------------------------------------------------------------------
// Payment (§§5.1, 8, design §6.3)
// ---------------------------------------------------------------------------------------

/// Exact `payment` transcript:
/// `LE16 version || request_digest || payer_payment_key || payer_credential_digest ||
/// package_digest`.
///
/// The Payment digest is `P_bytes(kgwpay_1, transcript)` (§5.1, owner answer Q9; kept by the
/// technical decision Q4): `request_digest` and `package_digest` are `P` values in their 32-byte
/// slots. Given canonical decoding and recomputed subordinate digests, the transcript binds every
/// field of the Payment frame transitively: the Request body and signature through
/// `request_digest`, and the statement, Ω(pred), `σ_send` and `τ_send` through the package
/// digest, whose `proof_digest` covers both proofs.
#[must_use]
pub fn kagemusha_wallet_payment_transcript_v1(
    request_digest: &[u8; 32],
    payer_payment_key: &KagemushaDevicePublicKeyV1,
    payer_credential_digest: &[u8; 32],
    package_digest: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1)
        .u16(KAGEMUSHA_WALLET_VERSION_V1)
        .digest(request_digest)
        .key(payer_payment_key)
        .digest(payer_credential_digest)
        .digest(package_digest)
        .finish()
}

/// Digests of one structurally validated Payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletPaymentDigestsV1 {
    /// Credit identity of the Request.
    pub credit_id: [u8; 32],
    /// Request digest.
    pub request: [u8; 32],
    /// Payer credential digest (equal to Ω(pred)'s).
    pub payer_credential: [u8; 32],
    /// Digests of the Send package.
    pub package: KagemushaWalletPackageDigestsV1,
    /// Payment digest `P_bytes(kgwpay_1, payment transcript)`, a σ-field value.
    pub payment: [u8; 32],
}

/// Fields unique to the receiver's signed Request, in original transcript order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPaymentRequestV1"
)]
pub struct KagemushaWalletPaymentRequestV1 {
    /// Payer account completed by the payer from its own credential.
    pub payer_account_digest: [u8; 32],
    /// Receiver account bound by its credential.
    pub receiver_account_digest: [u8; 32],
    /// Receiver credential digest retained in the signed Request.
    pub receiver_credential_digest: [u8; 32],
    /// Signed fee schedule digest, zero when absent.
    pub fee_schedule: [u8; 32],
    /// Receiver policy epoch at quotation.
    pub policy_epoch: u64,
    /// Receiver policy digest, zero when absent.
    pub scheme_policy: [u8; 32],
    /// Receiver authenticated accepted time.
    pub receiver_accepted_time_ms: u64,
    /// Request certificate-set digest.
    pub certificates: [u8; 32],
    /// Original fresh Request nonce.
    pub nonce: [u8; 32],
    /// Receiver signature over the complete reconstructed Request.
    pub signature: KagemushaDeviceSignatureV1,
}

/// One canonical Payment layout; the package supplies repeated signed context.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPaymentV1"
)]
pub struct KagemushaWalletPaymentV1 {
    /// Canonical first-release wire version.
    pub version: u16,
    /// Request fields not already present in the Send package.
    pub request: KagemushaWalletPaymentRequestV1,
    /// Complete committed Send package and its predecessor lineage.
    pub send: KagemushaWalletPackageV1,
}

/// Admit both role capacities before any proof original enters a fixed-capacity circuit tape.
fn require_payment_proof_sizes_v1(omega: usize, sigma: usize) -> WalletResult<()> {
    if sigma > KAGEMUSHA_WALLET_SIGMA_PROOF_CAP_V1 {
        return Err(invalid_v1("payment.sigma_proof_bytes"));
    }
    if omega > KAGEMUSHA_WALLET_OMEGA_PROOF_CAP_V1 {
        return Err(invalid_v1("payment.omega_proof_bytes"));
    }
    if omega
        .checked_add(sigma)
        .is_none_or(|sum| sum > KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1)
    {
        return Err(invalid_v1("payment.proof_budget"));
    }
    Ok(())
}

impl KagemushaWalletPaymentV1 {
    /// Assemble only from the complete Request and the payer's authenticated credential context.
    ///
    /// Preserves the current Request/payer custody checks before compacting repeated fields.
    ///
    /// # Errors
    /// Rejects an invalid Request or payer credential, a signed field differing from the
    /// Send package, or a Send package that does not verify under this payer credential.
    pub fn assemble(
        request: &KagemushaWalletRequestV1,
        payer_credential: &KagemushaWalletCredentialV1,
        send: KagemushaWalletPackageV1,
    ) -> WalletResult<Self> {
        request.validate()?;
        payer_credential.validate()?;
        request.require_payer(payer_credential)?;
        let payment = Self::from_signed(&request.signed(), send)?;
        payment.send.verify(payer_credential)?;
        Ok(payment)
    }

    /// Internal structural compaction; public assembly retains full credential custody checks.
    fn from_signed(
        request: &KagemushaWalletSignedRequestV1,
        send: KagemushaWalletPackageV1,
    ) -> WalletResult<Self> {
        request.validate()?;
        let b = &request.body;
        let payment = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            request: KagemushaWalletPaymentRequestV1 {
                payer_account_digest: b.payer_account_digest,
                receiver_account_digest: b.receiver_account_digest,
                receiver_credential_digest: b.receiver_credential_digest,
                fee_schedule: b.fee_schedule,
                policy_epoch: b.policy_epoch,
                scheme_policy: b.scheme_policy,
                receiver_accepted_time_ms: b.receiver_accepted_time_ms,
                certificates: b.certificates,
                nonce: b.nonce,
                signature: request.signature,
            },
            send,
        };
        // Never silently replace any signed value when removing duplicate fields.
        if &payment.signed_request()? != request {
            return Err(invalid_v1("payment.request"));
        }
        payment.digests()?;
        Ok(payment)
    }

    /// Reconstruct the exact Request without authenticating it; use digests/verify before trust.
    ///
    /// # Errors
    /// Rejects absent predecessor lineage or an effect other than Send.
    pub fn signed_request(&self) -> WalletResult<KagemushaWalletSignedRequestV1> {
        let omega = &self
            .send
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?
            .public;
        let KagemushaWalletEffectV1::Send {
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            ..
        } = self.send.statement.effect
        else {
            return Err(invalid_v1("payment.effect"));
        };
        let r = self.request;
        Ok(KagemushaWalletSignedRequestV1 {
            body: KagemushaWalletRequestBodyV1 {
                version: self.version,
                scheme_id: self.send.statement.scheme_id,
                asset_digest: self.send.statement.asset_digest,
                payer_wallet_id: omega.wallet_id,
                payer_account_digest: r.payer_account_digest,
                receiver_wallet_id,
                receiver_account_digest: r.receiver_account_digest,
                send_ordinal,
                receiver_credential_digest: r.receiver_credential_digest,
                amount,
                fee_schedule: r.fee_schedule,
                fee,
                policy_epoch: r.policy_epoch,
                scheme_policy: r.scheme_policy,
                receiver_accepted_time_ms: r.receiver_accepted_time_ms,
                certificates: r.certificates,
                nonce: r.nonce,
            },
            signature: r.signature,
        })
    }

    /// Validate the exact original digest relation and receipt, deriving key/digest from Omega.
    ///
    /// # Errors
    /// Rejects another version, malformed signed context, an invalid package or receipt,
    /// differing credit or Request digests, an early accepted time, or a stale policy epoch.
    pub fn digests(&self) -> WalletResult<KagemushaWalletPaymentDigestsV1> {
        if self.version != KAGEMUSHA_WALLET_VERSION_V1 {
            return Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
                field: "payment.version",
                version: self.version,
            });
        }
        let lineage = self
            .send
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?;
        require_payment_proof_sizes_v1(lineage.proof.len(), self.send.step_proof.bytes.len())?;
        let request = self.signed_request()?;
        request.validate()?;
        let (_, package) = self.send.check_lineage_consumer()?;
        let omega = &self
            .send
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?
            .public;
        let KagemushaWalletEffectV1::Send {
            credit_id: expected_credit,
            request: expected_request,
            accepted_lower_ms,
            ..
        } = self.send.statement.effect
        else {
            return Err(invalid_v1("payment.effect"));
        };
        let credit_id = request.credit_id();
        let request_digest = request.request_digest();
        for (field, valid) in [
            ("payment.effect.credit_id", credit_id == expected_credit),
            ("payment.effect.request", request_digest == expected_request),
            (
                "payment.effect.accepted_time",
                accepted_lower_ms >= request.body.receiver_accepted_time_ms,
            ),
            (
                "payment.policy_epoch",
                omega.policy_epoch >= request.body.policy_epoch,
            ),
        ] {
            if !valid {
                return Err(invalid_v1(field));
            }
        }
        let payment = kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
            &kagemusha_wallet_payment_transcript_v1(
                &request_digest,
                &omega.payment_key,
                &omega.credential_digest,
                &package.package,
            ),
        );
        Ok(KagemushaWalletPaymentDigestsV1 {
            credit_id,
            request: request_digest,
            payer_credential: omega.credential_digest,
            package,
            payment,
        })
    }

    /// Structurally validate the Payment.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn validate(&self) -> WalletResult<()> {
        self.digests().map(|_| ())
    }

    /// Payment digest of the structurally validated Payment.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn payment_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(self.digests()?.payment)
    }

    /// Verify the Payment at Receive (§5.1) against the session's inputs: the payer
    /// credential and its issuer certificate from the Payment carrier, and the receiver's own
    /// held Request, open or completed.
    ///
    /// Beyond [`Self::digests`] it checks that the carried Request completes the held one,
    /// verifies
    /// the held Request (signature, receiver credential, fee schedule and exact fee,
    /// certificate set) and the payer credential under `scheme`, binds the payer credential to
    /// the carried digest, key and Request payer, and checks the statement's relation. `σ_send`
    /// and Ω(pred) with its decide are verified by the proof owner.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects, a carried Request other than `request`, an
    /// invalid or unverifiable Request or payer credential, a payer credential whose digest,
    /// key, scheme, asset or wallet differ from the Payment's, equal payer and receiver keys,
    /// and another relation.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        payer_credential: &KagemushaWalletCredentialV1,
        payer_certificates: &KagemushaWalletCertificateSetV1,
        request: &KagemushaWalletRequestV1,
    ) -> WalletResult<KagemushaWalletPaymentDigestsV1> {
        self.verify_completed(scheme, payer_credential, payer_certificates, request)
            .map(|(digests, _)| digests)
    }

    /// [`Self::verify`], also returning the held Request completed by this Payment.
    fn verify_completed(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        payer_credential: &KagemushaWalletCredentialV1,
        payer_certificates: &KagemushaWalletCertificateSetV1,
        request: &KagemushaWalletRequestV1,
    ) -> WalletResult<(KagemushaWalletPaymentDigestsV1, KagemushaWalletRequestV1)> {
        let digests = self.digests()?;
        let request = request
            .complete_with(&self.signed_request()?)
            .map_err(|_| invalid_v1("payment.request"))?;
        request.verify(scheme)?;
        request.require_payer(payer_credential)?;
        if payer_credential.credential_digest() != digests.payer_credential {
            return Err(invalid_v1("payment.payer_credential_digest"));
        }
        if payer_credential.body.payment_key
            != self
                .send
                .lineage
                .lineage()
                .ok_or_else(|| invalid_v1("lineage.slot"))?
                .public
                .payment_key
        {
            return Err(invalid_v1("payment.payer_payment_key"));
        }
        verify_credential_with_set_v1(payer_credential, scheme, payer_certificates)?;
        self.send.statement.validate_for_scheme(scheme)?;
        Ok((digests, request))
    }

    /// The one native Receive preparation path of the receiver (§§3.4, 5.1; technical decision
    /// Q8): the full Payment verification ([`Self::verify`]) against the carrier's payer
    /// credential and certificates and the receiver's held open `request`, the receiver's local
    /// blacklist block on the payer's account (`list`, the receiver's held list;
    /// [`kagemusha_wallet_local_block_v1`]), then the Receive effect for the receiver's current
    /// credential and head. A Payment that fails changes no state.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify`] and the Receive effect reject.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_receive(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        payer_credential: &KagemushaWalletCredentialV1,
        payer_certificates: &KagemushaWalletCertificateSetV1,
        request: &KagemushaWalletRequestV1,
        receiver_credential: &KagemushaWalletCredentialV1,
        receiver_state: &KagemushaWalletStateV1,
        list: Option<&KagemushaWalletBlacklistV1>,
    ) -> WalletResult<KagemushaWalletReceivePreparationV1> {
        let (digests, request) =
            self.verify_completed(scheme, payer_credential, payer_certificates, request)?;
        kagemusha_wallet_local_block_v1(
            list,
            "request.payer_account_digest",
            &request.body.payer_account_digest,
        )?;
        let effect = self.receive_effect(&request, receiver_credential, receiver_state)?;
        Ok(KagemushaWalletReceivePreparationV1 { digests, effect })
    }

    /// Receive-effect part of [`Self::prepare_receive`] for the receiver holding
    /// `receiver_credential`, its current credential, its head `receiver_state` and its own
    /// signed `request` (§5.1).
    ///
    /// The receiver is matched by the Request's receiver `wallet_id` and the `payment_key` of
    /// the Request's receiver credential, never by credential-digest equality, so a Request
    /// quoted before a renewal stays receivable after it (owner answer Q8). The effect carries no
    /// Payment digest (§3). Consumed-credit nonmembership is checked inside the serialized
    /// Advance section (§4.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects, an invalid receiver credential or Request, a
    /// receiver state of another credential, a carried Request that does not complete
    /// `request`, a Payment for another scheme, asset, wallet or payment key.
    pub(super) fn receive_effect(
        &self,
        request: &KagemushaWalletRequestV1,
        receiver_credential: &KagemushaWalletCredentialV1,
        receiver_state: &KagemushaWalletStateV1,
    ) -> WalletResult<KagemushaWalletEffectV1> {
        let digests = self.digests()?;
        let request = request
            .complete_with(&self.signed_request()?)
            .map_err(|_| invalid_v1("payment.request"))?;
        receiver_state.validate_for_credential(receiver_credential)?;
        let signed_request = self.signed_request()?;
        let body = &signed_request.body;
        let receiver = &receiver_credential.body;
        require_scheme_v1("payment.scheme_id", &body.scheme_id, &receiver.scheme_id)?;
        if body.asset_digest != receiver.asset_digest {
            return Err(invalid_v1("payment.asset_digest"));
        }
        if body.receiver_wallet_id != receiver.wallet_id {
            return Err(invalid_v1("payment.receiver_wallet_id"));
        }
        if receiver.payment_key != request.receiver_credential.body.payment_key {
            return Err(invalid_v1("payment.receiver_payment_key"));
        }
        Ok(KagemushaWalletEffectV1::Receive {
            credit_id: digests.credit_id,
            payer_wallet_id: body.payer_wallet_id,
            amount: body.amount,
        })
    }

    /// Pending-outgoing leaf the payer's Send inserts (§3).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn pending_outgoing_leaf(&self) -> WalletResult<KagemushaWalletPendingOutgoingLeafV1> {
        let digests = self.digests()?;
        let signed_request = self.signed_request()?;
        let body = &signed_request.body;
        Ok(KagemushaWalletPendingOutgoingLeafV1 {
            credit_id: digests.credit_id,
            receiver_wallet_id: body.receiver_wallet_id,
            send_ordinal: body.send_ordinal,
            amount: body.amount,
            fee: body.fee,
            request_digest: digests.request,
        })
    }

    /// `send_chain` descriptor the payer's Send appends (§3).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn send_chain_entry(&self) -> WalletResult<KagemushaWalletSendChainEntryV1> {
        let leaf = self.pending_outgoing_leaf()?;
        Ok(KagemushaWalletSendChainEntryV1 {
            credit_id: leaf.credit_id,
            receiver_wallet_id: leaf.receiver_wallet_id,
            send_ordinal: leaf.send_ordinal,
            amount: leaf.amount,
            fee: leaf.fee,
            request_digest: leaf.request_digest,
        })
    }

    /// Consumed-credit leaf `credit_id → (amount, receive_sequence)` the receiver's Receive at
    /// `receive_sequence` inserts permanently (§3).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects and a zero receive sequence (Bootstrap).
    pub fn consumed_credit_leaf(
        &self,
        receive_sequence: u128,
    ) -> WalletResult<KagemushaWalletConsumedCreditLeafV1> {
        let digests = self.digests()?;
        if receive_sequence == 0 {
            return Err(invalid_v1("consumed_credit.receive_sequence"));
        }
        Ok(KagemushaWalletConsumedCreditLeafV1 {
            credit_id: digests.credit_id,
            amount: self.signed_request()?.body.amount,
            receive_sequence,
        })
    }

    /// `recv_chain` descriptor the receiver's Receive appends (§3).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn recv_chain_entry(&self) -> WalletResult<KagemushaWalletRecvChainEntryV1> {
        let digests = self.digests()?;
        let signed_request = self.signed_request()?;
        let body = &signed_request.body;
        Ok(KagemushaWalletRecvChainEntryV1 {
            credit_id: digests.credit_id,
            payer_wallet_id: body.payer_wallet_id,
            amount: body.amount,
        })
    }

    /// Fee-claim leaf of a nonzero fee, or `None` for a zero fee (§6.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects.
    pub fn fee_claim_leaf(&self) -> WalletResult<Option<KagemushaWalletFeeClaimLeafV1>> {
        let digests = self.digests()?;
        let signed_request = self.signed_request()?;
        let body = &signed_request.body;
        if body.fee == 0 {
            return Ok(None);
        }
        Ok(Some(KagemushaWalletFeeClaimLeafV1 {
            credit_id: digests.credit_id,
            fee: body.fee,
            fee_schedule_digest: body.fee_schedule,
        }))
    }

    /// Validate and encode the bounded canonical frame of the released output bytes.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Payment or a frame above the message bound.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
    }

    /// Decode one canonical Payment frame for `expected_scheme_id` and structurally validate
    /// it.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and what [`Self::digests`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let payment: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
        payment.require_versions()?;
        require_scheme_v1(
            "payment.scheme_id",
            &payment.send.statement.scheme_id,
            expected_scheme_id,
        )?;
        payment.validate()?;
        Ok(payment)
    }
}

/// Result of the one native Receive preparation path
/// ([`KagemushaWalletPaymentV1::prepare_receive`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KagemushaWalletReceivePreparationV1 {
    /// Digests of the verified Payment.
    pub digests: KagemushaWalletPaymentDigestsV1,
    /// Receive effect.
    pub effect: KagemushaWalletEffectV1,
}

// ---------------------------------------------------------------------------------------
// CreditStatus and Credited (§§3.1, 5.1, design §6.5 and §6.6)
// ---------------------------------------------------------------------------------------

/// Membership opening of `credit_id → (Payment digest, burned flag)` in an Ω's credit-digest
/// root (§§3, 5.1; owner answer A2).
///
/// The credit-digest tree is the depth-32 indexed tree of [`super::poseidon`]. The opened leaf is
/// `(credit_id, P(kgwcdig1, [credit_id, payment_digest, burned]), next_key)` at `slot`, with
/// exactly 32 siblings, height 0 first, as 1,024 concatenated 32-byte canonical σ-field values.
/// The flat byte string costs 32 bytes per sibling in the canonical frame; a sequence of 32-byte
/// arrays would cost 65 in Norito, which matters inside the 10,000-byte Credited bound (§8).
/// Only a membership opening is evidence; a non-membership (low-leaf) opening is not.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCreditOpeningV1"
)]
pub struct KagemushaWalletCreditOpeningV1 {
    /// Credit identity (the tree key), a canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Digest of the full canonical Payment recorded for the credit, a canonical σ-field value.
    pub payment_digest: [u8; 32],
    /// Whether `Λ_recv` took the burn branch for the credit.
    pub burned: bool,
    /// Next larger key of the credit-digest tree, or zero for the largest.
    pub next_key: [u8; 32],
    /// Slot of the leaf; at least 1 (slot 0 is the sentinel).
    pub slot: u32,
    /// Exactly 32 siblings, height 0 first: 1,024 concatenated canonical σ-field values.
    pub siblings: Vec<u8>,
}

impl KagemushaWalletCreditOpeningV1 {
    /// Opening of `leaf` from the credit-digest tree's membership opening of its key.
    ///
    /// # Errors
    ///
    /// Rejects an indexed leaf of another key or value than `leaf`'s.
    pub fn new(
        leaf: &KagemushaWalletCreditDigestLeafV1,
        indexed: &KagemushaWalletIndexedLeafV1,
        opening: &KagemushaWalletIndexedOpeningV1,
    ) -> WalletResult<Self> {
        if indexed.key != leaf.credit_id || indexed.value != leaf.leaf_value()? {
            return Err(invalid_v1("credit_opening.leaf"));
        }
        let credit_opening = Self {
            credit_id: leaf.credit_id,
            payment_digest: leaf.payment_digest,
            burned: leaf.burned,
            next_key: indexed.next_key,
            slot: opening.slot,
            siblings: opening.sibling_bytes(),
        };
        credit_opening.validate()?;
        Ok(credit_opening)
    }

    /// Credit-digest entry this opening proves.
    #[must_use]
    pub const fn leaf(&self) -> KagemushaWalletCreditDigestLeafV1 {
        KagemushaWalletCreditDigestLeafV1 {
            credit_id: self.credit_id,
            payment_digest: self.payment_digest,
            burned: self.burned,
        }
    }

    /// The indexed-tree opening of the carried slot and siblings.
    ///
    /// # Errors
    ///
    /// Rejects siblings other than 32 canonical values.
    pub fn indexed_opening(&self) -> WalletResult<KagemushaWalletIndexedOpeningV1> {
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(self.slot, &self.siblings)
            .map_err(|_| invalid_v1("credit_opening.siblings"))
    }

    /// Validate the opening's structure.
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical credit identity or Payment digest, a `next_key` that is
    /// noncanonical or nonzero and not above `credit_id`, slot 0, and siblings other than exactly
    /// 32 canonical 32-byte values.
    pub fn validate(&self) -> WalletResult<()> {
        require_nonzero_field_v1("credit_opening.credit_id", &self.credit_id)?;
        require_nonzero_field_v1("credit_opening.payment_digest", &self.payment_digest)?;
        require_canonical_field_v1("credit_opening.next_key", &self.next_key)?;
        if !is_zero_v1(&self.next_key)
            && kagemusha_wallet_integer_cmp_v1(&self.next_key, &self.credit_id)
                != core::cmp::Ordering::Greater
        {
            return Err(invalid_v1("credit_opening.next_key"));
        }
        if self.slot == 0 {
            return Err(invalid_v1("credit_opening.slot"));
        }
        self.indexed_opening()?;
        Ok(())
    }

    /// Credit-digest root this opening recomputes from its leaf
    /// `P(kgwimlf1, [credit_id, P(kgwcdig1, [credit_id, payment_digest, burned]), next_key])`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn root(&self) -> WalletResult<[u8; 32]> {
        self.validate()?;
        let leaf = self.leaf().indexed_leaf(self.next_key)?;
        self.indexed_opening()?.leaf_root(&leaf)
    }

    /// Exact credit-opening transcript (1,125 bytes):
    /// `credit_id || payment_digest || u8 burned || next_key || LE32 slot || siblings`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid opening.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        Ok(
            WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1)
                .digest(&self.credit_id)
                .digest(&self.payment_digest)
                .u8(u8::from(self.burned))
                .digest(&self.next_key)
                .u32(self.slot)
                .bytes(&self.siblings)
                .finish(),
        )
    }

    /// Opening digest `P_bytes(kgwcopn1, transcript)`, one canonical σ-field value (owner answer
    /// A3).
    ///
    /// # Errors
    ///
    /// Rejects an invalid opening.
    pub fn opening_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
            &self.transcript()?,
        ))
    }
}

/// Delivery status of one credit at the payer (§§1.1, 5.1); not a wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletDeliveryStatusV1 {
    /// The receiver's Receive package: credited, not yet covered by a fold.
    CreditedUnfolded,
    /// A `CreditStatus` opening without the burn flag.
    Credited,
    /// A `CreditStatus` opening with the burn flag (§3.2 burn branch).
    Burned,
}

/// Read-only `CreditStatus` of a folded receiver head `h` (§§3.1, 5.1):
/// `{statement(h), proof_digest(h), τ(h), Ω(h), membership opening}`, with no σ and no
/// Ω(pred).
///
/// It advances no state and need not be retained. A proof of absence is not evidence.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCreditStatusV1"
)]
pub struct KagemushaWalletCreditStatusV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Statement of the transition that selected `h`.
    pub statement: KagemushaWalletStatementV1,
    /// `proof_digest` bound by `h`'s receipt.
    pub proof_digest: [u8; 32],
    /// Receipt τ(h).
    pub receipt: KagemushaWalletReceiptV1,
    /// Lineage proof Ω(h).
    pub lineage: KagemushaWalletLineageV1,
    /// 32-sibling membership opening in Ω(h)'s credit-digest root.
    pub opening: KagemushaWalletCreditOpeningV1,
}

impl KagemushaWalletCreditStatusV1 {
    /// Validate the status, verify τ(h) under `Ω(h).payment_key` and return its digest
    /// `P_bytes(kgwcsts1, transcript)`, one canonical σ-field value (owner answer A3).
    ///
    /// Checks: the statement's successor is `Ω(h).head`; scheme, relation, credential digest
    /// and lifecycle equal Ω's; τ(h) verifies over the carried statement and `proof_digest`
    /// with its own capsule and Payment digest (nonzero exactly when `h` is a Receive); the
    /// opening recomputes `Ω(h).credit_digest_root`. The decide of Ω(h) is the proof owner's.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid statement, receipt, lineage or opening, a zero or
    /// noncanonical proof digest, every mismatch above, a receipt that does not verify, and an
    /// opening of another root.
    // TODO(G3): decide Ω(h) natively with the frozen artifact set.
    pub fn credit_status_digest(&self) -> WalletResult<[u8; 32]> {
        require_version_v1("credit_status.version", self.version)?;
        self.statement.validate()?;
        self.lineage.validate()?;
        require_nonzero_field_v1("credit_status.proof_digest", &self.proof_digest)?;
        let omega = &self.lineage.public;
        require_scheme_v1(
            "credit_status.scheme_id",
            &self.statement.scheme_id,
            &omega.scheme_id,
        )?;
        require_scheme_v1(
            "credit_status.relation_id",
            &self.statement.relation_id,
            &omega.relation_id,
        )?;
        for (field, matches) in [
            ("credit_status.head", self.statement.successor == omega.head),
            (
                "credit_status.credential_digest",
                self.statement.credential_digest == omega.credential_digest,
            ),
            (
                "credit_status.lifecycle",
                self.statement.lifecycle == omega.lifecycle,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        let signer = KagemushaWalletReceiptSignerV1::from_lineage(omega)?;
        let receipt = self
            .receipt
            .verify(&signer, &self.statement, &self.proof_digest)?;
        if self.opening.root()? != omega.credit_digest_root {
            return Err(invalid_v1("credit_status.opening"));
        }
        let opening = self.opening.opening_digest()?;
        Ok(kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1,
            &WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CREDIT_STATUS_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .digest(&self.statement.statement_digest()?)
                .digest(&self.proof_digest)
                .digest(&receipt)
                .digest(&self.lineage.lineage_digest())
                .digest(&opening)
                .finish(),
        ))
    }

    /// Validate the status.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::credit_status_digest`] rejects.
    pub fn validate(&self) -> WalletResult<()> {
        self.credit_status_digest().map(|_| ())
    }

    /// Check the status against the payer's held Request and the digest of its retained
    /// Payment (§5.1): `Ω(h).wallet_id` and `Ω(h).payment_key` equal the Request's receiver
    /// wallet and the `payment_key` of the Request's receiver credential (credential digests are
    /// not compared, so a receiver that renewed its credential after the Request still matches,
    /// owner answer Q8), and the opening is for that credit and Payment.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::credit_status_digest`] rejects and every mismatch above.
    pub fn check_for(
        &self,
        request: &KagemushaWalletRequestV1,
        payment_digest: &[u8; 32],
    ) -> WalletResult<KagemushaWalletDeliveryStatusV1> {
        self.validate()?;
        let omega = &self.lineage.public;
        let body = &request.body;
        for (field, matches) in [
            (
                "credit_status.receiver_wallet_id",
                omega.wallet_id == body.receiver_wallet_id,
            ),
            (
                "credit_status.receiver_payment_key",
                omega.payment_key == request.receiver_credential.body.payment_key,
            ),
            (
                "credit_status.credit_id",
                self.opening.credit_id == body.credit_id(),
            ),
            (
                "credit_status.payment_digest",
                self.opening.payment_digest == *payment_digest,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        Ok(if self.opening.burned {
            KagemushaWalletDeliveryStatusV1::Burned
        } else {
            KagemushaWalletDeliveryStatusV1::Credited
        })
    }
}

/// Delivery evidence carried by Credited (§5.1).
// The variants carry bounded package-sized values; boxing would only add allocations to a
// bounded, short-lived message whose wire shape stays the same.
#[allow(
    clippy::large_enum_variant,
    reason = "the bounded evidence stays inline in the canonical wire value"
)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCreditedEvidenceV1"
)]
pub enum KagemushaWalletCreditedEvidenceV1 {
    /// The receiver's Receive package `{statement, σ_recv, τ_recv}`, whose receipt binds the
    /// exact Payment digest; status *credited, unfolded*.
    #[codec(index = 1)]
    Receive {
        /// Complete Receive package.
        package: KagemushaWalletPackageV1,
    },
    /// A read-only `CreditStatus` against a folded receiver head; status *credited* or
    /// *burned*.
    #[codec(index = 2)]
    Status {
        /// `CreditStatus` of a folded head covering the credit.
        status: KagemushaWalletCreditStatusV1,
    },
}

impl KagemushaWalletCreditedEvidenceV1 {
    /// Wire and transcript tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Receive { .. } => 1,
            Self::Status { .. } => 2,
        }
    }

    /// Statement the evidence carries: the Receive statement, or `statement(h)` of the
    /// `CreditStatus`.
    #[must_use]
    pub const fn statement(&self) -> &KagemushaWalletStatementV1 {
        match self {
            Self::Receive { package } => &package.statement,
            Self::Status { status } => &status.statement,
        }
    }
}

/// Optional delivery evidence for one credit (§5.1).
///
/// `scheme_id` is the scheme of the evidence statement; carriers locate the decode-time scheme
/// by this field. The payer verifies the evidence against its held Request and retained
/// Payment ([`Self::verify_for`]).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCreditedV1"
)]
pub struct KagemushaWalletCreditedV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme of the evidence.
    pub scheme_id: [u8; 32],
    /// Receive package or `CreditStatus` evidence.
    pub evidence: KagemushaWalletCreditedEvidenceV1,
}

impl KagemushaWalletCreditedV1 {
    /// Evidence from the receiver's Receive package.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn from_receive(package: KagemushaWalletPackageV1) -> WalletResult<Self> {
        let credited = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: package.statement.scheme_id,
            evidence: KagemushaWalletCreditedEvidenceV1::Receive { package },
        };
        credited.validate()?;
        Ok(credited)
    }

    /// Evidence from a `CreditStatus` of a folded receiver head.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects.
    pub fn from_status(status: KagemushaWalletCreditStatusV1) -> WalletResult<Self> {
        let credited = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: status.statement.scheme_id,
            evidence: KagemushaWalletCreditedEvidenceV1::Status { status },
        };
        credited.validate()?;
        Ok(credited)
    }

    /// Validate the evidence structure (design §6.6).
    ///
    /// A Receive package is checked without its receipt signature, which needs the receiver
    /// key from the payer's held Request; a `CreditStatus` is checked in full.
    ///
    /// # Errors
    ///
    /// Rejects another version, a zero scheme; for Receive, a package that is not a valid
    /// Receive without Ω or of another scheme; for Status, what
    /// [`KagemushaWalletCreditStatusV1::credit_status_digest`] rejects and another scheme.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("credited.version", self.version)?;
        require_nonzero_v1("credited.scheme_id", &self.scheme_id)?;
        let statement = match &self.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                package.validate()?;
                if package.statement.effect.kind() != KagemushaWalletOperationKindV1::Receive {
                    return Err(invalid_v1("credited.evidence"));
                }
                &package.statement
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => {
                status.validate()?;
                &status.statement
            }
        };
        require_scheme_v1("credited.scheme_id", &statement.scheme_id, &self.scheme_id)
    }

    /// Verify the evidence against the payer's `scheme`, held `request` and retained `payment`
    /// and return its `credited` digest and delivery status (design §6.6).
    ///
    /// Both forms: the evidence statement names `scheme` and its relation identity, so a
    /// mismatched scheme or relation is rejected before the `ArchiveSent` mutation (§8) just as
    /// `Λ_archive` rejects it in-circuit (§3.2). Receive form: the effect's credit, payer wallet
    /// and amount match the Payment, the receipt binds the Payment's digest, the statement's
    /// asset is the Request's, and `τ_recv` verifies under the receiver payment key of the held
    /// Request's credential. Status form: [`KagemushaWalletCreditStatusV1::check_for`]. Neither
    /// form compares the receiver's credential digest with the Request's (owner answer Q8): the
    /// Receive form's receipt verifies under the Request credential's wallet and payment key,
    /// which a renewal preserves. `σ_recv`, Ω(h) and its decide are verified by the proof
    /// owner.
    ///
    /// The Credited digest is `P_bytes(kgwcrdd1, transcript)` (owner answer A3), one canonical
    /// σ-field value, over the transcript
    /// `LE16 version || u8 tag || credit_id || payment_digest || evidence_digest`, with the
    /// package digest (Receive) or the credit-status digest (Status) as evidence digest.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence, Request or Payment, evidence under another scheme or relation,
    /// a Payment for another Request, evidence for another credit, Payment, asset or receiver,
    /// and a receipt that does not verify.
    pub fn verify_for(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        request: &KagemushaWalletRequestV1,
        payment: &KagemushaWalletPaymentV1,
    ) -> WalletResult<([u8; 32], KagemushaWalletDeliveryStatusV1)> {
        self.validate()?;
        self.evidence.statement().validate_for_scheme(scheme)?;
        let payment_digests = payment.digests()?;
        let request = &request
            .complete_with(&payment.signed_request()?)
            .map_err(|_| invalid_v1("credited.payment.request"))?;
        let body = &request.body;
        require_scheme_v1("credited.scheme_id", &self.scheme_id, &body.scheme_id)?;
        let credit_id = payment_digests.credit_id;
        let (evidence_digest, status) = match &self.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                let KagemushaWalletEffectV1::Receive {
                    credit_id: effect_credit_id,
                    payer_wallet_id,
                    amount,
                } = package.statement.effect
                else {
                    return Err(invalid_v1("credited.evidence"));
                };
                for (field, matches) in [
                    ("credited.receive.credit_id", effect_credit_id == credit_id),
                    (
                        "credited.receive.payer_wallet_id",
                        payer_wallet_id == body.payer_wallet_id,
                    ),
                    ("credited.receive.amount", amount == body.amount),
                    (
                        "credited.receive.payment_digest",
                        package.receipt.payment_digest == payment_digests.payment,
                    ),
                    (
                        "credited.receive.asset_digest",
                        package.statement.asset_digest == body.asset_digest,
                    ),
                ] {
                    if !matches {
                        return Err(invalid_v1(field));
                    }
                }
                let signer =
                    KagemushaWalletReceiptSignerV1::from_credential(&request.receiver_credential)?;
                (
                    package.verify_with(&signer)?.package,
                    KagemushaWalletDeliveryStatusV1::CreditedUnfolded,
                )
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => {
                let delivery = status.check_for(request, &payment_digests.payment)?;
                (status.credit_status_digest()?, delivery)
            }
        };
        let digest = kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
            &WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CREDITED_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .u8(self.evidence.tag())
                .digest(&credit_id)
                .digest(&payment_digests.payment)
                .digest(&evidence_digest)
                .finish(),
        );
        Ok((digest, status))
    }

    /// `ArchiveSent` effect of the payer's `scheme`, held `request`, retained `payment` and its
    /// pending leaf (§5.1): archive for credited or burned evidence.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify_for`] rejects and a pending leaf that is not the
    /// Payment's.
    pub fn archive_sent_effect(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        request: &KagemushaWalletRequestV1,
        payment: &KagemushaWalletPaymentV1,
        pending: &KagemushaWalletPendingOutgoingLeafV1,
    ) -> WalletResult<KagemushaWalletEffectV1> {
        let (credited, _) = self.verify_for(scheme, request, payment)?;
        let expected = payment.pending_outgoing_leaf()?;
        if *pending != expected {
            return Err(invalid_v1("pending_outgoing"));
        }
        Ok(KagemushaWalletEffectV1::ArchiveSent {
            credit_id: expected.credit_id,
            credited,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Session control (§§5.1, 8, design §4.5 and C8)
// ---------------------------------------------------------------------------------------

/// Kind of one nonmonetary session control.
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
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSessionControlKindV1"
)]
pub enum KagemushaWalletSessionControlKindV1 {
    /// Setup declined before Send; carries a reason code.
    #[codec(index = 1)]
    SetupDeclined,
    /// Receive postponed (for example for capacity); carries the credit and a reason code.
    #[codec(index = 3)]
    ReceiveDeferred,
    /// Session closed.
    #[codec(index = 4)]
    Close,
}

impl KagemushaWalletSessionControlKindV1 {
    /// Every kind, in tag order.
    pub const ALL: [Self; 3] = [Self::SetupDeclined, Self::ReceiveDeferred, Self::Close];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::SetupDeclined => 1,
            Self::ReceiveDeferred => 3,
            Self::Close => 4,
        }
    }

    /// Width of the kind-dependent fields this kind uses.
    #[must_use]
    pub const fn fields_bytes(self) -> usize {
        match self {
            Self::SetupDeclined => SETUP_DECLINED_FIELDS_BYTES,
            Self::ReceiveDeferred => RECEIVE_DEFERRED_FIELDS_BYTES,
            Self::Close => CLOSE_FIELDS_BYTES,
        }
    }
}

/// Authentication of a session control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSessionAuthV1"
)]
pub enum KagemushaWalletSessionAuthV1 {
    /// Unsigned: `SetupDeclined` before the sender's own Request or Payment in the session.
    #[codec(index = 0)]
    Unsigned,
    /// Signed by the sender payment key under `kgwsctl1`.
    #[codec(index = 1)]
    Signed {
        /// Payment-key signature.
        signature: KagemushaDeviceSignatureV1,
    },
}

impl KagemushaWalletSessionAuthV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Unsigned => 0,
            Self::Signed { .. } => 1,
        }
    }
}

/// Nonmonetary session control; receivers drop invalid controls (§§5.1, 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSessionControlV1"
)]
pub struct KagemushaWalletSessionControlV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Session scheme.
    pub scheme_id: [u8; 32],
    /// Session asset scope digest.
    pub asset_digest: [u8; 32],
    /// Sending wallet.
    pub sender_wallet_id: [u8; 32],
    /// Peer wallet; zero when unknown.
    pub peer_wallet_id: [u8; 32],
    /// Session nonce.
    pub session_nonce: [u8; 32],
    /// Control kind.
    pub kind: KagemushaWalletSessionControlKindV1,
    /// Reason code of `SetupDeclined` and `ReceiveDeferred`; zero otherwise.
    pub reason: u16,
    /// Deferred credit of `ReceiveDeferred`; zero otherwise.
    pub credit_id: [u8; 32],
    /// Authentication.
    pub auth: KagemushaWalletSessionAuthV1,
}

impl KagemushaWalletSessionControlV1 {
    /// Exact `session-control-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_SESSION_CONTROL_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.sender_wallet_id)
            .digest(&self.peer_wallet_id)
            .digest(&self.session_nonce)
            .u8(self.kind.tag())
            .u16(self.reason)
            .digest(&self.credit_id)
            .finish()
    }

    /// Signing message `m = P_bytes(kgwsctl1, transcript)`: the 32 bytes the sender payment key signs with
    /// ECDSA-P256-SHA256 (owner answer A1).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::SessionControl, &self.transcript())
    }

    /// Freeze the sender payment-key signature over this control.
    ///
    /// # Errors
    ///
    /// Rejects an invalid control, a control for another wallet, scheme or asset than
    /// `sender_credential`, or a signature that does not verify.
    pub fn sign(
        mut self,
        sender_credential: &KagemushaWalletCredentialV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        self.auth = KagemushaWalletSessionAuthV1::Unsigned;
        self.validate()?;
        self.require_sender(sender_credential)?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &sender_credential.body.payment_key,
            Domain::SessionControl,
            &self.signing_message(),
            signer_output,
        )?;
        self.auth = KagemushaWalletSessionAuthV1::Signed { signature };
        Ok(self)
    }

    fn require_sender(&self, credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        credential.validate()?;
        let sender = &credential.body;
        require_scheme_v1(
            "session_control.scheme_id",
            &self.scheme_id,
            &sender.scheme_id,
        )?;
        if self.asset_digest != sender.asset_digest {
            return Err(invalid_v1("session_control.asset_digest"));
        }
        if self.sender_wallet_id != sender.wallet_id {
            return Err(invalid_v1("session_control.sender_wallet_id"));
        }
        Ok(())
    }

    /// Validate the control's structure.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a peer equal to the sender, kind fields that
    /// are set when unused or missing when used, and a noncanonical `credit_id`.
    pub fn validate(&self) -> WalletResult<()> {
        use KagemushaWalletSessionControlKindV1 as Kind;
        require_version_v1("session_control.version", self.version)?;
        require_nonzero_v1("session_control.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("session_control.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("session_control.session_nonce", &self.session_nonce)?;
        require_nonzero_v1("session_control.sender_wallet_id", &self.sender_wallet_id)?;
        if !is_zero_v1(&self.peer_wallet_id) && self.peer_wallet_id == self.sender_wallet_id {
            return Err(invalid_v1("session_control.peer_wallet_id"));
        }
        let uses_reason = matches!(self.kind, Kind::SetupDeclined | Kind::ReceiveDeferred);
        if !uses_reason && self.reason != 0 {
            return Err(invalid_v1("session_control.reason"));
        }
        if (self.kind == Kind::ReceiveDeferred) == is_zero_v1(&self.credit_id) {
            return Err(invalid_v1("session_control.credit_id"));
        }
        require_canonical_field_v1("session_control.credit_id", &self.credit_id)?;
        match self.auth {
            KagemushaWalletSessionAuthV1::Unsigned => Ok(()),
            KagemushaWalletSessionAuthV1::Signed { signature } => signature.validate(),
        }
    }

    /// Verify the control against the sender credential learned in the same session (design
    /// C8).
    ///
    /// Pass the credential of the sender's Request (receiver) or Payment carrier (payer) in this
    /// session, or `None` when the sender has sent neither. Unsigned controls are accepted only
    /// for `SetupDeclined` before the sender's key is known.
    ///
    /// # Errors
    ///
    /// Rejects an invalid control, a signed control whose key is unknown, an unsigned control
    /// that must be signed, a control for another wallet, scheme or asset than the credential,
    /// and a signature that does not verify.
    pub fn verify(
        &self,
        sender_credential: Option<&KagemushaWalletCredentialV1>,
    ) -> WalletResult<()> {
        use KagemushaWalletSessionControlKindV1 as Kind;
        self.validate()?;
        match (self.auth, sender_credential) {
            (KagemushaWalletSessionAuthV1::Signed { signature }, Some(credential)) => {
                self.require_sender(credential)?;
                kagemusha_wallet_verify_signature_v1(
                    &credential.body.payment_key,
                    Domain::SessionControl,
                    &self.signing_message(),
                    &signature,
                )
            }
            (KagemushaWalletSessionAuthV1::Signed { .. }, None) => {
                Err(invalid_v1("session_control.sender_key"))
            }
            (KagemushaWalletSessionAuthV1::Unsigned, None) if self.kind == Kind::SetupDeclined => {
                Ok(())
            }
            (KagemushaWalletSessionAuthV1::Unsigned, _) => Err(invalid_v1("session_control.auth")),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Policy data (§§3.3, 7, design §4.6 and C8)
// ---------------------------------------------------------------------------------------

/// One nonmonetary scheme-scoped policy item carried between peers.
///
/// The signed blacklist is not a policy item and never travels between peers: a wallet
/// installs it locally as one standalone
/// [`KagemushaWalletBlacklistV1`](super::KagemushaWalletBlacklistV1) frame. Wire tag 4 is
/// unused.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPolicyDataItemV1"
)]
pub enum KagemushaWalletPolicyDataItemV1 {
    /// Signed scheme policy.
    #[codec(index = 1)]
    SchemePolicy {
        /// Signed scheme policy.
        policy: KagemushaWalletSchemePolicyV1,
    },
    /// Signed fee schedule.
    #[codec(index = 2)]
    FeeSchedule {
        /// Signed fee schedule.
        schedule: KagemushaWalletFeeScheduleV1,
    },
    /// Root-signed signer certificates; never empty.
    #[codec(index = 3)]
    Certificates {
        /// Certificate set.
        certificates: KagemushaWalletCertificateSetV1,
    },
}

impl KagemushaWalletPolicyDataItemV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::SchemePolicy { .. } => 1,
            Self::FeeSchedule { .. } => 2,
            Self::Certificates { .. } => 3,
        }
    }
}

/// Peer-carried policy data: one scheme-scoped item under explicit scheme and asset fields.
///
/// Scheme-scoped objects are exempt from wallet binding: they are signed by scheme
/// authorities and carry no wallet authority. Applying an item is a separate `RefreshPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPolicyDataV1"
)]
pub struct KagemushaWalletPolicyDataV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme of the item.
    pub scheme_id: [u8; 32],
    /// Session asset scope digest; asset-scoped items must equal it.
    pub asset_digest: [u8; 32],
    /// Policy item.
    pub item: KagemushaWalletPolicyDataItemV1,
}

impl KagemushaWalletPolicyDataV1 {
    /// Validate the item and its scheme and asset bindings (design C8).
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, an invalid item, an item for another scheme or
    /// asset, and an empty certificate set.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("policy_data.version", self.version)?;
        require_nonzero_v1("policy_data.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("policy_data.asset_digest", &self.asset_digest)?;
        match &self.item {
            KagemushaWalletPolicyDataItemV1::SchemePolicy { policy } => {
                policy.validate()?;
                self.require_scope(&policy.body.scheme_id, Some(&policy.body.asset_digest))
            }
            KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule } => {
                schedule.validate()?;
                self.require_scope(&schedule.body.scheme_id, Some(&schedule.body.asset_digest))
            }
            KagemushaWalletPolicyDataItemV1::Certificates { certificates } => {
                certificates.validate()?;
                if certificates.is_empty() {
                    return Err(invalid_v1("policy_data.certificates"));
                }
                for certificate in &certificates.certificates {
                    self.require_scope(&certificate.body.scheme_id, None)?;
                }
                Ok(())
            }
        }
    }

    fn require_scope(
        &self,
        scheme_id: &[u8; 32],
        asset_digest: Option<&[u8; 32]>,
    ) -> WalletResult<()> {
        require_scheme_v1("policy_data.scheme_id", scheme_id, &self.scheme_id)?;
        if asset_digest.is_some_and(|asset_digest| *asset_digest != self.asset_digest) {
            return Err(invalid_v1("policy_data.asset_digest"));
        }
        Ok(())
    }

    /// Validate the item and verify its signatures under `scheme`.
    ///
    /// Signed policy items select their signer from `known_certificates` by digest;
    /// certificate items are verified under the scheme root.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme, a missing or wrong-role signer
    /// certificate, and signatures that do not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        known_certificates: &[KagemushaWalletSignerCertificateV1],
    ) -> WalletResult<()> {
        self.validate()?;
        require_scheme_v1(
            "policy_data.scheme_id",
            &self.scheme_id,
            &scheme.scheme_id(),
        )?;
        let signer = |digest: &[u8; 32]| {
            known_certificates
                .iter()
                .find(|certificate| certificate.certificate_digest() == *digest)
                .ok_or_else(|| invalid_v1("certificates.missing"))
        };
        match &self.item {
            KagemushaWalletPolicyDataItemV1::SchemePolicy { policy } => {
                policy.verify(scheme, signer(&policy.body.signer_certificate)?)
            }
            KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule } => {
                schedule.verify(scheme, signer(&schedule.body.signer_certificate)?)
            }
            KagemushaWalletPolicyDataItemV1::Certificates { certificates } => {
                certificates.verify(scheme)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Envelope, per-kind bounds and `kgm1:` text (§8, design §4.7)
// ---------------------------------------------------------------------------------------

/// One peer message; its tag selects the per-kind frame bound.
// The Payment carries a signed Request body and a package; boxing would only add allocations
// to bounded, short-lived carrier values whose wire shape stays the same.
#[allow(
    clippy::large_enum_variant,
    reason = "bounded messages stay inline in the canonical wire value"
)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletMessageV1"
)]
pub enum KagemushaWalletMessageV1 {
    /// Receiver's open setup quote. Tag 1 (the former payer Offer) is unused.
    #[codec(index = 2)]
    Request {
        /// Request.
        request: KagemushaWalletRequestV1,
    },
    /// Complete committed Payment.
    #[codec(index = 3)]
    Payment {
        /// Payment.
        payment: KagemushaWalletPaymentV1,
    },
    /// Delivery evidence.
    #[codec(index = 4)]
    Credited {
        /// Credited evidence.
        credited: KagemushaWalletCreditedV1,
    },
    /// Nonmonetary session control.
    #[codec(index = 5)]
    SessionControl {
        /// Session control.
        control: KagemushaWalletSessionControlV1,
    },
    /// Nonmonetary policy data. Tag 7 (the former Lineage hint) is unused.
    #[codec(index = 6)]
    PolicyData {
        /// Policy data.
        data: KagemushaWalletPolicyDataV1,
    },
}

impl KagemushaWalletMessageV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Request { .. } => 2,
            Self::Payment { .. } => 3,
            Self::Credited { .. } => 4,
            Self::SessionControl { .. } => 5,
            Self::PolicyData { .. } => 6,
        }
    }

    /// Maximum complete envelope frame of this kind (§8).
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        match self {
            Self::SessionControl { .. } => KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1,
            Self::Request { .. }
            | Self::Payment { .. }
            | Self::Credited { .. }
            | Self::PolicyData { .. } => KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        }
    }

    /// Top-level version field of the message.
    #[must_use]
    pub const fn version(&self) -> u16 {
        match self {
            Self::Request { request } => request.body.version,
            Self::Payment { payment } => payment.version,
            Self::Credited { credited } => credited.version,
            Self::SessionControl { control } => control.version,
            Self::PolicyData { data } => data.version,
        }
    }

    /// Scheme field checked at decode (design §6.7): the body scheme of Request, the Send
    /// statement scheme of Payment, and the message's own scheme field otherwise.
    #[must_use]
    pub const fn scheme_id(&self) -> &[u8; 32] {
        match self {
            Self::Request { request } => &request.body.scheme_id,
            Self::Payment { payment } => &payment.send.statement.scheme_id,
            Self::Credited { credited } => &credited.scheme_id,
            Self::SessionControl { control } => &control.scheme_id,
            Self::PolicyData { data } => &data.scheme_id,
        }
    }

    /// Validate the message's self-contained rules, including every signature whose key the
    /// message carries. A Request travels open. Payment and Credited are validated
    /// structurally: their full verification needs the session's inputs (design §6.7).
    ///
    /// # Errors
    ///
    /// Rejects what the message type's own validation rejects.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Request { request } => request.validate_open(),
            Self::Payment { payment } => payment.validate(),
            Self::Credited { credited } => credited.validate(),
            Self::SessionControl { control } => control.validate(),
            Self::PolicyData { data } => data.validate(),
        }
    }
}

/// Reject a complete envelope frame above its message kind's bound.
fn require_message_bound_v1(message: &KagemushaWalletMessageV1, len: usize) -> WalletResult<()> {
    let max = message.max_bytes();
    if len > max {
        return Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { actual: len, max });
    }
    Ok(())
}

/// The single canonical Norito V1 envelope of every peer message (§8).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnvelopeV1"
)]
pub struct KagemushaWalletEnvelopeV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Carried message.
    pub message: KagemushaWalletMessageV1,
}

impl KagemushaWalletEnvelopeV1 {
    /// Wrap `message` in a V1 envelope.
    #[must_use]
    pub const fn new(message: KagemushaWalletMessageV1) -> Self {
        Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            message,
        }
    }

    /// Validate the envelope and its message.
    ///
    /// # Errors
    ///
    /// Rejects another envelope or message version and what the message rejects.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("envelope.version", self.version)?;
        require_version_v1("message.version", self.message.version())?;
        self.message.validate()
    }

    /// Validate and encode the canonical frame within its per-kind bound.
    ///
    /// # Errors
    ///
    /// Rejects an invalid envelope or a frame above its kind's bound.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, self.message.max_bytes())
    }

    /// Decode one canonical frame up to, but not including, the expected-scheme check: byte
    /// cap, canonical decode, every version field, then the per-kind bound (design §0).
    fn decode_bounded(bytes: &[u8]) -> WalletResult<Self> {
        let envelope: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
        envelope.require_versions()?;
        require_message_bound_v1(&envelope.message, bytes.len())?;
        Ok(envelope)
    }

    /// Decode one canonical envelope frame for `expected_scheme_id` (design §0 order).
    ///
    /// # Errors
    ///
    /// Rejects, in order, a frame above the largest bound, a noncanonical frame, another
    /// version in any envelope, message or nested field, a frame above its kind's bound,
    /// another scheme, and what [`Self::validate`] rejects.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let envelope = Self::decode_bounded(bytes)?;
        require_scheme_v1(
            "envelope.scheme_id",
            envelope.message.scheme_id(),
            expected_scheme_id,
        )?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Encode the `kgm1:` text form: the prefix and unpadded base64url of the canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::to_canonical_bytes`] rejects.
    pub fn to_text(&self) -> WalletResult<String> {
        Ok(kagemusha_wallet_text_encode_v1(&self.to_canonical_bytes()?))
    }

    /// Strictly decode the `kgm1:` text form and then the canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_text_decode_v1`] and [`Self::decode_canonical`]
    /// reject.
    pub fn from_text(text: &str, expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        Self::decode_canonical(&kagemusha_wallet_text_decode_v1(text)?, expected_scheme_id)
    }
}

/// `kgm1:` text of one canonical frame: the prefix and unpadded base64url.
#[must_use]
pub fn kagemusha_wallet_text_encode_v1(frame: &[u8]) -> String {
    let mut text = String::with_capacity(
        KAGEMUSHA_WALLET_TEXT_PREFIX_V1
            .len()
            .saturating_add(frame.len().saturating_mul(4) / 3)
            .saturating_add(4),
    );
    text.push_str(KAGEMUSHA_WALLET_TEXT_PREFIX_V1);
    URL_SAFE_NO_PAD.encode_string(frame, &mut text);
    text
}

/// Strictly decode `kgm1:` text into canonical frame bytes (§8, design §4.7).
///
/// The text must not exceed the largest text bound, must start with the prefix, use only the
/// base64url alphabet without padding or whitespace, have a length that is not `1 mod 4`, and
/// re-encode to itself.
///
/// # Errors
///
/// Rejects oversized text and any other form.
pub fn kagemusha_wallet_text_decode_v1(text: &str) -> WalletResult<Vec<u8>> {
    if text.len() > KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1 {
        return Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: text.len(),
            max: KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1,
        });
    }
    let body = text
        .strip_prefix(KAGEMUSHA_WALLET_TEXT_PREFIX_V1)
        .ok_or_else(|| invalid_v1("text.prefix"))?;
    if body.is_empty() {
        return Err(invalid_v1("text.body"));
    }
    if !body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_v1("text.alphabet"));
    }
    if body.len() % 4 == 1 {
        return Err(invalid_v1("text.length"));
    }
    let frame = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|_| invalid_v1("text.base64url"))?;
    if URL_SAFE_NO_PAD.encode(&frame) != body {
        return Err(invalid_v1("text.base64url"));
    }
    Ok(frame)
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletFeeScheduleSlotV1 {
    fn require_versions(&self) -> WalletResult<()> {
        self.schedule()
            .map_or(Ok(()), WalletVersionsV1::require_versions)
    }
}

impl WalletVersionsV1 for KagemushaWalletRequestV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("request.version", self.body.version)?;
        self.receiver_credential.require_versions()?;
        self.fee_schedule.require_versions()?;
        self.certificates.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletPayerCompanionV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("payer_companion.version", self.version)?;
        self.payer_credential.require_versions()?;
        self.certificates.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletPaymentV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("payment.version", self.version)?;
        self.send.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletCreditStatusV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("credit_status.version", self.version)?;
        self.statement.require_versions()?;
        self.receipt.require_versions()?;
        self.lineage.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletCreditedEvidenceV1 {
    fn require_versions(&self) -> WalletResult<()> {
        match self {
            Self::Receive { package } => package.require_versions(),
            Self::Status { status } => status.require_versions(),
        }
    }
}

impl WalletVersionsV1 for KagemushaWalletCreditedV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("credited.version", self.version)?;
        self.evidence.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletSessionControlV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("session_control.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletPolicyDataItemV1 {
    fn require_versions(&self) -> WalletResult<()> {
        match self {
            Self::SchemePolicy { policy } => policy.require_versions(),
            Self::FeeSchedule { schedule } => schedule.require_versions(),
            Self::Certificates { certificates } => certificates.require_versions(),
        }
    }
}

impl WalletVersionsV1 for KagemushaWalletPolicyDataV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("policy_data.version", self.version)?;
        self.item.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletMessageV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("message.version", self.version())?;
        match self {
            Self::Request { request } => request.require_versions(),
            Self::Payment { payment } => payment.require_versions(),
            Self::Credited { credited } => credited.require_versions(),
            Self::SessionControl { control } => control.require_versions(),
            Self::PolicyData { data } => data.require_versions(),
        }
    }
}

impl WalletVersionsV1 for KagemushaWalletEnvelopeV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("envelope.version", self.version)?;
        self.message.require_versions()
    }
}
