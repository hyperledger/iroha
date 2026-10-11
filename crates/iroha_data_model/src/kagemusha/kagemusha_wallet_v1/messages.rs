//! Peer messages of the offline exchange (§§5.1, 8; design §6).
//!
//! Offer, Lineage, Request, session controls and policy data carry no monetary authority. A
//! Payment uses the compact layout of §5.1: the signed Request body, the payer's
//! `payment_key` and credential digest (both equal to Ω(pred)'s), and the Send package
//! `{statement, Ω(pred), σ_send, τ_send}`. The receiver's credential, fee schedule and
//! certificates are bound by digest in the Request body, which the receiver holds; the
//! payer's credential and certificates travel in the session's Offer (§8). Every component is
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
    KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1, KAGEMUSHA_WALLET_TEXT_PREFIX_V1,
    KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletValidationErrorV1, WalletResult, WalletVersionsV1,
    decode_frame_v1,
    digest::{
        KagemushaWalletDigestRoleV1 as Role, KagemushaWalletSignerOutputV1,
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
        KagemushaWalletFeeScheduleV1, KagemushaWalletSchemePolicyV1, KagemushaWalletTimeIntervalV1,
    },
    poseidon::{
        KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1, KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1,
        KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1, KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1,
        KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, KagemushaWalletIndexedLeafV1,
        KagemushaWalletIndexedOpeningV1, kagemusha_wallet_poseidon_bytes_v1, poseidon_items_v1,
    },
    require_canonical_field_v1, require_nonzero_field_v1, require_nonzero_v1, require_scheme_v1,
    require_version_v1,
    state::{
        KagemushaWalletConsumedCreditLeafV1, KagemushaWalletCreditDigestLeafV1,
        KagemushaWalletEffectV1, KagemushaWalletFeeClaimLeafV1, KagemushaWalletLineagePublicV1,
        KagemushaWalletLineageV1, KagemushaWalletOperationKindV1, KagemushaWalletPackageDigestsV1,
        KagemushaWalletPackageV1, KagemushaWalletPendingOutgoingLeafV1,
        KagemushaWalletReceiptSignerV1, KagemushaWalletReceiptV1, KagemushaWalletRecvChainEntryV1,
        KagemushaWalletSendChainEntryV1, KagemushaWalletStateV1, KagemushaWalletStatementV1,
    },
};

#[cfg(test)]
#[path = "messages_tests.rs"]
pub(super) mod messages_tests;

const DIGEST_BYTES: usize = 32;
const U16_BYTES: usize = 2;
const U64_BYTES: usize = 8;
const U128_BYTES: usize = 16;

/// Exact `offer-body` transcript bytes.
pub const KAGEMUSHA_WALLET_OFFER_BODY_TRANSCRIPT_BYTES_V1: usize =
    U16_BYTES + 5 * DIGEST_BYTES + 2 * U128_BYTES;
/// Exact `request-body` transcript bytes.
pub const KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1: usize =
    U16_BYTES + 11 * DIGEST_BYTES + 3 * U128_BYTES + 2 * U64_BYTES;
/// σ-field elements of the Request body hashed into `credit_id` (§5.1).
pub const KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1: usize = 28;
/// Exact `payment` transcript bytes:
/// `LE16 version || request_digest || payer_payment_key || payer_credential_digest ||
/// package_digest`.
pub const KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1: usize = U16_BYTES
    + DIGEST_BYTES
    + super::keys::KAGEMUSHA_DEVICE_PUBLIC_KEY_SEC1_BYTES_V1
    + 2 * DIGEST_BYTES;
/// Exact `credit-status` transcript bytes:
/// `LE16 version || statement_digest || proof_digest || receipt_digest || lineage_digest ||
/// opening_digest`.
pub const KAGEMUSHA_WALLET_CREDIT_STATUS_TRANSCRIPT_BYTES_V1: usize = U16_BYTES + 5 * DIGEST_BYTES;
/// Exact `credited` transcript bytes:
/// `LE16 version || u8 tag || credit_id || payment_digest || evidence_digest`.
pub const KAGEMUSHA_WALLET_CREDITED_TRANSCRIPT_BYTES_V1: usize = U16_BYTES + 1 + 3 * DIGEST_BYTES;
/// Fixed depth of the indexed credit-digest membership opening carried by `CreditStatus`.
pub const KAGEMUSHA_WALLET_CREDIT_OPENING_DEPTH_V1: usize =
    super::poseidon::KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1;

const SETUP_DECLINED_FIELDS_BYTES: usize = U16_BYTES;
const UNSUPPORTED_SCHEME_FIELDS_BYTES: usize = 0;
const RECEIVE_DEFERRED_FIELDS_BYTES: usize = U16_BYTES + DIGEST_BYTES;
const CLOSE_FIELDS_BYTES: usize = 0;
/// Kind-dependent field widths of every session control kind, in tag order.
const SESSION_CONTROL_FIELDS_BYTES: [usize; 4] = [
    SETUP_DECLINED_FIELDS_BYTES,
    UNSUPPORTED_SCHEME_FIELDS_BYTES,
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
// Offer (§5.1, design §4.1)
// ---------------------------------------------------------------------------------------

/// Body of a payer Offer, signed by the payer payment key under `kgwoffr1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletOfferBodyV1"
)]
pub struct KagemushaWalletOfferBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Offered scheme.
    pub scheme_id: [u8; 32],
    /// Offered asset scope digest.
    pub asset_digest: [u8; 32],
    /// Paying wallet.
    pub payer_wallet_id: [u8; 32],
    /// Digest of the payer credential carried beside the body.
    pub payer_credential_digest: [u8; 32],
    /// Payer's next send ordinal `s`.
    pub next_send: u128,
    /// Proposed positive amount.
    pub amount: u128,
    /// Fresh session nonce.
    pub session_nonce: [u8; 32],
}

impl KagemushaWalletOfferBodyV1 {
    /// Exact `offer-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_OFFER_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.payer_wallet_id)
            .digest(&self.payer_credential_digest)
            .u128(self.next_send)
            .u128(self.amount)
            .digest(&self.session_nonce)
            .finish()
    }

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Offer, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, and a zero amount.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("offer.version", self.version)?;
        for (field, digest) in [
            ("offer.scheme_id", &self.scheme_id),
            ("offer.asset_digest", &self.asset_digest),
            ("offer.payer_wallet_id", &self.payer_wallet_id),
            (
                "offer.payer_credential_digest",
                &self.payer_credential_digest,
            ),
            ("offer.session_nonce", &self.session_nonce),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        if self.amount == 0 {
            return Err(invalid_v1("offer.amount"));
        }
        Ok(())
    }
}

/// Authenticated session hint of a payer: next ordinal, amount and scheme (§5.1).
///
/// It has no debit or credit authority. `certificates` is exactly the payer issuer certificate.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletOfferV1")]
pub struct KagemushaWalletOfferV1 {
    /// Signed body.
    pub body: KagemushaWalletOfferBodyV1,
    /// Payer credential.
    pub payer_credential: KagemushaWalletCredentialV1,
    /// Exactly the payer credential's issuer certificate.
    pub certificates: KagemushaWalletCertificateSetV1,
    /// Payer payment-key signature over the `kgwoffr1` signing message.
    pub signature: KagemushaDeviceSignatureV1,
}

fn validate_offer_parts_v1(
    body: &KagemushaWalletOfferBodyV1,
    credential: &KagemushaWalletCredentialV1,
    certificates: &KagemushaWalletCertificateSetV1,
) -> WalletResult<()> {
    body.validate()?;
    // The nested credential is bounded like a standalone credential frame (§5.1: "its
    // `CredentialV1` (at most 1,024 bytes)").
    credential.to_canonical_bytes()?;
    let payer = &credential.body;
    require_scheme_v1("offer.scheme_id", &body.scheme_id, &payer.scheme_id)?;
    if body.asset_digest != payer.asset_digest {
        return Err(invalid_v1("offer.asset_digest"));
    }
    if body.payer_wallet_id != payer.wallet_id {
        return Err(invalid_v1("offer.payer_wallet_id"));
    }
    if body.payer_credential_digest != credential.credential_digest() {
        return Err(invalid_v1("offer.payer_credential_digest"));
    }
    require_exact_certificates_v1(
        certificates,
        &body.scheme_id,
        &[(
            payer.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )],
    )
}

impl KagemushaWalletOfferV1 {
    /// Freeze the payer payment-key signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or credential, a body for another wallet or credential, an
    /// issuer certificate that is not the credential's, or a signature that does not verify.
    pub fn sign(
        body: KagemushaWalletOfferBodyV1,
        payer_credential: KagemushaWalletCredentialV1,
        issuer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        let certificates = KagemushaWalletCertificateSetV1::new(vec![*issuer_certificate])?;
        validate_offer_parts_v1(&body, &payer_credential, &certificates)?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &payer_credential.body.payment_key,
            Domain::Offer,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self {
            body,
            payer_credential,
            certificates,
            signature,
        })
    }

    /// Validate the Offer and verify its payer signature.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or credential, a body that does not name the credential's
    /// wallet, scheme, asset or digest, a certificate set other than exactly the issuer
    /// certificate, and a signature that does not verify under the payer payment key.
    pub fn validate(&self) -> WalletResult<()> {
        validate_offer_parts_v1(&self.body, &self.payer_credential, &self.certificates)?;
        kagemusha_wallet_verify_signature_v1(
            &self.payer_credential.body.payment_key,
            Domain::Offer,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the Offer and verify its credential and certificate under `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme, and issuer or root signatures
    /// that do not verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        verify_credential_with_set_v1(&self.payer_credential, scheme, &self.certificates)
    }
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

/// Body of a receiver Request, signed by the receiver payment key under `kgwrqst1`.
///
/// Its 28 σ-field elements define `credit_id = P(kgwcrdt1, elements)` (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRequestBodyV1"
)]
pub struct KagemushaWalletRequestBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme.
    pub scheme_id: [u8; 32],
    /// Asset scope digest.
    pub asset_digest: [u8; 32],
    /// Paying wallet.
    pub payer_wallet_id: [u8; 32],
    /// Account digest of the payer credential.
    pub payer_account_digest: [u8; 32],
    /// Receiving wallet; the receiver credential's wallet.
    pub receiver_wallet_id: [u8; 32],
    /// Account digest of the receiver credential.
    pub receiver_account_digest: [u8; 32],
    /// Payer send ordinal `s` this quote is scoped to.
    pub send_ordinal: u128,
    /// Digest of the receiver credential carried beside the body.
    pub receiver_credential_digest: [u8; 32],
    /// Exact positive amount credited to the receiver.
    pub amount: u128,
    /// Fee schedule digest; zero for no fee.
    pub fee_schedule: [u8; 32],
    /// Exact fee under the schedule; zero without one.
    pub fee: u128,
    /// Receiver's scheme policy epoch; zero when none is held.
    pub policy_epoch: u64,
    /// Receiver's scheme policy digest; zero when none is held.
    pub scheme_policy: [u8; 32],
    /// Receiver's authenticated accepted time in Unix milliseconds.
    pub receiver_accepted_time_ms: u64,
    /// Digest of the Request's certificate set.
    pub certificates: [u8; 32],
    /// Fresh 256-bit nonce.
    pub nonce: [u8; 32],
}

impl KagemushaWalletRequestBodyV1 {
    /// Exact `request-body` transcript.
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

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Request, &self.transcript())
    }

    /// σ-field elements of the body in request-body order (§5.1): version; scheme id (2);
    /// asset digest (2); payer wallet (2); payer account (2); receiver wallet (2); receiver
    /// account (2); send ordinal; receiver
    /// credential digest (2); amount; fee schedule (2); fee; policy epoch; scheme policy (2);
    /// receiver accepted time; certificate-set digest (2); nonce (2) — 28 elements.
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
            .digest(&self.receiver_credential_digest)
            .integer(self.amount)
            .digest(&self.fee_schedule)
            .integer(self.fee)
            .integer(u128::from(self.policy_epoch))
            .digest(&self.scheme_policy)
            .integer(u128::from(self.receiver_accepted_time_ms))
            .digest(&self.certificates)
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

    /// Validate the body's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a zero amount, a payer equal to the receiver,
    /// an overflowing gross debit, a policy epoch that disagrees with its scheme-policy digest,
    /// and a nonzero fee without a fee schedule.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("request.version", self.version)?;
        for (field, digest) in [
            ("request.scheme_id", &self.scheme_id),
            ("request.asset_digest", &self.asset_digest),
            ("request.payer_wallet_id", &self.payer_wallet_id),
            ("request.payer_account_digest", &self.payer_account_digest),
            ("request.receiver_wallet_id", &self.receiver_wallet_id),
            (
                "request.receiver_account_digest",
                &self.receiver_account_digest,
            ),
            (
                "request.receiver_credential_digest",
                &self.receiver_credential_digest,
            ),
            ("request.certificates", &self.certificates),
            ("request.nonce", &self.nonce),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        if self.amount == 0 {
            return Err(invalid_v1("request.amount"));
        }
        if self.payer_wallet_id == self.receiver_wallet_id {
            return Err(invalid_v1("request.payer_wallet_id"));
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
}

/// Receiver-signed nonmonetary setup quote (§5.1).
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
    /// Receiver payment-key signature over the `kgwrqst1` signing message.
    pub signature: KagemushaDeviceSignatureV1,
}

fn validate_request_parts_v1(
    body: &KagemushaWalletRequestBodyV1,
    credential: &KagemushaWalletCredentialV1,
    fee_schedule: &KagemushaWalletFeeScheduleSlotV1,
    certificates: &KagemushaWalletCertificateSetV1,
) -> WalletResult<()> {
    body.validate()?;
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
    /// Accept the receiver payment-key signer output only after authenticating its payer Offer.
    ///
    /// The output is already produced: this constructor enforces context before freezing the
    /// signature. The receiver platform must authenticate this context before invoking its key.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects before the signature, and a signature that does
    /// not verify under the receiver payment key. The Offer and its issuer must verify under
    /// `scheme`, and its credential must match the Request payer wallet, account and asset.
    pub fn sign(
        scheme: &KagemushaWalletSchemeV1,
        offer: &KagemushaWalletOfferV1,
        body: KagemushaWalletRequestBodyV1,
        receiver_credential: KagemushaWalletCredentialV1,
        fee_schedule: KagemushaWalletFeeScheduleSlotV1,
        certificates: KagemushaWalletCertificateSetV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        validate_request_parts_v1(&body, &receiver_credential, &fee_schedule, &certificates)?;
        // The Offer's credential and issuer are authenticated before any signer output is
        // frozen into a Request. A caller cannot choose another payer account in the body.
        require_scheme_v1("request.scheme_id", &body.scheme_id, &scheme.scheme_id())?;
        offer.verify(scheme)?;
        require_request_payer_v1(
            &body,
            &receiver_credential.body.payment_key,
            &offer.payer_credential,
        )?;
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

    /// Request digest `H("request", m || signature)`.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            Role::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the Request and verify its receiver signature (§5.1, design §4.2 and C5).
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or credential, a body that does not name the receiver
    /// credential's wallet, scheme, asset or digest, a fee-schedule slot that disagrees with
    /// the body or prices another fee, a schedule for another scheme or asset, a certificate
    /// set other than exactly the receiver issuer and fee signer, a set digest that differs
    /// from the body, and a signature that does not verify under the receiver payment key.
    pub fn validate(&self) -> WalletResult<()> {
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

    /// Validate the Request and verify its credential, fee schedule and certificates under
    /// `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] rejects, another scheme, and issuer, policy or root
    /// signatures that do not verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
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

    /// Native Send-rule pre-check of the payer from its folded head (§§3.2, 5.1, design §6.2).
    ///
    /// `omega` is the Ω recorded as self-verified when the payer's current head was folded
    /// (§3.1 step 5); its `head` must be the commitment of `payer_state`. The Send relation
    /// enforces the same rules; the controls of §7 are checked separately with the state's
    /// lease, blacklist and quota checks.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Request or payer state, an Ω of another head, wallet, credential or
    /// payment key, another scheme or asset, a Request for another payer or ordinal, a payment
    /// to the payer itself or to the same key, a payer policy epoch below the Request's, a
    /// different scheme policy at the same epoch, a different fee schedule, and a gross debit
    /// above `balance − burned_total` with Ω's lineage-adjusted `burned_total`.
    pub fn check_send_rule(
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
        if body.payer_account_digest != payer_credential.body.account_digest {
            return Err(invalid_v1("request.payer_account_digest"));
        }
        if body.receiver_wallet_id == core.wallet_id {
            return Err(invalid_v1("request.receiver_wallet_id"));
        }
        if payer_credential.body.payment_key == self.receiver_credential.body.payment_key {
            return Err(invalid_v1("request.payment_key"));
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

    /// Send effect of this Request at the effective accepted time `interval` (§7).
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
    pub fn send_effect(
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
    /// Receiver payment-key signature over the `kgwrqst1` signing message.
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

    /// Request digest `H("request", m || signature)`.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            Role::Request,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Verify the receiver signature under `receiver_credential`, whose digest the body binds.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or credential, a credential other than the body's receiver
    /// credential, and a signature that does not verify.
    pub fn verify(&self, receiver_credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        self.validate()?;
        receiver_credential.validate()?;
        if receiver_credential.credential_digest() != self.body.receiver_credential_digest {
            return Err(invalid_v1("request.receiver_credential_digest"));
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
// Payment (§§5.1, 8, design §6.3)
// ---------------------------------------------------------------------------------------

/// Exact `payment` transcript:
/// `LE16 version || request_digest || payer_payment_key || payer_credential_digest ||
/// package_digest`.
///
/// The Payment digest is `P_bytes(kgwpay_1, transcript)` (§5.1, owner answer Q9): it binds the
/// signed Request and the payer fields directly and Ω(pred), `σ_send` and `τ_send` through the
/// package digest, whose `proof_digest` covers both proofs.
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

/// Complete canonical compact Payment (§§5.1, 8).
///
/// It contains the signed Request body, the payer's `payment_key` and credential digest (both
/// equal to Ω(pred)'s), and the Send package `{statement, Ω(pred), σ_send, τ_send}`. The
/// Payment is committed and retained before first release; delivery retries present the exact
/// same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletPaymentV1"
)]
pub struct KagemushaWalletPaymentV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Receiver-signed Request body.
    pub request: KagemushaWalletSignedRequestV1,
    /// Payer payment key; equal to `Ω(pred).payment_key`.
    pub payer_payment_key: KagemushaDevicePublicKeyV1,
    /// Payer credential digest; equal to `Ω(pred).credential_digest`.
    pub payer_credential_digest: [u8; 32],
    /// Complete committed Send package carrying Ω(pred).
    pub send: KagemushaWalletPackageV1,
}

impl KagemushaWalletPaymentV1 {
    /// Assemble the canonical Payment of a committed Send by the payer holding the full
    /// Request and its own credential.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Request, a payer credential other than the one the Request names,
    /// what [`Self::digests`] rejects, and a package or Ω for another payer credential.
    pub fn assemble(
        request: &KagemushaWalletRequestV1,
        payer_credential: &KagemushaWalletCredentialV1,
        send: KagemushaWalletPackageV1,
    ) -> WalletResult<Self> {
        request.validate()?;
        payer_credential.validate()?;
        request.require_payer(payer_credential)?;
        let payment = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            request: request.signed(),
            payer_payment_key: payer_credential.body.payment_key,
            payer_credential_digest: payer_credential.credential_digest(),
            send,
        };
        payment.digests()?;
        payment.send.verify(payer_credential)?;
        Ok(payment)
    }

    /// Structurally validate the Payment, run the §3.2 consumer checks and return its
    /// digests (design §6.3).
    ///
    /// No Payment digest is exposed without this validation. It is self-contained: the
    /// Request signature and the credentials that the Payment binds only by digest are
    /// verified by [`Self::verify`] with the session's inputs.
    ///
    /// # Errors
    ///
    /// Rejects another version; an invalid Request body, signature encoding or payer key; a
    /// package that is not a valid Send carrying Ω(pred), or whose receipt does not verify
    /// under `Ω.payment_key`; a Request payer other than `Ω.wallet_id`; a carried credential
    /// digest or payment key other than Ω's; a statement or effect whose scheme, asset,
    /// credit, receiver, ordinal, amount, fee, Request digest or accepted time differ from the
    /// Request; and an Ω policy epoch below the Request's.
    pub fn digests(&self) -> WalletResult<KagemushaWalletPaymentDigestsV1> {
        require_version_v1("payment.version", self.version)?;
        self.request.validate()?;
        self.payer_payment_key.validate()?;
        require_nonzero_v1(
            "payment.payer_credential_digest",
            &self.payer_credential_digest,
        )?;
        let body = &self.request.body;
        let statement = &self.send.statement;
        let KagemushaWalletEffectV1::Send {
            credit_id: effect_credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request: effect_request,
            accepted_lower_ms,
            ..
        } = statement.effect
        else {
            return Err(invalid_v1("payment.effect"));
        };
        let (_, package) = self.send.check_lineage_consumer()?;
        let omega = &self
            .send
            .lineage
            .lineage()
            .ok_or_else(|| invalid_v1("lineage.slot"))?
            .public;
        let credit_id = self.request.credit_id();
        let request_digest = self.request.request_digest();
        for (field, matches) in [
            (
                "payment.payer_wallet_id",
                body.payer_wallet_id == omega.wallet_id,
            ),
            (
                "payment.payer_credential_digest",
                self.payer_credential_digest == omega.credential_digest,
            ),
            (
                "payment.payer_payment_key",
                self.payer_payment_key == omega.payment_key,
            ),
            ("payment.effect.credit_id", effect_credit_id == credit_id),
            (
                "payment.effect.receiver_wallet_id",
                receiver_wallet_id == body.receiver_wallet_id,
            ),
            (
                "payment.effect.send_ordinal",
                send_ordinal == body.send_ordinal,
            ),
            ("payment.effect.amount", amount == body.amount),
            ("payment.effect.fee", fee == body.fee),
            ("payment.effect.request", effect_request == request_digest),
            (
                "payment.effect.accepted_time",
                accepted_lower_ms >= body.receiver_accepted_time_ms,
            ),
            (
                "payment.statement.asset_digest",
                statement.asset_digest == body.asset_digest,
            ),
            (
                "payment.policy_epoch",
                omega.policy_epoch >= body.policy_epoch,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        require_scheme_v1(
            "payment.statement.scheme_id",
            &statement.scheme_id,
            &body.scheme_id,
        )?;
        let payment = kagemusha_wallet_poseidon_bytes_v1(
            KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1,
            &kagemusha_wallet_payment_transcript_v1(
                &request_digest,
                &self.payer_payment_key,
                &self.payer_credential_digest,
                &package.package,
            ),
        );
        Ok(KagemushaWalletPaymentDigestsV1 {
            credit_id,
            request: request_digest,
            payer_credential: self.payer_credential_digest,
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
    /// credential and its issuer certificate from the Offer, and the receiver's own held
    /// Request.
    ///
    /// Beyond [`Self::digests`] it checks that the carried Request is the held one, verifies
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
        let digests = self.digests()?;
        if request.signed() != self.request {
            return Err(invalid_v1("payment.request"));
        }
        request.verify(scheme)?;
        request.require_payer(payer_credential)?;
        if payer_credential.credential_digest() != self.payer_credential_digest {
            return Err(invalid_v1("payment.payer_credential_digest"));
        }
        if payer_credential.body.payment_key != self.payer_payment_key {
            return Err(invalid_v1("payment.payer_payment_key"));
        }
        verify_credential_with_set_v1(payer_credential, scheme, payer_certificates)?;
        self.send.statement.validate_for_scheme(scheme)?;
        Ok(digests)
    }

    /// Receive effect of this Payment for the receiver holding `receiver_credential`, its
    /// current credential, and its own signed `request` (§5.1).
    ///
    /// The receiver is matched by the Request's receiver `wallet_id` and the `payment_key` of
    /// the Request's receiver credential, never by credential-digest equality, so a Request
    /// quoted before a renewal stays receivable after it (owner answer Q8). The effect carries
    /// no Payment digest (§3). Consumed-credit nonmembership is checked inside the serialized
    /// Advance section (§4.2).
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::digests`] rejects, an invalid receiver credential or Request, a
    /// carried Request other than `request`, and a Payment for another scheme, asset, wallet
    /// or payment key.
    pub fn receive_effect(
        &self,
        request: &KagemushaWalletRequestV1,
        receiver_credential: &KagemushaWalletCredentialV1,
    ) -> WalletResult<KagemushaWalletEffectV1> {
        let digests = self.digests()?;
        request.validate()?;
        receiver_credential.validate()?;
        if request.signed() != self.request {
            return Err(invalid_v1("payment.request"));
        }
        let body = &self.request.body;
        let receiver = &receiver_credential.body;
        require_scheme_v1("payment.scheme_id", &body.scheme_id, &receiver.scheme_id)?;
        if body.asset_digest != receiver.asset_digest {
            return Err(invalid_v1("payment.asset_digest"));
        }
        if body.receiver_wallet_id != receiver.wallet_id {
            return Err(invalid_v1("payment.receiver_wallet_id"));
        }
        if body.receiver_account_digest != receiver.account_digest {
            return Err(invalid_v1("payment.receiver_account_digest"));
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
        let body = &self.request.body;
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
            amount: self.request.body.amount,
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
        let body = &self.request.body;
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
        let body = &self.request.body;
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
            &payment.request.body.scheme_id,
            expected_scheme_id,
        )?;
        payment.validate()?;
        Ok(payment)
    }
}

// ---------------------------------------------------------------------------------------
// Lineage message (§§5.1, 8, design §6.4)
// ---------------------------------------------------------------------------------------

/// Ω of the payer's folded head, sent after an authenticated Offer (§5.1).
///
/// It is unsigned: the receiver verifies it only after an authenticated Offer, rate-limits
/// it, and checks Ω's `wallet_id`, credential digest and `payment_key` against the Offer's
/// credential. A Payment whose Ω(pred) is byte-identical (equal [`Self::lineage_digest`])
/// reuses that verification.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletLineageMessageV1"
)]
pub struct KagemushaWalletLineageMessageV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Lineage proof Ω of the payer's folded head.
    pub lineage: KagemushaWalletLineageV1,
}

impl KagemushaWalletLineageMessageV1 {
    /// Wrap `lineage` in a V1 message.
    #[must_use]
    pub const fn new(lineage: KagemushaWalletLineageV1) -> Self {
        Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            lineage,
        }
    }

    /// Validate the message structure.
    ///
    /// # Errors
    ///
    /// Rejects another version and an invalid lineage.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("lineage_message.version", self.version)?;
        self.lineage.validate()
    }

    /// Lineage digest `P_bytes(kgwlin_1, Ω bytes)`.
    #[must_use]
    pub fn lineage_digest(&self) -> [u8; 32] {
        self.lineage.lineage_digest()
    }

    /// Check Ω against the authenticated Offer of the same session (§5.1); the Offer must
    /// already have been verified.
    ///
    /// # Errors
    ///
    /// Rejects an invalid message or Offer and an Ω whose scheme, wallet, credential digest or
    /// payment key differ from the Offer's credential.
    pub fn verify_for_offer(&self, offer: &KagemushaWalletOfferV1) -> WalletResult<()> {
        self.validate()?;
        offer.validate()?;
        let omega = &self.lineage.public;
        let payer = &offer.payer_credential.body;
        require_scheme_v1("lineage.scheme_id", &omega.scheme_id, &payer.scheme_id)?;
        for (field, matches) in [
            ("lineage.wallet_id", omega.wallet_id == payer.wallet_id),
            (
                "lineage.credential_digest",
                omega.credential_digest == offer.body.payer_credential_digest,
            ),
            (
                "lineage.payment_key",
                omega.payment_key == payer.payment_key,
            ),
        ] {
            if !matches {
                return Err(invalid_v1(field));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// CreditStatus and Credited (§§3.1, 5.1, design §6.5 and §6.6)
// ---------------------------------------------------------------------------------------

/// Indexed membership opening of `credit_id → (Payment digest, burned flag)` in Ω's
/// credit-digest root (§§3.2, 3.4). The slot is nonzero and exactly 32 canonical siblings
/// open the linked leaf `(credit_id, P(kgwcdig1, [credit_id, payment_digest, burned]), next_key)`.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCreditOpeningV1"
)]
pub struct KagemushaWalletCreditOpeningV1 {
    /// Credit identity (the indexed map key), a nonzero canonical σ-field value.
    pub credit_id: [u8; 32],
    /// Full canonical Payment digest, a nonzero canonical σ-field value.
    pub payment_digest: [u8; 32],
    /// Whether the Receive relation took the burn branch.
    pub burned: bool,
    /// Next larger credit key, or zero for the last linked leaf.
    pub next_key: [u8; 32],
    /// Allocated membership slot; slot zero is the sentinel and cannot prove a credit.
    pub slot: u32,
    /// Exactly 1,024 canonical sibling bytes in increasing height.
    pub siblings: Vec<u8>,
}

impl KagemushaWalletCreditOpeningV1 {
    /// Build a credit opening from the value record and its actual indexed membership leaf.
    ///
    /// # Errors
    ///
    /// Rejects a leaf with another key or value and an invalid opening shape.
    pub fn new(
        leaf: &KagemushaWalletCreditDigestLeafV1,
        indexed_leaf: &KagemushaWalletIndexedLeafV1,
        opening: &KagemushaWalletIndexedOpeningV1,
    ) -> WalletResult<Self> {
        if *indexed_leaf != leaf.indexed_leaf(indexed_leaf.next_key)? {
            return Err(invalid_v1("credit_opening.leaf"));
        }
        let result = Self {
            credit_id: leaf.credit_id,
            payment_digest: leaf.payment_digest,
            burned: leaf.burned,
            next_key: indexed_leaf.next_key,
            slot: opening.slot,
            siblings: opening.sibling_bytes(),
        };
        result.validate()?;
        Ok(result)
    }

    /// Credit-digest value record this opening proves.
    #[must_use]
    pub const fn leaf(&self) -> KagemushaWalletCreditDigestLeafV1 {
        KagemushaWalletCreditDigestLeafV1 {
            credit_id: self.credit_id,
            payment_digest: self.payment_digest,
            burned: self.burned,
        }
    }

    /// Sibling values, height zero first; validation rejects a trailing partial value.
    pub fn sibling_values(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.siblings.chunks_exact(DIGEST_BYTES).map(|chunk| {
            let mut value = [0_u8; 32];
            value.copy_from_slice(chunk);
            value
        })
    }

    fn indexed_opening(&self) -> WalletResult<KagemushaWalletIndexedOpeningV1> {
        KagemushaWalletIndexedOpeningV1::from_sibling_bytes(self.slot, &self.siblings)
    }

    /// Validate the exact membership opening shape, key order and canonical field values.
    ///
    /// # Errors
    ///
    /// Rejects a zero or noncanonical credit or Payment digest, slot zero, a noncanonical
    /// next key or one not above the credit, another sibling length and a noncanonical sibling.
    pub fn validate(&self) -> WalletResult<()> {
        require_nonzero_field_v1("credit_opening.credit_id", &self.credit_id)?;
        require_nonzero_field_v1("credit_opening.payment_digest", &self.payment_digest)?;
        if self.slot == 0 {
            return Err(invalid_v1("credit_opening.slot"));
        }
        self.leaf().indexed_leaf(self.next_key)?;
        self.indexed_opening()?;
        Ok(())
    }

    /// Recompute the indexed credit-digest root of this membership opening.
    ///
    /// # Errors
    ///
    /// Rejects an invalid opening.
    pub fn root(&self) -> WalletResult<[u8; 32]> {
        self.validate()?;
        self.indexed_opening()?
            .leaf_root(&self.leaf().indexed_leaf(self.next_key)?)
    }

    /// Exact 1,125-byte transcript:
    /// `credit_id || payment_digest || u8 burned || next_key || LE32 slot || siblings`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid opening.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        Ok(WalletTranscriptV1::with_capacity(1_125)
            .digest(&self.credit_id)
            .digest(&self.payment_digest)
            .u8(u8::from(self.burned))
            .digest(&self.next_key)
            .u32(self.slot)
            .bytes(&self.siblings)
            .finish())
    }

    /// Canonical σ-field opening digest `P_bytes(kgwcopn1, transcript)`.
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
    /// Compressed credit-digest opening in Ω(h)'s credit-digest root.
    pub opening: KagemushaWalletCreditOpeningV1,
}

impl KagemushaWalletCreditStatusV1 {
    /// Validate the status, verify τ(h) under `Ω(h).payment_key` and return its digest
    /// `P_bytes(kgwcsts1, transcript)`.
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
                .digest(&self.statement.statement_digest())
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
    /// The `credited` transcript is
    /// `LE16 version || u8 tag || credit_id || payment_digest || evidence_digest`, with the
    /// package digest (Receive) or the `credit-status` digest (Status) as evidence digest.
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
        request.validate()?;
        let payment_digests = payment.digests()?;
        if payment.request != request.signed() {
            return Err(invalid_v1("credited.payment.request"));
        }
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
    /// The offered scheme is not supported; always unsigned and stateless.
    #[codec(index = 2)]
    UnsupportedScheme,
    /// Receive postponed (for example for capacity); carries the credit and a reason code.
    #[codec(index = 3)]
    ReceiveDeferred,
    /// Session closed.
    #[codec(index = 4)]
    Close,
}

impl KagemushaWalletSessionControlKindV1 {
    /// Every kind, in tag order.
    pub const ALL: [Self; 4] = [
        Self::SetupDeclined,
        Self::UnsupportedScheme,
        Self::ReceiveDeferred,
        Self::Close,
    ];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::SetupDeclined => 1,
            Self::UnsupportedScheme => 2,
            Self::ReceiveDeferred => 3,
            Self::Close => 4,
        }
    }

    /// Width of the kind-dependent fields this kind uses.
    #[must_use]
    pub const fn fields_bytes(self) -> usize {
        match self {
            Self::SetupDeclined => SETUP_DECLINED_FIELDS_BYTES,
            Self::UnsupportedScheme => UNSUPPORTED_SCHEME_FIELDS_BYTES,
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
    /// Unsigned: `UnsupportedScheme`, or `SetupDeclined` before the sender's own Offer or
    /// Request in the session.
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
    /// Session scheme; for `UnsupportedScheme`, the declined scheme.
    pub scheme_id: [u8; 32],
    /// Session asset scope digest.
    pub asset_digest: [u8; 32],
    /// Sending wallet; zero only for `UnsupportedScheme` (no wallet in that scheme).
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
    /// Stateless unsigned `UnsupportedScheme` reply to an Offer whose scheme the receiver does
    /// not support (§8).
    ///
    /// It names the declined scheme, asset and session nonce of `offer` and the offering payer
    /// as its peer; the sender wallet is zero because the receiver has no wallet in that scheme.
    /// Obtain `offer` from [`KagemushaWalletEnvelopeV1::decode_offered_scheme`].
    ///
    /// # Errors
    ///
    /// Rejects an invalid Offer body.
    pub fn unsupported_scheme(offer: &KagemushaWalletOfferBodyV1) -> WalletResult<Self> {
        offer.validate()?;
        let control = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: offer.scheme_id,
            asset_digest: offer.asset_digest,
            sender_wallet_id: [0; 32],
            peer_wallet_id: offer.payer_wallet_id,
            session_nonce: offer.session_nonce,
            kind: KagemushaWalletSessionControlKindV1::UnsupportedScheme,
            reason: 0,
            credit_id: [0; 32],
            auth: KagemushaWalletSessionAuthV1::Unsigned,
        };
        control.validate()?;
        Ok(control)
    }

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

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::SessionControl, &self.transcript())
    }

    /// Freeze the sender payment-key signature over this control.
    ///
    /// # Errors
    ///
    /// Rejects an invalid control, an `UnsupportedScheme` control, a control for another
    /// wallet, scheme or asset than `sender_credential`, or a signature that does not verify.
    pub fn sign(
        mut self,
        sender_credential: &KagemushaWalletCredentialV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        if self.kind == KagemushaWalletSessionControlKindV1::UnsupportedScheme {
            return Err(invalid_v1("session_control.auth"));
        }
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
    /// are set when unused or missing when used, a noncanonical `credit_id`, and a signed
    /// `UnsupportedScheme`.
    pub fn validate(&self) -> WalletResult<()> {
        use KagemushaWalletSessionControlKindV1 as Kind;
        require_version_v1("session_control.version", self.version)?;
        require_nonzero_v1("session_control.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("session_control.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("session_control.session_nonce", &self.session_nonce)?;
        if self.kind != Kind::UnsupportedScheme {
            require_nonzero_v1("session_control.sender_wallet_id", &self.sender_wallet_id)?;
        }
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
            KagemushaWalletSessionAuthV1::Signed { signature } => {
                if self.kind == Kind::UnsupportedScheme {
                    return Err(invalid_v1("session_control.auth"));
                }
                signature.validate()?;
                Ok(())
            }
        }
    }

    /// Verify the control against the sender credential learned in the same session (design
    /// C8).
    ///
    /// Pass the credential of the sender's Offer (payer) or Request (receiver) in this
    /// session, or `None` when the sender has sent neither. Unsigned controls are accepted only
    /// for `UnsupportedScheme`, and for `SetupDeclined` before the sender's key is known.
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
            (KagemushaWalletSessionAuthV1::Unsigned, _) if self.kind == Kind::UnsupportedScheme => {
                Ok(())
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
/// downloads it only while online, from the issuer or ledger, as one standalone
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
    /// Payer session hint.
    #[codec(index = 1)]
    Offer {
        /// Offer.
        offer: KagemushaWalletOfferV1,
    },
    /// Receiver setup quote.
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
    /// Nonmonetary policy data.
    #[codec(index = 6)]
    PolicyData {
        /// Policy data.
        data: KagemushaWalletPolicyDataV1,
    },
    /// Ω of the payer's folded head, after an authenticated Offer.
    #[codec(index = 7)]
    Lineage {
        /// Lineage message.
        lineage: KagemushaWalletLineageMessageV1,
    },
}

impl KagemushaWalletMessageV1 {
    /// Wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Offer { .. } => 1,
            Self::Request { .. } => 2,
            Self::Payment { .. } => 3,
            Self::Credited { .. } => 4,
            Self::SessionControl { .. } => 5,
            Self::PolicyData { .. } => 6,
            Self::Lineage { .. } => 7,
        }
    }

    /// Maximum complete envelope frame of this kind (§8).
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        match self {
            Self::Offer { .. } | Self::SessionControl { .. } => {
                KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1
            }
            Self::Request { .. }
            | Self::Payment { .. }
            | Self::Credited { .. }
            | Self::PolicyData { .. }
            | Self::Lineage { .. } => KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        }
    }

    /// Top-level version field of the message.
    #[must_use]
    pub const fn version(&self) -> u16 {
        match self {
            Self::Offer { offer } => offer.body.version,
            Self::Request { request } => request.body.version,
            Self::Payment { payment } => payment.version,
            Self::Credited { credited } => credited.version,
            Self::SessionControl { control } => control.version,
            Self::PolicyData { data } => data.version,
            Self::Lineage { lineage } => lineage.version,
        }
    }

    /// Scheme field checked at decode (design §6.7): the body scheme of Offer and Request, the
    /// Request scheme of Payment, Ω's scheme of Lineage, and the message's own scheme field
    /// otherwise.
    #[must_use]
    pub const fn scheme_id(&self) -> &[u8; 32] {
        match self {
            Self::Offer { offer } => &offer.body.scheme_id,
            Self::Request { request } => &request.body.scheme_id,
            Self::Payment { payment } => &payment.request.body.scheme_id,
            Self::Credited { credited } => &credited.scheme_id,
            Self::SessionControl { control } => &control.scheme_id,
            Self::PolicyData { data } => &data.scheme_id,
            Self::Lineage { lineage } => &lineage.lineage.public.scheme_id,
        }
    }

    /// Validate the message's self-contained rules, including every signature whose key the
    /// message carries. Payment, Credited and Lineage are validated structurally: their full
    /// verification needs the session's inputs (design §6.7).
    ///
    /// # Errors
    ///
    /// Rejects what the message type's own validation rejects.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Offer { offer } => offer.validate(),
            Self::Request { request } => request.validate(),
            Self::Payment { payment } => payment.validate(),
            Self::Credited { credited } => credited.validate(),
            Self::SessionControl { control } => control.validate(),
            Self::PolicyData { data } => data.validate(),
            Self::Lineage { lineage } => lineage.validate(),
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

    /// Decode an Offer envelope only far enough to decline its scheme (§8: "an unknown scheme
    /// can be declined during Offer").
    ///
    /// Runs the byte cap, canonical decoding, every version field and the per-kind bound in the
    /// order of [`Self::decode_canonical`], requires an Offer, and returns its structurally
    /// valid body without the expected-scheme check. The body is unauthenticated: the payer
    /// credential and signature are not verified, because a receiver that does not support the
    /// scheme cannot verify them. It confers nothing beyond the stateless
    /// [`KagemushaWalletSessionControlV1::unsupported_scheme`] reply; a supported scheme must be
    /// decoded with [`Self::decode_canonical`].
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::decode_canonical`] rejects before its scheme check, a message other
    /// than an Offer, and an invalid Offer body.
    pub fn decode_offered_scheme(bytes: &[u8]) -> WalletResult<KagemushaWalletOfferBodyV1> {
        let envelope = Self::decode_bounded(bytes)?;
        let KagemushaWalletMessageV1::Offer { offer } = envelope.message else {
            return Err(invalid_v1("envelope.message"));
        };
        offer.body.validate()?;
        Ok(offer.body)
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

    /// Strictly decode the `kgm1:` text form of an Offer only far enough to decline its scheme.
    ///
    /// # Errors
    ///
    /// Rejects what [`kagemusha_wallet_text_decode_v1`] and [`Self::decode_offered_scheme`]
    /// reject.
    pub fn offered_scheme_from_text(text: &str) -> WalletResult<KagemushaWalletOfferBodyV1> {
        Self::decode_offered_scheme(&kagemusha_wallet_text_decode_v1(text)?)
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

impl WalletVersionsV1 for KagemushaWalletOfferV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("offer.version", self.body.version)?;
        self.payer_credential.require_versions()?;
        self.certificates.require_versions()
    }
}

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

impl WalletVersionsV1 for KagemushaWalletPaymentV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("payment.version", self.version)?;
        require_version_v1("request.version", self.request.body.version)?;
        self.send.require_versions()
    }
}

impl WalletVersionsV1 for KagemushaWalletLineageMessageV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("lineage_message.version", self.version)?;
        self.lineage.require_versions()
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
            Self::Offer { offer } => offer.require_versions(),
            Self::Request { request } => request.require_versions(),
            Self::Payment { payment } => payment.require_versions(),
            Self::Credited { credited } => credited.require_versions(),
            Self::SessionControl { control } => control.require_versions(),
            Self::PolicyData { data } => data.require_versions(),
            Self::Lineage { lineage } => lineage.require_versions(),
        }
    }
}

impl WalletVersionsV1 for KagemushaWalletEnvelopeV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("envelope.version", self.version)?;
        self.message.require_versions()
    }
}
