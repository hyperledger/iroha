//! Complete first-release Anonymous-PGC payment relation.
//!
//! This is a clean-room, linear-size realization of the four legality
//! sub-languages in §6 of ePrint 2025/884.  It deliberately favors a small,
//! auditable collection of generalized Schnorr protocols over the paper's
//! optimized logarithmic-size composition:
//!
//! - every transfer ciphertext is proved well formed;
//! - a Schnorr proof opens the aggregate right component to zero plaintext;
//! - hidden, pairwise-distinct recipient indices are selected with OR proofs
//!   and their rerandomized values receive exact 32-bit positive range proofs;
//! - hidden, pairwise-distinct decoy indices are selected with OR proofs and
//!   proved to open to zero;
//! - one hidden sender index is shared by key ownership, negative transfer,
//!   and nonnegative post-balance relations.
//!
//! The selected-index commitments are binding Pedersen commitments.  A
//! generalized Schnorr multiplication proof shows every within-class index
//! difference has an inverse, preventing duplicate selections without
//! revealing the indices.  Since positive, zero, and negative openings are
//! mutually exclusive and the admitted counts sum to `n`, these proofs cover
//! exactly one sender, exactly `k` recipients, and exactly `n-k-1` decoys.
use super::{
    AnonymousPgcError, AnonymousPgcParametersV1, AnonymousPgcPoolInvariantV1,
    AnonymousPgcReadError, TwistedElGamalCiphertextV1, TwistedElGamalPublicKeyV1,
    fixed_array::FixedProofArray,
};
use crate::privacy_engines::p256::{
    CanonicalScalarV1, CompressedPointV1, P256EngineError, SecretScalarV1, TranscriptBindingV1,
    TranscriptV1, health_checked_p256_rng_v1, random_nonzero_scalar,
};
use p256::{ProjectivePoint, Scalar, elliptic_curve::Field};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
/// Closed suite for the complete payment proof.
pub const PGC_PAYMENT_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.p256.sha256.v1";
/// Canonical payment-proof wire version.
pub const PGC_PAYMENT_PROOF_VERSION_V1: u8 = 1;
/// Closed first-release anonymity-set sizes.
pub const PGC_PAYMENT_ANONYMITY_SET_SIZES_V1: [usize; 3] = [16, 32, 64];
/// Maximum intended recipients in one payment.
pub const PGC_PAYMENT_MAX_RECIPIENTS_V1: usize = 8;
/// Maximum canonical bytes accepted for one complete payment proof.
pub const MAX_PGC_PAYMENT_PROOF_BYTES_V1: usize = 4 * 1024 * 1024;
/// Closed supply-provenance fields bound into every payment statement.
pub const PGC_PAYMENT_POOL_INVARIANT_SCHEMA_V1: &[u8] =
    b"total_supply:u32be|bootstrap_digest:32|bootstrap_proof_digest:32";
const PAYMENT_MEMO_DIGEST_DOMAIN_V1: &[u8] = b"iroha.anonymous-pgc.payment.memo-and-ledger.v1";
const WELL_FORMED_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.well-formed.v1";
const BALANCE_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.balance.v1";
const RANGE_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.range32.v1";
const NONZERO_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.nonzero.v1";
const RECIPIENT_SELECTION_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.recipient-selection.v1";
const DECOY_SELECTION_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.decoy-selection.v1";
const SENDER_SELECTION_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.payment.sender-selection.v1";
const MAX_PROVER_RESTARTS: usize = 128;
const RANGE_BITS: usize = 32;
/// Public payment input, including the ledger ciphertexts queried at the
/// statement's committed current root.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousPgcPaymentStatementV1<'a> {
    public_keys: &'a [TwistedElGamalPublicKeyV1],
    transfer_ciphertexts: &'a [TwistedElGamalCiphertextV1],
    current_balance_ciphertexts: &'a [TwistedElGamalCiphertextV1],
    recipient_count: usize,
    pool_invariant: AnonymousPgcPoolInvariantV1,
    transcript_binding: TranscriptBindingV1<'a>,
    memo_and_ledger_digest: [u8; 32],
}
impl<'a> AnonymousPgcPaymentStatementV1<'a> {
    /// Construct a fully bound payment statement.
    ///
    /// `current_balance_ciphertexts` must be the complete ordered ledger table
    /// selected by the statement's current root.  It is absorbed explicitly by
    /// every sub-proof because those ciphertexts are queried state rather than
    /// fields of the public memo.
    ///
    /// # Errors
    ///
    /// Rejects unsupported sizes, count mismatches, unsorted/duplicate keys,
    /// malformed points, or governed transcript-digest mismatches.
    pub fn new(
        public_keys: &'a [TwistedElGamalPublicKeyV1],
        transfer_ciphertexts: &'a [TwistedElGamalCiphertextV1],
        current_balance_ciphertexts: &'a [TwistedElGamalCiphertextV1],
        recipient_count: usize,
        pool_invariant: AnonymousPgcPoolInvariantV1,
        transcript_binding: TranscriptBindingV1<'a>,
    ) -> Result<Self, AnonymousPgcError> {
        super::validate_binding(&transcript_binding)?;
        let count = public_keys.len();
        if !PGC_PAYMENT_ANONYMITY_SET_SIZES_V1.contains(&count) {
            return Err(AnonymousPgcError::InvalidPaymentAnonymitySetSize { count });
        }
        if transfer_ciphertexts.len() != count || current_balance_ciphertexts.len() != count {
            return Err(AnonymousPgcError::PaymentLengthMismatch {
                public_keys: count,
                transfers: transfer_ciphertexts.len(),
                current_balances: current_balance_ciphertexts.len(),
            });
        }
        if recipient_count == 0
            || recipient_count > PGC_PAYMENT_MAX_RECIPIENTS_V1
            || recipient_count >= count
        {
            return Err(AnonymousPgcError::InvalidPaymentRecipientCount {
                count: recipient_count,
                anonymity_set_size: count,
            });
        }
        for (index, key) in public_keys.iter().enumerate() {
            let _ = key.point.to_projective()?;
            if index > 0 && public_keys[index - 1].point >= key.point {
                return Err(AnonymousPgcError::PaymentKeysNotStrictlyIncreasing);
            }
        }
        for ciphertext in transfer_ciphertexts
            .iter()
            .chain(current_balance_ciphertexts)
        {
            ciphertext.validate()?;
        }
        let memo_and_ledger_digest = memo_and_ledger_digest(
            public_keys,
            transfer_ciphertexts,
            current_balance_ciphertexts,
            recipient_count,
            pool_invariant,
        )?;
        Ok(Self {
            public_keys,
            transfer_ciphertexts,
            current_balance_ciphertexts,
            recipient_count,
            pool_invariant,
            transcript_binding,
            memo_and_ledger_digest,
        })
    }
    /// Ordered anonymity-set size.
    #[must_use]
    pub const fn anonymity_set_size(&self) -> usize {
        self.public_keys.len()
    }
    /// Exact positive-recipient count.
    #[must_use]
    pub const fn recipient_count(&self) -> usize {
        self.recipient_count
    }
    /// Immutable total-supply and bootstrap-provenance invariant for the pool.
    #[must_use]
    pub const fn pool_invariant(&self) -> AnonymousPgcPoolInvariantV1 {
        self.pool_invariant
    }
    /// Digest of the ordered public memo and queried current ciphertext table.
    #[must_use]
    pub const fn memo_and_ledger_digest(&self) -> [u8; 32] {
        self.memo_and_ledger_digest
    }
    /// Ordered public keys.
    #[must_use]
    pub const fn public_keys(&self) -> &'a [TwistedElGamalPublicKeyV1] {
        self.public_keys
    }
    /// Ordered public transfer memo.
    #[must_use]
    pub const fn transfer_ciphertexts(&self) -> &'a [TwistedElGamalCiphertextV1] {
        self.transfer_ciphertexts
    }
    /// Ordered current ledger ciphertexts.
    #[must_use]
    pub const fn current_balance_ciphertexts(&self) -> &'a [TwistedElGamalCiphertextV1] {
        self.current_balance_ciphertexts
    }
}
/// Secret payment openings supplied by the transaction builder.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousPgcPaymentWitnessV1<'a> {
    /// Signed transfer values in public-memo order.
    pub transfer_values: &'a [i64],
    /// Transfer randomizers in public-memo order.
    pub transfer_randomness: &'a [SecretScalarV1],
    /// Hidden sender position.
    pub sender_index: usize,
    /// Sender account secret key.
    pub sender_secret: &'a SecretScalarV1,
}
fn payment_proof_decode_limits(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    payload_len: usize,
) -> Result<norito::DecodeLimits, AnonymousPgcError> {
    let anonymity_set_size = statement.anonymity_set_size();
    let recipient_count = statement.recipient_count();
    let decoy_count = anonymity_set_size
        .checked_sub(recipient_count)
        .and_then(|remaining| remaining.checked_sub(1))
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    let recipient_pairs = pair_count(recipient_count)?;
    let decoy_pairs = pair_count(decoy_count)?;
    let max_sequence_elements = [
        anonymity_set_size,
        recipient_count,
        recipient_pairs,
        decoy_count,
        decoy_pairs,
    ]
    .into_iter()
    .max()
    .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    let outer_elements = anonymity_set_size
        .checked_add(recipient_count)
        .and_then(|total| total.checked_add(recipient_pairs))
        .and_then(|total| total.checked_add(decoy_count))
        .and_then(|total| total.checked_add(decoy_pairs))
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    let selection_elements = anonymity_set_size
        .checked_mul(3)
        .and_then(|per_selection| {
            recipient_count
                .checked_add(decoy_count)
                .and_then(|selections| per_selection.checked_mul(selections))
        })
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    let sender_elements = anonymity_set_size
        .checked_mul(5)
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    let max_total_elements = outer_elements
        .checked_add(selection_elements)
        .and_then(|total| total.checked_add(sender_elements))
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
    Ok(norito::DecodeLimits::new(
        max_sequence_elements,
        payload_len,
        max_total_elements,
        MAX_PGC_PAYMENT_PROOF_BYTES_V1.saturating_mul(4),
        32,
    ))
}
/// Canonical well-formedness proof for one transfer ciphertext.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcTransferWellFormedProofV1"
)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcTransferWellFormedProofV1 {
    announcement_left: CompressedPointV1,
    announcement_right: CompressedPointV1,
    randomness_response: CanonicalScalarV1,
    value_response: CanonicalScalarV1,
}
/// Schnorr proof that the aggregate transfer plaintext is zero.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcBalanceConservationProofV1"
)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcBalanceConservationProofV1 {
    announcement: CompressedPointV1,
    randomness_response: CanonicalScalarV1,
}
/// Exact unsigned 32-bit Pedersen range proof.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcUnsignedRangeProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcUnsignedRangeProofV1 {
    bit_commitments: FixedProofArray<CompressedPointV1, RANGE_BITS>,
    branch_challenges: FixedProofArray<CanonicalScalarV1, { RANGE_BITS * 2 }>,
    branch_responses: FixedProofArray<CanonicalScalarV1, { RANGE_BITS * 2 }>,
}
/// Proof that the hidden value in a Pedersen commitment is nonzero.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcCommittedNonZeroProofV1"
)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcCommittedNonZeroProofV1 {
    inverse_commitment: CompressedPointV1,
    commitment_announcement: CompressedPointV1,
    product_announcement: CompressedPointV1,
    inverse_response: CanonicalScalarV1,
    inverse_blinding_response: CanonicalScalarV1,
    product_blinding_response: CanonicalScalarV1,
}
/// Exact range proof for `[1, 2^32-1]`.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcPositiveRangeProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcPositiveRangeProofV1 {
    unsigned: PgcUnsignedRangeProofV1,
    nonzero: PgcCommittedNonZeroProofV1,
}
/// Hidden selection of one recipient commitment and its committed index.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcRecipientSelectionProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcRecipientSelectionProofV1 {
    value_commitment: CompressedPointV1,
    index_commitment: CompressedPointV1,
    branch_challenges: Vec<CanonicalScalarV1>,
    value_blinding_responses: Vec<CanonicalScalarV1>,
    index_blinding_responses: Vec<CanonicalScalarV1>,
    positive_range: PgcPositiveRangeProofV1,
}
/// Hidden selection of one zero-valued decoy and its committed index.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcDecoySelectionProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcDecoySelectionProofV1 {
    index_commitment: CompressedPointV1,
    branch_challenges: Vec<CanonicalScalarV1>,
    opening_responses: Vec<CanonicalScalarV1>,
    index_blinding_responses: Vec<CanonicalScalarV1>,
}
/// Hidden sender relation sharing one branch across ownership, transfer, and
/// post-balance equations.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::PgcSenderSelectionProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcSenderSelectionProofV1 {
    transfer_magnitude_commitment: CompressedPointV1,
    post_balance_commitment: CompressedPointV1,
    index_commitment: CompressedPointV1,
    branch_challenges: Vec<CanonicalScalarV1>,
    inverse_key_responses: Vec<CanonicalScalarV1>,
    post_balance_blinding_responses: Vec<CanonicalScalarV1>,
    transfer_blinding_responses: Vec<CanonicalScalarV1>,
    index_blinding_responses: Vec<CanonicalScalarV1>,
    transfer_range: PgcPositiveRangeProofV1,
    post_balance_range: PgcUnsignedRangeProofV1,
}
/// Canonical complete payment proof.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::payment::AnonymousPgcPaymentProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct AnonymousPgcPaymentProofV1 {
    version: u8,
    well_formed: Vec<PgcTransferWellFormedProofV1>,
    balance_conservation: PgcBalanceConservationProofV1,
    recipients: Vec<PgcRecipientSelectionProofV1>,
    recipient_distinctness: Vec<PgcCommittedNonZeroProofV1>,
    decoys: Vec<PgcDecoySelectionProofV1>,
    decoy_distinctness: Vec<PgcCommittedNonZeroProofV1>,
    sender: PgcSenderSelectionProofV1,
}
/// Fully verified all-or-nothing encrypted account effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAnonymousPgcPaymentEffectV1 {
    next_balance_ciphertexts: Vec<TwistedElGamalCiphertextV1>,
}
impl VerifiedAnonymousPgcPaymentEffectV1 {
    /// Ordered successor ciphertexts.  The runtime must commit this complete
    /// vector atomically with the statement's successor root/epoch.
    #[must_use]
    pub fn next_balance_ciphertexts(&self) -> &[TwistedElGamalCiphertextV1] {
        &self.next_balance_ciphertexts
    }
}
impl AnonymousPgcPaymentProofV1 {
    /// Encode this proof as canonical Norito.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(self)
    }
    /// Decode exactly one canonical proof and validate all statement-dependent
    /// dimensions before any curve equation is attempted.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, trailing, noncanonical, unknown-version,
    /// or incorrectly shaped proof bytes. Original enclosing/allocator refusals
    /// remain typed; fallible streaming comparison authenticates canonicality.
    pub fn decode_exact(
        bytes: &[u8],
        statement: &AnonymousPgcPaymentStatementV1<'_>,
    ) -> Result<Self, AnonymousPgcReadError> {
        if bytes.len() > MAX_PGC_PAYMENT_PROOF_BYTES_V1 {
            return Err(AnonymousPgcError::EncodingTooLarge {
                actual: bytes.len(),
                max: MAX_PGC_PAYMENT_PROOF_BYTES_V1,
            }
            .into());
        }
        let limits = payment_proof_decode_limits(statement, bytes.len())?;
        let proof = norito::core::classify_decode_attempt(|| {
            let proof = norito::codec::decode_exact_from_slice_with_limits::<Self>(bytes, limits)?;
            // Authenticate fixed-V1 framing against the original borrowed proof.
            // No duplicate proof Vec or infallible re-encoding may erase refusal.
            norito::codec::verify_exact_payload(&proof, bytes)?;
            Ok(proof)
        })?;
        proof.validate_shape(statement)?;
        Ok(proof)
    }
    fn validate_shape(
        &self,
        statement: &AnonymousPgcPaymentStatementV1<'_>,
    ) -> Result<(), AnonymousPgcError> {
        if self.version != PGC_PAYMENT_PROOF_VERSION_V1 {
            return Err(AnonymousPgcError::UnsupportedPaymentProofVersion {
                version: self.version,
            });
        }
        let n = statement.anonymity_set_size();
        let k = statement.recipient_count();
        let decoys = n - k - 1;
        if self.well_formed.len() != n
            || self.recipients.len() != k
            || self.recipient_distinctness.len() != pair_count(k)?
            || self.decoys.len() != decoys
            || self.decoy_distinctness.len() != pair_count(decoys)?
        {
            return Err(AnonymousPgcError::InvalidPaymentProofShape);
        }
        for proof in &self.well_formed {
            proof.validate()?;
        }
        self.balance_conservation.validate()?;
        for proof in &self.recipients {
            proof.validate(n)?;
        }
        for proof in &self.recipient_distinctness {
            proof.validate()?;
        }
        for proof in &self.decoys {
            proof.validate(n)?;
        }
        for proof in &self.decoy_distinctness {
            proof.validate()?;
        }
        self.sender.validate(n)?;
        Ok(())
    }
}
impl PgcTransferWellFormedProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        let _ = self.announcement_left.to_projective()?;
        let _ = self.announcement_right.to_projective()?;
        let _ = self.randomness_response.to_scalar()?;
        let _ = self.value_response.to_scalar()?;
        Ok(())
    }
}
impl PgcBalanceConservationProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        let _ = self.announcement.to_projective()?;
        let _ = self.randomness_response.to_scalar()?;
        Ok(())
    }
}
impl PgcUnsignedRangeProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        for point in self.bit_commitments.iter() {
            let _ = point.to_projective()?;
        }
        for scalar in self
            .branch_challenges
            .iter()
            .chain(self.branch_responses.iter())
        {
            let _ = scalar.to_scalar()?;
        }
        Ok(())
    }
}
impl PgcCommittedNonZeroProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        let _ = self.inverse_commitment.to_projective()?;
        let _ = self.commitment_announcement.to_projective()?;
        let _ = self.product_announcement.to_projective()?;
        let _ = self.inverse_response.to_scalar()?;
        let _ = self.inverse_blinding_response.to_scalar()?;
        let _ = self.product_blinding_response.to_scalar()?;
        Ok(())
    }
}
impl PgcPositiveRangeProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        self.unsigned.validate()?;
        self.nonzero.validate()
    }
}
impl PgcRecipientSelectionProofV1 {
    fn validate(&self, count: usize) -> Result<(), AnonymousPgcError> {
        let _ = self.value_commitment.to_projective()?;
        let _ = self.index_commitment.to_projective()?;
        if self.branch_challenges.len() != count
            || self.value_blinding_responses.len() != count
            || self.index_blinding_responses.len() != count
        {
            return Err(AnonymousPgcError::InvalidPaymentSelectionProofShape);
        }
        for scalar in self
            .branch_challenges
            .iter()
            .chain(&self.value_blinding_responses)
            .chain(&self.index_blinding_responses)
        {
            let _ = scalar.to_scalar()?;
        }
        self.positive_range.validate()
    }
}
impl PgcDecoySelectionProofV1 {
    fn validate(&self, count: usize) -> Result<(), AnonymousPgcError> {
        let _ = self.index_commitment.to_projective()?;
        if self.branch_challenges.len() != count
            || self.opening_responses.len() != count
            || self.index_blinding_responses.len() != count
        {
            return Err(AnonymousPgcError::InvalidPaymentSelectionProofShape);
        }
        for scalar in self
            .branch_challenges
            .iter()
            .chain(&self.opening_responses)
            .chain(&self.index_blinding_responses)
        {
            let _ = scalar.to_scalar()?;
        }
        Ok(())
    }
}
impl PgcSenderSelectionProofV1 {
    fn validate(&self, count: usize) -> Result<(), AnonymousPgcError> {
        let _ = self.transfer_magnitude_commitment.to_projective()?;
        let _ = self.post_balance_commitment.to_projective()?;
        let _ = self.index_commitment.to_projective()?;
        for vector in [
            &self.branch_challenges,
            &self.inverse_key_responses,
            &self.post_balance_blinding_responses,
            &self.transfer_blinding_responses,
            &self.index_blinding_responses,
        ] {
            if vector.len() != count {
                return Err(AnonymousPgcError::InvalidPaymentSelectionProofShape);
            }
            for scalar in vector {
                let _ = scalar.to_scalar()?;
            }
        }
        self.transfer_range.validate()?;
        self.post_balance_range.validate()
    }
}
/// Encrypt a signed transfer in the closed interval
/// `[-(2^32-1), 2^32-1]`.
///
/// # Errors
///
/// Rejects a value outside the closed payment domain, malformed public keys,
/// or a prohibited identity ciphertext component.
pub fn encrypt_signed_with_randomness(
    public_key: TwistedElGamalPublicKeyV1,
    value: i64,
    randomness: &SecretScalarV1,
) -> Result<TwistedElGamalCiphertextV1, AnonymousPgcError> {
    let value_scalar = payment_value_scalar(value)?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let public = public_key.point.to_projective()?;
    let randomness = randomness.expose_scalar();
    Ok(TwistedElGamalCiphertextV1 {
        left: CompressedPointV1::from_projective(public * randomness)?,
        right: CompressedPointV1::from_projective(
            parameters.g * randomness + parameters.h * value_scalar,
        )?,
    })
}
/// Derive all post-payment encrypted balances in canonical key order.
///
/// The returned vector is an all-or-nothing effect: verification callers must
/// apply no account mutation unless the complete proof has verified and this
/// function returned every successor ciphertext.
///
/// # Errors
///
/// Rejects a statement length mismatch, malformed ciphertext, or a successor
/// with an identity component (which has no admitted canonical account wire).
pub fn derive_atomic_ciphertext_updates(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
) -> Result<Vec<TwistedElGamalCiphertextV1>, AnonymousPgcError> {
    statement
        .current_balance_ciphertexts
        .iter()
        .copied()
        .zip(statement.transfer_ciphertexts.iter().copied())
        .map(|(current, transfer)| super::add_ciphertexts(current, transfer))
        .collect()
}
fn payment_value_scalar(value: i64) -> Result<Scalar, AnonymousPgcError> {
    let magnitude = value.unsigned_abs();
    if magnitude > u64::from(u32::MAX) {
        return Err(AnonymousPgcError::PaymentValueOutOfRange { value });
    }
    let scalar = Scalar::from(magnitude);
    Ok(if value < 0 { -scalar } else { scalar })
}
fn pair_count(count: usize) -> Result<usize, AnonymousPgcError> {
    count
        .checked_mul(count.saturating_sub(1))
        .and_then(|value| value.checked_div(2))
        .ok_or(AnonymousPgcError::InvalidPaymentProofShape)
}
fn memo_and_ledger_digest(
    public_keys: &[TwistedElGamalPublicKeyV1],
    transfers: &[TwistedElGamalCiphertextV1],
    current_balances: &[TwistedElGamalCiphertextV1],
    recipient_count: usize,
    pool_invariant: AnonymousPgcPoolInvariantV1,
) -> Result<[u8; 32], AnonymousPgcError> {
    let count = u32::try_from(public_keys.len())
        .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?;
    let recipients =
        u32::try_from(recipient_count).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?;
    let mut hash = Sha256::new();
    hash.update(PAYMENT_MEMO_DIGEST_DOMAIN_V1);
    hash.update(count.to_be_bytes());
    hash.update(recipients.to_be_bytes());
    hash.update(pool_invariant.total_supply().to_be_bytes());
    hash.update(pool_invariant.bootstrap_digest());
    hash.update(pool_invariant.bootstrap_proof_digest());
    for ((key, transfer), current) in public_keys.iter().zip(transfers).zip(current_balances) {
        hash.update(key.point.as_bytes());
        hash.update(transfer.left.as_bytes());
        hash.update(transfer.right.as_bytes());
        hash.update(current.left.as_bytes());
        hash.update(current.right.as_bytes());
    }
    Ok(hash.finalize().into())
}
fn payment_transcript(
    suite: &'static [u8],
    statement: &AnonymousPgcPaymentStatementV1<'_>,
) -> Result<TranscriptV1, AnonymousPgcError> {
    let mut transcript = TranscriptV1::new(suite, &statement.transcript_binding)?;
    transcript.append_message(
        b"anonymity_set_size",
        &u32::try_from(statement.anonymity_set_size())
            .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
            .to_be_bytes(),
    )?;
    transcript.append_message(
        b"recipient_count",
        &u32::try_from(statement.recipient_count())
            .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
            .to_be_bytes(),
    )?;
    transcript.append_message(
        b"total_supply",
        &statement.pool_invariant.total_supply().to_be_bytes(),
    )?;
    transcript.append_message(
        b"bootstrap_digest",
        &statement.pool_invariant.bootstrap_digest(),
    )?;
    transcript.append_message(
        b"bootstrap_proof_digest",
        &statement.pool_invariant.bootstrap_proof_digest(),
    )?;
    transcript.append_message(b"memo_and_ledger_digest", &statement.memo_and_ledger_digest)?;
    for (index, ((key, transfer), current)) in statement
        .public_keys
        .iter()
        .zip(statement.transfer_ciphertexts)
        .zip(statement.current_balance_ciphertexts)
        .enumerate()
    {
        transcript.append_message(
            b"entry_index",
            &u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"public_key", &key.point)?;
        transcript.append_point(b"transfer_left", &transfer.left)?;
        transcript.append_point(b"transfer_right", &transfer.right)?;
        transcript.append_point(b"current_left", &current.left)?;
        transcript.append_point(b"current_right", &current.right)?;
    }
    Ok(transcript)
}
fn append_role_and_ordinal(
    transcript: &mut TranscriptV1,
    role: &[u8],
    ordinal: u32,
) -> Result<(), AnonymousPgcError> {
    transcript.append_message(b"proof_role", role)?;
    transcript.append_message(b"proof_ordinal", &ordinal.to_be_bytes())?;
    Ok(())
}
fn sum_scalars(values: impl IntoIterator<Item = Scalar>) -> Scalar {
    values
        .into_iter()
        .fold(Scalar::ZERO, |sum, value| sum + value)
}
fn sum_points(values: impl IntoIterator<Item = ProjectivePoint>) -> ProjectivePoint {
    values
        .into_iter()
        .fold(ProjectivePoint::IDENTITY, |sum, value| sum + value)
}
fn prove_well_formed<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    index: usize,
    value: Scalar,
    randomness: Scalar,
    rng: &mut R,
) -> Result<PgcTransferWellFormedProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    let key = statement.public_keys[index].point.to_projective()?;
    let ciphertext = statement.transfer_ciphertexts[index];
    if key * randomness != ciphertext.left.to_projective()?
        || parameters.g * randomness + parameters.h * value != ciphertext.right.to_projective()?
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    for _ in 0..MAX_PROVER_RESTARTS {
        let randomness_mask = random_nonzero_scalar(rng)?;
        let value_mask = random_nonzero_scalar(rng)?;
        let Ok(announcement_left) = CompressedPointV1::from_projective(key * randomness_mask)
        else {
            continue;
        };
        let Ok(announcement_right) = CompressedPointV1::from_projective(
            parameters.g * randomness_mask + parameters.h * value_mask,
        ) else {
            continue;
        };
        let mut transcript = payment_transcript(WELL_FORMED_SUITE_V1, statement)?;
        append_role_and_ordinal(
            &mut transcript,
            b"transfer-well-formed",
            u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
        )?;
        transcript.append_point(b"announcement_left", &announcement_left)?;
        transcript.append_point(b"announcement_right", &announcement_right)?;
        let challenge = transcript
            .challenge_nonzero_scalar(b"challenge", 0)?
            .to_scalar()?;
        return Ok(PgcTransferWellFormedProofV1 {
            announcement_left,
            announcement_right,
            randomness_response: CanonicalScalarV1::from_scalar(
                randomness_mask + challenge * randomness,
            ),
            value_response: CanonicalScalarV1::from_scalar(value_mask + challenge * value),
        });
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_well_formed(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    index: usize,
    proof: &PgcTransferWellFormedProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let mut transcript = payment_transcript(WELL_FORMED_SUITE_V1, statement)?;
    append_role_and_ordinal(
        &mut transcript,
        b"transfer-well-formed",
        u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
    )?;
    transcript.append_point(b"announcement_left", &proof.announcement_left)?;
    transcript.append_point(b"announcement_right", &proof.announcement_right)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    let randomness_response = proof.randomness_response.to_scalar()?;
    let value_response = proof.value_response.to_scalar()?;
    let key = statement.public_keys[index].point.to_projective()?;
    let ciphertext = statement.transfer_ciphertexts[index];
    if key * randomness_response
        != proof.announcement_left.to_projective()? + ciphertext.left.to_projective()? * challenge
        || parameters.g * randomness_response + parameters.h * value_response
            != proof.announcement_right.to_projective()?
                + ciphertext.right.to_projective()? * challenge
    {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    Ok(())
}
fn prove_balance_conservation<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    randomness: Scalar,
    rng: &mut R,
) -> Result<PgcBalanceConservationProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    let aggregate = sum_points(
        statement
            .transfer_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.right.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    if aggregate != parameters.g * randomness {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    // Scalar and challenge rejection sampling already enforce their fixed bounds.
    let mask = random_nonzero_scalar(rng)?;
    let announcement = CompressedPointV1::from_projective(parameters.g * mask)?;
    let mut transcript = payment_transcript(BALANCE_SUITE_V1, statement)?;
    transcript.append_point(b"announcement", &announcement)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    Ok(PgcBalanceConservationProofV1 {
        announcement,
        randomness_response: CanonicalScalarV1::from_scalar(mask + challenge * randomness),
    })
}
fn verify_balance_conservation(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    proof: &PgcBalanceConservationProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let aggregate = sum_points(
        statement
            .transfer_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.right.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut transcript = payment_transcript(BALANCE_SUITE_V1, statement)?;
    transcript.append_point(b"announcement", &proof.announcement)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    if parameters.g * proof.randomness_response.to_scalar()?
        != proof.announcement.to_projective()? + aggregate * challenge
    {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    Ok(())
}
fn prove_unsigned_range<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    value: u32,
    blinding: Scalar,
    rng: &mut R,
) -> Result<PgcUnsignedRangeProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    if commitment != parameters.h * Scalar::from(u64::from(value)) + parameters.g * blinding {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    for _ in 0..MAX_PROVER_RESTARTS {
        let mut bit_blindings = Vec::with_capacity(RANGE_BITS);
        let mut partial_blinding = Scalar::ZERO;
        for _ in 0..RANGE_BITS - 1 {
            let bit_blinding = random_nonzero_scalar(rng)?;
            partial_blinding += bit_blinding;
            bit_blindings.push(bit_blinding);
        }
        bit_blindings.push(blinding - partial_blinding);
        let mut bit_commitments = Vec::with_capacity(RANGE_BITS);
        let mut failed = false;
        for (bit, bit_blinding) in bit_blindings.iter().copied().enumerate() {
            let bit_value = u64::from((value >> bit) & 1) << bit;
            match CompressedPointV1::from_projective(
                parameters.h * Scalar::from(bit_value) + parameters.g * bit_blinding,
            ) {
                Ok(point) => bit_commitments.push(point),
                Err(P256EngineError::IdentityPoint) => {
                    failed = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if failed {
            continue;
        }
        let summed_commitments = sum_points(
            bit_commitments
                .iter()
                .map(|point| point.to_projective())
                .collect::<Result<Vec<_>, _>>()?,
        );
        if summed_commitments != commitment {
            return Err(AnonymousPgcError::InvalidPaymentWitness);
        }
        let mut challenges = vec![Scalar::ZERO; RANGE_BITS * 2];
        let mut responses = vec![Scalar::ZERO; RANGE_BITS * 2];
        let mut real_masks = vec![Scalar::ZERO; RANGE_BITS];
        let mut announcements = Vec::with_capacity(RANGE_BITS * 2);
        for bit in 0..RANGE_BITS {
            let selected = usize::from(((value >> bit) & 1) != 0);
            let simulated = 1 - selected;
            let real_mask = random_nonzero_scalar(rng)?;
            real_masks[bit] = real_mask;
            challenges[bit * 2 + simulated] = random_nonzero_scalar(rng)?;
            responses[bit * 2 + simulated] = random_nonzero_scalar(rng)?;
            let bit_commitment = bit_commitments[bit].to_projective()?;
            let weight = parameters.h * Scalar::from(1_u64 << bit);
            for branch in 0..2 {
                let announcement = if branch == selected {
                    parameters.g * real_mask
                } else {
                    let branch_statement = if branch == 0 {
                        bit_commitment
                    } else {
                        bit_commitment - weight
                    };
                    parameters.g * responses[bit * 2 + branch]
                        - branch_statement * challenges[bit * 2 + branch]
                };
                let Ok(announcement) = CompressedPointV1::from_projective(announcement) else {
                    failed = true;
                    break;
                };
                announcements.push(announcement);
            }
            if failed {
                break;
            }
        }
        if failed {
            continue;
        }
        let mut transcript = payment_transcript(RANGE_SUITE_V1, statement)?;
        append_role_and_ordinal(&mut transcript, role, ordinal)?;
        transcript.append_point(b"value_commitment", &commitment_encoded)?;
        for (bit, point) in bit_commitments.iter().enumerate() {
            transcript.append_message(
                b"bit_index",
                &u32::try_from(bit)
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                    .to_be_bytes(),
            )?;
            transcript.append_point(b"bit_commitment", point)?;
            transcript.append_point(b"branch_zero_announcement", &announcements[bit * 2])?;
            transcript.append_point(b"branch_one_announcement", &announcements[bit * 2 + 1])?;
        }
        for bit in 0..RANGE_BITS {
            let selected = usize::from(((value >> bit) & 1) != 0);
            let simulated = 1 - selected;
            let challenge = transcript
                .challenge_nonzero_scalar(
                    b"bit_challenge",
                    u32::try_from(bit).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
                )?
                .to_scalar()?;
            challenges[bit * 2 + selected] = challenge - challenges[bit * 2 + simulated];
            responses[bit * 2 + selected] =
                real_masks[bit] + challenges[bit * 2 + selected] * bit_blindings[bit];
        }
        let proof = PgcUnsignedRangeProofV1 {
            bit_commitments: bit_commitments
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidPaymentRangeProofShape)?,
            branch_challenges: challenges
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidPaymentRangeProofShape)?,
            branch_responses: responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidPaymentRangeProofShape)?,
        };
        proof.validate()?;
        return Ok(proof);
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_unsigned_range(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    proof: &PgcUnsignedRangeProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    let summed_commitments = sum_points(
        proof
            .bit_commitments
            .iter()
            .map(|point| point.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    if summed_commitments != commitment {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    let mut announcements = Vec::with_capacity(RANGE_BITS * 2);
    for bit in 0..RANGE_BITS {
        let bit_commitment = proof.bit_commitments[bit].to_projective()?;
        let weight = parameters.h * Scalar::from(1_u64 << bit);
        for branch in 0..2 {
            let branch_statement = if branch == 0 {
                bit_commitment
            } else {
                bit_commitment - weight
            };
            let response = proof.branch_responses[bit * 2 + branch].to_scalar()?;
            let challenge = proof.branch_challenges[bit * 2 + branch].to_scalar()?;
            announcements.push(CompressedPointV1::from_projective(
                parameters.g * response - branch_statement * challenge,
            )?);
        }
    }
    let mut transcript = payment_transcript(RANGE_SUITE_V1, statement)?;
    append_role_and_ordinal(&mut transcript, role, ordinal)?;
    transcript.append_point(b"value_commitment", &commitment_encoded)?;
    for (bit, point) in proof.bit_commitments.iter().enumerate() {
        transcript.append_message(
            b"bit_index",
            &u32::try_from(bit)
                .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"bit_commitment", point)?;
        transcript.append_point(b"branch_zero_announcement", &announcements[bit * 2])?;
        transcript.append_point(b"branch_one_announcement", &announcements[bit * 2 + 1])?;
    }
    for bit in 0..RANGE_BITS {
        let challenge = transcript
            .challenge_nonzero_scalar(
                b"bit_challenge",
                u32::try_from(bit).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            )?
            .to_scalar()?;
        let supplied = proof.branch_challenges[bit * 2].to_scalar()?
            + proof.branch_challenges[bit * 2 + 1].to_scalar()?;
        if supplied != challenge {
            return Err(AnonymousPgcError::PaymentProofEquationFailed);
        }
    }
    Ok(())
}
fn prove_committed_nonzero<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    value: Scalar,
    blinding: Scalar,
    rng: &mut R,
) -> Result<PgcCommittedNonZeroProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if bool::from(value.is_zero()) {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let parameters = AnonymousPgcParametersV1::get()?;
    if commitment != parameters.h * value + parameters.g * blinding {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    let inverse =
        Option::<Scalar>::from(value.invert()).ok_or(AnonymousPgcError::InvalidPaymentWitness)?;
    for _ in 0..MAX_PROVER_RESTARTS {
        let inverse_blinding = random_nonzero_scalar(rng)?;
        let inverse_commitment_point = parameters.h * inverse + parameters.g * inverse_blinding;
        let Ok(inverse_commitment) = CompressedPointV1::from_projective(inverse_commitment_point)
        else {
            continue;
        };
        let product_blinding = blinding * inverse;
        let inverse_mask = random_nonzero_scalar(rng)?;
        let inverse_blinding_mask = random_nonzero_scalar(rng)?;
        let product_blinding_mask = random_nonzero_scalar(rng)?;
        let Ok(commitment_announcement) = CompressedPointV1::from_projective(
            parameters.h * inverse_mask + parameters.g * inverse_blinding_mask,
        ) else {
            continue;
        };
        let Ok(product_announcement) = CompressedPointV1::from_projective(
            commitment * inverse_mask - parameters.g * product_blinding_mask,
        ) else {
            continue;
        };
        let mut transcript = payment_transcript(NONZERO_SUITE_V1, statement)?;
        append_role_and_ordinal(&mut transcript, role, ordinal)?;
        transcript.append_point(b"value_commitment", &commitment_encoded)?;
        transcript.append_point(b"inverse_commitment", &inverse_commitment)?;
        transcript.append_point(b"commitment_announcement", &commitment_announcement)?;
        transcript.append_point(b"product_announcement", &product_announcement)?;
        let challenge = transcript
            .challenge_nonzero_scalar(b"challenge", 0)?
            .to_scalar()?;
        return Ok(PgcCommittedNonZeroProofV1 {
            inverse_commitment,
            commitment_announcement,
            product_announcement,
            inverse_response: CanonicalScalarV1::from_scalar(inverse_mask + challenge * inverse),
            inverse_blinding_response: CanonicalScalarV1::from_scalar(
                inverse_blinding_mask + challenge * inverse_blinding,
            ),
            product_blinding_response: CanonicalScalarV1::from_scalar(
                product_blinding_mask + challenge * product_blinding,
            ),
        });
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_committed_nonzero(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    proof: &PgcCommittedNonZeroProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    let mut transcript = payment_transcript(NONZERO_SUITE_V1, statement)?;
    append_role_and_ordinal(&mut transcript, role, ordinal)?;
    transcript.append_point(b"value_commitment", &commitment_encoded)?;
    transcript.append_point(b"inverse_commitment", &proof.inverse_commitment)?;
    transcript.append_point(b"commitment_announcement", &proof.commitment_announcement)?;
    transcript.append_point(b"product_announcement", &proof.product_announcement)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    let inverse_response = proof.inverse_response.to_scalar()?;
    let inverse_blinding_response = proof.inverse_blinding_response.to_scalar()?;
    let product_blinding_response = proof.product_blinding_response.to_scalar()?;
    if parameters.h * inverse_response + parameters.g * inverse_blinding_response
        != proof.commitment_announcement.to_projective()?
            + proof.inverse_commitment.to_projective()? * challenge
        || commitment * inverse_response - parameters.g * product_blinding_response
            != proof.product_announcement.to_projective()? + parameters.h * challenge
    {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    Ok(())
}
fn prove_positive_range<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    value: u32,
    blinding: Scalar,
    rng: &mut R,
) -> Result<PgcPositiveRangeProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if value == 0 {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    Ok(PgcPositiveRangeProofV1 {
        unsigned: prove_unsigned_range(statement, role, ordinal, commitment, value, blinding, rng)?,
        nonzero: prove_committed_nonzero(
            statement,
            role,
            ordinal,
            commitment,
            Scalar::from(u64::from(value)),
            blinding,
            rng,
        )?,
    })
}
fn verify_positive_range(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    ordinal: u32,
    commitment: ProjectivePoint,
    proof: &PgcPositiveRangeProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    verify_unsigned_range(statement, role, ordinal, commitment, &proof.unsigned)?;
    verify_committed_nonzero(statement, role, ordinal, commitment, &proof.nonzero)
}
fn recipient_selection_announcements(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    value_commitment: ProjectivePoint,
    index_commitment: ProjectivePoint,
    challenges: &[Scalar],
    value_responses: &[Scalar],
    index_responses: &[Scalar],
) -> Result<Vec<(CompressedPointV1, CompressedPointV1)>, AnonymousPgcError> {
    let parameters = AnonymousPgcParametersV1::get()?;
    let mut announcements = Vec::with_capacity(statement.anonymity_set_size());
    for index in 0..statement.anonymity_set_size() {
        let value_statement = value_commitment
            - statement.transfer_ciphertexts[index]
                .right
                .to_projective()?;
        let index_statement = index_commitment
            - parameters.h
                * Scalar::from(
                    u64::try_from(index)
                        .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
                );
        announcements.push((
            CompressedPointV1::from_projective(
                parameters.g * value_responses[index] - value_statement * challenges[index],
            )?,
            CompressedPointV1::from_projective(
                parameters.g * index_responses[index] - index_statement * challenges[index],
            )?,
        ));
    }
    Ok(announcements)
}
fn recipient_selection_challenge(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    value_commitment: &CompressedPointV1,
    index_commitment: &CompressedPointV1,
    announcements: &[(CompressedPointV1, CompressedPointV1)],
) -> Result<Scalar, AnonymousPgcError> {
    let mut transcript = payment_transcript(RECIPIENT_SELECTION_SUITE_V1, statement)?;
    append_role_and_ordinal(&mut transcript, b"recipient-selection", ordinal)?;
    transcript.append_point(b"value_commitment", value_commitment)?;
    transcript.append_point(b"index_commitment", index_commitment)?;
    for (index, (value_announcement, index_announcement)) in announcements.iter().enumerate() {
        transcript.append_message(
            b"branch_index",
            &u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"value_announcement", value_announcement)?;
        transcript.append_point(b"index_announcement", index_announcement)?;
    }
    Ok(transcript
        .challenge_nonzero_scalar(b"selection_challenge", 0)?
        .to_scalar()?)
}
fn prove_recipient_selection<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    selected_index: usize,
    value: u32,
    transfer_randomness: Scalar,
    rng: &mut R,
) -> Result<(PgcRecipientSelectionProofV1, Scalar), AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if selected_index >= statement.anonymity_set_size() || value == 0 {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let parameters = AnonymousPgcParametersV1::get()?;
    if statement.transfer_ciphertexts[selected_index]
        .right
        .to_projective()?
        != parameters.g * transfer_randomness + parameters.h * Scalar::from(u64::from(value))
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    for _ in 0..MAX_PROVER_RESTARTS {
        let rerandomizer = random_nonzero_scalar(rng)?;
        let index_blinding = random_nonzero_scalar(rng)?;
        let value_commitment_point = statement.transfer_ciphertexts[selected_index]
            .right
            .to_projective()?
            + parameters.g * rerandomizer;
        let index_commitment_point = parameters.h
            * Scalar::from(
                u64::try_from(selected_index)
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            )
            + parameters.g * index_blinding;
        let Ok(value_commitment) = CompressedPointV1::from_projective(value_commitment_point)
        else {
            continue;
        };
        let Ok(index_commitment) = CompressedPointV1::from_projective(index_commitment_point)
        else {
            continue;
        };
        let n = statement.anonymity_set_size();
        let mut challenges = vec![Scalar::ZERO; n];
        let mut value_responses = vec![Scalar::ZERO; n];
        let mut index_responses = vec![Scalar::ZERO; n];
        for index in 0..n {
            if index != selected_index {
                challenges[index] = random_nonzero_scalar(rng)?;
                value_responses[index] = random_nonzero_scalar(rng)?;
                index_responses[index] = random_nonzero_scalar(rng)?;
            }
        }
        let value_mask = random_nonzero_scalar(rng)?;
        let index_mask = random_nonzero_scalar(rng)?;
        value_responses[selected_index] = value_mask;
        index_responses[selected_index] = index_mask;
        let Ok(announcements) = recipient_selection_announcements(
            statement,
            value_commitment_point,
            index_commitment_point,
            &challenges,
            &value_responses,
            &index_responses,
        ) else {
            continue;
        };
        let global_challenge = recipient_selection_challenge(
            statement,
            ordinal,
            &value_commitment,
            &index_commitment,
            &announcements,
        )?;
        let simulated_sum = sum_scalars(
            challenges
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, challenge)| (index != selected_index).then_some(challenge)),
        );
        challenges[selected_index] = global_challenge - simulated_sum;
        value_responses[selected_index] = value_mask + challenges[selected_index] * rerandomizer;
        index_responses[selected_index] = index_mask + challenges[selected_index] * index_blinding;
        let value_blinding = transfer_randomness + rerandomizer;
        let positive_range = prove_positive_range(
            statement,
            b"recipient-value",
            ordinal,
            value_commitment_point,
            value,
            value_blinding,
            rng,
        )?;
        let proof = PgcRecipientSelectionProofV1 {
            value_commitment,
            index_commitment,
            branch_challenges: challenges
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            value_blinding_responses: value_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            index_blinding_responses: index_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            positive_range,
        };
        proof.validate(n)?;
        return Ok((proof, index_blinding));
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_recipient_selection(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    proof: &PgcRecipientSelectionProofV1,
) -> Result<(), AnonymousPgcError> {
    let n = statement.anonymity_set_size();
    proof.validate(n)?;
    let challenges = proof
        .branch_challenges
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let value_responses = proof
        .value_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let index_responses = proof
        .index_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let value_commitment = proof.value_commitment.to_projective()?;
    let index_commitment = proof.index_commitment.to_projective()?;
    let announcements = recipient_selection_announcements(
        statement,
        value_commitment,
        index_commitment,
        &challenges,
        &value_responses,
        &index_responses,
    )?;
    let global_challenge = recipient_selection_challenge(
        statement,
        ordinal,
        &proof.value_commitment,
        &proof.index_commitment,
        &announcements,
    )?;
    if sum_scalars(challenges) != global_challenge {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    verify_positive_range(
        statement,
        b"recipient-value",
        ordinal,
        value_commitment,
        &proof.positive_range,
    )
}
fn decoy_selection_announcements(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    index_commitment: ProjectivePoint,
    challenges: &[Scalar],
    opening_responses: &[Scalar],
    index_responses: &[Scalar],
) -> Result<Vec<(CompressedPointV1, CompressedPointV1)>, AnonymousPgcError> {
    let parameters = AnonymousPgcParametersV1::get()?;
    let mut announcements = Vec::with_capacity(statement.anonymity_set_size());
    for index in 0..statement.anonymity_set_size() {
        let zero_statement = statement.transfer_ciphertexts[index]
            .right
            .to_projective()?;
        let index_statement = index_commitment
            - parameters.h
                * Scalar::from(
                    u64::try_from(index)
                        .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
                );
        announcements.push((
            CompressedPointV1::from_projective(
                parameters.g * opening_responses[index] - zero_statement * challenges[index],
            )?,
            CompressedPointV1::from_projective(
                parameters.g * index_responses[index] - index_statement * challenges[index],
            )?,
        ));
    }
    Ok(announcements)
}
fn decoy_selection_challenge(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    index_commitment: &CompressedPointV1,
    announcements: &[(CompressedPointV1, CompressedPointV1)],
) -> Result<Scalar, AnonymousPgcError> {
    let mut transcript = payment_transcript(DECOY_SELECTION_SUITE_V1, statement)?;
    append_role_and_ordinal(&mut transcript, b"decoy-selection", ordinal)?;
    transcript.append_point(b"index_commitment", index_commitment)?;
    for (index, (opening_announcement, index_announcement)) in announcements.iter().enumerate() {
        transcript.append_message(
            b"branch_index",
            &u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"opening_announcement", opening_announcement)?;
        transcript.append_point(b"index_announcement", index_announcement)?;
    }
    Ok(transcript
        .challenge_nonzero_scalar(b"selection_challenge", 0)?
        .to_scalar()?)
}
fn prove_decoy_selection<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    selected_index: usize,
    transfer_randomness: Scalar,
    rng: &mut R,
) -> Result<(PgcDecoySelectionProofV1, Scalar), AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if selected_index >= statement.anonymity_set_size() {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let parameters = AnonymousPgcParametersV1::get()?;
    if statement.transfer_ciphertexts[selected_index]
        .right
        .to_projective()?
        != parameters.g * transfer_randomness
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    for _ in 0..MAX_PROVER_RESTARTS {
        let index_blinding = random_nonzero_scalar(rng)?;
        let index_commitment_point = parameters.h
            * Scalar::from(
                u64::try_from(selected_index)
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            )
            + parameters.g * index_blinding;
        let Ok(index_commitment) = CompressedPointV1::from_projective(index_commitment_point)
        else {
            continue;
        };
        let n = statement.anonymity_set_size();
        let mut challenges = vec![Scalar::ZERO; n];
        let mut opening_responses = vec![Scalar::ZERO; n];
        let mut index_responses = vec![Scalar::ZERO; n];
        for index in 0..n {
            if index != selected_index {
                challenges[index] = random_nonzero_scalar(rng)?;
                opening_responses[index] = random_nonzero_scalar(rng)?;
                index_responses[index] = random_nonzero_scalar(rng)?;
            }
        }
        let opening_mask = random_nonzero_scalar(rng)?;
        let index_mask = random_nonzero_scalar(rng)?;
        opening_responses[selected_index] = opening_mask;
        index_responses[selected_index] = index_mask;
        let Ok(announcements) = decoy_selection_announcements(
            statement,
            index_commitment_point,
            &challenges,
            &opening_responses,
            &index_responses,
        ) else {
            continue;
        };
        let global_challenge =
            decoy_selection_challenge(statement, ordinal, &index_commitment, &announcements)?;
        let simulated_sum = sum_scalars(
            challenges
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, challenge)| (index != selected_index).then_some(challenge)),
        );
        challenges[selected_index] = global_challenge - simulated_sum;
        opening_responses[selected_index] =
            opening_mask + challenges[selected_index] * transfer_randomness;
        index_responses[selected_index] = index_mask + challenges[selected_index] * index_blinding;
        let proof = PgcDecoySelectionProofV1 {
            index_commitment,
            branch_challenges: challenges
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            opening_responses: opening_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            index_blinding_responses: index_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
        };
        proof.validate(n)?;
        return Ok((proof, index_blinding));
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_decoy_selection(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    ordinal: u32,
    proof: &PgcDecoySelectionProofV1,
) -> Result<(), AnonymousPgcError> {
    let n = statement.anonymity_set_size();
    proof.validate(n)?;
    let challenges = proof
        .branch_challenges
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let opening_responses = proof
        .opening_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let index_responses = proof
        .index_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let index_commitment = proof.index_commitment.to_projective()?;
    let announcements = decoy_selection_announcements(
        statement,
        index_commitment,
        &challenges,
        &opening_responses,
        &index_responses,
    )?;
    let global_challenge =
        decoy_selection_challenge(statement, ordinal, &proof.index_commitment, &announcements)?;
    if sum_scalars(challenges) != global_challenge {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    Ok(())
}
fn prove_distinct_indices<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    index_commitments: &[CompressedPointV1],
    indices: &[usize],
    blindings: &[Scalar],
    rng: &mut R,
) -> Result<Vec<PgcCommittedNonZeroProofV1>, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if index_commitments.len() != indices.len() || indices.len() != blindings.len() {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let mut proofs = Vec::with_capacity(pair_count(indices.len())?);
    let mut ordinal = 0_u32;
    for right in 1..indices.len() {
        for left in 0..right {
            if indices[left] == indices[right] {
                return Err(AnonymousPgcError::InvalidPaymentWitness);
            }
            let commitment = index_commitments[left].to_projective()?
                - index_commitments[right].to_projective()?;
            let value = Scalar::from(
                u64::try_from(indices[left])
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            ) - Scalar::from(
                u64::try_from(indices[right])
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            );
            let blinding = blindings[left] - blindings[right];
            proofs.push(prove_committed_nonzero(
                statement, role, ordinal, commitment, value, blinding, rng,
            )?);
            ordinal = ordinal
                .checked_add(1)
                .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
        }
    }
    Ok(proofs)
}
fn verify_distinct_indices(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    role: &[u8],
    index_commitments: &[CompressedPointV1],
    proofs: &[PgcCommittedNonZeroProofV1],
) -> Result<(), AnonymousPgcError> {
    if proofs.len() != pair_count(index_commitments.len())? {
        return Err(AnonymousPgcError::InvalidPaymentProofShape);
    }
    let mut ordinal = 0_u32;
    let mut proof_index = 0;
    for right in 1..index_commitments.len() {
        for left in 0..right {
            let commitment = index_commitments[left].to_projective()?
                - index_commitments[right].to_projective()?;
            verify_committed_nonzero(statement, role, ordinal, commitment, &proofs[proof_index])?;
            ordinal = ordinal
                .checked_add(1)
                .ok_or(AnonymousPgcError::InvalidPaymentProofShape)?;
            proof_index += 1;
        }
    }
    Ok(())
}
type SenderAnnouncementsV1 = (
    CompressedPointV1,
    CompressedPointV1,
    CompressedPointV1,
    CompressedPointV1,
);
struct SenderPublicCommitmentsV1 {
    transfer_magnitude: ProjectivePoint,
    post_balance: ProjectivePoint,
    index: ProjectivePoint,
}
struct SenderResponseSlicesV1<'a> {
    challenges: &'a [Scalar],
    inverse_key: &'a [Scalar],
    post_balance_blinding: &'a [Scalar],
    transfer_blinding: &'a [Scalar],
    index_blinding: &'a [Scalar],
}
fn sender_selection_announcements(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    commitments: &SenderPublicCommitmentsV1,
    responses: &SenderResponseSlicesV1<'_>,
) -> Result<Vec<SenderAnnouncementsV1>, AnonymousPgcError> {
    let parameters = AnonymousPgcParametersV1::get()?;
    let mut announcements = Vec::with_capacity(statement.anonymity_set_size());
    for index in 0..statement.anonymity_set_size() {
        let current = statement.current_balance_ciphertexts[index];
        let transfer = statement.transfer_ciphertexts[index];
        let post_left = current.left.to_projective()? + transfer.left.to_projective()?;
        let post_right = current.right.to_projective()? + transfer.right.to_projective()?;
        let challenge = responses.challenges[index];
        let index_statement = commitments.index
            - parameters.h
                * Scalar::from(
                    u64::try_from(index)
                        .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
                );
        announcements.push((
            CompressedPointV1::from_projective(
                statement.public_keys[index].point.to_projective()? * responses.inverse_key[index]
                    - parameters.g * challenge,
            )?,
            CompressedPointV1::from_projective(
                post_left * responses.inverse_key[index]
                    - parameters.g * responses.post_balance_blinding[index]
                    - (post_right - commitments.post_balance) * challenge,
            )?,
            CompressedPointV1::from_projective(
                parameters.g * responses.transfer_blinding[index]
                    - (commitments.transfer_magnitude + transfer.right.to_projective()?)
                        * challenge,
            )?,
            CompressedPointV1::from_projective(
                parameters.g * responses.index_blinding[index] - index_statement * challenge,
            )?,
        ));
    }
    Ok(announcements)
}
fn sender_selection_challenge(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    transfer_magnitude_commitment: &CompressedPointV1,
    post_balance_commitment: &CompressedPointV1,
    index_commitment: &CompressedPointV1,
    announcements: &[SenderAnnouncementsV1],
) -> Result<Scalar, AnonymousPgcError> {
    let mut transcript = payment_transcript(SENDER_SELECTION_SUITE_V1, statement)?;
    append_role_and_ordinal(&mut transcript, b"sender-selection", 0)?;
    transcript.append_point(
        b"transfer_magnitude_commitment",
        transfer_magnitude_commitment,
    )?;
    transcript.append_point(b"post_balance_commitment", post_balance_commitment)?;
    transcript.append_point(b"index_commitment", index_commitment)?;
    for (
        index,
        (key_announcement, post_balance_announcement, transfer_announcement, index_announcement),
    ) in announcements.iter().enumerate()
    {
        transcript.append_message(
            b"branch_index",
            &u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"key_announcement", key_announcement)?;
        transcript.append_point(b"post_balance_announcement", post_balance_announcement)?;
        transcript.append_point(b"transfer_announcement", transfer_announcement)?;
        transcript.append_point(b"index_announcement", index_announcement)?;
    }
    Ok(transcript
        .challenge_nonzero_scalar(b"selection_challenge", 0)?
        .to_scalar()?)
}
fn prove_sender_selection<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    sender_index: usize,
    sender_secret: &SecretScalarV1,
    transfer_randomness: Scalar,
    transfer_magnitude: u32,
    post_balance: u32,
    rng: &mut R,
) -> Result<PgcSenderSelectionProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    if sender_index >= statement.anonymity_set_size() || transfer_magnitude == 0 {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let parameters = AnonymousPgcParametersV1::get()?;
    let inverse_key = Option::<Scalar>::from(sender_secret.expose_scalar().invert())
        .ok_or(AnonymousPgcError::InvalidPaymentWitness)?;
    if statement.public_keys[sender_index].point.to_projective()? * inverse_key != parameters.g {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let sender_transfer = statement.transfer_ciphertexts[sender_index];
    if sender_transfer.right.to_projective()?
        != parameters.g * transfer_randomness
            - parameters.h * Scalar::from(u64::from(transfer_magnitude))
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let current = statement.current_balance_ciphertexts[sender_index];
    let post_left = current.left.to_projective()? + sender_transfer.left.to_projective()?;
    let post_right = current.right.to_projective()? + sender_transfer.right.to_projective()?;
    if post_right - post_left * inverse_key != parameters.h * Scalar::from(u64::from(post_balance))
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    for _ in 0..MAX_PROVER_RESTARTS {
        let transfer_commitment_blinding = random_nonzero_scalar(rng)?;
        let post_balance_blinding = random_nonzero_scalar(rng)?;
        let index_blinding = random_nonzero_scalar(rng)?;
        let transfer_magnitude_point = parameters.h * Scalar::from(u64::from(transfer_magnitude))
            + parameters.g * transfer_commitment_blinding;
        let post_balance_point = parameters.h * Scalar::from(u64::from(post_balance))
            + parameters.g * post_balance_blinding;
        let index_point = parameters.h
            * Scalar::from(
                u64::try_from(sender_index)
                    .map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            )
            + parameters.g * index_blinding;
        let Ok(transfer_magnitude_commitment) =
            CompressedPointV1::from_projective(transfer_magnitude_point)
        else {
            continue;
        };
        let Ok(post_balance_commitment) = CompressedPointV1::from_projective(post_balance_point)
        else {
            continue;
        };
        let Ok(index_commitment) = CompressedPointV1::from_projective(index_point) else {
            continue;
        };
        let n = statement.anonymity_set_size();
        let mut challenges = vec![Scalar::ZERO; n];
        let mut inverse_key_responses = vec![Scalar::ZERO; n];
        let mut post_balance_responses = vec![Scalar::ZERO; n];
        let mut transfer_responses = vec![Scalar::ZERO; n];
        let mut index_responses = vec![Scalar::ZERO; n];
        for index in 0..n {
            if index != sender_index {
                challenges[index] = random_nonzero_scalar(rng)?;
                inverse_key_responses[index] = random_nonzero_scalar(rng)?;
                post_balance_responses[index] = random_nonzero_scalar(rng)?;
                transfer_responses[index] = random_nonzero_scalar(rng)?;
                index_responses[index] = random_nonzero_scalar(rng)?;
            }
        }
        let inverse_key_mask = random_nonzero_scalar(rng)?;
        let post_balance_mask = random_nonzero_scalar(rng)?;
        let transfer_mask = random_nonzero_scalar(rng)?;
        let index_mask = random_nonzero_scalar(rng)?;
        inverse_key_responses[sender_index] = inverse_key_mask;
        post_balance_responses[sender_index] = post_balance_mask;
        transfer_responses[sender_index] = transfer_mask;
        index_responses[sender_index] = index_mask;
        let public_commitments = SenderPublicCommitmentsV1 {
            transfer_magnitude: transfer_magnitude_point,
            post_balance: post_balance_point,
            index: index_point,
        };
        let Ok(announcements) = sender_selection_announcements(
            statement,
            &public_commitments,
            &SenderResponseSlicesV1 {
                challenges: &challenges,
                inverse_key: &inverse_key_responses,
                post_balance_blinding: &post_balance_responses,
                transfer_blinding: &transfer_responses,
                index_blinding: &index_responses,
            },
        ) else {
            continue;
        };
        let global_challenge = sender_selection_challenge(
            statement,
            &transfer_magnitude_commitment,
            &post_balance_commitment,
            &index_commitment,
            &announcements,
        )?;
        let simulated_sum = sum_scalars(
            challenges
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, challenge)| (index != sender_index).then_some(challenge)),
        );
        challenges[sender_index] = global_challenge - simulated_sum;
        let sender_challenge = challenges[sender_index];
        inverse_key_responses[sender_index] = inverse_key_mask + sender_challenge * inverse_key;
        post_balance_responses[sender_index] =
            post_balance_mask + sender_challenge * post_balance_blinding;
        transfer_responses[sender_index] =
            transfer_mask + sender_challenge * (transfer_commitment_blinding + transfer_randomness);
        index_responses[sender_index] = index_mask + sender_challenge * index_blinding;
        let transfer_range = prove_positive_range(
            statement,
            b"sender-transfer-magnitude",
            0,
            transfer_magnitude_point,
            transfer_magnitude,
            transfer_commitment_blinding,
            rng,
        )?;
        let post_balance_range = prove_unsigned_range(
            statement,
            b"sender-post-balance",
            0,
            post_balance_point,
            post_balance,
            post_balance_blinding,
            rng,
        )?;
        let proof = PgcSenderSelectionProofV1 {
            transfer_magnitude_commitment,
            post_balance_commitment,
            index_commitment,
            branch_challenges: challenges
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            inverse_key_responses: inverse_key_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            post_balance_blinding_responses: post_balance_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            transfer_blinding_responses: transfer_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            index_blinding_responses: index_responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect(),
            transfer_range,
            post_balance_range,
        };
        proof.validate(n)?;
        return Ok(proof);
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_sender_selection(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    proof: &PgcSenderSelectionProofV1,
) -> Result<(), AnonymousPgcError> {
    let n = statement.anonymity_set_size();
    proof.validate(n)?;
    let challenges = proof
        .branch_challenges
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let inverse_key_responses = proof
        .inverse_key_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let post_balance_responses = proof
        .post_balance_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let transfer_responses = proof
        .transfer_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let index_responses = proof
        .index_blinding_responses
        .iter()
        .copied()
        .map(CanonicalScalarV1::to_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let public_commitments = SenderPublicCommitmentsV1 {
        transfer_magnitude: proof.transfer_magnitude_commitment.to_projective()?,
        post_balance: proof.post_balance_commitment.to_projective()?,
        index: proof.index_commitment.to_projective()?,
    };
    let announcements = sender_selection_announcements(
        statement,
        &public_commitments,
        &SenderResponseSlicesV1 {
            challenges: &challenges,
            inverse_key: &inverse_key_responses,
            post_balance_blinding: &post_balance_responses,
            transfer_blinding: &transfer_responses,
            index_blinding: &index_responses,
        },
    )?;
    let global_challenge = sender_selection_challenge(
        statement,
        &proof.transfer_magnitude_commitment,
        &proof.post_balance_commitment,
        &proof.index_commitment,
        &announcements,
    )?;
    if sum_scalars(challenges) != global_challenge {
        return Err(AnonymousPgcError::PaymentProofEquationFailed);
    }
    verify_positive_range(
        statement,
        b"sender-transfer-magnitude",
        0,
        public_commitments.transfer_magnitude,
        &proof.transfer_range,
    )?;
    verify_unsigned_range(
        statement,
        b"sender-post-balance",
        0,
        public_commitments.post_balance,
        &proof.post_balance_range,
    )
}
fn validate_payment_witness(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    witness: &AnonymousPgcPaymentWitnessV1<'_>,
) -> Result<(Vec<usize>, Vec<usize>, u32), AnonymousPgcError> {
    let n = statement.anonymity_set_size();
    if witness.transfer_values.len() != n
        || witness.transfer_randomness.len() != n
        || witness.sender_index >= n
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let mut recipients = Vec::new();
    let mut decoys = Vec::new();
    let mut senders = Vec::new();
    let mut sum = 0_i128;
    for (index, value) in witness.transfer_values.iter().copied().enumerate() {
        let _ = payment_value_scalar(value)?;
        sum = sum
            .checked_add(i128::from(value))
            .ok_or(AnonymousPgcError::InvalidPaymentWitness)?;
        match value.cmp(&0) {
            core::cmp::Ordering::Greater => recipients.push(index),
            core::cmp::Ordering::Equal => decoys.push(index),
            core::cmp::Ordering::Less => senders.push(index),
        }
        if encrypt_signed_with_randomness(
            statement.public_keys[index],
            value,
            &witness.transfer_randomness[index],
        )? != statement.transfer_ciphertexts[index]
        {
            return Err(AnonymousPgcError::InvalidPaymentWitness);
        }
    }
    if sum != 0
        || recipients.len() != statement.recipient_count()
        || decoys.len() != n - statement.recipient_count() - 1
        || senders.as_slice() != [witness.sender_index]
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let parameters = AnonymousPgcParametersV1::get()?;
    if parameters.g * witness.sender_secret.expose_scalar()
        != statement.public_keys[witness.sender_index]
            .point
            .to_projective()?
    {
        return Err(AnonymousPgcError::InvalidPaymentWitness);
    }
    let updates = derive_atomic_ciphertext_updates(statement)?;
    let post_balance = super::decrypt_u32(witness.sender_secret, updates[witness.sender_index])
        .map_err(|_| AnonymousPgcError::InvalidPaymentWitness)?;
    Ok((recipients, decoys, post_balance))
}
/// Prove the complete Anonymous-PGC payment legality relation.
///
/// # Errors
///
/// Rejects a false public memo/opening, wrong role counts, unbalanced values,
/// sender-key mismatch, insolvent sender, prohibited identity intermediate,
/// entropy exhaustion, or a proof exceeding its closed wire cap.
pub fn prove_payment<R>(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    witness: &AnonymousPgcPaymentWitnessV1<'_>,
    rng: &mut R,
) -> Result<AnonymousPgcPaymentProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    super::validate_binding(&statement.transcript_binding)?;
    let (recipient_indices, decoy_indices, post_balance) =
        validate_payment_witness(statement, witness)?;
    let mut checked_rng = health_checked_p256_rng_v1(rng)?;
    let mut well_formed = Vec::with_capacity(statement.anonymity_set_size());
    for index in 0..statement.anonymity_set_size() {
        well_formed.push(prove_well_formed(
            statement,
            index,
            payment_value_scalar(witness.transfer_values[index])?,
            witness.transfer_randomness[index].expose_scalar(),
            &mut checked_rng,
        )?);
    }
    let aggregate_randomness = sum_scalars(
        witness
            .transfer_randomness
            .iter()
            .map(SecretScalarV1::expose_scalar),
    );
    let balance_conservation =
        prove_balance_conservation(statement, aggregate_randomness, &mut checked_rng)?;
    let mut recipients = Vec::with_capacity(recipient_indices.len());
    let mut recipient_blindings = Vec::with_capacity(recipient_indices.len());
    for (ordinal, index) in recipient_indices.iter().copied().enumerate() {
        let value = u32::try_from(witness.transfer_values[index])
            .map_err(|_| AnonymousPgcError::InvalidPaymentWitness)?;
        let (proof, index_blinding) = prove_recipient_selection(
            statement,
            u32::try_from(ordinal).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            index,
            value,
            witness.transfer_randomness[index].expose_scalar(),
            &mut checked_rng,
        )?;
        recipients.push(proof);
        recipient_blindings.push(index_blinding);
    }
    let recipient_index_commitments = recipients
        .iter()
        .map(|proof| proof.index_commitment)
        .collect::<Vec<_>>();
    let recipient_distinctness = prove_distinct_indices(
        statement,
        b"recipient-index-distinct",
        &recipient_index_commitments,
        &recipient_indices,
        &recipient_blindings,
        &mut checked_rng,
    )?;
    let mut decoys = Vec::with_capacity(decoy_indices.len());
    let mut decoy_blindings = Vec::with_capacity(decoy_indices.len());
    for (ordinal, index) in decoy_indices.iter().copied().enumerate() {
        let (proof, index_blinding) = prove_decoy_selection(
            statement,
            u32::try_from(ordinal).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            index,
            witness.transfer_randomness[index].expose_scalar(),
            &mut checked_rng,
        )?;
        decoys.push(proof);
        decoy_blindings.push(index_blinding);
    }
    let decoy_index_commitments = decoys
        .iter()
        .map(|proof| proof.index_commitment)
        .collect::<Vec<_>>();
    let decoy_distinctness = prove_distinct_indices(
        statement,
        b"decoy-index-distinct",
        &decoy_index_commitments,
        &decoy_indices,
        &decoy_blindings,
        &mut checked_rng,
    )?;
    let sender_value = witness.transfer_values[witness.sender_index];
    let sender_magnitude = u32::try_from(sender_value.unsigned_abs())
        .map_err(|_| AnonymousPgcError::InvalidPaymentWitness)?;
    let sender = prove_sender_selection(
        statement,
        witness.sender_index,
        witness.sender_secret,
        witness.transfer_randomness[witness.sender_index].expose_scalar(),
        sender_magnitude,
        post_balance,
        &mut checked_rng,
    )?;
    let proof = AnonymousPgcPaymentProofV1 {
        version: PGC_PAYMENT_PROOF_VERSION_V1,
        well_formed,
        balance_conservation,
        recipients,
        recipient_distinctness,
        decoys,
        decoy_distinctness,
        sender,
    };
    proof.validate_shape(statement)?;
    let encoded_len = proof.encode().len();
    if encoded_len > MAX_PGC_PAYMENT_PROOF_BYTES_V1 {
        return Err(AnonymousPgcError::EncodingTooLarge {
            actual: encoded_len,
            max: MAX_PGC_PAYMENT_PROOF_BYTES_V1,
        });
    }
    verify_payment(statement, &proof).map_err(|_| AnonymousPgcError::ProverSelfCheckFailed)?;
    Ok(proof)
}
/// Verify every payment sub-language and return the complete atomic encrypted account effect.
///
/// # Errors
///
/// Rejects malformed proof material, any changed transcript/ledger/memo field,
/// failed well-formedness, imbalance, duplicate hidden indices, nonpositive
/// recipients, nonzero decoys, sender/key mismatch, negative transfer mismatch,
/// insolvent post-balance, or an invalid successor ciphertext.
pub fn verify_payment(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    proof: &AnonymousPgcPaymentProofV1,
) -> Result<VerifiedAnonymousPgcPaymentEffectV1, AnonymousPgcError> {
    super::validate_binding(&statement.transcript_binding)?;
    proof.validate_shape(statement)?;
    let next_balance_ciphertexts = derive_atomic_ciphertext_updates(statement)?;
    for (index, child) in proof.well_formed.iter().enumerate() {
        verify_well_formed(statement, index, child)?;
    }
    verify_balance_conservation(statement, &proof.balance_conservation)?;
    for (ordinal, recipient) in proof.recipients.iter().enumerate() {
        verify_recipient_selection(
            statement,
            u32::try_from(ordinal).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            recipient,
        )?;
    }
    let recipient_index_commitments = proof
        .recipients
        .iter()
        .map(|child| child.index_commitment)
        .collect::<Vec<_>>();
    verify_distinct_indices(
        statement,
        b"recipient-index-distinct",
        &recipient_index_commitments,
        &proof.recipient_distinctness,
    )?;
    for (ordinal, decoy) in proof.decoys.iter().enumerate() {
        verify_decoy_selection(
            statement,
            u32::try_from(ordinal).map_err(|_| AnonymousPgcError::InvalidPaymentProofShape)?,
            decoy,
        )?;
    }
    let decoy_index_commitments = proof
        .decoys
        .iter()
        .map(|child| child.index_commitment)
        .collect::<Vec<_>>();
    verify_distinct_indices(
        statement,
        b"decoy-index-distinct",
        &decoy_index_commitments,
        &proof.decoy_distinctness,
    )?;
    verify_sender_selection(statement, &proof.sender)?;
    Ok(VerifiedAnonymousPgcPaymentEffectV1 {
        next_balance_ciphertexts,
    })
}
/// Decode and verify canonical opaque payment-proof bytes.
///
/// # Errors
///
/// Returns the same failures as [`AnonymousPgcPaymentProofV1::decode_exact`]
/// and [`verify_payment`].
pub fn verify_payment_encoded(
    statement: &AnonymousPgcPaymentStatementV1<'_>,
    proof_bytes: &[u8],
) -> Result<VerifiedAnonymousPgcPaymentEffectV1, AnonymousPgcReadError> {
    let proof = AnonymousPgcPaymentProofV1::decode_exact(proof_bytes, statement)?;
    verify_payment(statement, &proof).map_err(Into::into)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::anonymous_pgc::TwistedElGamalKeyPairV1;
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::payment::tests::LegacyDynamicUnsignedRangeProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyDynamicUnsignedRangeProofV1 {
        bit_commitments: Vec<CompressedPointV1>,
        branch_challenges: Vec<CanonicalScalarV1>,
        branch_responses: Vec<CanonicalScalarV1>,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::payment::tests::LegacyDynamicPositiveRangeProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyDynamicPositiveRangeProofV1 {
        unsigned: LegacyDynamicUnsignedRangeProofV1,
        nonzero: PgcCommittedNonZeroProofV1,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::payment::tests::LegacyDynamicRecipientSelectionProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyDynamicRecipientSelectionProofV1 {
        value_commitment: CompressedPointV1,
        index_commitment: CompressedPointV1,
        branch_challenges: Vec<CanonicalScalarV1>,
        value_blinding_responses: Vec<CanonicalScalarV1>,
        index_blinding_responses: Vec<CanonicalScalarV1>,
        positive_range: LegacyDynamicPositiveRangeProofV1,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::payment::tests::LegacyDynamicSenderSelectionProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyDynamicSenderSelectionProofV1 {
        transfer_magnitude_commitment: CompressedPointV1,
        post_balance_commitment: CompressedPointV1,
        index_commitment: CompressedPointV1,
        branch_challenges: Vec<CanonicalScalarV1>,
        inverse_key_responses: Vec<CanonicalScalarV1>,
        post_balance_blinding_responses: Vec<CanonicalScalarV1>,
        transfer_blinding_responses: Vec<CanonicalScalarV1>,
        index_blinding_responses: Vec<CanonicalScalarV1>,
        transfer_range: LegacyDynamicPositiveRangeProofV1,
        post_balance_range: LegacyDynamicUnsignedRangeProofV1,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::payment::tests::LegacyDynamicPaymentProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyDynamicPaymentProofV1 {
        version: u8,
        well_formed: Vec<PgcTransferWellFormedProofV1>,
        balance_conservation: PgcBalanceConservationProofV1,
        recipients: Vec<LegacyDynamicRecipientSelectionProofV1>,
        recipient_distinctness: Vec<PgcCommittedNonZeroProofV1>,
        decoys: Vec<PgcDecoySelectionProofV1>,
        decoy_distinctness: Vec<PgcCommittedNonZeroProofV1>,
        sender: LegacyDynamicSenderSelectionProofV1,
    }
    fn legacy_dynamic_unsigned_range_v1(
        proof: &PgcUnsignedRangeProofV1,
    ) -> LegacyDynamicUnsignedRangeProofV1 {
        LegacyDynamicUnsignedRangeProofV1 {
            bit_commitments: proof.bit_commitments.to_vec(),
            branch_challenges: proof.branch_challenges.to_vec(),
            branch_responses: proof.branch_responses.to_vec(),
        }
    }
    fn legacy_dynamic_positive_range_v1(
        proof: &PgcPositiveRangeProofV1,
    ) -> LegacyDynamicPositiveRangeProofV1 {
        LegacyDynamicPositiveRangeProofV1 {
            unsigned: legacy_dynamic_unsigned_range_v1(&proof.unsigned),
            nonzero: proof.nonzero,
        }
    }
    fn legacy_dynamic_payment_v1(
        proof: &AnonymousPgcPaymentProofV1,
    ) -> LegacyDynamicPaymentProofV1 {
        LegacyDynamicPaymentProofV1 {
            version: proof.version,
            well_formed: proof.well_formed.clone(),
            balance_conservation: proof.balance_conservation,
            recipients: proof
                .recipients
                .iter()
                .map(|recipient| LegacyDynamicRecipientSelectionProofV1 {
                    value_commitment: recipient.value_commitment,
                    index_commitment: recipient.index_commitment,
                    branch_challenges: recipient.branch_challenges.clone(),
                    value_blinding_responses: recipient.value_blinding_responses.clone(),
                    index_blinding_responses: recipient.index_blinding_responses.clone(),
                    positive_range: legacy_dynamic_positive_range_v1(&recipient.positive_range),
                })
                .collect(),
            recipient_distinctness: proof.recipient_distinctness.clone(),
            decoys: proof.decoys.clone(),
            decoy_distinctness: proof.decoy_distinctness.clone(),
            sender: LegacyDynamicSenderSelectionProofV1 {
                transfer_magnitude_commitment: proof.sender.transfer_magnitude_commitment,
                post_balance_commitment: proof.sender.post_balance_commitment,
                index_commitment: proof.sender.index_commitment,
                branch_challenges: proof.sender.branch_challenges.clone(),
                inverse_key_responses: proof.sender.inverse_key_responses.clone(),
                post_balance_blinding_responses: proof
                    .sender
                    .post_balance_blinding_responses
                    .clone(),
                transfer_blinding_responses: proof.sender.transfer_blinding_responses.clone(),
                index_blinding_responses: proof.sender.index_blinding_responses.clone(),
                transfer_range: legacy_dynamic_positive_range_v1(&proof.sender.transfer_range),
                post_balance_range: legacy_dynamic_unsigned_range_v1(
                    &proof.sender.post_balance_range,
                ),
            },
        }
    }
    struct KatRng {
        seed: [u8; 32],
        counter: u64,
    }
    impl KatRng {
        fn new(seed: [u8; 32]) -> Self {
            Self { seed, counter: 0 }
        }
    }
    impl RngCore for KatRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            let mut offset = 0;
            while offset < destination.len() {
                let mut hash = Sha256::new();
                hash.update(b"iroha.anonymous-pgc.payment.kat-rng.v1");
                hash.update(self.seed);
                hash.update(self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block: [u8; 32] = hash.finalize().into();
                let take = (destination.len() - offset).min(block.len());
                destination[offset..offset + take].copy_from_slice(&block[..take]);
                offset += take;
            }
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for KatRng {}
    struct PartialFailureRng;
    impl RngCore for PartialFailureRng {
        fn next_u32(&mut self) -> u32 {
            panic!("PGC payment must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("PGC payment must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("PGC payment must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for (index, byte) in destination.iter_mut().take(19).enumerate() {
                *byte = index as u8;
            }
            Err(RngError::new(
                "injected partial Anonymous-PGC payment entropy failure",
            ))
        }
    }
    impl CryptoRng for PartialFailureRng {}
    fn secret(value: u64) -> SecretScalarV1 {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        SecretScalarV1::from_bytes(bytes).expect("nonzero test scalar")
    }
    fn binding() -> TranscriptBindingV1<'static> {
        let parameters = AnonymousPgcParametersV1::get().expect("parameters");
        TranscriptBindingV1 {
            network_id: &[0x81; 32],
            genesis_hash: [0x81; 32],
            action_index: 4,
            statement_digest: [0x82; 32],
            parameter_id: [0x83; 32],
            parameter_digest: parameters.parameter_digest(),
            verifier_digest: [0x84; 32],
            statement_schema_digest: [0x85; 32],
            engine_manifest_digest: [0x86; 32],
            generator_digest: parameters.generator_digest(),
        }
    }
    struct Fixture {
        key_pairs: Vec<TwistedElGamalKeyPairV1>,
        public_keys: Vec<TwistedElGamalPublicKeyV1>,
        transfers: Vec<TwistedElGamalCiphertextV1>,
        current_balances: Vec<TwistedElGamalCiphertextV1>,
        transfer_values: Vec<i64>,
        transfer_randomness: Vec<SecretScalarV1>,
        sender_index: usize,
        recipient_count: usize,
        total_supply: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let mut key_pairs = (2_u64..18)
                .map(|value| TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("key pair"))
                .collect::<Vec<_>>();
            key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
            let public_keys = key_pairs
                .iter()
                .map(TwistedElGamalKeyPairV1::public_key)
                .collect::<Vec<_>>();
            let sender_index = 7;
            let recipient_count = 2;
            let mut transfer_values = vec![0_i64; public_keys.len()];
            transfer_values[2] = 20;
            transfer_values[12] = 30;
            transfer_values[sender_index] = -50;
            let transfer_randomness = (0..public_keys.len())
                .map(|index| {
                    secret(
                        100 + u64::try_from(index).expect("test index fits deterministic scalar"),
                    )
                })
                .collect::<Vec<_>>();
            let transfers = public_keys
                .iter()
                .copied()
                .zip(&transfer_values)
                .zip(&transfer_randomness)
                .map(|((key, value), randomness)| {
                    encrypt_signed_with_randomness(key, *value, randomness)
                        .expect("signed transfer")
                })
                .collect::<Vec<_>>();
            let current_balances = public_keys
                .iter()
                .copied()
                .enumerate()
                .map(|(index, key)| {
                    super::super::encrypt_with_randomness(
                        key,
                        100,
                        &secret(
                            200 + u64::try_from(index)
                                .expect("test index fits deterministic scalar"),
                        ),
                    )
                    .expect("current balance")
                })
                .collect::<Vec<_>>();
            Self {
                key_pairs,
                public_keys,
                transfers,
                current_balances,
                transfer_values,
                transfer_randomness,
                sender_index,
                recipient_count,
                total_supply: 1_600,
            }
        }
        fn boundary_64() -> Self {
            let mut key_pairs = (1_000_u64..1_064)
                .map(|value| TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("key pair"))
                .collect::<Vec<_>>();
            key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
            let public_keys = key_pairs
                .iter()
                .map(TwistedElGamalKeyPairV1::public_key)
                .collect::<Vec<_>>();
            let sender_index = 31;
            let recipient_count = 1;
            let mut transfer_values = vec![0_i64; public_keys.len()];
            transfer_values[7] = 1;
            transfer_values[sender_index] = -1;
            let transfer_randomness = (0..public_keys.len())
                .map(|index| {
                    secret(
                        2_000 + u64::try_from(index).expect("test index fits deterministic scalar"),
                    )
                })
                .collect::<Vec<_>>();
            let transfers = public_keys
                .iter()
                .copied()
                .zip(&transfer_values)
                .zip(&transfer_randomness)
                .map(|((key, value), randomness)| {
                    encrypt_signed_with_randomness(key, *value, randomness)
                        .expect("signed transfer")
                })
                .collect::<Vec<_>>();
            let current_balances = public_keys
                .iter()
                .copied()
                .enumerate()
                .map(|(index, key)| {
                    super::super::encrypt_with_randomness(
                        key,
                        10,
                        &secret(
                            3_000
                                + u64::try_from(index)
                                    .expect("test index fits deterministic scalar"),
                        ),
                    )
                    .expect("current balance")
                })
                .collect::<Vec<_>>();
            Self {
                key_pairs,
                public_keys,
                transfers,
                current_balances,
                transfer_values,
                transfer_randomness,
                sender_index,
                recipient_count,
                total_supply: 640,
            }
        }
        fn pool_invariant(&self) -> AnonymousPgcPoolInvariantV1 {
            AnonymousPgcPoolInvariantV1::new(self.total_supply, [0x87; 32], [0x88; 32])
                .expect("pool invariant")
        }
        fn statement(&self) -> AnonymousPgcPaymentStatementV1<'_> {
            AnonymousPgcPaymentStatementV1::new(
                &self.public_keys,
                &self.transfers,
                &self.current_balances,
                self.recipient_count,
                self.pool_invariant(),
                binding(),
            )
            .expect("payment statement")
        }
        fn witness(&self) -> AnonymousPgcPaymentWitnessV1<'_> {
            AnonymousPgcPaymentWitnessV1 {
                transfer_values: &self.transfer_values,
                transfer_randomness: &self.transfer_randomness,
                sender_index: self.sender_index,
                sender_secret: self.key_pairs[self.sender_index].secret_scalar(),
            }
        }
        fn prove(&self) -> AnonymousPgcPaymentProofV1 {
            let mut rng = KatRng::new([0x91; 32]);
            prove_payment(&self.statement(), &self.witness(), &mut rng).expect("payment proof")
        }
    }
    fn mutate_scalar(value: CanonicalScalarV1) -> CanonicalScalarV1 {
        CanonicalScalarV1::from_scalar(value.to_scalar().expect("scalar") + Scalar::ONE)
    }
    fn negate_point(value: CompressedPointV1) -> CompressedPointV1 {
        CompressedPointV1::from_projective(-value.to_projective().expect("point"))
            .expect("nonidentity inverse")
    }
    #[test]
    fn payment_decoder_retains_original_scope_and_same_source_retry() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let bytes = fixture.prove().encode();
        let pointer = bytes.as_ptr();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
        let fail = || {
            norito::with_decode_limits_scope(limits, || verify_payment_encoded(&statement, &bytes))
        };
        let AnonymousPgcReadError::Codec(first) = fail().unwrap_err() else {
            panic!("actual payment decoder must retain the original codec error");
        };
        let first_owner = first.local_refusal().expect("original enclosing quota");
        assert_eq!(
            first_owner.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        assert_eq!(
            first_owner.resource_error(),
            first.error().decode_resource_error().unwrap()
        );
        let AnonymousPgcReadError::Codec(second) = fail().unwrap_err() else {
            panic!("second payment decoder refusal");
        };
        let second_owner = second.local_refusal().unwrap();
        assert_eq!(first_owner.resource_error(), second_owner.resource_error());
        assert_ne!(
            first_owner, second_owner,
            "equal quotas have distinct original scopes"
        );
        assert_eq!(bytes.as_ptr(), pointer);
        let retried =
            verify_payment_encoded(&statement, &bytes).expect("same original proof retries");
        assert_eq!(
            retried.next_balance_ciphertexts().len(),
            fixture.public_keys.len()
        );
        assert_eq!(bytes.as_ptr(), pointer);
        for bytes in [&[][..], &bytes[..bytes.len() - 1]] {
            let AnonymousPgcReadError::Codec(original) =
                verify_payment_encoded(&statement, bytes).unwrap_err()
            else {
                panic!("actual malformed proof must remain a codec rejection");
            };
            assert!(original.local_refusal().is_none());
        }
    }
    #[test]
    fn complete_payment_proves_verifies_and_derives_atomic_effect() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let effect = verify_payment(&statement, &proof).expect("payment verifies");
        let encoded = proof.encode();
        assert!(encoded.len() < MAX_PGC_PAYMENT_PROOF_BYTES_V1);
        let decoded =
            AnonymousPgcPaymentProofV1::decode_exact(&encoded, &statement).expect("decode");
        assert_eq!(decoded, proof);
        assert_eq!(
            verify_payment_encoded(&statement, &encoded)
                .expect("encoded verify")
                .next_balance_ciphertexts(),
            effect.next_balance_ciphertexts()
        );
        assert_eq!(effect.next_balance_ciphertexts().len(), 16);
        assert_eq!(
            super::super::decrypt_u32(
                fixture.key_pairs[fixture.sender_index].secret_scalar(),
                effect.next_balance_ciphertexts()[fixture.sender_index],
            )
            .expect("sender balance"),
            50
        );
        assert_eq!(
            super::super::decrypt_u32(
                fixture.key_pairs[2].secret_scalar(),
                effect.next_balance_ciphertexts()[2],
            )
            .expect("recipient balance"),
            120
        );
    }
    #[test]
    fn complete_payment_decodes_on_a_bounded_stack() {
        let fixture = Box::new(Fixture::new());
        let encoded = fixture.prove().encode();
        std::thread::Builder::new()
            .name("pgc-payment-bounded-decode".to_owned())
            .stack_size(512 * 1024)
            .spawn(move || {
                let proof =
                    AnonymousPgcPaymentProofV1::decode_exact(&encoded, &fixture.statement())
                        .expect("complete nested payment proof fits the bounded decoder stack");
                assert_eq!(proof.encode(), encoded);
                verify_payment(&fixture.statement(), &proof).expect("decoded payment verifies");
            })
            .expect("spawn bounded-stack payment decoder")
            .join()
            .expect("bounded-stack payment decoder completes");
    }
    #[test]
    fn payment_known_answer_vector_is_stable() {
        let fixture = Fixture::new();
        let proof = fixture.prove();
        verify_payment(&fixture.statement(), &proof).expect("verify");
        assert_eq!(
            (
                proof.encode().len(),
                hex::encode(Sha256::digest(proof.encode()))
            ),
            (
                69_859,
                "e14aa4f8f0635e62faa1451e15725486739db23335c23e19003be692e965ad67".to_owned()
            )
        );
    }
    #[test]
    fn first_release_rejects_legacy_dynamic_range_array_headers() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let canonical = proof.encode();
        let legacy = norito::codec::encode_adaptive(&legacy_dynamic_payment_v1(&proof));
        assert_eq!(
            legacy.len(),
            canonical.len() + 4 * 3 * core::mem::size_of::<u64>(),
            "the retired wire carried one u64 Vec count for each of three fixed arrays in four range proofs"
        );
        assert_ne!(legacy, canonical);
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(&legacy, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
    }
    #[test]
    fn complete_n64_boundary_fits_cap_decodes_verifies_and_is_atomic() {
        let fixture = Fixture::boundary_64();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let encoded = proof.encode();
        assert!(encoded.len() <= MAX_PGC_PAYMENT_PROOF_BYTES_V1);
        assert_eq!(
            AnonymousPgcPaymentProofV1::decode_exact(&encoded, &statement)
                .expect("strict n=64 decode"),
            proof
        );
        let effect = verify_payment_encoded(&statement, &encoded).expect("n=64 payment");
        assert_eq!(effect.next_balance_ciphertexts().len(), 64);
        assert_eq!(
            super::super::decrypt_u32(
                fixture.key_pairs[fixture.sender_index].secret_scalar(),
                effect.next_balance_ciphertexts()[fixture.sender_index],
            )
            .expect("sender balance"),
            9
        );
        assert_eq!(
            super::super::decrypt_u32(
                fixture.key_pairs[7].secret_scalar(),
                effect.next_balance_ciphertexts()[7],
            )
            .expect("recipient balance"),
            11
        );
    }
    #[test]
    fn rejects_cross_class_overlap_attempts_before_proof_composition() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let mut rng = KatRng::new([0x92; 32]);
        assert!(matches!(
            prove_recipient_selection(
                &statement,
                0,
                0,
                1,
                fixture.transfer_randomness[0].expose_scalar(),
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        assert!(matches!(
            prove_decoy_selection(
                &statement,
                0,
                2,
                fixture.transfer_randomness[2].expose_scalar(),
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        assert!(matches!(
            prove_recipient_selection(
                &statement,
                0,
                fixture.sender_index,
                50,
                fixture.transfer_randomness[fixture.sender_index].expose_scalar(),
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        assert!(matches!(
            prove_decoy_selection(
                &statement,
                0,
                fixture.sender_index,
                fixture.transfer_randomness[fixture.sender_index].expose_scalar(),
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        assert!(matches!(
            prove_sender_selection(
                &statement,
                2,
                fixture.key_pairs[2].secret_scalar(),
                fixture.transfer_randomness[2].expose_scalar(),
                20,
                120,
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        assert!(matches!(
            prove_sender_selection(
                &statement,
                0,
                fixture.key_pairs[0].secret_scalar(),
                fixture.transfer_randomness[0].expose_scalar(),
                1,
                100,
                &mut rng,
            ),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
    }
    #[test]
    fn rejects_false_witnesses_and_insolvency() {
        let mut fixture = Fixture::new();
        let mut rng = KatRng::new([0x93; 32]);
        fixture.transfer_values[2] = 19;
        assert!(matches!(
            prove_payment(&fixture.statement(), &fixture.witness(), &mut rng),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        let mut fixture = Fixture::new();
        fixture.transfer_values[3] = 1;
        assert!(matches!(
            prove_payment(&fixture.statement(), &fixture.witness(), &mut rng),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        let mut fixture = Fixture::new();
        fixture.current_balances[fixture.sender_index] = super::super::encrypt_with_randomness(
            fixture.public_keys[fixture.sender_index],
            49,
            &secret(250),
        )
        .expect("insufficient balance");
        assert!(matches!(
            prove_payment(&fixture.statement(), &fixture.witness(), &mut rng),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
        let fixture = Fixture::new();
        let wrong_secret = secret(99);
        let wrong_witness = AnonymousPgcPaymentWitnessV1 {
            transfer_values: &fixture.transfer_values,
            transfer_randomness: &fixture.transfer_randomness,
            sender_index: fixture.sender_index,
            sender_secret: &wrong_secret,
        };
        assert!(matches!(
            prove_payment(&fixture.statement(), &wrong_witness, &mut rng),
            Err(AnonymousPgcError::InvalidPaymentWitness)
        ));
    }
    #[test]
    fn complete_payment_rejects_partial_entropy_failure_before_proof_emission() {
        let fixture = Fixture::new();
        assert!(matches!(
            prove_payment(
                &fixture.statement(),
                &fixture.witness(),
                &mut PartialFailureRng,
            ),
            Err(AnonymousPgcError::P256(
                P256EngineError::RandomnessUnavailable
            ))
        ));
    }
    #[test]
    fn mutating_each_proof_family_is_rejected() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let mut changed = proof.clone();
        changed.well_formed[0].value_response =
            mutate_scalar(changed.well_formed[0].value_response);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.balance_conservation.randomness_response =
            mutate_scalar(changed.balance_conservation.randomness_response);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.recipients[0].value_blinding_responses[0] =
            mutate_scalar(changed.recipients[0].value_blinding_responses[0]);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.recipients[0]
            .positive_range
            .unsigned
            .branch_responses[0] = mutate_scalar(
            changed.recipients[0]
                .positive_range
                .unsigned
                .branch_responses[0],
        );
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.recipients[0]
            .positive_range
            .nonzero
            .inverse_response = mutate_scalar(
            changed.recipients[0]
                .positive_range
                .nonzero
                .inverse_response,
        );
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.recipient_distinctness[0].product_blinding_response =
            mutate_scalar(changed.recipient_distinctness[0].product_blinding_response);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.decoys[0].opening_responses[0] =
            mutate_scalar(changed.decoys[0].opening_responses[0]);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.decoy_distinctness[0].inverse_response =
            mutate_scalar(changed.decoy_distinctness[0].inverse_response);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.sender.inverse_key_responses[0] =
            mutate_scalar(changed.sender.inverse_key_responses[0]);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.sender.transfer_range.unsigned.branch_challenges[0] =
            mutate_scalar(changed.sender.transfer_range.unsigned.branch_challenges[0]);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.sender.post_balance_range.branch_responses[0] =
            mutate_scalar(changed.sender.post_balance_range.branch_responses[0]);
        assert!(verify_payment(&statement, &changed).is_err());
        let mut changed = proof;
        changed.recipients.swap(0, 1);
        assert!(verify_payment(&statement, &changed).is_err());
    }
    #[test]
    fn every_ordered_memo_and_ledger_component_changes_the_bound_digest() {
        let fixture = Fixture::new();
        let baseline = fixture.statement().memo_and_ledger_digest();
        for index in 0..fixture.public_keys.len() {
            let mut keys = fixture.public_keys.clone();
            keys[index].point = negate_point(keys[index].point);
            assert_ne!(
                memo_and_ledger_digest(
                    &keys,
                    &fixture.transfers,
                    &fixture.current_balances,
                    fixture.recipient_count,
                    fixture.pool_invariant(),
                )
                .expect("digest"),
                baseline
            );
            for component in 0..4 {
                let mut transfers = fixture.transfers.clone();
                let mut current = fixture.current_balances.clone();
                match component {
                    0 => transfers[index].left = negate_point(transfers[index].left),
                    1 => transfers[index].right = negate_point(transfers[index].right),
                    2 => current[index].left = negate_point(current[index].left),
                    3 => current[index].right = negate_point(current[index].right),
                    _ => unreachable!(),
                }
                assert_ne!(
                    memo_and_ledger_digest(
                        &fixture.public_keys,
                        &transfers,
                        &current,
                        fixture.recipient_count,
                        fixture.pool_invariant(),
                    )
                    .expect("digest"),
                    baseline
                );
            }
        }
        assert_ne!(
            memo_and_ledger_digest(
                &fixture.public_keys,
                &fixture.transfers,
                &fixture.current_balances,
                1,
                fixture.pool_invariant(),
            )
            .expect("digest"),
            baseline
        );
    }
    #[test]
    fn proof_is_bound_to_current_table_ordered_memo_and_transcript() {
        let fixture = Fixture::new();
        let proof = fixture.prove();
        let mut wrong_current = fixture.current_balances.clone();
        wrong_current[0] =
            super::super::encrypt_with_randomness(fixture.public_keys[0], 101, &secret(333))
                .expect("alternate current");
        let wrong_current_statement = AnonymousPgcPaymentStatementV1::new(
            &fixture.public_keys,
            &fixture.transfers,
            &wrong_current,
            fixture.recipient_count,
            fixture.pool_invariant(),
            binding(),
        )
        .expect("statement");
        assert!(verify_payment(&wrong_current_statement, &proof).is_err());
        let mut reordered_transfers = fixture.transfers.clone();
        reordered_transfers.swap(0, 1);
        let reordered_statement = AnonymousPgcPaymentStatementV1::new(
            &fixture.public_keys,
            &reordered_transfers,
            &fixture.current_balances,
            fixture.recipient_count,
            fixture.pool_invariant(),
            binding(),
        )
        .expect("statement");
        assert!(verify_payment(&reordered_statement, &proof).is_err());
        let mut changed_binding = binding();
        changed_binding.statement_digest[0] ^= 1;
        let changed_statement = AnonymousPgcPaymentStatementV1::new(
            &fixture.public_keys,
            &fixture.transfers,
            &fixture.current_balances,
            fixture.recipient_count,
            fixture.pool_invariant(),
            changed_binding,
        )
        .expect("statement");
        assert!(verify_payment(&changed_statement, &proof).is_err());
        for changed_invariant in [
            AnonymousPgcPoolInvariantV1::new(fixture.total_supply + 1, [0x87; 32], [0x88; 32])
                .expect("changed supply"),
            AnonymousPgcPoolInvariantV1::new(fixture.total_supply, [0x89; 32], [0x88; 32])
                .expect("changed bootstrap digest"),
            AnonymousPgcPoolInvariantV1::new(fixture.total_supply, [0x87; 32], [0x8a; 32])
                .expect("changed bootstrap proof digest"),
        ] {
            let changed_statement = AnonymousPgcPaymentStatementV1::new(
                &fixture.public_keys,
                &fixture.transfers,
                &fixture.current_balances,
                fixture.recipient_count,
                changed_invariant,
                binding(),
            )
            .expect("changed pool invariant statement");
            assert_ne!(
                changed_statement.memo_and_ledger_digest(),
                fixture.statement().memo_and_ledger_digest()
            );
            assert!(verify_payment(&changed_statement, &proof).is_err());
        }
    }
    #[test]
    fn decoder_caps_versions_shapes_and_atomic_effects_fail_closed() {
        let fixture = Fixture::new();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let bytes = proof.encode();
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(AnonymousPgcPaymentProofV1::decode_exact(&bytes[..end], &statement).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AnonymousPgcPaymentProofV1::decode_exact(&trailing, &statement).is_err());
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(
                &vec![0; MAX_PGC_PAYMENT_PROOF_BYTES_V1 + 1],
                &statement,
            ),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::EncodingTooLarge { .. }
            ))
        ));
        let mut unknown = proof.clone();
        unknown.version += 1;
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(&unknown.encode(), &statement),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::UnsupportedPaymentProofVersion { .. }
            ))
        ));
        let mut oversized_count = proof.clone();
        oversized_count
            .decoy_distinctness
            .push(oversized_count.decoy_distinctness[0]);
        let oversized = oversized_count.encode();
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(&oversized, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
        let encoded_count = 79_u64.to_le_bytes();
        let count_offset = oversized
            .windows(encoded_count.len())
            .position(|window| window == encoded_count)
            .expect("oversized decoy-pair count is present in canonical wire");
        let mut forged = oversized;
        forged[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(&forged, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
        let mut wrong_shape = proof;
        wrong_shape.recipients.pop();
        assert!(matches!(
            AnonymousPgcPaymentProofV1::decode_exact(&wrong_shape.encode(), &statement),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::InvalidPaymentProofShape
            ))
        ));
        assert_eq!(pair_count(8).expect("recipient pairs"), 28);
        assert_eq!(pair_count(62).expect("n=64 decoy pairs"), 1_891);
        let mut cancelling_current = fixture.current_balances.clone();
        cancelling_current[5] = TwistedElGamalCiphertextV1 {
            left: CompressedPointV1::from_projective(
                -fixture.transfers[5].left.to_projective().expect("left"),
            )
            .expect("inverse left"),
            right: CompressedPointV1::from_projective(
                -fixture.transfers[5].right.to_projective().expect("right"),
            )
            .expect("inverse right"),
        };
        let cancelling_statement = AnonymousPgcPaymentStatementV1::new(
            &fixture.public_keys,
            &fixture.transfers,
            &cancelling_current,
            fixture.recipient_count,
            fixture.pool_invariant(),
            binding(),
        )
        .expect("statement accepts individual canonical inputs");
        assert!(matches!(
            derive_atomic_ciphertext_updates(&cancelling_statement),
            Err(AnonymousPgcError::HomomorphicIdentity)
        ));
        assert!(verify_payment(&cancelling_statement, &fixture.prove()).is_err());
    }
    #[test]
    fn statement_and_signed_value_boundaries_are_strict() {
        let fixture = Fixture::new();
        assert!(matches!(
            AnonymousPgcPoolInvariantV1::new(0, [1; 32], [2; 32]),
            Err(AnonymousPgcError::ZeroPgcTotalSupply)
        ));
        assert!(matches!(
            AnonymousPgcPoolInvariantV1::new(1, [0; 32], [2; 32]),
            Err(AnonymousPgcError::ZeroPgcBootstrapDigest)
        ));
        assert!(matches!(
            AnonymousPgcPoolInvariantV1::new(1, [1; 32], [0; 32]),
            Err(AnonymousPgcError::ZeroPgcBootstrapProofDigest)
        ));
        assert!(matches!(
            AnonymousPgcPaymentStatementV1::new(
                &fixture.public_keys[..15],
                &fixture.transfers[..15],
                &fixture.current_balances[..15],
                2,
                fixture.pool_invariant(),
                binding(),
            ),
            Err(AnonymousPgcError::InvalidPaymentAnonymitySetSize { count: 15 })
        ));
        assert!(matches!(
            AnonymousPgcPaymentStatementV1::new(
                &fixture.public_keys,
                &fixture.transfers[..15],
                &fixture.current_balances,
                2,
                fixture.pool_invariant(),
                binding(),
            ),
            Err(AnonymousPgcError::PaymentLengthMismatch { .. })
        ));
        assert!(matches!(
            AnonymousPgcPaymentStatementV1::new(
                &fixture.public_keys,
                &fixture.transfers,
                &fixture.current_balances,
                0,
                fixture.pool_invariant(),
                binding(),
            ),
            Err(AnonymousPgcError::InvalidPaymentRecipientCount { .. })
        ));
        let mut duplicate_keys = fixture.public_keys.clone();
        duplicate_keys[1] = duplicate_keys[0];
        assert!(matches!(
            AnonymousPgcPaymentStatementV1::new(
                &duplicate_keys,
                &fixture.transfers,
                &fixture.current_balances,
                2,
                fixture.pool_invariant(),
                binding(),
            ),
            Err(AnonymousPgcError::PaymentKeysNotStrictlyIncreasing)
        ));
        let key = fixture.public_keys[0];
        let randomness = &fixture.transfer_randomness[0];
        for value in [-(i64::from(u32::MAX)), -1, 0, 1, i64::from(u32::MAX)] {
            encrypt_signed_with_randomness(key, value, randomness).expect("boundary");
        }
        for value in [
            -(i64::from(u32::MAX)) - 1,
            i64::from(u32::MAX) + 1,
            i64::MIN,
            i64::MAX,
        ] {
            assert!(matches!(
                encrypt_signed_with_randomness(key, value, randomness),
                Err(AnonymousPgcError::PaymentValueOutOfRange { .. })
            ));
        }
    }
}
