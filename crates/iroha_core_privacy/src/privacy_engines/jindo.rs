//! Native clean-room Jindo polynomial-commitment engine.
//!
//! This is the closed univariate, coefficient-encoding specialization of the
//! revised Jindo lattice PCS.  It deliberately does not expose the paper's
//! slot-encoding or general multilinear parameter surfaces.
//!
//! The implementation completes the public algorithms in Figures 2--7 of the current ePrint
//! 2026/044 revision as one exact, versioned, native-Rust profile: fixed ring parameters, proof
//! wire, prover, verifier, integer-only sampling, and adversarial vectors.
//!
//! The hard-cut wire uses 32 signed-monomial repetitions and has complete
//! machine-checked unit-difference evidence. Production qualification remains
//! unavailable until the exact parallel Fiat--Shamir transcript has a pinned
//! qROM extractor-loss theorem required by [`jindo_security_certificate_v1`].
use core::{num::NonZeroU32, time::Duration};
use iroha_crypto::{Hash, PrivateKey, PublicKey};
use iroha_data_model::{
    isi::privacy::SubmitPrivacyProofV1,
    prelude::{AccountId, NetworkId},
    privacy::{
        IROHA_JINDO_FIELD_ELEMENT_BYTES_V1, IROHA_JINDO_MAX_POLYNOMIALS_V1,
        IROHA_JINDO_RING_DEGREE_V1, IrohaJindoPolynomialCommitmentStatementV1,
        PrivacyConsensusLimitsV1, PrivacyJindoFieldElementV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1, PrivacyStatementContextV1,
        PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
    },
    transaction::{
        FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
        signed::TransactionSignatureError,
    },
};
use iroha_model_base::metadata::Metadata;
use rand_core_06::{CryptoRng, OsRng, RngCore};
use thiserror::Error;
#[cfg(test)]
fn network_id_from_genesis_hash_bytes(hash: [u8; 32]) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(hash),
        ),
    )
}
#[path = "jindo/codec.rs"]
mod codec;
#[path = "jindo/crs.rs"]
mod crs;
#[path = "jindo/encoding.rs"]
mod encoding;
#[path = "jindo/field.rs"]
mod field;
#[path = "jindo/norm.rs"]
mod norm;
#[path = "jindo/parameters.rs"]
mod parameters;
#[path = "jindo/protocol.rs"]
mod protocol;
#[path = "jindo/ring.rs"]
mod ring;
#[path = "jindo/sampling.rs"]
mod sampling;
#[path = "jindo/security.rs"]
mod security;
#[path = "jindo/transcript.rs"]
mod transcript;
pub use codec::{JindoProofCodecErrorV1, JindoProofSectionV1};
pub use parameters::{
    JINDO_PARALLEL_REPETITIONS_V1, JINDO_PARAMETER_MANIFEST_V1, JINDO_SOURCE_PROVENANCE_V1,
};
pub use protocol::{
    JINDO_NATIVE_PROOF_BYTES_V1, JINDO_SOURCE_PROFILE_V1, JINDO_SUITE_V1, JindoBindingFieldV1,
    JindoErrorV1, JindoOpeningV1, evaluate_polynomial_v1, jindo_crs_digest_v1,
    verify_batched_evaluation_v1,
};
#[cfg(test)]
pub use protocol::{commit_polynomial_v1, prove_batched_evaluation_v1};
pub use sampling::JindoSamplingErrorV1;
pub use security::{
    JINDO_SECURITY_CERTIFICATE_REQUIREMENTS_V1, JINDO_UNIT_DIFFERENCE_CERTIFICATE_DIGEST_V1,
    JindoUnitDifferenceCertificateErrorV1, JindoUnitDifferenceCertificateV1,
    jindo_unit_difference_certificate_v1,
};
#[cfg(test)]
pub use security::{
    JindoChallengePairErrorV1, JindoSecurityCertificateErrorV1, JindoSecurityCertificateV1,
    jindo_challenge_pair_has_unit_difference_v1, jindo_security_certificate_v1,
};
pub use transcript::{
    JINDO_SIGNED_MONOMIAL_CHALLENGE_CARDINALITY_V1, JindoSignedMonomialChallengeV1,
    JindoTranscriptErrorV1,
};
/// Exact coefficient-field byte width in the first native Jindo profile.
pub const JINDO_FIELD_ELEMENT_BYTES_V1: usize = IROHA_JINDO_FIELD_ELEMENT_BYTES_V1;
/// CELPC/Jindo coefficient-encoding base `b`.
pub const JINDO_ENCODING_BASE_V1: u64 = 3_611_623_616;
/// CELPC/Jindo coefficient digit count `d/gamma` (`exp` in the oracle).
pub const JINDO_ENCODING_EXPONENT_V1: usize = 8;
/// Cyclotomic application-ring degree `d`.
pub const JINDO_RING_DEGREE_V1: usize = IROHA_JINDO_RING_DEGREE_V1;
/// Coefficient-encoding `gamma`, i.e. the number of field slots.
pub const JINDO_ENCODING_SLOTS_V1: usize = JINDO_RING_DEGREE_V1 / JINDO_ENCODING_EXPONENT_V1;
/// Maximum polynomial coefficient count in the fixed first-release profile.
pub const JINDO_MAX_COEFFICIENTS_V1: usize = 256;
/// Exact polynomial count in one first-release batched opening.
pub const JINDO_MAX_BATCH_SIZE_V1: usize = IROHA_JINDO_MAX_POLYNOMIALS_V1 as usize;
const _: () = {
    assert!(JINDO_FIELD_ELEMENT_BYTES_V1 == 32);
    assert!(JINDO_RING_DEGREE_V1 == 1024);
    assert!(JINDO_MAX_COEFFICIENTS_V1 == 256);
    assert!(JINDO_MAX_BATCH_SIZE_V1 == 4);
};
/// Internal reason why one coefficient vector is not the unique first-release
/// encoding of a Jindo polynomial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JindoCanonicalPolynomialErrorV1 {
    Empty {
        polynomial_index: usize,
    },
    TooLarge {
        polynomial_index: usize,
        count: usize,
    },
    NonCanonicalCoefficient {
        polynomial_index: usize,
        coefficient_index: usize,
    },
    TrailingZeroCoefficient {
        polynomial_index: usize,
    },
}
/// Enforce the one accepted variable-length encoding of a degree-bounded
/// polynomial before padding it to the native fixed-width representation.
///
/// The zero polynomial is `[0]`. Every other polynomial is a non-empty vector
/// of canonical field elements whose final coefficient is non-zero. This
/// rejects all alternate encodings that would become equal after zero-padding.
fn validate_canonical_polynomial_v1(
    coefficients: &[PrivacyJindoFieldElementV1],
    polynomial_index: usize,
) -> Result<(), JindoCanonicalPolynomialErrorV1> {
    if coefficients.is_empty() {
        return Err(JindoCanonicalPolynomialErrorV1::Empty { polynomial_index });
    }
    if coefficients.len() > JINDO_MAX_COEFFICIENTS_V1 {
        return Err(JindoCanonicalPolynomialErrorV1::TooLarge {
            polynomial_index,
            count: coefficients.len(),
        });
    }
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        if field::JindoFieldElementV1::from_canonical_bytes(coefficient.encoding).is_none() {
            return Err(JindoCanonicalPolynomialErrorV1::NonCanonicalCoefficient {
                polynomial_index,
                coefficient_index,
            });
        }
    }
    if coefficients.len() > 1
        && coefficients
            .last()
            .is_some_and(|coefficient| coefficient.encoding == [0; 32])
    {
        return Err(JindoCanonicalPolynomialErrorV1::TrailingZeroCoefficient { polynomial_index });
    }
    Ok(())
}
/// Secret witness accepted by the canonical first-release Jindo action builder.
///
/// This type intentionally implements neither `Debug`, `Clone`, nor a
/// serialization trait. It owns all coefficient and evaluation-point bytes and
/// erases them on every return path, including constructor validation failure.
pub struct JindoPrivacyActionWitnessV1 {
    polynomials: Vec<Vec<PrivacyJindoFieldElementV1>>,
    evaluation_point: PrivacyJindoFieldElementV1,
}
impl JindoPrivacyActionWitnessV1 {
    /// Validate and take ownership of one canonical Jindo witness.
    ///
    /// A polynomial has exactly one accepted representation: it is non-empty, contains only
    /// canonical field encodings, and has no trailing zero coefficient unless it is the
    /// single-coefficient zero polynomial. Duplicate polynomials are rejected so one batch cannot
    /// express the same private relation through multiple encodings.
    ///
    /// # Errors
    ///
    /// Returns a precise structural error without including witness bytes.
    pub fn try_new(
        polynomials: Vec<Vec<PrivacyJindoFieldElementV1>>,
        evaluation_point: PrivacyJindoFieldElementV1,
    ) -> Result<Self, JindoPrivacyActionWitnessErrorV1> {
        let witness = Self {
            polynomials,
            evaluation_point,
        };
        witness.validate()?;
        Ok(witness)
    }
    fn validate(&self) -> Result<(), JindoPrivacyActionWitnessErrorV1> {
        if self.polynomials.len() != JINDO_MAX_BATCH_SIZE_V1 {
            return Err(JindoPrivacyActionWitnessErrorV1::InvalidPolynomialCount {
                count: self.polynomials.len(),
                expected: JINDO_MAX_BATCH_SIZE_V1,
            });
        }
        for (polynomial_index, polynomial) in self.polynomials.iter().enumerate() {
            validate_canonical_polynomial_v1(polynomial, polynomial_index)
                .map_err(JindoPrivacyActionWitnessErrorV1::from)?;
            if self.polynomials[..polynomial_index]
                .iter()
                .any(|earlier| earlier == polynomial)
            {
                return Err(JindoPrivacyActionWitnessErrorV1::DuplicatePolynomial {
                    polynomial_index,
                });
            }
        }
        if field::JindoFieldElementV1::from_canonical_bytes(self.evaluation_point.encoding)
            .is_none()
        {
            return Err(JindoPrivacyActionWitnessErrorV1::NonCanonicalEvaluationPoint);
        }
        Ok(())
    }
}
impl Drop for JindoPrivacyActionWitnessV1 {
    fn drop(&mut self) {
        for polynomial in &mut self.polynomials {
            for coefficient in polynomial {
                coefficient.encoding.fill(0);
            }
        }
        self.evaluation_point.encoding.fill(0);
    }
}
/// Canonical witness validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JindoPrivacyActionWitnessErrorV1 {
    /// The batch is not the exact frozen first-release size.
    #[error("Jindo witness requires exactly {expected} polynomials, got {count}")]
    InvalidPolynomialCount {
        /// Observed count.
        count: usize,
        /// Compiled exact batch size.
        expected: usize,
    },
    /// One polynomial has no coefficient.
    #[error("Jindo witness polynomial {polynomial_index} is empty")]
    EmptyPolynomial {
        /// Zero-based polynomial index.
        polynomial_index: usize,
    },
    /// One polynomial exceeds the fixed degree bound.
    #[error(
        "Jindo witness polynomial {polynomial_index} has {count} coefficients; maximum is {max}"
    )]
    PolynomialTooLarge {
        /// Zero-based polynomial index.
        polynomial_index: usize,
        /// Observed coefficient count.
        count: usize,
        /// Compiled maximum.
        max: usize,
    },
    /// A coefficient is not the unique little-endian field encoding.
    #[error(
        "Jindo witness polynomial {polynomial_index} coefficient {coefficient_index} is non-canonical"
    )]
    NonCanonicalCoefficient {
        /// Zero-based polynomial index.
        polynomial_index: usize,
        /// Zero-based coefficient index.
        coefficient_index: usize,
    },
    /// A polynomial used a redundant high zero coefficient.
    #[error("Jindo witness polynomial {polynomial_index} has a trailing zero coefficient")]
    TrailingZeroCoefficient {
        /// Zero-based polynomial index.
        polynomial_index: usize,
    },
    /// A polynomial repeats an earlier batch member.
    #[error("Jindo witness polynomial {polynomial_index} duplicates an earlier polynomial")]
    DuplicatePolynomial {
        /// Zero-based duplicate index.
        polynomial_index: usize,
    },
    /// The evaluation point is not a canonical coefficient-field element.
    #[error("Jindo witness evaluation point is non-canonical")]
    NonCanonicalEvaluationPoint,
}
impl From<JindoCanonicalPolynomialErrorV1> for JindoPrivacyActionWitnessErrorV1 {
    fn from(error: JindoCanonicalPolynomialErrorV1) -> Self {
        match error {
            JindoCanonicalPolynomialErrorV1::Empty { polynomial_index } => {
                Self::EmptyPolynomial { polynomial_index }
            }
            JindoCanonicalPolynomialErrorV1::TooLarge {
                polynomial_index,
                count,
            } => Self::PolynomialTooLarge {
                polynomial_index,
                count,
                max: JINDO_MAX_COEFFICIENTS_V1,
            },
            JindoCanonicalPolynomialErrorV1::NonCanonicalCoefficient {
                polynomial_index,
                coefficient_index,
            } => Self::NonCanonicalCoefficient {
                polynomial_index,
                coefficient_index,
            },
            JindoCanonicalPolynomialErrorV1::TrailingZeroCoefficient { polynomial_index } => {
                Self::TrailingZeroCoefficient { polynomial_index }
            }
        }
    }
}
/// Exact signature-bound transaction fields for one direct Jindo action.
#[derive(Clone, Debug)]
pub struct JindoPrivacyActionTransactionContextV1 {
    /// Exact genesis-header-derived transaction security domain.
    pub network_id: NetworkId,
    /// Exact single-key transaction authority.
    pub authority: AccountId,
    /// Required creation time, resolved once before the two-pass construction.
    pub creation_time: Duration,
    /// Optional transaction TTL.
    pub time_to_live: Option<Duration>,
    /// Optional transaction nonce.
    pub nonce: Option<NonZeroU32>,
    /// Exact signature-bound fee payer and maxima.
    pub fee_payment: FeePaymentIntent,
    /// Exact transaction metadata.
    pub metadata: Metadata,
}
/// Ledger-effect classification for a first-release Jindo action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JindoPrivacyActionEffectV1 {
    /// The chain verifies and finalizes the action but does not mutate a
    /// privacy pool, balance, nullifier set, or commitment tree.
    ActionVerificationAndFinalityOnly,
}
/// Pure proving output ready for transaction signing.
///
/// Its payload is the final two-pass payload; callers cannot replace the
/// executable, add attachments, or alter a binding before signing it through
/// [`sign_prepared_jindo_privacy_action_v1`].
pub struct JindoPreparedPrivacyActionV1 {
    payload: TransactionPayload,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    polynomial_count: u32,
    coefficient_counts: Vec<u32>,
}
impl core::fmt::Debug for JindoPreparedPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("JindoPreparedPrivacyActionV1")
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field("polynomial_count", &self.polynomial_count)
            .field("coefficient_counts", &self.coefficient_counts)
            .finish_non_exhaustive()
    }
}
impl JindoPreparedPrivacyActionV1 {
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    /// Borrow the exact immutable payload used to request an authenticated fee quote.
    ///
    /// Fee limits are transaction-intent bound, so callers must prepare the action again with
    /// the returned quote before signing. The final prepared payload should then be re-quoted to
    /// confirm that its fixed-width proof and fee-size fixed point preserve the same intent.
    #[must_use]
    pub const fn transaction_payload_for_fee_quote_v1(&self) -> &TransactionPayload {
        &self.payload
    }
    /// Borrow the final, already revalidated payload for the isolated native
    /// release-evidence runner.
    ///
    /// This hook is absent from daemon builds and never exposes witness
    /// material; it lets the feature-gated runner independently exercise the
    /// same typed envelope and verifier that consensus admission consumes.
    #[cfg(feature = "privacy-release-evidence")]
    #[doc(hidden)]
    pub const fn release_evidence_payload_v1(&self) -> &TransactionPayload {
        self.transaction_payload_for_fee_quote_v1()
    }
    /// Canonical transaction-intent digest bound into the statement.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical privacy proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical encoded typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded proof-envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Number of committed polynomials.
    #[must_use]
    pub const fn polynomial_count(&self) -> u32 {
        self.polynomial_count
    }
    /// Canonical coefficient counts in commitment order.
    #[must_use]
    pub fn coefficient_counts(&self) -> &[u32] {
        &self.coefficient_counts
    }
    /// This component action has no inferred ledger mutation.
    #[must_use]
    pub const fn effect(&self) -> JindoPrivacyActionEffectV1 {
        JindoPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
    }
}
/// Complete signed result produced by the canonical Jindo action path.
pub struct SignedJindoPrivacyActionV1 {
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
    adaptive_signed_transaction_bytes: u32,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    polynomial_count: u32,
    coefficient_counts: Vec<u32>,
}
impl core::fmt::Debug for SignedJindoPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedJindoPrivacyActionV1")
            .field("transaction_hash", &self.transaction_hash)
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field("polynomial_count", &self.polynomial_count)
            .field("coefficient_counts", &self.coefficient_counts)
            .finish_non_exhaustive()
    }
}
impl SignedJindoPrivacyActionV1 {
    /// Borrow the exact signed transaction.
    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed_transaction
    }
    /// Consume the result and return the exact signed transaction.
    #[must_use]
    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.signed_transaction
    }
    /// Canonical transaction hash computed from the signed transaction.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    /// Canonical transaction-intent digest bound into the statement.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical privacy proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical encoded typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded proof-envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Number of committed polynomials.
    #[must_use]
    pub const fn polynomial_count(&self) -> u32 {
        self.polynomial_count
    }
    /// Canonical coefficient counts in commitment order.
    #[must_use]
    pub fn coefficient_counts(&self) -> &[u32] {
        &self.coefficient_counts
    }
    /// This component action has no inferred ledger mutation.
    #[must_use]
    pub const fn effect(&self) -> JindoPrivacyActionEffectV1 {
        JindoPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
    }
}
/// Failure while preparing or signing the canonical Jindo privacy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JindoPrivacyActionBuildErrorV1 {
    /// Secret witness validation failed.
    #[error(transparent)]
    Witness(#[from] JindoPrivacyActionWitnessErrorV1),
    /// The caller supplied the all-zero genesis sentinel.
    #[error("Jindo action requires a non-zero canonical genesis hash")]
    ZeroGenesisHash,
    /// The signed transaction domain does not equal the supplied canonical genesis hash.
    #[error("Jindo action transaction network does not match the canonical genesis hash")]
    NetworkIdMismatch,
    /// Creation time cannot be represented in the transaction wire.
    #[error("Jindo action creation time cannot be represented in milliseconds")]
    CreationTimeOutOfRange,
    /// TTL cannot be represented in the transaction wire.
    #[error("Jindo action TTL cannot be represented in milliseconds")]
    TimeToLiveOutOfRange,
    /// Fee intent or fee metadata violates the canonical transaction policy.
    #[error("Jindo action transaction context is not canonical")]
    InvalidTransactionContext,
    /// The locally compiled governed Jindo profile is unavailable.
    #[error("the compiled native Jindo profile is unavailable")]
    CompiledProfileUnavailable,
    /// Native commitment or proving failed.
    #[error("native Jindo proving failed: {0}")]
    Native(#[from] JindoErrorV1),
    /// The unsigned payload could not derive its canonical privacy intent.
    #[error("Jindo action transaction-intent derivation failed")]
    TransactionIntent,
    /// The typed statement could not derive its canonical digest.
    #[error("Jindo action statement digest derivation failed")]
    StatementDigest,
    /// The typed statement could not be canonically encoded.
    #[error("the locally produced Jindo statement could not be encoded")]
    StatementEncoding,
    /// The final proof envelope failed its intrinsic consensus validation.
    #[error("the locally produced Jindo proof envelope failed validation")]
    EnvelopeValidation,
    /// The final payload did not reproduce its draft-derived intent binding.
    #[error("the locally produced Jindo payload failed intent validation")]
    FinalIntentBinding,
    /// The final envelope could not be canonically encoded.
    #[error("the locally produced Jindo proof envelope could not be encoded")]
    EnvelopeEncoding,
    /// A bounded canonical byte length did not fit its public result field.
    #[error("a canonical Jindo action byte length overflowed")]
    EncodedLengthOverflow,
    /// The authority is multisig and cannot use this single-key constructor.
    #[error("the Jindo action authority is not a single-key authority")]
    UnsupportedAuthority,
    /// The supplied private key does not control the exact authority.
    #[error("the supplied Jindo action signing key does not control the authority")]
    AuthorityKeyMismatch,
    /// The signature backend failed without exposing private key material.
    #[error("Jindo action transaction signing failed")]
    TransactionSigning,
    /// The signed payload no longer carries the prepared intent.
    #[error("signed Jindo action intent differs from the prepared intent")]
    SignedIntentMismatch,
}
fn validate_transaction_context_v1(
    context: &JindoPrivacyActionTransactionContextV1,
) -> Result<(), JindoPrivacyActionBuildErrorV1> {
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(JindoPrivacyActionBuildErrorV1::CreationTimeOutOfRange);
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(JindoPrivacyActionBuildErrorV1::TimeToLiveOutOfRange);
    }
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map(|_| ())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::InvalidTransactionContext)
}
fn validate_signing_authority_v1(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), JindoPrivacyActionBuildErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or(JindoPrivacyActionBuildErrorV1::UnsupportedAuthority)?;
    let derived = PublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(JindoPrivacyActionBuildErrorV1::AuthorityKeyMismatch);
    }
    Ok(())
}
fn transaction_payload_v1(
    context: &JindoPrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, JindoPrivacyActionBuildErrorV1> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_instructions([SubmitPrivacyProofV1::new(envelope)])
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map_err(|_| JindoPrivacyActionBuildErrorV1::InvalidTransactionContext)
}
/// Derive the canonical proof-independent transaction intent for the first pass.
///
/// The data-model projection canonically removes proof bytes and zeroes the self-referential intent
/// and statement digests. This helper materializes exactly that normalized preimage, derives its
/// digest immediately, and returns only the digest. Its proof-empty intermediate therefore cannot
/// be returned, signed, or submitted through the public prepared-action API.
fn derive_canonical_transaction_intent_digest_v1(
    context: &JindoPrivacyActionTransactionContextV1,
    statement: PrivacyStatementV1,
) -> Result<PrivacyTransactionIntentDigestV1, JindoPrivacyActionBuildErrorV1> {
    let normalized_projection_envelope = PrivacyProofEnvelopeV1::bind_v1(
        statement,
        PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(Vec::new())),
    )
    .map_err(|_| JindoPrivacyActionBuildErrorV1::StatementDigest)?;
    transaction_payload_v1(context, normalized_projection_envelope)?
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| JindoPrivacyActionBuildErrorV1::TransactionIntent)
}
/// Prepare and prove one canonical direct Jindo action using caller-provided
/// cryptographically secure randomness.
///
/// This is the pure proving half of the API: it does not receive or clone a transaction signing
/// key. It performs the required two-pass construction, first deriving the intent from a
/// proof-independent projection and then proving the final intent-bound statement. The final
/// payload is revalidated before it is returned.
///
/// # Errors
///
/// Returns a closed error for non-canonical context or witness input, native
/// proving failure, binding drift, or resource-limit violation.
pub fn prepare_jindo_privacy_action_with_rng_v1<R>(
    context: JindoPrivacyActionTransactionContextV1,
    witness: JindoPrivacyActionWitnessV1,
    canonical_genesis_hash: [u8; 32],
    rng: &mut R,
) -> Result<JindoPreparedPrivacyActionV1, JindoPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(JindoPrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(JindoPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    validate_transaction_context_v1(&context)?;
    witness.validate()?;
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
    )
    .map_err(|_| JindoPrivacyActionBuildErrorV1::CompiledProfileUnavailable)?;
    let polynomial_count = u32::try_from(witness.polynomials.len())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let coefficient_counts = witness
        .polynomials
        .iter()
        .map(|polynomial| {
            u32::try_from(polynomial.len())
                .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let claimed_evaluations = witness
        .polynomials
        .iter()
        .map(|polynomial| evaluate_polynomial_v1(polynomial, witness.evaluation_point))
        .collect::<Result<Vec<_>, _>>()?;
    let mut checked_rng = sampling::health_checked_jindo_rng_v1(rng).map_err(JindoErrorV1::from)?;
    let mut commitments = Vec::with_capacity(witness.polynomials.len());
    let mut openings = Vec::with_capacity(witness.polynomials.len());
    for polynomial in &witness.polynomials {
        let (commitment, opening) =
            protocol::commit_polynomial_with_checked_rng_v1(polynomial, &mut checked_rng)?;
        commitments.push(commitment);
        openings.push(opening);
    }
    let native_statement = IrohaJindoPolynomialCommitmentStatementV1 {
        context: PrivacyStatementContextV1 {
            network_id: context.network_id,
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
        },
        polynomial_commitments: commitments,
        evaluation_point: witness.evaluation_point,
        claimed_evaluations,
    };
    let draft_statement =
        PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(native_statement.clone());
    let transaction_intent_digest =
        derive_canonical_transaction_intent_digest_v1(&context, draft_statement)?;
    let mut final_statement = native_statement;
    final_statement.context.transaction_intent_digest = transaction_intent_digest;
    let typed_statement =
        PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(final_statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| JindoPrivacyActionBuildErrorV1::StatementDigest)?;
    let statement_bytes = u32::try_from(
        norito::to_bytes(&typed_statement)
            .map_err(|_| JindoPrivacyActionBuildErrorV1::StatementEncoding)?
            .len(),
    )
    .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let binding = crate::privacy_engines::p256::TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
        action_index: 0,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: jindo_crs_digest_v1(),
    };
    let proof = protocol::prove_batched_evaluation_with_checked_rng_v1(
        &final_statement,
        &witness.polynomials,
        &openings,
        &binding,
        &mut checked_rng,
    )?;
    let proof_bytes = u32::try_from(proof.len())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let final_envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(PrivacyProofBytesV1::new(proof)),
    )
    .map_err(|_| JindoPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(JindoPrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    final_envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let envelope_encoding = norito::to_bytes(&final_envelope)
        .map_err(|_| JindoPrivacyActionBuildErrorV1::EnvelopeEncoding)?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let final_payload = transaction_payload_v1(&context, final_envelope)?;
    let validated_intent = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| JindoPrivacyActionBuildErrorV1::FinalIntentBinding)?;
    if validated_intent != transaction_intent_digest {
        return Err(JindoPrivacyActionBuildErrorV1::FinalIntentBinding);
    }
    Ok(JindoPreparedPrivacyActionV1 {
        payload: final_payload,
        transaction_intent_digest: *transaction_intent_digest.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
        polynomial_count,
        coefficient_counts,
    })
}
#[cfg(any(test, feature = "test-utils"))]
/// Prepare and prove one canonical direct Jindo action using operating-system
/// randomness, without receiving a transaction signing key.
///
/// # Errors
///
/// Returns the same closed failures as [`prepare_jindo_privacy_action_with_rng_v1`].
pub fn prepare_jindo_privacy_action_v1(
    context: JindoPrivacyActionTransactionContextV1,
    witness: JindoPrivacyActionWitnessV1,
    canonical_genesis_hash: [u8; 32],
) -> Result<JindoPreparedPrivacyActionV1, JindoPrivacyActionBuildErrorV1> {
    prepare_jindo_privacy_action_with_rng_v1(context, witness, canonical_genesis_hash, &mut OsRng)
}
/// Sign a payload returned by the canonical pure Jindo prover.
///
/// # Errors
///
/// Returns an error for a multisig authority, an authority/key mismatch,
/// signature-backend failure, or post-sign intent drift.
pub fn sign_prepared_jindo_privacy_action_v1(
    prepared: JindoPreparedPrivacyActionV1,
    private_key: &PrivateKey,
) -> Result<SignedJindoPrivacyActionV1, JindoPrivacyActionBuildErrorV1> {
    validate_signing_authority_v1(prepared.payload.authority(), private_key)?;
    let expected_intent = prepared.transaction_intent_digest;
    let signed_transaction = TransactionBuilder::from_payload(prepared.payload)
        .map_err(|_| JindoPrivacyActionBuildErrorV1::InvalidTransactionContext)?
        .try_sign(private_key)
        .map_err(|error| match error {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                JindoPrivacyActionBuildErrorV1::UnsupportedAuthority
            }
            TransactionSignatureError::AuthorityKeyMismatch => {
                JindoPrivacyActionBuildErrorV1::AuthorityKeyMismatch
            }
            TransactionSignatureError::InvalidFeePaymentIntent(_) => {
                JindoPrivacyActionBuildErrorV1::InvalidTransactionContext
            }
            _ => JindoPrivacyActionBuildErrorV1::TransactionSigning,
        })?;
    let validated_binding = signed_transaction
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| JindoPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    let (validated_intent, signed_submission) =
        validated_binding.ok_or(JindoPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    if validated_intent.as_bytes() != &expected_intent {
        return Err(JindoPrivacyActionBuildErrorV1::SignedIntentMismatch);
    }
    signed_submission
        .envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| JindoPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    let transaction_hash = *signed_transaction.hash().as_ref();
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed_transaction).len())
            .map_err(|_| JindoPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    Ok(SignedJindoPrivacyActionV1 {
        signed_transaction,
        transaction_hash,
        adaptive_signed_transaction_bytes,
        transaction_intent_digest: expected_intent,
        statement_digest: prepared.statement_digest,
        proof_envelope_hash: prepared.proof_envelope_hash,
        statement_bytes: prepared.statement_bytes,
        proof_bytes: prepared.proof_bytes,
        encoded_proof_envelope_bytes: prepared.encoded_proof_envelope_bytes,
        polynomial_count: prepared.polynomial_count,
        coefficient_counts: prepared.coefficient_counts,
    })
}
/// Build, prove, bind, and sign one canonical direct Jindo privacy action with
/// caller-provided cryptographically secure randomness.
///
/// This entrypoint validates the signing authority before it requests any randomness or performs
/// proof work, then composes the pure prover and the prepared-action signer.
///
/// # Errors
///
/// Returns a closed validation, proving, binding, or signing error.
pub fn build_signed_privacy_action_with_rng_v1<R>(
    context: JindoPrivacyActionTransactionContextV1,
    witness: JindoPrivacyActionWitnessV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<SignedJindoPrivacyActionV1, JindoPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    validate_signing_authority_v1(&context.authority, private_key)?;
    let prepared =
        prepare_jindo_privacy_action_with_rng_v1(context, witness, canonical_genesis_hash, rng)?;
    sign_prepared_jindo_privacy_action_v1(prepared, private_key)
}
/// Build, prove, bind, and sign one canonical direct Jindo privacy action using
/// operating-system randomness.
///
/// This is the single convenience implementation used by SDK adapters.
///
/// # Errors
///
/// Returns the same closed failures as [`build_signed_privacy_action_with_rng_v1`].
pub fn build_signed_privacy_action_v1(
    context: JindoPrivacyActionTransactionContextV1,
    witness: JindoPrivacyActionWitnessV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedJindoPrivacyActionV1, JindoPrivacyActionBuildErrorV1> {
    build_signed_privacy_action_with_rng_v1(
        context,
        witness,
        canonical_genesis_hash,
        private_key,
        &mut OsRng,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use iroha_crypto::PrivateKey;
    use iroha_data_model::{
        prelude::AccountId,
        privacy::PrivacyJindoFieldElementV1,
        transaction::{Executable, FeePaymentIntent},
    };
    use iroha_model_base::metadata::Metadata;
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    struct TestRng(u64);
    impl TestRng {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.0 = value;
            value.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("invalid boundary input reached native randomness")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("invalid boundary input reached native randomness")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("invalid boundary input reached native randomness")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            panic!("invalid boundary input reached native randomness")
        }
    }
    impl CryptoRng for PanicRng {}
    fn field(value: u64) -> PrivacyJindoFieldElementV1 {
        let mut encoding = [0_u8; 32];
        encoding[..8].copy_from_slice(&value.to_le_bytes());
        PrivacyJindoFieldElementV1::new(encoding)
    }
    fn field_modulus() -> PrivacyJindoFieldElementV1 {
        let mut encoding = [0_u8; 32];
        for (chunk, limb) in encoding
            .chunks_exact_mut(core::mem::size_of::<u64>())
            .zip(field::JindoFieldElementV1::MODULUS)
        {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        PrivacyJindoFieldElementV1::new(encoding)
    }
    fn field_modulus_plus_one() -> PrivacyJindoFieldElementV1 {
        let mut value = field_modulus();
        value.encoding[0] = value.encoding[0]
            .checked_add(1)
            .expect("Jindo modulus low byte leaves room for one");
        value
    }
    fn authority() -> AccountId {
        AccountId::new(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("fixed public key"),
        )
    }
    fn private_key() -> PrivateKey {
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .expect("fixed private key")
    }
    fn foreign_private_key() -> PrivateKey {
        "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
            .parse()
            .expect("fixed foreign private key")
    }
    fn action_context() -> JindoPrivacyActionTransactionContextV1 {
        JindoPrivacyActionTransactionContextV1 {
            network_id: network_id_from_genesis_hash_bytes([0xA7; 32]),
            authority: authority(),
            creation_time: Duration::from_millis(1_800_000_000_123),
            time_to_live: Some(Duration::from_secs(60)),
            nonce: NonZeroU32::new(7),
            fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
            metadata: Metadata::default(),
        }
    }
    fn action_witness() -> JindoPrivacyActionWitnessV1 {
        JindoPrivacyActionWitnessV1::try_new(
            vec![
                vec![field(3), field(5), field(7), field(11)],
                vec![field(13), field(17)],
                vec![field(19), field(23)],
                vec![field(29), field(31)],
            ],
            field(13),
        )
        .expect("canonical fixed witness")
    }
    fn witness_error(
        polynomials: Vec<Vec<PrivacyJindoFieldElementV1>>,
        evaluation_point: PrivacyJindoFieldElementV1,
    ) -> JindoPrivacyActionWitnessErrorV1 {
        match JindoPrivacyActionWitnessV1::try_new(polynomials, evaluation_point) {
            Ok(_) => panic!("malformed witness was accepted"),
            Err(error) => error,
        }
    }
    fn exact_batch_with_first(
        first: Vec<PrivacyJindoFieldElementV1>,
    ) -> Vec<Vec<PrivacyJindoFieldElementV1>> {
        vec![first, vec![field(101)], vec![field(102)], vec![field(103)]]
    }
    fn perturb_rns_polynomial(
        polynomial: &mut ring::JindoRnsPolynomialV1,
        delta: i128,
        moduli: [ring::JindoPrimeModulusV1; 2],
    ) {
        let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
        coefficients[0] = delta;
        polynomial.add_assign(
            &ring::JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, moduli),
            moduli,
        );
    }
    #[test]
    fn fixed_profile_dimensions_are_self_consistent() {
        assert_eq!(JINDO_ENCODING_EXPONENT_V1, 8);
        assert_eq!(JINDO_ENCODING_SLOTS_V1, 128);
        assert_eq!(JINDO_RING_DEGREE_V1 % JINDO_ENCODING_EXPONENT_V1, 0);
        assert_eq!(JINDO_FIELD_ELEMENT_BYTES_V1, 32);
        assert!(JINDO_MAX_COEFFICIENTS_V1.is_power_of_two());
        assert_eq!(JINDO_MAX_BATCH_SIZE_V1, 4);
    }
    #[test]
    fn action_witness_rejects_noncanonical_and_ambiguous_representations() {
        assert!(matches!(
            witness_error(Vec::new(), field(1)),
            JindoPrivacyActionWitnessErrorV1::InvalidPolynomialCount { count: 0, .. }
        ));
        assert!(matches!(
            witness_error(vec![vec![field(1)]; JINDO_MAX_BATCH_SIZE_V1 + 1], field(1)),
            JindoPrivacyActionWitnessErrorV1::InvalidPolynomialCount { .. }
        ));
        for count in [1, 3] {
            assert!(matches!(
                witness_error(
                    (0..count).map(|i| vec![field(i as u64 + 1)]).collect(),
                    field(1)
                ),
                JindoPrivacyActionWitnessErrorV1::InvalidPolynomialCount { .. }
            ));
        }
        assert_eq!(
            witness_error(exact_batch_with_first(Vec::new()), field(1)),
            JindoPrivacyActionWitnessErrorV1::EmptyPolynomial {
                polynomial_index: 0
            }
        );
        assert!(matches!(
            witness_error(
                exact_batch_with_first(vec![field(1); JINDO_MAX_COEFFICIENTS_V1 + 1]),
                field(1)
            ),
            JindoPrivacyActionWitnessErrorV1::PolynomialTooLarge { .. }
        ));
        assert_eq!(
            witness_error(exact_batch_with_first(vec![field_modulus()]), field(1)),
            JindoPrivacyActionWitnessErrorV1::NonCanonicalCoefficient {
                polynomial_index: 0,
                coefficient_index: 0,
            }
        );
        assert_eq!(
            witness_error(
                exact_batch_with_first(vec![field_modulus_plus_one()]),
                field(1)
            ),
            JindoPrivacyActionWitnessErrorV1::NonCanonicalCoefficient {
                polynomial_index: 0,
                coefficient_index: 0,
            }
        );
        assert_eq!(
            witness_error(exact_batch_with_first(vec![field(1), field(0)]), field(1)),
            JindoPrivacyActionWitnessErrorV1::TrailingZeroCoefficient {
                polynomial_index: 0,
            }
        );
        let mut trailing_zero_at_cap = vec![field(1); JINDO_MAX_COEFFICIENTS_V1];
        trailing_zero_at_cap[JINDO_MAX_COEFFICIENTS_V1 - 1] = field(0);
        assert_eq!(
            witness_error(exact_batch_with_first(trailing_zero_at_cap), field(1)),
            JindoPrivacyActionWitnessErrorV1::TrailingZeroCoefficient {
                polynomial_index: 0,
            }
        );
        assert_eq!(
            witness_error(
                vec![
                    vec![field(1)],
                    vec![field(1)],
                    vec![field(2)],
                    vec![field(3)],
                ],
                field(1)
            ),
            JindoPrivacyActionWitnessErrorV1::DuplicatePolynomial {
                polynomial_index: 1,
            }
        );
        assert_eq!(
            witness_error(exact_batch_with_first(vec![field(1)]), field_modulus()),
            JindoPrivacyActionWitnessErrorV1::NonCanonicalEvaluationPoint
        );
        assert!(
            JindoPrivacyActionWitnessV1::try_new(exact_batch_with_first(vec![field(0)]), field(0))
                .is_ok(),
            "the uniquely encoded zero polynomial and zero point remain valid"
        );
        assert!(
            JindoPrivacyActionWitnessV1::try_new(
                exact_batch_with_first(vec![field(1); JINDO_MAX_COEFFICIENTS_V1]),
                field(0),
            )
            .is_ok(),
            "the exact coefficient cap remains valid when its leading coefficient is non-zero"
        );
    }
    #[test]
    fn action_builder_rejects_public_boundary_errors_before_randomness() {
        let zero_genesis = prepare_jindo_privacy_action_with_rng_v1(
            action_context(),
            action_witness(),
            [0; 32],
            &mut PanicRng,
        );
        assert!(matches!(
            zero_genesis,
            Err(JindoPrivacyActionBuildErrorV1::ZeroGenesisHash)
        ));
        let mut oversized_time = action_context();
        oversized_time.creation_time = Duration::from_secs(u64::MAX);
        let oversized_time = prepare_jindo_privacy_action_with_rng_v1(
            oversized_time,
            action_witness(),
            [0xA7; 32],
            &mut PanicRng,
        );
        assert!(matches!(
            oversized_time,
            Err(JindoPrivacyActionBuildErrorV1::CreationTimeOutOfRange)
        ));
        let wrong_key = build_signed_privacy_action_with_rng_v1(
            action_context(),
            action_witness(),
            [0xA7; 32],
            &foreign_private_key(),
            &mut PanicRng,
        );
        assert!(matches!(
            wrong_key,
            Err(JindoPrivacyActionBuildErrorV1::AuthorityKeyMismatch)
        ));
    }
    #[test]
    fn deterministic_action_api_builds_one_bound_signed_component_action() {
        let prepared = prepare_jindo_privacy_action_with_rng_v1(
            action_context(),
            action_witness(),
            [0xA7; 32],
            &mut TestRng::new(0x6a6a_29d0_0044_0001),
        )
        .expect("deterministic Jindo action proving");
        assert_eq!(prepared.polynomial_count(), 4);
        assert_eq!(prepared.coefficient_counts(), &[4, 2, 2, 2]);
        assert_eq!(prepared.proof_bytes(), JINDO_NATIVE_PROOF_BYTES_V1 as u32);

        assert_ne!(prepared.transaction_intent_digest(), [0; 32]);
        assert_ne!(prepared.statement_digest(), [0; 32]);
        assert_ne!(prepared.proof_envelope_hash(), [0; 32]);
        assert_eq!(
            prepared.effect(),
            JindoPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
        );
        let projected_intent = prepared
            .payload
            .privacy_transaction_intent_digest_v1()
            .expect("proof-independent intent projection");
        assert_eq!(
            projected_intent.as_bytes(),
            &prepared.transaction_intent_digest(),
            "the final payload must reproduce the first-pass projected intent"
        );
        match prepared.payload.instructions() {
            Executable::Instructions(instructions) => {
                assert_eq!(instructions.len(), 1, "exactly one direct action");
                assert!(
                    instructions[0]
                        .as_any()
                        .downcast_ref::<SubmitPrivacyProofV1>()
                        .is_some(),
                    "the sole action must be the typed Jindo submission"
                );
            }
            other => panic!("unexpected Jindo executable form: {other:?}"),
        }
        {
            let observed = prepared
                .payload
                .privacy_transaction_intent_binding_if_present_v1()
                .expect("canonical direct privacy scan")
                .expect("exactly one direct Jindo action");
            assert_eq!(observed.0.as_bytes(), &prepared.transaction_intent_digest());
            let envelope = &observed.1.envelope;
            let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
                PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
            )
            .expect("compiled Jindo profile");
            assert_eq!(envelope.protocol_id, profile.protocol_id);
            assert_eq!(envelope.proof_system_id, profile.proof_system_id);
            assert_eq!(envelope.engine_id, profile.engine_id);
            assert_eq!(envelope.parameter_id, profile.parameter_id);
            assert_eq!(envelope.parameter_digest, profile.parameter_digest);
            assert_eq!(envelope.verifier_digest, profile.verifier_digest);
            assert_eq!(
                envelope.statement_schema_digest,
                profile.statement_schema_digest
            );
            assert_eq!(
                envelope.engine_manifest_digest,
                profile.engine_manifest_digest
            );
            assert_eq!(
                prepared.statement_bytes(),
                u32::try_from(
                    norito::to_bytes(&envelope.statement)
                        .expect("typed statement encodes")
                        .len()
                )
                .expect("bounded statement bytes"),
                "the statement metric must bind the exact canonical encoding"
            );
            let PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(statement) =
                &envelope.statement
            else {
                panic!("typed Jindo statement changed variant")
            };
            assert_eq!(statement.context.action_index, 0);
            assert_eq!(
                statement.context.transaction_intent_digest.as_bytes(),
                &prepared.transaction_intent_digest()
            );
            let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(proof) = &envelope.proof else {
                panic!("typed Jindo proof changed variant")
            };
            assert!(
                !proof.as_bytes().is_empty(),
                "the proof-empty intent projection must never escape as a prepared action"
            );
            let mut proof_empty_escape = envelope.clone();
            proof_empty_escape.proof = PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(
                PrivacyProofBytesV1::new(Vec::new()),
            );
            assert!(
                proof_empty_escape
                    .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
                    .is_err(),
                "an adversarial proof-empty Jindo envelope must fail closed"
            );
            let binding = crate::privacy_engines::p256::TranscriptBindingV1 {
                network_id: statement.context.network_id.as_bytes(),
                genesis_hash: [0xA7; 32],
                action_index: statement.context.action_index,
                statement_digest: prepared.statement_digest(),
                parameter_id: *profile.parameter_id.as_bytes(),
                parameter_digest: *profile.parameter_digest.as_bytes(),
                verifier_digest: *profile.verifier_digest.as_bytes(),
                statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
                engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
                generator_digest: jindo_crs_digest_v1(),
            };
            verify_batched_evaluation_v1(
                statement,
                proof.as_bytes(),
                &binding,
                PrivacyConsensusLimitsV1::taira_default().max_proof_bytes_per_action,
            )
            .expect("final envelope is bound to the compiled profile and exact CRS");
            let decoded = codec::JindoEvaluationProofV1::decode_exact(
                proof.as_bytes(),
                JINDO_MAX_BATCH_SIZE_V1,
                PrivacyConsensusLimitsV1::taira_default().max_proof_bytes_per_action,
            )
            .expect("the canonical proof wire decodes");
            let mut mutations = Vec::new();
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.mask_commitments[0],
                1_i128 << 68,
                ring::JINDO_OUTER_MODULI_V1,
            );
            mutations.push(("aggregation-mask-commitment", mutated));
            let mut mutated = decoded.clone();
            mutated.mask_split_evaluation[0] =
                mutated.mask_split_evaluation[0] + field::JindoFieldElementV1::ONE;
            mutations.push(("aggregation-mask-evaluation", mutated));
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.partials[0],
                1_i128 << 80,
                ring::JINDO_INNER_MODULI_V1,
            );
            mutations.push(("quadratic-partial", mutated));
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.partials[JINDO_PARALLEL_REPETITIONS_V1 - 1],
                1_i128 << 80,
                ring::JINDO_INNER_MODULI_V1,
            );
            mutations.push(("terminal-parallel-quadratic-partial", mutated));
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.encode_responses[0],
                1_i128 << 80,
                ring::JINDO_INNER_MODULI_V1,
            );
            mutations.push(("encoded-response", mutated));
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.mlwe_responses[0],
                1_i128 << 80,
                ring::JINDO_INNER_MODULI_V1,
            );
            mutations.push(("mlwe-response", mutated));
            let mut mutated = decoded.clone();
            perturb_rns_polynomial(
                &mut mutated.inner_commitments[0],
                1_i128 << 68,
                ring::JINDO_OUTER_MODULI_V1,
            );
            mutations.push(("inner-commitment", mutated));
            let mut mutated = decoded.clone();
            mutated.blind_evaluations[0] =
                mutated.blind_evaluations[0] + field::JindoFieldElementV1::ONE;
            mutations.push(("split-blind-evaluation", mutated));
            let mut mutated = decoded;
            mutated.split_evaluations[0] =
                mutated.split_evaluations[0] + field::JindoFieldElementV1::ONE;
            mutations.push(("split-evaluation", mutated));
            for (section, mutation) in mutations {
                let mutation = mutation.encode();
                codec::JindoEvaluationProofV1::decode_exact(
                    &mutation,
                    JINDO_MAX_BATCH_SIZE_V1,
                    PrivacyConsensusLimitsV1::taira_default().max_proof_bytes_per_action,
                )
                .unwrap_or_else(|error| {
                    panic!("{section} mutation must remain canonically encoded: {error}")
                });
                let error = verify_batched_evaluation_v1(
                    statement,
                    &mutation,
                    &binding,
                    PrivacyConsensusLimitsV1::taira_default().max_proof_bytes_per_action,
                )
                .unwrap_err();
                assert!(
                    !matches!(error, JindoErrorV1::ProofCodec(_)),
                    "{section} must fail a semantic relation, not canonical decoding"
                );
            }
        }
        let mut tampered_payload = prepared.payload.clone();
        tampered_payload.nonce = NonZeroU32::new(8);
        assert!(
            tampered_payload
                .validate_privacy_transaction_intent_binding_v1()
                .is_err(),
            "post-proof mutation must invalidate the two-pass intent"
        );
        let expected_intent = prepared.transaction_intent_digest();
        let expected_statement = prepared.statement_digest();
        let expected_statement_bytes = prepared.statement_bytes();
        let expected_envelope_hash = prepared.proof_envelope_hash();
        let prepared_debug = format!("{prepared:?}");
        assert!(!prepared_debug.contains("TransactionPayload"));
        assert!(!prepared_debug.contains("PrivacyProofBytes"));
        assert!(!prepared_debug.contains("JindoOpening"));
        let signed = sign_prepared_jindo_privacy_action_v1(prepared, &private_key())
            .expect("fixed Jindo action signing");
        signed
            .signed_transaction()
            .verify_signature()
            .expect("locally signed transaction verifies");

        let (_, signed_submission) = signed
            .signed_transaction()
            .privacy_transaction_intent_binding_if_present_v1()
            .expect("signed direct privacy scan")
            .expect("signed Jindo submission");
        let PrivacyProofV1::IrohaJindoPolynomialCommitmentV1(signed_proof) =
            &signed_submission.envelope.proof
        else {
            panic!("signed Jindo proof changed variant")
        };
        assert!(
            !signed_proof.as_bytes().is_empty(),
            "the canonical normalized projection cannot cross the signing boundary"
        );
        signed_submission
            .envelope
            .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
            .expect("the signed boundary contains only the final valid Jindo envelope");
        assert_eq!(
            signed.transaction_hash(),
            *signed.signed_transaction().hash().as_ref()
        );
        let independently_encoded = norito::codec::encode_adaptive(signed.signed_transaction());
        assert_eq!(
            signed.adaptive_signed_transaction_bytes(),
            u32::try_from(independently_encoded.len()).expect("bounded transaction bytes")
        );
        assert!(
            signed.signed_transaction().attachments().is_none(),
            "the canonical Jindo action cannot carry proof attachments"
        );
        assert_eq!(signed.transaction_intent_digest(), expected_intent);
        assert_eq!(signed.statement_digest(), expected_statement);
        assert_eq!(signed.statement_bytes(), expected_statement_bytes);
        assert_eq!(signed.proof_envelope_hash(), expected_envelope_hash);
        assert_eq!(
            signed.effect(),
            JindoPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
        );
        let signed_debug = format!("{signed:?}");
        assert!(!signed_debug.contains("SignedTransaction {"));
        assert!(!signed_debug.contains("PrivacyProofBytes"));
        assert!(!signed_debug.contains("JindoOpening"));
    }
}
