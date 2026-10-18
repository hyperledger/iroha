//! Native Iroha V1 instantiation of ZK-AMS anonymous provisioning.
//!
//! The protocol workflow follows ZK-AMS v2, arXiv:2602.16130, Algorithms 1--4 and Appendices A/C.
//! The paper intentionally leaves the concrete linkable ring-signature group, hash, transcript, and
//! wire unspecified. This module closes Phase V to an LSAG instance over prime-order Ristretto255
//! with SHA3-512 and supplies the holder-possession Schnorr component composed with the admission
//! relation. This module defines the sole Iroha first-release profile; no paper prototype or
//! retired wire is admitted.
//!
//! Batch admission composes an exact low-s ES256 credential relation, a setup-free masked
//! relaxed-R1CS proof, and one transcript-bound Ristretto possession proof per ordered anchor.
//! Provisioning then consumes those admitted seed keys through the closed LSAG suite below.
use core::{num::NonZeroU32, time::Duration};
use curve25519_dalek::{
    RistrettoPoint, constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    scalar::Scalar, traits::Identity,
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_crypto::{Hash, PrivateKey, PublicKey};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_data_model::privacy::PrivacyStatementDigestV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_data_model::transaction::{Executable, signed::TransactionSignatureError};
use iroha_data_model::{
    account::AccountId,
    isi::privacy::SubmitPrivacyProofV1,
    prelude::NetworkId,
    privacy::{
        IrohaZkAmsProofV1, IrohaZkAmsStatementV1, PrivacyConsensusLimitsV1, PrivacyIssuerIdV1,
        PrivacyP256PointV1, PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1, PrivacyRootV1,
        PrivacyStatementContextV1, PrivacyStatementV1, PrivacyTransactionIntentDigestV1,
        PrivacyZkAmsActionV1, PrivacyZkAmsAdmissionAnchorV1, PrivacyZkAmsBatchAdmissionV1,
        PrivacyZkAmsIssuerPolicyRecordDigestV1, PrivacyZkAmsKeyImageV1,
        PrivacyZkAmsPersonhoodCredentialV1, PrivacyZkAmsProvisionAccountV1,
        PrivacyZkAmsRegistryIdV1, PrivacyZkAmsRegistryRecordDigestV1, PrivacyZkAmsSeedPublicKeyV1,
        ZK_AMS_PHC_VERSION_V1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload},
};
use iroha_model_base::metadata::Metadata;
use iroha_zkp_halo2::vega::{
    MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1, MaskedRelaxedRandomErrorV1,
    MaskedRelaxedRandomSourceV1, ZK_AMS_ACTION_INDEX_V1, ZkAmsAdmissionPublicInputV1,
    ZkAmsAdmissionRelationWitnessV1, ZkAmsProofContextV1, prove_zk_ams_admission_relation_v1,
    verify_zk_ams_admission_relation_v1,
};
#[cfg(test)]
fn network_id_from_genesis_hash_bytes(hash: [u8; 32]) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(hash),
        ),
    )
}
use super::{
    p256::{P256EngineError, TranscriptBindingV1},
    prover_randomness::{HealthCheckedCryptoRngV1, ProverRandomnessErrorV1},
};
/// Deterministic worker configuration for the canonical masked admission prover.
pub use iroha_zkp_halo2::vega::ZkAmsMaskedProverConfigV1;
use p256::{
    AffinePoint as P256AffinePoint, FieldBytes as P256FieldBytes,
    ProjectivePoint as P256ProjectivePoint, Scalar as P256Scalar,
    ecdsa::{
        Signature as P256Signature, VerifyingKey as P256VerifyingKey,
        signature::hazmat::PrehashVerifier as _,
    },
    elliptic_curve::{
        PrimeField as _, bigint::U256, group::Group as _, ops::Reduce, sec1::ToEncodedPoint as _,
    },
};
use rand_core_06::{CryptoRng, RngCore};
use sha2::Sha256;
use sha3::{Digest, Sha3_256, Sha3_512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Pinned source used for the Iroha ZK-AMS workflow and relation.
pub const ZK_AMS_SOURCE_PROFILE_V1: &[u8] = b"arxiv:2602.16130v2:algorithms-1-4:appendices-a-c";
/// Exact Iroha Phase-V suite label.
pub const ZK_AMS_LSAG_SUITE_V1: &[u8] = b"iroha-zk-ams-v1:phase-v:lsag-ristretto255-sha3-512";
/// Exact holder-possession suite composed with batch admission.
pub const ZK_AMS_ADMISSION_POSSESSION_SUITE_V1: &[u8] =
    b"iroha-zk-ams-v1:batch-admission:seed-possession-schnorr-ristretto255-sha3-512";
/// Hash-to-Ristretto domain for admitted seed public keys.
pub const ZK_AMS_HASH_TO_POINT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.lsag.hash-to-ristretto";
/// Canonical proof wire version.
pub const ZK_AMS_LSAG_PROOF_VERSION_V1: u8 = 1;
/// Canonical composed batch-admission proof wire version.
pub const ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1: u8 = 1;
/// Canonical holder-possession proof wire version.
pub const ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1: u8 = 1;
#[cfg(any(test, feature = "test-utils", feature = "privacy-release-evidence"))]
/// Smallest closed Phase-V ring.
pub const ZK_AMS_MIN_RING_SIZE_V1: usize = 16;
/// Largest closed Phase-V ring.
pub const ZK_AMS_MAX_RING_SIZE_V1: usize = 64;
/// Exact admitted ring sizes.
pub const ZK_AMS_RING_SIZES_V1: [usize; 3] = [16, 32, 64];
/// Exact maximum canonical Norito size for the closed 64-member LSAG wire.
///
/// The fixed fields occupy 45 bytes and each canonical `[u8; 32]` response
/// occupies 65 bytes in this wire profile: `45 + 64 * 65 = 4_205`.
pub const MAX_ZK_AMS_LSAG_PROOF_BYTES_V1: usize = 4_205;
/// Closed cumulative allocation ceiling for one bounded LSAG wire decode.
pub const ZK_AMS_LSAG_DECODE_ALLOCATION_BYTES_V1: usize = 32 * 1024;
/// Hard cap checked before holder-possession proof decoding.
pub const MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1: usize = 256;
/// Hard cap checked before the composed batch proof is decoded.
pub const MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1: usize =
    MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1
        + ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 * MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1
        + 4 * 1024;
/// Largest atomic admission batch in the first-release profile.
pub const ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1: usize = 8;
/// Sole privacy-action index in a canonical first-release ZK-AMS transaction.
pub const ZK_AMS_PRIVACY_ACTION_INDEX_V1: u32 = ZK_AMS_ACTION_INDEX_V1;
fn validate_zk_ams_binding_v1(binding: &TranscriptBindingV1<'_>) -> Result<(), ZkAmsErrorV1> {
    binding.validate()?;
    if binding.action_index != ZK_AMS_PRIVACY_ACTION_INDEX_V1 {
        return Err(ZkAmsErrorV1::InvalidBinding);
    }
    Ok(())
}
const RANDOM_REJECTION_ATTEMPTS: u32 = 1 << 16;
const TRANSCRIPT_VERSION_V1: u8 = 1;
const GENERATOR_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.generator-digest";
const REGISTRY_TRANSITION_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ams:registry-transition:v1";
const RELATION_PROOF_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-ams:relation-proof:v1";
/// Exact signature-bound transaction fields for one direct ZK-AMS action.
#[derive(Clone, Debug)]
pub struct ZkAmsPrivacyActionTransactionContextV1 {
    /// Exact genesis-header-derived transaction security domain.
    pub network_id: NetworkId,
    /// Exact transaction authority.
    pub authority: AccountId,
    /// Required creation time, resolved once before intent derivation.
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
/// Exact ledger effect certified by a canonical first-release ZK-AMS action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAmsPrivacyActionEffectV1 {
    /// Atomically append one ordered credential batch to the governed registry.
    BatchAdmission,
    /// Atomically create one account and consume one anonymous key image.
    ProvisionAccount,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Pure ZK-AMS proving output ready for transaction signing.
///
/// The payload and canonical genesis binding are private. This type deliberately implements neither
/// `Clone` nor a serialization trait, so the only public production transition is the consuming
/// [`sign_prepared_zk_ams_privacy_action_v1`] boundary.
pub struct ZkAmsPreparedPrivacyActionV1 {
    payload: TransactionPayload,
    canonical_genesis_hash: [u8; 32],
    effect: ZkAmsPrivacyActionEffectV1,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for ZkAmsPreparedPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkAmsPreparedPrivacyActionV1")
            .field("effect", &self.effect)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .finish_non_exhaustive()
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkAmsPreparedPrivacyActionV1 {
    /// Borrow the final revalidated payload for the isolated native release runner.
    #[cfg(feature = "privacy-release-evidence")]
    #[doc(hidden)]
    pub const fn release_evidence_payload_v1(&self) -> &TransactionPayload {
        &self.payload
    }
    /// Exact state effect certified by the prepared action.
    #[must_use]
    pub const fn effect(&self) -> ZkAmsPrivacyActionEffectV1 {
        self.effect
    }
    /// Canonical proof-independent transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical complete typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical proof envelope.
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
}
/// Complete signed result produced by the canonical ZK-AMS action path.
pub struct SignedZkAmsPrivacyActionV1 {
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
    adaptive_signed_transaction_bytes: u32,
    effect: ZkAmsPrivacyActionEffectV1,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
impl core::fmt::Debug for SignedZkAmsPrivacyActionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedZkAmsPrivacyActionV1")
            .field("transaction_hash", &self.transaction_hash)
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .field("effect", &self.effect)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .finish_non_exhaustive()
    }
}
impl SignedZkAmsPrivacyActionV1 {
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
    /// Canonical transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    /// Exact state effect certified by the signed action.
    #[must_use]
    pub const fn effect(&self) -> ZkAmsPrivacyActionEffectV1 {
        self.effect
    }
    /// Canonical proof-independent transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical complete typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical proof envelope.
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
}
/// Governed ZK-AMS fields shared by admission and provisioning statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPrivacyActionGovernanceV1 {
    /// Credential issuer governing the common admission relation.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Canonical compressed P-256 issuer key from authoritative state.
    pub issuer_public_key: PrivacyP256PointV1,
    /// Digest of the authoritative issuer, policy, and key record.
    pub issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1,
    /// Admitted-identity and provisioning registry.
    pub registry_id: PrivacyZkAmsRegistryIdV1,
    /// Digest of the authoritative registry snapshot.
    pub registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1,
    /// Admission policy identifier.
    pub policy_id: PrivacyPolicyIdV1,
    /// Digest of the exact governed admission policy.
    pub policy_digest: PrivacyPolicyDigestV1,
}
/// Failure while constructing or validating a canonical ZK-AMS transaction intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ZkAmsPrivacyActionIntentErrorV1 {
    /// Creation time cannot be represented in the transaction wire.
    #[error("ZK-AMS action creation time cannot be represented in milliseconds")]
    CreationTimeOutOfRange,
    /// TTL cannot be represented in the transaction wire.
    #[error("ZK-AMS action TTL cannot be represented in milliseconds")]
    TimeToLiveOutOfRange,
    /// Fee intent, TTL, or fee metadata violates canonical transaction policy.
    #[error("ZK-AMS action transaction context is not canonical")]
    InvalidTransactionContext,
    /// The locally compiled governed ZK-AMS profile is unavailable.
    #[error("the compiled native ZK-AMS profile is unavailable")]
    CompiledProfileUnavailable,
    /// The statement or its exact compiled context is invalid.
    #[error("the locally produced ZK-AMS statement failed validation")]
    StatementValidation,
    /// The typed statement could not derive its canonical digest.
    #[error("ZK-AMS action statement digest derivation failed")]
    StatementDigest,
    /// The unsigned payload could not derive its canonical privacy intent.
    #[error("ZK-AMS action transaction-intent derivation failed")]
    TransactionIntent,
    /// The final one-action payload did not reproduce the stored intent binding.
    #[error("the locally produced ZK-AMS payload failed intent validation")]
    FinalIntentBinding,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Closed failure for the canonical prove-then-sign ZK-AMS transaction path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkAmsPrivacyActionBuildErrorV1 {
    /// Two-pass transaction-intent construction failed.
    #[error(transparent)]
    Intent(#[from] ZkAmsPrivacyActionIntentErrorV1),
    /// The native relation, possession, or LSAG engine failed.
    #[error(transparent)]
    Native(#[from] ZkAmsErrorV1),
    /// The all-zero genesis sentinel is never a canonical chain binding.
    #[error("ZK-AMS action requires a non-zero canonical genesis hash")]
    ZeroGenesisHash,
    /// The signed transaction domain does not equal the supplied canonical genesis hash.
    #[error("ZK-AMS action transaction network does not match the canonical genesis hash")]
    NetworkIdMismatch,
    /// The typed statement could not derive its canonical digest.
    #[error("ZK-AMS action statement digest derivation failed")]
    StatementDigest,
    /// The typed statement could not be canonically encoded.
    #[error("the locally produced ZK-AMS statement could not be encoded")]
    StatementEncoding,
    /// The complete proof envelope failed intrinsic consensus validation.
    #[error("the locally produced ZK-AMS proof envelope failed validation")]
    EnvelopeValidation,
    /// The complete proof envelope could not be canonically encoded.
    #[error("the locally produced ZK-AMS proof envelope could not be encoded")]
    EnvelopeEncoding,
    /// A bounded canonical byte length did not fit its public result field.
    #[error("a canonical ZK-AMS action byte length overflowed")]
    EncodedLengthOverflow,
    /// The final proved payload did not reproduce the draft-derived intent.
    #[error("the locally produced ZK-AMS payload failed final intent validation")]
    FinalIntentBinding,
    /// The sealed prepared payload no longer matches its integrity record.
    #[error("the prepared ZK-AMS action payload failed integrity validation")]
    PreparedPayloadDrift,
    /// The authority is multisig and cannot use the single-key constructor.
    #[error("the ZK-AMS action authority is not a single-key authority")]
    UnsupportedAuthority,
    /// The supplied private key does not control the exact authority.
    #[error("the supplied ZK-AMS action signing key does not control the authority")]
    AuthorityKeyMismatch,
    /// The transaction signature backend failed without exposing key material.
    #[error("ZK-AMS action transaction signing failed")]
    TransactionSigning,
    /// The signed payload differs from the prepared proof or intent.
    #[error("signed ZK-AMS action differs from the prepared action")]
    SignedIntentMismatch,
}
/// Failure while constructing, decoding, signing, or verifying ZK-AMS Phase V.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkAmsErrorV1 {
    /// A shared consensus transcript field is invalid.
    #[error("invalid ZK-AMS consensus transcript binding")]
    InvalidBinding,
    /// A transcript label or value cannot be represented canonically.
    #[error("ZK-AMS transcript field is too large")]
    TranscriptFieldTooLarge,
    /// A seed public key or key image is malformed, non-canonical, or identity.
    #[error("invalid canonical nonidentity Ristretto255 point")]
    InvalidPoint,
    /// A secret or proof scalar is not canonical.
    #[error("invalid canonical Ristretto255 scalar")]
    InvalidScalar,
    /// A secret seed scalar is zero.
    #[error("ZK-AMS seed secret must be nonzero")]
    ZeroSecret,
    /// The ring is not one of the closed first-release sizes.
    #[error("ZK-AMS ring size {actual} is not one of 16, 32, or 64")]
    InvalidRingSize {
        /// Supplied number of ring members.
        actual: usize,
    },
    /// The ring is not strictly increasing in canonical byte order.
    #[error("ZK-AMS ring must be strictly increasing and duplicate-free")]
    NonCanonicalRing,
    /// The signer index is outside the supplied ring.
    #[error("ZK-AMS signer index {index} is outside ring size {ring_size}")]
    SignerIndexOutOfBounds {
        /// Supplied signer index.
        index: usize,
        /// Supplied ring size.
        ring_size: usize,
    },
    /// The secret key does not derive the selected public ring member.
    #[error("ZK-AMS seed secret does not match the selected ring member")]
    SignerPublicKeyMismatch,
    /// The supplied key image does not derive from the selected seed secret.
    #[error("ZK-AMS key image does not match the selected seed secret")]
    KeyImageMismatch,
    /// The operating-system or caller-supplied cryptographic RNG failed.
    #[error("ZK-AMS cryptographic random source is unavailable")]
    RandomnessUnavailable,
    /// The random source emitted a catastrophic constant or short-period prefix.
    #[error("ZK-AMS cryptographic random source failed its health check")]
    RandomnessHealthCheckFailed,
    /// The random source failed to yield a canonical nonzero scalar.
    #[error("ZK-AMS random scalar rejection sampling exhausted its work bound")]
    RandomnessExhausted,
    /// Proof bytes exceed the dedicated decoder cap.
    #[error("ZK-AMS LSAG proof length {actual} exceeds hard maximum {max}")]
    ProofTooLarge {
        /// Supplied proof bytes.
        actual: usize,
        /// Hard maximum.
        max: usize,
    },
    /// Holder-possession proof bytes exceed the dedicated decoder cap.
    #[error("ZK-AMS admission possession proof length {actual} exceeds hard maximum {max}")]
    PossessionProofTooLarge {
        /// Supplied proof bytes.
        actual: usize,
        /// Hard maximum.
        max: usize,
    },
    /// Exact Norito decode, shape validation, or canonical re-encoding failed.
    #[error("invalid canonical ZK-AMS LSAG proof encoding")]
    InvalidProofEncoding,
    /// The closed LSAG verification equation failed.
    #[error("ZK-AMS LSAG verification failed")]
    VerificationFailed,
    /// The typed statement is not a valid batch-admission statement.
    #[error("invalid typed ZK-AMS batch-admission statement")]
    InvalidStatement,
    /// The transcript binding differs from the complete typed statement.
    #[error("ZK-AMS statement/transcript binding mismatch")]
    BindingMismatch,
    /// Credential witness count or order differs from public anchors.
    #[error("ZK-AMS admission credential witnesses do not match ordered anchors")]
    CredentialMismatch,
    /// A PHC version, hidden field, or identifier is outside the fixed profile.
    #[error("invalid canonical ZK-AMS Personhood Credential")]
    InvalidCredential,
    /// The issuer key is malformed, non-canonical, or identity.
    #[error("invalid canonical ZK-AMS P-256 issuer key")]
    InvalidIssuerKey,
    /// An issuer signature is malformed or does not verify.
    #[error("invalid ZK-AMS issuer ES256 signature")]
    InvalidIssuerSignature,
    /// High-s issuer signatures are forbidden instead of normalized.
    #[error("non-canonical high-s ZK-AMS issuer signature")]
    HighSIssuerSignature,
    /// The declared final registry root is not the exact ordered transition.
    #[error("ZK-AMS ordered registry transition root mismatch")]
    RegistryTransitionMismatch,
    /// Composed batch proof exceeds its pre-decode cap.
    #[error("ZK-AMS batch proof length {actual} exceeds hard maximum {max}")]
    BatchProofTooLarge {
        /// Supplied proof length.
        actual: usize,
        /// Exact hard maximum.
        max: usize,
    },
    /// The native masked relation engine rejected witness, context, or proof.
    #[error("ZK-AMS masked admission relation failed")]
    AdmissionRelation,
}
impl From<P256EngineError> for ZkAmsErrorV1 {
    fn from(_: P256EngineError) -> Self {
        Self::InvalidBinding
    }
}
fn validate_zk_ams_transaction_context_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
) -> Result<(), ZkAmsPrivacyActionIntentErrorV1> {
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(ZkAmsPrivacyActionIntentErrorV1::CreationTimeOutOfRange);
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(ZkAmsPrivacyActionIntentErrorV1::TimeToLiveOutOfRange);
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
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::InvalidTransactionContext)
}
fn zk_ams_statement_context_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id: context.network_id,
        action_index: ZK_AMS_PRIVACY_ACTION_INDEX_V1,
        transaction_intent_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
fn zk_ams_transaction_payload_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, ZkAmsPrivacyActionIntentErrorV1> {
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
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::InvalidTransactionContext)
}
fn zk_ams_intent_projection_envelope_v1(
    statement: IrohaZkAmsStatementV1,
) -> Result<PrivacyProofEnvelopeV1, ZkAmsPrivacyActionIntentErrorV1> {
    let proof = match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(_) => {
            IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(PrivacyProofBytesV1::new(
                Vec::new(),
            ))
        }
        PrivacyZkAmsActionV1::ProvisionAccount(_) => {
            IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
                PrivacyProofBytesV1::new(Vec::new()),
            )
        }
    };
    PrivacyProofEnvelopeV1::bind_v1(
        PrivacyStatementV1::IrohaZkAmsV1(statement),
        PrivacyProofV1::IrohaZkAmsV1(proof),
    )
    .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::StatementDigest)
}
fn zk_ams_statement_v1(
    context: PrivacyStatementContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsActionV1,
) -> IrohaZkAmsStatementV1 {
    IrohaZkAmsStatementV1 {
        context,
        issuer_id: governance.issuer_id,
        issuer_public_key: governance.issuer_public_key,
        issuer_policy_record_digest: governance.issuer_policy_record_digest,
        registry_id: governance.registry_id,
        registry_record_digest: governance.registry_record_digest,
        policy_id: governance.policy_id,
        policy_digest: governance.policy_digest,
        action,
    }
}
fn prepare_zk_ams_privacy_action_transaction_intent_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsActionV1,
) -> Result<IrohaZkAmsStatementV1, ZkAmsPrivacyActionIntentErrorV1> {
    let profile =
        crate::privacy_profiles::compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
            .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    prepare_zk_ams_privacy_action_transaction_intent_with_profile_v1(
        context, governance, action, profile,
    )
}
fn prepare_zk_ams_privacy_action_transaction_intent_with_profile_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsActionV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
) -> Result<IrohaZkAmsStatementV1, ZkAmsPrivacyActionIntentErrorV1> {
    validate_zk_ams_transaction_context_v1(context)?;
    let draft_statement = zk_ams_statement_v1(
        zk_ams_statement_context_v1(
            context,
            profile,
            PrivacyTransactionIntentDigestV1::new([0; 32]),
        ),
        governance,
        action,
    );
    let draft_envelope = zk_ams_intent_projection_envelope_v1(draft_statement.clone())?;
    let transaction_intent_digest = zk_ams_transaction_payload_v1(context, draft_envelope)?
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::TransactionIntent)?;
    let mut final_statement = draft_statement;
    final_statement.context.transaction_intent_digest = transaction_intent_digest;
    let validated = validate_zk_ams_privacy_action_transaction_intent_with_profile_v1(
        context,
        &final_statement,
        profile,
    )?;
    if validated != transaction_intent_digest {
        return Err(ZkAmsPrivacyActionIntentErrorV1::FinalIntentBinding);
    }
    Ok(final_statement)
}
/// Construct a canonical single-action ZK-AMS batch-admission statement and
/// derive its proof-independent transaction-intent digest.
///
/// # Errors
///
/// Returns a closed error for an invalid transaction context, unavailable
/// compiled profile, invalid typed action, or final binding drift.
pub fn prepare_zk_ams_batch_admission_transaction_intent_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsBatchAdmissionV1,
) -> Result<IrohaZkAmsStatementV1, ZkAmsPrivacyActionIntentErrorV1> {
    prepare_zk_ams_privacy_action_transaction_intent_v1(
        context,
        governance,
        PrivacyZkAmsActionV1::BatchAdmission(action),
    )
}
/// Construct a canonical single-action ZK-AMS account-provisioning statement
/// and derive its proof-independent transaction-intent digest.
///
/// # Errors
///
/// Returns a closed error for an invalid transaction context, unavailable
/// compiled profile, invalid typed action, or final binding drift.
pub fn prepare_zk_ams_provision_account_transaction_intent_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsProvisionAccountV1,
) -> Result<IrohaZkAmsStatementV1, ZkAmsPrivacyActionIntentErrorV1> {
    prepare_zk_ams_privacy_action_transaction_intent_v1(
        context,
        governance,
        PrivacyZkAmsActionV1::ProvisionAccount(action),
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Validate a prepared ZK-AMS statement against its exact single-action
/// transaction context and return the canonical transaction-intent digest.
///
/// The local proof-empty envelope exists only long enough to reproduce the proof-independent
/// data-model projection. It cannot escape this helper or be submitted as an incomplete proof.
///
/// # Errors
///
/// Returns a closed error for an invalid context or statement, compiled-profile
/// drift, canonical encoding failure, or any final intent/digest mismatch.
pub fn validate_zk_ams_privacy_action_transaction_intent_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    statement: &IrohaZkAmsStatementV1,
) -> Result<PrivacyTransactionIntentDigestV1, ZkAmsPrivacyActionIntentErrorV1> {
    let profile =
        crate::privacy_profiles::compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
            .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    validate_zk_ams_privacy_action_transaction_intent_with_profile_v1(context, statement, profile)
}
fn validate_zk_ams_privacy_action_transaction_intent_with_profile_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    statement: &IrohaZkAmsStatementV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
) -> Result<PrivacyTransactionIntentDigestV1, ZkAmsPrivacyActionIntentErrorV1> {
    validate_zk_ams_transaction_context_v1(context)?;
    let expected_context = zk_ams_statement_context_v1(
        context,
        profile,
        statement.context.transaction_intent_digest,
    );
    if statement.context != expected_context {
        return Err(ZkAmsPrivacyActionIntentErrorV1::StatementValidation);
    }
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    typed_statement
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::StatementValidation)?;
    let envelope = zk_ams_intent_projection_envelope_v1(statement.clone())?;
    let validated = zk_ams_transaction_payload_v1(context, envelope)?
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::FinalIntentBinding)?;
    if validated != statement.context.transaction_intent_digest {
        return Err(ZkAmsPrivacyActionIntentErrorV1::FinalIntentBinding);
    }
    Ok(validated)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Copy)]
struct ZkAmsPrivacyActionIntegrityV1 {
    canonical_genesis_hash: [u8; 32],
    effect: ZkAmsPrivacyActionEffectV1,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl ZkAmsPreparedPrivacyActionV1 {
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    const fn integrity(&self) -> ZkAmsPrivacyActionIntegrityV1 {
        ZkAmsPrivacyActionIntegrityV1 {
            canonical_genesis_hash: self.canonical_genesis_hash,
            effect: self.effect,
            transaction_intent_digest: self.transaction_intent_digest,
            statement_digest: self.statement_digest,
            proof_envelope_hash: self.proof_envelope_hash,
            statement_bytes: self.statement_bytes,
            proof_bytes: self.proof_bytes,
            encoded_proof_envelope_bytes: self.encoded_proof_envelope_bytes,
        }
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn zk_ams_action_binding_v1<'a>(
    statement: &'a IrohaZkAmsStatementV1,
    canonical_genesis_hash: [u8; 32],
    statement_digest: PrivacyStatementDigestV1,
) -> TranscriptBindingV1<'a> {
    TranscriptBindingV1 {
        network_id: statement.context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
        action_index: statement.context.action_index,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *statement.context.parameter_id.as_bytes(),
        parameter_digest: *statement.context.parameter_digest.as_bytes(),
        verifier_digest: *statement.context.verifier_digest.as_bytes(),
        statement_schema_digest: *statement.context.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *statement.context.engine_manifest_digest.as_bytes(),
        generator_digest: zk_ams_generator_digest_v1(),
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_zk_ams_signing_authority_v1(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), ZkAmsPrivacyActionBuildErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or(ZkAmsPrivacyActionBuildErrorV1::UnsupportedAuthority)?;
    let derived = PublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(ZkAmsPrivacyActionBuildErrorV1::AuthorityKeyMismatch);
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_zk_ams_payload_integrity_v1(
    payload: &TransactionPayload,
    expected: ZkAmsPrivacyActionIntegrityV1,
) -> Result<(), ()> {
    if expected.canonical_genesis_hash == [0; 32] {
        return Err(());
    }
    match payload.instructions() {
        Executable::Instructions(instructions)
            if instructions.len() == 1
                && instructions[0]
                    .as_any()
                    .downcast_ref::<SubmitPrivacyProofV1>()
                    .is_some() => {}
        _ => return Err(()),
    }
    if payload.attachments.is_some() {
        return Err(());
    }
    let (intent, submission) = payload
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| ())?
        .ok_or(())?;
    if intent.as_bytes() != &expected.transaction_intent_digest {
        return Err(());
    }
    let envelope = &submission.envelope;
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ())?;
    if envelope.protocol_id != PrivacyProtocolIdV1::IrohaZkAmsV1
        || envelope.statement_digest.as_bytes() != &expected.statement_digest
    {
        return Err(());
    }
    let PrivacyStatementV1::IrohaZkAmsV1(statement) = &envelope.statement else {
        return Err(());
    };
    if statement.context.action_index != ZK_AMS_PRIVACY_ACTION_INDEX_V1
        || statement.context.transaction_intent_digest.as_bytes()
            != &expected.transaction_intent_digest
    {
        return Err(());
    }
    let statement_digest = envelope.statement.digest().map_err(|_| ())?;
    if statement_digest.as_bytes() != &expected.statement_digest {
        return Err(());
    }
    let statement_encoding = norito::to_bytes(&envelope.statement).map_err(|_| ())?;
    if u32::try_from(statement_encoding.len()).map_err(|_| ())? != expected.statement_bytes {
        return Err(());
    }
    let proof_bytes = match (&statement.action, &envelope.proof, expected.effect) {
        (
            PrivacyZkAmsActionV1::BatchAdmission(_),
            PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
                proof,
            )),
            ZkAmsPrivacyActionEffectV1::BatchAdmission,
        ) => proof.as_bytes(),
        (
            PrivacyZkAmsActionV1::ProvisionAccount(_),
            PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
                proof,
            )),
            ZkAmsPrivacyActionEffectV1::ProvisionAccount,
        ) => proof.as_bytes(),
        _ => return Err(()),
    };
    if u32::try_from(proof_bytes.len()).map_err(|_| ())? != expected.proof_bytes {
        return Err(());
    }
    let binding =
        zk_ams_action_binding_v1(statement, expected.canonical_genesis_hash, statement_digest);
    match expected.effect {
        ZkAmsPrivacyActionEffectV1::BatchAdmission => {
            verify_zk_ams_batch_admission_v1(statement, &binding, proof_bytes).map_err(|_| ())?;
        }
        ZkAmsPrivacyActionEffectV1::ProvisionAccount => {
            verify_zk_ams_provision_statement_v1(statement, &binding, proof_bytes)
                .map_err(|_| ())?;
        }
    }
    let envelope_encoding = norito::to_bytes(envelope).map_err(|_| ())?;
    if u32::try_from(envelope_encoding.len()).map_err(|_| ())?
        != expected.encoded_proof_envelope_bytes
        || *Hash::new(&envelope_encoding).as_ref() != expected.proof_envelope_hash
    {
        return Err(());
    }
    Ok(())
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn finalize_zk_ams_prepared_action_v1(
    context: &ZkAmsPrivacyActionTransactionContextV1,
    statement: IrohaZkAmsStatementV1,
    statement_digest: PrivacyStatementDigestV1,
    proof: IrohaZkAmsProofV1,
    canonical_genesis_hash: [u8; 32],
    effect: ZkAmsPrivacyActionEffectV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
) -> Result<ZkAmsPreparedPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1> {
    let proof_bytes = match &proof {
        IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(proof)
        | IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(proof) => {
            u32::try_from(proof.as_bytes().len())
                .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EncodedLengthOverflow)?
        }
    };
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement);
    typed_statement
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    if typed_statement
        .digest()
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::StatementDigest)?
        != statement_digest
    {
        return Err(ZkAmsPrivacyActionBuildErrorV1::StatementDigest);
    }
    let statement_bytes = u32::try_from(
        norito::to_bytes(&typed_statement)
            .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::StatementEncoding)?
            .len(),
    )
    .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let final_envelope =
        PrivacyProofEnvelopeV1::bind_v1(typed_statement, PrivacyProofV1::IrohaZkAmsV1(proof))
            .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(ZkAmsPrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    final_envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let envelope_encoding = norito::to_bytes(&final_envelope)
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EnvelopeEncoding)?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let final_payload = zk_ams_transaction_payload_v1(context, final_envelope)?;
    let transaction_intent_digest = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::FinalIntentBinding)?;
    let prepared = ZkAmsPreparedPrivacyActionV1 {
        payload: final_payload,
        canonical_genesis_hash,
        effect,
        transaction_intent_digest: *transaction_intent_digest.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
    };
    validate_zk_ams_payload_integrity_v1(&prepared.payload, prepared.integrity())
        .map_err(|()| ZkAmsPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    Ok(prepared)
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Prepare and prove one canonical ordered ZK-AMS batch admission.
///
/// The function owns the complete transaction context and public action while
/// borrowing secret witnesses only for the duration of native proving. It
/// returns one sealed, non-cloneable final payload.
///
/// # Errors
///
/// Returns a closed intent, transcript, witness, native-proof, encoding, or
/// self-verification failure.
pub fn prepare_zk_ams_batch_admission_privacy_action_with_rng_v1<R>(
    context: ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsBatchAdmissionV1,
    witnesses: &[ZkAmsBatchCredentialWitnessV1<'_>],
    config: ZkAmsMaskedProverConfigV1,
    canonical_genesis_hash: [u8; 32],
    rng: &mut R,
) -> Result<ZkAmsPreparedPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(ZkAmsPrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(ZkAmsPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    let profile =
        crate::privacy_profiles::compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
            .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    let statement = prepare_zk_ams_privacy_action_transaction_intent_with_profile_v1(
        &context,
        governance,
        PrivacyZkAmsActionV1::BatchAdmission(action),
        profile,
    )?;
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::StatementDigest)?;
    let binding = zk_ams_action_binding_v1(&statement, canonical_genesis_hash, statement_digest);
    let proof = prove_zk_ams_batch_admission_v1(&statement, &binding, witnesses, config, rng)?;
    finalize_zk_ams_prepared_action_v1(
        &context,
        statement,
        statement_digest,
        IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(PrivacyProofBytesV1::new(proof)),
        canonical_genesis_hash,
        ZkAmsPrivacyActionEffectV1::BatchAdmission,
        profile,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Prepare and prove one canonical ZK-AMS anonymous account provisioning action.
///
/// # Errors
///
/// Returns a closed intent, transcript, ring, key-image, native-proof,
/// encoding, or self-verification failure.
pub fn prepare_zk_ams_provision_privacy_action_with_rng_v1<R>(
    context: ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsProvisionAccountV1,
    signer_index: usize,
    secret: &ZkAmsSeedSecretV1,
    canonical_genesis_hash: [u8; 32],
    rng: &mut R,
) -> Result<ZkAmsPreparedPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(ZkAmsPrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(ZkAmsPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    let profile =
        crate::privacy_profiles::compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
            .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable)?;
    prepare_zk_ams_provision_privacy_action_with_rng_and_profile_v1(
        context,
        governance,
        action,
        signer_index,
        secret,
        canonical_genesis_hash,
        profile,
        rng,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn prepare_zk_ams_provision_privacy_action_with_rng_and_profile_v1<R>(
    context: ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsProvisionAccountV1,
    signer_index: usize,
    secret: &ZkAmsSeedSecretV1,
    canonical_genesis_hash: [u8; 32],
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
    rng: &mut R,
) -> Result<ZkAmsPreparedPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(ZkAmsPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    let statement = prepare_zk_ams_privacy_action_transaction_intent_with_profile_v1(
        &context,
        governance,
        PrivacyZkAmsActionV1::ProvisionAccount(action),
        profile,
    )?;
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::StatementDigest)?;
    let binding = zk_ams_action_binding_v1(&statement, canonical_genesis_hash, statement_digest);
    let proof =
        sign_zk_ams_provision_statement_v1(&statement, &binding, signer_index, secret, rng)?;
    finalize_zk_ams_prepared_action_v1(
        &context,
        statement,
        statement_digest,
        IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(PrivacyProofBytesV1::new(proof)),
        canonical_genesis_hash,
        ZkAmsPrivacyActionEffectV1::ProvisionAccount,
        profile,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
/// Consume and sign a payload returned by the canonical ZK-AMS prover.
///
/// The complete proof, statement, envelope hash, genesis binding, and proof-independent intent are
/// revalidated immediately before and after signing.
///
/// # Errors
///
/// Returns a closed failure for prepared drift, unsupported authority,
/// authority/key mismatch, signing failure, or post-sign drift.
pub fn sign_prepared_zk_ams_privacy_action_v1(
    prepared: ZkAmsPreparedPrivacyActionV1,
    private_key: &PrivateKey,
) -> Result<SignedZkAmsPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1> {
    validate_zk_ams_signing_authority_v1(prepared.payload.authority(), private_key)?;
    let integrity = prepared.integrity();
    validate_zk_ams_payload_integrity_v1(&prepared.payload, integrity)
        .map_err(|()| ZkAmsPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    let signed_transaction = TransactionBuilder::from_payload(prepared.payload)
        .map_err(|_| ZkAmsPrivacyActionIntentErrorV1::InvalidTransactionContext)?
        .try_sign(private_key)
        .map_err(|error| match error {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                ZkAmsPrivacyActionBuildErrorV1::UnsupportedAuthority
            }
            TransactionSignatureError::AuthorityKeyMismatch => {
                ZkAmsPrivacyActionBuildErrorV1::AuthorityKeyMismatch
            }
            TransactionSignatureError::InvalidFeePaymentIntent(_) => {
                ZkAmsPrivacyActionIntentErrorV1::InvalidTransactionContext.into()
            }
            _ => ZkAmsPrivacyActionBuildErrorV1::TransactionSigning,
        })?;
    validate_zk_ams_payload_integrity_v1(signed_transaction.payload(), integrity)
        .map_err(|()| ZkAmsPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    let transaction_hash = *signed_transaction.hash().as_ref();
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed_transaction).len())
            .map_err(|_| ZkAmsPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    Ok(SignedZkAmsPrivacyActionV1 {
        signed_transaction,
        transaction_hash,
        adaptive_signed_transaction_bytes,
        effect: integrity.effect,
        transaction_intent_digest: integrity.transaction_intent_digest,
        statement_digest: integrity.statement_digest,
        proof_envelope_hash: integrity.proof_envelope_hash,
        statement_bytes: integrity.statement_bytes,
        proof_bytes: integrity.proof_bytes,
        encoded_proof_envelope_bytes: integrity.encoded_proof_envelope_bytes,
    })
}
#[cfg(test)]
/// Build, prove, bind, and sign one canonical ZK-AMS provisioning action.
///
/// Authority validation precedes all proof work.
///
/// # Errors
///
/// Returns a closed validation, proving, binding, or signing failure.
pub fn build_signed_zk_ams_provision_privacy_action_with_rng_v1<R>(
    context: ZkAmsPrivacyActionTransactionContextV1,
    governance: ZkAmsPrivacyActionGovernanceV1,
    action: PrivacyZkAmsProvisionAccountV1,
    signer_index: usize,
    secret: &ZkAmsSeedSecretV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<SignedZkAmsPrivacyActionV1, ZkAmsPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    validate_zk_ams_signing_authority_v1(&context.authority, private_key)?;
    let prepared = prepare_zk_ams_provision_privacy_action_with_rng_v1(
        context,
        governance,
        action,
        signer_index,
        secret,
        canonical_genesis_hash,
        rng,
    )?;
    sign_prepared_zk_ams_privacy_action_v1(prepared, private_key)
}
/// Zeroizing canonical little-endian Ristretto scalar used as a seed secret.
pub struct ZkAmsSeedSecretV1 {
    bytes: Zeroizing<[u8; 32]>,
}
impl ZkAmsSeedSecretV1 {
    /// Parse one canonical nonzero seed secret.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical or zero scalar.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ZkAmsErrorV1> {
        Self::from_zeroizing_bytes(Zeroizing::new(bytes))
    }
    fn from_zeroizing_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, ZkAmsErrorV1> {
        let scalar = Zeroizing::new(scalar_from_canonical(*bytes)?);
        if *scalar == Scalar::ZERO {
            return Err(ZkAmsErrorV1::ZeroSecret);
        }
        Ok(Self { bytes })
    }
    /// Sample one unbiased canonical nonzero scalar.
    ///
    /// # Errors
    ///
    /// Returns an error when the random source does not produce an admitted
    /// canonical scalar within the fixed work bound.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, ZkAmsErrorV1> {
        let mut checked_rng = health_checked_zk_ams_rng_v1(rng)?;
        let scalar = Zeroizing::new(random_nonzero_scalar(&mut checked_rng)?);
        Self::from_zeroizing_bytes(Zeroizing::new(scalar.to_bytes()))
    }
    fn expose_scalar(&self) -> Zeroizing<Scalar> {
        Zeroizing::new(
            scalar_from_canonical(*self.bytes)
                .expect("ZK-AMS seed secret was validated at construction"),
        )
    }
}
impl core::fmt::Debug for ZkAmsSeedSecretV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkAmsSeedSecretV1([REDACTED])")
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::zk_ams::ZkAmsLsagProofWireV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
struct ZkAmsLsagProofWireV1 {
    version: u8,
    initial_challenge: [u8; 32],
    responses: Vec<[u8; 32]>,
}
impl Zeroize for ZkAmsLsagProofWireV1 {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.initial_challenge.zeroize();
        self.responses.zeroize();
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::zk_ams::ZkAmsAdmissionPossessionProofWireV1")]
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
struct ZkAmsAdmissionPossessionProofWireV1 {
    version: u8,
    commitment: [u8; 32],
    response: [u8; 32],
}
impl ZkAmsAdmissionPossessionProofWireV1 {
    /// Exact all-zero sentinel for an unused fixed batch slot.
    const UNUSED: Self = Self {
        version: 0,
        commitment: [0; 32],
        response: [0; 32],
    };
    fn is_unused(self) -> bool {
        self == Self::UNUSED
    }
}
impl Zeroize for ZkAmsAdmissionPossessionProofWireV1 {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.commitment.zeroize();
        self.response.zeroize();
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::privacy_engines::zk_ams::ZkAmsBatchAdmissionProofWireV1")]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
struct ZkAmsBatchAdmissionProofWireV1 {
    version: u8,
    relation_proof: Vec<u8>,
    possession_proof_count: u8,
    possession_proofs: [ZkAmsAdmissionPossessionProofWireV1; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1],
}
struct PreflightedZkAmsAdmissionPossessionV1 {
    public: RistrettoPoint,
    commitment: RistrettoPoint,
    response: Scalar,
}
impl Zeroize for ZkAmsBatchAdmissionProofWireV1 {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.relation_proof.zeroize();
        self.possession_proof_count.zeroize();
        self.possession_proofs.zeroize();
    }
}
fn zk_ams_lsag_decode_limits(ring_size: usize, payload_len: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        ring_size,
        payload_len,
        ring_size,
        ZK_AMS_LSAG_DECODE_ALLOCATION_BYTES_V1,
        8,
    )
}
fn zk_ams_possession_decode_limits(payload_len: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        0,
        payload_len,
        0,
        MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1.saturating_mul(4),
        8,
    )
}
fn zk_ams_batch_decode_limits(payload_len: usize) -> norito::DecodeLimits {
    // The only variable-length member is the masked-relation byte string.
    // Possession proofs occupy a fixed eight-slot value array with an explicit
    // count and canonical unused sentinel, so no nested attacker-selected
    // vector count can amplify allocation.
    norito::DecodeLimits::new(
        MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
        payload_len,
        MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1,
        MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1.saturating_mul(4),
        16,
    )
}
fn preflight_zk_ams_batch_admission_proof_size_v1(proof_bytes: &[u8]) -> Result<(), ZkAmsErrorV1> {
    if proof_bytes.len() > MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::BatchProofTooLarge {
            actual: proof_bytes.len(),
            max: MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1,
        });
    }
    Ok(())
}
fn decode_zk_ams_batch_admission_wire_v1(
    proof_bytes: &[u8],
    expected_possession_proof_count: usize,
) -> Result<ZkAmsBatchAdmissionProofWireV1, ZkAmsErrorV1> {
    preflight_zk_ams_batch_admission_proof_size_v1(proof_bytes)?;
    if expected_possession_proof_count > ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    let proof =
        norito::codec::decode_exact_from_slice_with_limits::<ZkAmsBatchAdmissionProofWireV1>(
            proof_bytes,
            zk_ams_batch_decode_limits(proof_bytes.len()),
        )
        .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    let count = usize::from(proof.possession_proof_count);
    if proof.version != ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1
        || count != expected_possession_proof_count
        || count > ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1
        || proof.possession_proofs[..count]
            .iter()
            .any(|possession| possession.version != ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1)
        || proof.possession_proofs[count..]
            .iter()
            .copied()
            .any(|possession| !possession.is_unused())
        || norito::codec::encode_adaptive(&proof) != proof_bytes
    {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    Ok(proof)
}
#[cfg(feature = "privacy-release-evidence")]
#[doc(hidden)]
pub fn zk_ams_batch_admission_adversarial_wires_v1(
    canonical_proof_bytes: &[u8],
    expected_possession_proof_count: usize,
) -> Result<Vec<Vec<u8>>, ZkAmsErrorV1> {
    let canonical = decode_zk_ams_batch_admission_wire_v1(
        canonical_proof_bytes,
        expected_possession_proof_count,
    )?;
    let mut mutations = Vec::new();
    mutations
        .try_reserve_exact(5)
        .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    let mut wrong_version = canonical.clone();
    wrong_version.version ^= 1;
    mutations.push(norito::codec::encode_adaptive(&wrong_version));
    let mut zero_count = canonical.clone();
    zero_count.possession_proof_count = 0;
    mutations.push(norito::codec::encode_adaptive(&zero_count));
    let mut excessive_count = canonical.clone();
    excessive_count.possession_proof_count = u8::try_from(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 + 1)
        .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    mutations.push(norito::codec::encode_adaptive(&excessive_count));
    if expected_possession_proof_count == 0 {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    let mut used_zero_sentinel = canonical.clone();
    used_zero_sentinel.possession_proofs[0] = ZkAmsAdmissionPossessionProofWireV1::UNUSED;
    mutations.push(norito::codec::encode_adaptive(&used_zero_sentinel));
    if expected_possession_proof_count < ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 {
        let mut nonzero_unused_tail = canonical;
        nonzero_unused_tail.possession_proofs[expected_possession_proof_count].commitment[0] ^= 1;
        mutations.push(norito::codec::encode_adaptive(&nonzero_unused_tail));
    }
    if mutations.iter().any(|mutation| {
        mutation == canonical_proof_bytes
            || mutation.len() > MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1
    }) {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    Ok(mutations)
}
fn decode_zk_ams_possession_wire_v1(
    proof_bytes: &[u8],
) -> Result<ZkAmsAdmissionPossessionProofWireV1, ZkAmsErrorV1> {
    if proof_bytes.len() > MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::PossessionProofTooLarge {
            actual: proof_bytes.len(),
            max: MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1,
        });
    }
    let proof =
        norito::codec::decode_exact_from_slice_with_limits::<ZkAmsAdmissionPossessionProofWireV1>(
            proof_bytes,
            zk_ams_possession_decode_limits(proof_bytes.len()),
        )
        .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    if proof.version != ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1
        || norito::codec::encode_adaptive(&proof) != proof_bytes
    {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    Ok(proof)
}
/// Borrowed secret material for one ordered admission anchor.
pub struct ZkAmsBatchCredentialWitnessV1<'a> {
    credential: &'a PrivacyZkAmsPersonhoodCredentialV1,
    issuer_signature: &'a [u8; 64],
    seed_secret: &'a ZkAmsSeedSecretV1,
}
impl<'a> ZkAmsBatchCredentialWitnessV1<'a> {
    /// Construct a borrowed admission witness. Exact credential, signature,
    /// anchor, and seed-key consistency is checked by the prover.
    #[must_use]
    pub const fn new(
        credential: &'a PrivacyZkAmsPersonhoodCredentialV1,
        issuer_signature: &'a [u8; 64],
        seed_secret: &'a ZkAmsSeedSecretV1,
    ) -> Self {
        Self {
            credential,
            issuer_signature,
            seed_secret,
        }
    }
}
impl core::fmt::Debug for ZkAmsBatchCredentialWitnessV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkAmsBatchCredentialWitnessV1([REDACTED])")
    }
}
struct ZkAmsIssuerSignatureWitnessV1 {
    r: Zeroizing<[u8; 32]>,
    s: Zeroizing<[u8; 32]>,
    recovery_x: Zeroizing<[u8; 32]>,
    recovery_y: Zeroizing<[u8; 32]>,
}
/// Atomic state effect certified by a complete batch-admission proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedZkAmsBatchAdmissionV1 {
    /// Credential issuer namespace.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Admission policy namespace.
    pub policy_id: PrivacyPolicyIdV1,
    /// Governed policy digest that runtime must match authoritatively.
    pub policy_digest: PrivacyPolicyDigestV1,
    /// Authoritative issuer/policy record digest to match.
    pub issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1,
    /// Admitted-identity registry namespace.
    pub registry_id: PrivacyZkAmsRegistryIdV1,
    /// Authoritative prior registry-record digest to match.
    pub registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1,
    /// Exact current registry root.
    pub current_root: PrivacyRootV1,
    /// Epoch of `current_root`.
    pub current_epoch: u64,
    /// Exact resulting registry root.
    pub next_root: PrivacyRootV1,
    /// Successor epoch of `next_root`.
    pub next_epoch: u64,
    /// Ordered anchors to insert atomically after duplicate-state checks.
    pub anchors: Vec<PrivacyZkAmsAdmissionAnchorV1>,
}
/// Atomic state effect certified by one anonymous account-provisioning proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedZkAmsProvisionAccountV1 {
    /// Credential issuer namespace.
    pub issuer_id: PrivacyIssuerIdV1,
    /// Admission policy namespace.
    pub policy_id: PrivacyPolicyIdV1,
    /// Governed policy digest runtime must match authoritatively.
    pub policy_digest: PrivacyPolicyDigestV1,
    /// Authoritative issuer/key/policy record digest.
    pub issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1,
    /// Admitted-identity registry namespace.
    pub registry_id: PrivacyZkAmsRegistryIdV1,
    /// Authoritative current registry-snapshot record digest.
    pub registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1,
    /// Exact current admitted-identity root.
    pub current_root: PrivacyRootV1,
    /// Exact current admitted-identity epoch.
    pub current_epoch: u64,
    /// Strictly ordered seed-key anonymity ring.
    pub ring: Vec<PrivacyZkAmsSeedPublicKeyV1>,
    /// Fresh target account to create and bind atomically.
    pub account_id: AccountId,
    /// Deterministic one-time provisioning replay marker.
    pub key_image: PrivacyZkAmsKeyImageV1,
}
/// Derive the canonical admitted seed public key.
#[must_use]
pub fn zk_ams_seed_public_key_v1(secret: &ZkAmsSeedSecretV1) -> [u8; 32] {
    let secret_scalar = secret.expose_scalar();
    (*secret_scalar * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes()
}
/// Derive the deterministic Phase-V key image used as a replay nullifier.
///
/// # Errors
///
/// Returns an error only if the derived point is the identity, a
/// cryptographically negligible event that is nevertheless rejected.
pub fn zk_ams_key_image_v1(secret: &ZkAmsSeedSecretV1) -> Result<[u8; 32], ZkAmsErrorV1> {
    let public = zk_ams_seed_public_key_v1(secret);
    let hash_point = hash_public_key_to_point(&public)?;
    let secret_scalar = secret.expose_scalar();
    let key_image = *secret_scalar * hash_point;
    if key_image == RistrettoPoint::identity() {
        return Err(ZkAmsErrorV1::InvalidPoint);
    }
    Ok(key_image.compress().to_bytes())
}
/// Return the digest of the exact Ristretto generator and hash-to-point suite.
#[must_use]
pub fn zk_ams_generator_digest_v1() -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(GENERATOR_DIGEST_DOMAIN_V1);
    hash.update(ZK_AMS_LSAG_SUITE_V1);
    hash.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hash.update(ZK_AMS_HASH_TO_POINT_DOMAIN_V1);
    hash.update(iroha_zkp_halo2::vega::zk_ams_t256_generator_digest_v1());
    hash.finalize().into()
}
/// Compute the exact ordered registry root after one public anchor.
#[must_use]
pub fn zk_ams_registry_transition_root_v1(
    registry_id: PrivacyZkAmsRegistryIdV1,
    prior_root: PrivacyRootV1,
    current_epoch: u64,
    next_epoch: u64,
    batch_size: u32,
    anchor_index: u32,
    anchor: PrivacyZkAmsAdmissionAnchorV1,
) -> PrivacyRootV1 {
    let mut hash = Sha256::new();
    hash.update(REGISTRY_TRANSITION_DOMAIN_V1);
    hash.update(registry_id.as_bytes());
    hash.update(prior_root.as_bytes());
    hash.update(current_epoch.to_be_bytes());
    hash.update(next_epoch.to_be_bytes());
    hash.update(batch_size.to_be_bytes());
    hash.update(anchor_index.to_be_bytes());
    hash.update(anchor.phc_hash.as_bytes());
    hash.update(anchor.seed_public_key.as_bytes());
    PrivacyRootV1::new(hash.finalize().into())
}
/// Prove one complete ordered ZK-AMS credential-admission batch.
///
/// The returned envelope contains the masked relaxed-R1CS proof plus one transcript-bound Ristretto
/// Schnorr possession proof per anchor. The prover runs the public verifier before releasing bytes.
///
/// # Errors
///
/// Fails closed for statement/binding drift, malformed credentials or low-s signatures, seed
/// mismatch, root-transition mismatch, random failure, or native relation failure.
pub fn prove_zk_ams_batch_admission_v1<R: CryptoRng + RngCore>(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
    witnesses: &[ZkAmsBatchCredentialWitnessV1<'_>],
    config: ZkAmsMaskedProverConfigV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    let (public_inputs, issuer_key) = build_admission_public_inputs(statement, binding)?;
    if witnesses.len() != public_inputs.len() {
        return Err(ZkAmsErrorV1::CredentialMismatch);
    }
    let batch = batch_action(statement)?;
    let mut signatures = Vec::with_capacity(witnesses.len());
    for ((witness, public), anchor) in witnesses
        .iter()
        .zip(public_inputs.iter())
        .zip(batch.anchors.iter())
    {
        validate_credential_witness(statement, anchor, witness)?;
        signatures.push(validate_issuer_signature(
            witness.issuer_signature,
            public.phc_hash,
            &issuer_key,
        )?);
    }
    let relation_witnesses = witnesses
        .iter()
        .zip(&signatures)
        .map(|(witness, signature)| {
            ZkAmsAdmissionRelationWitnessV1::new(
                witness.credential.subject_commitment.as_bytes(),
                witness.credential.credential_nonce.as_bytes(),
                &signature.r,
                &signature.s,
                &signature.recovery_x,
                &signature.recovery_y,
            )
            .map_err(|_| ZkAmsErrorV1::InvalidCredential)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relation_context = relation_context(binding);
    let mut checked_rng = health_checked_zk_ams_rng_v1(rng)?;
    let (relation_result, randomness_unavailable) = {
        let mut adapter = MaskedRandomAdapter {
            source: &mut checked_rng,
            randomness_unavailable: false,
        };
        let result = prove_zk_ams_admission_relation_v1(
            &relation_context,
            &public_inputs,
            &relation_witnesses,
            config,
            &mut adapter,
        );
        (result, adapter.randomness_unavailable)
    };
    let relation_proof = match relation_result {
        Ok(proof) => proof,
        Err(_) if randomness_unavailable => return Err(ZkAmsErrorV1::RandomnessUnavailable),
        Err(_) => return Err(ZkAmsErrorV1::AdmissionRelation),
    };
    let relation_digest = relation_proof_digest(&relation_proof);
    let encoded_possession_proofs = witnesses
        .iter()
        .zip(batch.anchors.iter())
        .enumerate()
        .map(|(index, (witness, anchor))| {
            prove_zk_ams_admission_possession_with_rng_v1(
                binding,
                u32::try_from(index).expect("batch is bounded to eight"),
                *anchor.phc_hash.as_bytes(),
                *anchor.seed_public_key.as_bytes(),
                relation_digest,
                witness.seed_secret,
                &mut checked_rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let possession_proof_count = u8::try_from(encoded_possession_proofs.len())
        .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    let mut possession_proofs =
        [ZkAmsAdmissionPossessionProofWireV1::UNUSED; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1];
    for (slot, encoded) in possession_proofs.iter_mut().zip(encoded_possession_proofs) {
        *slot = decode_zk_ams_possession_wire_v1(&encoded)?;
    }
    let proof = Zeroizing::new(ZkAmsBatchAdmissionProofWireV1 {
        version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
        relation_proof,
        possession_proof_count,
        possession_proofs,
    });
    let encoded = Zeroizing::new(norito::codec::encode_adaptive(&*proof));
    if encoded.len() > MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::BatchProofTooLarge {
            actual: encoded.len(),
            max: MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1,
        });
    }
    verify_zk_ams_batch_admission_v1(statement, binding, encoded.as_slice())?;
    Ok(encoded.to_vec())
}
/// Verify the complete batch composition and return one atomic state effect.
///
/// Runtime must still match the returned issuer/policy and registry record
/// digests against authoritative state and reject any already-admitted PHC or
/// seed key before applying all anchors atomically.
///
/// # Errors
///
/// Oversized input is rejected before Norito. Exact decoding, relation verification, every
/// possession proof, and the final transition root must all succeed before an effect is returned.
pub fn verify_zk_ams_batch_admission_v1(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
    proof_bytes: &[u8],
) -> Result<VerifiedZkAmsBatchAdmissionV1, ZkAmsErrorV1> {
    preflight_zk_ams_batch_admission_proof_size_v1(proof_bytes)?;
    let (public_inputs, _) = build_admission_public_inputs(statement, binding)?;
    let batch = batch_action(statement)?;
    let anchor_count = batch.anchors.len();
    let proof = decode_zk_ams_batch_admission_wire_v1(proof_bytes, anchor_count)?;
    let preflighted_possessions = batch
        .anchors
        .iter()
        .zip(&proof.possession_proofs[..anchor_count])
        .map(|(anchor, possession)| {
            preflight_zk_ams_admission_possession_wire_v1(
                *anchor.seed_public_key.as_bytes(),
                possession,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relation_context = relation_context(binding);
    verify_zk_ams_admission_relation_v1(&relation_context, &public_inputs, &proof.relation_proof)
        .map_err(|_| ZkAmsErrorV1::AdmissionRelation)?;
    let relation_digest = relation_proof_digest(&proof.relation_proof);
    for (index, (anchor, possession)) in batch
        .anchors
        .iter()
        .zip(preflighted_possessions)
        .enumerate()
    {
        verify_preflighted_zk_ams_admission_possession_v1(
            binding,
            u32::try_from(index).expect("batch is bounded to eight"),
            *anchor.phc_hash.as_bytes(),
            *anchor.seed_public_key.as_bytes(),
            relation_digest,
            possession,
        )?;
    }
    Ok(VerifiedZkAmsBatchAdmissionV1 {
        issuer_id: statement.issuer_id,
        policy_id: statement.policy_id,
        policy_digest: statement.policy_digest,
        issuer_policy_record_digest: statement.issuer_policy_record_digest,
        registry_id: statement.registry_id,
        registry_record_digest: statement.registry_record_digest,
        current_root: batch.account_registry_root,
        current_epoch: batch.account_registry_root_epoch,
        next_root: batch.next_account_registry_root,
        next_epoch: batch.next_account_registry_root_epoch,
        anchors: batch.anchors.clone(),
    })
}
/// Sign one account-provisioning statement with the selected seed secret.
///
/// `binding.statement_digest` is the digest of the complete typed ZK-AMS
/// statement, including account id, ordered ring, root/epoch, and key image.
///
/// # Errors
///
/// Fails closed for a malformed ring or key image, a mismatched secret, an
/// invalid consensus binding, or random-source exhaustion.
pub fn sign_zk_ams_provision_v1<R: CryptoRng + RngCore>(
    binding: &TranscriptBindingV1<'_>,
    ring: &[[u8; 32]],
    key_image_bytes: [u8; 32],
    signer_index: usize,
    secret: &ZkAmsSeedSecretV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    validate_zk_ams_binding_v1(binding)?;
    let ring_points = validate_ring(ring)?;
    let ring_size = ring.len();
    if signer_index >= ring_size {
        return Err(ZkAmsErrorV1::SignerIndexOutOfBounds {
            index: signer_index,
            ring_size,
        });
    }
    let secret_scalar = secret.expose_scalar();
    if *secret_scalar * RISTRETTO_BASEPOINT_POINT != ring_points[signer_index] {
        return Err(ZkAmsErrorV1::SignerPublicKeyMismatch);
    }
    let key_image = decode_nonidentity_point(key_image_bytes)?;
    let expected_image = *secret_scalar * hash_public_key_to_point(&ring[signer_index])?;
    if key_image != expected_image {
        return Err(ZkAmsErrorV1::KeyImageMismatch);
    }
    let mut checked_rng = health_checked_zk_ams_rng_v1(rng)?;
    let transcript = LsagTranscriptV1::new(binding, ring, key_image_bytes)?;
    let mut alpha = Zeroizing::new(random_nonzero_scalar(&mut checked_rng)?);
    let mut responses = Zeroizing::new(vec![Scalar::ZERO; ring_size]);
    for (index, response) in responses.iter_mut().enumerate() {
        if index != signer_index {
            *response = random_nonzero_scalar(&mut checked_rng)?;
        }
    }
    let mut challenges = Zeroizing::new(vec![Scalar::ZERO; ring_size]);
    let next = (signer_index + 1) % ring_size;
    let signer_hash_point = hash_public_key_to_point(&ring[signer_index])?;
    challenges[next] = transcript.challenge(
        signer_index,
        *alpha * RISTRETTO_BASEPOINT_POINT,
        *alpha * signer_hash_point,
    )?;
    let mut index = next;
    while index != signer_index {
        let hash_point = hash_public_key_to_point(&ring[index])?;
        let left =
            responses[index] * RISTRETTO_BASEPOINT_POINT + challenges[index] * ring_points[index];
        let right = responses[index] * hash_point + challenges[index] * key_image;
        challenges[(index + 1) % ring_size] = transcript.challenge(index, left, right)?;
        index = (index + 1) % ring_size;
    }
    responses[signer_index] = *alpha - challenges[signer_index] * *secret_scalar;
    alpha.zeroize();
    let proof = Zeroizing::new(ZkAmsLsagProofWireV1 {
        version: ZK_AMS_LSAG_PROOF_VERSION_V1,
        initial_challenge: challenges[0].to_bytes(),
        responses: responses.iter().map(Scalar::to_bytes).collect(),
    });
    let encoded = Zeroizing::new(norito::codec::encode_adaptive(&*proof));
    if encoded.len() > MAX_ZK_AMS_LSAG_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::ProofTooLarge {
            actual: encoded.len(),
            max: MAX_ZK_AMS_LSAG_PROOF_BYTES_V1,
        });
    }
    verify_zk_ams_provision_v1(binding, ring, key_image_bytes, encoded.as_slice())?;
    // The returned proof is public. The guarded construction copy is erased
    // on every early return, including cap, encoding, and self-check failures.
    Ok(encoded.to_vec())
}
/// Sign one complete typed ZK-AMS account-provisioning statement.
///
/// The wrapper validates and transcript-binds every authoritative record,
/// current root/epoch, ring key, target account, and key image before invoking
/// the LSAG prover, then runs the complete typed verifier before release.
pub fn sign_zk_ams_provision_statement_v1<R: CryptoRng + RngCore>(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
    signer_index: usize,
    secret: &ZkAmsSeedSecretV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    let provision = validate_provision_statement(statement, binding)?;
    let ring = provision
        .admitted_seed_key_ring
        .iter()
        .map(|key| *key.as_bytes())
        .collect::<Vec<_>>();
    let encoded = sign_zk_ams_provision_v1(
        binding,
        &ring,
        *provision.key_image.as_bytes(),
        signer_index,
        secret,
        rng,
    )?;
    verify_zk_ams_provision_statement_v1(statement, binding, &encoded)?;
    Ok(encoded)
}
#[cfg(test)]
/// Prove possession of the seed scalar for one ordered admission anchor.
///
/// This proof is intentionally a separate composed Schnorr component, not an
/// R1CS claim. Its Fiat--Shamir challenge binds the complete consensus
/// transcript, exact anchor, and digest of the masked relaxed-R1CS proof.
///
/// # Errors
///
/// Fails closed for an invalid binding or point, a mismatched seed secret,
/// random-source exhaustion, or an internal verifier self-check failure.
pub fn prove_zk_ams_admission_possession_v1<R: CryptoRng + RngCore>(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    secret: &ZkAmsSeedSecretV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    let secret_scalar = validate_admission_possession_inputs_v1(
        binding,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        secret,
    )?;
    let mut checked_rng = health_checked_zk_ams_rng_v1(rng)?;
    prove_zk_ams_admission_possession_validated_v1(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        &secret_scalar,
        &mut checked_rng,
    )
}
fn prove_zk_ams_admission_possession_with_rng_v1<R: CryptoRng + RngCore>(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    secret: &ZkAmsSeedSecretV1,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    let secret_scalar = validate_admission_possession_inputs_v1(
        binding,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        secret,
    )?;
    prove_zk_ams_admission_possession_validated_v1(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        &secret_scalar,
        rng,
    )
}
fn validate_admission_possession_inputs_v1(
    binding: &TranscriptBindingV1<'_>,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    secret: &ZkAmsSeedSecretV1,
) -> Result<Zeroizing<Scalar>, ZkAmsErrorV1> {
    validate_zk_ams_binding_v1(binding)?;
    if phc_hash == [0; 32] || relation_proof_digest == [0; 32] {
        return Err(ZkAmsErrorV1::InvalidBinding);
    }
    let public = decode_nonidentity_point(seed_public_key)?;
    let secret_scalar = secret.expose_scalar();
    if *secret_scalar * RISTRETTO_BASEPOINT_POINT != public {
        return Err(ZkAmsErrorV1::SignerPublicKeyMismatch);
    }
    Ok(secret_scalar)
}
fn prove_zk_ams_admission_possession_validated_v1<R: CryptoRng + RngCore>(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    secret_scalar: &Scalar,
    rng: &mut R,
) -> Result<Vec<u8>, ZkAmsErrorV1> {
    let nonce = Zeroizing::new(random_nonzero_scalar(rng)?);
    let commitment = *nonce * RISTRETTO_BASEPOINT_POINT;
    let challenge = admission_possession_challenge(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        commitment,
    )?;
    let response = Zeroizing::new(*nonce + challenge * *secret_scalar);
    let proof = Zeroizing::new(ZkAmsAdmissionPossessionProofWireV1 {
        version: ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1,
        commitment: commitment.compress().to_bytes(),
        response: response.to_bytes(),
    });
    let encoded = Zeroizing::new(norito::codec::encode_adaptive(&*proof));
    if encoded.len() > MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::PossessionProofTooLarge {
            actual: encoded.len(),
            max: MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1,
        });
    }
    verify_zk_ams_admission_possession_v1(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        encoded.as_slice(),
    )?;
    Ok(encoded.to_vec())
}
/// Verify the transcript-composed seed-possession proof for one anchor.
///
/// # Errors
///
/// Rejects oversized or non-canonical Norito, malformed points/scalars,
/// wrong-suite material, mutated transcript fields, and failed equations.
pub fn verify_zk_ams_admission_possession_v1(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    proof_bytes: &[u8],
) -> Result<(), ZkAmsErrorV1> {
    let proof = decode_zk_ams_possession_wire_v1(proof_bytes)?;
    verify_zk_ams_admission_possession_wire_v1(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        &proof,
    )
}
fn verify_zk_ams_admission_possession_wire_v1(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    proof: &ZkAmsAdmissionPossessionProofWireV1,
) -> Result<(), ZkAmsErrorV1> {
    validate_zk_ams_binding_v1(binding)?;
    if phc_hash == [0; 32] || relation_proof_digest == [0; 32] {
        return Err(ZkAmsErrorV1::InvalidBinding);
    }
    let preflight = preflight_zk_ams_admission_possession_wire_v1(seed_public_key, proof)?;
    verify_preflighted_zk_ams_admission_possession_v1(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        preflight,
    )
}
fn preflight_zk_ams_admission_possession_wire_v1(
    seed_public_key: [u8; 32],
    proof: &ZkAmsAdmissionPossessionProofWireV1,
) -> Result<PreflightedZkAmsAdmissionPossessionV1, ZkAmsErrorV1> {
    if proof.version != ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1 {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    let public = decode_nonidentity_point(seed_public_key)?;
    let commitment = decode_nonidentity_point(proof.commitment)?;
    let response = scalar_from_canonical(proof.response)?;
    Ok(PreflightedZkAmsAdmissionPossessionV1 {
        public,
        commitment,
        response,
    })
}
fn verify_preflighted_zk_ams_admission_possession_v1(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    preflight: PreflightedZkAmsAdmissionPossessionV1,
) -> Result<(), ZkAmsErrorV1> {
    let PreflightedZkAmsAdmissionPossessionV1 {
        public,
        commitment,
        response,
    } = preflight;
    let challenge = admission_possession_challenge(
        binding,
        anchor_index,
        phc_hash,
        seed_public_key,
        relation_proof_digest,
        commitment,
    )?;
    if response * RISTRETTO_BASEPOINT_POINT != commitment + challenge * public {
        return Err(ZkAmsErrorV1::VerificationFailed);
    }
    Ok(())
}
/// Verify one canonical Phase-V LSAG proof.
///
/// # Errors
///
/// Fails closed before allocation for oversized proof bytes, then rejects non-canonical Norito,
/// scalars, points, ring order, or verification equations.
pub fn verify_zk_ams_provision_v1(
    binding: &TranscriptBindingV1<'_>,
    ring: &[[u8; 32]],
    key_image_bytes: [u8; 32],
    proof_bytes: &[u8],
) -> Result<(), ZkAmsErrorV1> {
    validate_zk_ams_binding_v1(binding)?;
    if proof_bytes.len() > MAX_ZK_AMS_LSAG_PROOF_BYTES_V1 {
        return Err(ZkAmsErrorV1::ProofTooLarge {
            actual: proof_bytes.len(),
            max: MAX_ZK_AMS_LSAG_PROOF_BYTES_V1,
        });
    }
    let ring_points = validate_ring(ring)?;
    let key_image = decode_nonidentity_point(key_image_bytes)?;
    let proof = norito::codec::decode_exact_from_slice_with_limits::<ZkAmsLsagProofWireV1>(
        proof_bytes,
        zk_ams_lsag_decode_limits(ring.len(), proof_bytes.len()),
    )
    .map_err(|_| ZkAmsErrorV1::InvalidProofEncoding)?;
    if proof.version != ZK_AMS_LSAG_PROOF_VERSION_V1
        || proof.responses.len() != ring.len()
        || norito::codec::encode_adaptive(&proof) != proof_bytes
    {
        return Err(ZkAmsErrorV1::InvalidProofEncoding);
    }
    let mut challenge = scalar_from_canonical(proof.initial_challenge)?;
    let responses = proof
        .responses
        .into_iter()
        .map(scalar_from_canonical)
        .collect::<Result<Vec<_>, _>>()?;
    let transcript = LsagTranscriptV1::new(binding, ring, key_image_bytes)?;
    for (index, ((public_key, response), public_bytes)) in ring_points
        .iter()
        .copied()
        .zip(responses.iter().copied())
        .zip(ring.iter())
        .enumerate()
    {
        let hash_point = hash_public_key_to_point(public_bytes)?;
        let left = response * RISTRETTO_BASEPOINT_POINT + challenge * public_key;
        let right = response * hash_point + challenge * key_image;
        challenge = transcript.challenge(index, left, right)?;
    }
    if challenge.to_bytes() != proof.initial_challenge {
        return Err(ZkAmsErrorV1::VerificationFailed);
    }
    Ok(())
}
/// Verify one complete typed provisioning statement and derive its atomic ledger effect.
pub fn verify_zk_ams_provision_statement_v1(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
    proof_bytes: &[u8],
) -> Result<VerifiedZkAmsProvisionAccountV1, ZkAmsErrorV1> {
    let provision = validate_provision_statement(statement, binding)?;
    let ring = provision
        .admitted_seed_key_ring
        .iter()
        .map(|key| *key.as_bytes())
        .collect::<Vec<_>>();
    verify_zk_ams_provision_v1(binding, &ring, *provision.key_image.as_bytes(), proof_bytes)?;
    Ok(VerifiedZkAmsProvisionAccountV1 {
        issuer_id: statement.issuer_id,
        policy_id: statement.policy_id,
        policy_digest: statement.policy_digest,
        issuer_policy_record_digest: statement.issuer_policy_record_digest,
        registry_id: statement.registry_id,
        registry_record_digest: statement.registry_record_digest,
        current_root: provision.account_registry_root,
        current_epoch: provision.account_registry_root_epoch,
        ring: provision.admitted_seed_key_ring.clone(),
        account_id: provision.account_id.clone(),
        key_image: provision.key_image,
    })
}
fn validate_ring(ring: &[[u8; 32]]) -> Result<Vec<RistrettoPoint>, ZkAmsErrorV1> {
    if !ZK_AMS_RING_SIZES_V1.contains(&ring.len()) {
        return Err(ZkAmsErrorV1::InvalidRingSize { actual: ring.len() });
    }
    if ring.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ZkAmsErrorV1::NonCanonicalRing);
    }
    ring.iter().copied().map(decode_nonidentity_point).collect()
}
fn decode_nonidentity_point(bytes: [u8; 32]) -> Result<RistrettoPoint, ZkAmsErrorV1> {
    let point = CompressedRistretto(bytes)
        .decompress()
        .ok_or(ZkAmsErrorV1::InvalidPoint)?;
    if point == RistrettoPoint::identity() || point.compress().to_bytes() != bytes {
        return Err(ZkAmsErrorV1::InvalidPoint);
    }
    Ok(point)
}
fn hash_public_key_to_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, ZkAmsErrorV1> {
    let mut hash = Sha3_512::new();
    hash.update(ZK_AMS_HASH_TO_POINT_DOMAIN_V1);
    hash.update(
        u16::try_from(ZK_AMS_LSAG_SUITE_V1.len())
            .map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?
            .to_be_bytes(),
    );
    hash.update(ZK_AMS_LSAG_SUITE_V1);
    hash.update(bytes);
    let uniform: [u8; 64] = hash.finalize().into();
    let point = RistrettoPoint::from_uniform_bytes(&uniform);
    if point == RistrettoPoint::identity() {
        return Err(ZkAmsErrorV1::InvalidPoint);
    }
    Ok(point)
}
fn admission_possession_challenge(
    binding: &TranscriptBindingV1<'_>,
    anchor_index: u32,
    phc_hash: [u8; 32],
    seed_public_key: [u8; 32],
    relation_proof_digest: [u8; 32],
    commitment: RistrettoPoint,
) -> Result<Scalar, ZkAmsErrorV1> {
    if commitment == RistrettoPoint::identity() {
        return Err(ZkAmsErrorV1::InvalidPoint);
    }
    let mut hash = Sha3_512::new();
    append_field(&mut hash, b"domain", ZK_AMS_ADMISSION_POSSESSION_SUITE_V1)?;
    append_field(&mut hash, b"transcript_version", &[TRANSCRIPT_VERSION_V1])?;
    append_field(&mut hash, b"network_id", binding.network_id)?;
    append_field(&mut hash, b"genesis_hash", &binding.genesis_hash)?;
    append_field(
        &mut hash,
        b"action_index",
        &binding.action_index.to_be_bytes(),
    )?;
    append_field(&mut hash, b"statement_digest", &binding.statement_digest)?;
    append_field(&mut hash, b"parameter_id", &binding.parameter_id)?;
    append_field(&mut hash, b"parameter_digest", &binding.parameter_digest)?;
    append_field(&mut hash, b"verifier_digest", &binding.verifier_digest)?;
    append_field(
        &mut hash,
        b"statement_schema_digest",
        &binding.statement_schema_digest,
    )?;
    append_field(
        &mut hash,
        b"engine_manifest_digest",
        &binding.engine_manifest_digest,
    )?;
    append_field(&mut hash, b"generator_digest", &binding.generator_digest)?;
    append_field(&mut hash, b"anchor_index", &anchor_index.to_be_bytes())?;
    append_field(&mut hash, b"phc_hash", &phc_hash)?;
    append_field(&mut hash, b"seed_public_key", &seed_public_key)?;
    append_field(&mut hash, b"relation_proof_digest", &relation_proof_digest)?;
    append_field(&mut hash, b"commitment", commitment.compress().as_bytes())?;
    let wide: [u8; 64] = hash.finalize().into();
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}
fn batch_action(
    statement: &IrohaZkAmsStatementV1,
) -> Result<&PrivacyZkAmsBatchAdmissionV1, ZkAmsErrorV1> {
    match &statement.action {
        PrivacyZkAmsActionV1::BatchAdmission(batch) => Ok(batch),
        PrivacyZkAmsActionV1::ProvisionAccount(_) => Err(ZkAmsErrorV1::InvalidStatement),
    }
}
fn provision_action(
    statement: &IrohaZkAmsStatementV1,
) -> Result<&PrivacyZkAmsProvisionAccountV1, ZkAmsErrorV1> {
    match &statement.action {
        PrivacyZkAmsActionV1::ProvisionAccount(provision) => Ok(provision),
        PrivacyZkAmsActionV1::BatchAdmission(_) => Err(ZkAmsErrorV1::InvalidStatement),
    }
}
fn validate_provision_statement<'a>(
    statement: &'a IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<&'a PrivacyZkAmsProvisionAccountV1, ZkAmsErrorV1> {
    validate_statement_binding(statement, binding)?;
    let provision = provision_action(statement)?;
    if statement.issuer_id.is_zero()
        || statement.policy_id.is_zero()
        || statement.registry_id.is_zero()
        || statement.issuer_policy_record_digest.is_zero()
        || statement.registry_record_digest.is_zero()
        || statement.policy_digest.is_zero()
        || provision.account_registry_root.is_zero()
        || provision.account_registry_root_epoch == 0
        || provision.key_image.is_zero()
    {
        return Err(ZkAmsErrorV1::InvalidStatement);
    }
    let issuer_key = P256VerifyingKey::from_sec1_bytes(statement.issuer_public_key.as_bytes())
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerKey)?;
    if issuer_key.to_encoded_point(true).as_bytes() != statement.issuer_public_key.as_bytes() {
        return Err(ZkAmsErrorV1::InvalidIssuerKey);
    }
    let ring = provision
        .admitted_seed_key_ring
        .iter()
        .map(|key| *key.as_bytes())
        .collect::<Vec<_>>();
    validate_ring(&ring)?;
    decode_nonidentity_point(*provision.key_image.as_bytes())?;
    Ok(provision)
}
fn validate_statement_binding(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<(), ZkAmsErrorV1> {
    validate_zk_ams_binding_v1(binding)?;
    let context = &statement.context;
    if context.action_index != ZK_AMS_PRIVACY_ACTION_INDEX_V1
        || binding.network_id != context.network_id.as_bytes()
        || binding.action_index != context.action_index
        || binding.parameter_id != *context.parameter_id.as_bytes()
        || binding.parameter_digest != *context.parameter_digest.as_bytes()
        || binding.verifier_digest != *context.verifier_digest.as_bytes()
        || binding.statement_schema_digest != *context.statement_schema_digest.as_bytes()
        || binding.engine_manifest_digest != *context.engine_manifest_digest.as_bytes()
        || binding.generator_digest != zk_ams_generator_digest_v1()
        || context.transaction_intent_digest.is_zero()
    {
        return Err(ZkAmsErrorV1::BindingMismatch);
    }
    let statement_digest = PrivacyStatementV1::IrohaZkAmsV1(statement.clone())
        .digest()
        .map_err(|_| ZkAmsErrorV1::InvalidStatement)?;
    if binding.statement_digest != *statement_digest.as_bytes() {
        return Err(ZkAmsErrorV1::BindingMismatch);
    }
    Ok(())
}
fn build_admission_public_inputs(
    statement: &IrohaZkAmsStatementV1,
    binding: &TranscriptBindingV1<'_>,
) -> Result<(Vec<ZkAmsAdmissionPublicInputV1>, P256VerifyingKey), ZkAmsErrorV1> {
    validate_statement_binding(statement, binding)?;
    let batch = batch_action(statement)?;
    if statement.issuer_id.is_zero()
        || statement.policy_id.is_zero()
        || statement.registry_id.is_zero()
        || statement.issuer_policy_record_digest.is_zero()
        || statement.registry_record_digest.is_zero()
        || statement.policy_digest.is_zero()
        || batch.account_registry_root.is_zero()
        || batch.next_account_registry_root.is_zero()
        || batch.account_registry_root_epoch == 0
        || batch
            .account_registry_root_epoch
            .checked_add(1)
            .is_none_or(|epoch| epoch != batch.next_account_registry_root_epoch)
        || batch.anchors.is_empty()
        || batch.anchors.len() > ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1
    {
        return Err(ZkAmsErrorV1::InvalidStatement);
    }
    for (index, anchor) in batch.anchors.iter().enumerate() {
        if anchor.phc_hash.is_zero()
            || anchor.seed_public_key.is_zero()
            || batch.anchors[..index]
                .iter()
                .any(|prior| prior.phc_hash == anchor.phc_hash)
            || batch.anchors[..index]
                .iter()
                .any(|prior| prior.seed_public_key == anchor.seed_public_key)
        {
            return Err(ZkAmsErrorV1::InvalidStatement);
        }
        decode_nonidentity_point(*anchor.seed_public_key.as_bytes())?;
    }
    let issuer_key = P256VerifyingKey::from_sec1_bytes(statement.issuer_public_key.as_bytes())
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerKey)?;
    let canonical = issuer_key.to_encoded_point(true);
    if canonical.as_bytes() != statement.issuer_public_key.as_bytes() {
        return Err(ZkAmsErrorV1::InvalidIssuerKey);
    }
    let uncompressed = issuer_key.to_encoded_point(false);
    let issuer_key_x: [u8; 32] = uncompressed
        .x()
        .ok_or(ZkAmsErrorV1::InvalidIssuerKey)?
        .as_slice()
        .try_into()
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerKey)?;
    let issuer_key_y: [u8; 32] = uncompressed
        .y()
        .ok_or(ZkAmsErrorV1::InvalidIssuerKey)?
        .as_slice()
        .try_into()
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerKey)?;
    let issuer_key_prefix = statement.issuer_public_key.as_bytes()[0];
    let batch_size =
        u32::try_from(batch.anchors.len()).map_err(|_| ZkAmsErrorV1::InvalidStatement)?;
    let mut prior_root = batch.account_registry_root;
    let mut public_inputs = Vec::with_capacity(batch.anchors.len());
    for (index, anchor) in batch.anchors.iter().copied().enumerate() {
        let anchor_index = u32::try_from(index).expect("batch is bounded to eight");
        let next_root = zk_ams_registry_transition_root_v1(
            statement.registry_id,
            prior_root,
            batch.account_registry_root_epoch,
            batch.next_account_registry_root_epoch,
            batch_size,
            anchor_index,
            anchor,
        );
        public_inputs.push(ZkAmsAdmissionPublicInputV1 {
            issuer_key_x,
            issuer_key_y,
            issuer_key_prefix,
            issuer_id: *statement.issuer_id.as_bytes(),
            policy_id: *statement.policy_id.as_bytes(),
            issuer_policy_record_digest: *statement.issuer_policy_record_digest.as_bytes(),
            registry_id: *statement.registry_id.as_bytes(),
            registry_record_digest: *statement.registry_record_digest.as_bytes(),
            policy_digest: *statement.policy_digest.as_bytes(),
            phc_hash: *anchor.phc_hash.as_bytes(),
            seed_public_key: *anchor.seed_public_key.as_bytes(),
            prior_registry_root: *prior_root.as_bytes(),
            next_registry_root: *next_root.as_bytes(),
            current_registry_epoch: batch.account_registry_root_epoch,
            next_registry_epoch: batch.next_account_registry_root_epoch,
            batch_size,
            anchor_index,
        });
        prior_root = next_root;
    }
    if prior_root != batch.next_account_registry_root {
        return Err(ZkAmsErrorV1::RegistryTransitionMismatch);
    }
    Ok((public_inputs, issuer_key))
}
fn validate_credential_witness(
    statement: &IrohaZkAmsStatementV1,
    anchor: &PrivacyZkAmsAdmissionAnchorV1,
    witness: &ZkAmsBatchCredentialWitnessV1<'_>,
) -> Result<(), ZkAmsErrorV1> {
    let credential = witness.credential;
    if credential.version != ZK_AMS_PHC_VERSION_V1
        || credential.issuer_id != statement.issuer_id
        || credential.policy_id != statement.policy_id
        || credential.subject_commitment.is_zero()
        || credential.credential_nonce.is_zero()
        || credential.seed_public_key != anchor.seed_public_key
        || credential.digest() != anchor.phc_hash
        || zk_ams_seed_public_key_v1(witness.seed_secret) != *anchor.seed_public_key.as_bytes()
    {
        return Err(ZkAmsErrorV1::InvalidCredential);
    }
    Ok(())
}
fn validate_issuer_signature(
    signature_bytes: &[u8; 64],
    message_digest: [u8; 32],
    issuer_key: &P256VerifyingKey,
) -> Result<ZkAmsIssuerSignatureWitnessV1, ZkAmsErrorV1> {
    let signature = P256Signature::from_slice(signature_bytes)
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerSignature)?;
    if signature.normalize_s().is_some() {
        return Err(ZkAmsErrorV1::HighSIssuerSignature);
    }
    issuer_key
        .verify_prehash(&message_digest, &signature)
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerSignature)?;
    let (r, s) = signature.split_scalars();
    let s_inverse = Option::<P256Scalar>::from(s.as_ref().invert())
        .ok_or(ZkAmsErrorV1::InvalidIssuerSignature)?;
    let digest_scalar =
        <P256Scalar as Reduce<U256>>::reduce_bytes(&P256FieldBytes::from(message_digest));
    let issuer_point = P256ProjectivePoint::from(*issuer_key.as_affine());
    let recovery =
        (P256ProjectivePoint::GENERATOR * digest_scalar + issuer_point * *r.as_ref()) * s_inverse;
    if bool::from(recovery.is_identity()) {
        return Err(ZkAmsErrorV1::InvalidIssuerSignature);
    }
    let recovery = P256AffinePoint::from(recovery).to_encoded_point(false);
    let recovery_x: [u8; 32] = recovery
        .x()
        .ok_or(ZkAmsErrorV1::InvalidIssuerSignature)?
        .as_slice()
        .try_into()
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerSignature)?;
    let recovery_y: [u8; 32] = recovery
        .y()
        .ok_or(ZkAmsErrorV1::InvalidIssuerSignature)?
        .as_slice()
        .try_into()
        .map_err(|_| ZkAmsErrorV1::InvalidIssuerSignature)?;
    Ok(ZkAmsIssuerSignatureWitnessV1 {
        r: Zeroizing::new(r.as_ref().to_repr().into()),
        s: Zeroizing::new(s.as_ref().to_repr().into()),
        recovery_x: Zeroizing::new(recovery_x),
        recovery_y: Zeroizing::new(recovery_y),
    })
}
fn relation_context<'a>(binding: &'a TranscriptBindingV1<'a>) -> ZkAmsProofContextV1<'a> {
    ZkAmsProofContextV1 {
        // The protected Halo2 profile retains this internal field name; the
        // bytes are the exact genesis-derived NetworkId, never a ChainId label.
        chain_id: binding.network_id,
        genesis_hash: binding.genesis_hash,
        action_index: binding.action_index,
        statement_digest: binding.statement_digest,
        parameter_id: binding.parameter_id,
        parameter_digest: binding.parameter_digest,
        verifier_digest: binding.verifier_digest,
        statement_schema_digest: binding.statement_schema_digest,
        engine_manifest_digest: binding.engine_manifest_digest,
        generator_digest: binding.generator_digest,
    }
}
fn relation_proof_digest(proof_bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(RELATION_PROOF_DIGEST_DOMAIN_V1);
    hash.update(
        u64::try_from(proof_bytes.len())
            .expect("bounded proof length fits u64")
            .to_le_bytes(),
    );
    hash.update(proof_bytes);
    hash.finalize().into()
}
fn health_checked_zk_ams_rng_v1<R>(
    rng: &mut R,
) -> Result<HealthCheckedCryptoRngV1<'_, R>, ZkAmsErrorV1>
where
    R: CryptoRng + RngCore,
{
    HealthCheckedCryptoRngV1::new(rng).map_err(|error| match error {
        ProverRandomnessErrorV1::Unavailable => ZkAmsErrorV1::RandomnessUnavailable,
        ProverRandomnessErrorV1::Unhealthy => ZkAmsErrorV1::RandomnessHealthCheckFailed,
    })
}
struct MaskedRandomAdapter<'a, R> {
    source: &'a mut R,
    randomness_unavailable: bool,
}
impl<R: CryptoRng + RngCore> MaskedRelaxedRandomSourceV1 for MaskedRandomAdapter<'_, R> {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        self.source.try_fill_bytes(destination).map_err(|_| {
            self.randomness_unavailable = true;
            MaskedRelaxedRandomErrorV1::Unavailable
        })
    }
}
fn scalar_from_canonical(bytes: [u8; 32]) -> Result<Scalar, ZkAmsErrorV1> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(ZkAmsErrorV1::InvalidScalar)
}
fn random_nonzero_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Scalar, ZkAmsErrorV1> {
    for _ in 0..RANDOM_REJECTION_ATTEMPTS {
        let mut candidate = [0_u8; 32];
        if rng.try_fill_bytes(&mut candidate).is_err() {
            candidate.zeroize();
            return Err(ZkAmsErrorV1::RandomnessUnavailable);
        }
        let parsed = scalar_from_canonical(candidate);
        candidate.zeroize();
        if let Ok(scalar) = parsed {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }
    }
    Err(ZkAmsErrorV1::RandomnessExhausted)
}
#[derive(Clone)]
struct LsagTranscriptV1 {
    prefix: Sha3_512,
}
impl LsagTranscriptV1 {
    fn new(
        binding: &TranscriptBindingV1<'_>,
        ring: &[[u8; 32]],
        key_image: [u8; 32],
    ) -> Result<Self, ZkAmsErrorV1> {
        validate_zk_ams_binding_v1(binding)?;
        let mut prefix = Sha3_512::new();
        append_field(&mut prefix, b"domain", ZK_AMS_LSAG_SUITE_V1)?;
        append_field(&mut prefix, b"transcript_version", &[TRANSCRIPT_VERSION_V1])?;
        append_field(&mut prefix, b"network_id", binding.network_id)?;
        append_field(&mut prefix, b"genesis_hash", &binding.genesis_hash)?;
        append_field(
            &mut prefix,
            b"action_index",
            &binding.action_index.to_be_bytes(),
        )?;
        append_field(&mut prefix, b"statement_digest", &binding.statement_digest)?;
        append_field(&mut prefix, b"parameter_id", &binding.parameter_id)?;
        append_field(&mut prefix, b"parameter_digest", &binding.parameter_digest)?;
        append_field(&mut prefix, b"verifier_digest", &binding.verifier_digest)?;
        append_field(
            &mut prefix,
            b"statement_schema_digest",
            &binding.statement_schema_digest,
        )?;
        append_field(
            &mut prefix,
            b"engine_manifest_digest",
            &binding.engine_manifest_digest,
        )?;
        append_field(&mut prefix, b"generator_digest", &binding.generator_digest)?;
        append_field(
            &mut prefix,
            b"ring_count",
            &u32::try_from(ring.len())
                .map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?
                .to_be_bytes(),
        )?;
        for (index, public_key) in ring.iter().enumerate() {
            append_indexed_field(&mut prefix, b"ring_public_key", index, public_key)?;
        }
        append_field(&mut prefix, b"key_image", &key_image)?;
        Ok(Self { prefix })
    }
    fn challenge(
        &self,
        index: usize,
        left: RistrettoPoint,
        right: RistrettoPoint,
    ) -> Result<Scalar, ZkAmsErrorV1> {
        if left == RistrettoPoint::identity() || right == RistrettoPoint::identity() {
            return Err(ZkAmsErrorV1::VerificationFailed);
        }
        let mut hash = self.prefix.clone();
        append_field(
            &mut hash,
            b"ring_index",
            &u32::try_from(index)
                .map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?
                .to_be_bytes(),
        )?;
        append_field(&mut hash, b"left", left.compress().as_bytes())?;
        append_field(&mut hash, b"right", right.compress().as_bytes())?;
        let wide: [u8; 64] = hash.finalize().into();
        Ok(Scalar::from_bytes_mod_order_wide(&wide))
    }
}
fn append_indexed_field(
    hash: &mut Sha3_512,
    label: &[u8],
    index: usize,
    value: &[u8],
) -> Result<(), ZkAmsErrorV1> {
    let index = u32::try_from(index).map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?;
    let mut indexed_label = Vec::with_capacity(label.len() + 4);
    indexed_label.extend_from_slice(label);
    indexed_label.extend_from_slice(&index.to_be_bytes());
    append_field(hash, &indexed_label, value)
}
fn append_field(hash: &mut Sha3_512, label: &[u8], value: &[u8]) -> Result<(), ZkAmsErrorV1> {
    let label_len =
        u16::try_from(label.len()).map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?;
    let value_len =
        u32::try_from(value.len()).map_err(|_| ZkAmsErrorV1::TranscriptFieldTooLarge)?;
    hash.update(label_len.to_be_bytes());
    hash.update(label);
    hash.update(value_len.to_be_bytes());
    hash.update(value);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        num::{NonZeroU32, NonZeroU64},
        time::Duration,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        privacy::{
            PrivacyEngineManifestDigestV1, PrivacyP256PointV1, PrivacyParameterDigestV1,
            PrivacyParameterIdV1, PrivacyStatementContextV1, PrivacyStatementSchemaDigestV1,
            PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
            PrivacyZkAmsCredentialNonceV1, PrivacyZkAmsPhcHashV1, PrivacyZkAmsSubjectCommitmentV1,
        },
        transaction::FeePaymentIntent,
    };
    use iroha_model_base::metadata::Metadata;
    use p256::ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner as _};
    use rand_core_06::Error as RngError;
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::zk_ams::tests::RetiredWireZkAmsBatchAdmissionProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct RetiredWireZkAmsBatchAdmissionProofV1 {
        version: u8,
        relation_proof: Vec<u8>,
        possession_proofs: Vec<Vec<u8>>,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::zk_ams::tests::RetiredWireZkAmsOptionSlotsBatchAdmissionProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct RetiredWireZkAmsOptionSlotsBatchAdmissionProofV1 {
        version: u8,
        relation_proof: Vec<u8>,
        possession_proofs:
            [Option<ZkAmsAdmissionPossessionProofWireV1>; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1],
    }
    #[derive(Clone, Copy)]
    struct TestRng(u64);
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("public preflight reached the random source")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("public preflight reached the random source")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("public preflight reached the random source")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            panic!("public preflight reached the random source")
        }
    }
    impl CryptoRng for PanicRng {}
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
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            rand_core_06::impls::fill_bytes_via_next(self, destination);
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            destination.fill(0);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}
    struct PeriodicRng;
    impl RngCore for PeriodicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = ((index % 8) as u8).wrapping_mul(29).wrapping_add(7);
            }
            Ok(())
        }
    }
    impl CryptoRng for PeriodicRng {}
    struct FailingRng;
    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("ZK-AMS must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            Err(RngError::new("injected ZK-AMS RNG failure"))
        }
    }
    impl CryptoRng for FailingRng {}
    fn seed_secret(value: u8) -> ZkAmsSeedSecretV1 {
        let mut bytes = [0_u8; 32];
        bytes[0] = value;
        ZkAmsSeedSecretV1::from_bytes(bytes).expect("small scalar is canonical and nonzero")
    }
    fn sorted_ring(size: usize) -> Vec<([u8; 32], ZkAmsSeedSecretV1)> {
        let mut ring = (1..=size)
            .map(|index| {
                let secret =
                    seed_secret(u8::try_from(index).expect("test ring is bounded to 64 members"));
                (zk_ams_seed_public_key_v1(&secret), secret)
            })
            .collect::<Vec<_>>();
        ring.sort_by_key(|(public, _)| *public);
        ring
    }
    fn binding() -> TranscriptBindingV1<'static> {
        TranscriptBindingV1 {
            network_id: &[0x11; 32],
            genesis_hash: [0x11; 32],
            action_index: ZK_AMS_PRIVACY_ACTION_INDEX_V1,
            statement_digest: [0x12; 32],
            parameter_id: [0x13; 32],
            parameter_digest: [0x14; 32],
            verifier_digest: [0x15; 32],
            statement_schema_digest: [0x16; 32],
            engine_manifest_digest: [0x17; 32],
            generator_digest: zk_ams_generator_digest_v1(),
        }
    }
    fn mutate_every_binding_axis() -> Vec<(&'static str, TranscriptBindingV1<'static>)> {
        let mut mutations = Vec::new();
        let mut changed = binding();
        changed.network_id = &[0x12; 32];
        changed.genesis_hash = [0x12; 32];
        mutations.push(("chain", changed));
        let mut changed = binding();
        changed.genesis_hash[0] ^= 1;
        mutations.push(("genesis", changed));
        let mut changed = binding();
        changed.action_index += 1;
        mutations.push(("action-index", changed));
        let mut changed = binding();
        changed.statement_digest[0] ^= 1;
        mutations.push(("statement", changed));
        let mut changed = binding();
        changed.parameter_id[0] ^= 1;
        mutations.push(("parameter-id", changed));
        let mut changed = binding();
        changed.parameter_digest[0] ^= 1;
        mutations.push(("parameter-digest", changed));
        let mut changed = binding();
        changed.verifier_digest[0] ^= 1;
        mutations.push(("verifier", changed));
        let mut changed = binding();
        changed.statement_schema_digest[0] ^= 1;
        mutations.push(("schema", changed));
        let mut changed = binding();
        changed.engine_manifest_digest[0] ^= 1;
        mutations.push(("manifest", changed));
        let mut changed = binding();
        changed.generator_digest[0] ^= 1;
        mutations.push(("generator", changed));
        mutations
    }
    fn sign_fixture(
        size: usize,
        signer_index: usize,
    ) -> (Vec<([u8; 32], ZkAmsSeedSecretV1)>, [u8; 32], Vec<u8>) {
        let ring = sorted_ring(size);
        let public = ring.iter().map(|(public, _)| *public).collect::<Vec<_>>();
        let key_image = zk_ams_key_image_v1(&ring[signer_index].1).expect("key image");
        let mut rng = TestRng::new(0x9e37_79b9_7f4a_7c15);
        let proof = sign_zk_ams_provision_v1(
            &binding(),
            &public,
            key_image,
            signer_index,
            &ring[signer_index].1,
            &mut rng,
        )
        .expect("valid LSAG");
        (ring, key_image, proof)
    }
    #[test]
    fn seed_codec_and_key_images_are_canonical_deterministic_and_distinct() {
        assert!(matches!(
            ZkAmsSeedSecretV1::from_bytes([0; 32]),
            Err(ZkAmsErrorV1::ZeroSecret)
        ));
        assert!(matches!(
            ZkAmsSeedSecretV1::from_bytes([u8::MAX; 32]),
            Err(ZkAmsErrorV1::InvalidScalar)
        ));
        assert!(matches!(
            ZkAmsSeedSecretV1::generate(&mut ZeroRng),
            Err(ZkAmsErrorV1::RandomnessHealthCheckFailed)
        ));
        assert!(matches!(
            ZkAmsSeedSecretV1::generate(&mut PeriodicRng),
            Err(ZkAmsErrorV1::RandomnessHealthCheckFailed)
        ));
        assert!(matches!(
            ZkAmsSeedSecretV1::generate(&mut FailingRng),
            Err(ZkAmsErrorV1::RandomnessUnavailable)
        ));
        let first = seed_secret(1);
        let second = seed_secret(2);
        assert_ne!(
            zk_ams_seed_public_key_v1(&first),
            zk_ams_seed_public_key_v1(&second)
        );
        let first_image = zk_ams_key_image_v1(&first).expect("first key image");
        assert_eq!(
            first_image,
            zk_ams_key_image_v1(&first).expect("deterministic key image")
        );
        assert_ne!(
            first_image,
            zk_ams_key_image_v1(&second).expect("second key image")
        );
        assert!(decode_nonidentity_point(first_image).is_ok());
    }
    #[test]
    fn generator_identity_stays_testable_while_governed_profile_is_closed() {
        assert_ne!(zk_ams_generator_digest_v1(), [0; 32]);
        assert!(iroha_zkp_halo2::vega::zk_ams_compiled_profile_digest_v1().is_err());
        assert!(
            crate::privacy_profiles::compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaZkAmsV1)
                .is_err()
        );
    }
    #[test]
    fn lsag_roundtrips_every_closed_ring_size_and_self_checks() {
        for (case, size) in ZK_AMS_RING_SIZES_V1.into_iter().enumerate() {
            let signer_index = (size / 2) + case;
            let (ring, key_image, proof) = sign_fixture(size, signer_index);
            let public = ring.iter().map(|(public, _)| *public).collect::<Vec<_>>();
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &proof)
                .expect("valid LSAG proof");
            assert_eq!(proof.len(), 45 + size * 65);
            assert!(proof.len() <= MAX_ZK_AMS_LSAG_PROOF_BYTES_V1);
            let decoded = norito::codec::decode_exact_from_slice::<ZkAmsLsagProofWireV1>(&proof)
                .expect("exact proof wire");
            assert_eq!(decoded.version, ZK_AMS_LSAG_PROOF_VERSION_V1);
            assert_eq!(decoded.responses.len(), size);
            let mut second_rng = TestRng::new(0x9e37_79b9_7f4a_7c15);
            assert_eq!(
                sign_zk_ams_provision_v1(
                    &binding(),
                    &public,
                    key_image,
                    signer_index,
                    &ring[signer_index].1,
                    &mut second_rng,
                )
                .expect("deterministic LSAG"),
                proof
            );
        }
    }
    #[test]
    fn maximum_lsag_requires_the_first_release_decode_allocation_budget() {
        const RETIRED_UNDERSIZED_BUDGET_BYTES_V1: usize = 4 * 4_205;
        let size = ZK_AMS_MAX_RING_SIZE_V1;
        let (_ring, _key_image, proof) = sign_fixture(size, size / 2);
        assert_eq!(RETIRED_UNDERSIZED_BUDGET_BYTES_V1, 16_820);
        assert_eq!(ZK_AMS_LSAG_DECODE_ALLOCATION_BYTES_V1, 32 * 1024);
        let decoded = norito::codec::decode_exact_from_slice_with_limits::<ZkAmsLsagProofWireV1>(
            &proof,
            zk_ams_lsag_decode_limits(size, proof.len()),
        )
        .expect("maximum-ring LSAG must decode under the governed budget");
        assert_eq!(decoded.responses.len(), size);
        let retired_limits = norito::DecodeLimits::new(
            size,
            proof.len(),
            size,
            RETIRED_UNDERSIZED_BUDGET_BYTES_V1,
            8,
        );
        assert!(
            norito::codec::decode_exact_from_slice_with_limits::<ZkAmsLsagProofWireV1>(
                &proof,
                retired_limits,
            )
            .is_err(),
            "the retired allocation budget unexpectedly admits the maximum canonical LSAG"
        );
    }
    #[test]
    fn lsag_decoder_preflights_oversized_and_forged_response_counts() {
        let (ring, key_image, proof) = sign_fixture(16, 7);
        let public = ring.iter().map(|(public, _)| *public).collect::<Vec<_>>();
        let mut decoded = norito::codec::decode_exact_from_slice::<ZkAmsLsagProofWireV1>(&proof)
            .expect("canonical LSAG");
        decoded.responses.push([0; 32]);
        let oversized = norito::codec::encode_adaptive(&decoded);
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &oversized),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
        let encoded_count = 17_u64.to_le_bytes();
        let count_offset = oversized
            .windows(encoded_count.len())
            .position(|window| window == encoded_count)
            .expect("oversized response count is present in canonical wire");
        let mut forged = oversized;
        forged[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &forged),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
    }
    #[test]
    fn batch_decoder_preflights_relation_count_and_rejects_inexact_wires() {
        let mut possession_proofs =
            [ZkAmsAdmissionPossessionProofWireV1::UNUSED; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1];
        possession_proofs[0] = ZkAmsAdmissionPossessionProofWireV1 {
            version: ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1,
            commitment: [1; 32],
            response: [2; 32],
        };
        let canonical_wire = ZkAmsBatchAdmissionProofWireV1 {
            version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
            relation_proof: Vec::new(),
            possession_proof_count: 1,
            possession_proofs,
        };
        let canonical = norito::codec::encode_adaptive(&canonical_wire);
        let decode_raw = |bytes: &[u8]| {
            norito::codec::decode_exact_from_slice_with_limits::<ZkAmsBatchAdmissionProofWireV1>(
                bytes,
                zk_ams_batch_decode_limits(bytes.len()),
            )
        };
        assert_eq!(
            decode_zk_ams_batch_admission_wire_v1(&canonical, 1)
                .expect("canonical fixed-slot wire"),
            canonical_wire
        );
        let retired_wire = RetiredWireZkAmsBatchAdmissionProofV1 {
            version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
            relation_proof: Vec::new(),
            possession_proofs: Vec::new(),
        };
        let retired_wire_bytes = norito::codec::encode_adaptive(&retired_wire);
        assert_ne!(retired_wire_bytes, canonical);
        assert!(
            decode_zk_ams_batch_admission_wire_v1(&retired_wire_bytes, 1).is_err(),
            "the unreleased nested-Vec wire must not survive the first-release schema"
        );
        let mut retired_option_slots = [None; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1];
        retired_option_slots[0] = Some(ZkAmsAdmissionPossessionProofWireV1 {
            version: ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1,
            commitment: [1; 32],
            response: [2; 32],
        });
        let retired_option_array =
            norito::codec::encode_adaptive(&RetiredWireZkAmsOptionSlotsBatchAdmissionProofV1 {
                version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
                relation_proof: Vec::new(),
                possession_proofs: retired_option_slots,
            });
        assert_ne!(retired_option_array, canonical);
        assert!(
            decode_zk_ams_batch_admission_wire_v1(&retired_option_array, 1).is_err(),
            "the unreleased Option-array wire must not reach the first-release decoder"
        );
        let max_wire = ZkAmsBatchAdmissionProofWireV1 {
            version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
            relation_proof: Vec::new(),
            possession_proof_count: ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 as u8,
            possession_proofs: [ZkAmsAdmissionPossessionProofWireV1 {
                version: ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1,
                commitment: [3; 32],
                response: [4; 32],
            }; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1],
        };
        let max_encoded = norito::codec::encode_adaptive(&max_wire);
        assert_eq!(
            decode_zk_ams_batch_admission_wire_v1(
                &max_encoded,
                ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1,
            )
            .expect("all eight canonical slots"),
            max_wire
        );
        assert!(
            decode_zk_ams_batch_admission_wire_v1(&canonical[..canonical.len() - 1], 1).is_err()
        );
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode_zk_ams_batch_admission_wire_v1(&trailing, 1).is_err());
        assert!(
            decode_zk_ams_batch_admission_wire_v1(&canonical, 0).is_err(),
            "wire count must equal the statement anchor count"
        );
        assert!(
            decode_zk_ams_batch_admission_wire_v1(
                &canonical,
                ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 + 1,
            )
            .is_err(),
            "an expected count above the fixed profile must fail before decoding"
        );
        for (label, malformed) in [
            ("outer version", {
                let mut proof = canonical_wire.clone();
                proof.version ^= 1;
                proof
            }),
            ("zero count", {
                let mut proof = canonical_wire.clone();
                proof.possession_proof_count = 0;
                proof
            }),
            ("count beyond statement", {
                let mut proof = canonical_wire.clone();
                proof.possession_proof_count = 2;
                proof
            }),
            ("count beyond profile", {
                let mut proof = canonical_wire.clone();
                proof.possession_proof_count = u8::try_from(ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1 + 1)
                    .expect("fixed test count fits u8");
                proof
            }),
            ("used zero sentinel", {
                let mut proof = canonical_wire.clone();
                proof.possession_proofs[0] = ZkAmsAdmissionPossessionProofWireV1::UNUSED;
                proof
            }),
            ("unused nonzero version", {
                let mut proof = canonical_wire.clone();
                proof.possession_proofs[1].version = ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1;
                proof
            }),
            ("unused nonzero body", {
                let mut proof = canonical_wire.clone();
                proof.possession_proofs[1].commitment[0] = 1;
                proof
            }),
        ] {
            let encoded = norito::codec::encode_adaptive(&malformed);
            assert!(
                decode_zk_ams_batch_admission_wire_v1(&encoded, 1).is_err(),
                "{label} unexpectedly passed the canonical fixed-slot decoder"
            );
        }
        let oversized_count = MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 + 1;
        let oversized = ZkAmsBatchAdmissionProofWireV1 {
            version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
            relation_proof: vec![0; oversized_count],
            possession_proof_count: 0,
            possession_proofs: [ZkAmsAdmissionPossessionProofWireV1::UNUSED;
                ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1],
        };
        let encoded = norito::codec::encode_adaptive(&oversized);
        assert!(matches!(
            decode_raw(&encoded),
            Err(norito::Error::SequenceLengthExceeded { length, limit })
                if length == oversized_count as u64
                    && limit == MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1 as u64
        ));
        let encoded_count = (oversized_count as u64).to_le_bytes();
        let count_offset = encoded
            .windows(encoded_count.len())
            .position(|window| window == encoded_count)
            .expect("oversized relation count is present in canonical wire");
        let mut forged = encoded;
        forged[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            decode_raw(&forged).is_err(),
            "a forged maximum relation length must fail before allocation"
        );
    }
    #[test]
    fn lsag_rejects_invalid_ring_signer_image_and_randomness() {
        let ring = sorted_ring(16);
        let public = ring.iter().map(|(public, _)| *public).collect::<Vec<_>>();
        let image = zk_ams_key_image_v1(&ring[3].1).expect("key image");
        for invalid_size in [0, 1, 15, 17, 31, 33, 63, 65] {
            let invalid = sorted_ring(invalid_size)
                .into_iter()
                .map(|(public, _)| public)
                .collect::<Vec<_>>();
            assert!(matches!(
                verify_zk_ams_provision_v1(&binding(), &invalid, image, &[]),
                Err(ZkAmsErrorV1::InvalidRingSize {
                    actual
                }) if actual == invalid_size
            ));
        }
        let mut swapped = public.clone();
        swapped.swap(0, 1);
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &swapped, image, &[]),
            Err(ZkAmsErrorV1::NonCanonicalRing)
        ));
        let mut duplicate = public.clone();
        duplicate[1] = duplicate[0];
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &duplicate, image, &[]),
            Err(ZkAmsErrorV1::NonCanonicalRing)
        ));
        let mut rng = TestRng::new(4);
        assert!(matches!(
            sign_zk_ams_provision_v1(
                &binding(),
                &public,
                image,
                public.len(),
                &ring[3].1,
                &mut rng
            ),
            Err(ZkAmsErrorV1::SignerIndexOutOfBounds { .. })
        ));
        assert!(matches!(
            sign_zk_ams_provision_v1(&binding(), &public, image, 3, &ring[4].1, &mut rng),
            Err(ZkAmsErrorV1::SignerPublicKeyMismatch)
        ));
        let other_image = zk_ams_key_image_v1(&ring[4].1).expect("other key image");
        assert!(matches!(
            sign_zk_ams_provision_v1(&binding(), &public, other_image, 3, &ring[3].1, &mut rng),
            Err(ZkAmsErrorV1::KeyImageMismatch)
        ));
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, [0; 32], &[]),
            Err(ZkAmsErrorV1::InvalidPoint)
        ));
        assert!(matches!(
            sign_zk_ams_provision_v1(&binding(), &public, image, 3, &ring[3].1, &mut ZeroRng),
            Err(ZkAmsErrorV1::RandomnessHealthCheckFailed)
        ));
        assert!(matches!(
            sign_zk_ams_provision_v1(&binding(), &public, image, 3, &ring[3].1, &mut PeriodicRng),
            Err(ZkAmsErrorV1::RandomnessHealthCheckFailed)
        ));
    }
    #[test]
    fn lsag_wire_transcript_ring_and_image_mutations_fail_closed() {
        let signer_index = 7;
        let (ring, key_image, proof) = sign_fixture(16, signer_index);
        let public = ring.iter().map(|(public, _)| *public).collect::<Vec<_>>();
        for (label, changed) in mutate_every_binding_axis() {
            assert!(
                verify_zk_ams_provision_v1(&changed, &public, key_image, &proof).is_err(),
                "{label} replay must fail"
            );
        }
        let other_image = zk_ams_key_image_v1(&ring[8].1).expect("other image");
        assert!(verify_zk_ams_provision_v1(&binding(), &public, other_image, &proof).is_err());
        let mut substituted = public.clone();
        let outsider = seed_secret(90);
        substituted[0] = zk_ams_seed_public_key_v1(&outsider);
        substituted.sort();
        assert_ne!(substituted, public);
        assert!(verify_zk_ams_provision_v1(&binding(), &substituted, key_image, &proof).is_err());
        for truncated_len in [
            0,
            1,
            proof.len() / 4,
            proof.len() / 2,
            proof.len().saturating_sub(1),
        ] {
            assert!(
                verify_zk_ams_provision_v1(&binding(), &public, key_image, &proof[..truncated_len])
                    .is_err(),
                "truncation at {truncated_len} must fail"
            );
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &trailing),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
        assert!(matches!(
            verify_zk_ams_provision_v1(
                &binding(),
                &public,
                key_image,
                &vec![0; MAX_ZK_AMS_LSAG_PROOF_BYTES_V1 + 1]
            ),
            Err(ZkAmsErrorV1::ProofTooLarge { .. })
        ));
        let mut decoded = norito::codec::decode_exact_from_slice::<ZkAmsLsagProofWireV1>(&proof)
            .expect("decode proof");
        decoded.version ^= 1;
        let wrong_version = norito::codec::encode_adaptive(&decoded);
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &wrong_version),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
        decoded.version = ZK_AMS_LSAG_PROOF_VERSION_V1;
        decoded.responses[0] = [u8::MAX; 32];
        let noncanonical_scalar = norito::codec::encode_adaptive(&decoded);
        assert!(matches!(
            verify_zk_ams_provision_v1(&binding(), &public, key_image, &noncanonical_scalar),
            Err(ZkAmsErrorV1::InvalidScalar)
        ));
        let sample_count = 64_usize.min(proof.len());
        for sample in 0..sample_count {
            let offset = sample * proof.len() / sample_count;
            let mut corrupted = proof.clone();
            corrupted[offset] ^= 1_u8 << (sample % 8);
            assert!(
                verify_zk_ams_provision_v1(&binding(), &public, key_image, &corrupted).is_err(),
                "corruption sample {sample} at {offset} must fail"
            );
        }
    }
    #[test]
    fn possession_proof_binds_every_anchor_and_consensus_axis() {
        let secret = seed_secret(19);
        let public = zk_ams_seed_public_key_v1(&secret);
        let phc_hash = [0x31; 32];
        let relation_digest = [0x32; 32];
        let mut rng = TestRng::new(0x1234_5678_90ab_cdef);
        let proof = prove_zk_ams_admission_possession_v1(
            &binding(),
            3,
            phc_hash,
            public,
            relation_digest,
            &secret,
            &mut rng,
        )
        .expect("possession proof");
        verify_zk_ams_admission_possession_v1(
            &binding(),
            3,
            phc_hash,
            public,
            relation_digest,
            &proof,
        )
        .expect("valid possession proof");
        for (label, changed) in mutate_every_binding_axis() {
            assert!(
                verify_zk_ams_admission_possession_v1(
                    &changed,
                    3,
                    phc_hash,
                    public,
                    relation_digest,
                    &proof
                )
                .is_err(),
                "{label} replay must fail"
            );
        }
        for (label, index, phc, key, relation) in [
            ("anchor-index", 4, phc_hash, public, relation_digest),
            ("phc", 3, [0x33; 32], public, relation_digest),
            (
                "seed-key",
                3,
                phc_hash,
                zk_ams_seed_public_key_v1(&seed_secret(20)),
                relation_digest,
            ),
            ("relation", 3, phc_hash, public, [0x34; 32]),
        ] {
            assert!(
                verify_zk_ams_admission_possession_v1(
                    &binding(),
                    index,
                    phc,
                    key,
                    relation,
                    &proof
                )
                .is_err(),
                "{label} substitution must fail"
            );
        }
        assert!(matches!(
            verify_zk_ams_admission_possession_v1(
                &binding(),
                3,
                [0; 32],
                public,
                relation_digest,
                &proof
            ),
            Err(ZkAmsErrorV1::InvalidBinding)
        ));
        assert!(matches!(
            verify_zk_ams_admission_possession_v1(&binding(), 3, phc_hash, public, [0; 32], &proof),
            Err(ZkAmsErrorV1::InvalidBinding)
        ));
        assert!(matches!(
            prove_zk_ams_admission_possession_v1(
                &binding(),
                3,
                phc_hash,
                public,
                relation_digest,
                &seed_secret(21),
                &mut rng
            ),
            Err(ZkAmsErrorV1::SignerPublicKeyMismatch)
        ));
        for truncated_len in [0, 1, proof.len() / 2, proof.len().saturating_sub(1)] {
            assert!(
                verify_zk_ams_admission_possession_v1(
                    &binding(),
                    3,
                    phc_hash,
                    public,
                    relation_digest,
                    &proof[..truncated_len],
                )
                .is_err()
            );
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(matches!(
            verify_zk_ams_admission_possession_v1(
                &binding(),
                3,
                phc_hash,
                public,
                relation_digest,
                &trailing
            ),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
        assert!(matches!(
            verify_zk_ams_admission_possession_v1(
                &binding(),
                3,
                phc_hash,
                public,
                relation_digest,
                &vec![0; MAX_ZK_AMS_ADMISSION_POSSESSION_PROOF_BYTES_V1 + 1]
            ),
            Err(ZkAmsErrorV1::PossessionProofTooLarge { .. })
        ));
        for offset in 0..proof.len() {
            let mut corrupted = proof.clone();
            corrupted[offset] ^= 1_u8 << (offset % 8);
            assert!(
                verify_zk_ams_admission_possession_v1(
                    &binding(),
                    3,
                    phc_hash,
                    public,
                    relation_digest,
                    &corrupted
                )
                .is_err(),
                "possession corruption at {offset} must fail"
            );
        }
    }
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive test account");
        AccountId::new(key_pair.public_key().clone())
    }
    fn typed_context() -> PrivacyStatementContextV1 {
        PrivacyStatementContextV1 {
            network_id: network_id_from_genesis_hash_bytes([0x11; 32]),
            action_index: ZK_AMS_PRIVACY_ACTION_INDEX_V1,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x21; 32]),
            parameter_id: PrivacyParameterIdV1::new([0x22; 32]),
            parameter_digest: PrivacyParameterDigestV1::new([0x23; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([0x24; 32]),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new([0x25; 32]),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new([0x26; 32]),
        }
    }
    fn issuer_key() -> PrivacyP256PointV1 {
        let signing_key =
            P256SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed P-256 issuer key");
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        let bytes: [u8; 33] = encoded.as_bytes().try_into().expect("compressed P-256 key");
        PrivacyP256PointV1::new(bytes)
    }
    fn typed_batch_statement() -> IrohaZkAmsStatementV1 {
        let issuer_id = PrivacyIssuerIdV1::new([0x31; 32]);
        let registry_id = PrivacyZkAmsRegistryIdV1::new([0x33; 32]);
        let current_root = PrivacyRootV1::new([0x37; 32]);
        let current_epoch = 9;
        let next_epoch = current_epoch + 1;
        let anchor = PrivacyZkAmsAdmissionAnchorV1 {
            phc_hash: PrivacyZkAmsPhcHashV1::new([0x41; 32]),
            seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(zk_ams_seed_public_key_v1(
                &seed_secret(41),
            )),
        };
        let next_root = zk_ams_registry_transition_root_v1(
            registry_id,
            current_root,
            current_epoch,
            next_epoch,
            1,
            0,
            anchor,
        );
        IrohaZkAmsStatementV1 {
            context: typed_context(),
            issuer_id,
            issuer_public_key: issuer_key(),
            issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1::new([0x32; 32]),
            registry_id,
            registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1::new([0x34; 32]),
            policy_id: PrivacyPolicyIdV1::new([0x35; 32]),
            policy_digest: PrivacyPolicyDigestV1::new([0x36; 32]),
            action: PrivacyZkAmsActionV1::BatchAdmission(PrivacyZkAmsBatchAdmissionV1 {
                account_registry_root: current_root,
                account_registry_root_epoch: current_epoch,
                next_account_registry_root: next_root,
                next_account_registry_root_epoch: next_epoch,
                anchors: vec![anchor],
            }),
        }
    }
    fn typed_provision_statement(
        ring: &[([u8; 32], ZkAmsSeedSecretV1)],
        key_image: [u8; 32],
    ) -> IrohaZkAmsStatementV1 {
        IrohaZkAmsStatementV1 {
            context: typed_context(),
            issuer_id: PrivacyIssuerIdV1::new([0x31; 32]),
            issuer_public_key: issuer_key(),
            issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1::new([0x32; 32]),
            registry_id: PrivacyZkAmsRegistryIdV1::new([0x33; 32]),
            registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1::new([0x34; 32]),
            policy_id: PrivacyPolicyIdV1::new([0x35; 32]),
            policy_digest: PrivacyPolicyDigestV1::new([0x36; 32]),
            action: PrivacyZkAmsActionV1::ProvisionAccount(PrivacyZkAmsProvisionAccountV1 {
                account_registry_root: PrivacyRootV1::new([0x37; 32]),
                account_registry_root_epoch: 9,
                admitted_seed_key_ring: ring
                    .iter()
                    .map(|(public, _)| PrivacyZkAmsSeedPublicKeyV1::new(*public))
                    .collect(),
                account_id: account(40),
                key_image: PrivacyZkAmsKeyImageV1::new(key_image),
            }),
        }
    }
    fn intent_governance(statement: &IrohaZkAmsStatementV1) -> ZkAmsPrivacyActionGovernanceV1 {
        ZkAmsPrivacyActionGovernanceV1 {
            issuer_id: statement.issuer_id,
            issuer_public_key: statement.issuer_public_key,
            issuer_policy_record_digest: statement.issuer_policy_record_digest,
            registry_id: statement.registry_id,
            registry_record_digest: statement.registry_record_digest,
            policy_id: statement.policy_id,
            policy_digest: statement.policy_digest,
        }
    }
    fn intent_transaction_context(
        creation_time_ms: u64,
        nonce: u32,
    ) -> ZkAmsPrivacyActionTransactionContextV1 {
        ZkAmsPrivacyActionTransactionContextV1 {
            network_id: network_id_from_genesis_hash_bytes([0x11; 32]),
            authority: account(60),
            creation_time: Duration::from_millis(creation_time_ms),
            time_to_live: Some(Duration::from_secs(60)),
            nonce: NonZeroU32::new(nonce),
            fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
            metadata: Metadata::default(),
        }
    }
    fn sealed_provision_fixture() -> (
        ZkAmsPrivacyActionTransactionContextV1,
        ZkAmsPrivacyActionGovernanceV1,
        PrivacyZkAmsProvisionAccountV1,
        Vec<([u8; 32], ZkAmsSeedSecretV1)>,
    ) {
        let ring = sorted_ring(ZK_AMS_MIN_RING_SIZE_V1);
        let key_image = zk_ams_key_image_v1(&ring[5].1).expect("canonical key image");
        let template = typed_provision_statement(&ring, key_image);
        let PrivacyZkAmsActionV1::ProvisionAccount(action) = template.action.clone() else {
            unreachable!()
        };
        (
            intent_transaction_context(1_800_000_000_021, 21),
            intent_governance(&template),
            action,
            ring,
        )
    }
    #[test]
    fn public_transaction_intent_surface_stays_closed_before_release_readiness() {
        let template = typed_batch_statement();
        let PrivacyZkAmsActionV1::BatchAdmission(action) = template.action.clone() else {
            unreachable!()
        };
        let context = intent_transaction_context(1_800_000_000_012, 13);
        assert_eq!(
            prepare_zk_ams_batch_admission_transaction_intent_v1(
                &context,
                intent_governance(&template),
                action,
            ),
            Err(ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable),
        );
        assert_eq!(
            validate_zk_ams_privacy_action_transaction_intent_v1(&context, &template),
            Err(ZkAmsPrivacyActionIntentErrorV1::CompiledProfileUnavailable),
        );
    }
    #[test]
    fn sealed_provision_builder_preflights_public_failures_before_randomness() {
        let (context, governance, action, ring) = sealed_provision_fixture();
        assert!(matches!(
            prepare_zk_ams_provision_privacy_action_with_rng_v1(
                context,
                governance,
                action,
                5,
                &ring[5].1,
                [0; 32],
                &mut PanicRng,
            ),
            Err(ZkAmsPrivacyActionBuildErrorV1::ZeroGenesisHash)
        ));
        let (context, governance, action, ring) = sealed_provision_fixture();
        let foreign = KeyPair::try_from_seed(vec![61; 32], Algorithm::Ed25519)
            .expect("foreign transaction signer");
        assert!(matches!(
            build_signed_zk_ams_provision_privacy_action_with_rng_v1(
                context,
                governance,
                action,
                5,
                &ring[5].1,
                [0x11; 32],
                foreign.private_key(),
                &mut PanicRng,
            ),
            Err(ZkAmsPrivacyActionBuildErrorV1::AuthorityKeyMismatch)
        ));
    }
    fn binding_for_statement(statement: &IrohaZkAmsStatementV1) -> TranscriptBindingV1<'_> {
        let statement_digest = PrivacyStatementV1::IrohaZkAmsV1(statement.clone())
            .digest()
            .expect("typed statement digest");
        TranscriptBindingV1 {
            network_id: statement.context.network_id.as_bytes(),
            genesis_hash: [0x11; 32],
            action_index: statement.context.action_index,
            statement_digest: *statement_digest.as_bytes(),
            parameter_id: *statement.context.parameter_id.as_bytes(),
            parameter_digest: *statement.context.parameter_digest.as_bytes(),
            verifier_digest: *statement.context.verifier_digest.as_bytes(),
            statement_schema_digest: *statement.context.statement_schema_digest.as_bytes(),
            engine_manifest_digest: *statement.context.engine_manifest_digest.as_bytes(),
            generator_digest: zk_ams_generator_digest_v1(),
        }
    }
    #[test]
    #[ignore = "release gate: proves the full masked ZK-AMS admission relation"]
    fn complete_batch_admission_proves_verifies_and_fails_closed() {
        let issuer_signing_key =
            P256SigningKey::from_bytes((&[7_u8; 32]).into()).expect("fixed issuer key");
        let issuer_id = PrivacyIssuerIdV1::new([0x31; 32]);
        let policy_id = PrivacyPolicyIdV1::new([0x35; 32]);
        let registry_id = PrivacyZkAmsRegistryIdV1::new([0x33; 32]);
        let current_root = PrivacyRootV1::new([0x37; 32]);
        let current_epoch = 9_u64;
        let next_epoch = current_epoch + 1;
        let seed_secrets = [seed_secret(41), seed_secret(42)];
        let credentials = seed_secrets
            .iter()
            .enumerate()
            .map(|(index, secret)| PrivacyZkAmsPersonhoodCredentialV1 {
                version: ZK_AMS_PHC_VERSION_V1,
                issuer_id,
                policy_id,
                subject_commitment: PrivacyZkAmsSubjectCommitmentV1::new(
                    [0x41 + u8::try_from(index).expect("bounded fixture"); 32],
                ),
                seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(zk_ams_seed_public_key_v1(
                    secret,
                )),
                credential_nonce: PrivacyZkAmsCredentialNonceV1::new(
                    [0x51 + u8::try_from(index).expect("bounded fixture"); 32],
                ),
            })
            .collect::<Vec<_>>();
        let signatures = credentials
            .iter()
            .map(|credential| {
                let signature: P256Signature = issuer_signing_key
                    .sign_prehash(credential.digest().as_bytes())
                    .expect("issuer prehash signature");
                let signature = signature.normalize_s().unwrap_or(signature);
                <[u8; 64]>::from(signature.to_bytes())
            })
            .collect::<Vec<_>>();
        let anchors = credentials
            .iter()
            .map(|credential| PrivacyZkAmsAdmissionAnchorV1 {
                phc_hash: credential.digest(),
                seed_public_key: credential.seed_public_key,
            })
            .collect::<Vec<_>>();
        let batch_size = u32::try_from(anchors.len()).expect("bounded fixture");
        let next_root = anchors.iter().copied().enumerate().fold(
            current_root,
            |prior_root, (index, anchor)| {
                zk_ams_registry_transition_root_v1(
                    registry_id,
                    prior_root,
                    current_epoch,
                    next_epoch,
                    batch_size,
                    u32::try_from(index).expect("bounded fixture"),
                    anchor,
                )
            },
        );
        let statement = IrohaZkAmsStatementV1 {
            context: typed_context(),
            issuer_id,
            issuer_public_key: issuer_key(),
            issuer_policy_record_digest: PrivacyZkAmsIssuerPolicyRecordDigestV1::new([0x32; 32]),
            registry_id,
            registry_record_digest: PrivacyZkAmsRegistryRecordDigestV1::new([0x34; 32]),
            policy_id,
            policy_digest: PrivacyPolicyDigestV1::new([0x36; 32]),
            action: PrivacyZkAmsActionV1::BatchAdmission(PrivacyZkAmsBatchAdmissionV1 {
                account_registry_root: current_root,
                account_registry_root_epoch: current_epoch,
                next_account_registry_root: next_root,
                next_account_registry_root_epoch: next_epoch,
                anchors: anchors.clone(),
            }),
        };
        let binding = binding_for_statement(&statement);
        let witnesses = credentials
            .iter()
            .zip(&signatures)
            .zip(&seed_secrets)
            .map(|((credential, signature), secret)| {
                ZkAmsBatchCredentialWitnessV1::new(credential, signature, secret)
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            prove_zk_ams_batch_admission_v1(
                &statement,
                &binding,
                &witnesses[..1],
                ZkAmsMaskedProverConfigV1::new(1).expect("worker count"),
                &mut TestRng::new(1),
            ),
            Err(ZkAmsErrorV1::CredentialMismatch)
        ));
        let wrong_secret = seed_secret(43);
        let wrong_secret_witnesses = [
            ZkAmsBatchCredentialWitnessV1::new(&credentials[0], &signatures[0], &wrong_secret),
            ZkAmsBatchCredentialWitnessV1::new(&credentials[1], &signatures[1], &seed_secrets[1]),
        ];
        assert!(matches!(
            prove_zk_ams_batch_admission_v1(
                &statement,
                &binding,
                &wrong_secret_witnesses,
                ZkAmsMaskedProverConfigV1::new(1).expect("worker count"),
                &mut TestRng::new(2),
            ),
            Err(ZkAmsErrorV1::InvalidCredential)
        ));
        let mut invalid_signatures = signatures.clone();
        invalid_signatures[0][0] ^= 1;
        let invalid_signature_witnesses = [
            ZkAmsBatchCredentialWitnessV1::new(
                &credentials[0],
                &invalid_signatures[0],
                &seed_secrets[0],
            ),
            ZkAmsBatchCredentialWitnessV1::new(
                &credentials[1],
                &invalid_signatures[1],
                &seed_secrets[1],
            ),
        ];
        assert!(matches!(
            prove_zk_ams_batch_admission_v1(
                &statement,
                &binding,
                &invalid_signature_witnesses,
                ZkAmsMaskedProverConfigV1::new(1).expect("worker count"),
                &mut TestRng::new(3),
            ),
            Err(ZkAmsErrorV1::InvalidIssuerSignature)
        ));
        let low_s = P256Signature::from_slice(&signatures[0]).expect("canonical signature");
        let (r, s) = low_s.split_scalars();
        let high_s =
            P256Signature::from_scalars(r.to_repr(), (-*s).to_repr()).expect("high-s counterpart");
        assert!(high_s.normalize_s().is_some());
        let high_s_bytes = <[u8; 64]>::from(high_s.to_bytes());
        let high_s_witnesses = [
            ZkAmsBatchCredentialWitnessV1::new(&credentials[0], &high_s_bytes, &seed_secrets[0]),
            ZkAmsBatchCredentialWitnessV1::new(&credentials[1], &signatures[1], &seed_secrets[1]),
        ];
        assert!(matches!(
            prove_zk_ams_batch_admission_v1(
                &statement,
                &binding,
                &high_s_witnesses,
                ZkAmsMaskedProverConfigV1::new(1).expect("worker count"),
                &mut TestRng::new(4),
            ),
            Err(ZkAmsErrorV1::HighSIssuerSignature)
        ));
        let mut rng = TestRng::new(0x1a2b_3c4d_5e6f_7788);
        let proof = prove_zk_ams_batch_admission_v1(
            &statement,
            &binding,
            &witnesses,
            ZkAmsMaskedProverConfigV1::new(1).expect("worker count"),
            &mut rng,
        )
        .expect("complete batch admission proof");
        let effect = verify_zk_ams_batch_admission_v1(&statement, &binding, &proof)
            .expect("complete batch admission verification");
        assert_eq!(effect.issuer_id, issuer_id);
        assert_eq!(effect.policy_id, policy_id);
        assert_eq!(effect.registry_id, registry_id);
        assert_eq!(effect.current_root, current_root);
        assert_eq!(effect.current_epoch, current_epoch);
        assert_eq!(effect.next_root, next_root);
        assert_eq!(effect.next_epoch, next_epoch);
        assert_eq!(effect.anchors, anchors);
        let mut replay_binding = binding;
        replay_binding.action_index += 1;
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(&statement, &replay_binding, &proof),
            Err(ZkAmsErrorV1::BindingMismatch)
        ));
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(&statement, &binding, &trailing),
            Err(ZkAmsErrorV1::InvalidProofEncoding)
        ));
        let mut corrupted = proof;
        let offset = corrupted.len() / 2;
        corrupted[offset] ^= 0x80;
        assert!(
            verify_zk_ams_batch_admission_v1(&statement, &binding, &corrupted).is_err(),
            "one-bit proof corruption must fail closed"
        );
    }
    #[test]
    fn batch_preflights_possession_body_before_expensive_relation_verification() {
        let statement = typed_batch_statement();
        let binding = binding_for_statement(&statement);
        let mut possession_proofs =
            [ZkAmsAdmissionPossessionProofWireV1::UNUSED; ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1];
        possession_proofs[0] = ZkAmsAdmissionPossessionProofWireV1 {
            version: ZK_AMS_ADMISSION_POSSESSION_PROOF_VERSION_V1,
            commitment: zk_ams_seed_public_key_v1(&seed_secret(42)),
            response: [0; 32],
        };
        let mut wire = ZkAmsBatchAdmissionProofWireV1 {
            version: ZK_AMS_BATCH_ADMISSION_PROOF_VERSION_V1,
            relation_proof: vec![0xff],
            possession_proof_count: 1,
            possession_proofs,
        };
        let mut wrong_binding = binding;
        wrong_binding.action_index ^= 1;
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(
                &statement,
                &wrong_binding,
                &vec![0; MAX_ZK_AMS_BATCH_ADMISSION_PROOF_BYTES_V1 + 1],
            ),
            Err(ZkAmsErrorV1::BatchProofTooLarge { .. })
        ));
        let invalid_relation = norito::codec::encode_adaptive(&wire);
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(&statement, &binding, &invalid_relation),
            Err(ZkAmsErrorV1::AdmissionRelation)
        ));
        wire.possession_proofs[0].response = [0xff; 32];
        let invalid_scalar = norito::codec::encode_adaptive(&wire);
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(&statement, &binding, &invalid_scalar),
            Err(ZkAmsErrorV1::InvalidScalar)
        ));
        wire.possession_proofs[0].commitment = [0; 32];
        let identity_commitment = norito::codec::encode_adaptive(&wire);
        assert!(matches!(
            verify_zk_ams_batch_admission_v1(&statement, &binding, &identity_commitment),
            Err(ZkAmsErrorV1::InvalidPoint)
        ));
    }
    #[test]
    fn typed_provisioning_binds_all_state_message_ring_and_image_fields() {
        let signer_index = 5;
        let ring = sorted_ring(16);
        let key_image = zk_ams_key_image_v1(&ring[signer_index].1).expect("key image");
        let statement = typed_provision_statement(&ring, key_image);
        let binding = binding_for_statement(&statement);
        let mut rng = TestRng::new(0xfeed_face_cafe_beef);
        let proof = sign_zk_ams_provision_statement_v1(
            &statement,
            &binding,
            signer_index,
            &ring[signer_index].1,
            &mut rng,
        )
        .expect("typed provisioning proof");
        let effect = verify_zk_ams_provision_statement_v1(&statement, &binding, &proof)
            .expect("typed provisioning verification");
        let PrivacyZkAmsActionV1::ProvisionAccount(provision) = &statement.action else {
            unreachable!()
        };
        assert_eq!(effect.issuer_id, statement.issuer_id);
        assert_eq!(effect.registry_id, statement.registry_id);
        assert_eq!(effect.current_root, provision.account_registry_root);
        assert_eq!(effect.current_epoch, provision.account_registry_root_epoch);
        assert_eq!(effect.ring, provision.admitted_seed_key_ring);
        assert_eq!(effect.account_id, provision.account_id);
        assert_eq!(effect.key_image, provision.key_image);
        let mutations: [(&str, fn(&mut IrohaZkAmsStatementV1)); 12] = [
            ("issuer", |value| value.issuer_id.0[0] ^= 1),
            ("issuer-key", |value| value.issuer_public_key.0[0] ^= 1),
            ("issuer-record", |value| {
                value.issuer_policy_record_digest.0[0] ^= 1
            }),
            ("registry", |value| value.registry_id.0[0] ^= 1),
            ("registry-record", |value| {
                value.registry_record_digest.0[0] ^= 1
            }),
            ("policy", |value| value.policy_id.0[0] ^= 1),
            ("policy-digest", |value| value.policy_digest.0[0] ^= 1),
            ("transaction-intent", |value| {
                value.context.transaction_intent_digest.0[0] ^= 1
            }),
            ("root", |value| {
                let PrivacyZkAmsActionV1::ProvisionAccount(action) = &mut value.action else {
                    unreachable!()
                };
                action.account_registry_root.0[0] ^= 1;
            }),
            ("epoch", |value| {
                let PrivacyZkAmsActionV1::ProvisionAccount(action) = &mut value.action else {
                    unreachable!()
                };
                action.account_registry_root_epoch += 1;
            }),
            ("account", |value| {
                let PrivacyZkAmsActionV1::ProvisionAccount(action) = &mut value.action else {
                    unreachable!()
                };
                action.account_id = account(41);
            }),
            ("key-image", |value| {
                let PrivacyZkAmsActionV1::ProvisionAccount(action) = &mut value.action else {
                    unreachable!()
                };
                action.key_image.0[0] ^= 1;
            }),
        ];
        for (label, mutate) in mutations {
            let mut changed = statement.clone();
            mutate(&mut changed);
            let changed_binding = binding_for_statement(&changed);
            assert!(
                verify_zk_ams_provision_statement_v1(&changed, &changed_binding, &proof).is_err(),
                "{label} substitution must fail"
            );
        }
        let mut noncanonical_action_index = statement.clone();
        noncanonical_action_index.context.action_index = 1;
        let noncanonical_binding = binding_for_statement(&noncanonical_action_index);
        assert_eq!(
            verify_zk_ams_provision_statement_v1(
                &noncanonical_action_index,
                &noncanonical_binding,
                &proof,
            ),
            Err(ZkAmsErrorV1::InvalidBinding),
            "first-release ZK-AMS admits only action index zero",
        );
        let mut changed = statement.clone();
        let PrivacyZkAmsActionV1::ProvisionAccount(action) = &mut changed.action else {
            unreachable!()
        };
        action.admitted_seed_key_ring.swap(0, 1);
        let changed_binding = binding_for_statement(&changed);
        assert!(matches!(
            verify_zk_ams_provision_statement_v1(&changed, &changed_binding, &proof),
            Err(ZkAmsErrorV1::NonCanonicalRing)
        ));
        let mut wrong_action = statement;
        wrong_action.action = PrivacyZkAmsActionV1::BatchAdmission(PrivacyZkAmsBatchAdmissionV1 {
            account_registry_root: PrivacyRootV1::new([1; 32]),
            account_registry_root_epoch: 1,
            next_account_registry_root: PrivacyRootV1::new([2; 32]),
            next_account_registry_root_epoch: 2,
            anchors: vec![PrivacyZkAmsAdmissionAnchorV1 {
                phc_hash: iroha_data_model::privacy::PrivacyZkAmsPhcHashV1::new([3; 32]),
                seed_public_key: PrivacyZkAmsSeedPublicKeyV1::new(ring[0].0),
            }],
        });
        let wrong_binding = binding_for_statement(&wrong_action);
        assert!(matches!(
            verify_zk_ams_provision_statement_v1(&wrong_action, &wrong_binding, &proof),
            Err(ZkAmsErrorV1::InvalidStatement)
        ));
    }
}
