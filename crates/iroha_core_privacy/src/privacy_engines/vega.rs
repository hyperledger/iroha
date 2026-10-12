//! Canonical native Vega engine for ISO/IEC 18013-5 mDL age proofs.
//!
//! The proof system follows Microsoft `vega-prover` commit
//! `c0ee259053cd12eaf43ed71b5cde375452b3ee4d` (MIT). The application relation
//! is the paper's Figure 9 mDL circuit, closed to one first-release profile.
mod artifacts;
mod cbor;
mod mdl;
pub use artifacts::{
    VEGA_MDL_FIGURE9_ARTIFACT_MANIFEST_SCHEMA_V1,
    VEGA_MDL_FIGURE9_ARTIFACT_MANIFEST_SCHEMA_VERSION_V1,
    VEGA_MDL_FIGURE9_KEY_ARTIFACT_MAX_BYTES_V1, VegaMdlFigure9ArtifactBindingV1,
    VegaMdlFigure9ArtifactLengthMismatchV1, VegaMdlFigure9ArtifactManifestV1,
    VegaMdlFigure9ArtifactQualificationErrorV1, VegaMdlFigure9ArtifactRoleV1,
    VegaMdlFigure9ArtifactSourceErrorV1, VegaMdlFigure9ProverArtifactInstallReceiptV1,
    VegaMdlFigure9ProverArtifactSourceV1, VegaMdlFigure9VerifierArtifactInstallReceiptV1,
    VegaMdlFigure9VerifierArtifactSourceV1,
    qualify_and_install_vega_mdl_figure9_prover_artifacts_v1,
    qualify_and_install_vega_mdl_figure9_verifier_artifact_v1,
};
use core::{fmt, num::NonZeroU32, time::Duration};
use iroha_crypto::{Hash, PrivateKey, PublicKey as IrohaPublicKey};
use iroha_data_model::{
    isi::privacy::SubmitPrivacyProofV1,
    prelude::{AccountId, NetworkId},
    privacy::{
        PrivacyChallengeV1, PrivacyConsensusLimitsV1, PrivacyP256PointV1, PrivacyProofBytesV1,
        PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1,
        PrivacySessionTranscriptDigestV1, PrivacyStatementContextV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyVegaDeviceAuthenticationDigestV1,
        PrivacyVegaIssuerRecordLifecycleV1, PrivacyVegaIssuerRecordV1, PrivacyVegaMdlDateV1,
        VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
        VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1, VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1,
        VEGA_MDL_MAX_PRESENTATION_YEAR_V1, VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1,
        VEGA_MDL_MIN_PRESENTATION_YEAR_V1, VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
        VegaExistingCredentialStatementV1,
    },
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
        signed::TransactionSignatureError,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_zkp_halo2::vega::{
    VEGA_MDL_ACTION_INDEX_V1, VegaFieldError, VegaMdlFigure9ErrorV1, VegaMdlProofContextV1,
    VegaMdlProofErrorV1, VegaMdlProverConfigV1, VegaRandomSourceErrorV1, VegaRandomSourceV1,
    VegaT256ScalarV1, prove_vega_mdl_figure9_v1, verify_vega_mdl_figure9_v1,
};
use p256::{
    EncodedPoint, PublicKey as P256PublicKey,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey,
        signature::hazmat::PrehashSigner as _,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand_core_06::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;
#[cfg(test)]
fn network_id_from_genesis_hash_bytes(hash: [u8; 32]) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(hash),
        ),
    )
}
use super::prover_randomness::{HealthCheckedCryptoRngV1, ProverRandomnessErrorV1};
pub use mdl::{
    VegaEcdsaWitnessV1, VegaMdlLookupTableV1, VegaMdlValidatedWitnessV1, VegaMdlWitnessV1,
    validate_mdl_witness,
};
/// Pinned upstream source revision implemented by this engine.
pub const VEGA_PINNED_SOURCE_COMMIT_V1: &[u8] = b"c0ee259053cd12eaf43ed71b5cde375452b3ee4d";
/// Canonical Figure 9 public-input count.
pub const VEGA_MDL_PUBLIC_INPUT_COUNT_V1: usize = 14;
/// Domain of the Iroha device-authentication binding frame.
pub const VEGA_MDL_DEVICE_AUTHENTICATION_DOMAIN_V1: &[u8] =
    b"iroha.vega.mdl.device-authentication.v1";
/// Version of the Iroha device-authentication binding frame.
pub const VEGA_MDL_DEVICE_AUTHENTICATION_FRAME_VERSION_V1: u8 = 1;
/// Exact ISO/IEC 18013-5 mDL document type.
pub const VEGA_MDL_DOCUMENT_TYPE_V1: &[u8] = b"org.iso.18013.5.1.mDL";
/// Exact ISO/IEC 18013-5 mDL namespace.
pub const VEGA_MDL_NAMESPACE_V1: &[u8] = b"org.iso.18013.5.1";
/// Sole privacy-action index in a canonical first-release Vega transaction.
pub const VEGA_PRIVACY_ACTION_INDEX_V1: u32 = VEGA_MDL_ACTION_INDEX_V1;
/// Deterministic commitment worker count used by the first-release action API.
pub const VEGA_PRIVACY_ACTION_PROVER_WORKERS_V1: usize = 1;
/// Exact signature-bound transaction fields for one direct Vega action.
#[derive(Clone, Debug)]
pub struct VegaPrivacyActionTransactionContextV1 {
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
/// Public Vega action inputs that are independent of transaction-derived fields.
///
/// The statement context, transaction intent, and device-authentication digest
/// are deliberately absent. The canonical action API derives all three instead
/// of accepting self-referential caller values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VegaPrivacyActionPublicInputV1 {
    /// Exact active authoritative issuer revision.
    pub issuer_record: PrivacyVegaIssuerRecordV1,
    /// Public trusted UTC presentation date.
    pub presentation_date: PrivacyVegaMdlDateV1,
    /// Public minimum age threshold in completed Gregorian years.
    pub minimum_age_years: u8,
    /// Fresh reader challenge.
    pub reader_challenge: PrivacyChallengeV1,
    /// Digest of the canonical ISO 18013-5 session transcript.
    pub session_transcript_digest: PrivacySessionTranscriptDigestV1,
}
/// Private document material needed before the final device signature exists.
///
/// The holder-device signature is intentionally absent because `H_dev` includes the
/// transaction-intent digest. The action API derives the intent, constructs final `H_dev`, and
/// signs it with the separately supplied device key before native witness validation and proving.
pub struct VegaPrivacyActionWitnessMaterialV1 {
    issuer_authentication_sig_structure: Zeroizing<Vec<u8>>,
    mobile_security_object_payload: Zeroizing<Vec<u8>>,
    birth_date_issuer_signed_item: Zeroizing<Vec<u8>>,
    issuer_signature: Zeroizing<[u8; 64]>,
}
impl fmt::Debug for VegaPrivacyActionWitnessMaterialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VegaPrivacyActionWitnessMaterialV1")
            .field(
                "issuer_authentication_sig_structure_bytes",
                &self.issuer_authentication_sig_structure.len(),
            )
            .field(
                "mobile_security_object_payload_bytes",
                &self.mobile_security_object_payload.len(),
            )
            .field(
                "birth_date_issuer_signed_item_bytes",
                &self.birth_date_issuer_signed_item.len(),
            )
            .field("private_values", &"[REDACTED]")
            .finish()
    }
}
impl VegaPrivacyActionWitnessMaterialV1 {
    /// Construct exact-shape private material for one Vega action.
    ///
    /// # Errors
    ///
    /// Returns [`VegaMdlError::InvalidInputLength`] unless every private
    /// document fragment has its one released canonical byte width.
    pub fn new(
        issuer_authentication_sig_structure: Vec<u8>,
        mobile_security_object_payload: Vec<u8>,
        birth_date_issuer_signed_item: Vec<u8>,
        issuer_signature: &[u8],
    ) -> Result<Self, VegaMdlError> {
        // Take zeroizing ownership before the first fallible check so malformed
        // private material is erased on every constructor return path.
        let issuer_authentication_sig_structure =
            Zeroizing::new(issuer_authentication_sig_structure);
        let mobile_security_object_payload = Zeroizing::new(mobile_security_object_payload);
        let birth_date_issuer_signed_item = Zeroizing::new(birth_date_issuer_signed_item);
        for (field, actual, expected) in [
            (
                "issuer_authentication_sig_structure",
                issuer_authentication_sig_structure.len(),
                VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1,
            ),
            (
                "mobile_security_object_payload",
                mobile_security_object_payload.len(),
                VEGA_MDL_MSO_PAYLOAD_BYTES_V1,
            ),
            (
                "birth_date_issuer_signed_item",
                birth_date_issuer_signed_item.len(),
                VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1,
            ),
            ("issuer_signature", issuer_signature.len(), 64),
        ] {
            if actual != expected {
                return Err(VegaMdlError::InvalidInputLength {
                    field,
                    actual,
                    expected,
                });
            }
        }
        let mut issuer_signature_bytes = Zeroizing::new([0_u8; 64]);
        issuer_signature_bytes.copy_from_slice(issuer_signature);
        Ok(Self {
            issuer_authentication_sig_structure,
            mobile_security_object_payload,
            birth_date_issuer_signed_item,
            issuer_signature: issuer_signature_bytes,
        })
    }
    fn witness_with_device_signature(
        &self,
        device_signature: Zeroizing<[u8; 64]>,
    ) -> Result<VegaMdlWitnessV1, VegaMdlError> {
        VegaMdlWitnessV1::from_zeroizing_parts(
            self.issuer_authentication_sig_structure.clone(),
            self.mobile_security_object_payload.clone(),
            self.birth_date_issuer_signed_item.clone(),
            self.issuer_signature.clone(),
            device_signature,
        )
    }
}
/// Ledger-effect classification for a first-release Vega action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VegaPrivacyActionEffectV1 {
    /// The chain verifies and finalizes the action without a ledger mutation.
    ActionVerificationAndFinalityOnly,
}
/// Pure Vega proving output ready for transaction signing.
///
/// Its payload is the final two-pass payload. Public callers cannot replace
/// the executable, proof, statement, attachments, or signature-bound fields
/// before signing it through [`sign_prepared_vega_privacy_action_v1`].
pub struct VegaPreparedPrivacyActionV1 {
    payload: TransactionPayload,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
impl fmt::Debug for VegaPreparedPrivacyActionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VegaPreparedPrivacyActionV1")
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
impl VegaPreparedPrivacyActionV1 {
    /// Borrow the final, already revalidated payload for the isolated native
    /// release-evidence runner.
    ///
    /// This hook is absent from daemon builds and never exposes private
    /// document or signing-key material.
    #[cfg(feature = "privacy-release-evidence")]
    #[doc(hidden)]
    pub const fn release_evidence_payload_v1(&self) -> &TransactionPayload {
        &self.payload
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
    /// This component action has no inferred ledger mutation.
    #[must_use]
    pub const fn effect(&self) -> VegaPrivacyActionEffectV1 {
        VegaPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
    }
}
/// Complete signed result produced by the canonical Vega action path.
pub struct SignedVegaPrivacyActionV1 {
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
    adaptive_signed_transaction_bytes: u32,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
impl fmt::Debug for SignedVegaPrivacyActionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedVegaPrivacyActionV1")
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
            .finish_non_exhaustive()
    }
}
impl SignedVegaPrivacyActionV1 {
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
    /// This component action has no inferred ledger mutation.
    #[must_use]
    pub const fn effect(&self) -> VegaPrivacyActionEffectV1 {
        VegaPrivacyActionEffectV1::ActionVerificationAndFinalityOnly
    }
}
/// Consensus field whose duplicated binding did not match the public statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VegaBindingFieldV1 {
    /// Genesis-header-derived network identity.
    NetworkId,
    /// Action index.
    ActionIndex,
    /// Parameter-set identifier.
    ParameterId,
    /// Parameter-set digest.
    ParameterDigest,
    /// Verifier digest.
    VerifierDigest,
    /// Statement-schema digest.
    StatementSchemaDigest,
    /// Engine-manifest digest.
    EngineManifestDigest,
}
/// ECDSA role used by a Vega witness diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VegaSignatureRoleV1 {
    /// Credential issuer authentication.
    Issuer,
    /// Holder-device authentication.
    Device,
}
/// Failure returned by the closed Vega mDL engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VegaMdlError {
    /// A duplicated consensus binding differs from the statement context.
    #[error("Vega consensus binding mismatches statement field {field:?}")]
    BindingMismatch {
        /// Mismatched field.
        field: VegaBindingFieldV1,
    },
    /// The typed network identity and explicit genesis hash differ.
    #[error("Vega network id differs from its genesis hash")]
    NetworkGenesisMismatch,
    /// A mandatory consensus digest is the all-zero sentinel.
    #[error("Vega consensus digest `{field}` must be non-zero")]
    ZeroConsensusDigest {
        /// Stable field label.
        field: &'static str,
    },
    /// Epoch zero cannot select an authoritative issuer revision.
    #[error("Vega issuer-record epoch must be non-zero")]
    ZeroIssuerRecordEpoch,
    /// A canonical frame label or value does not fit its length prefix.
    #[error("Vega device-authentication frame field is too large")]
    FrameFieldTooLarge,
    /// The statement's device digest is not the canonical Iroha binding hash.
    #[error("Vega device-authentication digest does not match the consensus frame")]
    DeviceAuthenticationDigestMismatch,
    /// A trusted block timestamp cannot be represented as an admitted UTC date.
    #[error("Vega trusted block timestamp is outside the admitted UTC range")]
    TrustedTimestampOutOfRange,
    /// The public date differs from the trusted block timestamp's UTC date.
    #[error("Vega public presentation date differs from trusted UTC block date")]
    TrustedPresentationDateMismatch,
    /// A public or private date is not a valid proleptic Gregorian date.
    #[error("Vega `{field}` is not a valid Gregorian date")]
    InvalidDate {
        /// Stable date field label.
        field: &'static str,
    },
    /// The public age threshold is outside the closed first-release range.
    #[error("Vega age threshold {actual} is outside {min}..={max}")]
    InvalidAgeThreshold {
        /// Supplied threshold.
        actual: u8,
        /// Inclusive minimum.
        min: u8,
        /// Inclusive maximum.
        max: u8,
    },
    /// An input differs from the one canonical released byte width.
    #[error("Vega `{field}` length {actual} is not exactly {expected}")]
    InvalidInputLength {
        /// Stable input label.
        field: &'static str,
        /// Actual byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// Deterministic CBOR parsing failed.
    #[error("Vega input is not strict deterministic CBOR")]
    InvalidCanonicalCbor,
    /// The COSE `Sig_structure` is not the exact first-release shape.
    #[error("Vega issuer COSE Sig_structure has an invalid shape")]
    InvalidIssuerSignatureStructure,
    /// The protected COSE header is not exactly `{1: -7}`.
    #[error("Vega protected COSE header is not the closed ES256 profile")]
    InvalidProtectedHeader,
    /// The authenticated COSE payload differs from the supplied MSO payload.
    #[error("Vega issuer COSE payload is not the supplied MSO payload")]
    IssuerPayloadMismatch,
    /// A Tag-24 byte-string wrapper is absent or malformed.
    #[error("Vega `{field}` is not a canonical Tag-24 encoded-CBOR byte string")]
    InvalidTag24Wrapper {
        /// Stable wrapped field label.
        field: &'static str,
    },
    /// A mandatory MSO or signed-item field is missing.
    #[error("Vega document field `{field}` is missing")]
    MissingDocumentField {
        /// Stable field label.
        field: &'static str,
    },
    /// A mandatory field has the wrong CBOR type or shape.
    #[error("Vega document field `{field}` has an invalid CBOR shape")]
    InvalidDocumentFieldShape {
        /// Stable field label.
        field: &'static str,
    },
    /// A mandatory field differs from the closed first-release value.
    #[error("Vega document field `{field}` is outside the closed profile")]
    InvalidDocumentFieldValue {
        /// Stable field label.
        field: &'static str,
    },
    /// A P-256 public key is malformed, non-canonical, off-curve, or identity.
    #[error("Vega `{field}` is not a valid P-256 public key")]
    InvalidP256PublicKey {
        /// Stable public-key label.
        field: &'static str,
    },
    /// An ECDSA signature component is zero, non-canonical, or outside P-256's scalar order.
    #[error("Vega {role:?} ES256 signature encoding is invalid")]
    InvalidSignatureEncoding {
        /// Signature role.
        role: VegaSignatureRoleV1,
    },
    /// An otherwise valid ES256 signature used the malleable high-s
    /// representative instead of the sole admitted low-s representative.
    #[error("Vega {role:?} ES256 signature is non-canonical high-s")]
    NonCanonicalHighSSignature {
        /// Signature role.
        role: VegaSignatureRoleV1,
    },
    /// Native ES256 verification failed during witness preflight.
    #[error("Vega {role:?} ES256 signature verification failed")]
    SignatureVerificationFailed {
        /// Signature role.
        role: VegaSignatureRoleV1,
    },
    /// The birth signed-item digest does not match its authenticated MSO entry.
    #[error("Vega birth-date signed-item digest mismatch")]
    BirthDateDigestMismatch,
    /// The credential is expired on the public presentation date.
    #[error("Vega credential validUntil date must be after presentation date")]
    CredentialExpired,
    /// The issuer's signing timestamp follows the credential's activation timestamp.
    #[error("Vega credential signed timestamp must not follow validFrom timestamp")]
    CredentialSignedAfterValidFrom,
    /// The credential is not active on the public presentation date.
    #[error("Vega credential validFrom date must not follow presentation date")]
    CredentialNotYetValid,
    /// The private date of birth follows the presentation date.
    #[error("Vega birth date follows the presentation date")]
    BirthDateAfterPresentation,
    /// The private date of birth does not satisfy the public age threshold.
    #[error("Vega completed Gregorian age is below the public threshold")]
    AgeThresholdNotMet,
    /// An address used by the lookup relation cannot be represented by the
    /// fixed `u32` witness format.
    #[error("Vega lookup address does not fit u32")]
    LookupAddressOverflow,
    /// A Figure 9 public input is not canonical in the T256 scalar field.
    #[error("Vega Figure 9 public input is not a canonical T256 scalar")]
    InvalidPublicInputScalar,
    /// The witness is not the one released exact deterministic-CBOR profile.
    #[error("Vega witness is not the released exact Figure 9 encoding")]
    InvalidClosedProfileEncoding,
    /// The operating-system or caller-supplied cryptographic RNG failed.
    #[error("Vega cryptographic random source is unavailable")]
    RandomnessUnavailable,
    /// The random source emitted a catastrophic constant or short-period prefix.
    #[error("Vega cryptographic random source failed its health check")]
    RandomnessHealthCheckFailed,
    /// A locally constructed proof failed the independent public verifier.
    #[error("Vega prover self-check failed")]
    ProverSelfCheckFailed,
    /// Canonical proof construction, decoding, or verification failed.
    #[error(transparent)]
    Proof(#[from] VegaMdlProofErrorV1),
}
/// Failure while preparing or signing the canonical Vega privacy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VegaPrivacyActionBuildErrorV1 {
    /// The caller supplied the all-zero genesis sentinel.
    #[error("Vega action requires a non-zero canonical genesis hash")]
    ZeroGenesisHash,
    /// The signed transaction domain does not equal the supplied canonical genesis hash.
    #[error("Vega action transaction network does not match the canonical genesis hash")]
    NetworkIdMismatch,
    /// Creation time cannot be represented in the transaction wire.
    #[error("Vega action creation time cannot be represented in milliseconds")]
    CreationTimeOutOfRange,
    /// TTL cannot be represented in the transaction wire.
    #[error("Vega action TTL cannot be represented in milliseconds")]
    TimeToLiveOutOfRange,
    /// Fee intent, TTL, or fee metadata violates canonical transaction policy.
    #[error("Vega action transaction context is not canonical")]
    InvalidTransactionContext,
    /// The locally compiled governed Vega profile is unavailable.
    #[error("the compiled native Vega profile is unavailable")]
    CompiledProfileUnavailable,
    /// The supplied issuer revision is malformed, stale, or not active.
    #[error("Vega action requires one canonical active issuer revision")]
    InvalidIssuerRecord,
    /// The holder device key could not sign final `H_dev`.
    #[error("Vega holder-device authentication signing failed")]
    DeviceAuthenticationSigning,
    /// Native statement, witness, or proving validation failed.
    #[error(transparent)]
    Native(#[from] VegaMdlError),
    /// The typed statement failed consensus validation.
    #[error("the locally produced Vega statement failed validation")]
    StatementValidation,
    /// The typed statement could not derive its canonical digest.
    #[error("Vega action statement digest derivation failed")]
    StatementDigest,
    /// The typed statement could not be canonically encoded.
    #[error("the locally produced Vega statement could not be encoded")]
    StatementEncoding,
    /// The unsigned payload could not derive its canonical privacy intent.
    #[error("Vega action transaction-intent derivation failed")]
    TransactionIntent,
    /// The final proof envelope failed intrinsic consensus validation.
    #[error("the locally produced Vega proof envelope failed validation")]
    EnvelopeValidation,
    /// The final envelope could not be canonically encoded.
    #[error("the locally produced Vega proof envelope could not be encoded")]
    EnvelopeEncoding,
    /// The final one-action payload did not reproduce the draft intent.
    #[error("the locally produced Vega payload failed intent validation")]
    FinalIntentBinding,
    /// A prepared payload changed after proof construction.
    #[error("the prepared Vega payload no longer matches its sealed proof and statement")]
    PreparedPayloadDrift,
    /// A bounded canonical byte length did not fit its public result field.
    #[error("a canonical Vega action byte length overflowed")]
    EncodedLengthOverflow,
    /// The authority is multisig and cannot use this single-key constructor.
    #[error("the Vega action authority is not a single-key authority")]
    UnsupportedAuthority,
    /// The supplied private key does not control the exact authority.
    #[error("the supplied Vega action signing key does not control the authority")]
    AuthorityKeyMismatch,
    /// The transaction signature backend failed.
    #[error("Vega action transaction signing failed")]
    TransactionSigning,
    /// The signed payload no longer carries the prepared intent.
    #[error("signed Vega action intent differs from the prepared intent")]
    SignedIntentMismatch,
}
impl From<cbor::CborError> for VegaMdlError {
    fn from(_: cbor::CborError) -> Self {
        Self::InvalidCanonicalCbor
    }
}
impl From<VegaFieldError> for VegaMdlError {
    fn from(_: VegaFieldError) -> Self {
        Self::InvalidPublicInputScalar
    }
}
impl From<VegaMdlFigure9ErrorV1> for VegaMdlError {
    fn from(_: VegaMdlFigure9ErrorV1) -> Self {
        Self::InvalidClosedProfileEncoding
    }
}
/// Duplicated consensus values required to bind a public Vega statement to the
/// active chain and governed artifacts.
#[derive(Clone, Copy, Debug)]
pub struct VegaMdlConsensusBindingV1<'a> {
    /// Exact genesis-header-derived network-identity bytes.
    pub network_id: &'a [u8; 32],
    /// Hash of the exact genesis block or genesis manifest.
    pub genesis_hash: [u8; 32],
    /// Zero-based privacy action index inside its transaction.
    pub action_index: u32,
    /// Exact governed parameter-set identifier.
    pub parameter_id: [u8; 32],
    /// Digest of the governed parameter set.
    pub parameter_digest: [u8; 32],
    /// Digest of the exact verifier artifact.
    pub verifier_digest: [u8; 32],
    /// Digest of the exact typed public-statement schema.
    pub statement_schema_digest: [u8; 32],
    /// Digest of the native engine manifest admitted by governance.
    pub engine_manifest_digest: [u8; 32],
}
impl<'a> VegaMdlConsensusBindingV1<'a> {
    /// Build a binding from a statement context plus the independently trusted genesis hash.
    #[must_use]
    pub fn from_context(context: &'a PrivacyStatementContextV1, genesis_hash: [u8; 32]) -> Self {
        Self {
            network_id: context.network_id.as_bytes(),
            genesis_hash,
            action_index: context.action_index,
            parameter_id: *context.parameter_id.as_bytes(),
            parameter_digest: *context.parameter_digest.as_bytes(),
            verifier_digest: *context.verifier_digest.as_bytes(),
            statement_schema_digest: *context.statement_schema_digest.as_bytes(),
            engine_manifest_digest: *context.engine_manifest_digest.as_bytes(),
        }
    }
    /// Borrow the exact consensus frame used by the native proof transcript.
    #[must_use]
    pub const fn proof_context(&self) -> VegaMdlProofContextV1<'a> {
        VegaMdlProofContextV1 {
            // The protected Halo2 profile retains this internal field name;
            // these are exact NetworkId bytes, never a display label.
            chain_id: self.network_id,
            genesis_hash: self.genesis_hash,
            action_index: self.action_index,
            parameter_id: self.parameter_id,
            parameter_digest: self.parameter_digest,
            verifier_digest: self.verifier_digest,
            statement_schema_digest: self.statement_schema_digest,
            engine_manifest_digest: self.engine_manifest_digest,
        }
    }
    fn validate(&self, statement: &VegaExistingCredentialStatementV1) -> Result<(), VegaMdlError> {
        if self.network_id != &self.genesis_hash {
            return Err(VegaMdlError::NetworkGenesisMismatch);
        }
        if self.network_id != statement.context.network_id.as_bytes() {
            return Err(VegaMdlError::BindingMismatch {
                field: VegaBindingFieldV1::NetworkId,
            });
        }
        if self.action_index != VEGA_PRIVACY_ACTION_INDEX_V1
            || statement.context.action_index != VEGA_PRIVACY_ACTION_INDEX_V1
            || self.action_index != statement.context.action_index
        {
            return Err(VegaMdlError::BindingMismatch {
                field: VegaBindingFieldV1::ActionIndex,
            });
        }
        for (field, supplied, expected) in [
            (
                VegaBindingFieldV1::ParameterId,
                self.parameter_id,
                *statement.context.parameter_id.as_bytes(),
            ),
            (
                VegaBindingFieldV1::ParameterDigest,
                self.parameter_digest,
                *statement.context.parameter_digest.as_bytes(),
            ),
            (
                VegaBindingFieldV1::VerifierDigest,
                self.verifier_digest,
                *statement.context.verifier_digest.as_bytes(),
            ),
            (
                VegaBindingFieldV1::StatementSchemaDigest,
                self.statement_schema_digest,
                *statement.context.statement_schema_digest.as_bytes(),
            ),
            (
                VegaBindingFieldV1::EngineManifestDigest,
                self.engine_manifest_digest,
                *statement.context.engine_manifest_digest.as_bytes(),
            ),
        ] {
            if supplied != expected {
                return Err(VegaMdlError::BindingMismatch { field });
            }
        }
        for (field, digest) in [
            ("genesis_hash", self.genesis_hash),
            ("parameter_id", self.parameter_id),
            ("parameter_digest", self.parameter_digest),
            ("verifier_digest", self.verifier_digest),
            ("statement_schema_digest", self.statement_schema_digest),
            ("engine_manifest_digest", self.engine_manifest_digest),
        ] {
            if digest == [0; 32] {
                return Err(VegaMdlError::ZeroConsensusDigest { field });
            }
        }
        Ok(())
    }
}
/// Exact ordered T256 scalar public inputs for the Figure 9 relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VegaMdlPublicInputsV1 {
    elements: [VegaT256ScalarV1; VEGA_MDL_PUBLIC_INPUT_COUNT_V1],
}
impl VegaMdlPublicInputsV1 {
    /// Translate a typed public statement without reducing any 256-bit value.
    ///
    /// The order is `Q_I.x`, `Q_I.y`, the eight big-endian 32-bit words of
    /// `H_dev`, `Y`, `M`, `D`, and `tau`.
    ///
    /// # Errors
    ///
    /// Returns [`VegaMdlError`] for an invalid issuer key, Gregorian date, or
    /// non-canonical coordinate.
    pub fn from_statement(
        statement: &VegaExistingCredentialStatementV1,
    ) -> Result<Self, VegaMdlError> {
        validate_public_statement(statement)?;
        let (issuer_x, issuer_y) = p256_affine_coordinates(statement.issuer_public_key)?;
        let mut elements = [VegaT256ScalarV1::from_u64(0); VEGA_MDL_PUBLIC_INPUT_COUNT_V1];
        elements[0] = VegaT256ScalarV1::from_be_bytes_exact(issuer_x)?;
        elements[1] = VegaT256ScalarV1::from_be_bytes_exact(issuer_y)?;
        for (index, word) in statement
            .device_authentication_digest
            .as_bytes()
            .chunks_exact(4)
            .enumerate()
        {
            let value = u32::from_be_bytes(
                word.try_into()
                    .expect("four-byte chunks have an exact fixed width"),
            );
            elements[index + 2] = VegaT256ScalarV1::from_u64(u64::from(value));
        }
        elements[10] = VegaT256ScalarV1::from_u64(u64::from(statement.presentation_date.year));
        elements[11] = VegaT256ScalarV1::from_u64(u64::from(statement.presentation_date.month));
        elements[12] = VegaT256ScalarV1::from_u64(u64::from(statement.presentation_date.day));
        elements[13] = VegaT256ScalarV1::from_u64(u64::from(statement.minimum_age_years));
        Ok(Self { elements })
    }
    /// Borrow the exact ordered public-input vector.
    #[must_use]
    pub const fn as_array(&self) -> &[VegaT256ScalarV1; VEGA_MDL_PUBLIC_INPUT_COUNT_V1] {
        &self.elements
    }
}
struct CoreVegaRandomSource<'a, R> {
    source: HealthCheckedCryptoRngV1<'a, R>,
}
impl<'a, R> CoreVegaRandomSource<'a, R>
where
    R: RngCore + CryptoRng,
{
    fn new(source: &'a mut R) -> Result<Self, VegaMdlError> {
        let source = HealthCheckedCryptoRngV1::new(source).map_err(|error| match error {
            ProverRandomnessErrorV1::Unavailable => VegaMdlError::RandomnessUnavailable,
            ProverRandomnessErrorV1::Unhealthy => VegaMdlError::RandomnessHealthCheckFailed,
        })?;
        Ok(Self { source })
    }
}
impl<R: RngCore + CryptoRng> VegaRandomSourceV1 for CoreVegaRandomSource<'_, R> {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), VegaRandomSourceErrorV1> {
        self.source
            .try_fill_bytes(destination)
            .map_err(|_| VegaRandomSourceErrorV1::Unavailable)
    }
}
/// Preflight and prove the complete closed Figure 9 mDL relation.
///
/// The public statement is checked against the independently supplied consensus binding and trusted
/// block date before private parsing. The same typed statement and binding are then passed to the
/// circuit and Fiat--Shamir transcript; native preflight is never accepted as a substitute for the
/// proof relation.
///
/// # Errors
///
/// Fails closed on malformed consensus context, a stale or malformed credential, invalid ES256
/// authentication, random-source failure, an unsatisfied circuit, or proof-system failure.
pub fn prove_mdl_figure9_v1<R: RngCore + CryptoRng>(
    statement: &VegaExistingCredentialStatementV1,
    binding: &VegaMdlConsensusBindingV1<'_>,
    trusted_block_timestamp_ms: u64,
    witness: VegaMdlWitnessV1,
    config: VegaMdlProverConfigV1,
    random: &mut R,
) -> Result<Vec<u8>, VegaMdlError> {
    let validated = validate_mdl_witness(statement, binding, trusted_block_timestamp_ms, witness)?;
    let circuit_witness = validated.circuit_witness()?;
    let mut random_source = CoreVegaRandomSource::new(random)?;
    let proof = prove_vega_mdl_figure9_v1(
        &binding.proof_context(),
        validated.public_inputs().as_array(),
        &circuit_witness,
        config,
        &mut random_source,
    )
    .map_err(VegaMdlError::from)?;
    verify_vega_mdl_figure9_v1(
        &binding.proof_context(),
        validated.public_inputs().as_array(),
        &proof,
    )
    .map_err(|_| VegaMdlError::ProverSelfCheckFailed)?;
    Ok(proof)
}
/// Verify one canonical Figure 9 proof against consensus and trusted time.
///
/// Verification independently reconstructs the fourteen typed public inputs
/// and the device-authentication binding digest. It never accepts prover-side
/// preflight results or caller-supplied lookup data.
///
/// # Errors
///
/// Fails closed on a context mismatch, invalid trusted date, device-binding
/// mismatch, malformed proof encoding, or failed proof equations.
pub fn verify_mdl_figure9_v1(
    statement: &VegaExistingCredentialStatementV1,
    binding: &VegaMdlConsensusBindingV1<'_>,
    trusted_block_timestamp_ms: u64,
    proof: &[u8],
) -> Result<(), VegaMdlError> {
    binding.validate(statement)?;
    validate_trusted_presentation_date_v1(statement, trusted_block_timestamp_ms)?;
    if derive_device_authentication_digest_v1(statement, binding)?
        != statement.device_authentication_digest
    {
        return Err(VegaMdlError::DeviceAuthenticationDigestMismatch);
    }
    let public_inputs = VegaMdlPublicInputsV1::from_statement(statement)?;
    verify_vega_mdl_figure9_v1(&binding.proof_context(), public_inputs.as_array(), proof)
        .map_err(VegaMdlError::from)
}
fn validate_vega_transaction_context_v1(
    context: &VegaPrivacyActionTransactionContextV1,
) -> Result<(), VegaPrivacyActionBuildErrorV1> {
    if context.authority.try_signatory().is_none() {
        return Err(VegaPrivacyActionBuildErrorV1::UnsupportedAuthority);
    }
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(VegaPrivacyActionBuildErrorV1::CreationTimeOutOfRange);
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(VegaPrivacyActionBuildErrorV1::TimeToLiveOutOfRange);
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
        .map_err(|_| VegaPrivacyActionBuildErrorV1::InvalidTransactionContext)
}
fn validate_vega_public_input_v1(
    input: VegaPrivacyActionPublicInputV1,
) -> Result<(), VegaPrivacyActionBuildErrorV1> {
    input
        .issuer_record
        .validate()
        .map_err(|_| VegaPrivacyActionBuildErrorV1::InvalidIssuerRecord)?;
    if input.issuer_record.lifecycle != PrivacyVegaIssuerRecordLifecycleV1::Active {
        return Err(VegaPrivacyActionBuildErrorV1::InvalidIssuerRecord);
    }
    Ok(())
}
fn vega_statement_context_v1(
    context: &VegaPrivacyActionTransactionContextV1,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
    transaction_intent_digest: PrivacyTransactionIntentDigestV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id: context.network_id,
        action_index: VEGA_PRIVACY_ACTION_INDEX_V1,
        transaction_intent_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
fn vega_statement_v1(
    context: PrivacyStatementContextV1,
    input: VegaPrivacyActionPublicInputV1,
    device_authentication_digest: PrivacyVegaDeviceAuthenticationDigestV1,
) -> VegaExistingCredentialStatementV1 {
    VegaExistingCredentialStatementV1 {
        context,
        issuer_id: input.issuer_record.issuer_id,
        issuer_record_epoch: input.issuer_record.record_epoch,
        issuer_record_digest: input.issuer_record.record_digest,
        document_type: input.issuer_record.document_type,
        namespace: input.issuer_record.namespace,
        digest_algorithm: input.issuer_record.digest_algorithm,
        issuer_authentication_algorithm: input.issuer_record.issuer_authentication_algorithm,
        device_authentication_algorithm: input.issuer_record.device_authentication_algorithm,
        issuer_public_key: input.issuer_record.issuer_public_key,
        device_authentication_digest,
        presentation_date: input.presentation_date,
        minimum_age_years: input.minimum_age_years,
        reader_challenge: input.reader_challenge,
        session_transcript_digest: input.session_transcript_digest,
    }
}
fn vega_transaction_payload_v1(
    context: &VegaPrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, VegaPrivacyActionBuildErrorV1> {
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
        .map_err(|_| VegaPrivacyActionBuildErrorV1::InvalidTransactionContext)
}
fn derive_vega_transaction_intent_digest_v1(
    context: &VegaPrivacyActionTransactionContextV1,
    statement: VegaExistingCredentialStatementV1,
) -> Result<PrivacyTransactionIntentDigestV1, VegaPrivacyActionBuildErrorV1> {
    // The proof-empty projection exists only on this stack frame. It cannot be
    // returned, signed, or submitted through the sealed prepared-action API.
    let normalized_projection_envelope = PrivacyProofEnvelopeV1::bind_v1(
        PrivacyStatementV1::VegaExistingCredentialZkV1(statement),
        PrivacyProofV1::VegaExistingCredentialZkV1(PrivacyProofBytesV1::new(Vec::new())),
    )
    .map_err(|_| VegaPrivacyActionBuildErrorV1::StatementDigest)?;
    vega_transaction_payload_v1(context, normalized_projection_envelope)?
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| VegaPrivacyActionBuildErrorV1::TransactionIntent)
}
fn validate_vega_signing_authority_v1(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), VegaPrivacyActionBuildErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or(VegaPrivacyActionBuildErrorV1::UnsupportedAuthority)?;
    let derived = IrohaPublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(VegaPrivacyActionBuildErrorV1::AuthorityKeyMismatch);
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct VegaPrivacyActionIntegrityV1 {
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
}
impl VegaPreparedPrivacyActionV1 {
    const fn integrity(&self) -> VegaPrivacyActionIntegrityV1 {
        VegaPrivacyActionIntegrityV1 {
            transaction_intent_digest: self.transaction_intent_digest,
            statement_digest: self.statement_digest,
            proof_envelope_hash: self.proof_envelope_hash,
            statement_bytes: self.statement_bytes,
            proof_bytes: self.proof_bytes,
            encoded_proof_envelope_bytes: self.encoded_proof_envelope_bytes,
        }
    }
}
fn validate_vega_payload_integrity_v1(
    payload: &TransactionPayload,
    expected: VegaPrivacyActionIntegrityV1,
) -> Result<(), ()> {
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
    if envelope.protocol_id != PrivacyProtocolIdV1::VegaExistingCredentialZkV1
        || envelope.statement_digest.as_bytes() != &expected.statement_digest
    {
        return Err(());
    }
    let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) = &envelope.statement else {
        return Err(());
    };
    if statement.context.action_index != VEGA_PRIVACY_ACTION_INDEX_V1
        || statement.context.transaction_intent_digest.as_bytes()
            != &expected.transaction_intent_digest
    {
        return Err(());
    }
    let PrivacyProofV1::VegaExistingCredentialZkV1(proof) = &envelope.proof else {
        return Err(());
    };
    if u32::try_from(proof.as_bytes().len()).map_err(|_| ())? != expected.proof_bytes {
        return Err(());
    }
    let statement_encoding = norito::to_bytes(&envelope.statement).map_err(|_| ())?;
    if u32::try_from(statement_encoding.len()).map_err(|_| ())? != expected.statement_bytes {
        return Err(());
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
/// Prepare and prove one canonical direct Vega action using caller-provided
/// cryptographically secure proof randomness.
///
/// This pure proving half never receives the transaction signing key. The holder-device key is
/// witness material: it signs only the final derived `H_dev`, after the proof-independent
/// transaction intent has been computed. The final one-instruction payload is intrinsically
/// validated, sealed by exact metrics, and revalidated against the original intent before return.
///
/// # Errors
///
/// Returns a closed error for an invalid transaction context, issuer record,
/// document witness, device key, trusted timestamp, native proof, resource
/// limit, canonical encoding, or final binding drift.
pub fn prepare_vega_privacy_action_with_rng_v1<R>(
    context: VegaPrivacyActionTransactionContextV1,
    input: VegaPrivacyActionPublicInputV1,
    witness_material: VegaPrivacyActionWitnessMaterialV1,
    device_signing_key: &P256SigningKey,
    canonical_genesis_hash: [u8; 32],
    trusted_block_timestamp_ms: u64,
    rng: &mut R,
) -> Result<VegaPreparedPrivacyActionV1, VegaPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(VegaPrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(VegaPrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    validate_vega_transaction_context_v1(&context)?;
    validate_vega_public_input_v1(input)?;
    let profile = crate::privacy_profiles::compiled_privacy_profile_v1(
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
    )
    .map_err(|_| VegaPrivacyActionBuildErrorV1::CompiledProfileUnavailable)?;
    prepare_vega_privacy_action_with_profile_and_rng_v1(
        context,
        input,
        witness_material,
        device_signing_key,
        canonical_genesis_hash,
        trusted_block_timestamp_ms,
        profile,
        rng,
    )
}
fn prepare_vega_privacy_action_with_profile_and_rng_v1<R>(
    context: VegaPrivacyActionTransactionContextV1,
    input: VegaPrivacyActionPublicInputV1,
    witness_material: VegaPrivacyActionWitnessMaterialV1,
    device_signing_key: &P256SigningKey,
    canonical_genesis_hash: [u8; 32],
    trusted_block_timestamp_ms: u64,
    profile: crate::privacy_profiles::CompiledPrivacyProfileV1,
    rng: &mut R,
) -> Result<VegaPreparedPrivacyActionV1, VegaPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    let draft_statement = vega_statement_v1(
        vega_statement_context_v1(
            &context,
            profile,
            PrivacyTransactionIntentDigestV1::new([0; 32]),
        ),
        input,
        PrivacyVegaDeviceAuthenticationDigestV1::new([0; 32]),
    );
    let transaction_intent_digest =
        derive_vega_transaction_intent_digest_v1(&context, draft_statement.clone())?;
    let mut final_statement = draft_statement;
    final_statement.context.transaction_intent_digest = transaction_intent_digest;
    let device_authentication_digest = {
        let binding = VegaMdlConsensusBindingV1::from_context(
            &final_statement.context,
            canonical_genesis_hash,
        );
        derive_device_authentication_digest_v1(&final_statement, &binding)?
    };
    final_statement.device_authentication_digest = device_authentication_digest;
    let device_signature: Zeroizing<[u8; 64]> = Zeroizing::new({
        let signature: P256Signature = device_signing_key
            .sign_prehash(device_authentication_digest.as_bytes())
            .map_err(|_| VegaPrivacyActionBuildErrorV1::DeviceAuthenticationSigning)?;
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into()
    });
    let witness = witness_material
        .witness_with_device_signature(device_signature)
        .map_err(VegaPrivacyActionBuildErrorV1::from)?;
    let typed_statement = PrivacyStatementV1::VegaExistingCredentialZkV1(final_statement.clone());
    typed_statement
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| VegaPrivacyActionBuildErrorV1::StatementValidation)?;
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| VegaPrivacyActionBuildErrorV1::StatementDigest)?;
    let statement_bytes = u32::try_from(
        norito::to_bytes(&typed_statement)
            .map_err(|_| VegaPrivacyActionBuildErrorV1::StatementEncoding)?
            .len(),
    )
    .map_err(|_| VegaPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let binding =
        VegaMdlConsensusBindingV1::from_context(&final_statement.context, canonical_genesis_hash);
    let config = VegaMdlProverConfigV1::new(VEGA_PRIVACY_ACTION_PROVER_WORKERS_V1)
        .expect("fixed first-release Vega worker count is valid");
    let proof = prove_mdl_figure9_v1(
        &final_statement,
        &binding,
        trusted_block_timestamp_ms,
        witness,
        config,
        rng,
    )?;
    let proof_bytes = u32::try_from(proof.len())
        .map_err(|_| VegaPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let final_envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::VegaExistingCredentialZkV1(PrivacyProofBytesV1::new(proof)),
    )
    .map_err(|_| VegaPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(VegaPrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    final_envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| VegaPrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let envelope_encoding = norito::to_bytes(&final_envelope)
        .map_err(|_| VegaPrivacyActionBuildErrorV1::EnvelopeEncoding)?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| VegaPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let final_payload = vega_transaction_payload_v1(&context, final_envelope)?;
    let validated_intent = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| VegaPrivacyActionBuildErrorV1::FinalIntentBinding)?;
    if validated_intent != transaction_intent_digest {
        return Err(VegaPrivacyActionBuildErrorV1::FinalIntentBinding);
    }
    let prepared = VegaPreparedPrivacyActionV1 {
        payload: final_payload,
        transaction_intent_digest: *transaction_intent_digest.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
    };
    validate_vega_payload_integrity_v1(&prepared.payload, prepared.integrity())
        .map_err(|_| VegaPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    Ok(prepared)
}
/// Sign a payload returned by the canonical pure Vega prover.
///
/// The sealed statement, proof, envelope encoding, and intent are recomputed
/// before and after transaction signing, so proof bytes projected out of the
/// intent cannot be changed at the prepared boundary.
///
/// # Errors
///
/// Returns an error for prepared-payload drift, a multisig authority,
/// authority/key mismatch, signature-backend failure, or signed intent drift.
pub fn sign_prepared_vega_privacy_action_v1(
    prepared: VegaPreparedPrivacyActionV1,
    private_key: &PrivateKey,
) -> Result<SignedVegaPrivacyActionV1, VegaPrivacyActionBuildErrorV1> {
    validate_vega_signing_authority_v1(prepared.payload.authority(), private_key)?;
    let integrity = prepared.integrity();
    validate_vega_payload_integrity_v1(&prepared.payload, integrity)
        .map_err(|_| VegaPrivacyActionBuildErrorV1::PreparedPayloadDrift)?;
    let signed_transaction = TransactionBuilder::from_payload(prepared.payload)
        .map_err(|_| VegaPrivacyActionBuildErrorV1::InvalidTransactionContext)?
        .try_sign(private_key)
        .map_err(|error| match error {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                VegaPrivacyActionBuildErrorV1::UnsupportedAuthority
            }
            TransactionSignatureError::AuthorityKeyMismatch => {
                VegaPrivacyActionBuildErrorV1::AuthorityKeyMismatch
            }
            TransactionSignatureError::InvalidFeePaymentIntent(_) => {
                VegaPrivacyActionBuildErrorV1::InvalidTransactionContext
            }
            _ => VegaPrivacyActionBuildErrorV1::TransactionSigning,
        })?;
    validate_vega_payload_integrity_v1(signed_transaction.payload(), integrity)
        .map_err(|_| VegaPrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    let transaction_hash = *signed_transaction.hash().as_ref();
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed_transaction).len())
            .map_err(|_| VegaPrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    Ok(SignedVegaPrivacyActionV1 {
        signed_transaction,
        transaction_hash,
        adaptive_signed_transaction_bytes,
        transaction_intent_digest: integrity.transaction_intent_digest,
        statement_digest: integrity.statement_digest,
        proof_envelope_hash: integrity.proof_envelope_hash,
        statement_bytes: integrity.statement_bytes,
        proof_bytes: integrity.proof_bytes,
        encoded_proof_envelope_bytes: integrity.encoded_proof_envelope_bytes,
    })
}
/// Build, prove, bind, and sign one canonical direct Vega privacy action with
/// caller-provided cryptographically secure proof randomness.
///
/// The transaction authority is validated before device signing, witness
/// validation, randomness, or proof work.
///
/// # Errors
///
/// Returns a closed validation, proving, binding, or signing error.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_vega_privacy_action_with_rng_v1<R>(
    context: VegaPrivacyActionTransactionContextV1,
    input: VegaPrivacyActionPublicInputV1,
    witness_material: VegaPrivacyActionWitnessMaterialV1,
    device_signing_key: &P256SigningKey,
    canonical_genesis_hash: [u8; 32],
    trusted_block_timestamp_ms: u64,
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<SignedVegaPrivacyActionV1, VegaPrivacyActionBuildErrorV1>
where
    R: CryptoRng + RngCore,
{
    validate_vega_transaction_context_v1(&context)?;
    validate_vega_signing_authority_v1(&context.authority, private_key)?;
    let prepared = prepare_vega_privacy_action_with_rng_v1(
        context,
        input,
        witness_material,
        device_signing_key,
        canonical_genesis_hash,
        trusted_block_timestamp_ms,
        rng,
    )?;
    sign_prepared_vega_privacy_action_v1(prepared, private_key)
}
/// Build, prove, bind, and sign one canonical direct Vega privacy action using
/// operating-system proof randomness.
///
/// # Errors
///
/// Returns the same closed failures as [`build_signed_vega_privacy_action_with_rng_v1`].
#[allow(clippy::too_many_arguments)]
pub fn build_signed_vega_privacy_action_v1(
    context: VegaPrivacyActionTransactionContextV1,
    input: VegaPrivacyActionPublicInputV1,
    witness_material: VegaPrivacyActionWitnessMaterialV1,
    device_signing_key: &P256SigningKey,
    canonical_genesis_hash: [u8; 32],
    trusted_block_timestamp_ms: u64,
    private_key: &PrivateKey,
) -> Result<SignedVegaPrivacyActionV1, VegaPrivacyActionBuildErrorV1> {
    build_signed_vega_privacy_action_with_rng_v1(
        context,
        input,
        witness_material,
        device_signing_key,
        canonical_genesis_hash,
        trusted_block_timestamp_ms,
        private_key,
        &mut OsRng,
    )
}
/// Construct the exact length-delimited device-authentication consensus frame.
///
/// # Errors
///
/// Returns [`VegaMdlError`] when a duplicated binding mismatches the statement
/// or a mandatory value is invalid.
pub fn device_authentication_frame_v1(
    statement: &VegaExistingCredentialStatementV1,
    binding: &VegaMdlConsensusBindingV1<'_>,
) -> Result<Vec<u8>, VegaMdlError> {
    binding.validate(statement)?;
    validate_public_statement(statement)?;
    let mut frame = Vec::with_capacity(768);
    append_frame_field(
        &mut frame,
        b"domain",
        VEGA_MDL_DEVICE_AUTHENTICATION_DOMAIN_V1,
    )?;
    append_frame_field(
        &mut frame,
        b"frame_version",
        &[VEGA_MDL_DEVICE_AUTHENTICATION_FRAME_VERSION_V1],
    )?;
    append_frame_field(&mut frame, b"upstream_commit", VEGA_PINNED_SOURCE_COMMIT_V1)?;
    append_frame_field(&mut frame, b"network_id", binding.network_id)?;
    append_frame_field(&mut frame, b"genesis_hash", &binding.genesis_hash)?;
    append_frame_field(
        &mut frame,
        b"action_index",
        &binding.action_index.to_be_bytes(),
    )?;
    append_frame_field(
        &mut frame,
        b"transaction_intent_digest",
        statement.context.transaction_intent_digest.as_bytes(),
    )?;
    append_frame_field(&mut frame, b"parameter_id", &binding.parameter_id)?;
    append_frame_field(&mut frame, b"parameter_digest", &binding.parameter_digest)?;
    append_frame_field(&mut frame, b"verifier_digest", &binding.verifier_digest)?;
    append_frame_field(
        &mut frame,
        b"statement_schema_digest",
        &binding.statement_schema_digest,
    )?;
    append_frame_field(
        &mut frame,
        b"engine_manifest_digest",
        &binding.engine_manifest_digest,
    )?;
    append_frame_field(&mut frame, b"issuer_id", statement.issuer_id.as_bytes())?;
    append_frame_field(
        &mut frame,
        b"issuer_record_epoch",
        &statement.issuer_record_epoch.to_be_bytes(),
    )?;
    append_frame_field(
        &mut frame,
        b"issuer_record_digest",
        statement.issuer_record_digest.as_bytes(),
    )?;
    append_frame_field(&mut frame, b"document_type", VEGA_MDL_DOCUMENT_TYPE_V1)?;
    append_frame_field(&mut frame, b"namespace", VEGA_MDL_NAMESPACE_V1)?;
    append_frame_field(&mut frame, b"digest_algorithm", b"SHA-256")?;
    append_frame_field(&mut frame, b"issuer_authentication", b"COSE_Sign1/ES256")?;
    append_frame_field(&mut frame, b"device_authentication", b"COSE_Sign1/ES256")?;
    append_frame_field(
        &mut frame,
        b"issuer_public_key",
        statement.issuer_public_key.as_bytes(),
    )?;
    append_frame_field(
        &mut frame,
        b"presentation_year",
        &statement.presentation_date.year.to_be_bytes(),
    )?;
    append_frame_field(
        &mut frame,
        b"presentation_month",
        &[statement.presentation_date.month],
    )?;
    append_frame_field(
        &mut frame,
        b"presentation_day",
        &[statement.presentation_date.day],
    )?;
    append_frame_field(
        &mut frame,
        b"minimum_age_years",
        &[statement.minimum_age_years],
    )?;
    append_frame_field(
        &mut frame,
        b"reader_challenge",
        statement.reader_challenge.as_bytes(),
    )?;
    append_frame_field(
        &mut frame,
        b"session_transcript_digest",
        statement.session_transcript_digest.as_bytes(),
    )?;
    Ok(frame)
}
/// Derive `H_dev` from the exact Iroha consensus frame.
///
/// # Errors
///
/// Returns [`VegaMdlError`] when the statement or duplicated binding is malformed.
pub fn derive_device_authentication_digest_v1(
    statement: &VegaExistingCredentialStatementV1,
    binding: &VegaMdlConsensusBindingV1<'_>,
) -> Result<PrivacyVegaDeviceAuthenticationDigestV1, VegaMdlError> {
    let frame = device_authentication_frame_v1(statement, binding)?;
    Ok(PrivacyVegaDeviceAuthenticationDigestV1::new(
        Sha256::digest(frame).into(),
    ))
}
/// Require the statement's public date to equal the trusted block timestamp's UTC date.
///
/// # Errors
///
/// Returns [`VegaMdlError`] when the timestamp is outside the supported range or the dates differ.
pub fn validate_trusted_presentation_date_v1(
    statement: &VegaExistingCredentialStatementV1,
    trusted_block_timestamp_ms: u64,
) -> Result<(), VegaMdlError> {
    validate_public_statement(statement)?;
    let unix_seconds = i64::try_from(trusted_block_timestamp_ms / 1_000)
        .map_err(|_| VegaMdlError::TrustedTimestampOutOfRange)?;
    let date = OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map_err(|_| VegaMdlError::TrustedTimestampOutOfRange)?
        .date();
    let trusted = PrivacyVegaMdlDateV1 {
        year: u16::try_from(date.year()).map_err(|_| VegaMdlError::TrustedTimestampOutOfRange)?,
        month: u8::from(date.month()),
        day: date.day(),
    };
    if trusted != statement.presentation_date {
        return Err(VegaMdlError::TrustedPresentationDateMismatch);
    }
    Ok(())
}
pub(super) fn validate_date(
    date: PrivacyVegaMdlDateV1,
    field: &'static str,
) -> Result<Date, VegaMdlError> {
    let month = Month::try_from(date.month).map_err(|_| VegaMdlError::InvalidDate { field })?;
    Date::from_calendar_date(i32::from(date.year), month, date.day)
        .map_err(|_| VegaMdlError::InvalidDate { field })
}
fn validate_public_statement(
    statement: &VegaExistingCredentialStatementV1,
) -> Result<(), VegaMdlError> {
    if statement.issuer_record_epoch == 0 {
        return Err(VegaMdlError::ZeroIssuerRecordEpoch);
    }
    let _ = validate_date(statement.presentation_date, "presentation_date")?;
    if !(VEGA_MDL_MIN_PRESENTATION_YEAR_V1..=VEGA_MDL_MAX_PRESENTATION_YEAR_V1)
        .contains(&statement.presentation_date.year)
    {
        return Err(VegaMdlError::InvalidDate {
            field: "presentation_date",
        });
    }
    if !(VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1..=VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1)
        .contains(&statement.minimum_age_years)
    {
        return Err(VegaMdlError::InvalidAgeThreshold {
            actual: statement.minimum_age_years,
            min: VEGA_MDL_MIN_AGE_THRESHOLD_YEARS_V1,
            max: VEGA_MDL_MAX_AGE_THRESHOLD_YEARS_V1,
        });
    }
    for (field, digest) in [
        (
            "transaction_intent_digest",
            statement.context.transaction_intent_digest.as_bytes(),
        ),
        ("issuer_id", statement.issuer_id.as_bytes()),
        (
            "issuer_record_digest",
            statement.issuer_record_digest.as_bytes(),
        ),
        ("reader_challenge", statement.reader_challenge.as_bytes()),
        (
            "session_transcript_digest",
            statement.session_transcript_digest.as_bytes(),
        ),
    ] {
        if digest == &[0; 32] {
            return Err(VegaMdlError::ZeroConsensusDigest { field });
        }
    }
    let _ = p256_affine_coordinates(statement.issuer_public_key)?;
    Ok(())
}
fn p256_affine_coordinates(
    encoded: PrivacyP256PointV1,
) -> Result<([u8; 32], [u8; 32]), VegaMdlError> {
    let public_key = P256PublicKey::from_sec1_bytes(encoded.as_bytes()).map_err(|_| {
        VegaMdlError::InvalidP256PublicKey {
            field: "issuer_public_key",
        }
    })?;
    let uncompressed: EncodedPoint = public_key.to_encoded_point(false);
    let x = uncompressed.x().ok_or(VegaMdlError::InvalidP256PublicKey {
        field: "issuer_public_key",
    })?;
    let y = uncompressed.y().ok_or(VegaMdlError::InvalidP256PublicKey {
        field: "issuer_public_key",
    })?;
    let mut x_bytes = [0_u8; 32];
    let mut y_bytes = [0_u8; 32];
    x_bytes.copy_from_slice(x);
    y_bytes.copy_from_slice(y);
    Ok((x_bytes, y_bytes))
}
fn append_frame_field(frame: &mut Vec<u8>, label: &[u8], value: &[u8]) -> Result<(), VegaMdlError> {
    let label_len = u16::try_from(label.len()).map_err(|_| VegaMdlError::FrameFieldTooLarge)?;
    let value_len = u32::try_from(value.len()).map_err(|_| VegaMdlError::FrameFieldTooLarge)?;
    frame.extend_from_slice(&label_len.to_be_bytes());
    frame.extend_from_slice(label);
    frame.extend_from_slice(&value_len.to_be_bytes());
    frame.extend_from_slice(value);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::{MultisigMember, MultisigPolicy},
        privacy::{
            PrivacyCredentialDocumentTypeV1, PrivacyIssuerIdV1, PrivacyVegaIssuerRecordDigestV1,
            PrivacyVegaMdlDigestAlgorithmV1, PrivacyVegaMdlNamespaceV1,
            PrivacyVegaMdlSignatureAlgorithmV1,
        },
    };
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    struct PanicRng;
    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("invalid Vega action boundary reached proof randomness")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("invalid Vega action boundary reached proof randomness")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("invalid Vega action boundary reached proof randomness")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            panic!("invalid Vega action boundary reached proof randomness")
        }
    }
    impl CryptoRng for PanicRng {}
    #[derive(Clone, Copy)]
    enum VegaEntropyModeV1 {
        Healthy,
        Constant(u8),
        Periodic(usize),
        PartialError { request: usize },
        Panic { request: usize },
    }
    struct VegaEntropySourceV1 {
        mode: VegaEntropyModeV1,
        cursor: usize,
        requests: Vec<usize>,
    }
    impl VegaEntropySourceV1 {
        fn new(mode: VegaEntropyModeV1) -> Self {
            Self {
                mode,
                cursor: 0,
                requests: Vec::new(),
            }
        }
        fn healthy_byte(index: usize) -> u8 {
            u8::try_from(index % 251).expect("stream byte is reduced below 251")
        }
        fn stream_byte(&self, index: usize) -> u8 {
            match self.mode {
                VegaEntropyModeV1::Constant(byte) => byte,
                VegaEntropyModeV1::Periodic(period) => {
                    u8::try_from(index % period).expect("test periods fit u8")
                }
                VegaEntropyModeV1::Healthy
                | VegaEntropyModeV1::PartialError { .. }
                | VegaEntropyModeV1::Panic { .. } => Self::healthy_byte(index),
            }
        }
    }
    impl RngCore for VegaEntropySourceV1 {
        fn next_u32(&mut self) -> u32 {
            panic!("Vega must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("Vega must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("Vega must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.requests.push(destination.len());
            let request = self.requests.len();
            let partial_error = matches!(
                self.mode,
                VegaEntropyModeV1::PartialError {
                    request: failing_request
                } if failing_request == request
            );
            let panicking = matches!(
                self.mode,
                VegaEntropyModeV1::Panic {
                    request: panicking_request
                } if panicking_request == request
            );
            let written = if partial_error || panicking {
                destination.len().min(17)
            } else {
                destination.len()
            };
            for offset in 0..written {
                destination[offset] = self.stream_byte(self.cursor);
                self.cursor += 1;
            }
            if panicking {
                panic!("injected Vega entropy panic after a partial write")
            }
            if partial_error {
                return Err(RngError::new(
                    "injected Vega entropy failure after a partial write",
                ));
            }
            Ok(())
        }
    }
    impl CryptoRng for VegaEntropySourceV1 {}
    fn transaction_key(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixed Vega transaction key")
    }
    fn action_context() -> VegaPrivacyActionTransactionContextV1 {
        let key_pair = transaction_key(0x41);
        VegaPrivacyActionTransactionContextV1 {
            network_id: network_id_from_genesis_hash_bytes([0xA7; 32]),
            authority: AccountId::new(key_pair.public_key().clone()),
            creation_time: Duration::from_millis(1_785_023_999_999),
            time_to_live: Some(Duration::from_secs(60)),
            nonce: NonZeroU32::new(26),
            fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
            metadata: Metadata::default(),
        }
    }
    fn action_public_input(
        lifecycle: PrivacyVegaIssuerRecordLifecycleV1,
    ) -> VegaPrivacyActionPublicInputV1 {
        let issuer_signing_key =
            P256SigningKey::from_bytes((&[1_u8; 32]).into()).expect("fixed issuer key");
        let encoded = issuer_signing_key.verifying_key().to_encoded_point(true);
        let issuer_public_key = PrivacyP256PointV1::new(
            encoded
                .as_bytes()
                .try_into()
                .expect("compressed P-256 point has 33 bytes"),
        );
        let issuer_record = PrivacyVegaIssuerRecordV1::new(
            PrivacyIssuerIdV1::new([0x40; 32]),
            1,
            issuer_public_key,
            PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
            PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
            PrivacyVegaMdlDigestAlgorithmV1::Sha256,
            PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
            None,
            lifecycle,
        )
        .expect("fixed issuer record");
        VegaPrivacyActionPublicInputV1 {
            issuer_record,
            presentation_date: PrivacyVegaMdlDateV1 {
                year: 2026,
                month: 7,
                day: 26,
            },
            minimum_age_years: 18,
            reader_challenge: PrivacyChallengeV1::new([0x31; 32]),
            session_transcript_digest: PrivacySessionTranscriptDigestV1::new([0x32; 32]),
        }
    }
    fn witness_material() -> VegaPrivacyActionWitnessMaterialV1 {
        VegaPrivacyActionWitnessMaterialV1::new(
            vec![0; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1],
            vec![0; VEGA_MDL_MSO_PAYLOAD_BYTES_V1],
            vec![0; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1],
            &[0; 64],
        )
        .expect("exact-shape boundary witness material")
    }
    fn device_signing_key() -> P256SigningKey {
        P256SigningKey::from_bytes((&[2_u8; 32]).into()).expect("fixed device key")
    }
    #[test]
    fn vega_random_source_rejects_unavailable_constant_and_periodic_prefixes() {
        let mut unavailable =
            VegaEntropySourceV1::new(VegaEntropyModeV1::PartialError { request: 1 });
        assert!(matches!(
            CoreVegaRandomSource::new(&mut unavailable),
            Err(VegaMdlError::RandomnessUnavailable)
        ));
        assert_eq!(unavailable.requests, [64]);
        let mut constant = VegaEntropySourceV1::new(VegaEntropyModeV1::Constant(0xA5));
        assert!(matches!(
            CoreVegaRandomSource::new(&mut constant),
            Err(VegaMdlError::RandomnessHealthCheckFailed)
        ));
        assert_eq!(constant.requests, [64]);
        for period in [1, 2, 4, 8, 16, 32] {
            let mut periodic = VegaEntropySourceV1::new(VegaEntropyModeV1::Periodic(period));
            assert!(matches!(
                CoreVegaRandomSource::new(&mut periodic),
                Err(VegaMdlError::RandomnessHealthCheckFailed)
            ));
            assert_eq!(periodic.requests, [64]);
        }
    }
    #[test]
    fn vega_random_source_uses_only_fixed_source_blocks_and_preserves_stream_order() {
        let mut source = VegaEntropySourceV1::new(VegaEntropyModeV1::Healthy);
        let mut actual = [0_u8; 129];
        {
            let mut random_source =
                CoreVegaRandomSource::new(&mut source).expect("healthy Vega entropy");
            random_source
                .fill_bytes(&mut actual[..1])
                .expect("one byte from initial reservoir");
            random_source
                .fill_bytes(&mut actual[1..64])
                .expect("remaining initial reservoir");
            random_source
                .fill_bytes(&mut actual[64..])
                .expect("two canonical refills");
        }
        let expected = core::array::from_fn(VegaEntropySourceV1::healthy_byte);
        assert_eq!(actual, expected);
        assert_eq!(source.requests, [64, 64, 64]);
    }
    #[test]
    fn vega_random_source_partial_error_zeroizes_and_prevents_reentry() {
        let mut source = VegaEntropySourceV1::new(VegaEntropyModeV1::PartialError { request: 2 });
        let mut first = [0xA5; 65];
        let mut retry = [0x5A; 65];
        {
            let mut random_source =
                CoreVegaRandomSource::new(&mut source).expect("healthy initial block");
            assert!(matches!(
                random_source.fill_bytes(&mut first),
                Err(VegaRandomSourceErrorV1::Unavailable)
            ));
            assert_eq!(first, [0; 65]);
            assert!(matches!(
                random_source.fill_bytes(&mut retry),
                Err(VegaRandomSourceErrorV1::Unavailable)
            ));
            assert_eq!(retry, [0; 65]);
        }
        assert_eq!(source.requests, [64, 64]);
    }
    #[test]
    fn vega_random_source_unwind_zeroizes_and_permanently_poisons_session() {
        let mut source = VegaEntropySourceV1::new(VegaEntropyModeV1::Panic { request: 2 });
        let mut first = [0xA5; 65];
        let mut retry = [0x5A; 65];
        {
            let mut random_source =
                CoreVegaRandomSource::new(&mut source).expect("healthy initial block");
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    random_source.fill_bytes(&mut first).ok();
                }))
                .is_err()
            );
            assert_eq!(first, [0; 65]);
            assert!(matches!(
                random_source.fill_bytes(&mut retry),
                Err(VegaRandomSourceErrorV1::Unavailable)
            ));
            assert_eq!(retry, [0; 65]);
        }
        assert_eq!(source.requests, [64, 64]);
    }
    #[test]
    fn action_witness_material_rejects_every_noncanonical_length() {
        let short_issuer_structure = VegaPrivacyActionWitnessMaterialV1::new(
            vec![0; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1 - 1],
            vec![0; VEGA_MDL_MSO_PAYLOAD_BYTES_V1],
            vec![0; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1],
            &[0; 64],
        );
        assert!(matches!(
            short_issuer_structure,
            Err(VegaMdlError::InvalidInputLength {
                field: "issuer_authentication_sig_structure",
                ..
            })
        ));
        let long_mso = VegaPrivacyActionWitnessMaterialV1::new(
            vec![0; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1],
            vec![0; VEGA_MDL_MSO_PAYLOAD_BYTES_V1 + 1],
            vec![0; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1],
            &[0; 64],
        );
        assert!(matches!(
            long_mso,
            Err(VegaMdlError::InvalidInputLength {
                field: "mobile_security_object_payload",
                ..
            })
        ));
        let short_birth_item = VegaPrivacyActionWitnessMaterialV1::new(
            vec![0; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1],
            vec![0; VEGA_MDL_MSO_PAYLOAD_BYTES_V1],
            vec![0; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1 - 1],
            &[0; 64],
        );
        assert!(matches!(
            short_birth_item,
            Err(VegaMdlError::InvalidInputLength {
                field: "birth_date_issuer_signed_item",
                ..
            })
        ));
        let short_signature = VegaPrivacyActionWitnessMaterialV1::new(
            vec![0; VEGA_MDL_ISSUER_AUTHENTICATION_SIG_STRUCTURE_BYTES_V1],
            vec![0; VEGA_MDL_MSO_PAYLOAD_BYTES_V1],
            vec![0; VEGA_MDL_BIRTH_DATE_ISSUER_SIGNED_ITEM_BYTES_V1],
            &[0; 63],
        );
        assert!(matches!(
            short_signature,
            Err(VegaMdlError::InvalidInputLength {
                field: "issuer_signature",
                ..
            })
        ));
        let debug = format!("{:?}", witness_material());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("issuer_signature:"));
    }
    #[test]
    fn action_builder_rejects_public_boundaries_before_proof_randomness() {
        let zero_genesis = prepare_vega_privacy_action_with_rng_v1(
            action_context(),
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active),
            witness_material(),
            &device_signing_key(),
            [0; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            zero_genesis,
            Err(VegaPrivacyActionBuildErrorV1::ZeroGenesisHash)
        ));
        let mut oversized_creation_time = action_context();
        oversized_creation_time.creation_time = Duration::from_secs(u64::MAX);
        let oversized_creation_time = prepare_vega_privacy_action_with_rng_v1(
            oversized_creation_time,
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active),
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            oversized_creation_time,
            Err(VegaPrivacyActionBuildErrorV1::CreationTimeOutOfRange)
        ));
        let mut oversized_ttl = action_context();
        oversized_ttl.time_to_live = Some(Duration::from_secs(u64::MAX));
        let oversized_ttl = prepare_vega_privacy_action_with_rng_v1(
            oversized_ttl,
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active),
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            oversized_ttl,
            Err(VegaPrivacyActionBuildErrorV1::TimeToLiveOutOfRange)
        ));
        let multisig_key = transaction_key(0x41);
        let multisig_member = MultisigMember::new(multisig_key.public_key().clone(), 1)
            .expect("fixed multisig member");
        let mut multisig_context = action_context();
        multisig_context.authority = AccountId::new_multisig(
            MultisigPolicy::new(1, vec![multisig_member]).expect("fixed multisig policy"),
        );
        let multisig = prepare_vega_privacy_action_with_rng_v1(
            multisig_context,
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active),
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            multisig,
            Err(VegaPrivacyActionBuildErrorV1::UnsupportedAuthority)
        ));
        let revoked_issuer = prepare_vega_privacy_action_with_rng_v1(
            action_context(),
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Revoked),
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            revoked_issuer,
            Err(VegaPrivacyActionBuildErrorV1::InvalidIssuerRecord)
        ));
        let mut tampered_issuer_input =
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active);
        let mut tampered_record_digest =
            *tampered_issuer_input.issuer_record.record_digest.as_bytes();
        tampered_record_digest[0] ^= 1;
        tampered_issuer_input.issuer_record.record_digest =
            PrivacyVegaIssuerRecordDigestV1::new(tampered_record_digest);
        let tampered_issuer = prepare_vega_privacy_action_with_rng_v1(
            action_context(),
            tampered_issuer_input,
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            &mut PanicRng,
        );
        assert!(matches!(
            tampered_issuer,
            Err(VegaPrivacyActionBuildErrorV1::InvalidIssuerRecord)
        ));
        let foreign_key = transaction_key(0x42);
        let wrong_transaction_key = build_signed_vega_privacy_action_with_rng_v1(
            action_context(),
            action_public_input(PrivacyVegaIssuerRecordLifecycleV1::Active),
            witness_material(),
            &device_signing_key(),
            [0xA7; 32],
            1_785_024_000_000,
            foreign_key.private_key(),
            &mut PanicRng,
        );
        assert!(matches!(
            wrong_transaction_key,
            Err(VegaPrivacyActionBuildErrorV1::AuthorityKeyMismatch)
        ));
    }
}
