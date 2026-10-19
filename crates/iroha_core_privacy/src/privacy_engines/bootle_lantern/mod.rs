//! Native fixed-profile Bootle/Lantern anonymous-credential engine.
//!
//! This implementation follows the fixed BLNS presentation relation over
//! `Z_12289[X]/(X^64 + 1)` and its Lantern/LNP22 module-linear-and-norm proof.
//! Consensus admission supplies the exact committed issuer-policy revision,
//! recomputes the transaction-intent binding, and binds the chain genesis
//! hash before this verifier is invoked.
pub mod bounds;
pub mod codec;
pub mod compression;
mod credential_sampling;
mod falcon512;
mod holder_aes256;
#[cfg(test)]
pub mod holder_store;
pub mod issuance_store;
pub mod issuer;
pub mod params;
pub mod proof;
mod randomness;
pub mod relation;
pub mod ring;
pub mod sampling;
pub mod scope;
mod toolbox;
pub mod transcript;
pub(crate) use credential_sampling::{
    BOOTLE_CREDENTIAL_RANDOMNESS_PROFILE_DESCRIPTOR_V1,
    CREDENTIAL_RANDOMNESS_NORM_SQUARED_BOUND_V1, CREDENTIAL_RANDOMNESS_POLYNOMIALS_V1,
    MAX_CREDENTIAL_RANDOMNESS_COEFFICIENT_PROPOSALS_V1,
    MAX_CREDENTIAL_RANDOMNESS_VECTOR_ATTEMPTS_V1,
};
pub(crate) use falcon512::{
    BOOTLE_LANTERN_FALCON512_DEFAULT_KEYGEN_CANDIDATES_V1,
    BOOTLE_LANTERN_FALCON512_IMPLEMENTATION_PROVENANCE_V1,
    BOOTLE_LANTERN_FALCON512_KEYGEN_PARITY_ATTEMPTS_V1,
    BOOTLE_LANTERN_FALCON512_MAPPING_DESCRIPTOR_V1,
    BOOTLE_LANTERN_FALCON512_PREIMAGE_PROPOSALS_PER_COEFFICIENT_V1,
    BOOTLE_LANTERN_FALCON512_PREIMAGE_TOTAL_PROPOSALS_V1,
    BOOTLE_LANTERN_FALCON512_PROFILE_DESCRIPTOR_V1,
};
use iroha_data_model::privacy::{
    BootleLanternIssuerPolicyV1, IrohaBootleLanternAnoncredStatementV1, PrivacyStatementV1,
};
pub(crate) use issuance_store::BOOTLE_LANTERN_ISSUANCE_STORE_PROFILE_DESCRIPTOR_V1;
pub(crate) use issuer::BOOTLE_LANTERN_ISSUANCE_WIRE_DESCRIPTOR_V1;
use rand_core_06::{CryptoRng, RngCore};
pub(crate) use randomness::BOOTLE_LANTERN_ISSUANCE_RANDOMNESS_DESCRIPTOR_V1;
pub(crate) use scope::BOOTLE_LANTERN_CREDENTIAL_SCOPE_DIGEST_DOMAIN_V1;
use thiserror::Error;
pub(crate) use toolbox::application_relation_digest_v1;
/// The complete first-release fixed-profile prover, verifier, strict codec,
/// governed binding pipeline, masked coefficient-field compiler, and exact
/// integer-ring challenge rejection path are available.
pub const BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1: bool = true;
/// Failure while constructing or verifying one fully consensus-bound presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BoundPresentationErrorV1 {
    /// The complete native proof relation is not available.
    #[error("Bootle/Lantern complete native engine is unavailable")]
    EngineUnavailable,
    /// Canonical encoding of the complete typed statement failed.
    #[error("Bootle/Lantern canonical statement digest failed")]
    StatementDigest,
    /// Trusted policy and typed public statement do not compile together.
    #[error("Bootle/Lantern public relation compilation failed: {0}")]
    Relation(#[from] relation::RelationErrorV1),
    /// Transparent parameters or complete public challenge binding are invalid.
    #[error("Bootle/Lantern presentation transcript construction failed: {0}")]
    Transcript(#[from] transcript::TranscriptErrorV1),
    /// Native proof construction, mandatory self-check, or verification equation failed.
    #[error("Bootle/Lantern native presentation proof failed: {0}")]
    Proof(#[from] proof::PresentationProofErrorV1),
}
/// Failure while strictly decoding and verifying one fully bound presentation.
///
/// The codec variant is kept distinct so consensus callers can preserve their
/// stable wire-versus-cryptography failure categories without duplicating the
/// production verification pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BoundPresentationEncodedErrorV1 {
    /// Proof bytes were not the unique canonical fixed-profile wire value.
    #[error("Bootle/Lantern presentation proof decoding failed: {0}")]
    Codec(#[from] codec::ProofCodecErrorV1),
    /// The decoded proof failed the complete governed presentation verifier.
    #[error(transparent)]
    Presentation(#[from] BoundPresentationErrorV1),
}
fn compile_bound_presentation_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
) -> Result<
    (
        relation::BootleLanternApplicationRelationV1,
        transcript::PresentationTranscriptV1,
    ),
    BoundPresentationErrorV1,
> {
    let matrix_seed = transcript::matrix_seed_v1(*statement.context.parameter_digest.as_bytes())?;
    let relation = relation::compile_application_relation_v1(
        statement,
        policy,
        matrix_seed,
        canonical_genesis_hash,
    )?;
    let statement_digest = PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone())
        .digest()
        .map_err(|_| BoundPresentationErrorV1::StatementDigest)?;
    let transcript = transcript::PresentationTranscriptV1::new(
        transcript::PresentationChallengeBindingV1 {
            parameter_digest: *statement.context.parameter_digest.as_bytes(),
            genesis_hash: canonical_genesis_hash,
            statement_digest: *statement_digest.as_bytes(),
            issuer_policy_record_digest: *statement.issuer_policy_record_digest.as_bytes(),
            transaction_intent_digest: *statement.context.transaction_intent_digest.as_bytes(),
        },
        matrix_seed,
        application_relation_digest_v1(&relation),
    )?;
    Ok((relation, transcript))
}
fn prove_bound_presentation_enabled_v1<R: CryptoRng + RngCore>(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    witness: &relation::BootleLanternPresentationWitnessV1,
    rng: &mut R,
) -> Result<codec::BootleLanternPresentationProofV1, BoundPresentationErrorV1> {
    let (relation, transcript) =
        compile_bound_presentation_v1(statement, policy, canonical_genesis_hash)?;
    proof::prove_presentation_v1(&relation, witness, &transcript, rng)
        .map_err(BoundPresentationErrorV1::from)
}
fn verify_bound_presentation_enabled_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    proof: &codec::BootleLanternPresentationProofV1,
) -> Result<(), BoundPresentationErrorV1> {
    let (relation, transcript) =
        compile_bound_presentation_v1(statement, policy, canonical_genesis_hash)?;
    proof::verify_presentation_v1(&relation, &transcript, proof)
        .map_err(BoundPresentationErrorV1::from)
}
fn verify_bound_presentation_encoded_enabled_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    proof_bytes: &[u8],
    max_bytes: u32,
) -> Result<(), BoundPresentationEncodedErrorV1> {
    let proof = codec::BootleLanternPresentationProofV1::decode_exact(proof_bytes, max_bytes)?;
    verify_bound_presentation_enabled_v1(statement, policy, canonical_genesis_hash, &proof)?;
    Ok(())
}
/// Prove one canonical typed Bootle/Lantern presentation.
///
/// This is the producer-side counterpart of the consensus verifier. It compiles the exact governed
/// issuer-policy record, derives the canonical protocol-tagged statement digest, binds the chain
/// genesis hash and transaction intent, and releases proof bytes only after the native prover's
/// independent self-verification succeeds.
///
/// # Errors
///
/// Rejects any invalid or substituted policy record, statement-to-policy
/// mismatch, zero or inconsistent transcript field, invalid witness, random
/// source failure, proof work-budget exhaustion, or failed prover self-check.
///
/// # Timing boundary
///
/// This producer API inherits the native prover's bounded, variable-work rejection samplers. Invoke
/// it only across a local authenticated boundary with process isolation; proof completion timing is
/// not safe to expose to an untrusted remote observer or hostile co-tenant.
pub fn prove_bound_presentation_v1<R: CryptoRng + RngCore>(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    witness: &relation::BootleLanternPresentationWitnessV1,
    rng: &mut R,
) -> Result<codec::BootleLanternPresentationProofV1, BoundPresentationErrorV1> {
    if !BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1 {
        return Err(BoundPresentationErrorV1::EngineUnavailable);
    }
    prove_bound_presentation_enabled_v1(statement, policy, canonical_genesis_hash, witness, rng)
}
#[cfg(test)]
/// Verify one canonical typed Bootle/Lantern presentation through the same governed policy,
/// statement digest, genesis binding, and compiled relation used by the producer.
///
/// # Errors
///
/// Rejects a substituted or malformed policy, any statement/policy mismatch,
/// invalid complete challenge binding, or any failed native proof equation.
pub fn verify_bound_presentation_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    proof: &codec::BootleLanternPresentationProofV1,
) -> Result<(), BoundPresentationErrorV1> {
    if !BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1 {
        return Err(BoundPresentationErrorV1::EngineUnavailable);
    }
    verify_bound_presentation_enabled_v1(statement, policy, canonical_genesis_hash, proof)
}
/// Strictly decode and verify one canonical typed Bootle/Lantern presentation.
///
/// This is the sole encoded production verifier. It composes the fixed-width, exact canonical
/// decoder with [`verify_bound_presentation_v1`], so callers cannot accidentally stop after
/// structural wire validation or reconstruct a weaker transcript.
///
/// # Errors
///
/// Rejects the configured byte ceiling, every malformed or non-canonical wire
/// value, a substituted governed policy or statement, an invalid complete
/// challenge binding, and every failed native proof equation.
pub fn verify_bound_presentation_encoded_v1(
    statement: &IrohaBootleLanternAnoncredStatementV1,
    policy: &BootleLanternIssuerPolicyV1,
    canonical_genesis_hash: [u8; 32],
    proof_bytes: &[u8],
    max_bytes: u32,
) -> Result<(), BoundPresentationEncodedErrorV1> {
    if !BOOTLE_LANTERN_FULL_ENGINE_AVAILABLE_V1 {
        return Err(BoundPresentationErrorV1::EngineUnavailable.into());
    }
    verify_bound_presentation_encoded_enabled_v1(
        statement,
        policy,
        canonical_genesis_hash,
        proof_bytes,
        max_bytes,
    )
}
