//! Production proof and wallet facades for first-release PQ-MASP.
use super::{
    relation::{
        PqMaspNotePlaintextV1, PqMaspRelationErrorV1, PqMaspWitnessV1,
        derive_pq_masp_note_commitment_v1, validate_pq_masp_relation_v1, validate_statement_v1,
    },
    stark::{prove_pq_masp_stark_v1_with_rng, verify_pq_masp_stark_v1},
    wire::{
        PqMaspWireErrorV1, authorize_pq_masp_stark_proof_v1, derive_pq_masp_recipient_id_v1,
        encrypt_pq_masp_note_v1 as encrypt_pq_masp_note_from_seed_v1,
        validate_pq_masp_authorization_secret_key_v1, verify_pq_masp_authorization_v1,
    },
};
use crate::privacy_engines::{
    proof_managed_note_stark::ProofManagedNoteStarkErrorV1,
    prover_randomness::{
        HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1,
        derive_healthy_try_crypto_seed_v1,
    },
};
use iroha_data_model::privacy::{
    PqMaspStarkStatementV1, PrivacyCommitmentV1, PrivacyConsensusLimitsV1,
    PrivacyEncryptedOutputV1, PrivacyNativeConsensusBindingV1,
    PrivacyNativeConsensusBindingValidationErrorV1, PrivacyStatementV1,
};
use rand::{TryCryptoRng, rngs::OsRng};
use soranet_pq::HedgedRngSeed;
use thiserror::Error;
const PQ_MASP_AUTHORIZATION_HEDGE_PURPOSE_V1: &[u8] =
    b"iroha:privacy:pq-masp:authorization-hedge:v1";
const PQ_MASP_NOTE_ENCRYPTION_PURPOSE_V1: &[u8] = b"iroha:privacy:pq-masp:note-encryption-seed:v1";
/// Failure constructing or checking a complete authorized PQ-MASP proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PqMaspProofErrorV1 {
    /// The public statement or private witness failed the canonical relation.
    #[error(transparent)]
    Relation(#[from] PqMaspRelationErrorV1),
    /// ML-DSA authorization material or its complete outer wire was invalid.
    #[error(transparent)]
    Authorization(#[from] PqMaspWireErrorV1),
    /// The trusted native consensus binding is invalid or does not exactly
    /// match the public statement context.
    #[error(transparent)]
    ConsensusBinding(#[from] PrivacyNativeConsensusBindingValidationErrorV1),
    /// The validated consensus binding could not be canonically encoded.
    #[error("PQ-MASP consensus binding encoding failed")]
    ConsensusBindingEncoding,
    /// Canonical statement encoding failed before authorization.
    #[error("PQ-MASP statement digest encoding failed")]
    StatementEncoding,
    /// The injected or operating-system cryptographic source failed.
    #[error("PQ-MASP prover entropy is unavailable")]
    RandomnessUnavailable,
    /// The cryptographic source emitted a catastrophic repeated pattern.
    #[error("PQ-MASP prover entropy failed its health check")]
    UnhealthyRandomness,
    /// A fixed proof or allocation bound was exceeded.
    #[error("PQ-MASP proof resource bound is exceeded")]
    ResourceLimit,
    /// Supplied proof bytes are malformed or invalid for the statement.
    #[error("PQ-MASP proof verification failed")]
    InvalidProof,
    /// A prevalidated witness could not be compiled by the fixed prover.
    #[error("PQ-MASP prover invariant failed")]
    ProverInvariant,
    /// The independent final check rejected bytes produced by the prover.
    #[error("PQ-MASP prover self-verification failed")]
    SelfVerification,
}
fn map_entropy_error_v1(error: TryCryptoProverRandomnessErrorV1) -> PqMaspProofErrorV1 {
    match error {
        TryCryptoProverRandomnessErrorV1::Unavailable => PqMaspProofErrorV1::RandomnessUnavailable,
        TryCryptoProverRandomnessErrorV1::Unhealthy => PqMaspProofErrorV1::UnhealthyRandomness,
    }
}
fn map_wallet_entropy_error_v1(error: TryCryptoProverRandomnessErrorV1) -> PqMaspWireErrorV1 {
    match error {
        TryCryptoProverRandomnessErrorV1::Unavailable => PqMaspWireErrorV1::RandomnessUnavailable,
        TryCryptoProverRandomnessErrorV1::Unhealthy => PqMaspWireErrorV1::UnhealthyRandomness,
    }
}
fn map_prover_error_v1(error: ProofManagedNoteStarkErrorV1) -> PqMaspProofErrorV1 {
    match error {
        ProofManagedNoteStarkErrorV1::Randomness => PqMaspProofErrorV1::RandomnessUnavailable,
        ProofManagedNoteStarkErrorV1::Resource => PqMaspProofErrorV1::ResourceLimit,
        ProofManagedNoteStarkErrorV1::InvalidProfile
        | ProofManagedNoteStarkErrorV1::InvalidTrace
        | ProofManagedNoteStarkErrorV1::Copy
        | ProofManagedNoteStarkErrorV1::Constraint
        | ProofManagedNoteStarkErrorV1::ProofWire
        | ProofManagedNoteStarkErrorV1::TraceOpening
        | ProofManagedNoteStarkErrorV1::Composition
        | ProofManagedNoteStarkErrorV1::Fri
        | ProofManagedNoteStarkErrorV1::Transcript
        | ProofManagedNoteStarkErrorV1::Internal => PqMaspProofErrorV1::ProverInvariant,
    }
}
fn map_verifier_error_v1(error: ProofManagedNoteStarkErrorV1) -> PqMaspProofErrorV1 {
    match error {
        ProofManagedNoteStarkErrorV1::Resource => PqMaspProofErrorV1::ResourceLimit,
        ProofManagedNoteStarkErrorV1::InvalidProfile | ProofManagedNoteStarkErrorV1::Internal => {
            PqMaspProofErrorV1::ProverInvariant
        }
        ProofManagedNoteStarkErrorV1::InvalidTrace
        | ProofManagedNoteStarkErrorV1::Copy
        | ProofManagedNoteStarkErrorV1::Constraint
        | ProofManagedNoteStarkErrorV1::ProofWire
        | ProofManagedNoteStarkErrorV1::TraceOpening
        | ProofManagedNoteStarkErrorV1::Composition
        | ProofManagedNoteStarkErrorV1::Fri
        | ProofManagedNoteStarkErrorV1::Transcript
        | ProofManagedNoteStarkErrorV1::Randomness => PqMaspProofErrorV1::InvalidProof,
    }
}
fn statement_digest_v1(
    statement: &PqMaspStarkStatementV1,
) -> Result<iroha_data_model::privacy::PrivacyStatementDigestV1, PqMaspProofErrorV1> {
    PrivacyStatementV1::PqMaspStarkV1(statement.clone())
        .digest()
        .map_err(|_| PqMaspProofErrorV1::StatementEncoding)
}
/// Construct a complete STARK-plus-ML-DSA PQ-MASP proof with injected entropy.
///
/// The function preflights the exact one-to-two relation and ML-DSA secret-key binding before proof
/// allocation. It reserves canonical source block two for the independent authorization hedge,
/// replays block one to the STARK before continuing at block three, signs the protocol-tagged
/// statement and exact inner-proof digest, then verifies the complete outer wire before returning.
///
/// # Errors
///
/// Returns a typed relation, key, encoding, entropy, resource, or prover
/// failure. A successful result is never returned without final verification.
pub fn prove_pq_masp_v1_with_rng<R: TryCryptoRng + ?Sized>(
    statement: &PqMaspStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    witness: &PqMaspWitnessV1,
    authorization_secret_key: &[u8],
    randomness: &mut R,
) -> Result<Vec<u8>, PqMaspProofErrorV1> {
    validate_pq_masp_relation_v1(statement, witness)?;
    consensus_binding.validate_against_context(&statement.context, consensus_limits)?;
    let consensus_binding_digest = consensus_binding
        .digest()
        .map_err(|_| PqMaspProofErrorV1::ConsensusBindingEncoding)?;
    validate_pq_masp_authorization_secret_key_v1(
        statement.authorization_key_digest,
        authorization_secret_key,
    )?;
    let statement_digest = statement_digest_v1(statement)?;
    let checked_randomness =
        HealthCheckedTryCryptoRngV1::new(randomness).map_err(map_entropy_error_v1)?;
    let (mut stark_randomness, authorization_seed) = checked_randomness
        .partition_initial_block_with_independent_seed_v1(PQ_MASP_AUTHORIZATION_HEDGE_PURPOSE_V1)
        .map_err(map_entropy_error_v1)?;
    let stark_proof = prove_pq_masp_stark_v1_with_rng(
        statement,
        consensus_binding,
        consensus_limits,
        witness,
        &mut stark_randomness,
    )
    .map_err(map_prover_error_v1)?;
    let proof = authorize_pq_masp_stark_proof_v1(
        statement_digest,
        consensus_binding_digest,
        statement.authorization_key_digest,
        authorization_secret_key,
        &stark_proof,
        HedgedRngSeed::from_entropy(*authorization_seed),
    )?;
    verify_pq_masp_v1(statement, consensus_binding, consensus_limits, &proof)
        .map_err(|_| PqMaspProofErrorV1::SelfVerification)?;
    Ok(proof)
}
/// Construct a complete STARK-plus-ML-DSA PQ-MASP proof with OS entropy.
///
/// # Errors
///
/// Returns the same closed typed failures as [`prove_pq_masp_v1_with_rng`].
pub fn prove_pq_masp_v1(
    statement: &PqMaspStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    witness: &PqMaspWitnessV1,
    authorization_secret_key: &[u8],
) -> Result<Vec<u8>, PqMaspProofErrorV1> {
    prove_pq_masp_v1_with_rng(
        statement,
        consensus_binding,
        consensus_limits,
        witness,
        authorization_secret_key,
        &mut OsRng,
    )
}
/// Verify one complete first-release PQ-MASP authorization and inner STARK.
///
/// # Errors
///
/// Rejects malformed, oversized, non-canonical, wrong-key, statement- or
/// consensus-binding-substituted, signature-invalid, or inner-proof-invalid bytes.
pub fn verify_pq_masp_v1(
    statement: &PqMaspStarkStatementV1,
    consensus_binding: &PrivacyNativeConsensusBindingV1,
    consensus_limits: &PrivacyConsensusLimitsV1,
    proof: &[u8],
) -> Result<(), PqMaspProofErrorV1> {
    validate_statement_v1(statement)?;
    consensus_binding.validate_against_context(&statement.context, consensus_limits)?;
    let consensus_binding_digest = consensus_binding
        .digest()
        .map_err(|_| PqMaspProofErrorV1::ConsensusBindingEncoding)?;
    let statement_digest = statement_digest_v1(statement)?;
    let authorization = verify_pq_masp_authorization_v1(
        statement_digest,
        consensus_binding_digest,
        statement.authorization_key_digest,
        proof,
    )?;
    verify_pq_masp_stark_v1(
        statement,
        consensus_binding,
        consensus_limits,
        authorization.stark_proof,
    )
    .map_err(map_verifier_error_v1)
}
/// Encrypt one PQ-MASP output note with injected, health-checked entropy.
///
/// The recipient binding and note commitment are checked before entropy is
/// consumed. All 64 sampled bytes influence the internal ML-KEM hedge seed.
///
/// # Errors
///
/// Rejects malformed keys or note material, recipient mismatch, entropy failure or repetition,
/// allocation failure, or authenticated-encryption failure.
pub fn encrypt_pq_masp_note_v1_with_rng<R: TryCryptoRng + ?Sized>(
    statement: &PqMaspStarkStatementV1,
    note: &PqMaspNotePlaintextV1,
    recipient_public_key: &[u8],
    randomness: &mut R,
) -> Result<(PrivacyCommitmentV1, PrivacyEncryptedOutputV1), PqMaspWireErrorV1> {
    let recipient = derive_pq_masp_recipient_id_v1(recipient_public_key)?;
    if recipient != note.recipient_key_digest() {
        return Err(PqMaspWireErrorV1::EncryptedOutputBinding);
    }
    derive_pq_masp_note_commitment_v1(statement, note)
        .map_err(|_| PqMaspWireErrorV1::NoteCommitmentMismatch)?;
    let seed = derive_healthy_try_crypto_seed_v1(randomness, PQ_MASP_NOTE_ENCRYPTION_PURPOSE_V1)
        .map_err(map_wallet_entropy_error_v1)?;
    encrypt_pq_masp_note_from_seed_v1(
        statement,
        note,
        recipient_public_key,
        HedgedRngSeed::from_entropy(*seed),
    )
}
/// Encrypt one PQ-MASP output note with operating-system entropy.
///
/// # Errors
///
/// Returns the same closed typed failures as [`encrypt_pq_masp_note_v1_with_rng`].
pub fn encrypt_pq_masp_note_v1(
    statement: &PqMaspStarkStatementV1,
    note: &PqMaspNotePlaintextV1,
    recipient_public_key: &[u8],
) -> Result<(PrivacyCommitmentV1, PrivacyEncryptedOutputV1), PqMaspWireErrorV1> {
    encrypt_pq_masp_note_v1_with_rng(statement, note, recipient_public_key, &mut OsRng)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::pq_masp::{
        PQ_MASP_TREE_DEPTH_V1, PqMaspInputWitnessV1, PqMaspOutputWitnessV1, PqMaspWitnessV1,
        derive_pq_masp_authorization_key_digest_v1, derive_pq_masp_nullifier_key_digest_v1,
    };
    use rand::{TryCryptoRng, TryRngCore};
    #[derive(Debug)]
    struct InjectedEntropyError;
    impl core::fmt::Display for InjectedEntropyError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected PQ-MASP entropy failure")
        }
    }
    enum EntropyMode {
        FailPartial,
        Constant,
        Repeated,
    }
    struct AdversarialRng(EntropyMode);
    impl TryRngCore for AdversarialRng {
        type Error = InjectedEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            match self.0 {
                EntropyMode::FailPartial => {
                    let midpoint = destination.len() / 2;
                    destination[..midpoint].fill(0x51);
                    Err(InjectedEntropyError)
                }
                EntropyMode::Constant => {
                    destination.fill(0x61);
                    Ok(())
                }
                EntropyMode::Repeated => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = [1, 3, 7, 9][index % 4];
                    }
                    Ok(())
                }
            }
        }
    }
    impl TryCryptoRng for AdversarialRng {}
    #[derive(Clone, Copy, Debug)]
    enum PartitionFaultV1 {
        FirstPartialFailure,
        FirstConstant,
        FirstPeriodic,
        SecondPartialFailure,
        SecondConstant,
        SecondPeriodic,
        SecondRepeatsFirst,
    }
    struct PartitionFaultRngV1 {
        fault: PartitionFaultV1,
        requests: usize,
    }
    impl PartitionFaultRngV1 {
        const fn new(fault: PartitionFaultV1) -> Self {
            Self { fault, requests: 0 }
        }
        fn fill_healthy_block_v1(destination: &mut [u8]) {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = u8::try_from(index)
                    .expect("canonical entropy block index fits u8")
                    .wrapping_mul(73)
                    .wrapping_add(19);
            }
        }
        fn fill_periodic_block_v1(destination: &mut [u8]) {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = [1, 3, 7, 9][index % 4];
            }
        }
    }
    impl TryRngCore for PartitionFaultRngV1 {
        type Error = InjectedEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(InjectedEntropyError)
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.requests += 1;
            assert_eq!(
                destination.len(),
                64,
                "the PQ-MASP source boundary must remain canonical"
            );
            match (self.requests, self.fault) {
                (1, PartitionFaultV1::FirstPartialFailure)
                | (2, PartitionFaultV1::SecondPartialFailure) => {
                    let midpoint = destination.len() / 2;
                    destination[..midpoint].fill(0x51);
                    Err(InjectedEntropyError)
                }
                (1, PartitionFaultV1::FirstConstant) | (2, PartitionFaultV1::SecondConstant) => {
                    destination.fill(0x61);
                    Ok(())
                }
                (1, PartitionFaultV1::FirstPeriodic) | (2, PartitionFaultV1::SecondPeriodic) => {
                    Self::fill_periodic_block_v1(destination);
                    Ok(())
                }
                (1, _) | (2, PartitionFaultV1::SecondRepeatsFirst) => {
                    Self::fill_healthy_block_v1(destination);
                    Ok(())
                }
                _ => panic!("PQ-MASP reached the expensive prover after entropy preflight failed"),
            }
        }
    }
    impl TryCryptoRng for PartitionFaultRngV1 {}
    fn consensus_material(
        statement: &PqMaspStarkStatementV1,
    ) -> (PrivacyNativeConsensusBindingV1, PrivacyConsensusLimitsV1) {
        let limits = PrivacyConsensusLimitsV1::taira_default();
        let genesis_hash = iroha_crypto::Hash::prehashed([0xC2; 32]).into();
        let binding =
            PrivacyNativeConsensusBindingV1::new(&statement.context, genesis_hash, &limits)
                .expect("valid PQ-MASP consensus binding");
        (binding, limits)
    }
    #[test]
    fn consensus_fixture_binds_the_canonical_genesis_bytes() {
        let (statement, _) =
            crate::privacy_engines::pq_masp::relation::test_fixtures::valid_fixture();
        let (binding, limits) = consensus_material(&statement);
        assert_eq!(binding.network_id, statement.context.network_id);
        assert_eq!(
            binding.validate_against_context(&statement.context, &limits),
            Ok(())
        );
        let mut unmarked = binding;
        unmarked.genesis_hash = [0xC2; 32];
        assert_eq!(
            unmarked.validate_against_context(&statement.context, &limits),
            Err(PrivacyNativeConsensusBindingValidationErrorV1::NetworkGenesisMismatch)
        );
    }
    fn note() -> PqMaspNotePlaintextV1 {
        let secret = [0x31; 32];
        PqMaspNotePlaintextV1::new(
            11,
            iroha_data_model::privacy::PrivacyAuthorizationKeyDigestV1::new([0x32; 32]),
            iroha_data_model::privacy::PrivacyRecipientIdV1::new([0x33; 32]),
            derive_pq_masp_nullifier_key_digest_v1(&secret).expect("nullifier digest"),
            [0x34; 32],
            [0x35; 32],
            [0x36; 32],
        )
        .expect("note")
    }
    #[test]
    fn typed_witnesses_reject_malformed_material_and_redact_debug() {
        let note = note();
        assert_eq!(format!("{note:?}"), "PqMaspNotePlaintextV1(<redacted>)");
        assert_eq!(
            PqMaspInputWitnessV1::new(
                note.clone(),
                [0x41; 32],
                0,
                [[0x42; 32]; PQ_MASP_TREE_DEPTH_V1],
            ),
            Err(PqMaspRelationErrorV1::NullifierKeyMismatch)
        );
        assert_eq!(
            PqMaspInputWitnessV1::new(
                note.clone(),
                [0x31; 32],
                0,
                [[0; 32]; PQ_MASP_TREE_DEPTH_V1],
            ),
            Err(PqMaspRelationErrorV1::ZeroWitnessComponent)
        );
        let input = PqMaspInputWitnessV1::new(
            note.clone(),
            [0x31; 32],
            0,
            [[0x42; 32]; PQ_MASP_TREE_DEPTH_V1],
        )
        .expect("input");
        let output = PqMaspOutputWitnessV1::new(note).expect("output");
        assert_eq!(
            PqMaspWitnessV1::new(Vec::new(), vec![output.clone()]),
            Err(PqMaspRelationErrorV1::WitnessShape)
        );
        let witness = PqMaspWitnessV1::new(vec![input], vec![output]).expect("witness");
        let debug = format!("{witness:?}");
        assert!(debug.contains("input_count"));
        assert!(!debug.contains("31313131"));
    }
    #[test]
    fn authorization_seed_rejects_failure_constant_and_repeated_patterns() {
        assert_eq!(
            derive_healthy_try_crypto_seed_v1(
                &mut AdversarialRng(EntropyMode::FailPartial),
                PQ_MASP_AUTHORIZATION_HEDGE_PURPOSE_V1,
            )
            .map(|_| ()),
            Err(TryCryptoProverRandomnessErrorV1::Unavailable)
        );
        assert_eq!(
            derive_healthy_try_crypto_seed_v1(
                &mut AdversarialRng(EntropyMode::Constant),
                PQ_MASP_AUTHORIZATION_HEDGE_PURPOSE_V1,
            )
            .map(|_| ()),
            Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
        );
        assert_eq!(
            derive_healthy_try_crypto_seed_v1(
                &mut AdversarialRng(EntropyMode::Repeated),
                PQ_MASP_AUTHORIZATION_HEDGE_PURPOSE_V1,
            )
            .map(|_| ()),
            Err(TryCryptoProverRandomnessErrorV1::Unhealthy)
        );
    }
    #[test]
    fn authorized_facade_maps_every_partition_entropy_failure_before_proving() {
        use soranet_pq::{HedgedRngSeed, MlDsaSuite, generate_mldsa_keypair_from_seed};
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xA6; 32]),
            b"pq-masp-partition-failure-tests-v1",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("authorization key digest");
        let (statement, witness) =
            crate::privacy_engines::pq_masp::relation::test_fixtures::
                valid_fixture_with_authorization_key_digest(key_digest);
        let (binding, limits) = consensus_material(&statement);
        let cases = [
            (
                PartitionFaultV1::FirstPartialFailure,
                PqMaspProofErrorV1::RandomnessUnavailable,
                1,
            ),
            (
                PartitionFaultV1::FirstConstant,
                PqMaspProofErrorV1::UnhealthyRandomness,
                1,
            ),
            (
                PartitionFaultV1::FirstPeriodic,
                PqMaspProofErrorV1::UnhealthyRandomness,
                1,
            ),
            (
                PartitionFaultV1::SecondPartialFailure,
                PqMaspProofErrorV1::RandomnessUnavailable,
                2,
            ),
            (
                PartitionFaultV1::SecondConstant,
                PqMaspProofErrorV1::UnhealthyRandomness,
                2,
            ),
            (
                PartitionFaultV1::SecondPeriodic,
                PqMaspProofErrorV1::UnhealthyRandomness,
                2,
            ),
            (
                PartitionFaultV1::SecondRepeatsFirst,
                PqMaspProofErrorV1::UnhealthyRandomness,
                2,
            ),
        ];
        for (fault, expected, expected_requests) in cases {
            let mut randomness = PartitionFaultRngV1::new(fault);
            assert_eq!(
                prove_pq_masp_v1_with_rng(
                    &statement,
                    &binding,
                    &limits,
                    &witness,
                    authorization_keys.secret_key(),
                    &mut randomness,
                ),
                Err(expected),
                "incorrect typed facade failure for {fault:?}"
            );
            assert_eq!(
                randomness.requests, expected_requests,
                "entropy fault {fault:?} crossed its fail-closed request boundary"
            );
        }
    }
    #[test]
    fn authorized_facade_rejects_relation_binding_and_key_before_entropy() {
        use soranet_pq::{HedgedRngSeed, MlDsaSuite, generate_mldsa_keypair_from_seed};
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xA7; 32]),
            b"pq-masp-pre-entropy-order-tests-v1",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("authorization key digest");
        let (statement, witness) =
            crate::privacy_engines::pq_masp::relation::test_fixtures::
                valid_fixture_with_authorization_key_digest(key_digest);
        let (binding, limits) = consensus_material(&statement);
        let mut invalid_statement = statement.clone();
        invalid_statement.nullifiers[0] =
            iroha_data_model::privacy::PrivacyNullifierV1::new([0xF1; 32]);
        let mut relation_rng = PartitionFaultRngV1::new(PartitionFaultV1::SecondPartialFailure);
        assert!(matches!(
            prove_pq_masp_v1_with_rng(
                &invalid_statement,
                &binding,
                &limits,
                &witness,
                authorization_keys.secret_key(),
                &mut relation_rng,
            ),
            Err(PqMaspProofErrorV1::Relation(_))
        ));
        assert_eq!(relation_rng.requests, 0);
        let mut invalid_binding = binding;
        invalid_binding.genesis_hash = [0; 32];
        let mut binding_rng = PartitionFaultRngV1::new(PartitionFaultV1::SecondPartialFailure);
        assert!(matches!(
            prove_pq_masp_v1_with_rng(
                &statement,
                &invalid_binding,
                &limits,
                &witness,
                authorization_keys.secret_key(),
                &mut binding_rng,
            ),
            Err(PqMaspProofErrorV1::ConsensusBinding(_))
        ));
        assert_eq!(binding_rng.requests, 0);
        let wrong_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy([0xA8; 32]),
            b"pq-masp-pre-entropy-wrong-key-v1",
        )
        .expect("wrong ML-DSA authorization key");
        let mut key_rng = PartitionFaultRngV1::new(PartitionFaultV1::SecondPartialFailure);
        assert_eq!(
            prove_pq_masp_v1_with_rng(
                &statement,
                &binding,
                &limits,
                &witness,
                wrong_keys.secret_key(),
                &mut key_rng,
            ),
            Err(PqMaspProofErrorV1::Authorization(
                PqMaspWireErrorV1::AuthorizationKeyMismatch,
            ))
        );
        assert_eq!(key_rng.requests, 0);
    }
    #[test]
    fn verifier_preflights_statement_bounds_before_outer_proof_parsing() {
        let (mut statement, _) =
            crate::privacy_engines::pq_masp::relation::test_fixtures::valid_fixture();
        let duplicate = statement.nullifiers[0];
        while statement.nullifiers.len() <= crate::privacy_engines::pq_masp::PQ_MASP_INPUT_BOUND_V1
        {
            statement.nullifiers.push(duplicate);
        }
        let (binding, limits) = consensus_material(&statement);
        assert_eq!(
            verify_pq_masp_v1(&statement, &binding, &limits, &[]),
            Err(PqMaspProofErrorV1::Relation(
                PqMaspRelationErrorV1::InvalidStatement,
            ))
        );
    }
    #[test]
    fn verifier_rejects_every_mismatched_consensus_binding_axis_before_wire_parsing() {
        let (statement, _) =
            crate::privacy_engines::pq_masp::relation::test_fixtures::valid_fixture();
        let (binding, limits) = consensus_material(&statement);
        let mut substitutions = Vec::new();
        let mut zero_genesis = binding;
        zero_genesis.genesis_hash = [0; 32];
        substitutions.push((
            "genesis_hash",
            zero_genesis,
            PrivacyNativeConsensusBindingValidationErrorV1::ZeroGenesisHash,
        ));
        let mut network_id = binding;
        network_id.network_id =
            iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xC3; 32]),
            ));
        network_id.genesis_hash = [0xC3; 32];
        substitutions.push((
            "network_id",
            network_id,
            PrivacyNativeConsensusBindingValidationErrorV1::NetworkIdMismatch,
        ));
        let mut action_index = binding;
        action_index.action_index += 1;
        substitutions.push((
            "action_index",
            action_index,
            PrivacyNativeConsensusBindingValidationErrorV1::ActionIndexMismatch,
        ));
        let mut transaction_intent = binding;
        transaction_intent.transaction_intent_digest =
            iroha_data_model::privacy::PrivacyTransactionIntentDigestV1::new([0xE1; 32]);
        substitutions.push((
            "transaction_intent_digest",
            transaction_intent,
            PrivacyNativeConsensusBindingValidationErrorV1::TransactionIntentDigestMismatch,
        ));
        let mut parameter_id = binding;
        parameter_id.parameter_id =
            iroha_data_model::privacy::PrivacyParameterIdV1::new([0xE2; 32]);
        substitutions.push((
            "parameter_id",
            parameter_id,
            PrivacyNativeConsensusBindingValidationErrorV1::ParameterIdMismatch,
        ));
        let mut parameter_digest = binding;
        parameter_digest.parameter_digest =
            iroha_data_model::privacy::PrivacyParameterDigestV1::new([0xE3; 32]);
        substitutions.push((
            "parameter_digest",
            parameter_digest,
            PrivacyNativeConsensusBindingValidationErrorV1::ParameterDigestMismatch,
        ));
        let mut verifier_digest = binding;
        verifier_digest.verifier_digest =
            iroha_data_model::privacy::PrivacyVerifierDigestV1::new([0xE4; 32]);
        substitutions.push((
            "verifier_digest",
            verifier_digest,
            PrivacyNativeConsensusBindingValidationErrorV1::VerifierDigestMismatch,
        ));
        let mut schema_digest = binding;
        schema_digest.statement_schema_digest =
            iroha_data_model::privacy::PrivacyStatementSchemaDigestV1::new([0xE5; 32]);
        substitutions.push((
            "statement_schema_digest",
            schema_digest,
            PrivacyNativeConsensusBindingValidationErrorV1::StatementSchemaDigestMismatch,
        ));
        let mut manifest_digest = binding;
        manifest_digest.engine_manifest_digest =
            iroha_data_model::privacy::PrivacyEngineManifestDigestV1::new([0xE6; 32]);
        substitutions.push((
            "engine_manifest_digest",
            manifest_digest,
            PrivacyNativeConsensusBindingValidationErrorV1::EngineManifestDigestMismatch,
        ));
        for (axis, substituted, expected) in substitutions {
            assert_eq!(
                verify_pq_masp_v1(&statement, &substituted, &limits, &[]),
                Err(PqMaspProofErrorV1::ConsensusBinding(expected)),
                "mismatched {axis} reached outer proof parsing"
            );
        }
    }
}
