//! Native zk-X509 engine boundary.
//!
//! The consensus verifier is present in every node build. Prover preparation and proof construction
//! are compiled only for tests or the explicitly non-shipping `privacy-release-evidence` workflow.
//!
//! The sole credential path constructs and independently verifies the bound `X5S1` MAIN/compact-CA
//! envelope. A native reference check, projection-only proof, or collection of unbound subproofs is
//! never accepted as a credential proof.
#[cfg(test)]
use super::prover_observation::{PhaseTimerV1, PhaseV1};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::{
    accumulator_stark::{ZkX509CaAccumulatorProofErrorV1, stages::commit_ca_through_auxiliary_v1},
    codec::{ZkX509WitnessCodecErrorV1, ZkX509WitnessV1},
    credential_pre_aux::ZkX509CredentialPreAuxErrorV1,
    credential_stark::encode_zk_x509_credential_envelope_v1,
    main_assembly::{ZkX509MainAssemblyErrorV1, build_zk_x509_main_trace_assembly_v1},
    relation::{
        ZkX509GovernanceV1, ZkX509RelationErrorV1, ZkX509RelationOutputV1,
        validate_reference_relation_v1,
    },
    stark::{
        ZkX509StarkErrorV1, commit_zk_x509_main_base_phase_v1_with_rng, finish_joint_main_ca_v1,
    },
};
use super::{
    accumulator_stark::{
        ca_accumulator_base_root_from_proof_v1, ca_profile_digest_v1, ca_public_digest_v1,
        joint_verifier::CaJointVerifierOraclesV1,
    },
    air::{ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1, ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1},
    credential_joint::JointOriginalOpeningsV1,
    credential_pre_aux::{
        ZK_X509_CREDENTIAL_PRE_AUX_DESCRIPTOR_V1, derive_zk_x509_credential_pre_aux_binding_v1,
    },
    credential_stark::{
        ZkX509CredentialProofErrorV1, ZkX509CredentialPublicBindingV1,
        decode_zk_x509_credential_envelope_v1,
    },
    der_air::ZkX509Rfc5280StatementV1,
    fixed_algebraic::ZK_X509_FIXED_ALGEBRAIC_DESCRIPTOR_V1,
    fixed_algebraic_p256::{
        ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1, ZkX509P256FixedAlgebraicErrorV1,
        zk_x509_p256_fixed_algebraic_schedule_v1,
    },
    fixed_algebraic_sha::{
        ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1, ZkX509ShaFixedAlgebraicErrorV1,
        zk_x509_sha_fixed_algebraic_schedule_v1,
    },
    io_air::ZK_X509_IO_AIR_DESCRIPTOR_V1,
    main_io::ZK_X509_MAIN_IO_DECLARATIONS_DESCRIPTOR_V1,
    merkle::hash_frame_v1,
    profile::{
        ZK_X509_CERTIFICATE_POLICY_REVISION_SCHEMA_V1, ZK_X509_CRL_PROFILE_V1,
        ZK_X509_CRL_REVISION_SCHEMA_V1, ZK_X509_CRL_SCOPE_PROFILE_V1, ZK_X509_ECDSA_RULES_V1,
        ZK_X509_RFC5280_PROFILE_V1, ZK_X509_SOURCE_PROFILE_V1, ZK_X509_STARK_PROFILE_DESCRIPTOR_V1,
        ZK_X509_SUITE_V1, ZK_X509_TRUST_ANCHOR_REVISION_SCHEMA_V1,
    },
    proof_instance::ZkX509ProofInstanceV1,
    sha_call_bus_stark::{
        ZK_X509_SHA_CALL_BUS_STARK_DESCRIPTOR_V1, ZkX509ShaCallPublicShapeV1,
        ZkX509ShaCallScheduleV1,
    },
    sha256_word_air::ZK_X509_SHA256_WORD_AIR_DESCRIPTOR_V1,
    stark::{
        MainJointVerifierOraclesV1, main_joint_auxiliary_from_proofs_v1,
        zk_x509_main_pre_aux_from_proof_v1,
    },
    verifier_profile::{
        ZK_X509_MAIN_ASSEMBLY_DESCRIPTOR_V1, ZK_X509_SHA256_LOCAL_AIR_DESCRIPTOR_V1,
        compile_zk_x509_rfc_statement_from_authoritative_state_v1,
    },
};
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_engines::prover_randomness::{
    HealthCheckedTryCryptoRngV1, TryCryptoProverRandomnessErrorV1,
};
use crate::privacy_state::PrivacyZkX509AuthoritativeStateV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use crate::privacy_state::validate_privacy_zk_x509_statement_state_v1;
use iroha_data_model::privacy::IrohaZkX509StarkP256StatementV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use iroha_data_model::privacy::PrivacyConsensusLimitsV1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
use rand::TryCryptoRng;
use thiserror::Error;
const COMPILED_PROFILE_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-x509.compiled-profile.v1";
const REFERENCE_PREPARATION_SCHEMA_V1: &[u8] = b"trusted-authoritative-state+trusted-block-time+taira-consensus-limits+exact-norito-zk-x509-witness-v1-flags0+strict-reference-relation";
const COMPILED_PROFILE_FIELD_COUNT_V1: usize = 29;
const SHA_DISCLOSURE_SHAPE_COUNT_V1: usize = 5;
// Independently encoded and SHA-256 checked from the exact ordered 29-field
// manifest, including the compact-CA descriptor and all six SHA3-384 algebraic
// schedule digests in their opaque byte order. The manifest itself uses SHA-256.
// This identifies the sole compiled AIR and geometry; activation additionally requires
// the proof cap and the complete soundness and resource certificates.
// Native derivation and independent framing bind the joint MAIN/CA private links,
// quotient blinding, selected P256 inputs and RFC output metadata in this candidate.
// Native diagnostics and independent framing bind the required proof-instance nonce.
// TODO: complete native credential, hiding and resource qualification before activating this profile.
const ZK_X509_COMPILED_PROFILE_DIGEST_V1: Option<[u8; 32]> = Some([
    0xfb, 0x4d, 0xc4, 0xd0, 0xb2, 0xce, 0x27, 0x7e, 0x23, 0xd3, 0xde, 0x9d, 0x4c, 0xcd, 0x6c, 0x32,
    0xc9, 0xa9, 0xb0, 0xef, 0x5b, 0x39, 0xf7, 0xc9, 0x63, 0xf8, 0xb9, 0x14, 0xcf, 0x15, 0x86, 0x0b,
]);
/// Exact algebraic-schedule-bearing profile required by MAIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZkX509CompiledProfileV1 {
    digest: [u8; 32],
}
impl ZkX509CompiledProfileV1 {
    /// Consensus transcript digest of the complete release manifest.
    ///
    /// This fingerprint identifies the compiled profile; it grants no source-pin or activation
    /// authority. Acceptance still requires the complete proof, soundness and resource checks.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}
/// Canonically decoded and reference-validated private prover input.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedZkX509ProverInputV1 {
    witness: ZkX509WitnessV1,
    projection: ZkX509RelationOutputV1,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl PreparedZkX509ProverInputV1 {
    /// Borrow the sole canonical witness representation.
    pub(crate) const fn witness(&self) -> &ZkX509WitnessV1 {
        &self.witness
    }
    /// Deterministic public projection recomputed from the private relation.
    pub(crate) const fn projection(&self) -> ZkX509RelationOutputV1 {
        self.projection
    }
}
/// Complete verifier-owned public input compiled before aggregate verification.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ZkX509ConsensusPublicInputsV1 {
    /// Canonical `X5S1` header binding derived from statement plus genesis.
    credential_binding: ZkX509CredentialPublicBindingV1,
    /// RFC predicates with the CRL number selected only from trusted state.
    rfc_statement: ZkX509Rfc5280StatementV1,
}
fn compile_zk_x509_consensus_public_inputs_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: &PrivacyZkX509AuthoritativeStateV1,
    genesis_hash: [u8; 32],
) -> Result<ZkX509ConsensusPublicInputsV1, ZkX509EngineErrorV1> {
    let credential_binding =
        ZkX509CredentialPublicBindingV1::from_consensus_context_v1(statement, genesis_hash)?;
    let rfc_statement =
        compile_zk_x509_rfc_statement_from_authoritative_state_v1(statement, authoritative_state);
    Ok(ZkX509ConsensusPublicInputsV1 {
        credential_binding,
        rfc_statement,
    })
}
/// Native prover preparation or credential-proof failure.
#[derive(Debug, PartialEq, Eq, Error)]
#[cfg_attr(
    not(any(test, feature = "privacy-release-evidence")),
    derive(Clone, Copy)
)]
#[doc(hidden)]
pub enum ZkX509EngineErrorV1 {
    /// Persisted state, roots, epochs, policy, or trusted block time mismatch.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 authoritative state validation failed: {0}")]
    InvalidAuthoritativeState(String),
    /// Private witness bytes are not the sole exact bounded grammar.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    WitnessCodec(#[from] ZkX509WitnessCodecErrorV1),
    /// Decode followed by encode did not reproduce the exact input bytes.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 witness codec failed its exact round-trip invariant")]
    WitnessRoundTripMismatch,
    /// Strict RFC 5280/reference relation failure.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    ReferenceRelation(#[from] ZkX509RelationErrorV1),
    /// Canonical challenge-independent MAIN material could not be assembled.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    MainAssembly(#[from] ZkX509MainAssemblyErrorV1),
    /// Joint MAIN/compact-CA challenge derivation failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    CredentialPreAux(#[from] ZkX509CredentialPreAuxErrorV1),
    /// Complete MAIN proof construction failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    MainProofConstruction(#[from] ZkX509StarkErrorV1),
    /// Dedicated compact-CA proof construction failed.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    CaProofConstruction(#[from] ZkX509CaAccumulatorProofErrorV1),
    /// Prover entropy was unavailable or failed the first-release health policy.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error(transparent)]
    ProverRandomness(#[from] TryCryptoProverRandomnessErrorV1),
    /// Canonical credential envelope or consensus-context binding failure.
    #[error(transparent)]
    CredentialProof(#[from] ZkX509CredentialProofErrorV1),
    /// Producer-generated X5S1 bytes failed the independent consensus verifier.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 credential prover self-check failed")]
    ProverSelfCheckFailed,
    /// Canonical MAIN assembly did not reproduce prover preparation exactly.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    #[error("zk-X509 canonical prover projection mismatch")]
    ProverProjectionMismatch,
    /// The canonical SHA algebraic compiler or schedule rejected its profile.
    #[error(transparent)]
    ShaFixedAlgebraic(#[from] ZkX509ShaFixedAlgebraicErrorV1),
    /// The canonical P-256 algebraic compiler or schedule rejected its profile.
    #[error(transparent)]
    P256FixedAlgebraic(#[from] ZkX509P256FixedAlgebraicErrorV1),
    /// The complete 29-field release manifest has not been pinned.
    #[error("zk-X509 compiled profile is not release-pinned")]
    CompiledProfileUnpinned,
    /// Recomputed 29-field manifest digest differs from the consensus pin.
    #[error("zk-X509 compiled profile digest mismatch")]
    CompiledProfileMismatch,
}
/// Replay the complete cryptographic verifier for the bound subproof pair.
fn verify_zk_x509_credential_subproofs_v1(
    proof_instance: ZkX509ProofInstanceV1,
    statement: &IrohaZkX509StarkP256StatementV1,
    consensus_public: &ZkX509ConsensusPublicInputsV1,
    main_aggregate: &[u8],
    ca_subproof: &[u8],
    joint_openings: JointOriginalOpeningsV1,
) -> Result<(), ZkX509EngineErrorV1> {
    construct_zk_x509_compiled_profile_v1()?;
    let sha_shape = ZkX509ShaCallPublicShapeV1 {
        disclosed_attributes: consensus_public
            .rfc_statement
            .disclosed_attribute_indices
            .len(),
    };
    let sha_schedule = ZkX509ShaCallScheduleV1::new(sha_shape)
        .map_err(|_| ZkX509CredentialProofErrorV1::InvalidStatement)?;
    let main_pre_aux = zk_x509_main_pre_aux_from_proof_v1(
        proof_instance,
        consensus_public.credential_binding,
        main_aggregate,
    )
    .map_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1("credential-main", &_error);
        ZkX509CredentialProofErrorV1::MainProof
    })?;
    let ca_base_root = ca_accumulator_base_root_from_proof_v1(ca_subproof).map_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1("credential-ca", &_error);
        ZkX509CredentialProofErrorV1::CaProof
    })?;
    let credential_binding = derive_zk_x509_credential_pre_aux_binding_v1(
        main_pre_aux,
        ca_profile_digest_v1().map_err(|_| ZkX509CredentialProofErrorV1::CaProof)?,
        ca_public_digest_v1(
            proof_instance,
            consensus_public.credential_binding.ca_public_v1(),
            &sha_schedule,
        )
        .map_err(|_| ZkX509CredentialProofErrorV1::CaProof)?,
        ca_base_root,
    )
    .map_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1("credential-cross-binding", &_error);
        ZkX509CredentialProofErrorV1::CrossSubproofMismatch
    })?;
    let auxiliary =
        main_joint_auxiliary_from_proofs_v1(&credential_binding, main_aggregate, ca_subproof)
            .map_err(|_| ZkX509CredentialProofErrorV1::CrossSubproofMismatch)?;
    let main = MainJointVerifierOraclesV1::new_v1(
        statement,
        &consensus_public.rfc_statement,
        consensus_public.credential_binding,
        credential_binding,
        auxiliary,
        &sha_schedule,
        main_aggregate,
    )
    .map_err(|_| ZkX509CredentialProofErrorV1::MainProof)?;
    let ca = CaJointVerifierOraclesV1::new_v1(
        consensus_public.credential_binding.ca_public_v1(),
        &sha_schedule,
        main_pre_aux,
        auxiliary,
        ca_subproof,
    )
    .map_err(|_| ZkX509CredentialProofErrorV1::CaProof)?;
    let point = main
        .derive_joint_point_v1(&ca)
        .map_err(|_| ZkX509CredentialProofErrorV1::CrossSubproofMismatch)?;
    let mut main = main
        .open_joint_point_v1(point)
        .map_err(|_| ZkX509CredentialProofErrorV1::MainProof)?;
    let mut ca = ca
        .open_joint_point_v1(point)
        .map_err(|_| ZkX509CredentialProofErrorV1::CaProof)?;
    let binding = main
        .bind_ca_openings_v1(&mut ca, joint_openings)
        .map_err(|_| ZkX509CredentialProofErrorV1::CrossSubproofMismatch)?;
    main.finish_v1(binding)
        .map_err(|_| ZkX509CredentialProofErrorV1::MainProof)?;
    ca.finish_v1(binding)
        .map_err(|_| ZkX509CredentialProofErrorV1::CaProof)?;
    Ok(())
}
/// Verify one canonical credential proof against verifier-owned consensus data.
///
/// This is the sole consensus entry point for `X5S1`. It already performs strict envelope decoding
/// and binds the complete typed statement to the committed genesis hash before inspecting any
/// aggregate. The caller must supply the same authoritative snapshot it already validated against
/// trusted block time and consensus limits; the engine compiles the RFC public input from that
/// snapshot rather than from proof metadata.
#[doc(hidden)]
pub fn verify_zk_x509_credential_proof_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: &PrivacyZkX509AuthoritativeStateV1,
    genesis_hash: [u8; 32],
    encoded_proof: &[u8],
) -> Result<(), ZkX509EngineErrorV1> {
    let consensus_public =
        compile_zk_x509_consensus_public_inputs_v1(statement, authoritative_state, genesis_hash)?;
    let envelope = decode_zk_x509_credential_envelope_v1(encoded_proof).inspect_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1("credential-envelope-decode", _error);
    })?;
    if envelope.public != consensus_public.credential_binding {
        return Err(ZkX509CredentialProofErrorV1::PublicBindingMismatch.into());
    }
    verify_zk_x509_credential_subproofs_v1(
        envelope.proof_instance,
        statement,
        &consensus_public,
        envelope.main_aggregate,
        envelope.ca_subproof,
        envelope.joint_openings,
    )
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn validate_witness_round_trip_v1(
    witness: &ZkX509WitnessV1,
    encoded_witness: &[u8],
) -> Result<(), ZkX509EngineErrorV1> {
    let canonical = super::private_table::PrivateTableV1::new(
        witness.encode_v1()?,
        super::private_table::zeroize_words_v1,
    );
    if canonical.as_slice() != encoded_witness {
        return Err(ZkX509EngineErrorV1::WitnessRoundTripMismatch);
    }
    Ok(())
}

/// Decode and validate the exact prover input against trusted ledger state.
///
/// This function performs no proof construction. Its output is the only
/// admitted input to the credential-proof constructor.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) fn prepare_zk_x509_prover_input_v1(
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: &PrivacyZkX509AuthoritativeStateV1,
    trusted_block_timestamp_ms: u64,
    consensus_limits: &PrivacyConsensusLimitsV1,
    encoded_witness: &[u8],
) -> Result<PreparedZkX509ProverInputV1, ZkX509EngineErrorV1> {
    validate_privacy_zk_x509_statement_state_v1(
        statement,
        authoritative_state,
        trusted_block_timestamp_ms,
        consensus_limits,
    )
    .map_err(ZkX509EngineErrorV1::InvalidAuthoritativeState)?;
    let witness = ZkX509WitnessV1::decode_exact_v1(encoded_witness)?;
    // Decode is already exact.  Re-encoding here is a deliberate differential
    // invariant for the eventual external prover boundary.
    validate_witness_round_trip_v1(&witness, encoded_witness)?;
    let trust_anchor = authoritative_state.trust_anchor();
    let crl = authoritative_state.crl_record();
    let governance = ZkX509GovernanceV1 {
        trust_anchor: &trust_anchor,
        certificate_policy: authoritative_state.certificate_policy(),
        crl: &crl,
    };
    let projection = validate_reference_relation_v1(statement, governance, &witness)?;
    Ok(PreparedZkX509ProverInputV1 {
        witness,
        projection,
    })
}
/// Construct one canonical `X5S1` credential proof with injected entropy.
///
/// Every state, witness, release-profile, topology, and native-relation check
/// completes before the entropy source is touched. The constructor then:
///
/// 1. joins the exact six MAIN base groups under one authenticated root;
/// 2. commits the CA base root, derives the joint `X5B1` capability, and commits
///    the CA auxiliary columns using those shared challenges;
/// 3. commits the MAIN auxiliary columns and binds both original auxiliary roots;
/// 4. commits both compositions and FRI masks before the shared DEEP point,
///    binds all joint openings, and completes both local FRI proofs;
/// 5. wraps the ordered pair and 132 joint openings in `X5S1` and independently
///    invokes the consensus verifier on the exact final bytes.
///
/// There is no independently accepted subproof path and no host-side
/// reference-relation substitute for the final self-check.
///
/// Successful construction consumes the canonical entropy sequence. Construction
/// is fail-fast after preflight: an error may consume only a prefix of that
/// sequence, and the injected RNG is neither rolled back nor advanced to a fixed
/// failure position. An uncertain accelerator completion returns no proof and
/// stops further source construction and entropy use under the existing process
/// quarantine. Callers must not depend on identical RNG state across failures.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[doc(hidden)]
pub fn prove_zk_x509_credential_proof_v1_with_rng<R: TryCryptoRng>(
    statement: &IrohaZkX509StarkP256StatementV1,
    authoritative_state: &PrivacyZkX509AuthoritativeStateV1,
    trusted_block_timestamp_ms: u64,
    consensus_limits: &PrivacyConsensusLimitsV1,
    genesis_hash: [u8; 32],
    encoded_witness: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, ZkX509EngineErrorV1> {
    if fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1() {
        return Err(ZkX509StarkErrorV1::AcceleratorCompletionUncertain.into());
    }
    // Every witness-dependent preflight deliberately precedes the first
    // entropy read.
    #[cfg(test)]
    let preparation_timer = PhaseTimerV1::start_v1(PhaseV1::Preparation);
    construct_zk_x509_compiled_profile_v1()?;
    let consensus_public =
        compile_zk_x509_consensus_public_inputs_v1(statement, authoritative_state, genesis_hash)?;
    super::stark::validate_zk_x509_main_proof_budget_v1()?;
    let prepared = prepare_zk_x509_prover_input_v1(
        statement,
        authoritative_state,
        trusted_block_timestamp_ms,
        consensus_limits,
        encoded_witness,
    )?;
    let trust_anchor = authoritative_state.trust_anchor();
    let crl = authoritative_state.crl_record();
    let governance = ZkX509GovernanceV1 {
        trust_anchor: &trust_anchor,
        certificate_policy: authoritative_state.certificate_policy(),
        crl: &crl,
    };
    #[cfg(test)]
    preparation_timer.complete_v1();
    #[cfg(test)]
    let assembly_timer = PhaseTimerV1::start_v1(PhaseV1::Assembly);
    let assembly = build_zk_x509_main_trace_assembly_v1(statement, governance, prepared.witness())?;
    if assembly.relation_output != prepared.projection() {
        return Err(ZkX509EngineErrorV1::ProverProjectionMismatch);
    }
    #[cfg(test)]
    assembly_timer.complete_v1();
    let mut checked_rng = HealthCheckedTryCryptoRngV1::new(rng)?;
    let proof_instance = ZkX509ProofInstanceV1::sample_v1(&mut checked_rng)?;
    let (main_phase, main_pre_aux) = commit_zk_x509_main_base_phase_v1_with_rng(
        proof_instance,
        statement,
        &assembly,
        consensus_public.credential_binding,
        &mut checked_rng,
    )?;
    #[cfg(test)]
    let ca_timer = PhaseTimerV1::start_v1(PhaseV1::CompactCa);
    let ca_phase = commit_ca_through_auxiliary_v1(
        &assembly.ca_accumulator_trace,
        &assembly.sha_schedule,
        main_pre_aux,
        &mut checked_rng,
    )?;
    #[cfg(test)]
    ca_timer.complete_v1();
    let main_phase =
        main_phase.bind_joint_credential_pre_aux_v1_with_rng(&ca_phase, &mut checked_rng)?;
    let (main_aggregate, ca_subproof, joint_openings) =
        finish_joint_main_ca_v1(main_phase, ca_phase, &mut checked_rng)?;
    #[cfg(test)]
    let envelope_timer = PhaseTimerV1::start_v1(PhaseV1::EnvelopeAndSelfCheck);
    let encoded = encode_zk_x509_credential_envelope_v1(
        proof_instance,
        consensus_public.credential_binding,
        &main_aggregate,
        &ca_subproof,
        &joint_openings
            .encode_v1()
            .map_err(|_| ZkX509CredentialProofErrorV1::MalformedEnvelope)?,
    )?;
    #[cfg(test)]
    prover_diagnostic::capture_public_unverified_candidate_v1(&encoded);
    let envelope = decode_zk_x509_credential_envelope_v1(&encoded).map_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1("credential-envelope-decode", &_error);
        ZkX509EngineErrorV1::ProverSelfCheckFailed
    })?;
    if envelope.proof_instance != proof_instance
        || envelope.public != consensus_public.credential_binding
    {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1(
            "credential-public-binding",
            &ZkX509CredentialProofErrorV1::PublicBindingMismatch,
        );
        return Err(ZkX509EngineErrorV1::ProverSelfCheckFailed);
    }
    verify_zk_x509_credential_subproofs_v1(
        envelope.proof_instance,
        statement,
        &consensus_public,
        envelope.main_aggregate,
        envelope.ca_subproof,
        envelope.joint_openings,
    )
    .map_err(|_error| {
        #[cfg(test)]
        prover_diagnostic::record_public_verifier_error_v1(
            "credential-subproof-self-check",
            &_error,
        );
        ZkX509EngineErrorV1::ProverSelfCheckFailed
    })?;
    #[cfg(test)]
    envelope_timer.complete_v1();
    Ok(encoded)
}
fn compiled_profile_fields_v1<'a>(
    sha_schedule_digests: &'a [[u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1],
    p256_schedule_digest: &'a [u8; 48],
) -> [&'a [u8]; COMPILED_PROFILE_FIELD_COUNT_V1] {
    [
        ZK_X509_SUITE_V1,
        ZK_X509_SOURCE_PROFILE_V1,
        ZK_X509_RFC5280_PROFILE_V1,
        ZK_X509_CRL_PROFILE_V1,
        ZK_X509_CRL_SCOPE_PROFILE_V1,
        ZK_X509_TRUST_ANCHOR_REVISION_SCHEMA_V1,
        ZK_X509_CERTIFICATE_POLICY_REVISION_SCHEMA_V1,
        ZK_X509_CRL_REVISION_SCHEMA_V1,
        ZK_X509_ECDSA_RULES_V1,
        ZK_X509_STARK_PROFILE_DESCRIPTOR_V1,
        ZK_X509_MAIN_ASSEMBLY_DESCRIPTOR_V1,
        ZK_X509_MAIN_IO_DECLARATIONS_DESCRIPTOR_V1,
        ZK_X509_CREDENTIAL_PRE_AUX_DESCRIPTOR_V1,
        ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1,
        &ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1,
        ZK_X509_SHA256_LOCAL_AIR_DESCRIPTOR_V1,
        ZK_X509_SHA256_WORD_AIR_DESCRIPTOR_V1,
        ZK_X509_SHA_CALL_BUS_STARK_DESCRIPTOR_V1,
        ZK_X509_IO_AIR_DESCRIPTOR_V1,
        REFERENCE_PREPARATION_SCHEMA_V1,
        ZK_X509_FIXED_ALGEBRAIC_DESCRIPTOR_V1,
        ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1,
        &sha_schedule_digests[0],
        &sha_schedule_digests[1],
        &sha_schedule_digests[2],
        &sha_schedule_digests[3],
        &sha_schedule_digests[4],
        ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1,
        p256_schedule_digest,
    ]
}
fn compiled_profile_schedule_digests_v1()
-> Result<([[u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1], [u8; 48]), ZkX509EngineErrorV1> {
    let mut sha = [[0_u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1];
    for (disclosed_attributes, digest) in sha.iter_mut().enumerate() {
        *digest = zk_x509_sha_fixed_algebraic_schedule_v1(ZkX509ShaCallPublicShapeV1 {
            disclosed_attributes,
        })?
        .descriptor_digest_v1()
        .to_bytes();
    }
    let p256 = zk_x509_p256_fixed_algebraic_schedule_v1()?
        .descriptor_digest_v1()
        .to_bytes();
    Ok((sha, p256))
}
/// Recompute the sole exact 29-field compiled-profile digest.
pub(crate) fn recompute_zk_x509_compiled_profile_digest_v1() -> Result<[u8; 32], ZkX509EngineErrorV1>
{
    let (sha, p256) = compiled_profile_schedule_digests_v1()?;
    hash_frame_v1(
        COMPILED_PROFILE_DIGEST_DOMAIN_V1,
        &compiled_profile_fields_v1(&sha, &p256),
    )
    .map_err(|_| ZkX509EngineErrorV1::CompiledProfileMismatch)
}
/// Construct the sole complete algebraic-schedule-bearing release profile.
///
/// All six success-only verifier schedule caches must compile before the
/// manifest digest is compared with its independent release pin.
#[doc(hidden)]
pub fn construct_zk_x509_compiled_profile_v1()
-> Result<ZkX509CompiledProfileV1, ZkX509EngineErrorV1> {
    let digest = recompute_zk_x509_compiled_profile_digest_v1()?;
    let expected =
        ZK_X509_COMPILED_PROFILE_DIGEST_V1.ok_or(ZkX509EngineErrorV1::CompiledProfileUnpinned)?;
    if digest != expected {
        return Err(ZkX509EngineErrorV1::CompiledProfileMismatch);
    }
    Ok(ZkX509CompiledProfileV1 { digest })
}
#[cfg(test)]
mod tests {
    use super::super::profile::ZK_X509_HASH_FRAME_DOMAIN_V1;
    use super::*;
    use iroha_data_model::privacy::PrivacyProtocolIdV1;
    use sha2::{Digest, Sha256};
    fn independently_encode_compiled_profile_frame_v1(fields: &[&[u8]]) -> Vec<u8> {
        let domain_len =
            u16::try_from(COMPILED_PROFILE_DIGEST_DOMAIN_V1.len()).expect("small domain");
        let field_count = u16::try_from(fields.len()).expect("small field manifest");
        let mut frame = Vec::new();
        frame.extend_from_slice(ZK_X509_HASH_FRAME_DOMAIN_V1);
        frame.extend_from_slice(&domain_len.to_be_bytes());
        frame.extend_from_slice(COMPILED_PROFILE_DIGEST_DOMAIN_V1);
        frame.extend_from_slice(&field_count.to_be_bytes());
        for field in fields {
            let field_len = u64::try_from(field.len()).expect("profile field fits u64");
            frame.extend_from_slice(&field_len.to_be_bytes());
            frame.extend_from_slice(field);
        }
        frame
    }
    fn independent_compiled_profile_digest_v1(fields: &[&[u8]]) -> [u8; 32] {
        Sha256::digest(independently_encode_compiled_profile_frame_v1(fields)).into()
    }
    #[test]
    fn compiled_profile_manifest_has_the_exact_29_field_order() {
        let sha_digests: [[u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1] =
            core::array::from_fn(|shape| [u8::try_from(0x31 + shape).expect("five shapes"); 48]);
        let p256_digest = [0x41; 48];
        let fields = compiled_profile_fields_v1(&sha_digests, &p256_digest);
        let original_fields: [&[u8]; 20] = [
            ZK_X509_SUITE_V1,
            ZK_X509_SOURCE_PROFILE_V1,
            ZK_X509_RFC5280_PROFILE_V1,
            ZK_X509_CRL_PROFILE_V1,
            ZK_X509_CRL_SCOPE_PROFILE_V1,
            ZK_X509_TRUST_ANCHOR_REVISION_SCHEMA_V1,
            ZK_X509_CERTIFICATE_POLICY_REVISION_SCHEMA_V1,
            ZK_X509_CRL_REVISION_SCHEMA_V1,
            ZK_X509_ECDSA_RULES_V1,
            ZK_X509_STARK_PROFILE_DESCRIPTOR_V1,
            ZK_X509_MAIN_ASSEMBLY_DESCRIPTOR_V1,
            ZK_X509_MAIN_IO_DECLARATIONS_DESCRIPTOR_V1,
            ZK_X509_CREDENTIAL_PRE_AUX_DESCRIPTOR_V1,
            ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1,
            &ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1,
            ZK_X509_SHA256_LOCAL_AIR_DESCRIPTOR_V1,
            ZK_X509_SHA256_WORD_AIR_DESCRIPTOR_V1,
            ZK_X509_SHA_CALL_BUS_STARK_DESCRIPTOR_V1,
            ZK_X509_IO_AIR_DESCRIPTOR_V1,
            REFERENCE_PREPARATION_SCHEMA_V1,
        ];
        assert_eq!(fields.len(), 29);
        assert_eq!(&fields[..20], &original_fields);
        assert_eq!(fields[20], ZK_X509_FIXED_ALGEBRAIC_DESCRIPTOR_V1);
        assert_eq!(
            fields[21],
            ZK_X509_SHA_FIXED_ALGEBRAIC_COMPILER_DESCRIPTOR_V1
        );
        for (shape, digest) in sha_digests.iter().enumerate() {
            assert_eq!(fields[22 + shape], digest);
        }
        assert_eq!(fields[27], ZK_X509_P256_FIXED_ALGEBRAIC_DESCRIPTOR_V1);
        assert_eq!(fields[28], p256_digest);
        assert!(
            fields[12]
                .windows(b"post-base-challenges=exact272-goldilocks-fields".len())
                .any(|window| window == b"post-base-challenges=exact272-goldilocks-fields")
        );
        assert!(
            fields[17]
                .windows(b"main-common-lde-log22".len())
                .any(|window| window == b"main-common-lde-log22")
        );
        assert!(
            !fields[17]
                .windows(b"common-lde-log25".len())
                .any(|window| window == b"common-lde-log25")
        );
    }
    #[test]
    fn compiled_profile_digest_exactly_binds_compact_ca_subproof_descriptor_pin() {
        let sha_digests: [[u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1] =
            core::array::from_fn(|shape| [u8::try_from(0x71 + shape).expect("five shapes"); 48]);
        let p256_digest = [0x81; 48];
        let canonical_fields = compiled_profile_fields_v1(&sha_digests, &p256_digest);
        assert_eq!(
            canonical_fields[14],
            ZK_X509_COMPACT_CA_SUBPROOF_DESCRIPTOR_SHA256_V1.as_slice()
        );
        let canonical = independent_compiled_profile_digest_v1(&canonical_fields);
        let mut changed = canonical_fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        changed[14][0] ^= 1;
        let changed_fields = changed.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_ne!(
            independent_compiled_profile_digest_v1(&changed_fields),
            canonical,
            "the compact-CA prover/verifier descriptor pin must rotate the compiled profile"
        );
    }
    #[test]
    fn compiled_profile_binds_every_algebraic_field_and_its_order() {
        let sha_digests: [[u8; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1] =
            core::array::from_fn(|shape| [u8::try_from(0x51 + shape).expect("five shapes"); 48]);
        let p256_digest = [0x61; 48];
        let canonical_fields = compiled_profile_fields_v1(&sha_digests, &p256_digest);
        let canonical = independent_compiled_profile_digest_v1(&canonical_fields);
        let owned = canonical_fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        for field in 20..COMPILED_PROFILE_FIELD_COUNT_V1 {
            let mut changed = owned.clone();
            changed[field][0] ^= 1;
            let changed_fields = changed.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_ne!(
                independent_compiled_profile_digest_v1(&changed_fields),
                canonical,
                "manifest field {field} must be bound"
            );
        }
        let mut reordered = owned;
        reordered.swap(22, 23);
        let reordered_fields = reordered.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_ne!(
            independent_compiled_profile_digest_v1(&reordered_fields),
            canonical,
            "SHA disclosure-shape digest order must be bound"
        );
    }
    #[test]
    fn compiled_profile_constructor_matches_the_independent_release_pin() {
        let (sha_digests, p256_digest) =
            compiled_profile_schedule_digests_v1().expect("all six frozen schedules");
        let fields = compiled_profile_fields_v1(&sha_digests, &p256_digest);
        let independent = independent_compiled_profile_digest_v1(&fields);
        let recomputed =
            recompute_zk_x509_compiled_profile_digest_v1().expect("canonical manifest digest");
        assert_eq!(recomputed, independent);
        if cfg!(feature = "privacy-release-evidence")
            || ZK_X509_COMPILED_PROFILE_DIGEST_V1 != Some(independent)
        {
            // These are public profile descriptors, never witness material.
            // Release evidence retains the genuine native framing inputs even
            // when the current stored pin already matches the constructor.
            eprintln!(
                "zk-x509-independent-compiled-profile-sha256={}",
                hex::encode(independent)
            );
            for (index, field) in fields.iter().enumerate() {
                eprintln!(
                    "zk-x509-compiled-profile-field-{index}={}",
                    hex::encode(field)
                );
            }
        }
        assert_eq!(ZK_X509_COMPILED_PROFILE_DIGEST_V1, Some(independent));
        assert_eq!(
            construct_zk_x509_compiled_profile_v1()
                .expect("release-pinned profile")
                .digest(),
            independent
        );
    }
    // Historical profile tests must use the exact old public descriptors,
    // rather than accidentally mixing a new closure with an old SHA-padding pin.
    fn restore_retired_public_terminal_profile_descriptors_v1(fields: &mut [Vec<u8>]) {
        assert_eq!(fields.len(), COMPILED_PROFILE_FIELD_COUNT_V1);
        fields[9] = b"field=goldilocks-fp4:w4=7:base=0xffffffff00000001|wire=X5S1-containing-exactly-one-X5M1-and-one-X5C1-v1|x5m1=claims-plus-length-delimited-aggregate-only-no-fixed-sidecar|main-logical-registrations=49|main-same-log-trace-groups=6-logs5,8,15,16,18,19|main-physical-roots=one-joined-base-and-one-joined-aux|main-physical-commitment-chunks=80|physical-chunk-columns=64|max-native-trace-log2=19|compact-ca-dedicated-log13-subproof-depth12|sha-fixed-calls=29-across-four-log19-slices|p256-binding-sink-degree=3-including-fixed-selectors|sha-capacity-and-call-degree=6-including-fixed-selectors|sha-digest-address=polynomial-select|sha-fixed-algebraic-width=472-verifier-derived-no-proof-bytes|p256-log19-fixed-algebraic-width=404-six-role-schedules-alias-fifteen-registrations-verifier-derived-no-proof-bytes|fixed-polynomials=verifier-derived-at-deep-and-native-translates|shared-x5b1-challenges=single-joined-main-base-root+ca-base-root+main-and-ca-public-profile+exact272-fields-ordered-sha-call,rfc,projection,io,der,sha-word-memory,sha-word-base-fold,p256-value,p256-cross,p256-scalar,p256-arithmetic-copy+one-opaque-main-post-base-token|main-io=statement-only-exact40+5d-declarations+logical55922+4736d-active-rows+fixed-capacity262144|main-trace-hiding-coefficients=1816|ca-trace-hiding-coefficients=696|fri-mask-oracles=1-fp4-per-subproof-roots-before-batching|lde-column-batch=8|max-constraint-degree=7|fri-rate=9over64|main-fri-blowup=8|ca-lde-log2=16|fri-queries=136-distinct-without-replacement|composition-fp4-lanes=1|fri-batching-m=3|affine-arities=2,2,2|fri-folding=2|fri-leaves=ordered-low-high-pairs|main-fri-terminal-length=1024-degree143|ca-fri-terminal-length=1024-degree143|deep-points=1-per-subproof-current+next-openings|ca-deep-constraints=all1379-fp4-verifier-fixed-polynomials-current-only-query-rows|main-deep-constraints=all49-fp4-native-vanishing-six-chunk-recomposition-verifier-fixed-polynomials-current-only-query-rows|grinding-bits=20|target-soundness-bits=128|rfc5280-temporal-air=base285-aux280-fixed102-constraints1681-degree4-authenticated72-times-73-relations-38bit-slack-affine-loglookup-30-relations|rbr-budget-bits=157|random-oracle-kappa=256|max-ro-queries-log2=64|max-encoded-combined-bound=9420938|max-proof-bytes=9437184|peak-memory-ceiling-bytes=12884901888|address-space-ceiling-bytes=34359738368|prover-target-seconds=300|release-evidence-schema=deterministic-X5S1-KAT+public-binding-mutations+wire-corruption-and-truncation+maximum-shape-process-measurement|shared-stark-v1=q136-blowup8-digest384-fp4-blocked-pending-independent-qualification|activation=unavailable".to_vec();
        fields[10] = b"zk-x509-main-assembly-v1-incompatible:strict-reference-prover-invariant:exact-der-rfc-projection-ca-sources:29-verifier-positioned-sha-witnesses:five-p256-equations:optional-slot2-rfc-zero-source-and-public-valid-dummy-selector:statement-compiled-deduplicated-sequential-byte-io:exact-witness-declaration-replay:logical-active-row-census:exact49-registrations:no-host-verification-substitute:verifier-terminal-replay=complete:activation=governance-gated".to_vec();
        // Historical profiles predate the corrected CA domain descriptor.
        // Restore its exact bytes alongside the retired relation descriptors.
        fields[12] = b"zk-x509-credential-pre-aux-v1:X5B1:version1:profile=main-profile-digest+ca-profile-digest:public=consensus-context-digest+ca-public-digest:base-roots=exact-main1-joined-ordered-native-log5,8,15,16,18,19-then-ca1-log13:post-base-challenges=exact272-goldilocks-fields:01-sha-call=4lanes*(beta,call,role,slot,kind,word,value)=28:02-rfc=4lanes*tuple12=48:03-projection=4lanes*(copy-beta,copy-gamma,compaction-active,compaction-invocation,compaction-position,compaction-value,compaction-gamma)=28:04-io=4lanes*(beta,channel,offset,value,is-write)=20:05-der=4lanes*(tuple12-then-byte-lookup)=52:06-sha-word-memory=4lanes*(beta,address,value,is-write)=16:07-sha-word-base-fold=4:08-p256-value=4lanes*7=28:09-p256-cross=4lanes*4=16:10-p256-scalar=4lanes*5=20:11-p256-arithmetic-copy=4lanes*3=12:lane-major-within-each-family:one-private-opaque-main-post-base-capability:no-raw-constructor:bind-post-challenge-state-and-all272-canonical-challenges-into-each-local-transcript-before-aux-roots:no-caller-selected-binding".to_vec();
        fields[13] = b"byte-memory-permutation=complete|strict-der-segment=complete|projection-segment=complete|shared-current-next-deep-ali=complete|rfc5280-base-row-provider=complete|rfc5280-aggregate-and-eighteen-independent-output-role-products=complete|rfc5280-x5r1-and-der-terminal-validator=complete|sha-call-witness-assembly-and-terminal-binding=complete|p256-witness-assembly-and-terminal-binding=complete|compact-ca-subproof=complete|full-49-registration-prover-and-verifier=complete|combined-main-ca-envelope=complete|consensus-verifier-integration=complete|release-evidence-schema=deterministic-X5S1-KAT+public-binding-mutations+wire-corruption-and-truncation+maximum-shape-process-measurement|activation=unavailable-qualification".to_vec();
        fields[14] =
            hex::decode("307915059aa0f173351facf134c2c08df720e365cfdb96c239eca44c07b654bb")
                .unwrap();
        // These historical pins included the original 32 whole-segment totals
        // and 64 public RFC-stream products; restore their exact old descriptor.
        fields[17] = b"zk-x509-sha-call-bus-stark-v1-incompatible:29-fixed-capacity-calls=cert-tbs[3]+crl-tbs+framed-complete-signed-crl+projection[7]+issuer-spki+trust-record+policy-record+crl-record+compact-ca-leaf+compact-ca-node[12]:max-blocks616:word-rows1972128=compression655424+local-init232+local-digest232+memory1316240:four-log19-segments-whole-call-packed-active-rows480288,521952,521696,448192-no-cross-segment-call-transition:base89=word-capacity76+proof-bound-rfc-raw-length-bits13:aux78=word-capacity54+input-products4+digest-products4+rfc-consumer-products16:fixed118=word72+call-segment-length-control9+thirteen-verifier-one-hot-compact-ca-call-selectors+four-field-native-rfc-event-descriptors-of-width6:constraints796=prior588+thirteen-call-times-four-lanes-times-four-start-terminal-equalities208:degree6-including-fixed-selectors:polynomial-digest-address=digest*dynamic+(1-digest)*fixed:base-two-chunks-aux-two-chunks-per-segment:same-log-bucket-base356-aux312-base-chunks8-aux-chunks8:private-exact-length-unique-padding-transition-across-blocks-and-active-block-prefix:fine-grained-message-cap-and-fixed-role-length-enforcement:frozen-canonical-inactive-computation-memory-and-mask-suffix:selected-digest-from-unique-final-active-block:inactive-chain-and-projection-slots-canonical-sha-empty-dummy:address=(call,role,slot,input-or-digest,word):four-independent-domain-separated-goldilocks-lanes:separate-word-memory-and-call-challenge-families:segment-continuous-source-digest-and-rfc-products-with-registration-owned-terminals:cyclic-physical-padding-recurrence=1-segment-last-padding:padding-base-and-aux=zero:word-capacity-recurrence=local-compute+digest+memory-call-last:compact-ca-calls16through28-each-bind-proof-carried-source-and-digest-start-and-terminal-products-by-verifier-fixed-one-hot-selectors-without-division:rfc-consumer-products-derived-algebraically-from-committed-message-bits-masks-and-verifier-fixed-event-descriptors:four-byte-streams-total-degree5-recurrences-including-fixed-selectors:proof-bound-u64-raw-length-consumers:certificate-tbs-crl-tbs-framed-complete-crl-and-framed-issuer-spki-channels:three-governance-self-digests-explicit-sha-field-frames:no-host-branch-on-opened-fixed-columns:main-common-lde-log22:protocol2-independent-per-lane-fri-mask-oracles:max-encoded-sha-proof2836064:stream-one-call-at-a-time:on-demand-full-row-widening-without-duplicated-aux-or-fixed-vectors".to_vec();
        // These rejection fixtures predate the selected-input writer multiplicities.
        // Freeze both the descriptor and its exact original schedule digest;
        // inheriting either current field would manufacture a mixed profile.
        fields[27] = b"zk-x509-p256-fixed-algebraic-v1-incompatible:native-log19:generator-coset-lde-log22:width404:six-schedules=certificate-arithmetic134+wallet-arithmetic134+certificate-execution46+wallet-execution46+certificate-sorted22+wallet-sorted22:typed-composite-children=134,134,46,46,22,22:each-child-generic-cap65536:composite-digest=sha3-384-opaque48-binds-profile+ordered-widths+ordered-child-digests:row-major-child-opening-concatenation:aliases-exactly15=signatures0through4-times-arithmetic0+value-execution0+value-sorted1:signatures0through3-certificate-role:signature4-wallet-role:closed-value-free-topology-only:additive-affine+repeated-affine+sparse:operation-metadata-plan=min-exact-row-axis-vs-canonical-call-axis:row-axis-on-tie:call-segments=14x43+64x222+row-tail18:sorted-active-factors=725504-distinct-from-execution-logical-factors949312:sorted-equal-read-runs=min-exact-relative-factor-axis-vs-per-value-axis:relative-factor-axis-on-tie:sorted-whole-plan=min-exact-global-local-vs-phase-hybrid:global-local-on-tie:phase-hybrid=prefix893-local+min-local-vs13x43-phase+scalar-boundary222-local+min-local-vs63x222-phase+tail18-local:pinned-boundary-extents=1712,9984:pinned-repeated-extents=1888,10176:local-on-phase-tie:no-native-matrix:no-lde-table:no-artifact:no-merkle:no-proof-fixed-bytes:first-release".to_vec();
        fields[28] = hex::decode(
            "27920427fcfec454c4454b1af2035f3b0af4dcadfeafb6c6824f93478217fc9a3107137c5eac8eacb141fe8e72d1384d",
        )
        .unwrap();
    }
    #[test]
    fn retired_profile_restoration_freezes_pre_aux_sha_and_p256_manifest_fields() {
        let sha_digests = [[0x51; 48]; SHA_DISCLOSURE_SHAPE_COUNT_V1];
        let p256_digest = [0x61; 48];
        let fields = compiled_profile_fields_v1(&sha_digests, &p256_digest);
        let mut canonical = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        let mut substituted = canonical.clone();
        substituted[12] = b"substituted-current-pre-aux-descriptor".to_vec();
        substituted[17] = b"substituted-current-sha-call-descriptor".to_vec();
        substituted[27] = b"substituted-current-p256-descriptor".to_vec();
        substituted[28] = vec![0x91; 48];
        restore_retired_public_terminal_profile_descriptors_v1(&mut canonical);
        restore_retired_public_terminal_profile_descriptors_v1(&mut substituted);
        assert_eq!(substituted, canonical);
        assert_eq!(canonical[28].len(), 48);
        for (field, (retired, current)) in canonical.iter().zip(fields).enumerate() {
            if ![9, 10, 12, 13, 14, 17, 27, 28].contains(&field) {
                assert_eq!(retired, current);
            }
        }
    }
    #[test]
    fn compiled_profile_binds_private_terminal_closure() {
        let (sha, p256) = compiled_profile_schedule_digests_v1().unwrap();
        let fields = compiled_profile_fields_v1(&sha, &p256);
        let profile = core::str::from_utf8(fields[9]).unwrap();
        assert!(profile.contains("main-public-terminal-records=0|ca-public-terminal-records=0"));
        assert!(
            profile.contains("main-frame-bytes=1002-includes992-key-DEEP-values|ca-frame-bytes=10")
        );
        assert!(profile.contains("main-key-byte-joins=12-blocks647-equalities-rfc-to-io-and-real-p256-root-powers2,8-max-quotient-degree538744|main-sha-digest-joins=5-blocks40-u32-equalities-unreduced-be-four-byte-real-p256-root-power32-max-quotient-degree2155224"));
        assert!(profile.contains(
            "MAIN31-key-and-digest:5-power8+6-power2+20-power32+MAIN24-translated-aux+CA108-translated-aux"
        ));
        assert!(profile.contains("max-encoded-combined-bound=9412944"));
        assert!(profile.contains("main-sha-rfc-private-union=16-constant-native-bridges+16-segment-quartic-links+4-role-quartic-links-original-masks-existing-aux-DEEP-no-extra-openings-degree2104411"));
        assert!(profile.contains("max-proof-bytes=9437184"));
        assert!(profile.contains("quotient-chunk-stride=fri-degree-cap-minus137"));
        assert!(profile.contains(
            "quotient-chunk-masks=137-independent-fp4-coefficients-adjacent-cancellation"
        ));
        assert!(profile.contains("main-quotient-mask-order=all-local-and-private-link-contributions-then-blind-before-root"));
        assert!(
            profile.contains(
                "private-der-rfc-source-and-p256-terminal-scalars=364-committed-air-only"
            )
        );
        assert!(
            core::str::from_utf8(fields[10])
                .unwrap()
                .contains("no-unmasked-der-rfc-source-or-p256-terminal-scalars")
        );
        let components = core::str::from_utf8(fields[13]).unwrap();
        assert!(
            components
                .contains("rfc5280-private-source-and-CA-original-polynomial-air-links=complete")
        );
        assert!(components.contains("private-committed-terminal-air-links=complete"));
    }
    #[test]
    fn compiled_profile_rejects_retired_public_terminal_exposure() {
        let (sha, p256) = compiled_profile_schedule_digests_v1().unwrap();
        let fields = compiled_profile_fields_v1(&sha, &p256);
        let mut retired = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        restore_retired_public_terminal_profile_descriptors_v1(&mut retired);
        let retired_fields = retired.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let old_digest = independent_compiled_profile_digest_v1(&retired_fields);
        assert_eq!(
            hex::encode(old_digest),
            "0312a22aad46561f42f28831baff280a072f34899284e354938c09a82e7adcdf"
        );
        assert_ne!(
            old_digest,
            recompute_zk_x509_compiled_profile_digest_v1().unwrap()
        );
        assert_ne!(Some(old_digest), ZK_X509_COMPILED_PROFILE_DIGEST_V1);
        let mut supplied = super::super::stark::construct_zk_x509_main_verifier_profile_v1()
            .expect("current verifier profile");
        supplied.compiled_profile_digest = old_digest;
        assert!(super::super::stark::validate_zk_x509_main_verifier_profile_v1(supplied).is_err());
    }
    #[test]
    fn compiled_profile_rejects_the_superseded_sha_padding_descriptor() {
        let (sha, p256) = compiled_profile_schedule_digests_v1().unwrap();
        let fields = compiled_profile_fields_v1(&sha, &p256);
        let mut superseded = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        restore_retired_public_terminal_profile_descriptors_v1(&mut superseded);
        let current = core::str::from_utf8(&superseded[17]).unwrap().to_owned();
        let word_boundary = "word-capacity-recurrence=local-compute+digest+memory-call-last:";
        let bus_boundary =
            "cyclic-physical-padding-recurrence=1-segment-last-padding:padding-base-and-aux=zero:";
        assert_eq!(current.matches(word_boundary).count(), 1);
        assert_eq!(current.matches(bus_boundary).count(), 1);
        // Historical SHA-padding profiles also used the retired compact-CA
        // descriptor. Preserve their exact original digests and rejection tests.
        superseded[14] =
            hex::decode("9a34a72f020551e65442c24b58ee075f6c485e36e0df7c579b246b19d0195b9a")
                .unwrap();
        for (descriptor, expected_digest) in [
            (
                current.clone(),
                "19aa35927ebc6e0ff800a0c80b6b315c2615350f35c82afdb9eae609d4c9ca9c",
            ),
            (
                current.replace(word_boundary, ""),
                "9d2d34512de90d13a0f68d352bbcc887ba9ac2f2a89e5deb845ff5c4c64d45ff",
            ),
            (
                current.replace(word_boundary, "").replace(bus_boundary, ""),
                "f82e78a995ce1b9ca1e91628901e9acd9b01a6841c13e062e30ad6dfdf028795",
            ),
        ] {
            superseded[17] = descriptor.into_bytes();
            let old_fields = superseded.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let old_digest = independent_compiled_profile_digest_v1(&old_fields);
            assert_eq!(hex::encode(old_digest), expected_digest);
            assert_ne!(Some(old_digest), ZK_X509_COMPILED_PROFILE_DIGEST_V1);
            assert_ne!(
                construct_zk_x509_compiled_profile_v1().unwrap().digest(),
                old_digest
            );
            let mut supplied = super::super::stark::construct_zk_x509_main_verifier_profile_v1()
                .expect("current verifier profile");
            supplied.compiled_profile_digest = old_digest;
            assert!(
                super::super::stark::validate_zk_x509_main_verifier_profile_v1(supplied).is_err()
            );
        }
    }
    #[test]
    fn compiled_profile_rejects_retired_enterprise_eku_identifiers() {
        let (sha, p256) = compiled_profile_schedule_digests_v1().unwrap();
        let fields = compiled_profile_fields_v1(&sha, &p256);
        let mut predecessor = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        let descriptor = core::str::from_utf8(&predecessor[9]).unwrap();
        let marker = "-eku-canonical-profile-uuid-oids";
        assert_eq!(descriptor.matches(marker).count(), 1);
        predecessor[9] = descriptor.replace(marker, "").into_bytes();
        let borrowed = predecessor.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let old_digest = independent_compiled_profile_digest_v1(&borrowed);
        // All 29 predecessor fields were emitted by the frozen fd0a8 native
        // constructor; this is its authentic profile, not a fabricated pin.
        assert_eq!(
            hex::encode(old_digest),
            "c095101f36ac92550ae15df711d2a1fff126b7540e65922ab18a34d5691ae688"
        );
        assert_ne!(
            old_digest,
            recompute_zk_x509_compiled_profile_digest_v1().unwrap()
        );
        assert_ne!(Some(old_digest), ZK_X509_COMPILED_PROFILE_DIGEST_V1);
        let mut supplied = super::super::stark::construct_zk_x509_main_verifier_profile_v1()
            .expect("current verifier profile");
        supplied.compiled_profile_digest = old_digest;
        assert!(super::super::stark::validate_zk_x509_main_verifier_profile_v1(supplied).is_err());
    }
    #[test]
    fn compiled_profile_rejects_ungated_rfc_root_helper_descriptor() {
        let (sha, p256) = compiled_profile_schedule_digests_v1().unwrap();
        let fields = compiled_profile_fields_v1(&sha, &p256);
        let mut predecessor = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        let descriptor = core::str::from_utf8(&predecessor[9]).unwrap();
        let marker = "source-node-root-kind-active-gated-helper-";
        assert_eq!(descriptor.matches(marker).count(), 1);
        let current_without_gate = descriptor.replace(marker, "").into_bytes();
        // Freeze the exact native predecessor descriptor. Stripping only this
        // marker from later RFC closures would manufacture a different profile.
        predecessor[9] = b"proof-instance=required-public32-after-version-count-before-consensus-context:checked-disjoint-entropy-before-first-commitment:all-zero-canonical|dynamic-hash-profile-suffix=00-X5I1-family-u8-nonce32:joint0-main1-ca2:all-commitments-and-transcript-operations:fixed-compiler-metadata-unscoped|field=goldilocks-fp4:w4=7:base=0xffffffff00000001|wire=X5S1-containing-main24-ca108-joint-original-openings-and-exactly-one-X5M1-and-one-X5C1-v1|x5m1=version1+31-original-key-DEEP-values+length-delimited-aggregate-no-fixed-sidecar|main-public-terminal-records=0|ca-public-terminal-records=0|main-frame-bytes=1002-includes992-key-DEEP-values|ca-frame-bytes=10|joint-openings=132-canonical-Fp4-values4224|ca-private-endpoint-links=108-original-polynomial-quotients-MAIN-composition|private-der-rfc-source-and-p256-terminal-scalars=364-committed-air-only|main-private-endpoint-links=192-linear-quotients-original-masks-shared-native-points|main-key-byte-joins=12-blocks647-equalities-rfc-to-io-and-real-p256-root-powers2,8-max-quotient-degree538744|main-sha-digest-joins=5-blocks40-u32-equalities-unreduced-be-four-byte-real-p256-root-power32-max-quotient-degree2155224|main-sha-rfc-private-union=16-constant-native-bridges+16-segment-quartic-links+4-role-quartic-links-original-masks-existing-aux-DEEP-no-extra-openings-degree2104411|main-link-alpha-order=local-component-history+both-original-aux-roots+fresh-local-alphas+192-ordered-private-endpoint-link-descriptors+endpoint-link-alphas+17-key-and-digest-join-descriptors+key-and-digest-alphas+20-private-sha-union-descriptors+sha-union-alphas+108-ordered-CA-private-link-descriptors+CA-link-alphas|main-logical-registrations=49|main-same-log-trace-groups=6-logs5,8,15,16,18,19|main-physical-roots=one-joined-base-and-one-joined-aux|main-physical-commitment-chunks=80|physical-chunk-columns=64|max-native-trace-log2=19|compact-ca-dedicated-log12-subproof-depth12|sha-fixed-calls=29-across-four-log19-slices|p256-binding-sink-degree=3-including-fixed-selectors|sha-capacity-and-call-degree=6-including-fixed-selectors|sha-digest-address=polynomial-select|sha-fixed-algebraic-width=472-verifier-derived-no-proof-bytes|p256-log19-fixed-algebraic-width=404-six-role-schedules-alias-fifteen-registrations-verifier-derived-no-proof-bytes|fixed-polynomials=verifier-derived-at-deep-and-native-translates|shared-x5b1-challenges=single-joined-main-base-root+ca-base-root+main-and-ca-public-profile+exact272-fields-ordered-sha-call,rfc,projection,io,der,sha-word-memory,sha-word-base-fold,p256-value,p256-cross,p256-scalar,p256-arithmetic-copy+one-opaque-main-post-base-token|main-io=statement-only-exact40+5d-declarations+logical55922+4736d-active-rows+fixed-capacity262144|main-trace-hiding-coefficients=1816|ca-trace-hiding-coefficients=2100|fri-mask-oracles=1-fp4-per-subproof-roots-before-batching|lde-column-batch=8|max-constraint-degree=7|fri-rate=9over64|main-fri-blowup=8|ca-lde-log2=16|fri-queries=136-distinct-without-replacement|composition-fp4-lanes=1|quotient-chunk-stride=fri-degree-cap-minus137|quotient-chunk-masks=137-independent-fp4-coefficients-adjacent-cancellation|main-quotient-mask-order=all-local-and-private-link-contributions-then-blind-before-root|fri-batching-m=3|binary-fold-arity=2|fri-folding=2|fri-leaves=ordered-low-high-pairs|main-fri-terminal-length=1024-degree143|ca-fri-terminal-length=1024-degree143|deep-points=one-joint-point-after-both-original-aux-composition-and-FRI-mask-roots:both-local-checkpoints-bound:current+next+MAIN31-key-and-digest:5-power8+6-power2+20-power32+MAIN24-translated-aux+CA108-translated-aux:combined-domain-admission:both-local-DEEP-and-MAIN31-then-ordered132-values-bound-before-independent-local-mixes|ca-deep-constraints=all1363-fp4-verifier-fixed-polynomials-current-only-query-rows|main-deep-constraints=all49-fp4-native-vanishing-six-chunk-recomposition-verifier-fixed-polynomials-current-only-query-rows|grinding-bits=20|target-soundness-bits=128|rfc5280-temporal-air=base285-aux280-fixed147-constraints1941-degree4-five-key-and-five-complete-spki-outputs-der-node-byte-lookups-key-length66-offset1-spki-content89-total91-offset0-nine-variable-tbs-crl-signature-byte-and-canonical-u16-in-eight-byte-big-endian-length-pairs-live-prefix-count-node-continuity-source-start-helper-projection-leaf-serial-magnitude-sign-octet-nonzero-first-byte-big-endian-length-selected-original-subject-oid-value-provenance-with-complete-name-oid-census-three-original-classes-disjoint-document-stride12-keys1through48-six-bit-positive-gaps-uniqueness-nonempty-bounded-rdns-and-complete-original-value-census-country-printable-utf8-dfa-output-metadata-six-verifier-fixed-equations-authenticated72-times-73-relations-38bit-slack-affine-loglookup-39-relations|rbr-budget-bits=157|joint-configuration-bound=8-per-domain,64-paired|joint-point-exclusion-bound=3277643777|joint-cleared-degree-bounds=19398656,40960|joint-algebraic-error-bits=219|base-collision-configuration-factor=64|random-oracle-kappa=256|max-ro-queries-log2=64|max-encoded-combined-bound=9412944|max-proof-bytes=9437184|peak-memory-ceiling-bytes=12884901888|address-space-ceiling-bytes=34359738368|prover-target-seconds=300|release-evidence-schema=deterministic-X5S1-KAT+public-binding-mutations+wire-corruption-and-truncation+maximum-shape-process-measurement|shared-stark-v1=q136-blowup8-digest384-fp4-blocked-pending-independent-qualification|activation=unavailable".to_vec();
        let borrowed = predecessor.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let old_digest = independent_compiled_profile_digest_v1(&borrowed);
        assert_eq!(
            hex::encode(old_digest),
            "294649842da2b565e94b022ce59c7a7c662aa2bf70502d8a554abb510d487852"
        );
        assert_ne!(
            old_digest,
            recompute_zk_x509_compiled_profile_digest_v1().unwrap()
        );
        // Also reject the current relation with just its activity-gate marker
        // removed; this distinct mutation must not replace the historical pin.
        let mut ungated_current = fields
            .iter()
            .map(|field| field.to_vec())
            .collect::<Vec<_>>();
        ungated_current[9] = current_without_gate;
        let current_fields = ungated_current
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let current_mutation_digest = independent_compiled_profile_digest_v1(&current_fields);
        assert_ne!(
            current_mutation_digest,
            recompute_zk_x509_compiled_profile_digest_v1().unwrap()
        );
        for rejected_digest in [old_digest, current_mutation_digest] {
            let mut supplied = super::super::stark::construct_zk_x509_main_verifier_profile_v1()
                .expect("current verifier profile");
            supplied.compiled_profile_digest = rejected_digest;
            assert!(
                super::super::stark::validate_zk_x509_main_verifier_profile_v1(supplied).is_err()
            );
        }
    }
    /// Record forbidden entropy reads while rejecting every request immediately.
    #[derive(Default)]
    struct PreflightEntropyV1 {
        requests: usize,
    }
    impl rand::TryRngCore for PreflightEntropyV1 {
        type Error = &'static str;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.requests += 1;
            Err("preflight must not request entropy")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.requests += 1;
            Err("preflight must not request entropy")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            self.requests += 1;
            Err("preflight must not request entropy")
        }
    }
    impl rand::TryCryptoRng for PreflightEntropyV1 {}

    #[test]
    fn credential_prover_rejects_profile_or_genesis_before_entropy() {
        let fixture = super::super::relation::release_fixture::build_zk_x509_reference_fixture_v1()
            .expect("canonical reference fixture");
        let mut rng = PreflightEntropyV1::default();
        let error = prove_zk_x509_credential_proof_v1_with_rng(
            &fixture.statement,
            &fixture.authoritative_state,
            fixture.statement.presentation_not_before_unix_seconds * 1_000,
            &PrivacyConsensusLimitsV1::taira_default(),
            [0; 32],
            &[],
            &mut rng,
        )
        .expect_err("invalid genesis must not reach credential proof construction");
        assert_eq!(
            error,
            ZkX509EngineErrorV1::CredentialProof(ZkX509CredentialProofErrorV1::InvalidStatement)
        );
        assert_eq!(rng.requests, 0, "credential preflight consumed entropy");
    }

    #[test]
    fn credential_prover_accepts_geometry_but_rejects_invalid_witness_before_entropy() {
        super::super::stark::validate_zk_x509_main_proof_budget_v1()
            .expect("complete MAIN and CA wire fits the unchanged credential budget");
        let fixture = super::super::relation::release_fixture::build_zk_x509_reference_fixture_v1()
            .expect("canonical reference fixture");
        let mut rng = PreflightEntropyV1::default();
        let error = prove_zk_x509_credential_proof_v1_with_rng(
            &fixture.statement,
            &fixture.authoritative_state,
            fixture.statement.presentation_not_before_unix_seconds * 1_000,
            &PrivacyConsensusLimitsV1::taira_default(),
            *fixture.statement.context.network_id.as_bytes(),
            &[],
            &mut rng,
        )
        .expect_err("invalid witness must reject before proof construction or entropy");
        assert_eq!(
            error,
            ZkX509EngineErrorV1::WitnessCodec(ZkX509WitnessCodecErrorV1::Truncated)
        );
        assert_eq!(rng.requests, 0);
    }

    #[test]
    fn sole_profile_is_pinned_while_release_activation_stays_unavailable() {
        assert!(ZK_X509_COMPILED_PROFILE_DIGEST_V1.is_some());
        assert!(
            String::from_utf8_lossy(ZK_X509_AIR_COMPONENT_DESCRIPTOR_V1)
                .ends_with("activation=unavailable-qualification")
        );
    }
    #[test]
    fn consensus_entry_point_cannot_bypass_engine_unavailability() {
        let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
        assert_eq!(
            crate::privacy_profiles::compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
    }
    #[test]
    fn credential_prover_has_one_preflighted_joint_root_path_and_no_subproof_escape() {
        let source = include_str!("engine.rs");
        // Search only production text: an obsolete signature must not match
        // this test's own search literal and inspect the assertions themselves.
        let production_source = &source[..source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("test module")];
        let prover_start = production_source
            .find("pub fn prove_zk_x509_credential_proof_v1_with_rng")
            .expect("sole credential prover");
        let prover_end = production_source[prover_start..]
            .find("fn compiled_profile_fields_v1")
            .map(|offset| prover_start + offset)
            .expect("sole credential prover end");
        let prover = &production_source[prover_start..prover_end];
        let quarantine = prover
            .find("goldilocks_transform_completion_uncertain_v1()")
            .expect("quarantine before construction or entropy");
        let profile_gate = prover
            .find("construct_zk_x509_compiled_profile_v1()")
            .expect("pinned profile validation");
        let preparation = prover
            .find("prepare_zk_x509_prover_input_v1(")
            .expect("canonical witness preparation");
        let assembly = prover
            .find("build_zk_x509_main_trace_assembly_v1(")
            .expect("canonical MAIN assembly");
        let entropy = prover
            .find("HealthCheckedTryCryptoRngV1::new(rng)")
            .expect("health-checked entropy");
        let nonce = prover
            .find("ZkX509ProofInstanceV1::sample_v1(&mut checked_rng)")
            .expect("disjoint public nonce before private masks");
        let main_base = prover
            .find("commit_zk_x509_main_base_phase_v1_with_rng(")
            .expect("joined MAIN base root");
        let ca = prover
            .find("commit_ca_through_auxiliary_v1(")
            .expect("original compact-CA auxiliary phase");
        let joint_binding = prover
            .find(".bind_joint_credential_pre_aux_v1_with_rng(")
            .expect("joint MAIN and CA root X5B1 with retained owner admission");
        let main_aux = prover
            .find("finish_joint_main_ca_v1(")
            .expect("paired original MAIN and CA composition/DEEP/FRI");
        let envelope = prover
            .find("encode_zk_x509_credential_envelope_v1(")
            .expect("X5S1 envelope");
        let self_check = prover
            .find("verify_zk_x509_credential_subproofs_v1(")
            .expect("independent final self-check");
        assert!(quarantine < profile_gate);
        assert!(
            profile_gate < preparation
                && preparation < assembly
                && assembly < entropy
                && entropy < nonce
                && nonce < main_base
                && main_base < ca
                && ca < joint_binding
                && joint_binding < main_aux
                && main_aux < envelope
                && envelope < self_check
        );
        for forbidden in [
            "verify_reference",
            "accept_main_subproof",
            "accept_ca_subproof",
            "ConsensusVerifierUnavailable",
            "require_complete_zk_x509_air_v1",
            "after_release_gate",
            "zk_x509_air_gaps_v1",
            "OsRng",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "credential prover must not contain {forbidden}"
            );
        }
        let protocol_id = PrivacyProtocolIdV1::IrohaZkX509StarkP256V1;
        assert_eq!(
            crate::privacy_profiles::compiled_privacy_profile_v1(protocol_id),
            Err(
                crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                    protocol_id,
                }
            )
        );
    }
}

#[cfg(test)]
#[path = "engine_prover_diagnostic.rs"]
pub(super) mod prover_diagnostic;
