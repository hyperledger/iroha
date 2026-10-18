//! Native first-release private-note execution for `iroha-ivm-private-note-stark-v1`.
//!
//! The module has one closed profile:
//!
//! - a fixed, canonical private-program bytecode;
//! - SHA-256 framed note authorities, commitments, and nullifiers;
//! - membership in the ledger's exact depth-32 proof-managed SHA-256 tree;
//! - checked 128-bit value conservation;
//! - deterministic program execution; and
//! - a transparent Goldilocks STARK with SHA3-384 Merkle commitments and binary
//!   FRI whose public-input transcript commits the canonical statement and the
//!   exact typed chain, genesis, action, and governed-artifact consensus
//!   binding.
//!
//! Wallet witnesses never cross the ledger boundary. Verification returns only statement-derived
//! effects; in particular, no proof or caller can select a successor accumulator root.
//!
//! The native verifier and deterministic compiled profile are wired into typed runtime dispatch.
//! Compiling the profile does not create or activate a protocol lifecycle record; deployment still
//! requires explicit governed admission after the release gates pass. There is no legacy proof or
//! ciphertext codec.
mod air;
mod codec;
mod facade;
#[cfg(any(test, feature = "privacy-release-evidence"))]
mod fixture;
mod relation;
mod stark;
#[cfg(any(test, feature = "test-utils"))]
mod test_fixtures;
#[cfg(test)]
mod tests;
mod wallet;
pub(crate) use air::{
    IVM_PRIVATE_NOTE_AGGREGATE_AIR_DESCRIPTOR_V1, PRIVATE_NOTE_BASE_WIDTH_V1,
    PRIVATE_NOTE_TRACE_LOG2_V1,
};
pub(crate) use codec::PRIVATE_PROGRAM_BYTES_V1;
#[cfg(test)]
pub(crate) use codec::encode_private_program_v1;
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub use facade::verify_ivm_private_note_v1;
pub use facade::{
    IvmPrivateNoteProofErrorV1, prove_ivm_private_note_v1, prove_ivm_private_note_v1_with_rng,
};
#[cfg(feature = "privacy-release-evidence")]
#[doc(hidden)]
pub use fixture::{
    ivm_private_note_network_fixture_v1, ivm_private_note_release_fixture_v1,
    ivm_private_note_release_invalid_path_fixture_v1,
};
pub(crate) use relation::{
    IVM_PRIVATE_NOTE_ENGINE_DESCRIPTOR_V1, IVM_PRIVATE_NOTE_HASH_PROFILE_DESCRIPTOR_V1,
    PrivateNoteRelationProfileV1, derive_private_note_input_openings_commitment_v1,
    derive_profiled_input_commitment_v1, derive_profiled_output_commitment_v1,
    preflight_private_note_relation_with_profile_v1,
};
pub use relation::{
    IvmPrivateNoteInputWitnessV1, IvmPrivateNoteOutputWitnessV1, IvmPrivateNoteRelationErrorV1,
    IvmPrivateNoteWitnessV1, PRIVATE_NOTE_MAX_INPUTS_V1, PRIVATE_NOTE_MAX_OUTPUTS_V1,
    PRIVATE_NOTE_TREE_DEPTH_V1, PRIVATE_PROGRAM_INSTRUCTION_BYTES_V1,
    PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1, PRIVATE_PROGRAM_REGISTER_COUNT_V1, PrivateInstructionV1,
    PrivateNotePlaintextV1, PrivateOpcodeV1, PrivateProgramV1, derive_note_authority_v1,
    derive_note_commitment_v1, derive_note_nullifier_v1, derive_private_program_id_v1,
};
#[cfg(test)]
pub(crate) use relation::{
    accumulator_leaf_digest_for_testing_v1, accumulator_node_digest_for_testing_v1,
};
pub use stark::IVM_PRIVATE_NOTE_MAX_PROOF_BYTES_V1;
pub(crate) use stark::{
    IVM_PRIVATE_NOTE_STARK_PROFILE_DESCRIPTOR_V1, PRIVATE_NOTE_DOMAINS_V1,
    PRIVATE_NOTE_PROFILE_AUX_WIDTH_V1, PRIVATE_NOTE_PROFILE_CONSTRAINT_DEGREE_V1,
    PrivateNoteStarkRelationV1, validate_ivm_private_note_stark_profile_v1,
    verify_private_note_stark_v1,
};
#[cfg(test)]
pub use wallet::decrypt_ivm_private_wallet_note_v1;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub use wallet::encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1;
pub(crate) use wallet::validate_ivm_private_wallet_encryption_opening_v1;
pub use wallet::{
    IvmPrivateNoteWalletErrorV1, derive_ivm_private_recipient_id_v1,
    encrypt_ivm_private_wallet_note_v1, encrypt_ivm_private_wallet_note_with_os_rng_v1,
    ivm_private_recipient_public_key_v1, validate_ivm_private_encrypted_output_v1,
};
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn private_note_statement_fixture_v1() -> (
    iroha_data_model::privacy::IrohaIvmPrivateNoteStarkStatementV1,
    iroha_data_model::privacy::PrivacyCommitmentV1,
) {
    let fixture = test_fixtures::fixture();
    (fixture.statement, fixture.input_commitment)
}

pub(crate) use relation::derive_note_nullifier_for_namespace_v1;
