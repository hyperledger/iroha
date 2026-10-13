//! Native confidential proof path for atomic cross-dataspace settlement.
//!
//! This module is deliberately separate from transparent DvP/PvP and from the
//! generic IVM private-note protocol. It reuses only the audited fixed note AIR
//! relation while owning distinct wire magic, transcript domains, public
//! manifest binding, exact two-input/three-output geometry, and wallet-local
//! witness types.

/// Hybrid-KEM audit capsules and canonical plaintext commitment.
pub mod audit;
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_fixtures;

mod facade;
mod relation;
mod stark;
mod wallet;

pub use facade::{
    AtomicPrivateSettlementProofErrorV1, prove_atomic_private_settlement_v1,
    prove_atomic_private_settlement_v1_with_rng, verify_atomic_private_settlement_v1,
};
#[doc(hidden)]
pub use relation::validate_audit_openings_v1;
pub use relation::{
    AtomicPrivateSettlementInputWitnessV1, AtomicPrivateSettlementProverWitnessV1,
    AtomicPrivateSettlementRelationErrorV1, atomic_private_settlement_audit_input_commitment_v1,
    atomic_private_settlement_dummy_input_memo_digest_v1,
    atomic_private_settlement_output_memo_digests_v1, atomic_private_settlement_program_id_v1,
};
#[cfg(test)]
pub use wallet::AtomicPrivateSettlementBootstrapPlanV1;
pub use wallet::{
    ATOMIC_PRIVATE_SETTLEMENT_WALLET_BUNDLE_MAX_BYTES_V1, AtomicPrivateSettlementInputSecretV1,
    AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementPreparedProofV1,
    AtomicPrivateSettlementProvisionalBundleV1, AtomicPrivateSettlementProvisionalLegInputV1,
    AtomicPrivateSettlementWalletErrorV1, AtomicPrivateSettlementWalletInspectionV1,
    complete_atomic_private_settlement_prepared_leg_v1,
    consume_atomic_private_settlement_wallet_bundle_v1,
    finalize_atomic_private_settlement_provisional_bundle_v1,
    inspect_atomic_private_settlement_wallet_bundle_v1,
};
#[cfg(any(test, feature = "test-utils"))]
pub use wallet::{
    derive_atomic_private_settlement_input_nullifiers_v1,
    encode_atomic_private_settlement_wallet_bundle_v1, plan_atomic_private_settlement_bootstrap_v1,
    prepare_atomic_private_settlement_funding_note_v1,
    prepare_atomic_private_settlement_input_openings_v1,
    prepare_atomic_private_settlement_outputs_v1,
};

/// Validate the closed settlement-only two-input/three-output proof profile.
///
/// This check is separate from the generic IVM private-note activation because
/// the public generic relation remains capped at two outputs. Settlement owns
/// a purpose-separated three-output relation, transcript, wire magic, and
/// governance/configuration gate while reusing the common proof machinery.
///
/// # Errors
///
/// Returns a redacted invariant failure if the compiled settlement profile is
/// inconsistent with the consensus-pinned proof geometry.
pub fn validate_atomic_private_settlement_profile_v1()
-> Result<(), AtomicPrivateSettlementProofErrorV1> {
    stark::validate_atomic_private_settlement_stark_profile_v1()
        .map_err(|_| AtomicPrivateSettlementProofErrorV1::ProverInvariant)
}
