#![doc = "Pre-verify deduplication tests for ZK attachments."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Unit tests for pre-verify dedup logic with optional `vk_commitment`.
#![cfg(feature = "zk-preverify")]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_core_zk::native_pipa_r::BACKEND as NATIVE_BACKEND;
use iroha_data_model::{block::BlockHeader, proof::ProofBox};
use nonzero_ext::nonzero;
fn open_verify_proof(vk_hash: [u8; 32]) -> ProofBox {
    iroha_core_zk::test_utils::native_framing_fixture_envelope(
        iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
        vk_hash,
    )
    .proof_box(NATIVE_BACKEND)
}
#[test]
fn preverify_state_wrapper_requires_bound_commitments_and_dedups() {
    // Build minimal state and block context
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let c1 = [0x11u8; 32];
    let proof = open_verify_proof(c1);
    let missing = stx.preverify_proof(&proof, None, 100_000, Some(c1), None, true);
    assert!(matches!(
        missing,
        iroha_core_zk::PreverifyResult::VerifyingKeyMissing
    ));
    let r1 = stx.preverify_proof(&proof, None, 100_000, None, Some(c1), true);
    assert!(matches!(r1, iroha_core_zk::PreverifyResult::Accepted));
    let r1_dup = stx.preverify_proof(&proof, None, 100_000, Some(c1), Some(c1), true);
    assert!(matches!(r1_dup, iroha_core_zk::PreverifyResult::Duplicate));
    let c2 = [0x22u8; 32];
    let mismatch = stx.preverify_proof(&proof, None, 100_000, Some(c2), Some(c1), true);
    assert!(matches!(
        mismatch,
        iroha_core_zk::PreverifyResult::VerifyingKeyMismatch
    ));
    let proof2 = open_verify_proof(c2);
    let r2 = stx.preverify_proof(&proof2, None, 100_000, Some(c2), Some(c2), true);
    assert!(matches!(r2, iroha_core_zk::PreverifyResult::Accepted));
}
