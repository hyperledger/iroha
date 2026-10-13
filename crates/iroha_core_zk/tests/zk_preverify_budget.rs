#![doc = "Unit tests for pre-verify budget handling."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! Unit tests for pre-verify budget handling.
#![cfg(feature = "zk-preverify")]
use iroha_core_zk::{DedupCache, PreverifyResult, preverify_with_budget};
use iroha_data_model::proof::ProofBox;
#[test]
fn budget_exceeded_for_large_input_vs_budget() {
    let mut d = DedupCache::new();
    let proof = ProofBox::new("halo2/ipa".into(), vec![1u8; 64]);
    // Provide an unrealistically small budget so that we hit the branch deterministically
    let res = preverify_with_budget(&proof, None, &mut d, 8, None, None, true)
        .expect("verification attempt must complete for this semantic fixture");
    assert!(matches!(res, PreverifyResult::PreverifyBudgetExceeded));
}
