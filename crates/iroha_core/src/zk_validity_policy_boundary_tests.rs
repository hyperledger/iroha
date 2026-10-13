//! Boundary tests of the committed ZK proof and work limits.
//!
//! Each limit is exercised at exactly its committed value and one unit above
//! it, through the State transition that enforces it, on a node that holds the
//! default settings and on a node that holds divergent ones. The committed
//! value decides on both.

use std::num::NonZeroU64;

use iroha_config::parameters::actual::Zk;
use iroha_data_model::{block::BlockHeader, parameter::Parameter, proof::ProofBox};

use super::{ZkValidityPolicyV1, policy_of};
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, default_zk_config},
};

/// Settings a node may not decide: every limit exercised here is set to a
/// value that would reject the at-limit case or admit the over-limit case.
fn divergent_node_zk(loose: bool) -> Zk {
    let mut node = default_zk_config();
    let value = if loose { 1_000_000 } else { 1 };
    node.max_nullifiers_per_tx = value;
    node.max_commitments_per_tx = value;
    node.max_verify_calls_per_tx = value;
    node.max_verify_calls_per_block = value;
    node.max_confidential_ops_per_block = value;
    node.max_proof_size_bytes = value;
    node.max_proof_bytes_block = u64::from(value);
    node.preverify_max_bytes = usize::try_from(value).expect("fits usize");
    node.preverify_budget_bytes = u64::from(value);
    node.max_verify_batch = if loose { 30 } else { 1 };
    node
}

fn state_with(node: Option<Zk>, policy: &ZkValidityPolicyV1) -> State {
    let world = World::default();
    {
        let mut block = world.block();
        block
            .parameters
            .get_mut()
            .set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()))
            .expect("valid fixture parameters");
        block.commit();
    }
    let mut state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    if let Some(node) = node {
        state
            .install_node_zk(node)
            .expect("node ZK resources install");
    }
    state
}

fn header() -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(2).expect("nonzero"), None, None, 0, 0)
}

/// Every node configuration the committed limit must be indifferent to.
fn nodes() -> [Option<Zk>; 3] {
    [
        None,
        Some(divergent_node_zk(false)),
        Some(divergent_node_zk(true)),
    ]
}

#[test]
fn nullifiers_per_transaction_accept_the_committed_limit_and_reject_one_more() {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_nullifiers_per_tx = 5;
    for node in nodes() {
        let state = state_with(node, &policy);
        let mut block = state.block(header());
        let mut at_limit = block.transaction();
        at_limit.register_nullifiers(3).expect("three of five");
        at_limit
            .register_nullifiers(2)
            .expect("exactly the committed limit is accepted");
        let error = at_limit
            .register_nullifiers(1)
            .expect_err("one nullifier above the committed limit is rejected");
        assert!(
            format!("{error:?}").contains("nullifiers per transaction cap exceeded"),
            "{error:?}"
        );
        drop(at_limit);
        let mut over = block.transaction();
        over.register_nullifiers(6)
            .expect_err("limit plus one in a single step is rejected");
    }
}

#[test]
fn commitments_per_transaction_accept_the_committed_limit_and_reject_one_more() {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_commitments_per_tx = 4;
    for node in nodes() {
        let state = state_with(node, &policy);
        let mut block = state.block(header());
        let mut at_limit = block.transaction();
        at_limit
            .register_commitments(4)
            .expect("exactly the committed limit is accepted");
        let error = at_limit
            .register_commitments(1)
            .expect_err("one commitment above the committed limit is rejected");
        assert!(
            format!("{error:?}").contains("commitments per transaction cap exceeded"),
            "{error:?}"
        );
        drop(at_limit);
        let mut over = block.transaction();
        over.register_commitments(5)
            .expect_err("limit plus one in a single step is rejected");
    }
}

#[test]
fn proof_size_accepts_the_committed_limit_and_rejects_one_byte_more() {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_proof_size_bytes = 4_096;
    for node in nodes() {
        let state = state_with(node, &policy);
        let mut block = state.block(header());
        let mut transaction = block.transaction();
        transaction
            .register_confidential_proof(4_096)
            .expect("a proof of exactly the committed size is accepted");
        let error = transaction
            .register_confidential_proof(4_097)
            .expect_err("one byte above the committed size is rejected");
        assert!(
            format!("{error:?}").contains("confidential proof exceeds max_proof_size_bytes"),
            "{error:?}"
        );
    }
}

#[test]
fn verify_calls_accept_the_committed_limits_and_reject_one_more() {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_verify_calls_per_tx = 2;
    policy.confidential.max_verify_calls_per_block = 3;
    for node in nodes() {
        let state = state_with(node, &policy);
        let mut block = state.block(header());
        // Per transaction: exactly two calls, the third is rejected.
        let mut first = block.transaction();
        first.register_confidential_proof(8).expect("first call");
        first
            .register_confidential_proof(8)
            .expect("exactly the committed per-transaction limit is accepted");
        let error = first
            .register_confidential_proof(8)
            .expect_err("one call above the per-transaction limit is rejected");
        assert!(
            format!("{error:?}").contains("confidential verify calls per transaction exceeded"),
            "{error:?}"
        );
        drop(first);
        // The block totals of the first transaction's accepted work, carried
        // as the production overlay path carries them.
        block.account_confidential_work_v1(2, 2, 16, 0);
        // Per block: the third call of the block is exactly the limit, the
        // fourth is rejected although its transaction made only two.
        let mut second = block.transaction();
        second
            .register_confidential_proof(8)
            .expect("exactly the committed per-block limit is accepted");
        let error = second
            .register_confidential_proof(8)
            .expect_err("one call above the per-block limit is rejected");
        assert!(
            format!("{error:?}").contains("confidential verify calls per block exceeded"),
            "{error:?}"
        );
    }
}

#[cfg(feature = "zk-preverify")]
#[test]
fn preverify_budget_and_size_accept_the_committed_limit_and_reject_one_byte_more() {
    use crate::zk::PreverifyResult;

    let proof = |len: usize| ProofBox::new("pipa-r/pasta".into(), vec![0x5A; len]);
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.proofs.preverify_max_bytes = 512;
    policy.proofs.preverify_budget_bytes = 64;
    let mut size_only = ZkValidityPolicyV1::protocol_default();
    size_only.proofs.preverify_max_bytes = 512;
    size_only.proofs.preverify_budget_bytes = 0;
    for node in nodes() {
        // Budget: a proof of exactly the budget is not refused by it; one
        // byte more is.
        let state = state_with(node.clone(), &policy);
        let mut block = state.block(header());
        let mut transaction = block.transaction();
        let at_budget = transaction
            .preverify_proof(&proof(64), None, 0, None, None, true)
            .expect("preverification policy verdict must complete");
        assert_ne!(at_budget, PreverifyResult::PreverifyBudgetExceeded);
        assert_ne!(at_budget, PreverifyResult::ProofTooBig);
        assert_eq!(
            transaction
                .preverify_proof(&proof(65), None, 0, None, None, true)
                .expect("preverification policy verdict must complete"),
            PreverifyResult::PreverifyBudgetExceeded
        );
        // Size: with the budget unlimited, exactly the maximum is not refused
        // for its size; one byte more is.
        let state = state_with(node, &size_only);
        let mut block = state.block(header());
        let mut transaction = block.transaction();
        let at_size = transaction
            .preverify_proof(&proof(512), None, 0, None, None, true)
            .expect("preverification policy verdict must complete");
        assert_ne!(at_size, PreverifyResult::ProofTooBig);
        assert_ne!(at_size, PreverifyResult::PreverifyBudgetExceeded);
        assert_eq!(
            transaction
                .preverify_proof(&proof(513), None, 0, None, None, true)
                .expect("preverification policy verdict must complete"),
            PreverifyResult::ProofTooBig
        );
    }
}

#[test]
fn every_node_reads_the_committed_limits_exercised_here() {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_nullifiers_per_tx = 5;
    policy.proofs.max_verify_batch = 11;
    for node in nodes() {
        let state = state_with(node, &policy);
        let block = state.block(header());
        assert_eq!(policy_of(&block.zk), policy);
        // The guardrails verification reads are projected from the same value.
        assert_eq!(block.zk.max_verify_batch, 11);
    }
}
