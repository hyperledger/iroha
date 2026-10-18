//! Deterministic proposal-order execution test.

#![allow(clippy::items_after_statements)]
//! Independent account metadata events expose execution order. Ordinary network transactions
//! follow proposal position, and block results retain those positions after execution.
use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
use iroha_data_model::prelude::*;
use iroha_model_base::chain::ChainId;
fn build_world() -> (
    CertifiedTestChain,
    NetworkId,
    Vec<(AccountId, iroha_crypto::KeyPair)>,
) {
    let chain_id: ChainId = "chain".parse().unwrap();
    // Each universal account owns a separate metadata key, so the transactions do not conflict.
    let (a1, k1) = iroha_test_samples::gen_account_in("wonderland");
    let (a2, k2) = iroha_test_samples::gen_account_in("wonderland");
    let (a3, k3) = iroha_test_samples::gen_account_in("wonderland");
    let (a4, k4) = iroha_test_samples::gen_account_in("wonderland");
    let acc1 = Account::new(a1.clone()).build(&a1);
    let acc2 = Account::new(a2.clone()).build(&a1);
    let acc3 = Account::new(a3.clone()).build(&a1);
    let acc4 = Account::new(a4.clone()).build(&a1);
    let world = iroha_core::state::World::with([], [acc1, acc2, acc3, acc4], []);
    let mut config = TestChainConfig::new(world, 1000);
    config.chain_id = chain_id;
    let chain = CertifiedTestChain::start(config).unwrap();
    let network_id = chain.network_id();
    (
        chain,
        network_id,
        vec![(a1, k1), (a2, k2), (a3, k3), (a4, k4)],
    )
}
fn run_block(
    chain: &mut CertifiedTestChain,
    txs: Vec<SignedTransaction>,
) -> (SignedBlock, Vec<AccountId>) {
    let payload_hashes: Vec<_> = txs
        .iter()
        .map(SignedTransaction::hash_as_entrypoint)
        .collect();
    let proposal = chain.proposal(None, txs);
    let mut pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();
    let (block, execution_order) = pending
        .inspect(move |original| {
            let execution_order = original
                .state
                .world
                .take_external_events()
                .into_iter()
                .filter_map(|event| {
                    let EventBox::Data(event) = event else {
                        return None;
                    };
                    match event.as_ref() {
                        DataEvent::Account(AccountEvent::MetadataInserted(change)) => {
                            Some(change.target().clone())
                        }
                        _ => None,
                    }
                })
                .collect();
            assert_eq!(
                original
                    .block
                    .as_ref()
                    .network_input_hashes()
                    .collect::<Vec<_>>(),
                payload_hashes,
                "entrypoint hashes must preserve proposal order"
            );
            (original.block.as_ref().clone(), execution_order)
        })
        .unwrap();
    // This test observes execution only; the original unpublished overlay is discarded so
    // every permutation starts from exactly the same authenticated state.
    drop(pending);
    (block, execution_order)
}
fn independent_transactions(
    network_id: NetworkId,
    accs: &[(AccountId, iroha_crypto::KeyPair)],
) -> Vec<SignedTransaction> {
    accs.iter()
        .enumerate()
        .map(|(i, (aid, kp))| {
            TransactionBuilder::new(
                network_id,
                aid.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([SetKeyValue::account(
                aid.clone(),
                "scheduler_marker".parse().unwrap(),
                iroha_primitives::json::Json::new(format!("transaction-{i}")),
            )])
            .sign(kp.private_key())
        })
        .collect()
}
fn proposal_order(txs: &[SignedTransaction]) -> Vec<AccountId> {
    txs.iter().map(|tx| tx.authority().clone()).collect()
}
#[test]
fn ordinary_network_execution_follows_proposal_order() {
    let (mut chain, network_id, accs) = build_world();
    let txs = independent_transactions(network_id, &accs);
    // Each permutation is a distinct proposal order, irrespective of entrypoint hashes.
    let perms: Vec<Vec<usize>> = vec![
        vec![0, 1, 2, 3], // identity
        vec![3, 2, 1, 0], // reverse
        vec![1, 2, 3, 0], // rotate left 1
        vec![2, 3, 0, 1], // rotate left 2
        vec![0, 2, 1, 3], // swap middle
    ];
    for p in perms {
        let permuted_txs: Vec<_> = p.iter().map(|&i| txs[i].clone()).collect();
        let expected = proposal_order(&permuted_txs);
        let (vb, got) = run_block(&mut chain, permuted_txs);
        assert_eq!(got, expected, "execution must follow proposal order");
        // All must be approved
        assert!((0..4).all(|index| {
            vb.network_output_at(index)
                .expect("validated transaction has an output")
                .1
                .result
                .as_ref()
                .is_ok()
        }));
    }
}
#[test]
fn ordinary_network_execution_follows_randomized_proposal_orders() {
    // Exercise many distinct proposal orders with a fixed, reproducible shuffle.
    let (mut chain, network_id, accs) = build_world();
    let txs = independent_transactions(network_id, &accs);
    // Deterministic LCG for shuffling
    #[derive(Clone)]
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next(&mut self) -> u64 {
            // Constants from Numerical Recipes
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            self.0
        }
    }
    fn shuffle<T: Clone>(rng: &mut Lcg, v: &[T]) -> Vec<T> {
        let mut out = v.to_vec();
        // Fisher–Yates using our LCG
        let n = out.len();
        for i in (1..n).rev() {
            let j = usize::try_from(rng.next()).unwrap() % (i + 1);
            out.swap(i, j);
        }
        out
    }
    // Exercise many randomized permutations with a fixed seed for reproducibility
    let mut rng = Lcg::new(0x00C0_FFEE);
    for _ in 0..64 {
        let permuted = shuffle(&mut rng, &txs);
        let expected = proposal_order(&permuted);
        let (vb, got) = run_block(&mut chain, permuted);
        assert_eq!(
            got, expected,
            "execution must follow each proposal's input order"
        );
        assert!((0..4).all(|index| {
            vb.network_output_at(index)
                .expect("validated transaction has an output")
                .1
                .result
                .as_ref()
                .is_ok()
        }));
    }
}

#[test]
fn scheduler_results_preserve_payload_indices_after_reordering() {
    let (mut chain, network_id, accs) = build_world();
    let mut txs = independent_transactions(network_id, &accs);
    let (authority, keypair) = &accs[0];
    txs[0] = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([RemoveKeyValue::account(
        authority.clone(),
        "missing".parse().unwrap(),
    )])
    .sign(keypair.private_key());
    let rejected_hash = txs[0].hash_as_entrypoint();

    // Descending hashes show that ordinary execution follows proposal position,
    // including when hash priority would choose the reverse order.
    txs.sort_by_key(|tx| std::cmp::Reverse(tx.hash_as_entrypoint()));
    for _ in 0..txs.len() {
        let expected: Vec<_> = txs
            .iter()
            .filter(|tx| tx.hash_as_entrypoint() != rejected_hash)
            .map(|tx| tx.authority().clone())
            .collect();
        let (block, execution_order) = run_block(&mut chain, txs.clone());
        assert_eq!(execution_order, expected);
        assert_eq!(block.execution_outputs().len(), txs.len());
        for (index, tx) in txs.iter().enumerate() {
            let result = &block
                .network_output_at(u32::try_from(index).expect("input index fits u32"))
                .expect("validated transaction has an output")
                .1
                .result;
            assert_eq!(
                result.as_ref().is_err(),
                tx.hash_as_entrypoint() == rejected_hash,
                "a transaction result must remain attached to its payload index"
            );
        }
        txs.rotate_left(1);
    }
}
