// Native publication retains the exact external membership of its original execution.
// Keep these selectors and their original hash/height assertions while retiring direct
// publication of caller-executed overlays. The complete four-seat fixture owns every QC.

state_test! { sync apply_without_execution_indexes_sealed_commitment_entrypoint_hash
    use crate::sumeragi::{
        payload::{self, Assembly},
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    };

    let (authority, keypair) = gen_account_in("wonderland");
    let domain = Domain::new(sample_domain_id()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(
        World::with([domain], [account], []),
        1_000,
    )).expect("apply the original signed four-validator genesis");
    let network_id = chain.network_id();
    let inner_tx = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    ).sign(keypair.private_key());
    let salt = [0x57; 32];
    let reveal_deadline_height = 3;
    let commitment = iroha_data_model::transaction::signed::compute_sealed_transaction_commitment(
        &network_id, &inner_tx, salt, reveal_deadline_height,
    );
    let payload = iroha_data_model::transaction::signed::SealedTransactionCommitmentPayload {
        network_id,
        authority,
        commitment,
        reveal_after_height: 3,
        reveal_deadline_height,
        nonce: None,
    };
    let entrypoint = TransactionEntrypoint::SealedCommitment(
        iroha_data_model::transaction::signed::SignedSealedTransactionCommitment::sign(
            payload, keypair.private_key(),
        ),
    );
    let entrypoint_hash = entrypoint.hash();
    let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(entrypoint));
    let parent = chain.committed(1);
    let cadence = {
        let view = chain.state().view();
        Duration::from_millis(view.world().consensus_schedule().ready(2)
            .expect("original genesis authorizes height two").params.block_time_ms)
    };
    // Assemble the exact sealed source and its routing from committed State before
    // any execution. No supplied output, result, witness or certificate grants trust.
    let proposal = payload::assemble(
        chain.state(),
        Assembly { parent: parent.block(), view: 0, cadence },
        &[accepted],
    ).expect("assemble the exact original sealed entrypoint");
    assert!(!proposal.has_results());
    assert_eq!(proposal.network_entrypoint_count(), 1);
    assert_eq!(proposal.network_entrypoint_at(0).unwrap().hash(), entrypoint_hash);
    assert!(!chain.state().has_committed_entrypoint(entrypoint_hash));
    let committed = chain.commit_proposal(proposal, Signers::Quorum, iroha_sumeragi::types::ControlWitness::default());
    assert_eq!(committed.block().network_entrypoint_count(), 1);
    assert_eq!(committed.block().network_entrypoint_at(0).unwrap().hash(), entrypoint_hash);
    assert!(committed.block().network_output_at(0).unwrap().1.result.is_ok());
    let state = chain.state();
    assert!(state.has_committed_entrypoint(entrypoint_hash));
    assert_eq!(
        state.committed_entrypoint_height(&entrypoint_hash),
        Some(nonzero!(2_usize))
    );
}

state_test! { sync apply_without_execution_keeps_plain_external_transaction_hashes
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

    let (authority, keypair) = gen_account_in("wonderland");
    let domain = Domain::new(sample_domain_id()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(
        World::with([domain], [account], []),
        1_000,
    )).expect("apply the original signed four-validator genesis");
    let tx = chain.sign(
        &keypair,
        [Log::new(Level::INFO, "external".to_owned()).into()],
        2_000,
    );
    let tx_hash = tx.hash_as_entrypoint();
    assert!(!chain.state().has_committed_entrypoint(tx_hash));
    assert_eq!(chain.commit(vec![tx]), [true]);
    let committed = chain.committed(2);
    assert_eq!(committed.block().network_entrypoint_count(), 1);
    assert_eq!(committed.block().network_entrypoint_at(0).unwrap().hash(), tx_hash);
    let state = chain.state();
    assert!(state.has_committed_entrypoint(tx_hash));
    assert_eq!(
        state.committed_entrypoint_height(&tx_hash),
        Some(nonzero!(2_usize))
    );
}
