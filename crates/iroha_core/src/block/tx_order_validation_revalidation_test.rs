#[tokio::test]
async fn tx_order_same_in_validation_and_revalidation() {
    // Predefined world state
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("Valid");
    let account = Account::new(alice_id.clone()).build(&alice_id);
    let domain = Domain::new(domain_id).build(&alice_id);
    let (account_a_id, _) = gen_account_in("wonderland");
    let (second_account_id, _) = gen_account_in("wonderland");
    let world = World::with([domain], [account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_handle);
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    // Two independent register instructions (no ordering dependencies)
    let register_a = Register::account(Account::new(account_a_id));
    let register_b = Register::account(Account::new(second_account_id));
    let tx = TransactionBuilder::new(
        state.network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions::<InstructionBox>([register_a.into()])
    .sign(alice_keypair.private_key());
    let crypto_cfg = state.crypto();
    let (_clock, time_source) = TimeSource::new_mock(tx.creation_time());
    let tx = AcceptedTransaction::accept_with_time_source(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
        &time_source,
    )
    .expect("Valid");
    let (missing_account_id, _) = gen_account_in("wonderland");
    let fail_instruction = Unregister::account(missing_account_id);
    let succeed_instruction = register_b;
    let tx0 = TransactionBuilder::new(
        state.network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions::<InstructionBox>([fail_instruction.into()])
    .sign(alice_keypair.private_key());
    let (_clock, time_source) = TimeSource::new_mock(tx0.creation_time());
    let tx0 = AcceptedTransaction::accept_with_time_source(
        tx0,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
        &time_source,
    )
    .expect("Valid");
    let tx2 = TransactionBuilder::new(
        state.network_id,
        alice_id,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions::<InstructionBox>([succeed_instruction.into()])
    .sign(alice_keypair.private_key());
    let (_clock, time_source) = TimeSource::new_mock(tx2.creation_time());
    let tx2 = AcceptedTransaction::accept_with_time_source(
        tx2,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        crypto_cfg.as_ref(),
        &time_source,
    )
    .expect("Valid");
    let fail_hash = tx0.hash_as_entrypoint();
    let register_hash = tx.hash_as_entrypoint();
    let succeed_hash = tx2.hash_as_entrypoint();
    // Creating a block of two identical transactions and validating it
    let transactions = vec![tx0, tx, tx2];
    let unverified_block = BlockBuilder::new(transactions)
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(alice_keypair.private_key())
        .unpack(|_| {});
    let (mut state_block, state_block_recorder) =
        crate::block::ValidBlock::start_component_execution(
            &unverified_block.clone().into(),
            state,
        )
        .expect("original writer-first component execution");
    let valid_block = unverified_block
        .validate_and_record_transactions(&mut state_block, state_block_recorder)
        .unpack(|_| {});
    // The 1st transaction should fail and 2nd succeed
    let block_ref = valid_block.as_ref();
    let outcomes: Vec<_> = block_ref
        .network_entrypoints()
        .enumerate()
        .map(|(index, input)| {
            let (output_index, row) = block_ref
                .network_output_at(u32::try_from(index).unwrap())
                .expect("exact Network source output");
            assert_eq!(usize::try_from(output_index).unwrap(), index);
            (input.hash(), &row.result)
        })
        .collect();
    let lookup = |hash: &_, label: &str| {
        outcomes
            .iter()
            .find(|(entry_hash, _)| entry_hash == hash)
            .unwrap_or_else(|| panic!("missing result for {label}"))
            .1
            .as_ref()
    };
    let fail_result = lookup(&fail_hash, "fail tx");
    assert!(fail_result.is_err(), "fail tx must be rejected");
    let register_result = lookup(&register_hash, "register tx");
    assert!(
        register_result.is_ok(),
        "register tx must succeed, got {register_result:?}"
    );
    let succeed_result = lookup(&succeed_hash, "succeed tx");
    assert!(
        succeed_result.is_ok(),
        "succeed tx must succeed, got {succeed_result:?}"
    );
}
