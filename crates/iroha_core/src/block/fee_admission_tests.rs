#[test]
fn fee_enabled_single_transfer_uses_canonical_output_owner() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-single-transfer-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let tx = TransactionBuilder::new_with_time_source(
        state.network_id,
        payer_id.clone(),
        &block_time_source,
        fee_payment,
    )
    .with_instructions([Transfer::asset_quantity(
        payer_transfer_asset.clone(),
        1_u32,
        recipient_id.clone(),
    )])
    .sign(payer_keypair.private_key());
    let tx = AcceptedTransaction::accept_with_time_source(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        &block_time_source,
    )
    .expect("transaction should pass stateless admission");
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    let errors = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .filter_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .map(|(idx, error)| (idx, format!("{error:?}")))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "fee-enabled transfer should be accepted: {errors:?}"
    );

    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_transfer_asset).expect("payer rose").0,
        Quantity::from(4_u32)
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose")
            .0,
        Quantity::from(1_u32)
    );
    assert_eq!(
        assets.get(&payer_fee_asset).expect("payer xor").0,
        Quantity::from(9_u32)
    );
}
#[test]
fn fee_enabled_account_metadata_uses_canonical_output_owner() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-non-transfer-fallback-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, sink],
        [fee_asset_definition],
        [Asset::new(payer_fee_asset.clone(), Quantity::from(10_u32))],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let marker_key: Name = "fee_fallback_marker".parse().expect("metadata key");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([SetKeyValue::account(
            payer_id.clone(),
            marker_key.clone(),
            Json::from(true),
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .is_none(),
        "supported non-transfer fee transaction should be accepted by its canonical owner"
    );

    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_fee_asset).expect("payer xor").0,
        Quantity::from(9_u32)
    );
    let marker_value = state_block
        .world
        .map_account(&payer_id, |account| {
            account.value().metadata().get(&marker_key).cloned()
        })
        .expect("payer account exists");
    assert_eq!(marker_value, Some(Json::from(true)));
}
#[test]
fn fee_enabled_single_transfer_rejects_without_partial_state_when_fee_missing() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-insufficient-fee-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::zero()),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let mut builder = TransactionBuilder::new(
        state.network_id,
        payer_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::Nexus,
                fee_asset_definition_id.clone(),
                Quantity::one(),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0),
        "insufficient fee must reject the transaction"
    );
    let (_, rejection) = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .expect("fee rejection");
    let expected = format!(
        "fee balance `{payer_fee_asset}` for authority `{payer_id}` is insufficient: requires 1, available 0"
    );
    assert!(
        matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
                if message == &expected
        ),
        "the signed fee limit must pass before rejecting insufficient funding: {rejection:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_transfer_asset).expect("payer rose").0,
        Quantity::from(5_u32),
        "business transfer must not leak when fee charging fails"
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose")
            .0,
        Quantity::zero(),
        "recipient balance must remain unchanged when fee charging fails"
    );
    assert_eq!(
        assets.get(&payer_fee_asset).expect("payer xor").0,
        Quantity::zero(),
        "failed fee debit must not create a negative or partial fee state"
    );
}
#[test]
fn fee_enabled_single_transfer_with_active_data_trigger_retains_callback_outputs() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-data-trigger-fallback-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let trigger_marker_key: Name = "fee_trigger_marker".parse().expect("metadata key");
    let trigger_id: TriggerId = "fee_transfer_trigger_guard".parse().unwrap();
    let trigger = Trigger::new(
        trigger_id,
        Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                payer_id.clone(),
                trigger_marker_key.clone(),
                Json::from("triggered"),
            ))],
            Repeats::Exactly(1),
            payer_id.clone(),
            DataEventFilter::Asset(AssetEventFilter::new().for_asset(payer_transfer_asset.clone())),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    );
    native_chain.setup_world_at(10, |setup_tx| {
        Register::trigger(trigger)
            .execute(&payer_id, setup_tx)
            .expect("register data trigger");
    });
    let setup_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id.clone(),
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&setup_signed))
        .sign(payer_keypair.private_key())
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
    assert!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .is_none(),
        "fee-enabled transfer and its callback must share the same canonical output owner"
    );

    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_transfer_asset).expect("payer rose").0,
        Quantity::from(4_u32)
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose")
            .0,
        Quantity::from(1_u32)
    );
    assert_eq!(
        assets.get(&payer_fee_asset).expect("payer xor").0,
        Quantity::from(9_u32)
    );
    let marker_value = state_block
        .world
        .map_account(&payer_id, |account| {
            account.value().metadata().get(&trigger_marker_key).cloned()
        })
        .expect("payer account exists");
    assert_eq!(marker_value, Some(Json::from("triggered")));
}
#[test]
fn same_block_data_trigger_registration_is_atomic_with_rejected_transfer() {
    let chain_id = ChainId::from("same-block-data-trigger-atomicity");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let asset_definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "rose".parse().expect("asset name"));
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_asset = AssetId::of(asset_definition_id.clone(), payer_id.clone());
    let recipient_asset = AssetId::of(asset_definition_id, recipient_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient],
        [asset_definition],
        [
            Asset::new(payer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_asset.clone(), Quantity::zero()),
        ],
        [],
    );
    let mut state = State::new_with_chain(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        chain_id,
    );
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.parallel_apply = true;
    pipeline.parallel_overlay = true;
    pipeline.workers = 2;
    state.set_pipeline(pipeline);
    let trigger_id: TriggerId = "same_block_failing_transfer_trigger".parse().unwrap();
    let marker: Name = "same_block_trigger_marker".parse().unwrap();
    let missing_domain =
        DomainId::try_new("missing-trigger-domain", "universal").expect("missing domain id");
    let trigger = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![
                InstructionBox::from(SetKeyValue::account(
                    payer_id.clone(),
                    marker.clone(),
                    Json::from(true),
                )),
                InstructionBox::from(Unregister::domain(missing_domain)),
            ],
            Repeats::Exactly(1),
            payer_id.clone(),
            DataEventFilter::Asset(AssetEventFilter::new().for_asset(payer_asset.clone())),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    );
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let make_accepted = |creation_time_ms: u64, instructions: Vec<InstructionBox>| {
        let mut builder = TransactionBuilder::new(
            state.network_id,
            payer_id.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(creation_time_ms));
        accept_transaction_at_mock_time(
            builder
                .with_instructions(instructions)
                .sign(payer_keypair.private_key()),
            &state.network_id,
            max_clock_drift,
            tx_limits,
            state.crypto().as_ref(),
            Duration::from_millis(10),
        )
        .expect("transaction passes stateless admission")
    };
    let register = make_accepted(
        0,
        vec![
            Grant::account_permission(
                iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                    authority: payer_id.clone(),
                },
                payer_id.clone(),
            )
            .into(),
            Register::trigger(trigger).into(),
        ],
    );
    let transfer = make_accepted(
        1,
        vec![Transfer::asset_quantity(payer_asset.clone(), 1_u32, recipient_id).into()],
    );
    let leader = crate::block::checked_keypair_with_algorithm(Algorithm::BlsNormal);
    let (_leader_public, leader_private) = leader.into_parts();
    let previous = ValidBlock::new_dummy_and_modify_header(&leader_private, |header| {
        header.set_height(nonzero!(1_u64));
    });
    let _previous: SignedBlock = previous.into();
    let previous = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let block = BlockBuilder::new_with_time_source(vec![register, transfer], block_time_source)
        .chain(1, Some(&previous))
        .sign(payer_keypair.private_key())
        .unpack(|_| {});
    let (mut state_block, state_block_recorder) =
        crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
            .expect("original writer-first component execution");

    let valid = block
        .validate_and_record_transactions(&mut state_block, state_block_recorder)
        .unpack(|_| {});
    let results = valid
        .as_ref()
        .network_entrypoints()
        .enumerate()
        .map(|(index, entrypoint)| {
            let (output_index, output) = valid
                .as_ref()
                .network_output_at(u32::try_from(index).expect("fixture Network index fits u32"))
                .expect("every queried input has its explicit Network output");
            assert_eq!(usize::try_from(output_index).unwrap(), index);
            (index, entrypoint, &output.result)
        })
        .map(|(_, _, result)| result.0.clone())
        .collect::<Vec<_>>();
    assert!(
        results[0].is_ok(),
        "trigger registration failed: {results:?}"
    );
    assert!(
        results[1].is_err(),
        "failing trigger must reject transfer: {results:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_asset).expect("payer asset").0,
        Quantity::from(5_u32)
    );
    assert_eq!(
        assets.get(&recipient_asset).expect("recipient asset").0,
        Quantity::zero()
    );
    let marker_value = state_block
        .world
        .map_account(&payer_id, |account| {
            account.value().metadata().get(&marker).cloned()
        })
        .expect("payer account exists");
    assert!(marker_value.is_none(), "rejected trigger effects leaked");
    let action = state_block
        .world
        .triggers
        .data_triggers()
        .get(&trigger_id)
        .expect("successful trigger registration persists");
    assert_eq!(action.repeats, Repeats::Exactly(1));
}
#[test]
fn prepared_execute_trigger_retains_nested_gas_on_success_and_rejection() {
    use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;

    for reject_nested_action in [false, true] {
        let chain_id = ChainId::try_from(format!(
            "prepared-execute-trigger-gas-{reject_nested_action}"
        ))
        .expect("canonical test chain id");
        let (authority, keypair) = gen_account_in("wonderland");
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id).build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let world = World::with([domain], [account], []);
        let mut state = State::new_with_chain(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            chain_id,
        );
        let mut pipeline = state.installed_pipeline().clone();
        pipeline.parallel_apply = true;
        pipeline.parallel_overlay = true;
        pipeline.workers = 2;
        state.set_pipeline(pipeline);
        let native_chain = component_chain(state);
        let state = native_chain.state();

        let trigger_id: TriggerId = format!("prepared_nested_gas_{reject_nested_action}")
            .parse()
            .expect("trigger id");
        let marker: Name = "prepared_nested_gas_marker".parse().expect("metadata key");
        let marker_instruction = InstructionBox::from(SetKeyValue::account(
            authority.clone(),
            marker.clone(),
            Json::from(true),
        ));
        let mut nested_instructions = vec![marker_instruction.clone()];
        if reject_nested_action {
            nested_instructions.push(InstructionBox::from(Unregister::domain(
                DomainId::try_new("missing-nested-trigger", "universal")
                    .expect("missing domain id"),
            )));
        }
        let expected_nested_gas =
            crate::gas::meter_instructions(&nested_instructions, &crate::gas::DEFAULT_ZK_GAS);
        let trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                nested_instructions,
                Repeats::Exactly(1),
                authority.clone(),
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        native_chain.setup_world_at(10, |setup_tx| {
            Register::trigger(trigger)
                .execute(&authority, setup_tx)
                .expect("register by-call trigger");
        });
        let setup_signed = state
            .view()
            .latest_block()
            .expect("original block read attempt")
            .expect("original genesis");

        let execute_instruction = InstructionBox::from(ExecuteTrigger::new(trigger_id));
        let expected_base_gas = crate::gas::meter_instructions(
            core::slice::from_ref(&execute_instruction),
            &crate::gas::DEFAULT_ZK_GAS,
        );
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction())
        };
        let mut builder = TransactionBuilder::new(
            state.network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(0));
        let accepted = accept_transaction_at_mock_time(
            builder
                .with_instructions([execute_instruction])
                .sign(keypair.private_key()),
            &state.network_id,
            max_clock_drift,
            tx_limits,
            state.crypto().as_ref(),
            Duration::from_millis(10),
        )
        .expect("ExecuteTrigger transaction passes stateless admission");
        let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
        let block = BlockBuilder::new_with_time_source(vec![accepted], block_time_source)
            .chain(1, Some(&setup_signed))
            .sign(keypair.private_key())
            .unpack(|_| {});
        let (mut state_block, state_block_recorder) =
            crate::block::ValidBlock::start_component_execution(&block.clone().into(), state)
                .expect("original writer-first component execution");
        let valid = block
            .validate_and_record_transactions(&mut state_block, state_block_recorder)
            .unpack(|_| {});
        let result = valid
            .as_ref()
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = valid
                    .as_ref()
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .next()
            .expect("one transaction result")
            .2
            .0
            .clone();
        assert_eq!(
            result.is_err(),
            reject_nested_action,
            "unexpected ExecuteTrigger result: {result:?}"
        );
        assert_eq!(
            state_block.gas_used_in_block,
            expected_base_gas.saturating_add(expected_nested_gas),
            "authored and nested trigger work must be block-accounted exactly once"
        );
        let marker_value = state_block
            .world
            .map_account(&authority, |account| {
                account.value().metadata().get(&marker).cloned()
            })
            .expect("authority account exists");
        assert_eq!(
            marker_value.is_none(),
            reject_nested_action,
            "nested trigger effects must commit on success and roll back on rejection"
        );
    }
}
#[test]
fn fee_enabled_single_transfer_rejects_without_partial_state_when_fee_asset_missing() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-missing-fee-asset-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0),
        "missing payer fee asset must reject the transaction"
    );
    let (_, rejection) = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .expect("fee rejection");
    let expected = format!(
        "fee balance `{payer_fee_asset}` for authority `{payer_id}` is insufficient: requires 1, available 0"
    );
    assert!(
        matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
                if message == &expected
        ),
        "the signed fee limit must pass before rejecting insufficient funding: {rejection:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets.get(&payer_transfer_asset).expect("payer rose").0,
        Quantity::from(5_u32),
        "business transfer must not leak when fee asset lookup fails"
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose")
            .0,
        Quantity::zero(),
        "recipient balance must remain unchanged when fee asset lookup fails"
    );
    assert!(
        assets.get(&payer_fee_asset).is_none(),
        "fee charging must not create the missing payer fee asset"
    );
}
#[test]
fn fee_enabled_transfer_fee_same_asset_rolls_back_business_and_settles_actual_work() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-same-asset-fee-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_asset = AssetId::of(asset_definition_id.clone(), payer_id.clone());
    let recipient_asset = AssetId::of(asset_definition_id.clone(), recipient_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [asset_definition],
        [
            Asset::new(payer_asset.clone(), Quantity::from(1_u32)),
            Asset::new(recipient_asset.clone(), Quantity::zero()),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions([Transfer::asset_quantity(
            payer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0),
        "fee debit must reject when the payer only has enough balance for the transfer itself"
    );

    let assets = state_block.world.assets();
    assert_eq!(
        assets
            .get(&payer_asset)
            .map_or_else(Quantity::zero, |asset| asset.0.clone()),
        Quantity::zero(),
        "the rejected transfer must retain exactly its execution-owned base fee"
    );
    assert_eq!(
        assets.get(&recipient_asset).expect("recipient rose").0,
        Quantity::zero(),
        "recipient must not receive funds from a transaction rejected during fee charging"
    );
}
#[test]
fn fee_enabled_shared_fee_balance_rejects_later_transfer_without_rolling_back_prior_success() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-shared-fee-balance-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::from(1_u32)),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut first_builder =
        TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment.clone());
    first_builder.set_creation_time(Duration::from_millis(0));
    let first_tx = first_builder
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id.clone(),
        )])
        .sign(payer_keypair.private_key());
    let first_tx = accept_transaction_at_mock_time(
        first_tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("first transaction should pass stateless admission");
    let mut second_builder =
        TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    second_builder.set_creation_time(Duration::from_millis(1));
    let second_tx = second_builder
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .sign(payer_keypair.private_key());
    let second_tx = accept_transaction_at_mock_time(
        second_tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("second transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block =
        BlockBuilder::new_with_time_source(vec![first_tx, second_tx], block_time_source)
            .chain(1, Some(&latest_signed))
            .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .filter_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .count(),
        1,
        "only one of the two transfers can pay the configured base fee"
    );

    let (_, rejection) = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .expect("fee rejection");
    let expected = format!(
        "fee balance `{payer_fee_asset}` for authority `{payer_id}` is insufficient: requires 1, available 0"
    );
    assert!(
        matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
                if message == &expected
        ),
        "the signed fee limit must pass before rejecting insufficient funding: {rejection:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets
            .get(&payer_transfer_asset)
            .expect("payer rose after block")
            .0,
        Quantity::from(4_u32),
        "the accepted transfer must remain committed"
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose after block")
            .0,
        Quantity::from(1_u32),
        "the rejected transfer must not leak after the first fee drains the payer"
    );
    assert_eq!(
        assets
            .get(&payer_fee_asset)
            .map(|asset| asset.0.clone())
            .unwrap_or_else(Quantity::zero),
        Quantity::zero(),
        "only the accepted transaction may consume the available fee balance"
    );
}
#[test]
fn fee_enabled_transfer_then_failing_instruction_rolls_back_business_effects() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-transfer-then-fail-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            fee_asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let missing_domain_id = DomainId::try_new("missing-domain", "universal").unwrap();
    let tx = builder
        .with_instructions::<InstructionBox>([
            Transfer::asset_quantity(payer_transfer_asset.clone(), 1_u32, recipient_id).into(),
            Unregister::domain(missing_domain_id.clone()).into(),
        ])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0),
        "the failing instruction after the transfer must reject the whole transaction"
    );

    assert_eq!(
        valid_block.as_ref().output_results().count(),
        1,
        "the canonical execution owner must retain exactly one transaction result"
    );
    let (_, rejection) = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .expect("instruction rejection");
    assert!(
        matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                iroha_data_model::isi::error::InstructionExecutionError::Find(
                    iroha_data_model::query::error::FindError::Domain(domain)
                )
            )) if domain == &missing_domain_id
        ),
        "the missing domain instruction must reject after successful fee admission: {rejection:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets
            .get(&payer_transfer_asset)
            .expect("payer rose after rejected transfer")
            .0,
        Quantity::from(5_u32),
        "payer balance must remain unchanged after rejected transfer"
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose after rejected transfer")
            .0,
        Quantity::zero(),
        "recipient must not receive assets from a transaction rejected after the transfer"
    );
    assert_eq!(
        assets
            .get(&payer_fee_asset)
            .expect("payer xor after rejected transfer")
            .0,
        Quantity::from(9_u32),
        "rejected business execution must still charge the configured Nexus fee"
    );
}
#[test]
fn fee_enabled_non_increasing_sequence_rejects_before_transfer_or_fee() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-sequence-admission-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let payer_fee_asset = AssetId::of(fee_asset_definition_id.clone(), payer_id.clone());
    let mut world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(payer_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let mut params = iroha_data_model::parameter::system::Parameters::default();
    params.transaction = params.transaction.with_ingress_enforcement(false, true);
    world.parameters = mv::cell::Cell::new(
        crate::state::StateParameters::try_from(params).expect("valid fixture parameters"),
    );
    world.tx_sequences.insert(payer_id.clone(), 5);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let native_chain = component_chain_with_genesis_parameters(
        state,
        vec![iroha_data_model::parameter::Parameter::Transaction(
            iroha_data_model::parameter::system::TransactionParameter::RequireSequence(true),
        )],
    );
    let state = native_chain.state();
    assert!(
        state
            .view()
            .world()
            .parameters()
            .transaction()
            .require_sequence,
        "the original signed genesis must retain the requested sequence policy"
    );
    assert_eq!(
        state.view().world().tx_sequences.get(&payer_id),
        Some(&5),
        "original signed genesis must retain the independently seeded previous sequence"
    );
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("tx_sequence").expect("metadata key"),
        Json::from(5_u64),
    );
    let mut builder = TransactionBuilder::new(
        state.network_id,
        payer_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(
            vec![iroha_data_model::transaction::FeeChargeLimit::new(
                iroha_data_model::transaction::FeeChargeKind::Nexus,
                fee_asset_definition_id.clone(),
                Quantity::one(),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_metadata(metadata)
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0),
        "non-increasing tx_sequence must reject before transfer or fee application"
    );

    let (_, rejection) = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .expect("sequence rejection");
    let expected = format!("Transaction sequence 5 for {payer_id} must exceed previous 5");
    assert!(
        matches!(
            rejection,
            TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
                if message == &expected
        ),
        "the repeated sequence must be the precise rejection cause: {rejection:?}"
    );
    let assets = state_block.world.assets();
    assert_eq!(
        assets
            .get(&payer_transfer_asset)
            .expect("payer rose after sequence rejection")
            .0,
        Quantity::from(5_u32)
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose after sequence rejection")
            .0,
        Quantity::zero()
    );
    assert_eq!(
        assets
            .get(&payer_fee_asset)
            .expect("payer xor after sequence rejection")
            .0,
        Quantity::from(10_u32),
        "stateful admission failures must not charge Nexus fees"
    );
    assert_eq!(
        state_block.world.tx_sequences.get(&payer_id),
        Some(&5),
        "rejected sequence must not advance stored per-authority state"
    );
}
#[test]
fn legacy_fee_sponsor_metadata_rejects_before_block_admission_without_state_mutation() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("legacy-fee-sponsor-metadata-default-fees-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (sponsor_id, _sponsor_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let sponsor = Account::new(sponsor_id.clone()).build(&sponsor_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let sponsor_fee_asset = AssetId::of(fee_asset_definition_id.clone(), sponsor_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, sponsor, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(sponsor_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let kura = Arc::new(Kura::blank_kura_for_testing());
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_with_chain(world, Arc::clone(&kura), query_handle, chain_id.clone());
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("fee_sponsor").expect("metadata key"),
        Json::new(sponsor_id.to_string()),
    );
    let mut builder = TransactionBuilder::new(
        state.network_id,
        payer_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(0));
    let error = builder
        .with_metadata(metadata)
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .try_sign(payer_keypair.private_key())
        .expect_err("retired fee_sponsor metadata must fail before block admission");
    assert!(
        matches!(
            &error,
            iroha_data_model::transaction::signed::TransactionSignatureError::InvalidFeePaymentIntent(message)
                if message.contains("legacy transaction metadata key `fee_sponsor`")
        ),
        "unexpected signing error: {error}"
    );
    let state_view = state.world.view();
    let assets = state_view.assets();
    assert_eq!(
        assets
            .get(&payer_transfer_asset)
            .expect("payer rose after signing rejection")
            .0,
        Quantity::from(5_u32)
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose after signing rejection")
            .0,
        Quantity::zero()
    );
    assert_eq!(
        assets
            .get(&sponsor_fee_asset)
            .expect("sponsor xor after signing rejection")
            .0,
        Quantity::from(10_u32),
        "signing rejection must not debit the legacy sponsor"
    );
}
#[test]
fn legacy_fee_sponsor_metadata_rejects_when_nexus_fees_are_configured() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("legacy-fee-sponsor-metadata-configured-fees-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (sponsor_id, _sponsor_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let sponsor = Account::new(sponsor_id.clone()).build(&sponsor_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "rose".parse().expect("asset name"),
    );
    let fee_asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let fee_asset_definition = AssetDefinition::numeric(
        fee_asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let sponsor_fee_asset = AssetId::of(fee_asset_definition_id.clone(), sponsor_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, sponsor, recipient, sink],
        [transfer_asset_definition, fee_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
            Asset::new(sponsor_fee_asset.clone(), Quantity::from(10_u32)),
        ],
        [],
    );
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("fee_sponsor").expect("metadata key"),
        Json::new(sponsor_id.to_string()),
    );
    let mut builder = TransactionBuilder::new(
        state.network_id,
        payer_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(0));
    let error = builder
        .with_metadata(metadata)
        .with_instructions([Transfer::asset_quantity(
            payer_transfer_asset.clone(),
            1_u32,
            recipient_id,
        )])
        .try_sign(payer_keypair.private_key())
        .expect_err("retired fee_sponsor metadata must fail before block admission");
    assert!(
        matches!(
            &error,
            iroha_data_model::transaction::signed::TransactionSignatureError::InvalidFeePaymentIntent(message)
                if message.contains("legacy transaction metadata key `fee_sponsor`")
        ),
        "unexpected signing error: {error}"
    );
    let state_view = state.world.view();
    let assets = state_view.assets();
    assert_eq!(
        assets
            .get(&payer_transfer_asset)
            .expect("payer rose after signing rejection")
            .0,
        Quantity::from(5_u32)
    );
    assert_eq!(
        assets
            .get(&recipient_transfer_asset)
            .expect("recipient rose after signing rejection")
            .0,
        Quantity::zero()
    );
    assert_eq!(
        assets
            .get(&sponsor_fee_asset)
            .expect("sponsor xor after signing rejection")
            .0,
        Quantity::from(10_u32),
        "signing rejection must not debit the legacy sponsor"
    );
}
#[test]
fn invalid_fee_asset_is_rejected_before_runtime_or_balance_mutation() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("fee-detached-invalid-fee-asset-test");
    let (payer_id, _payer_keypair) = gen_account_in("wonderland");
    let (recipient_id, _recipient_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let recipient = Account::new(recipient_id.clone()).build(&recipient_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let transfer_asset_definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "rose".parse().expect("asset name"));
    let transfer_asset_definition = AssetDefinition::numeric(
        transfer_asset_definition_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_transfer_asset = AssetId::of(transfer_asset_definition_id.clone(), payer_id.clone());
    let recipient_transfer_asset =
        AssetId::of(transfer_asset_definition_id.clone(), recipient_id.clone());
    let world = World::with_assets(
        [domain],
        [payer, recipient, sink],
        [transfer_asset_definition],
        [
            Asset::new(payer_transfer_asset.clone(), Quantity::from(5_u32)),
            Asset::new(recipient_transfer_asset.clone(), Quantity::zero()),
        ],
        [],
    );
    let kura = Arc::new(Kura::blank_kura_for_testing());
    let query_handle = LiveQueryStore::start_test();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = "not-an-asset-literal".to_owned();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let mut state = State::new_with_chain(world, Arc::clone(&kura), query_handle, chain_id);
    let original_config = state.nexus_snapshot();
    let original_world = norito::json::to_json(&state.world).unwrap();
    let error = state
        .set_nexus_from_config(nexus)
        .expect_err("invalid fee identity cannot enter runtime configuration");
    assert!(
        error.to_string().contains("fee"),
        "precise fee policy rejection: {error}"
    );
    assert_eq!(norito::json::to_json(&state.world).unwrap(), original_world);
    let retained = state.nexus_snapshot().fees;
    assert_eq!(retained.fee_asset_id, original_config.fees.fee_asset_id);
    assert_eq!(
        retained.fee_sink_account_id,
        original_config.fees.fee_sink_account_id
    );
    assert_eq!(retained.base_fee, original_config.fees.base_fee);
    assert_eq!(retained.per_byte_fee, original_config.fees.per_byte_fee);
    assert_eq!(
        retained.per_instruction_fee,
        original_config.fees.per_instruction_fee
    );
    assert_eq!(
        retained.per_gas_unit_fee,
        original_config.fees.per_gas_unit_fee
    );
    assert_eq!(state.kura().blocks_count(), 0);
    let view = state.view();
    assert_eq!(
        view.world.assets().get(&payer_transfer_asset).unwrap().0,
        Quantity::from(5_u32)
    );
    assert_eq!(
        view.world
            .assets()
            .get(&recipient_transfer_asset)
            .unwrap()
            .0,
        Quantity::zero()
    );
}

#[test]
fn rejected_data_trigger_execution_still_charges_nexus_fee() {
    let _guard = crate::status::nexus_fee_test_lock()
        .lock()
        .expect("nexus fee test lock");
    crate::status::reset_nexus_economics_for_tests();
    let chain_id = ChainId::from("rejected-trigger-fee-test");
    let (payer_id, payer_keypair) = gen_account_in("wonderland");
    let (sink_id, _sink_keypair) = gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain = Domain::new(domain_id.clone()).build(&payer_id);
    let payer = Account::new(payer_id.clone()).build(&payer_id);
    let sink = Account::new(sink_id.clone()).build(&sink_id);
    let asset_definition_id = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR identity");
    let asset_definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&payer_id);
    let payer_asset = Asset::new(
        AssetId::of(asset_definition_id.clone(), payer_id.clone()),
        Quantity::from(10_u32),
    );
    let sink_asset = Asset::new(
        AssetId::of(asset_definition_id.clone(), sink_id.clone()),
        Quantity::zero(),
    );
    let world = World::with_assets(
        [domain],
        [payer, sink],
        [asset_definition],
        [payer_asset, sink_asset],
        [],
    );
    let _kura = Arc::new(Kura::blank_kura_for_testing());
    let _query_handle = LiveQueryStore::start_test();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = asset_definition_id.to_string();
    nexus.fees.fee_sink_account_id = sink_id.to_string();
    let state = configured_component_state(world, chain_id.clone(), nexus);
    {
        let mut world = state.world.block();
        world
            .parameters
            .set_parameter(iroha_data_model::parameter::Parameter::SmartContract(
                iroha_data_model::parameter::SmartContractParameter::ExecutionDepth(0),
            ))
            .expect("valid fixture parameters");
        world.commit();
    }
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let latest_signed = state
        .view()
        .latest_block()
        .expect("original block read attempt")
        .expect("original genesis");
    let trigger_id: TriggerId = "fee_depth_limit_trigger".parse().unwrap();
    let flag_key: Name = "fee_trigger_flag".parse().unwrap();
    let event_key: Name = "fee_trigger_event".parse().unwrap();
    let trigger = Trigger::new(
        trigger_id,
        Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                payer_id.clone(),
                flag_key,
                Json::from(true),
            ))],
            Repeats::Indefinitely,
            payer_id.clone(),
            DataEventFilter::Account(AccountEventFilter::new().for_account(payer_id.clone())),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    );
    let fee_payment = iroha_data_model::transaction::FeePaymentIntent::authority(
        vec![iroha_data_model::transaction::FeeChargeLimit::new(
            iroha_data_model::transaction::FeeChargeKind::Nexus,
            asset_definition_id.clone(),
            Quantity::from(1_u32),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(state.network_id, payer_id.clone(), fee_payment);
    builder.set_creation_time(Duration::from_millis(0));
    let tx = builder
        .with_instructions::<InstructionBox>([
            Grant::account_permission(
                iroha_executor_data_model::permission::trigger::CanRegisterTrigger {
                    authority: payer_id.clone(),
                },
                payer_id.clone(),
            )
            .into(),
            Register::trigger(trigger).into(),
            SetKeyValue::account(payer_id.clone(), event_key.clone(), Json::from(true)).into(),
        ])
        .sign(payer_keypair.private_key());
    let tx = accept_transaction_at_mock_time(
        tx,
        &state.network_id,
        max_clock_drift,
        tx_limits,
        state.crypto().as_ref(),
        Duration::from_millis(10),
    )
    .expect("transaction should pass stateless admission");
    let (_block_handle, block_time_source) = TimeSource::new_mock(Duration::from_millis(10));
    let unverified_block = BlockBuilder::new_with_time_source(vec![tx], block_time_source)
        .chain(1, Some(&latest_signed))
        .sign(payer_keypair.private_key())
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
    assert_eq!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .map(|(idx, _)| idx),
        Some(0)
    );
    let first_error = valid_block
        .as_ref()
        .output_results()
        .enumerate()
        .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
        .map(|(_, err)| err);
    assert!(
        matches!(
            first_error,
            Some(TransactionRejectionReason::TriggerExecution(
                iroha_data_model::transaction::error::TriggerExecutionFail::MaxDepthExceeded
            ))
        ),
        "unexpected trigger rejection: {first_error:?}"
    );
    let assets = state_block.world.assets();
    let payer_balance = assets
        .get(&AssetId::of(asset_definition_id.clone(), payer_id.clone()))
        .expect("payer balance exists")
        .0
        .to_string();
    let sink_balance = assets
        .get(&AssetId::of(asset_definition_id, sink_id))
        .expect("sink balance exists")
        .0
        .to_string();
    assert_eq!(payer_balance, "9", "tx error: {first_error:?}");
    assert_eq!(sink_balance, "0");
    let event_value = state_block
        .world
        .map_account(&payer_id, |account| {
            account.value().metadata().get(&event_key).cloned()
        })
        .expect("payer account exists");
    assert!(
        event_value.is_none(),
        "trigger-rejected transaction state changes must still be rolled back"
    );
}
#[tokio::test]
async fn validate_and_record_transactions_allows_missing_authority_self_register() {
    let chain_id = ChainId::from("missing-authority-self-register-block");
    let (authority, keypair) = gen_account_in("wonderland");
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, chain_id.clone());
    let native_chain = component_chain(state);
    let state = native_chain.state();
    let (max_clock_drift, tx_limits) = {
        let state_view = state.world.view();
        let params = state_view.parameters();
        (params.sumeragi().max_clock_drift(), params.transaction())
    };
    let tx = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([
        InstructionBox::from(Register::account(Account::new(authority.clone()))),
        InstructionBox::from(Log::new(Level::INFO, "self-register".into())),
    ])
    .sign(keypair.private_key());
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
    .expect("admission should accept transaction shape");
    let unverified_block = BlockBuilder::new(vec![tx])
        .chain(
            0,
            state
                .view()
                .latest_block()
                .expect("original block read attempt")
                .as_deref(),
        )
        .sign(keypair.private_key())
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
    assert!(
        valid_block
            .as_ref()
            .output_results()
            .enumerate()
            .find_map(|(index, result)| result.as_ref().err().map(|reason| (index, reason)))
            .is_none(),
        "self-register block path should not produce transaction errors"
    );
    assert!(
        state_block.world.accounts.get(&authority).is_some(),
        "authority account should be materialized during block execution"
    );
}
