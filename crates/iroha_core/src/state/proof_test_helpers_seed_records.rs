#[test]
#[allow(clippy::too_many_lines)]
fn proof_test_helpers_seed_records() {
    use nonzero_ext::nonzero;
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let_row! { proof_id = ProofId { backend: "halo2/test".into(), proof_hash: [0xAA; 32], } };
    let_row! { record = ProofRecord { id: proof_id.clone(), vk_ref: None, vk_commitment: None, status: ProofStatus::Verified, verified_at_height: Some(1), bridge: None, } };
    stx.world
        .proofs_mut_for_testing()
        .insert(proof_id.clone(), record.clone());
    stx.world
        .proof_tags_mut_for_testing()
        .insert(proof_id.clone(), vec![*b"TAG1"]);
    stx.world
        .proofs_by_tag_mut_for_testing()
        .insert(*b"TAG1", vec![proof_id.clone()]);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit seeded proofs");
    let view = state.view();
    let world = &view.world;
    assert_eq!(world.proofs().get(&proof_id), Some(&record));
    assert_eq!(world.proof_tags().get(&proof_id), Some(&vec![*b"TAG1"]));
    assert_eq!(
        world.proofs_by_tag().get(b"TAG1"),
        Some(&vec![proof_id.clone()])
    );
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn by_call_trigger_emits_event_and_chains_data_trigger() -> Result<()> {
    // World with domain/account/asset
    let state = blank_state();
    let_row! { block = new_dummy_block_with_payload( |h| { h.set_height(NonZeroU64::new(1).unwrap()); h.creation_time_ms = 1; }) };
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    Register::account(new_sample_account(&ALICE_ID))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let_row! { asset_def_id: AssetDefinitionId = iroha_data_model::asset::AssetDefinitionId::derive_from_components( DomainId::try_new("wonderland", "universal").unwrap(), "rose".parse().unwrap(), ) };
    Register::asset_definition(AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    // Data trigger: whenever ALICE's rose asset changes, set account metadata flag=ok (runs once)
    let asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let key: Name = "flag".parse().unwrap();
    let data_trigger_id: TriggerId = "on_rose_added".parse().unwrap();
    let_row! { data_trigger = Trigger::new( data_trigger_id.clone(), Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("ok")), ))], Repeats::Exactly(1), ALICE_ID.clone(), DataEventFilter::Asset(data_pre::AssetEventFilter::new().for_asset(asset_id.clone())), ) .expect("trigger action fixture satisfies validation invariants"), ) };
    Register::trigger(data_trigger)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    // By-call trigger: mint 1 to ALICE's rose
    let by_call_id: TriggerId = "call_mint".parse().unwrap();
    let_row! { by_call = Trigger::new( by_call_id.clone(), Action::new( vec![InstructionBox::from(Mint::asset_quantity( 1_u32, asset_id.clone(), ))], Repeats::Exactly(1), ALICE_ID.clone(), ExecuteTriggerEventFilter::new() .for_trigger(by_call_id.clone()) .under_authority(ALICE_ID.clone()), ) .expect("trigger action fixture satisfies validation invariants"), ) };
    Register::trigger(by_call)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing()
        .expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = new_dummy_block_with_payload( |h| { h.set_height(NonZeroU64::new(2).unwrap()); }) };
    // Now execute the by-call trigger via transaction API and expect data trigger to chain
    let mut state_block2 = state.block(block2.as_ref().header());
    let mut stx2 = state_block2.transaction_for_callback_testing();
    let_row! { evt = ExecuteTriggerEvent { trigger_id: by_call_id.clone(), authority: ALICE_ID.clone(), args: Json::from(norito::json!({})), } };
    stx2.execute_called_trigger(&by_call_id, &evt)
        .expect("execute by-call");
    stx2.apply_callback_for_testing()
        .expect("capture successful component callbacks");
    // Observe the component owner's captured events without publishing a block.
    let events = state_block2.world.take_external_events();
    // ExecuteTrigger event (exactly one for this trigger id)
    let_row! { exec_count = events .iter() .filter(|e| matches!(e, EventBox::ExecuteTrigger(ev) if ev.trigger_id() == &by_call_id)) .count() };
    assert_eq!(exec_count, 1, "expected exactly one ExecuteTrigger event");
    // Asset Added event for the minted asset
    let_row! { added_count = events .iter() .filter(|e| { if let EventBox::Data(ev) = e && let data_pre::DataEvent::Domain(data_pre::DomainEvent::Asset( data_pre::ScopedAsset { event: data_pre::AssetEvent::Added(ch), .. }, )) = ev.as_ref() { return ch.asset == asset_id && ch.amount == Quantity::one(); } false }) .count() };
    assert_eq!(added_count, 1, "expected exactly one Asset::Added for mint");
    // Negative: no Asset::Removed for this asset
    assert!(events.iter().all(|e| {
        if let EventBox::Data(ev) = e
            && let data_pre::DataEvent::Domain(data_pre::DomainEvent::Asset(
                data_pre::ScopedAsset {
                    event: data_pre::AssetEvent::Removed(ch),
                    ..
                },
            )) = ev.as_ref()
        {
            return ch.asset != asset_id;
        }
        true
    }));
    // Account metadata inserted event for ALICE (flag=ok)
    let_row! { meta_count = events .iter() .filter(|e| { if let EventBox::Data(ev) = e && let data_pre::DataEvent::Account(data_pre::AccountEvent::MetadataInserted(mc)) = ev.as_ref() { return *mc.target() == *ALICE_ID && mc.key() == &key && mc.value() == &Json::from(norito::json!("ok")); } false }) .count() };
    assert_eq!(
        meta_count, 1,
        "expected exactly one MetadataInserted for flag"
    );
    // Negative: no metadata removal for flag in this event batch
    assert!(events.iter().all(|e| {
        if let EventBox::Data(ev) = e
            && let data_pre::DataEvent::Account(data_pre::AccountEvent::MetadataRemoved(mc)) =
                ev.as_ref()
        {
            return !(*mc.target() == *ALICE_ID && mc.key() == &key);
        }
        true
    }));
    // TriggerCompleted events should be emitted for the by-call trigger and the chained data trigger
    let_row! { completed: Vec<_> = events .iter() .filter_map(|e| { if let EventBox::TriggerCompleted(ev) = e { Some(ev) } else { None } }) .collect() };
    assert_eq!(
        completed.len(),
        2,
        "expected TriggerCompleted events for both executed triggers"
    );
    use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;
    let_row! { by_call_completion = completed .iter() .find(|ev| ev.trigger_id() == &by_call_id) .expect("by-call trigger to emit completion event") };
    assert!(matches!(
        by_call_completion.outcome(),
        TriggerCompletedOutcome::Success
    ));
    let_row! { chained_completion = completed .iter() .find(|ev| ev.trigger_id() == &data_trigger_id) .expect("chained data trigger to emit completion event") };
    assert!(matches!(
        chained_completion.outcome(),
        TriggerCompletedOutcome::Success
    ));
    state_block2.commit_world_overlay_for_testing().unwrap();
    // Check that the data trigger action took effect
    let_row! { flag_val = state .view() .world .map_account(&ALICE_ID, |a| a.value().metadata().get(&key).cloned()) .unwrap() };
    assert_eq!(flag_val, Some(Json::from(norito::json!("ok"))));
    Ok(())
}
state_test! { sync deterministic_pipeline_block_approved_trigger_executes
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_block_approved".parse().unwrap();
    let key: Name = "pipeline_flag".parse().unwrap();
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("ok")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect("pipeline trigger should execute");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&key),
        Some(&Json::from(norito::json!("ok")))
    );
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "one-shot pipeline trigger should be pruned"
    );
}
state_test! { sync constrained_pipeline_block_trigger_ignores_wrong_height_approved_event
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_block_height_constrained".parse().unwrap();
    let key: Name = "pipeline_block_height_constrained".parse().unwrap();
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("matched")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from( BlockEventFilter::new() .for_height(NonZeroU64::new(7).unwrap()) .for_status(BlockStatus::Approved), ), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect("wrong-height approved event should be ignored");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&key).is_none(),
        "wrong-height approved block event must not execute the trigger"
    );
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("unmatched trigger should remain") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
}
state_test! { sync one_shot_pipeline_trigger_executes_once_for_multiple_matching_events
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_one_shot_multi_match".parse().unwrap();
    let key: Name = "pipeline_one_shot_multi_match".parse().unwrap();
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("set-once")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let_row! { block3 = trigger_component_block(&state, 3) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let_row! { steps = stx .execute_pipeline_triggers([ PipelineEventBox::from(BlockEvent { header: block2.as_ref().header(), status: BlockStatus::Approved, }), PipelineEventBox::from(BlockEvent { header: block3.as_ref().header(), status: BlockStatus::Approved, }), ]) .expect("matching approved block events should execute at most once") };
    assert_eq!(
        steps.len(),
        1,
        "one-shot trigger must not execute twice in the same batch"
    );
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&key),
        Some(&Json::from(norito::json!("set-once")))
    );
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "one-shot trigger should be pruned after its first matching event"
    );
}
state_test! { sync one_shot_pipeline_transaction_trigger_executes_once_for_duplicate_matching_facts
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::events::pipeline::{
        PipelineEventBox, TransactionEvent, TransactionEventFilter, TransactionStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_tx_one_shot_duplicate".parse().unwrap();
    let key: Name = "pipeline_tx_one_shot_duplicate".parse().unwrap();
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("set-once")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from( TransactionEventFilter::new().for_status(TransactionStatus::Approved), ), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let tx_hash_a = HashOf::from_untyped_unchecked(Hash::prehashed([0xA1; Hash::LENGTH]));
    let tx_hash_b = HashOf::from_untyped_unchecked(Hash::prehashed([0xB2; Hash::LENGTH]));
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let_row! { steps = stx .execute_pipeline_triggers([ PipelineEventBox::from(TransactionEvent { hash: tx_hash_a, block_height: Some(block2.as_ref().header().height()), lane_id: LaneId::SINGLE, dataspace_id: DataSpaceId::UNIVERSAL, status: TransactionStatus::Approved, }), PipelineEventBox::from(TransactionEvent { hash: tx_hash_b, block_height: Some(block2.as_ref().header().height()), lane_id: LaneId::SINGLE, dataspace_id: DataSpaceId::UNIVERSAL, status: TransactionStatus::Approved, }), ]) .expect("duplicate matching approved transaction facts should execute at most once") };
    assert_eq!(
        steps.len(),
        1,
        "one-shot transaction trigger must not execute twice in the same batch"
    );
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&key),
        Some(&Json::from(norito::json!("set-once")))
    );
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "one-shot transaction trigger should be pruned after first match"
    );
}
state_test! { sync deterministic_pipeline_transaction_approved_and_rejected_triggers_execute
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::events::pipeline::{
        PipelineEventBox, TransactionEvent, TransactionEventFilter, TransactionStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let approved_trigger_id: TriggerId = "pipeline_tx_approved".parse().unwrap();
    let rejected_trigger_id: TriggerId = "pipeline_tx_rejected".parse().unwrap();
    let approved_key: Name = "pipeline_tx_approved".parse().unwrap();
    let rejected_key: Name = "pipeline_tx_rejected".parse().unwrap();
    let_row! { rejection = iroha_data_model::transaction::error::TransactionRejectionReason::Validation( iroha_data_model::ValidationFail::NotPermitted("expected rejection".to_owned()), ) };
    for (trigger_id, key, status) in [
        (
            approved_trigger_id.clone(),
            approved_key.clone(),
            TransactionStatus::Approved,
        ),
        (
            rejected_trigger_id.clone(),
            rejected_key.clone(),
            TransactionStatus::Rejected(Box::new(rejection.clone())),
        ),
    ] {
        let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key, Json::from(norito::json!("ok")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(TransactionEventFilter::new().for_status(status)), ) .expect("trigger action fixture satisfies validation invariants") };
        Register::trigger(Trigger::new(trigger_id, action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
    }
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let tx_hash_a = HashOf::from_untyped_unchecked(Hash::prehashed([0xA5; Hash::LENGTH]));
    let tx_hash_b = HashOf::from_untyped_unchecked(Hash::prehashed([0x5A; Hash::LENGTH]));
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([
        PipelineEventBox::from(TransactionEvent {
            hash: tx_hash_a,
            block_height: Some(block2.as_ref().header().height()),
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Approved,
        }),
        PipelineEventBox::from(TransactionEvent {
            hash: tx_hash_b,
            block_height: Some(block2.as_ref().header().height()),
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Rejected(Box::new(rejection)),
        }),
    ])
    .expect("deterministic transaction pipeline triggers should execute");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&approved_key),
        Some(&Json::from(norito::json!("ok")))
    );
    assert_eq!(
        account.metadata().get(&rejected_key),
        Some(&Json::from(norito::json!("ok")))
    );
    assert!(
        view.world
            .triggers()
            .ids()
            .get(&approved_trigger_id)
            .is_none()
    );
    assert!(
        view.world
            .triggers()
            .ids()
            .get(&rejected_trigger_id)
            .is_none()
    );
}
state_test! { sync malformed_enabled_pipeline_trigger_does_not_execute_or_decrement
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_malformed_enabled".parse().unwrap();
    let key: Name = "must_not_be_set".parse().unwrap();
    let mut metadata = Metadata::default();
    metadata.insert(
        crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key"),
        Json::from(norito::json!({"bad": true})),
    );
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("unexpected")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") .with_metadata(metadata) };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect("malformed enabled metadata should fail closed without erroring");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&key).is_none(),
        "disabled pipeline trigger must not execute"
    );
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("disabled trigger should remain registered") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
    assert!(
        view.world
            .triggers()
            .active_pipeline_trigger_ids()
            .get(&trigger_id)
            .is_none(),
        "malformed enabled metadata must not appear active"
    );
}
state_test! { sync numeric_zero_enabled_pipeline_trigger_does_not_execute_or_decrement
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_numeric_zero_enabled".parse().unwrap();
    let key: Name = "pipeline_numeric_zero_enabled".parse().unwrap();
    let mut metadata = Metadata::default();
    metadata.insert(
        crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
            .parse::<Name>()
            .expect("valid metadata key"),
        Json::from(0_u64),
    );
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("unexpected")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") .with_metadata(metadata) };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect("numeric zero enabled metadata should disable without erroring");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&key).is_none(),
        "numeric-zero disabled pipeline trigger must not execute"
    );
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("disabled trigger should remain registered") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
    assert!(
        view.world
            .triggers()
            .active_pipeline_trigger_ids()
            .get(&trigger_id)
            .is_none(),
        "numeric-zero enabled metadata must not appear active"
    );
}
state_test! { sync constrained_pipeline_transaction_trigger_ignores_near_miss_events
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::events::pipeline::{
        PipelineEventBox, TransactionEvent, TransactionEventFilter, TransactionStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let wanted_hash = HashOf::from_untyped_unchecked(Hash::prehashed([0x11; Hash::LENGTH]));
    let other_hash = HashOf::from_untyped_unchecked(Hash::prehashed([0x22; Hash::LENGTH]));
    let wanted_height = block1.as_ref().header().height();
    let trigger_id: TriggerId = "pipeline_tx_constrained".parse().unwrap();
    let key: Name = "pipeline_tx_constrained".parse().unwrap();
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( ALICE_ID.clone(), key.clone(), Json::from(norito::json!("matched")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from( TransactionEventFilter::new() .for_hash(wanted_hash.clone()) .for_block_height(Some(wanted_height)) .for_lane_id(LaneId::SINGLE) .for_dataspace_id(DataSpaceId::UNIVERSAL) .for_status(TransactionStatus::Approved), ), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([
        PipelineEventBox::from(TransactionEvent {
            hash: other_hash,
            block_height: Some(wanted_height),
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Approved,
        }),
        PipelineEventBox::from(TransactionEvent {
            hash: wanted_hash,
            block_height: Some(block2.as_ref().header().height()),
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            status: TransactionStatus::Approved,
        }),
    ])
    .expect("non-matching deterministic events should be ignored");
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&key).is_none(),
        "near-miss transaction events must not execute the trigger"
    );
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("unmatched trigger should remain") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
}
state_test! { sync pipeline_trigger_fails_closed_on_missing_bytecode
    use iroha_data_model::{
        events::pipeline::{BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox},
        transaction::{Executable, IvmBytecode},
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "missing_bytecode_pipeline".parse().unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let bytecode = IvmBytecode::from_compiled(assemble_ivm_header(&raw));
    let blob_hash = HashOf::new(&bytecode);
    let_row! { action = Action::new( Executable::Ivm(bytecode), Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let mut state = authenticate_trigger_fixture(state);
    assert!(
        state.world.triggers.remove_contract_for_test(blob_hash),
        "contract entry should be removed for test setup"
    );
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let_row! { err = stx .execute_pipeline_triggers([PipelineEventBox::from(BlockEvent { header: block2.as_ref().header(), status: BlockStatus::Approved, })]) .expect_err("missing bytecode should reject pipeline trigger execution") };
    let err_debug = format!("{err:?}");
    assert!(
        err_debug.contains("missing trigger bytecode"),
        "unexpected error: {err_debug}"
    );
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("failed pipeline trigger should remain for storage repair") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
}
state_test! { sync isolated_pipeline_failure_rolls_back_disables_and_allows_healthy_sibling
    use iroha_data_model::events::pipeline::{
        BlockEventFilter, BlockStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let bad_trigger_id: TriggerId = "a_pipeline_failure".parse().unwrap();
    let good_trigger_id: TriggerId = "b_pipeline_healthy".parse().unwrap();
    let rolled_back_key: Name = "pipeline_rolled_back".parse().unwrap();
    let healthy_key: Name = "pipeline_healthy".parse().unwrap();
    let missing_account = AccountId::new(crate::state::checked_keypair().public_key().clone());
    let_row! { bad_action = Action::new(
        vec![
            InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                rolled_back_key.clone(),
                Json::from(norito::json!("must-roll-back")),
            )),
            InstructionBox::from(SetKeyValue::account(
                missing_account,
                "missing".parse().unwrap(),
                Json::from(norito::json!("boom")),
            )),
        ],
        Repeats::Indefinitely,
        ALICE_ID.clone(),
        PipelineEventFilterBox::from(
            BlockEventFilter::new().for_status(BlockStatus::Approved),
        ),
    ).expect("bad pipeline trigger action") };
    let_row! { good_action = Action::new(
        vec![InstructionBox::from(SetKeyValue::account(
            ALICE_ID.clone(),
            healthy_key.clone(),
            Json::from(norito::json!("ok")),
        ))],
        Repeats::Exactly(1),
        ALICE_ID.clone(),
        PipelineEventFilterBox::from(
            BlockEventFilter::new().for_status(BlockStatus::Approved),
        ),
    ).expect("healthy pipeline trigger action") };
    Register::trigger(Trigger::new(bad_trigger_id.clone(), bad_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    Register::trigger(Trigger::new(good_trigger_id.clone(), good_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);

    let_row! { block2 = trigger_component_block(&state, 2) };
    let (state_block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&state, block2.as_ref());
    let outcomes = outputs.iter().map(|output| {
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Pipeline(row) = output else {
            panic!("only matched Pipeline sources exist in this fixture");
        };
        (&row.invocation.trigger.trigger_id, &row.result)
    }).collect::<Vec<_>>();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes[0].1.is_err(), "bad trigger must report failure");
    assert!(outcomes[1].1.is_ok(), "healthy sibling must still execute");
    state_block.commit_world_overlay_for_testing().unwrap();

    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&rolled_back_key).is_none(),
        "prefix effects from the failed callback must roll back",
    );
    assert_eq!(
        account.metadata().get(&healthy_key),
        Some(&Json::from(norito::json!("ok"))),
    );
    let bad_trigger = view
        .world
        .triggers()
        .pipeline_triggers()
        .get(&bad_trigger_id)
        .expect("failed trigger remains available for inspection");
    assert_eq!(bad_trigger.repeats(), &Repeats::Indefinitely);
    assert!(!crate::smartcontracts::isi::triggers::trigger_is_enabled(
        bad_trigger.metadata()
    ));
    assert!(
        view.world
            .triggers()
            .active_pipeline_trigger_ids()
            .get(&bad_trigger_id)
            .is_none(),
        "failed trigger must be quarantined from later blocks",
    );
    assert!(
        view.world.triggers().ids().get(&good_trigger_id).is_none(),
        "healthy one-shot trigger should be depleted",
    );
}
state_test! { sync pipeline_trigger_replacement_keeps_its_own_repeat_budget
    use iroha_data_model::events::pipeline::{
        BlockEventFilter, BlockStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_self_replacement".parse().unwrap();
    let filter = PipelineEventFilterBox::from(
        BlockEventFilter::new().for_status(BlockStatus::Approved),
    );
    let_row! { replacement = Trigger::new(
        trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter.clone(),
        ).expect("replacement trigger action"),
    ) };
    let_row! { original = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![
                InstructionBox::from(Unregister::trigger(trigger_id.clone())),
                InstructionBox::from(Register::trigger(replacement)),
            ],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter,
        ).expect("original trigger action"),
    ) };
    Register::trigger(original)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);

    let_row! { block2 = trigger_component_block(&state, 2) };
    let (state_block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&state, block2.as_ref());
    let outcomes = outputs.iter().map(|output| {
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Pipeline(row) = output else {
            panic!("only matched Pipeline sources exist in this fixture");
        };
        (&row.invocation.trigger.trigger_id, &row.result)
    }).collect::<Vec<_>>();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].1.is_ok());
    state_block.commit_world_overlay_for_testing().unwrap();

    let view = state.view();
    let replacement = view
        .world
        .triggers()
        .pipeline_triggers()
        .get(&trigger_id)
        .expect("replacement trigger must remain registered");
    assert_eq!(replacement.repeats(), &Repeats::Exactly(1));
}
state_test! { sync pipeline_trigger_revalidates_a_sibling_replaced_after_matching
    use iroha_data_model::events::pipeline::{
        BlockEventFilter, BlockStatus,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let replacer_id: TriggerId = "a_pipeline_sibling_replacer".parse().unwrap();
    let victim_trigger_id: TriggerId = "b_pipeline_sibling_replaced".parse().unwrap();
    let replacement_executed: Name = "pipeline_replacement_executed".parse().unwrap();
    let filter = PipelineEventFilterBox::from(
        BlockEventFilter::new().for_status(BlockStatus::Approved),
    );
    let_row! { replacement = Trigger::new(
        victim_trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                replacement_executed.clone(),
                Json::from(norito::json!(true)),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter.clone(),
        ).expect("replacement sibling action"),
    ) };
    let_row! { replacer = Trigger::new(
        replacer_id.clone(),
        Action::new(
            vec![
                InstructionBox::from(Unregister::trigger(victim_trigger_id.clone())),
                InstructionBox::from(Register::trigger(replacement)),
            ],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter.clone(),
        ).expect("sibling replacer action"),
    ) };
    let_row! { original_sibling = Trigger::new(
        victim_trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            filter,
        ).expect("original sibling action"),
    ) };
    Register::trigger(replacer)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    Register::trigger(original_sibling)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);

    let_row! { block2 = trigger_component_block(&state, 2) };
    let (state_block, recording, outputs, fragments_before) =
        crate::state::run_empty_network_owner_fixture(&state, block2.as_ref());
    let outcomes = outputs.iter().map(|output| {
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Pipeline(row) = output else {
            panic!("only matched Pipeline sources exist in this fixture");
        };
        (&row.invocation.trigger.trigger_id, &row.result)
    }).collect::<Vec<_>>();
    assert_eq!(outcomes.len(), 1, "the stale sibling match must be skipped");
    assert_eq!(outcomes[0].0, &replacer_id);
    assert!(outcomes[0].1.is_ok());
    assert_eq!(
        state_block.committed_fragment_count(),
        fragments_before.saturating_add(1),
        "a skipped stale match must not commit a phantom empty fragment",
    );
    state_block.commit_world_overlay_for_testing().unwrap();

    {
        let view = state.view();
        let account = view.world.account(&ALICE_ID).expect("alice account");
        assert!(
            account.metadata().get(&replacement_executed).is_none(),
            "a replacement registered after ID matching must not execute in the same block",
        );
        let replacement = view
            .world
            .triggers()
            .pipeline_triggers()
            .get(&victim_trigger_id)
            .expect("replacement sibling must remain registered");
        assert_eq!(replacement.repeats(), &Repeats::Exactly(1));
    }
    drop(recording);

    let_row! { block3 = trigger_component_block(&state, 3) };
    let (state_block, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&state, block3.as_ref());
    let outcomes = outputs.iter().map(|output| {
        let iroha_data_model::block::execution_output::ExecutionOutputV1::Pipeline(row) = output else {
            panic!("only matched Pipeline sources exist in this fixture");
        };
        (&row.invocation.trigger.trigger_id, &row.result)
    }).collect::<Vec<_>>();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].1.is_ok());
    state_block.commit_world_overlay_for_testing().unwrap();

    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&replacement_executed),
        Some(&Json::from(norito::json!(true))),
        "the replacement becomes eligible in the following block",
    );
}
state_test! { sync data_trigger_revalidates_the_captured_incarnation_and_event
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let_row! { asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "data_revalidation_coin".parse().unwrap(),
    ) };
    Register::asset_definition(AssetDefinition::numeric(
        asset_definition_id.clone(),
        "data revalidation coin",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(DomainId::try_new("wonderland", "universal").unwrap()),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    let asset_id = AssetId::new(asset_definition_id, ALICE_ID.clone());
    let replacer_id: TriggerId = "a_data_sibling_replacer".parse().unwrap();
    let victim_trigger_id: TriggerId = "b_data_sibling_replaced".parse().unwrap();
    let replacement_executed: Name = "data_replacement_executed".parse().unwrap();
    let asset_filter = DataEventFilter::Asset(
        data_pre::AssetEventFilter::new().for_asset(asset_id.clone()),
    );
    let_row! { replacement = Trigger::new(
        victim_trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                replacement_executed.clone(),
                Json::from(norito::json!(true)),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            asset_filter.clone(),
        ).expect("replacement data-trigger action"),
    ) };
    let_row! { replacer = Trigger::new(
        replacer_id.clone(),
        Action::new(
            vec![
                InstructionBox::from(Unregister::trigger(victim_trigger_id.clone())),
                InstructionBox::from(Register::trigger(replacement)),
            ],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            asset_filter.clone(),
        ).expect("data-trigger sibling replacer action"),
    ) };
    let_row! { original_sibling = Trigger::new(
        victim_trigger_id.clone(),
        Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            asset_filter,
        ).expect("original data-trigger sibling action"),
    ) };
    Register::trigger(replacer)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    Register::trigger(original_sibling)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);

    let_row! { block2 = trigger_component_block(&state, 2) };
    let callback_source = signed_callback_boundary_source(
&state,
&block2.as_ref().header(),
vec![
        Mint::asset_quantity(1_u32, asset_id.clone()).into(),
        Mint::asset_quantity(1_u32, asset_id.clone()).into(),
    ],
);
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_fastpq_testing(
        Hash::from(callback_source.hash_as_entrypoint()),
    );
    // The same signed two-instruction source owns both direct drains. This
    // boundary fixture inspects its disposable overlay and never applies it.
    stx.current_entrypoint_index = Some(0);
    stx.tx_call_hash = Some(Hash::from(callback_source.hash_as_entrypoint()));
    stx.current_tx_hash = Some(callback_source.hash());
    Mint::asset_quantity(1_u32, asset_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let first_sequence = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect("the matching replacer executes");
    assert!(first_sequence.iter().any(|step| step.id == replacer_id));
    assert!(
        stx.world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&replacement_executed)
            .is_none(),
        "the replacement must not inherit the predecessor's captured asset event",
    );
    let replacement = stx
        .world
        .triggers
        .data_triggers()
        .get(&victim_trigger_id)
        .expect("replacement data trigger remains registered");
    assert_eq!(replacement.repeats(), &Repeats::Exactly(1));

    Mint::asset_quantity(1_u32, asset_id)
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    stx.execute_data_triggers_dfs(&ALICE_ID)
        .expect("a fresh matching asset event executes the replacement");
    assert_eq!(
        stx.world
            .account(&ALICE_ID)
            .unwrap()
            .metadata()
            .get(&replacement_executed),
        Some(&Json::from(norito::json!(true))),
    );
}
state_test! { sync pipeline_trigger_instruction_failure_rolls_back_and_preserves_repeats
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let trigger_id: TriggerId = "pipeline_direct_failure".parse().unwrap();
    let missing_account = AccountId::new(crate::state::checked_keypair().public_key().clone());
    let_row! { action = Action::new( vec![InstructionBox::from(SetKeyValue::account( missing_account, "missing".parse().unwrap(), Json::from(norito::json!("boom")), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect_err("failing pipeline instruction must reject trigger execution");
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let_row! { trigger = view .world .triggers() .pipeline_triggers() .get(&trigger_id) .expect("failed pipeline trigger should remain") };
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
}
state_test! { sync pipeline_trigger_chained_data_failure_rolls_back_and_preserves_repeats
    use iroha_data_model::events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, PipelineEventBox,
    };
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let_row! { asset_def_id = AssetDefinitionId::derive_from_components( DomainId::try_new("wonderland", "universal").unwrap(), "pipeline_rose".parse().unwrap(), ) };
    Register::asset_definition(AssetDefinition::numeric(
        asset_def_id.clone(),
        "pipeline_rose",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(DomainId::try_new("wonderland", "universal").unwrap()),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    let asset_id = AssetId::new(asset_def_id, ALICE_ID.clone());
    let data_trigger_id: TriggerId = "pipeline_failing_data_after_mint".parse().unwrap();
    let missing_account = AccountId::new(crate::state::checked_keypair().public_key().clone());
    let_row! { data_action = Action::new( vec![InstructionBox::from(SetKeyValue::account( missing_account, "missing".parse().unwrap(), Json::from(norito::json!("boom")), ))], Repeats::Exactly(1), ALICE_ID.clone(), DataEventFilter::Asset(data_pre::AssetEventFilter::new().for_asset(asset_id.clone())), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(data_trigger_id, data_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let pipeline_trigger_id: TriggerId = "pipeline_mint_then_failing_data".parse().unwrap();
    let_row! { pipeline_action = Action::new( vec![InstructionBox::from(Mint::asset_quantity( 1_u32, asset_id.clone(), ))], Repeats::Exactly(1), ALICE_ID.clone(), PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Approved)), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(pipeline_trigger_id.clone(), pipeline_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    stx.execute_pipeline_triggers([PipelineEventBox::from(BlockEvent {
        header: block2.as_ref().header(),
        status: BlockStatus::Approved,
    })])
    .expect_err("chained data trigger failure must reject pipeline execution");
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.asset(&asset_id).is_err(),
        "pipeline mint must roll back with chained failure"
    );
    let_row! { repeats = view .world .triggers() .pipeline_triggers() .get(&pipeline_trigger_id) .expect("pipeline trigger should remain") .repeats() };
    assert_eq!(repeats, &Repeats::Exactly(1));
}
state_test! { sync by_call_chained_data_trigger_failure_rolls_back_and_preserves_repeats
    pipeline_trigger_transaction!(state, block1, state_block, stx);
    let_row! { asset_def_id = AssetDefinitionId::derive_from_components( DomainId::try_new("wonderland", "universal").unwrap(), "rose".parse().unwrap(), ) };
    Register::asset_definition(AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(DomainId::try_new("wonderland", "universal").unwrap()),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    let asset_id = AssetId::new(asset_def_id, ALICE_ID.clone());
    let data_trigger_id: TriggerId = "failing_data_after_call".parse().unwrap();
    let missing_account = AccountId::new(crate::state::checked_keypair().public_key().clone());
    let_row! { data_action = Action::new( vec![InstructionBox::from(SetKeyValue::account( missing_account, "missing".parse().unwrap(), Json::from(norito::json!("boom")), ))], Repeats::Exactly(1), ALICE_ID.clone(), DataEventFilter::Asset(data_pre::AssetEventFilter::new().for_asset(asset_id.clone())), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(data_trigger_id, data_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let by_call_id: TriggerId = "call_then_failing_data".parse().unwrap();
    let_row! { by_call_action = Action::new( vec![InstructionBox::from(Mint::asset_quantity( 1_u32, asset_id.clone(), ))], Repeats::Exactly(1), ALICE_ID.clone(), ExecuteTriggerEventFilter::new() .for_trigger(by_call_id.clone()) .under_authority(ALICE_ID.clone()), ) .expect("trigger action fixture satisfies validation invariants") };
    Register::trigger(Trigger::new(by_call_id.clone(), by_call_action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing().expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let_row! { block2 = trigger_component_block(&state, 2) };
    let mut state_block = state.block(block2.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let_row! { event = ExecuteTriggerEvent { trigger_id: by_call_id.clone(), authority: ALICE_ID.clone(), args: Json::default(), } };
    stx.execute_called_trigger(&by_call_id, &event)
        .expect_err("chained data trigger failure must reject by-call execution");
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.asset(&asset_id).is_err(),
        "by-call mint must roll back with chained failure"
    );
    let_row! { repeats = view .world .triggers() .by_call_triggers() .get(&by_call_id) .expect("by-call trigger should remain") .repeats() };
    assert_eq!(repeats, &Repeats::Exactly(1));
}
