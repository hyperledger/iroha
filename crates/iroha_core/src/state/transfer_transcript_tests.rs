// Transfer-transcript tests remain in the parent state test module.
use super::*;
use crate::kura::Kura;
use iroha_data_model::block::BlockHeader;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use nonzero_ext::nonzero;
fn sample_delta(amount: u32) -> TransferDeltaTranscript {
    TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        amount: Quantity::from(amount),
        from_balance_before: Quantity::from(100_u32),
        from_balance_after: Quantity::from(100_u32.saturating_sub(amount)),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(amount),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    }
}
#[test]
fn transfer_transcripts_flush_into_block_map_on_apply() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let call_hash = iroha_crypto::Hash::prehashed([0_u8; iroha_crypto::Hash::LENGTH]);
    let mut tx = block.transaction_for_fastpq_testing(call_hash);
    let asset_definition: iroha_data_model::asset::AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let delta = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition,
        amount: Quantity::zero(),
        from_balance_before: Quantity::zero(),
        from_balance_after: Quantity::zero(),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::zero(),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    let expected_poseidon = crate::fastpq::poseidon_preimage_digest(&delta, &call_hash);
    tx.record_transfer_transcript(&ALICE_ID, delta)
        .expect("record transcript");
    assert_eq!(
        tx.pending_transfer_transcripts[0].poseidon_preimage_digest,
        Some(expected_poseidon),
        "single-delta transfer transcript digest should be computed while recording"
    );
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    let entry = transcripts
        .get(&call_hash)
        .expect("transcripts recorded for call hash");
    assert_eq!(entry.len(), 1);
    let transcript = &entry[0];
    assert_eq!(
        transcript.authority_digest,
        crate::fastpq::authority_digest(&ALICE_ID)
    );
    assert_eq!(transcript.poseidon_preimage_digest, Some(expected_poseidon));
}
#[test]
fn transfer_transcripts_reject_missing_call_hash() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let asset_definition: iroha_data_model::asset::AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let delta = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition,
        amount: Quantity::zero(),
        from_balance_before: Quantity::zero(),
        from_balance_after: Quantity::zero(),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::zero(),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    let err = tx
        .record_transfer_transcript(&ALICE_ID, delta)
        .expect_err("missing transaction call_hash must fail");
    assert!(
        err.to_string().contains("transaction call_hash"),
        "unexpected error: {err}"
    );
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    assert!(transcripts.is_empty());
}
#[test]
fn transfer_transcript_identity_preflight_always_fails_closed() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    {
        let mut transaction = block.transaction();
        let error = transaction
            .require_transfer_transcript_identity("test transfer")
            .expect_err("live transfer without call_hash must fail closed");
        assert!(error.to_string().contains("transaction call_hash"));
        let call_hash = iroha_crypto::Hash::prehashed([0xA5; iroha_crypto::Hash::LENGTH]);
        transaction.tx_call_hash = Some(call_hash);
        assert_eq!(
            transaction
                .require_transfer_transcript_identity("test transfer")
                .expect("live transfer with call_hash must pass"),
            call_hash
        );
    }
    let transaction = block.transaction();
    let error = transaction
        .require_transfer_transcript_identity("test transfer after prior transaction")
        .expect_err("every transaction without call_hash must fail closed");
    assert!(error.to_string().contains("transaction call_hash"));
}
#[test]
fn transfer_transcripts_reject_missing_call_hash_without_fastpq_work() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let mut tx = block.transaction();
    tx.record_transfer_transcript(&ALICE_ID, sample_delta(1))
        .expect_err("missing transcript identity must fail closed");
    assert!(
        tx.pending_transfer_transcripts.is_empty(),
        "rejected transfer must not stage FASTPQ transcripts"
    );
    tx.apply();
    assert!(block.drain_transfer_transcripts().is_empty());
    let witness = crate::exec_witness::drain_exec_witness();
    assert!(witness.fastpq_transcripts.is_empty());
    assert!(witness.fastpq_batches.is_empty());
}
#[test]
fn generated_rwa_id_rejects_missing_call_hash() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    let domain = DomainId::try_new("wonderland", "universal").unwrap();
    let err = tx
        .next_generated_rwa_id(&domain, "test")
        .expect_err("missing transaction call_hash must fail");
    assert!(
        err.to_string().contains("transaction call_hash"),
        "unexpected error: {err}"
    );
}
#[test]
fn transfer_transcripts_batch_records_multiple_deltas() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
        [1_u8; iroha_crypto::Hash::LENGTH],
    ));
    let asset_definition: iroha_data_model::asset::AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let delta_a = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: asset_definition.clone(),
        amount: Quantity::from(10_u32),
        from_balance_before: Quantity::from(100_u32),
        from_balance_after: Quantity::from(90_u32),
        to_balance_before: Quantity::from(0_u32),
        to_balance_after: Quantity::from(10_u32),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    let delta_b = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition,
        amount: Quantity::from(5_u32),
        from_balance_before: Quantity::from(90_u32),
        from_balance_after: Quantity::from(85_u32),
        to_balance_before: Quantity::from(10_u32),
        to_balance_after: Quantity::from(15_u32),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    tx.record_transfer_transcripts(&ALICE_ID, vec![delta_a.clone(), delta_b.clone()])
        .expect("record batch transcript");
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 1);
    let entry = transcripts.values().next().expect("batch recorded");
    assert_eq!(entry.len(), 1);
    let transcript = &entry[0];
    assert_eq!(transcript.deltas, vec![delta_a, delta_b]);
    assert_eq!(
        transcript.authority_digest,
        crate::fastpq::authority_digest(&ALICE_ID)
    );
    assert!(transcript.poseidon_preimage_digest.is_none());
}
#[test]
fn transfer_transcripts_batch_flushes_each_recorded_transaction_hash() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new(World::default(), Arc::clone(&kura), query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let call_hash_a = iroha_crypto::Hash::prehashed([2_u8; iroha_crypto::Hash::LENGTH]);
    let call_hash_b = iroha_crypto::Hash::prehashed([3_u8; iroha_crypto::Hash::LENGTH]);
    block.admit_fastpq_source_for_testing(call_hash_a);
    block.admit_fastpq_source_for_testing(call_hash_b);
    let mut tx = block.transaction();
    let asset_definition: iroha_data_model::asset::AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let delta_a = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: asset_definition.clone(),
        amount: Quantity::from(10_u32),
        from_balance_before: Quantity::from(100_u32),
        from_balance_after: Quantity::from(90_u32),
        to_balance_before: Quantity::from(0_u32),
        to_balance_after: Quantity::from(10_u32),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    let delta_b = TransferDeltaTranscript {
        from_account: (*BOB_ID).clone(),
        to_account: (*ALICE_ID).clone(),
        asset_definition,
        amount: Quantity::from(5_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(5_u32),
        to_balance_before: Quantity::from(90_u32),
        to_balance_after: Quantity::from(95_u32),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    tx.tx_call_hash = Some(call_hash_a);
    tx.record_transfer_transcript(&ALICE_ID, delta_a.clone())
        .expect("record first transcript");
    tx.tx_call_hash = Some(call_hash_b);
    tx.record_transfer_transcript(&BOB_ID, delta_b.clone())
        .expect("record second transcript");
    tx.tx_call_hash = None;
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 2);
    assert_eq!(
        transcripts
            .get(&call_hash_a)
            .expect("first hash transcript")[0]
            .deltas,
        vec![delta_a]
    );
    assert_eq!(
        transcripts
            .get(&call_hash_b)
            .expect("second hash transcript")[0]
            .deltas,
        vec![delta_b]
    );
}
#[test]
fn detached_asset_transfer_matches_sequential_transcript_and_events() {
    std::thread::Builder::new()
        .name("detached_asset_transfer_matches_sequential_transcript_and_events".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(check_detached_asset_transfer_matches_sequential_transcript_and_events)
        .expect("spawn state test with an explicit stack budget")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn check_detached_asset_transfer_matches_sequential_transcript_and_events() {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::isi::Transfer;
    fn build_transfer_world(receiver_asset_balance: Option<u32>) -> (World, AssetId, AssetId) {
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob_account = Account::new(BOB_ID.clone()).build(&BOB_ID);
        let asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id,
            "rose".parse().expect("asset name"),
        );
        let asset_definition = {
            let __asset_definition_id = asset_definition_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID);
        let alice_asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
        let bob_asset_id = AssetId::new(asset_definition_id, BOB_ID.clone());
        let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(10_u32));
        let mut assets = vec![alice_asset];
        if let Some(balance) = receiver_asset_balance {
            assets.push(Asset::new(bob_asset_id.clone(), Quantity::from(balance)));
        }
        let world = World::with_assets(
            [domain],
            [alice_account, bob_account],
            [asset_definition],
            assets,
            [],
        );
        (world, alice_asset_id, bob_asset_id)
    }
    fn balance(state: &State, asset_id: &AssetId) -> Quantity {
        state
            .view()
            .world()
            .assets()
            .get(asset_id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }
    let call_hash = iroha_crypto::Hash::prehashed([7_u8; iroha_crypto::Hash::LENGTH]);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let (world_seq, alice_asset_id, bob_asset_id) = build_transfer_world(None);
    let kura_seq = Kura::blank_kura_for_testing();
    let query_seq = crate::query::store::LiveQueryStore::start_test();
    let state_seq = State::new(world_seq, Arc::clone(&kura_seq), query_seq);
    let mut block_seq = state_seq.block(header);
    {
        let mut tx = block_seq.transaction_for_fastpq_testing(call_hash);
        Transfer::asset_quantity(alice_asset_id.clone(), 3_u32, BOB_ID.clone())
            .execute(&ALICE_ID, &mut tx)
            .expect("sequential transfer");
        tx.apply();
    }
    let events_seq = block_seq.world.take_external_events();
    let transcripts_seq = block_seq.drain_transfer_transcripts();
    let sources_seq = block_seq
        .captured_fastpq_transcript_sources()
        .unwrap()
        .clone();
    assert_eq!(sources_seq.len(), 1);
    assert!(!sources_seq[&call_hash].is_protocol_purpose());
    block_seq
        .commit_world_overlay_for_testing()
        .expect("commit sequential block");
    let (world_det, _, _) = build_transfer_world(None);
    let kura_det = Kura::blank_kura_for_testing();
    let query_det = crate::query::store::LiveQueryStore::start_test();
    let state_det = State::new(world_det, Arc::clone(&kura_det), query_det);
    let mut block_det = state_det.block(header);
    block_det.admit_fastpq_source_for_testing(call_hash);
    let instruction: InstructionBox =
        Transfer::asset_quantity(alice_asset_id.clone(), 3_u32, BOB_ID.clone()).into();
    let mut delta = DetachedStateTransactionDelta::default();
    crate::executor::execute_instruction_detached(&ALICE_ID, &instruction, &mut delta)
        .expect("detached transfer should be recorded");
    let delta_for_existing_transaction = delta.clone();
    delta
        .merge_into_with_context(
            &mut block_det,
            &ALICE_ID,
            DetachedMergeContext {
                tx_call_hash: Some(call_hash),
                current_tx_hash: None,
                current_lane_id: None,
                current_dataspace_id: None,
            },
        )
        .expect("detached transfer merge");
    let events_det = block_det.world.take_external_events();
    let transcripts_det = block_det.drain_transfer_transcripts();
    assert_eq!(
        block_det.captured_fastpq_transcript_sources().unwrap(),
        &sources_seq
    );
    block_det
        .commit_world_overlay_for_testing()
        .expect("commit detached block");
    let (world_existing_tx, _, _) = build_transfer_world(None);
    let kura_existing_tx = Kura::blank_kura_for_testing();
    let query_existing_tx = crate::query::store::LiveQueryStore::start_test();
    let state_existing_tx = State::new(
        world_existing_tx,
        Arc::clone(&kura_existing_tx),
        query_existing_tx,
    );
    let mut block_existing_tx = state_existing_tx.block(header);
    {
        let mut tx = block_existing_tx.transaction_for_fastpq_testing(call_hash);
        delta_for_existing_transaction
            .merge_single_transfer_into_transaction(&mut tx, &ALICE_ID)
            .expect("detached delta should be a single transfer")
            .expect("detached transfer merge into existing transaction");
        tx.apply();
    }
    let events_existing_tx = block_existing_tx.world.take_external_events();
    let transcripts_existing_tx = block_existing_tx.drain_transfer_transcripts();
    assert_eq!(
        block_existing_tx
            .captured_fastpq_transcript_sources()
            .unwrap(),
        &sources_seq
    );
    block_existing_tx
        .commit_world_overlay_for_testing()
        .expect("commit existing-transaction detached block");
    let second_call_hash = iroha_crypto::Hash::prehashed([8_u8; iroha_crypto::Hash::LENGTH]);
    let (world_batch, _, _) = build_transfer_world(None);
    let first_lane = LaneId::new(0);
    let second_lane = LaneId::new(1);
    let rejected_lane = LaneId::new(2);
    let catalog = iroha_data_model::nexus::LaneCatalog::new(
        nonzero!(3_u32),
        (0..3)
            .map(|index| iroha_data_model::nexus::LaneConfig {
                id: LaneId::new(index),
                alias: format!("grouped-transfer-{index}"),
                ..iroha_data_model::nexus::LaneConfig::default()
            })
            .collect(),
    )
    .expect("three distinct routing lanes");
    let nexus = iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog),
        lane_catalog: catalog.clone(),
        configured_lane_catalog: catalog,
        ..Default::default()
    };
    // Physical catalogs do not grant execution-lane incarnations. Install the
    // actual native fixed-lane policy through signed genesis and advance its
    // activation with genuine committed work before borrowing a frozen source.
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators};
    use iroha_data_model::sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
    };
    let mut config = TestChainConfig::new(world_batch, 0);
    config.nexus = Some(nexus);
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 16,
        max_merge_blocks: 8,
        stall_window: 100,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: [second_lane, rejected_lane]
            .into_iter()
            .map(|lane| SumeragiFixedLane {
                lane,
                dataspace: DataSpaceId::UNIVERSAL,
                committee: fixture_validators()
                    .into_iter()
                    .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
                    .collect(),
            })
            .collect(),
        routes: Vec::new(),
        autoscale: None,
    };
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            policy.into_custom_parameter(),
        ));
    let mut native_chain = CertifiedTestChain::start(config)
        .expect("apply the original physical catalog and native lane policy in signed genesis");
    assert_eq!(native_chain.height(), 1);
    {
        let state = native_chain.state();
        let parent = state
            .view()
            .latest_block()
            .expect("completed original State read")
            .expect("original signed genesis parent");
        let header = BlockHeader::new(
            nonzero!(2_u64),
            Some(parent.hash()),
            None,
            u64::try_from(parent.header().creation_time().as_millis())
                .unwrap()
                .checked_add(1)
                .unwrap(),
            0,
        );
        assert!(state.lane_incarnation_at_height(second_lane, 2).is_some());
        let mut inactive = state.block(header);
        let events = inactive.world.external_event_buf.len();
        let fragments = inactive.committed_fragment_count();
        {
            let mut tx = inactive.transaction_for_fastpq_testing(second_call_hash);
            tx.current_lane_id = Some(second_lane);
            let result = Transfer::asset_quantity(alice_asset_id.clone(), 2_u32, BOB_ID.clone())
                .execute(&ALICE_ID, &mut tx);
            assert!(
                matches!(result,
                    Err(Error::InvariantViolation(message))
                        if message.contains("no frozen active incarnation")
                ),
                "a configured physical lane cannot grant pending native activation"
            );
            assert_eq!(
                tx.world.assets().get(&alice_asset_id).unwrap().0,
                Quantity::from(10_u32)
            );
            assert!(tx.world.assets().get(&bob_asset_id).is_none());
        }
        assert_eq!(inactive.world.external_event_buf.len(), events);
        assert_eq!(inactive.committed_fragment_count(), fragments);
    }
    native_chain.commit(Vec::new());
    native_chain.commit(Vec::new());
    let state_batch = native_chain.state();
    assert_eq!(state_batch.committed_height(), 3);
    let parent = state_batch
        .view()
        .latest_block()
        .expect("completed original State read")
        .expect("actual activated native lane parent");
    let height = u64::try_from(state_batch.committed_height())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let batch_header = BlockHeader::new(
        NonZeroU64::new(height).unwrap(),
        Some(parent.hash()),
        None,
        u64::try_from(parent.header().creation_time().as_millis())
            .unwrap()
            .checked_add(1)
            .unwrap(),
        0,
    );
    for lane in [first_lane, second_lane, rejected_lane] {
        assert!(
            state_batch
                .lane_incarnation_at_height(lane, height)
                .is_some(),
            "each attempted source follows its original physical incarnation"
        );
        if lane != first_lane {
            assert!(
                state_batch
                    .view()
                    .world()
                    .sumeragi_lanes()
                    .lane(lane)
                    .unwrap()
                    .admits_anchor(height - 1),
                "native execution authority is genuinely active"
            );
        }
    }
    let native_incarnation = iroha_crypto::Hash::from_marked_bytes(
        state_batch
            .view()
            .world()
            .sumeragi_lanes()
            .lane(second_lane)
            .unwrap()
            .incarnation,
    )
    .expect("actual retained native incarnation");
    let mut block_batch = state_batch.block(batch_header);
    let batch_start_fragments = block_batch.committed_fragment_count();
    let mut first_delta = DetachedStateTransactionDelta::default();
    let first_instruction: InstructionBox =
        Transfer::asset_quantity(alice_asset_id.clone(), 3_u32, BOB_ID.clone()).into();
    crate::executor::execute_instruction_detached(&ALICE_ID, &first_instruction, &mut first_delta)
        .expect("first detached transfer should be recorded");
    let mut second_delta = DetachedStateTransactionDelta::default();
    let second_instruction: InstructionBox =
        Transfer::asset_quantity(alice_asset_id.clone(), 2_u32, BOB_ID.clone()).into();
    crate::executor::execute_instruction_detached(
        &ALICE_ID,
        &second_instruction,
        &mut second_delta,
    )
    .expect("second detached transfer should be recorded");
    let rejected_call_hash = iroha_crypto::Hash::prehashed([9_u8; iroha_crypto::Hash::LENGTH]);
    let mut rejected_delta = DetachedStateTransactionDelta::default();
    let rejected_instruction: InstructionBox =
        Transfer::asset_quantity(alice_asset_id.clone(), 99_u32, BOB_ID.clone()).into();
    crate::executor::execute_instruction_detached(
        &ALICE_ID,
        &rejected_instruction,
        &mut rejected_delta,
    )
    .expect("record an overdrawn attempt for merge-time rejection");
    for hash in [call_hash, second_call_hash, rejected_call_hash] {
        block_batch.admit_fastpq_source_for_testing(hash);
    }
    {
        let mut tx = block_batch.transaction();
        tx.current_lane_id = Some(first_lane);
        tx.tx_call_hash = Some(call_hash);
        first_delta
            .merge_numeric_transfer_batch_into_transaction(&mut tx, &ALICE_ID)
            .expect("first delta should be a single transfer")
            .expect("first batch transfer merge");
        tx.current_lane_id = Some(second_lane);
        tx.tx_call_hash = Some(second_call_hash);
        second_delta
            .merge_numeric_transfer_batch_into_transaction(&mut tx, &ALICE_ID)
            .expect("second delta should be a single transfer")
            .expect("second batch transfer merge");
        tx.current_lane_id = Some(rejected_lane);
        tx.tx_call_hash = Some(rejected_call_hash);
        let successful_events = tx.world.external_event_buf.len();
        rejected_delta
            .merge_numeric_transfer_batch_into_transaction(&mut tx, &ALICE_ID)
            .expect("rejected delta is one transparent transfer")
            .expect_err("99 units must exceed the five units left after successful merges");
        assert_eq!(tx.world.external_event_buf.len(), successful_events);
        assert_eq!(
            tx.world.assets().get(&alice_asset_id).unwrap().0,
            Quantity::from(5_u32)
        );
        assert_eq!(
            tx.world.assets().get(&bob_asset_id).unwrap().0,
            Quantity::from(5_u32)
        );
        tx.tx_call_hash = None;
        tx.current_lane_id = None;
        tx.apply();
    }
    block_batch.record_applied_batch_lanes(BTreeSet::from([first_lane, second_lane]));
    assert_eq!(
        block_batch.touched_lanes,
        BTreeSet::from([first_lane, second_lane])
    );
    assert!(!block_batch.touched_lanes.contains(&rejected_lane));
    // A successful merge in a subsequently dropped overlay publishes neither
    // its balances nor its lane. A zero-success overlay has the same rule.
    let applied_fragments = block_batch.committed_fragment_count();
    let applied_events = block_batch.world.external_event_buf.len();
    for successful_before_drop in [true, false] {
        let mut tx = block_batch.transaction();
        tx.current_lane_id = Some(rejected_lane);
        tx.tx_call_hash = Some(rejected_call_hash);
        let result = if successful_before_drop {
            &first_delta
        } else {
            &rejected_delta
        }
        .merge_numeric_transfer_batch_into_transaction(&mut tx, &ALICE_ID)
        .expect("control delta is one transparent transfer");
        if successful_before_drop {
            result.expect("the dropped overlay can transfer three of the five remaining units");
        } else {
            result.expect_err("zero-success overlay rejects the overdrawn transfer");
        }
        drop(tx);
        assert_eq!(
            block_batch.touched_lanes,
            BTreeSet::from([first_lane, second_lane])
        );
        assert_eq!(block_batch.committed_fragment_count(), applied_fragments);
        assert_eq!(block_batch.world.external_event_buf.len(), applied_events);
        assert_eq!(
            block_batch.world.assets().get(&bob_asset_id).unwrap().0,
            Quantity::from(5_u32)
        );
        assert_eq!(
            block_batch.world.assets().get(&alice_asset_id).unwrap().0,
            Quantity::from(5_u32)
        );
    }
    block_batch.record_applied_batch_lanes(BTreeSet::new());
    assert_eq!(
        block_batch.touched_lanes,
        BTreeSet::from([first_lane, second_lane])
    );
    // Exercise the production touched-lane DA predicate with only the later
    // successful lane covered. The earlier successful lane must still fail.
    let record = |lane_id| {
        iroha_data_model::da::commitment::DaCommitmentRecord::new(
            lane_id,
            1,
            1,
            iroha_data_model::da::types::BlobDigest::new([0x31; 32]),
            iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0x41; 32]),
            iroha_data_model::da::commitment::DaProofScheme::MerkleSha256,
            iroha_crypto::Hash::prehashed([0x51; 32]),
            None,
            iroha_data_model::da::commitment::RetentionClass::default(),
            iroha_data_model::da::types::StorageTicketId::new([0x61; 32]),
            iroha_crypto::Signature::new(
                crate::state::checked_keypair().private_key(),
                b"grouped-transfer DA cursor fixture",
            ),
        )
    };
    let mut cursors = DaShardCursorIndex::new(&block_batch.nexus.lane_config);
    let height = batch_header.height().get();
    cursors
        .advance(
            block_batch.nexus.lane_config.shard_id(second_lane),
            &record(second_lane),
            height,
        )
        .expect("later successful lane cursor");
    assert!(
        matches!(block_batch.validate_touched_lane_cursors(&cursors, height),
            Err(BlockValidationError::DaShardCursor(DaShardCursorError::MissingCursor {
                lane_id, block_height, ..
            })) if lane_id == first_lane && block_height == height
        )
    );
    cursors
        .advance(
            block_batch.nexus.lane_config.shard_id(first_lane),
            &record(first_lane),
            height,
        )
        .expect("earlier successful lane cursor");
    block_batch
        .validate_touched_lane_cursors(&cursors, height)
        .expect("both successful lanes are covered; rejected lane requires no cursor");
    block_batch.add_committed_fragments(1);
    assert_eq!(
        block_batch.committed_fragment_count(),
        batch_start_fragments + 2
    );
    let events_batch = block_batch.world.take_external_events();
    let transcripts_batch = block_batch.drain_transfer_transcripts();
    assert!(
        !transcripts_batch.contains_key(&rejected_call_hash),
        "rejected and dropped attempts must not publish transcripts"
    );
    let captured_sources = block_batch.captured_fastpq_transcript_sources().unwrap();
    assert!(captured_sources.contains_key(&call_hash));
    assert!(captured_sources.contains_key(&second_call_hash));
    assert_eq!(
        captured_sources[&second_call_hash].route(),
        iroha_data_model::fastpq::FastpqSourceRouteV1::Lane(
            iroha_data_model::fastpq::FastpqSourceLaneV1 {
                lane_id: second_lane,
                lane_incarnation: native_incarnation,
            },
        )
    );
    assert!(
        !captured_sources.contains_key(&rejected_call_hash),
        "rejected and dropped attempts must not publish source captures"
    );
    block_batch
        .commit_world_overlay_for_testing()
        .expect("commit batch detached block");
    assert_eq!(events_seq, events_det);
    assert_eq!(events_seq, events_existing_tx);
    assert_eq!(transcripts_seq, transcripts_det);
    assert_eq!(transcripts_seq, transcripts_existing_tx);
    assert_eq!(
        transcripts_seq.get(&call_hash),
        transcripts_batch.get(&call_hash)
    );
    assert!(
        transcripts_batch.contains_key(&second_call_hash),
        "second batch transfer should keep its own transaction call hash"
    );
    assert!(
        events_batch.len() > events_seq.len(),
        "two-transfer batch should preserve both transfers' event stream"
    );
    let (world_batch_guard, _, _) = build_transfer_world(Some(0));
    let kura_batch_guard = Kura::blank_kura_for_testing();
    let query_batch_guard = crate::query::store::LiveQueryStore::start_test();
    let state_batch_guard = State::new(
        world_batch_guard,
        Arc::clone(&kura_batch_guard),
        query_batch_guard,
    );
    let mut block_batch_guard = state_batch_guard.block(header);
    let mut batch_guard_tx = block_batch_guard.transaction();
    batch_guard_tx.world.add_account_permission(
        &ALICE_ID,
        iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
            authority: ALICE_ID.clone(),
        }
        .into(),
    );
    assert!(
        first_delta.supports_numeric_transfer_batch_merge(&batch_guard_tx),
        "preseeded receiver assets without matching data triggers should batch"
    );
    let executable = iroha_data_model::transaction::Executable::Instructions(
        iroha_primitives::const_vec::ConstVec::from(Vec::<InstructionBox>::new()),
    );
    let mut nonmatching_action =
        crate::smartcontracts::triggers::specialized::SpecializedAction::new(
            executable.clone(),
            Repeats::Indefinitely,
            ALICE_ID.clone(),
            data_pre::DataEventFilter::Configuration(data_pre::ConfigurationEventFilter::new()),
        )
        .expect("test data-trigger action satisfies its authority invariant");
    nonmatching_action.metadata =
        crate::smartcontracts::isi::triggers::global_data_trigger_scope_metadata_for_testing(
            &ALICE_ID,
        );
    batch_guard_tx
        .world
        .triggers
        .add_data_trigger(
            crate::smartcontracts::triggers::specialized::SpecializedTrigger::new(
                "nonmatching_transfer_batch_guard"
                    .parse()
                    .expect("trigger id"),
                nonmatching_action,
            ),
        )
        .expect("add nonmatching data trigger");
    assert!(
        first_delta.supports_numeric_transfer_batch_merge(&batch_guard_tx),
        "unrelated data triggers should not disable transfer batching"
    );
    let mut matching_action = crate::smartcontracts::triggers::specialized::SpecializedAction::new(
        executable,
        Repeats::Indefinitely,
        ALICE_ID.clone(),
        data_pre::DataEventFilter::Asset(data_pre::AssetEventFilter::new()),
    )
    .expect("test data-trigger action satisfies its authority invariant");
    matching_action.metadata =
        crate::smartcontracts::isi::triggers::global_data_trigger_scope_metadata_for_testing(
            &ALICE_ID,
        );
    batch_guard_tx
        .world
        .triggers
        .add_data_trigger(
            crate::smartcontracts::triggers::specialized::SpecializedTrigger::new(
                "matching_transfer_batch_guard".parse().expect("trigger id"),
                matching_action,
            ),
        )
        .expect("add matching data trigger");
    assert!(
        !first_delta.supports_numeric_transfer_batch_merge(&batch_guard_tx),
        "matching asset data triggers should keep per-transaction semantics"
    );
    drop(batch_guard_tx);
    assert_eq!(balance(&state_det, &alice_asset_id), Quantity::from(7_u32));
    assert_eq!(balance(&state_det, &bob_asset_id), Quantity::from(3_u32));
    assert_eq!(
        balance(&state_existing_tx, &alice_asset_id),
        Quantity::from(7_u32)
    );
    assert_eq!(
        balance(&state_existing_tx, &bob_asset_id),
        Quantity::from(3_u32)
    );
    assert_eq!(balance(state_batch, &alice_asset_id), Quantity::from(5_u32));
    assert_eq!(balance(state_batch, &bob_asset_id), Quantity::from(5_u32));
    assert_eq!(
        balance(&state_seq, &alice_asset_id),
        balance(&state_det, &alice_asset_id)
    );
    assert_eq!(
        balance(&state_seq, &bob_asset_id),
        balance(&state_det, &bob_asset_id)
    );
    assert_eq!(
        balance(&state_seq, &alice_asset_id),
        balance(&state_existing_tx, &alice_asset_id)
    );
    assert_eq!(
        balance(&state_seq, &bob_asset_id),
        balance(&state_existing_tx, &bob_asset_id)
    );
    let transcript = transcripts_det
        .get(&call_hash)
        .and_then(|entry| entry.first())
        .expect("detached transfer transcript recorded");
    let transfer_delta = transcript
        .deltas
        .first()
        .expect("single transfer delta recorded");
    assert_eq!(transfer_delta.from_balance_before, Quantity::from(10_u32));
    assert_eq!(transfer_delta.from_balance_after, Quantity::from(7_u32));
    assert_eq!(transfer_delta.to_balance_before, Quantity::zero());
    assert_eq!(transfer_delta.to_balance_after, Quantity::from(3_u32));
    assert!(transcript.poseidon_preimage_digest.is_some());
}
