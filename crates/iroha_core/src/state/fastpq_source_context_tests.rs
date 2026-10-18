//! FASTPQ source provenance follows actual transaction apply and rollback boundaries.

use super::*;
use crate::{
    fastpq::{FastpqCapturedSourceRoute, FastpqSourceCaptureError},
    query::store::LiveQueryStore,
};
use iroha_data_model::{
    block::BlockHeader,
    fastpq::{FastpqSourceLaneV1, TransferSmtWitness},
    nexus::{LaneCatalog, LaneConfig},
    parameter::system::SumeragiParameters,
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord},
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use nonzero_ext::nonzero;

fn state() -> State {
    State::new(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn header() -> BlockHeader {
    BlockHeader::new(nonzero!(1_u64), None, None, 7, 0)
}

fn native_lane() -> SumeragiLaneRecord {
    SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: LaneId::new(1),
        dataspace: DataSpaceId::UNIVERSAL,
        incarnation: Hash::new(b"committed native lane incarnation").into(),
        params: SumeragiParameters::default(),
        committee: crate::sumeragi::test_chain::fixture_validators()
            .into_iter()
            .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
            .collect(),
        created_at: 1,
        active_from: 3,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 3,
        rescued: 0,
    }
}

// These component fixtures select the committed owner that source capture reads.
// Signed policy creation and lane certificates are covered by the Kagami fixture.
fn native_state(record: Option<SumeragiLaneRecord>, nexus_secondary: bool) -> State {
    let world = World::default();
    if let Some(record) = record {
        let mut block = world.block();
        block.sumeragi_lanes.get_mut().upsert(record);
        block.commit();
    }
    if nexus_secondary {
        State::new_with_pre_genesis_nexus_for_testing(
            world,
            iroha_config::parameters::actual::Nexus {
                lane_catalog: LaneCatalog::new(
                    nonzero!(2_u32),
                    vec![
                        LaneConfig::default(),
                        LaneConfig {
                            id: LaneId::new(1),
                            alias: "separate-nexus-lane".to_owned(),
                            ..LaneConfig::default()
                        },
                    ],
                )
                .unwrap(),
                ..Default::default()
            },
            LiveQueryStore::start_test(),
        )
    } else {
        State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }
}

fn native_header(height: u64) -> BlockHeader {
    BlockHeader::new(height.try_into().unwrap(), None, None, 7, 0)
}

fn delta() -> TransferDeltaTranscript {
    TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        ),
        amount: Quantity::from(1_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(9_u32),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(1_u32),
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    }
}

#[test]
fn native_lane_source_uses_its_committed_incarnation_without_a_physical_catalog_entry() {
    use crate::sumeragi::test_chain::{
        CertifiedTestChain, Signers, TestChainConfig, fixture_validators,
    };
    use iroha_data_model::{
        isi::{Register, SetKeyValue},
        parameter::Parameter,
        sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
        },
    };
    use iroha_test_samples::ALICE_KEYPAIR;

    let lane = LaneId::new(2);
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 16,
        max_merge_blocks: 8,
        stall_window: 100,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane,
            dataspace: DataSpaceId::UNIVERSAL,
            committee: fixture_validators()
                .into_iter()
                .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
                .collect(),
        }],
        routes: vec![SumeragiLaneRoute {
            lane,
            account: Some(ALICE_ID.to_string()),
            instruction: None,
        }],
        autoscale: None,
    };
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config
        .genesis_instructions
        .push(Register::account(Account::new(ALICE_ID.clone())).into());
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
    let mut chain = CertifiedTestChain::start(config).expect("original native lane policy");
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let original = chain
        .state()
        .view()
        .world()
        .sumeragi_lanes()
        .lane(lane)
        .unwrap()
        .clone();
    assert!(original.admits_anchor(chain.height()));
    assert!(
        !chain
            .state()
            .nexus_snapshot()
            .lane_catalog
            .lanes()
            .iter()
            .any(|entry| entry.id == lane)
    );
    let expected = Hash::from_marked_bytes(original.incarnation).expect("exact native chain hash");
    let transaction = chain.sign(
        &ALICE_KEYPAIR,
        [SetKeyValue::account(
            ALICE_ID.clone(),
            "native_source".parse().unwrap(),
            Json::new(1_u32),
        )
        .into()],
        chain.committed(chain.height()).block_time_ms(),
    );
    let proposal = chain.proposal(None, vec![transaction]);
    let mut pending = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .expect("native routed execution has its original frozen source");
    pending
        .inspect(move |execution| {
            let inventory = execution.state.fastpq_source_inventory().unwrap().unwrap();
            assert_eq!(inventory.entries().len(), 1);
            assert_eq!(
                inventory.entries()[0].route,
                iroha_data_model::fastpq::FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id: lane,
                    lane_incarnation: expected
                },)
            );
            let result = &execution
                .block
                .as_ref()
                .network_output_at(0)
                .unwrap()
                .1
                .result;
            assert!(
                result.is_ok(),
                "original native execution rejected: {result:?}"
            );
        })
        .unwrap();
    pending
        .publish(Signers::Quorum)
        .expect("publish the original native source");
}

#[test]
fn native_source_freezes_original_activation_closing_and_incarnation() {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneState};

    let state = state();
    let lane = LaneId::new(7);
    let original = Hash::new(b"original native incarnation");
    let record = SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane,
        dataspace: DataSpaceId::UNIVERSAL,
        incarnation: original.into(),
        params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        committee: Vec::new(),
        created_at: 10,
        active_from: 12,
        closing: Some(20),
        anchor_freshness: 16,
        merged: iroha_data_model::sumeragi_lanes::SumeragiLaneFrontier::default(),
        merged_at: 12,
        rescued: 0,
    };
    let native = SumeragiLaneState {
        lanes: vec![record],
        ..Default::default()
    };
    let mut lanes = state.world.sumeragi_lanes.block();
    *lanes.get_mut() = native.clone();
    lanes.commit();
    for (height, expected) in [
        (12, None),
        (13, Some(original)),
        (20, Some(original)),
        (21, None),
    ] {
        let mut block = state.block(BlockHeader::new(
            NonZeroU64::new(height).unwrap(),
            None,
            None,
            height,
            0,
        ));
        let captured = Arc::clone(block.fastpq_source_context.as_ref().unwrap());
        assert_eq!(
            captured.lane_incarnations.get(&lane).copied().flatten(),
            expected
        );
        assert!(captured.lane_incarnations[&LaneId::SINGLE].is_some());
        let mut changed = native.clone();
        changed.lanes[0].incarnation = Hash::new(b"later incarnation").into();
        changed.lanes[0].active_from = 1;
        changed.lanes[0].closing = None;
        *block.world.sumeragi_lanes.get_mut() = changed;
        assert_eq!(
            captured.lane_incarnations.get(&lane).copied().flatten(),
            expected,
            "later overlay effects cannot alter the original source-height capture"
        );
    }
}

#[test]
fn source_records_publish_only_on_apply_and_survive_transcript_drain() {
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"execution call");
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
    }
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(block.fastpq_transcripts.is_empty());
    let first_fragment = block.committed_fragments as u64;
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_lane_id = Some(LaneId::SINGLE);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.apply();
    }
    let captured = block.captured_fastpq_transcript_sources().unwrap()[&hash];
    assert_eq!(captured.entry_hash(), hash);
    assert_eq!(captured.source().network_id, state.network_id);
    assert_eq!(captured.source().height, 1);
    assert_eq!(captured.first_fragment_index(), first_fragment);
    assert!(!captured.is_protocol_purpose());
    assert_eq!(block.drain_transfer_transcripts().len(), 1);
    assert_eq!(
        block.captured_fastpq_transcript_sources().unwrap()[&hash],
        captured
    );
}

#[test]
fn source_incarnation_is_frozen_before_block_and_transaction_lane_mutation() {
    let state = state();
    let mut block = state.block(header());
    let original = StateReadOnly::lane_incarnation_at_height(&block, LaneId::SINGLE, 1).unwrap();
    let hash = Hash::new(b"execution call");
    let mut changed: [u8; 32] = original.into();
    changed[20] ^= 1;
    block
        .lane_incarnations
        .insert(LaneId::SINGLE, Hash::prehashed(changed));
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_lane_id = Some(LaneId::SINGLE);
        tx.current_dataspace_id = Some(DataSpaceId::new(7));
        tx.lane_incarnations
            .insert(LaneId::SINGLE, Hash::new(b"later transaction mutation"));
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        // A later caller-context change cannot rewrite the previously captured occurrence.
        tx.current_dataspace_id = Some(DataSpaceId::new(8));
        tx.apply();
    }
    assert_eq!(
        block.captured_fastpq_transcript_sources().unwrap()[&hash].route(),
        FastpqCapturedSourceRoute::Lane(FastpqSourceLaneV1 {
            lane_id: LaneId::SINGLE,
            lane_incarnation: original,
        })
    );
    assert_eq!(
        block.captured_fastpq_transcript_sources().unwrap()[&hash].dataspace_id(),
        DataSpaceId::new(7)
    );
}

#[test]
fn native_protocol_purposes_keep_distinct_keys_and_explicit_absent_lane() {
    let state = state();
    let mut block = state.block(header());
    let hashes = [
        Hash::new(b"typed purpose one"),
        Hash::new(b"typed purpose two"),
    ];
    let fragment = block.committed_fragments as u64;
    {
        let mut tx = block.transaction_for_fastpq_protocol_testing();
        tx.current_dataspace_id = Some(DataSpaceId::new(7));
        for hash in hashes {
            tx.record_test_transfer_transcripts(&ALICE_ID, hash, vec![delta()]);
        }
        tx.apply();
    }
    let sources = block.captured_fastpq_transcript_sources().unwrap();
    assert_eq!(sources.len(), 2);
    for hash in hashes {
        let captured = sources[&hash];
        assert!(captured.is_protocol_purpose());
        assert_eq!(captured.entry_hash(), hash);
        assert_eq!(captured.first_fragment_index(), fragment);
        assert_eq!(captured.route(), FastpqCapturedSourceRoute::Unrouted);
        assert_eq!(captured.dataspace_id(), DataSpaceId::new(7));
        assert_eq!(block.fastpq_transcripts[&hash][0].batch_hash, hash);
    }
}

#[test]
fn discarded_conflicts_do_not_poison_block_but_applied_conflicts_hide_partial_map() {
    let state = state();
    let mut block = state.block(header());
    let hash = Hash::new(b"execution call");
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.current_dataspace_id = Some(DataSpaceId::new(7));
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
    }
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.apply();
    }
    assert_eq!(block.captured_fastpq_transcript_sources().unwrap().len(), 1);
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_dataspace_id = Some(DataSpaceId::new(7));
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.apply();
    }
    assert_eq!(
        block.captured_fastpq_transcript_sources(),
        Err(&FastpqSourceCaptureError::ConflictingSource { entry_hash: hash })
    );
}

#[test]
fn unresolved_lane_refuses_apply_and_later_valid_capture_cannot_unpoison_carrier() {
    let state = state();
    let mut block = state.merge_preexecution_block(header());
    let missing = LaneId::new(999);
    let bad = Hash::new(b"bad call");
    let good = Hash::new(b"good call");
    block.admit_fastpq_source_for_testing(bad);
    block.admit_fastpq_source_for_testing(good);
    {
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(bad);
        tx.current_lane_id = Some(missing);
        let error = tx
            .record_transfer_transcript(&ALICE_ID, delta())
            .unwrap_err();
        assert!(error.to_string().contains(&missing.to_string()));
        assert!(tx.pending_transfer_transcripts.is_empty());
        tx.apply();
    }
    assert!(block.fastpq_transcripts.is_empty());
    assert!(matches!(
        block.execution_output_plan,
        Some(output_capacity::ExecutionOutputPlanState::Poisoned)
    ));
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut tx = block.transaction();
        tx.tx_call_hash = Some(good);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.apply();
    }));
    assert!(
        refused.is_err(),
        "poisoned original cannot reacquire a child"
    );
    assert!(block.fastpq_transcripts.is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        block.execution_output_plan,
        Some(output_capacity::ExecutionOutputPlanState::Poisoned)
    ));
}

#[test]
fn batched_calls_keep_their_captured_context_when_apply_clears_active_call() {
    let state = state();
    let mut block = state.block(header());
    let hashes = [
        Hash::new(b"batch first call"),
        Hash::new(b"batch second call"),
    ];
    for hash in hashes {
        block.admit_fastpq_source_for_testing(hash);
    }
    {
        let mut tx = block.transaction();
        for (index, hash) in hashes.iter().enumerate() {
            tx.tx_call_hash = Some(*hash);
            tx.current_dataspace_id = Some(DataSpaceId::new(index as u64));
            tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        }
        tx.tx_call_hash = None;
        tx.apply();
    }
    let sources = block.captured_fastpq_transcript_sources().unwrap();
    assert_eq!(sources.len(), 2);
    for (index, hash) in hashes.iter().enumerate() {
        assert_eq!(sources[hash].dataspace_id(), DataSpaceId::new(index as u64));
        assert!(!sources[hash].is_protocol_purpose());
        assert_eq!(block.fastpq_transcripts[hash][0].batch_hash, *hash);
    }
}

#[test]
fn changing_the_apply_bucket_after_recording_invalidates_source_capture() {
    let state = state();
    let mut block = state.block(header());
    {
        let mut tx = block.transaction_for_fastpq_testing(Hash::new(b"recorded call"));
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.tx_call_hash = Some(Hash::new(b"different apply bucket"));
        tx.apply();
    }
    assert_eq!(
        block.captured_fastpq_transcript_sources(),
        Err(&FastpqSourceCaptureError::ExecutionIdentityMismatch)
    );
}

#[test]
fn normal_and_replacement_scopes_freeze_incarnation_before_pristine_stage() {
    fn mutate_stage(block: &mut StateBlock<'_>) -> Result<(), core::convert::Infallible> {
        block
            .lane_incarnations
            .insert(LaneId::SINGLE, Hash::new(b"pristine stage mutation"));
        Ok(())
    }
    let state = state();
    let original = {
        let probe = state.merge_preexecution_block(header());
        StateReadOnly::lane_incarnation_at_height(&probe, LaneId::SINGLE, 1).unwrap()
    };
    for replacement in [false, true] {
        let mut block = if replacement {
            state
                .block_and_revert_with_pristine_stage(header(), mutate_stage)
                .unwrap()
        } else {
            state
                .block_with_pristine_stage(header(), mutate_stage)
                .unwrap()
        };
        let hash = Hash::new(b"staged call");
        {
            let mut tx = block.transaction_for_fastpq_testing(hash);
            tx.current_lane_id = Some(LaneId::SINGLE);
            tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
            tx.apply();
        }
        assert_eq!(
            block.captured_fastpq_transcript_sources().unwrap()[&hash].route(),
            FastpqCapturedSourceRoute::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::SINGLE,
                lane_incarnation: original
            })
        );
    }
}

#[test]
fn native_source_uses_exact_committed_incarnation_without_nexus_fallback() {
    let record = native_lane();
    let original = Hash::from_marked_bytes(record.incarnation).unwrap();
    for nexus_secondary in [false, true] {
        let state = native_state(Some(record.clone()), nexus_secondary);
        let mut block = state.merge_preexecution_block(native_header(4));
        let separate = StateReadOnly::lane_incarnation_at_height(&block, record.lane, 4);
        assert_eq!(separate.is_some(), nexus_secondary);
        assert_ne!(separate, Some(original));
        let hash = Hash::new(b"native source owner");
        {
            let mut tx = block.transaction_for_fastpq_testing(hash);
            tx.current_lane_id = Some(record.lane);
            tx.current_dataspace_id = Some(record.dataspace);
            tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
            tx.apply();
        }
        let captured = block.captured_fastpq_transcript_sources().unwrap()[&hash];
        assert_eq!(
            captured.route(),
            FastpqCapturedSourceRoute::Lane(FastpqSourceLaneV1 {
                lane_id: record.lane,
                lane_incarnation: original,
            })
        );
        assert_eq!(captured.dataspace_id(), record.dataspace);
    }
}

#[test]
fn native_source_uses_routing_parent_anchor_and_refuses_invalid_identity() {
    for (height, closing, marked, admitted) in [
        (3, None, true, false),
        (4, None, true, true),
        (7, Some(7), true, true),
        (8, Some(7), true, false),
        (4, None, false, false),
    ] {
        let mut record = native_lane();
        record.closing = closing;
        if !marked {
            record.incarnation[31] &= !1;
            assert_ne!(record.incarnation, [0; 32]);
        }
        let state = native_state(Some(record.clone()), false);
        let mut block = state.merge_preexecution_block(native_header(height));
        let hash = Hash::new(b"native source admission boundary");
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_lane_id = Some(record.lane);
        let result = tx.record_transfer_transcript(&ALICE_ID, delta());
        assert_eq!(result.is_ok(), admitted, "height={height}, marked={marked}");
        if !admitted {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("no frozen active incarnation")
            );
        }
        tx.apply();
        assert_eq!(block.fastpq_transcripts.contains_key(&hash), admitted);
    }
}

#[test]
fn missing_native_record_cannot_use_a_configured_nexus_lane() {
    // A retired lane has no native record, even if another subsystem retains
    // a Nexus lane with the same numeric id.
    let state = native_state(None, true);
    let mut block = state.merge_preexecution_block(native_header(4));
    assert!(StateReadOnly::lane_incarnation_at_height(&block, LaneId::new(1), 4).is_some());
    let hash = Hash::new(b"missing native lane");
    let mut tx = block.transaction_for_fastpq_testing(hash);
    tx.current_lane_id = Some(LaneId::new(1));
    assert!(tx.record_transfer_transcript(&ALICE_ID, delta()).is_err());
    tx.apply();
    assert!(block.fastpq_transcripts.is_empty());
    assert!(matches!(
        block.execution_output_plan,
        Some(output_capacity::ExecutionOutputPlanState::Poisoned)
    ));
}

#[test]
fn native_incarnation_is_frozen_before_world_and_transaction_mutation() {
    let record = native_lane();
    let original = Hash::from_marked_bytes(record.incarnation).unwrap();
    let state = native_state(Some(record.clone()), false);
    let mut block = state.merge_preexecution_block(native_header(4));
    block
        .world
        .sumeragi_lanes
        .get_mut()
        .lane_mut(record.lane)
        .unwrap()
        .incarnation = Hash::new(b"later block native incarnation").into();
    let hash = Hash::new(b"frozen native source");
    {
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.world
            .sumeragi_lanes
            .get_mut()
            .lane_mut(record.lane)
            .unwrap()
            .incarnation = Hash::new(b"later transaction native incarnation").into();
        tx.current_lane_id = Some(record.lane);
        tx.record_transfer_transcript(&ALICE_ID, delta()).unwrap();
        tx.apply();
    }
    assert_eq!(
        block.captured_fastpq_transcript_sources().unwrap()[&hash].route(),
        FastpqCapturedSourceRoute::Lane(FastpqSourceLaneV1 {
            lane_id: record.lane,
            lane_incarnation: original,
        })
    );
}

#[test]
fn normal_and_replacement_scopes_do_not_admit_native_lanes_created_after_freeze() {
    fn create_stage(block: &mut StateBlock<'_>) -> Result<(), core::convert::Infallible> {
        block.world.sumeragi_lanes.get_mut().upsert(native_lane());
        Ok(())
    }
    let state = state();
    for replacement in [false, true] {
        let mut block = if replacement {
            state
                .block_and_revert_with_pristine_stage(native_header(4), create_stage)
                .unwrap()
        } else {
            state
                .block_with_pristine_stage(native_header(4), create_stage)
                .unwrap()
        };
        assert!(
            block
                .world
                .sumeragi_lanes
                .get()
                .lane(LaneId::new(1))
                .is_some()
        );
        let hash = Hash::new(b"native lane created after capture");
        let mut tx = block.transaction_for_fastpq_testing(hash);
        tx.current_lane_id = Some(LaneId::new(1));
        assert!(tx.record_transfer_transcript(&ALICE_ID, delta()).is_err());
        tx.apply();
        assert!(block.fastpq_transcripts.is_empty());
    }
}
