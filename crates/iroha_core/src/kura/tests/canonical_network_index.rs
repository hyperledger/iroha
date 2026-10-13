use iroha_data_model::block::{BlockExecutionContextBundle, ExternalExecutionContext};
// Canonical Network index fixtures exercise structural membership, never mint execution/finality.
/// Attach structurally checked outputs under a finite, explicit storage-test policy.
pub(crate) fn install_network_index_test_outputs(
    block: &mut SignedBlock,
    outputs: Vec<iroha_data_model::block::execution_output::ExecutionOutputV1>,
) {
    use iroha_data_model::block::output_budget::ExecutionOutputLimits;
    // Explicit finite storage-fixture policy, not a runtime admission default.
    let limits = ExecutionOutputLimits {
        max_outputs: 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_total_output_bytes: 128 * 1024 * 1024,
        max_executed_wire_bytes: 256 * 1024 * 1024,
    };
    let fragments = u64::try_from(
        outputs
            .iter()
            .filter(|output| output.result().is_ok())
            .count(),
    )
    .expect("bounded storage fixture fragment count");
    let proposal = block
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection");
    block
        .set_execution_outputs(
            outputs,
            fragments,
            std::collections::BTreeMap::default(),
            Vec::new(),
            iroha_data_model::nexus::AxtPolicySnapshot::default(),
            std::collections::BTreeSet::default(),
            &limits,
        )
        .expect("canonical bounded storage-fixture outputs");
    assert_eq!(
        block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection"),
        proposal
    );
}

fn network_index_block_at(height: u64, inputs: Vec<TransactionEntrypoint>) -> SignedBlock {
    use iroha_data_model::block::builder::BlockBuilder as ModelBlockBuilder;
    let header = BlockHeader::new(
        height.try_into().unwrap(),
        (height > 1).then(|| HashOf::from_untyped_unchecked(Hash::new(b"index structural parent"))),
        None,
        100 + height,
        0,
    );
    let mut builder = ModelBlockBuilder::new(header);
    for input in inputs {
        match input {
            TransactionEntrypoint::External(tx) => builder.push_transaction(tx),
            TransactionEntrypoint::SealedReveal(reveal) => {
                builder.push_sealed_transaction_reveal(reveal)
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                builder.push_sealed_transaction_commitment(commitment)
            }
        };
    }
    let mut block = builder.build_with_signature(0, SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key());
    attach_ok_results_to_block(&mut block);
    block
}

fn network_index_signal_input(marker: u64) -> TransactionEntrypoint {
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;
    let mut metadata = Metadata::default();
    metadata.insert("kaigi_signal".parse().unwrap(), Json::new(norito::json!({
        "schema": "iroha-demo-kaigi-chain-signal/v1", "callId": (kaigi_signal_test_call("canonical-inputs").to_string())
    })));
    let mut tx = TransactionBuilder::new(
        test_network_id(b"canonical-index"),
        SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    tx.set_creation_time(std::time::Duration::from_millis(marker));
    TransactionEntrypoint::External(
        tx.with_metadata(metadata)
            .with_instructions([Log::new(Level::INFO, marker.to_string())])
            .sign(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key()),
    )
}

fn network_index_internal_output() -> iroha_data_model::block::execution_output::ExecutionOutputV1 {
    use iroha_data_model::{
        block::execution_output::*,
        events::time::{TimeEvent, TimeInterval},
    };
    let trigger_id: iroha_data_model::trigger::TriggerId = "index_timer".parse().unwrap();
    ExecutionOutputV1::Time(TimeExecutionOutputV1 {
        invocation: TimeInvocationV1 {
            schedule_index: 0,
            event: TimeEvent {
                interval: TimeInterval {
                    since_ms: 101,
                    length_ms: 1,
                },
            },
            trigger: TriggerUseV1 {
                trigger_id: trigger_id.clone(),
                registered_at_height: 1,
                action_hash: Hash::new(b"structural action"),
            },
        },
        result: iroha_data_model::transaction::TransactionResult::new(Ok(vec![
            iroha_data_model::trigger::DataTriggerStep {
                id: trigger_id,
                instructions: iroha_data_model::transaction::signed::ExecutionStep(
                    Vec::new().into(),
                ),
            },
        ])),
        failure_root: None,
        completions: Vec::new(),
    })
}

#[test]
fn canonical_network_index_joins_sealed_rejected_and_internal_outputs() {
    use iroha_data_model::{
        block::execution_output::ExecutionOutputV1, transaction::signed::SealedTransactionReveal,
    };
    let first = network_index_signal_input(1);
    let TransactionEntrypoint::External(signed) = network_index_signal_input(2) else {
        unreachable!()
    };
    let inner = signed.hash_as_entrypoint();
    let sealed = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"sealed source"),
        signed,
        [4; 32],
    ));
    let mut block = network_index_block_at(2, vec![first.clone(), sealed.clone()]);
    let mut outputs = block.execution_outputs().to_vec();
    let ExecutionOutputV1::Network(row) = &mut outputs[0] else {
        unreachable!()
    };
    row.result = iroha_data_model::transaction::TransactionResult::new(Err(
        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::NotPermitted("index fixture rejection".into()),
        ),
    ));
    outputs.push(network_index_internal_output());
    install_network_index_test_outputs(&mut block, outputs);
    let height = nonzero!(2_usize);
    let mut index = super::TransactionEntrypointIndex::complete_empty();
    Kura::insert_transaction_entrypoint_heights(&mut index, height, &block);
    assert!(index.indexed_heights.contains(&height));
    assert!(index.incomplete_heights.is_empty());
    assert_eq!(index.heights_by_entrypoint.len(), 2);
    assert!(index.heights_by_entrypoint.contains_key(&first.hash()));
    assert!(index.heights_by_entrypoint.contains_key(&sealed.hash()));
    assert!(!index.heights_by_entrypoint.contains_key(&inner));
    assert_eq!(
        index
            .heights_by_result_status
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [false, true]
    );
    let by_input =
        &index.kaigi_signal_candidates[&kaigi_signal_test_call("canonical-inputs")][&height];
    assert_eq!(
        by_input.len(),
        1,
        "rejected Network and internal Time are not signal candidates"
    );
    let locator = &by_input[&1];
    assert_eq!(locator.position.network_input_index(), 1);
    assert_eq!(locator.position.entrypoint_hash(), sealed.hash());
    assert_eq!(block.execution_outputs().len(), 3);
    assert_eq!(
        index.inventories_by_height[&height].entrypoint_hashes.len(),
        2
    );
    // Internal success must not introduce a successful Network result membership.
    let mut internal_only = network_index_block_at(2, Vec::new());
    install_network_index_test_outputs(&mut internal_only, vec![network_index_internal_output()]);
    Kura::insert_transaction_entrypoint_heights(&mut index, height, &internal_only);
    assert!(index.indexed_heights.contains(&height));
    assert!(index.heights_by_result_status.is_empty());
    assert!(index.heights_by_entrypoint.is_empty());
    assert!(index.kaigi_signal_candidates.is_empty());
}

#[test]
fn canonical_network_index_refuses_whole_malformed_carrier_before_membership() {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    let block = network_index_block_at(
        2,
        vec![network_index_signal_input(1), network_index_signal_input(2)],
    );
    let height = nonzero!(2_usize);
    for mutation in 0..6 {
        let mut value = norito::json::to_value(&block).unwrap();
        let result = value
            .as_object_mut()
            .unwrap()
            .get_mut("result")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let mut outputs = block.execution_outputs().to_vec();
        match mutation {
            0 => {
                outputs.pop();
            }
            1 => {
                let ExecutionOutputV1::Network(row) = &mut outputs[1] else {
                    unreachable!()
                };
                row.input_index = 0;
            }
            2 => {
                outputs[1] = network_index_internal_output();
            }
            3 => {
                outputs.swap(0, 1);
            }
            4 => {
                result.insert(
                    "output_merkle".into(),
                    norito::json::to_value(
                        &iroha_crypto::MerkleTree::<ExecutionOutputV1>::default(),
                    )
                    .unwrap(),
                );
            }
            _ => {}
        }
        if mutation < 4 {
            result.insert("outputs".into(), norito::json::to_value(&outputs).unwrap());
        }
        let malformed: SignedBlock = if mutation == 5 {
            block
                .canonical_resultless_proposal()
                .expect("valid fixture proposal projection")
        } else {
            norito::json::from_value(value).unwrap()
        };
        let mut index = super::TransactionEntrypointIndex::complete_empty();
        Kura::insert_transaction_entrypoint_heights(&mut index, height, &block);
        Kura::insert_transaction_entrypoint_heights(&mut index, height, &malformed);
        assert!(!index.complete);
        assert!(
            index.incomplete_heights.contains(&height),
            "mutation {mutation}"
        );
        assert!(index.indexed_heights.is_empty());
        assert!(index.heights_by_entrypoint.is_empty());
        assert!(index.heights_by_authority.is_empty());
        assert!(index.heights_by_timestamp_ms.is_empty());
        assert!(index.heights_by_result_status.is_empty());
        assert!(index.kaigi_signal_candidates.is_empty());
        assert!(index.inventories_by_height.is_empty());
        Kura::truncate_transaction_entrypoint_index_to(&mut index, 0);
        assert!(index.complete);
        assert!(index.incomplete_heights.is_empty());
    }
}

#[test]
fn canonical_network_index_rebuild_missing_body_and_replacement_stay_explicit() {
    let first = network_index_block_at(1, vec![network_index_signal_input(1)]);
    let second = network_index_block_at(2, vec![network_index_signal_input(2)]);
    let data: BlockData = [
        (first.hash(), Some(share_storage_fixture(first))),
        (second.hash(), None),
    ]
    .into_iter()
    .collect();
    let mut index = Kura::build_transaction_entrypoint_index(&data);
    assert!(!index.complete);
    assert_eq!(index.indexed_heights, BTreeSet::from([nonzero!(1_usize)]));
    assert!(index.incomplete_heights.contains(&nonzero!(2_usize)));
    Kura::insert_transaction_entrypoint_heights(&mut index, nonzero!(2_usize), &second);
    assert!(index.incomplete_heights.is_empty());
    let prior = second.network_entrypoint_at(0).unwrap().hash();
    let replacement = network_index_block_at(2, vec![network_index_signal_input(3)]);
    Kura::insert_transaction_entrypoint_heights(&mut index, nonzero!(2_usize), &replacement);
    assert!(!index.heights_by_entrypoint.contains_key(&prior));
    assert!(
        index
            .heights_by_entrypoint
            .contains_key(&replacement.network_entrypoint_at(0).unwrap().hash())
    );
    Kura::truncate_transaction_entrypoint_index_to(&mut index, 1);
    assert!(index.complete);
    assert_eq!(index.heights_by_entrypoint.len(), 1);
}

#[test]
fn canonical_network_position_roundtrips_and_refuses_retired_phase_layout() {
    #[derive(norito::Encode)]
    struct RetiredPosition {
        block_height: u64,
        execution_phase: u8,
        transaction_index: u64,
        block_hash: HashOf<BlockHeader>,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    }

    use norito::codec::{DecodeAll, Encode};
    let position = kaigi_signal_test_locator(3, 7).position;
    let bytes = norito::encode_canonical(&position).unwrap();
    assert_eq!(
        norito::decode_canonical::<super::KaigiSignalCandidatePosition>(&bytes).unwrap(),
        position
    );
    let old = RetiredPosition {
        block_height: 3,
        execution_phase: 1,
        transaction_index: 7,
        block_hash: position.block_hash(),
        entrypoint_hash: position.entrypoint_hash(),
    };
    assert!(super::KaigiSignalCandidatePosition::decode_all(&mut old.encode().as_slice()).is_err());
}

fn network_index_native_block() -> SignedBlock {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection};
    // This fixture tests structural indexing only. It never supplies finality authority.
    let mut block = network_index_block_at(3, vec![network_index_signal_input(7)]);
    let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
        block.network_entrypoint_at(0).unwrap().hash(),
        LaneId::new(2),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )]);
    context.lane_merge = Some(SumeragiLaneMergeSection {
        merges: vec![SumeragiLaneMerge {
            lane: LaneId::new(2),
            incarnation: [1; 32],
            from: 1,
            to: 1,
            tip_hash: [2; 32],
            tip_result: [3; 32],
        }],
        time_floor_ms: 8,
        merged_count: 1,
    });
    block.set_execution_context(Some(context));
    attach_ok_results_to_block(&mut block);
    block
}

#[test]
fn canonical_network_index_projects_merged_suffix_once_and_rejects_missing_outputs() {
    let block = network_index_native_block();
    assert_eq!(block.external_entrypoint_count(), 1);
    assert_eq!(block.network_entrypoint_count(), 1);
    let source = block.network_entrypoint_at(0).unwrap();
    let height = nonzero!(3_usize);
    let mut index = super::TransactionEntrypointIndex::complete_empty();
    Kura::insert_transaction_entrypoint_heights(&mut index, height, &block);
    assert!(index.incomplete_heights.is_empty());
    assert_eq!(
        index
            .heights_by_entrypoint
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [source.hash()]
    );
    let page = Kura::collect_kaigi_signal_candidate_locators(
        &index,
        &kaigi_signal_test_call("canonical-inputs"),
        3,
        None,
        nonzero!(1_usize),
    )
    .unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].position.network_input_index(), 0);
    assert_eq!(page.candidates[0].position.entrypoint_hash(), source.hash());

    // Direct inputs precede the merged suffix and both occupy ordinary Network rows.
    let mut combined = block.clone();
    let direct = network_index_signal_input(99);
    let mut context = combined.execution_context().unwrap().clone();
    context.external.insert(
        0,
        ExternalExecutionContext::new(
            direct.hash(),
            LaneId::SINGLE,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        ),
    );
    combined.set_external_entrypoints(vec![direct, source.clone()]);
    combined.set_execution_context(Some(context));
    attach_ok_results_to_block(&mut combined);
    Kura::insert_transaction_entrypoint_heights(&mut index, height, &combined);
    assert!(index.incomplete_heights.is_empty());
    assert_eq!(index.heights_by_entrypoint.len(), 2);
    let candidates =
        &index.kaigi_signal_candidates[&kaigi_signal_test_call("canonical-inputs")][&height];
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[&1].position.entrypoint_hash(), source.hash());

    // A removed or substituted original input cannot reuse previously complete output joins.
    for inputs in [Vec::new(), vec![network_index_signal_input(98)]] {
        let mut missing = block.clone();
        missing.set_external_entrypoints(inputs);
        Kura::insert_transaction_entrypoint_heights(&mut index, height, &missing);
        assert!(index.incomplete_heights.contains(&height));
        assert!(index.indexed_heights.is_empty());
        assert!(index.heights_by_entrypoint.is_empty());
        assert!(index.kaigi_signal_candidates.is_empty());
    }
}

/// Structural storage rows only; these outputs never confer execution or finality authority.
fn attach_ok_results_to_block(block: &mut SignedBlock) {
    use iroha_data_model::block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1};
    let outputs = (0..block.network_entrypoint_count())
        .map(|index| {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: u32::try_from(index).unwrap(),
                result: TransactionResult::new(Ok(DataTriggerSequence::default())),
                completions: Vec::new(),
            })
        })
        .collect();
    install_network_index_test_outputs(block, outputs);
}
