//! Exact native replay-source checks over structural output fixtures with genuine BLS QCs.
//! These tests authenticate joins, completions and executed bytes; they do not execute a World.

use super::*;
use iroha_crypto::Hash;
use iroha_data_model::{
    ValidationFail,
    asset::{AssetDefinitionId, AssetId},
    block::{
        BlockPayload, BlockResult, BlockSignature, builder::BlockBuilder, execution_output::*,
        output_budget::ExecutionOutputLimits,
    },
    events::{
        data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferOutcome},
        time::{TimeEvent, TimeInterval},
        trigger_completed::TriggerCompletedOutcome,
    },
    fastpq::TransferTranscript,
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionEntrypoint,
        error::TransactionRejectionReason,
        signed::{ExecutionStep, SealedTransactionReveal, TransactionResult},
    },
    trigger::{DataTriggerStep, TriggerId},
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use norito::codec::{DecodeAll, Encode};
use std::time::Duration;

fn limits() -> ExecutionOutputLimits {
    ExecutionOutputLimits {
        max_outputs: 32,
        max_output_bytes: 64 * 1024,
        max_total_output_bytes: 256 * 1024,
        max_executed_wire_bytes: 1024 * 1024,
    }
}

fn install(block: &mut SignedBlock, outputs: Vec<ExecutionOutputV1>) {
    let fragments = block.committed_fragment_count().unwrap_or(3);
    let transcripts = if block.has_results() {
        block.fastpq_transcripts().clone()
    } else {
        std::collections::BTreeMap::default()
    };
    let envelopes = block.axt_envelopes().unwrap_or_default().to_vec();
    let policy = block.axt_policy_snapshot().cloned().unwrap_or_default();
    let transitions = block
        .axt_transitioned_dataspaces()
        .cloned()
        .unwrap_or_default();
    block
        .set_execution_outputs(
            outputs,
            fragments,
            transcripts,
            envelopes,
            policy,
            transitions,
            &limits(),
        )
        .expect("structural output fixture fits explicit limits");
}

fn fixture() -> Fixture {
    fixture_with(|_| {})
}

fn fixture_with(edit: impl FnOnce(&mut SignedBlock)) -> Fixture {
    let mut native = NativeFinalityFixture::start("native-replay-output-custody");
    let signed = |millis| {
        let mut transaction = TransactionBuilder::new(
            native.network_id(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        transaction.set_creation_time(Duration::from_millis(millis));
        transaction.sign(ALICE_KEYPAIR.private_key())
    };
    let mut builder = BlockBuilder::new(native.next_header());
    builder.push_transaction(signed(1));
    builder.push_sealed_transaction_reveal(SealedTransactionReveal::new(
        Hash::new(b"structural sealed commitment"),
        signed(2),
        [7; 32],
    ));
    let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    let mut outputs = (0..2)
        .map(|input_index| {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index,
                result: TransactionResult::new(Ok(Vec::new())),
                completions: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    let trigger = |id: &str| TriggerUseV1 {
        trigger_id: id.parse().unwrap(),
        registered_at_height: 1,
        action_hash: Hash::new(id.as_bytes()),
    };
    let trace = |id: &TriggerId| {
        TransactionResult::new(Ok(vec![DataTriggerStep {
            id: id.clone(),
            instructions: ExecutionStep(Vec::new().into()),
        }]))
    };
    let completion = |id: &TriggerId| {
        vec![InvocationCompletionV1 {
            callback_index: 0,
            trigger_id: id.clone(),
            outcome: TriggerCompletedOutcome::Success,
        }]
    };
    let pipeline = trigger("replay_pipeline");
    outputs.push(ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
        invocation: PipelineInvocationV1 {
            event: PipelineEventPositionV1::BlockApproved,
            candidate_index: 0,
            trigger: pipeline.clone(),
        },
        result: trace(&pipeline.trigger_id),
        failure_root: None,
        completions: completion(&pipeline.trigger_id),
    }));
    let timer = trigger("replay_timer");
    for schedule_index in [0, 1] {
        outputs.push(ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: TimeInvocationV1 {
                schedule_index,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 1,
                        length_ms: 1,
                    },
                },
                trigger: timer.clone(),
            },
            result: trace(&timer.trigger_id),
            failure_root: None,
            completions: completion(&timer.trigger_id),
        }));
    }
    install(&mut block, outputs);
    edit(&mut block);
    native.certify(block);
    super::fixture_from_native(&native)
}

#[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
#[norito_schema(
    name = "iroha_core::sumeragi::block_store::tests::replay_outputs::MutableReplayBlock"
)]
struct MutableReplayBlock {
    signatures: iroha_data_model::block::BlockSignatures,
    payload: BlockPayload,
    result: Option<BlockResult>,
    commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
}

fn mutate(block: &SignedBlock, change: impl FnOnce(&mut MutableReplayBlock)) -> SignedBlock {
    let mut raw = MutableReplayBlock::decode_all(&mut block.encode().as_slice()).unwrap();
    change(&mut raw);
    SignedBlock::decode_all(&mut raw.encode().as_slice()).unwrap()
}

fn receipt() -> AssetBatchTransferOutcome {
    let definition = AssetDefinitionId::derive_from_components(
        DomainId::try_new("replay-parity", "universal").unwrap(),
        "coin".parse().unwrap(),
    );
    AssetBatchTransferOutcome {
        leg_index: 0,
        leg_id: "retained-leg".into(),
        asset: AssetId::new(definition, ALICE_ID.clone()),
        destination: ALICE_ID.clone(),
        amount: 1_u32.into(),
        status: AssetBatchTransferLegStatus::Applied,
    }
}

/// Exercise the actual retained reader, including certificate custody and exact source selection.
/// Keep complete transient block/certificate construction outside the decoder caller frame.
#[inline(never)]
fn read(fixture: &Fixture, block: &SignedBlock, height: u64) -> CommittedRead {
    let budget = &fixture.store.execution_budget;
    let certificate = block
        .commit_certificate()
        .unwrap()
        .clone()
        .admit(budget)
        .unwrap();
    let original = block.clone().with_commit_certificate(Some(certificate));
    let original = iroha_data_model::block::SharedSignedBlock::reserve(budget)
        .unwrap()
        .initialize(original);
    CommittedRead::new(
        original,
        height,
        budget.clone(),
        fixture.store.hasher.clone(),
        fixture.schedule.clone(),
        fixture.store.root_scope,
    )
}

fn invalid_data(error: Attempt<io::Error>) -> io::Error {
    let Attempt::Rejected(error) = error else {
        panic!("malformed source must be rejected, not deferred: {error}");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    error
}

fn original_read(fixture: &Fixture) {
    let retained = fixture.store.execution_budget.reserved_bytes();
    {
        let (body, qc) = read(fixture, &fixture.executed, 2).poll().unwrap();
        assert!(body.admitted_to(&fixture.store.execution_budget));
        assert_eq!(body.source(), fixture.body.source());
        assert_eq!(body, fixture.body);
        assert_eq!(qc, fixture.qc);
        let metadata = read(fixture, &fixture.executed, 2).poll_metadata().unwrap();
        assert_eq!(metadata.manifest.header, *fixture.body.header());
        assert_eq!(metadata.manifest.availability, *fixture.body.availability());
        assert_eq!(metadata.commit_qc, fixture.qc);
    }
    assert_eq!(fixture.store.execution_budget.reserved_bytes(), retained);
}

/// Check both the direct native guard and its real retained committed-read caller.
fn reject_changed(fixture: &Fixture, changed: &SignedBlock) -> io::Error {
    assert_eq!(
        changed.commit_certificate(),
        fixture.executed.commit_certificate()
    );
    let direct = invalid_data(execution::validate(changed, fixture.store.root_scope).unwrap_err());
    let retained = fixture.store.execution_budget.reserved_bytes();
    {
        let mut reader = read(fixture, changed, 2);
        for _ in 0..2 {
            let error = invalid_data(reader.poll().unwrap_err());
            assert_eq!(error.to_string(), direct.to_string());
        }
        let mut metadata = read(fixture, changed, 2);
        for _ in 0..2 {
            let error = invalid_data(metadata.poll_metadata().unwrap_err());
            assert_eq!(error.to_string(), direct.to_string());
        }
    }
    assert_eq!(fixture.store.execution_budget.reserved_bytes(), retained);
    assert_eq!(fixture.store.height(), 1);
    original_read(fixture);
    direct
}

#[test]
fn full_parity_keeps_unequal_source_output_counts_and_distinct_time_calls() {
    let f = fixture();
    let block = f.executed.as_ref();
    assert_eq!(block.network_entrypoint_count(), 2);
    assert_eq!(block.execution_outputs().len(), 5);
    assert_eq!(block.network_output_at(1).unwrap().1.input_index, 1);
    assert!(block.network_output_at(2).is_none());
    let outputs = block.execution_outputs();
    assert_eq!(
        outputs[3].result(),
        outputs[4].result(),
        "equal displayed Time programs"
    );
    assert_ne!(
        outputs[3].execution_call_hash(block.hash(), block).unwrap(),
        outputs[4].execution_call_hash(block.hash(), block).unwrap()
    );
    execution::validate(block, f.store.root_scope).unwrap();
    original_read(&f);
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body, f.body);
    assert_eq!(qc, f.qc);
    let stored = f
        .store
        .kura
        .get_block(NonZeroUsize::new(2).unwrap(), &f.store.execution_budget)
        .unwrap()
        .unwrap();
    assert_eq!(stored.encode_wire().unwrap(), block.encode_wire().unwrap());
}

#[test]
fn stale_cache_and_malformed_joins_fail_on_both_comparison_sides() {
    let f = fixture();
    let block = f.executed.as_ref();
    for attack in 0..5 {
        let corrupted = mutate(block, |raw| {
            let result = raw.result.as_mut().unwrap();
            match attack {
                0 => {
                    let ExecutionOutputV1::Network(row) = &mut result.outputs[0] else {
                        unreachable!()
                    };
                    row.result =
                        TransactionResult::new(Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted("stale leaf".into()),
                        )));
                }
                1 => {
                    result.outputs.remove(0);
                }
                2 => {
                    result.outputs.swap(1, 2);
                }
                3 => {
                    let ExecutionOutputV1::Network(row) = &mut result.outputs[1] else {
                        unreachable!()
                    };
                    row.input_index = 0;
                }
                _ => raw.payload.external_entrypoints.swap(0, 1),
            }
        });
        let cache_error = corrupted.validate_output_merkle_cache().unwrap_err();
        let error = reject_changed(&f, &corrupted);
        if attack == 4 {
            assert_eq!(
                error.to_string(),
                "proposal header commitments differ from their actual payload"
            );
        } else {
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<iroha_crypto::MerkleError>(),
                Some(&cache_error)
            );
        }
        // The former two-side comparison now covers both actual native boundaries:
        // the stored-frame consumer above and the replayed-result commitment producer.
        let replayed = corrupted.with_commit_certificate(None);
        let transition = crate::sumeragi::commitment::WorldStateTransition {
            parent_world_state_root: Hash::new(b"structural replay parent World"),
            world_state_root: Hash::new(b"structural replay World"),
            event_commitment: None,
        };
        let error = crate::sumeragi::commitment::execution_commitment(
            &iroha_data_model::block::consensus::ExecWitness::default(),
            &replayed,
            &transition,
        )
        .unwrap_err();
        assert!(
            matches!(error, iroha_data_model::sumeragi_finality::CommitmentError::InvalidOutputs(reason)
            if reason == cache_error.to_string())
        );
    }
}

#[test]
fn checked_changed_rows_preserve_proposal_but_fail_complete_output_parity() {
    let f = fixture();
    let original = f.executed.as_ref();
    for attack in 0..5 {
        let mut changed = original.clone();
        let mut outputs = changed.execution_outputs().to_vec();
        match attack {
            0 => {
                let ExecutionOutputV1::Network(row) = &mut outputs[0] else {
                    unreachable!()
                };
                row.result.set_batch_transfer_outcomes(vec![receipt()]);
            }
            1 => {
                let ExecutionOutputV1::Network(row) = &mut outputs[0] else {
                    unreachable!()
                };
                row.completions.push(InvocationCompletionV1 {
                    callback_index: 0,
                    trigger_id: "changed_callback".parse().unwrap(),
                    outcome: TriggerCompletedOutcome::Success,
                });
            }
            2 => {
                let ExecutionOutputV1::Pipeline(row) = &mut outputs[2] else {
                    unreachable!()
                };
                row.invocation.trigger.action_hash = Hash::new(b"different action");
            }
            3 => {
                outputs.pop();
            }
            _ => {
                let ExecutionOutputV1::Time(row) = &mut outputs[4] else {
                    unreachable!()
                };
                row.invocation.schedule_index = 2;
            }
        }
        install(&mut changed, outputs);
        changed.validate_output_merkle_cache().unwrap();
        assert_eq!(changed.header(), original.header());
        assert_eq!(
            changed.canonical_resultless_proposal().unwrap(),
            original.canonical_resultless_proposal().unwrap()
        );
        assert_eq!(changed.hash(), original.hash());
        assert_ne!(
            changed.encode_wire().unwrap(),
            original.encode_wire().unwrap()
        );
        assert_ne!(
            changed.output_merkle_commitment(),
            original.output_merkle_commitment()
        );
        assert_ne!(changed.execution_outputs(), original.execution_outputs());
        if attack == 3 {
            assert_eq!(changed.execution_outputs().len(), 4);
            assert_eq!(
                changed.execution_outputs(),
                &original.execution_outputs()[..4]
            );
            assert!(changed.execution_outputs().get(4).is_none());
            assert!(original.execution_outputs().get(4).is_some());
        }
        let error = reject_changed(&f, &changed);
        assert_eq!(
            error.to_string(),
            "executed block differs from its certified result commitment"
        );
    }
}

#[test]
fn metadata_outside_output_merkle_is_part_of_replay_parity() {
    let f = fixture();
    let original = f.executed.as_ref();
    for attack in 0..3 {
        let changed = mutate(original, |raw| {
            let result = raw.result.as_mut().unwrap();
            match attack {
                0 => result.committed_fragment_count += 1,
                1 => {
                    let call = Hash::new(b"structurally valid additional protocol call");
                    result.fastpq_transcripts.insert(
                        call,
                        vec![TransferTranscript {
                            batch_hash: call,
                            deltas: Vec::new(),
                            authority_digest: Hash::new(b"changed"),
                            poseidon_preimage_digest: None,
                        }],
                    );
                }
                _ => {
                    result
                        .axt_transitioned_dataspaces
                        .insert(DataSpaceId::new(9));
                }
            }
        });
        changed.validate_output_merkle_cache().unwrap();
        assert_eq!(
            changed.output_merkle_commitment(),
            original.output_merkle_commitment()
        );
        assert_eq!(changed.execution_outputs(), original.execution_outputs());
        assert_ne!(
            changed.encode_wire().unwrap(),
            original.encode_wire().unwrap()
        );
        assert_ne!(
            changed.executed_block_wire_identity().unwrap(),
            original.executed_block_wire_identity().unwrap()
        );
        match attack {
            0 => assert_eq!(
                changed.committed_fragment_count(),
                original.committed_fragment_count().map(|count| count + 1)
            ),
            1 => {
                assert_ne!(changed.fastpq_transcripts(), original.fastpq_transcripts());
                let call = Hash::new(b"structurally valid additional protocol call");
                assert_eq!(changed.fastpq_transcripts()[&call].len(), 1);
                assert_eq!(
                    changed.fastpq_transcripts()[&call][0].authority_digest,
                    Hash::new(b"changed")
                );
            }
            _ => {
                assert_ne!(
                    changed.axt_transitioned_dataspaces(),
                    original.axt_transitioned_dataspaces()
                );
                assert!(
                    changed
                        .axt_transitioned_dataspaces()
                        .unwrap()
                        .contains(&DataSpaceId::new(9))
                );
            }
        }
        let error = reject_changed(&f, &changed);
        assert_eq!(
            error.to_string(),
            "executed block differs from its certified result commitment"
        );
    }
}

#[test]
fn diagnostics_separate_internal_failures_from_explicit_sealed_network_join() {
    let f = fixture_with(|block| {
        let mut outputs = block.execution_outputs().to_vec();
        let ExecutionOutputV1::Network(network) = &mut outputs[1] else {
            unreachable!()
        };
        network.result = TransactionResult::new(Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("sealed rejection".into()),
        )));
        let ExecutionOutputV1::Pipeline(pipeline) = &outputs[2] else {
            unreachable!()
        };
        outputs[2] =
            ExecutionOutputV1::pipeline_output_limit_rejection(pipeline.invocation.clone());
        let ExecutionOutputV1::Time(timer) = &outputs[3] else {
            unreachable!()
        };
        outputs[3] = ExecutionOutputV1::time_output_limit_rejection(timer.invocation.clone());
        install(block, outputs);
    });
    let block = f.executed.as_ref();
    execution::validate(block, f.store.root_scope).unwrap();
    original_read(&f);
    let sources = block.network_entrypoints().collect::<Vec<_>>();
    assert_eq!(sources.len(), 2);
    let (first_position, first) = block.network_output_at(0).unwrap();
    let (sealed_position, sealed) = block.network_output_at(1).unwrap();
    assert_eq!(first_position, 0);
    assert_eq!(sealed_position, 1);
    assert!(first.result.is_ok());
    assert_eq!(sources[0].hash(), sources[0].execution_call_hash());
    assert_eq!(sealed.input_index, 1);
    assert_ne!(sources[1].hash(), sources[1].execution_call_hash());
    assert_eq!(
        sources[1].hash(),
        block.network_entrypoint_at(1).unwrap().hash()
    );
    assert!(matches!(sources[1], TransactionEntrypoint::SealedReveal(_)));
    assert!(sealed.result.is_err());
    let failures = block
        .execution_outputs()
        .iter()
        .enumerate()
        .filter(|(_, output)| output.result().is_err())
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 3);
    assert_eq!(failures[0].0, 1);
    assert!(matches!(failures[0].1, ExecutionOutputV1::Network(row)
        if row.input_index == 1 && matches!(row.result.as_ref(), Err(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(reason))) if reason == "sealed rejection")));
    assert_eq!(failures[1].0, 2);
    assert!(matches!(failures[1].1, ExecutionOutputV1::Pipeline(row)
        if row.invocation.event == PipelineEventPositionV1::BlockApproved
            && row.invocation.trigger.trigger_id == "replay_pipeline".parse().unwrap()));
    assert!(failures[1].1.is_output_limit_rejection());
    assert_eq!(failures[2].0, 3);
    assert!(matches!(failures[2].1, ExecutionOutputV1::Time(row)
        if row.invocation.schedule_index == 0 && row.invocation.trigger.trigger_id == "replay_timer".parse().unwrap()));
    assert!(failures[2].1.is_output_limit_rejection());
    let resultless = block.canonical_resultless_proposal().unwrap();
    assert!(resultless.output_results().all(|result| result.is_ok()));
    assert!(resultless.execution_outputs().is_empty());
    assert!(resultless.validate_output_merkle_cache().is_err());
    for index in 0..2 {
        assert!(resultless.network_output_at(index).is_none());
    }
}

#[test]
fn parity_refuses_different_headers_and_signatures_even_with_equal_output_rows() {
    let f = fixture();
    let original = f.executed.as_ref();
    let wrong_header = mutate(original, |raw| raw.payload.header.creation_time_ms += 1);
    wrong_header.validate_output_merkle_cache().unwrap();
    assert_eq!(
        wrong_header.execution_outputs(),
        original.execution_outputs()
    );
    assert_ne!(wrong_header.header(), original.header());
    let error = reject_changed(&f, &wrong_header);
    assert!(matches!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<iroha_data_model::sumeragi_finality::CertifiedResultError>(),
        Some(iroha_data_model::sumeragi_finality::CertifiedResultError::BlockMismatch)
    ));
    let mut wrong_signatures = original.clone();
    wrong_signatures
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([BlockSignature::new(
                1,
                iroha_crypto::SignatureOf::try_from_hash(
                    ALICE_KEYPAIR.private_key(),
                    original.hash(),
                )
                .unwrap(),
            )])
            .expect("at most 31 block signatures"),
        )
        .unwrap();
    assert!(!wrong_signatures.signatures().eq(original.signatures()));
    assert_eq!(
        wrong_signatures.execution_outputs(),
        original.execution_outputs()
    );
    let error = reject_changed(&f, &wrong_signatures);
    assert_eq!(
        error.to_string(),
        "executed block differs from its certified result commitment"
    );
    let error = invalid_data(read(&f, original, 3).poll().unwrap_err());
    assert_eq!(
        error.to_string(),
        "committed source height or instance mismatch"
    );
    original_read(&f);
}
