//! Real paid Worker capture/commit guards for local unresolved Prepared outbound intent.

use super::*;
use crate::sumeragi::{
    block_store::KuraBlockStore,
    driver::traits::BlockStore as _,
    test_chain::{CertifiedTestChain, Signers},
};
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{
    block::BlockHeader as IrohaHeader, isi::InstructionBox, sumeragi_amx::AmxRecordKind,
};
use std::{fs, path::PathBuf};

fn with_paid_worker(
    test: impl FnOnce(&CertifiedTestChain, InstructionBox, KeyPair, &mut Worker<'_>, &KuraBlockStore)
    + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-intent-worker-test")
        .spawn(move || {
            crate::sumeragi::amx::with_paid_prepare_retry_fixture(|chain, instruction, customer| {
                publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                    |chain, worker, blocks, _events| {
                        test(chain, instruction, customer, worker, blocks)
                    },
                );
            })
        })
        .unwrap()
        .join()
        .unwrap();
}
fn path(chain: &CertifiedTestChain, height: u64, hash: HashOf<IrohaHeader>) -> PathBuf {
    let mut hex = String::new();
    for byte in hash.as_ref() {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!("{height:020}-{hex}.ami"))
}
fn paid_block(
    chain: &CertifiedTestChain,
    worker: &mut Worker<'_>,
    instruction: InstructionBox,
    customer: &KeyPair,
    duplicate: bool,
) -> (AvailableBody, Qc) {
    let block = publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
        let instructions = if duplicate {
            vec![instruction.clone(), instruction]
        } else {
            vec![instruction]
        };
        chain.sign(customer, instructions, time)
    });
    let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
    let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else {
        panic!("genuine paid original must execute");
    };
    let qc = chain.commit_qc(block.header().height, hash, result, Signers::Quorum);
    (block, qc)
}

// This control uses only the original APIs and can be installed before the production fix.
#[test]
fn original_paid_prepared_commit_captures_durable_intent_before_acknowledgement() {
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        let (block, qc) = paid_block(chain, worker, instruction, &customer, false);
        let live = worker.live.as_ref().unwrap();
        let archive = live.native_contexts.as_ref().unwrap();
        let carrier = archive.carrier_hash();
        let height = archive.height();
        let prepared = live
            .witness
            .as_ref()
            .unwrap()
            .writes
            .iter()
            .filter(|entry| {
                entry.key.first() == Some(&0xD9)
                    && entry.key.get(1) == Some(&(AmxRecordKind::Prepared as u8))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            prepared.len(),
            1,
            "actual committed transaction writes one original Prepared record"
        );
        let tx: [u8; 32] = prepared[0].key[2..].try_into().unwrap();
        let intent_path = path(chain, height, carrier);
        assert!(
            !intent_path.exists(),
            "uncommitted overlay must not publish outbound intent"
        );
        worker.prepare(&block, &qc).unwrap();
        assert!(
            !intent_path.exists(),
            "prepared certificate is still not published State"
        );
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert_eq!(worker.applied, (height, qc.block_hash));
        assert!(
            intent_path.is_file(),
            "committed Prepared must durably retain its original outbound intent"
        );
        assert!(fs::metadata(&intent_path).unwrap().len() > 0);
        let view = worker.state.view();
        let proof =
            crate::sumeragi::amx::amx_record_proof(&view, height, AmxRecordKind::Prepared, tx)
                .complete()
                .unwrap()
                .expect("same original committed archive supplies genuine Prepared proof");
        drop(view);
        assert_eq!(proof.canonical().record.tx(), tx);
    });
}

#[test]
fn rejected_paid_prepare_overlay_never_publishes_outbound_intent() {
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        // The second identical Prepare rejects the actual entire signed transaction.
        let (block, qc) = paid_block(chain, worker, instruction, &customer, true);
        let live = worker.live.as_ref().unwrap();
        let source = live.native_contexts.as_ref().unwrap();
        let target = path(chain, source.height(), source.carrier_hash());
        assert!(
            !live
                .witness
                .as_ref()
                .unwrap()
                .writes
                .iter()
                .any(|entry| entry.key.first() == Some(&0xD9)
                    && entry.key.get(1) == Some(&(AmxRecordKind::Prepared as u8)))
        );
        assert!(source.prepared_intent_bytes().is_none());
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert!(
            !target.exists(),
            "aborted overlay cannot manufacture a durable Prepared intent"
        );
        assert!(
            worker
                .state
                .view()
                .world()
                .sumeragi_amx_participant()
                .canonical()
                .unwrap()
                .participant
                .prepared
                .is_empty()
        );
    });
}

#[test]
fn original_paid_intent_capacity_refusal_retains_completed_context_and_same_pool_retry() {
    with_paid_worker(|chain, instruction, customer, worker, _blocks| {
        let block = publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
            chain.sign(&customer, [instruction], time)
        });
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let budget = worker.state.ivm_execution_budget();
        let limit = budget.limit_bytes();
        let mut blocker = None;
        let mut pointer = None;
        let mut bytes = None;
        let outcome = worker.run_execution_with_finisher(&block, hash, |worker| {
            worker.prepare_original_result().unwrap();
            let original = worker.finishing.as_mut().unwrap();
            original.native_contexts = Some(
                worker
                    .context
                    .native_context_archive
                    .prepare(
                        &original.overlay,
                        original.valid.as_ref(),
                        original.phase.ready().unwrap(),
                        &original.witness,
                    )
                    .unwrap(),
            );
            let context = original.native_contexts.as_ref().unwrap();
            pointer = Some(context.canonical_bytes().as_ptr());
            bytes = Some(context.canonical_bytes().to_vec());
            blocker = Some(
                budget
                    .try_reserve_bytes(limit - budget.reserved_bytes())
                    .unwrap(),
            );
            worker.finish_execution_with_encoder(encode_result_preimage)
        });
        let Err(PublicationError::Deferred(refusal)) = outcome else {
            panic!("intent must preserve typed original pool refusal");
        };
        assert!(matches!(
            refusal.allocation_refusal(),
            Some(iroha_allocation::AllocationRefusal::Capacity { .. })
        ));
        let original = worker.finishing.as_ref().unwrap();
        let context = original.native_contexts.as_ref().unwrap();
        let Some(NativeContextArchiveError::Allocation(
            iroha_allocation::ChargedBufferError::Admission(actual),
        )) = &original.archive_refusal
        else {
            panic!("the actual original intent admission must be retained");
        };
        assert_eq!(refusal.allocation_refusal(), Some(actual));
        assert_eq!(Some(context.canonical_bytes().as_ptr()), pointer);
        assert_eq!(context.canonical_bytes(), bytes.as_ref().unwrap());
        assert!(context.prepared_intent_bytes().is_none());
        assert_eq!(worker.state.view().height(), 1);
        assert!(worker.live.is_none());
        assert_eq!(budget.limit_bytes(), limit);
        assert!(budget.same_pool(&worker.state.ivm_execution_budget()));
        drop(blocker.take());
        worker
            .finish_execution_with_encoder(encode_result_preimage)
            .unwrap();
        let live = worker.live.as_ref().unwrap();
        let context = live.native_contexts.as_ref().unwrap();
        assert_eq!(Some(context.canonical_bytes().as_ptr()), pointer);
        assert_eq!(context.canonical_bytes(), bytes.as_ref().unwrap());
        crate::query::native_context_archive::prepared_intent_test_helpers::verify_original(
            context.prepared_intent_bytes().unwrap(),
            live.overlay.as_deref().unwrap(),
            match &live.phase {
                PublicationPhase::Executed { valid, .. } => valid.as_ref(),
                _ => panic!("original executed phase"),
            },
            live.commitment().get(),
            live.witness.as_ref().unwrap(),
        );
    });
}

#[test]
fn original_paid_intent_namespace_refusal_retains_both_buffers_and_exact_commit_retry() {
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        let (block, qc) = paid_block(chain, worker, instruction, &customer, false);
        let source = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let context_pointer = source.canonical_bytes().as_ptr();
        let intent_pointer = source.prepared_intent_bytes().unwrap().as_ptr();
        let expected = source.prepared_intent_bytes().unwrap().to_vec();
        let target = path(chain, source.height(), source.carrier_hash());
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        let directory = chain.kura().store_root().join("native-contexts");
        let hidden = directory.with_extension("original-held");
        fs::rename(&directory, &hidden).unwrap();
        assert!(worker.commit(&block, &qc).is_err());
        for _ in 0..2 {
            let source = &worker.pending_commit.as_ref().unwrap().native_contexts;
            assert_eq!(source.canonical_bytes().as_ptr(), context_pointer);
            assert_eq!(
                source.prepared_intent_bytes().unwrap().as_ptr(),
                intent_pointer
            );
            assert_eq!(source.prepared_intent_bytes().unwrap(), expected);
            assert!(worker.commit(&block, &qc).is_err());
            assert_eq!(worker.applied.0, 1);
        }
        fs::rename(&hidden, &directory).unwrap();
        worker.commit(&block, &qc).unwrap();
        assert!(worker.pending_commit.is_none());
        assert_eq!(fs::read(&target).unwrap(), expected);
    });
}

#[cfg(unix)]
#[test]
fn original_paid_intent_commit_repetition_and_archive_reopen_are_create_only_and_zero_new_pool_bytes()
 {
    use std::os::unix::fs::MetadataExt as _;
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        let (block, qc) = paid_block(chain, worker, instruction, &customer, false);
        let source = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let target = path(chain, source.height(), source.carrier_hash());
        let expected = source.prepared_intent_bytes().unwrap().to_vec();
        let original_pointer = source.prepared_intent_bytes().unwrap().as_ptr();
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();

        // Retain the actual committed publication across a real archive refusal. Successful
        // acknowledgement retires these buffers; it must not leave a second live owner.
        let directory = chain.kura().store_root().join("native-contexts");
        let hidden = directory.with_extension("reopen-original-held");
        fs::rename(&directory, &hidden).unwrap();
        assert!(worker.commit(&block, &qc).is_err());
        fs::rename(&hidden, &directory).unwrap();
        let original = &worker.pending_commit.as_ref().unwrap().native_contexts;
        assert_eq!(
            original.prepared_intent_bytes().unwrap().as_ptr(),
            original_pointer
        );
        worker
            .context
            .native_context_archive
            .publish(original)
            .unwrap();
        let metadata = fs::metadata(&target).unwrap();
        let budget = worker.state.ivm_execution_budget();
        let reserved = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - reserved)
            .unwrap();
        let reopened = crate::query::native_context_archive::NativeContextArchive::open(
            chain.kura(),
            budget.clone(),
            chain.kura().native_context_archive_max_bytes(),
        )
        .unwrap();
        reopened.publish(original).unwrap();
        let repeated = fs::metadata(&target).unwrap();
        assert_eq!(repeated.ino(), metadata.ino());
        assert_eq!(repeated.dev(), metadata.dev());
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert_eq!(
            original.prepared_intent_bytes().unwrap().as_ptr(),
            original_pointer
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), reserved);

        worker.commit(&block, &qc).unwrap();
        assert!(worker.pending_commit.is_none());
        assert!(worker.live.as_ref().unwrap().native_contexts.is_none());
        assert_eq!(worker.applied, (block.header().height, qc.block_hash));
        let acknowledged = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - acknowledged)
            .unwrap();
        worker.commit(&block, &qc).unwrap();
        let repeated = fs::metadata(&target).unwrap();
        assert_eq!(repeated.ino(), metadata.ino());
        assert_eq!(repeated.dev(), metadata.dev());
        assert_eq!(fs::read(&target).unwrap(), expected);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), acknowledged);
    });
}

#[test]
fn original_paid_intent_changed_durable_bytes_never_acknowledge_or_repair() {
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        let (block, qc) = paid_block(chain, worker, instruction, &customer, false);
        let source = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let target = path(chain, source.height(), source.carrier_hash());
        let pointer = source.prepared_intent_bytes().unwrap().as_ptr();
        fs::write(&target, b"foreign-published-intent").unwrap();
        worker.prepare(&block, &qc).unwrap();
        blocks.append(&block, &qc).unwrap();
        for _ in 0..2 {
            assert!(worker.commit(&block, &qc).is_err());
            assert_eq!(worker.applied.0, 1);
            assert_eq!(
                worker
                    .pending_commit
                    .as_ref()
                    .unwrap()
                    .native_contexts
                    .prepared_intent_bytes()
                    .unwrap()
                    .as_ptr(),
                pointer
            );
            assert_eq!(fs::read(&target).unwrap(), b"foreign-published-intent");
        }
    });
}

#[test]
fn original_paid_intent_capture_rejects_changed_carrier_execution_and_foreign_pool() {
    with_paid_worker(|chain, instruction, customer, worker, _blocks| {
        let block = publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
            chain.sign(&customer, [instruction], time)
        });
        let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
        let outcome = worker.run_execution_with_finisher(&block, hash, |worker| {
            worker.prepare_original_result().unwrap();
            let original = worker.finishing.as_mut().unwrap();
            let result = original.phase.ready().unwrap();
            let mut context = worker
                .context
                .native_context_archive
                .prepare(
                    &original.overlay,
                    original.valid.as_ref(),
                    result,
                    &original.witness,
                )
                .unwrap();
            let pointer = context.canonical_bytes().as_ptr();
            assert!(original.witness.matches_original_native_execution(
                original.valid.as_ref(),
                result.get().execution
            ));
            assert!(!original.witness.matches_original_native_execution(
                chain.committed(1).block(),
                result.get().execution
            ));
            let mut changed_execution = result.get().execution;
            changed_execution.ordinary_writes_root =
                iroha_crypto::Hash::new(b"substituted native writes");
            assert!(
                !original
                    .witness
                    .matches_original_native_execution(original.valid.as_ref(), changed_execution)
            );
            assert!(matches!(
                worker.context.native_context_archive.prepare_amx_intents(
                    &mut context,
                    &original.overlay,
                    chain.committed(1).block(),
                    result,
                    &original.witness
                ),
                Err(NativeContextArchiveError::Source(_))
            ));
            let pool = worker.state.ivm_execution_budget();
            let foreign_pool = iroha_allocation::AllocationBudget::new(pool.limit_bytes());
            let foreign = crate::query::native_context_archive::NativeContextArchive::open(
                chain.kura(),
                foreign_pool.clone(),
                chain.kura().native_context_archive_max_bytes(),
            )
            .unwrap();
            assert!(matches!(
                foreign.prepare_amx_intents(
                    &mut context,
                    &original.overlay,
                    original.valid.as_ref(),
                    result,
                    &original.witness
                ),
                Err(NativeContextArchiveError::Source(_))
            ));
            assert_eq!(foreign_pool.reserved_bytes(), 0);
            assert!(
                original
                    .overlay
                    .world()
                    .sumeragi_amx_participant()
                    .authenticated_parent_source(&foreign_pool)
                    .is_none()
            );
            assert_eq!(context.canonical_bytes().as_ptr(), pointer);
            worker
                .context
                .native_context_archive
                .prepare_amx_intents(
                    &mut context,
                    &original.overlay,
                    original.valid.as_ref(),
                    result,
                    &original.witness,
                )
                .unwrap();
            let intent_pointer = context.prepared_intent_bytes().unwrap().as_ptr();
            assert!(
                matches!(
                    worker.context.native_context_archive.prepare_amx_intents(
                        &mut context,
                        &original.overlay,
                        chain.committed(1).block(),
                        result,
                        &original.witness
                    ),
                    Err(NativeContextArchiveError::Source(_))
                ),
                "completed intent cannot authorize a substituted native carrier"
            );
            assert_eq!(
                context.prepared_intent_bytes().unwrap().as_ptr(),
                intent_pointer
            );
            assert_eq!(context.canonical_bytes().as_ptr(), pointer);
            original.native_contexts = Some(context);
            worker.finish_execution_with_encoder(encode_result_preimage)
        });
        assert!(matches!(outcome, Ok(Some(_))));
    });
}

#[test]
fn original_paid_prepared_witness_survives_same_block_pruning_before_intent_commit() {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-intent-pruning-test")
        .spawn(|| crate::sumeragi::amx::with_paid_prepare_pruning_fixture(|chain, instructions, customer, transactions| {
            publication_tests::with_worker_chain(chain, ConsensusMode::Permissioned,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes), |chain, worker, blocks, _events| {
                    let block = publication_tests::proposal_with_transaction(chain, worker,
                        |chain, time| chain.sign(&customer, instructions, time));
                    let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
                    let Some(ExecOutcome::Valid(result)) = worker.execute(&block, hash) else { panic!("actual paid same-block Prepare originals must execute"); };
                    let qc = chain.commit_qc(block.header().height, hash, result, Signers::Quorum);
                    let live = worker.live.as_ref().unwrap();
                    let overlay = live.overlay.as_deref().unwrap();
                    let participant = &overlay.world().sumeragi_amx_participant().canonical().unwrap().participant;
                    assert!(participant.entry(&transactions[0]).is_none(), "real Decision settles and prunes the earlier expired No entry");
                    assert!(participant.entry(&transactions[1]).is_some());
                    assert_eq!(participant.prepared.len(), 1);
                    let witness = live.witness.as_ref().unwrap();
                    assert_eq!(witness.writes.iter().filter(|entry| entry.key.first() == Some(&0xD9)
                        && entry.key.get(1) == Some(&(AmxRecordKind::Prepared as u8))).count(), 2,
                        "both original committed Prepared records survive final-state pruning");
                    let source = live.native_contexts.as_ref().unwrap();
                    crate::query::native_context_archive::prepared_intent_test_helpers::verify_original(
                        source.prepared_intent_bytes().unwrap(), overlay,
                        match &live.phase { PublicationPhase::Executed { valid, .. } => valid.as_ref(), _ => panic!("original executed phase") },
                        live.commitment().get(), witness);
                    let target = path(chain, source.height(), source.carrier_hash());
                    let expected = source.prepared_intent_bytes().unwrap().to_vec();
                    worker.prepare(&block, &qc).unwrap(); blocks.append(&block, &qc).unwrap(); worker.commit(&block, &qc).unwrap();
                    assert_eq!(fs::read(target).unwrap(), expected);
                });
        })).unwrap().join().unwrap();
}

#[cfg(unix)]
#[test]
fn original_paid_intent_historical_replay_preserves_exact_record_and_repetition_identity() {
    use std::os::unix::fs::MetadataExt as _;
    with_paid_worker(|chain, instruction, customer, worker, blocks| {
        let (block, qc) = paid_block(chain, worker, instruction, &customer, false);
        let source = worker
            .live
            .as_ref()
            .unwrap()
            .native_contexts
            .as_ref()
            .unwrap();
        let target = path(chain, source.height(), source.carrier_hash());
        let expected = source.prepared_intent_bytes().unwrap().to_vec();
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        assert!(worker.live.is_none());
        assert!(worker.completed_replay.is_some());
        let original = fs::metadata(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), expected);
        let budget = worker.state.ivm_execution_budget();
        let retained = budget.reserved_bytes();
        worker.replay(&block, &qc).unwrap();
        assert_eq!(budget.reserved_bytes(), retained);
        assert_eq!(fs::metadata(&target).unwrap().ino(), original.ino());
        assert_eq!(fs::metadata(&target).unwrap().dev(), original.dev());
        assert_eq!(fs::read(&target).unwrap(), expected);
    });
}
