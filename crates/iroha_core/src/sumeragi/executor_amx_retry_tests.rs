//! Actual paid Worker deferral retains completed leg custody, not a cached execution result.

use super::*;

#[test]
fn original_paid_amx_post_decode_refusal_retains_worker_leg_and_exact_retry() {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-worker-retry-test")
        .spawn(|| crate::sumeragi::amx::with_paid_prepare_retry_fixture(|chain, instruction, customer| {
            publication_tests::with_worker_chain(chain, ConsensusMode::Permissioned,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                |chain, worker, _blocks, events| {
                    let block = publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
                        chain.sign(&customer, [instruction], time)
                    });
                    let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
                    let budget = worker.state.ivm_execution_budget();
                    let height = worker.state.view().height();
                    let wire = block.payload().as_slice().as_ptr();
                    let original = {
                        let view = worker.state.view();
                        view.world().sumeragi_amx_participant().clone()
                    };
                    let observer = crate::sumeragi::amx::NativeLegRetryObservation::occupy_after_first_completion();
                    assert!(worker.parent_applied(&block), "the actual execution parent is applied");
                    // Borrow the production Worker's typed result before the public
                    // Execute transport projects local failures into a diagnostic string.
                    let Err(PublicationError::Deferred(refusal)) = worker.run_execution(&block, hash, false) else {
                        panic!("the original Candidate must return its typed local deferral");
                    };
                    let first = observer.snapshot();
                    assert_eq!(first.0, 1, "actual canonical leg completed before Candidate refusal");
                    assert_eq!(first.1, 1);
                    assert!(first.2.unwrap().retained_bytes > 0);
                    assert!(matches!(&refusal, PublicationDeferral::StateStorage(
                        crate::state::StateStorageAdmissionError::NativeAmx(_))));
                    assert!(matches!(refusal.allocation_refusal(),
                        Some(iroha_allocation::AllocationRefusal::Capacity { .. })));
                    let original_candidate = observer.original_candidate_refusal()
                        .expect("the real Candidate refused after actual canonical completion");
                    assert_eq!(refusal.allocation_refusal(), Some(&original_candidate),
                        "Worker returns the exact original Candidate pool/release generation");
                    assert_eq!(worker.state.view().height(), height);
                    assert!(worker.results.is_empty());
                    assert!(worker.live.is_none()); assert!(worker.finishing.is_none());
                    assert!(worker.quarantine_context.is_none());
                    assert!(worker.context.staging.get(&hash).is_none());
                    assert!(events.try_recv().is_err());
                    assert_eq!(block.payload().as_slice().as_ptr(), wire);
                    {
                        let view = worker.state.view();
                        assert!(std::ptr::eq(view.world().sumeragi_amx_participant().canonical().unwrap(),
                            original.canonical().unwrap()), "no fee/debit/escrow publication on local refusal");
                    }
                    observer.release_original_blocker();
                    let generation = worker.state.state_view_generation();
                    let parent = worker.applied;
                    worker.state.with_held_view_publication_for_reader_test(|_| {});
                    assert_eq!(worker.state.state_view_generation(), generation.checked_add(2).unwrap(),
                        "the actual State writer completed another visibility publication");
                    assert_eq!(worker.applied, parent, "visibility publication does not replace the execution parent");
                    assert_eq!(worker.state.view().height(), height);
                    assert!(worker.parent_applied(&block));
                    assert_eq!(block.payload().as_slice().as_ptr(), wire);
                    {
                        let view = worker.state.view();
                        assert!(std::ptr::eq(view.world().sumeragi_amx_participant().canonical().unwrap(),
                            original.canonical().unwrap()), "visibility publication does not publish fee/debit/escrow effects");
                    }
                    let retry_attempt = worker.run_execution(&block, hash, false);
                    assert!(matches!(&retry_attempt, Ok(Some(_))),
                        "same original paid candidate must retry after genuine capacity release: {retry_attempt:?}");
                    let Some(ExecOutcome::Valid(public_result)) = worker.execute(&block, hash, false) else {
                        panic!("same original paid candidate must retry after genuine capacity release");
                    };
                    assert_eq!(Some(public_result), retry_attempt.unwrap(),
                        "public Execute reports the same freshly authenticated execution result");
                    let retry = observer.snapshot();
                    assert_eq!(retry.0, 1,
                        "completed canonical decoder must not allocate or consume cumulative leg work again");
                    assert_eq!(retry.1, 2, "current business/authority checks rerun on the original graph");
                    assert_eq!(retry.2, first.2);
                    assert_eq!(block.payload().as_slice().as_ptr(), wire);
                    assert_eq!(worker.state.view().height(), height);
                    assert!(worker.routing_refusal.is_none());
                    assert!(worker.recovery.is_none(), "a completed visibility interval cannot invalidate byte-only decode custody");
                    assert!(worker.live.is_some() || worker.finishing.is_some());
                    assert!(budget.reserved_bytes() > 0);
                });
        })).unwrap().join().unwrap();
}

fn with_original_paid_bank(
    duplicate: bool,
    test: impl FnOnce(
        &SignedBlock,
        &AvailableBody,
        &iroha_allocation::AllocationBudget,
        &dyn iroha_sumeragi::crypto::Crypto,
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-worker-bank-test")
        .spawn(move || {
            crate::sumeragi::amx::with_paid_prepare_retry_fixture(|chain, instruction, customer| {
                publication_tests::with_worker_chain(
                    chain,
                    ConsensusMode::Permissioned,
                    Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                    |chain, worker, _blocks, _events| {
                        let block = publication_tests::proposal_with_transaction(
                            chain,
                            worker,
                            |chain, time| {
                                let instructions = if duplicate {
                                    vec![instruction.clone(), instruction]
                                } else {
                                    vec![instruction]
                                };
                                chain.sign(&customer, instructions, time)
                            },
                        );
                        let pool = worker.state.ivm_execution_budget();
                        let mut attempt = SignatureDecodeAttempt {
                            block_hash: block.hash(&**worker.context.crypto.as_ref().unwrap()),
                            source: block.clone(),
                            decoder:
                                iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(
                                    &pool,
                                )
                                .unwrap(),
                            decoded: None,
                            returned_refusal: None,
                            amx_legs: None,
                            parent_service:
                                crate::sumeragi::certified_chain::ParentServicePreparation::default(
                                ),
                        };
                        let original = attempt.original_decoded(&pool).unwrap();
                        test(
                            original,
                            &block,
                            &pool,
                            &**worker.context.crypto.as_ref().unwrap(),
                        );
                    },
                );
            })
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn completed_amx_worker_bank_refuses_replaced_source_parent_and_foreign_pool() {
    with_original_paid_bank(false, |original, source, pool, crypto| {
        let baseline = pool.reserved_bytes();
        let mut bank = None;
        let requests = crate::test_allocations::allocations_during(|| {
            bank = Some(crate::sumeragi::amx::NativeAmxLegPreparations::new(
                original, source, pool,
            ));
        });
        assert_eq!(
            requests, 0,
            "bank binding clones only existing charged shared source owners"
        );
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "source binding creates no new physical reservation"
        );
        let bank = bank.unwrap();
        assert!(bank.matches_original(original, source, source, pool));
        let replacement = original.clone();
        assert!(
            replacement
                .matches_resultless_proposal_wire(source.payload().as_slice())
                .unwrap()
        );
        assert_ne!(
            replacement.external_entrypoints_slice().as_ptr(),
            original.external_entrypoints_slice().as_ptr()
        );
        assert!(
            !bank.matches_original(&replacement, source, source, pool),
            "equal-content replacement is not the actual retained original SignedBlock"
        );
        let foreign = iroha_allocation::AllocationBudget::new(pool.limit_bytes());
        assert!(!bank.matches_original(original, source, source, &foreign));
        // Each replacement is genuinely restored with the same original signed
        // header, codeword and production crypto, not an untrusted fabricated body.
        for replace_payload in [true, false] {
            let restored = restored_same_content_source(source, pool, crypto, replace_payload);
            assert!(
                restored == *source,
                "semantic equality alone cannot identify physical source custody"
            );
            let original_owner = if replace_payload {
                source.payload().charged_source(pool)
            } else {
                source.availability().charged_source(pool)
            }
            .unwrap();
            let replacement_owner = if replace_payload {
                restored.payload().charged_source(pool)
            } else {
                restored.availability().charged_source(pool)
            }
            .unwrap();
            assert!(!std::ptr::eq(original_owner, replacement_owner));
            assert!(
                !bank.matches_original(original, source, &restored, pool),
                "equal signed bytes with a different actual payload or availability owner must refuse"
            );
            assert!(
                !bank.matches_original(original, &restored, &restored, pool),
                "a substituted retained source cannot rebind the bank's original charged owners"
            );
        }
        assert!(bank.matches_original(original, source, source, pool));
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "restored alternatives retire their actual charged backing"
        );
        drop(bank);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "shared bank anchors retire without premature source refund"
        );
    });
}

fn restored_same_content_source(
    source: &AvailableBody,
    pool: &iroha_allocation::AllocationBudget,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,
    replace_payload: bool,
) -> AvailableBody {
    use iroha_sumeragi::availability::{AvailabilityFrame, BodyRestoration, PayloadBytes};
    let bytes = if replace_payload {
        source.payload().as_slice()
    } else {
        source.availability().as_slice()
    };
    let mut replacement = iroha_allocation::ChargedBuffer::new(bytes.len(), pool).unwrap();
    replacement.append(bytes).unwrap();
    let (availability, payload) = if replace_payload {
        (
            source.availability().clone(),
            PayloadBytes::from_charged(replacement, pool)
                .unwrap_or_else(|(_, error)| panic!("actual payload sharing: {error}")),
        )
    } else {
        (
            AvailabilityFrame::from_charged(replacement, pool)
                .unwrap_or_else(|(_, error)| panic!("actual availability sharing: {error}")),
            source.payload().clone(),
        )
    };
    BodyRestoration::new(
        source.source().clone(),
        source.header().clone(),
        availability,
        payload,
    )
    .complete(pool, crypto)
    .unwrap_or_else(|(_, error)| panic!("genuine signed body restoration: {error:?}"))
}

#[test]
fn completed_amx_worker_bank_preserves_equal_occurrences_and_metadata_refusal() {
    with_original_paid_bank(true, |original, source, pool, _crypto| {
        use iroha_data_model::{isi::sumeragi_amx::PrepareAmxV1, transaction::Executable};
        let input = &original.external_entrypoints_slice()[0];
        let iroha_data_model::transaction::TransactionEntrypoint::External(signed) = input else {
            panic!("signed input");
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("direct ISIs");
        };
        let first = instructions[0]
            .as_any()
            .downcast_ref::<PrepareAmxV1>()
            .unwrap();
        let second = instructions[1]
            .as_any()
            .downcast_ref::<PrepareAmxV1>()
            .unwrap();
        assert_eq!(first, second);
        assert_ne!(
            first
                .transaction
                .leg(first.dataspace)
                .unwrap()
                .payload
                .as_ptr(),
            second
                .transaction
                .leg(second.dataspace)
                .unwrap()
                .payload
                .as_ptr()
        );
        let baseline = pool.reserved_bytes();
        let mut bank = crate::sumeragi::amx::NativeAmxLegPreparations::new(original, source, pool);
        let observer =
            crate::sumeragi::amx::NativeLegRetryObservation::occupy_after_first_completion();
        let failure = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
            .with_leg(first, 0, pool, |_| Ok::<_, ()>(()))
            .expect_err("occupied original pool must retain graph before metadata admission");
        assert!(matches!(
            failure,
            crate::sumeragi::amx::NativeLegExecutionError::Metadata(
                iroha_allocation::ChargedBufferError::Admission(
                    iroha_allocation::AllocationRefusal::Capacity { .. }
                )
            )
        ));
        let retained = observer.snapshot();
        assert_eq!(retained.0, 1);
        observer.release_original_blocker();
        assert_eq!(
            pool.reserved_bytes(),
            baseline + retained.2.unwrap().retained_bytes,
            "metadata refusal retains actual graph and both canonical controls"
        );
        assert!(
            crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
                .with_leg(first, 0, pool, |_| Ok::<_, ()>(()))
                .is_ok()
        );
        assert_eq!(observer.snapshot().0, 1);
        assert!(
            crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
                .with_leg(second, 1, pool, |_| Ok::<_, ()>(()))
                .is_ok()
        );
        assert_eq!(
            observer.snapshot().0,
            2,
            "equal values at distinct signed ordinals decode independently"
        );
        assert!(
            crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
                .with_leg(first, 0, pool, |_| Ok::<_, ()>(()))
                .is_ok()
        );
        assert_eq!(
            observer.snapshot().0,
            2,
            "exact completed occurrence reuses its original work"
        );
        assert!(bank.matches_original(original, source, source, pool));
        drop(bank);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "all actual graph/control/metadata storage retires before its refunds"
        );
    });
}

#[test]
fn original_paid_amx_worker_retry_reauthenticates_changed_native_parent() {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-worker-parent-retry-test")
        .spawn(|| crate::sumeragi::amx::with_paid_prepare_retry_fixture(|chain, instruction, customer| {
            publication_tests::with_worker_chain(chain, ConsensusMode::Permissioned,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                |chain, worker, _blocks, events| {
                    let block = publication_tests::proposal_with_transaction(chain, worker, |chain, time| {
                        chain.sign(&customer, [instruction], time)
                    });
                    let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
                    let parent = worker.applied;
                    let height = worker.state.view().height();
                    let original = worker.state.view().world().sumeragi_amx_participant().clone();
                    let observer = crate::sumeragi::amx::NativeLegRetryObservation::occupy_after_first_completion();
                    assert!(worker.parent_applied(&block));
                    let Err(PublicationError::Deferred(refusal)) = worker.run_execution(&block, hash, false) else {
                        panic!("the original Candidate must defer after completing the paid leg");
                    };
                    assert_eq!(observer.snapshot().0, 1);
                    assert_eq!(observer.snapshot().1, 1);
                    assert_eq!(refusal.allocation_refusal(), observer.original_candidate_refusal().as_ref());
                    observer.release_original_blocker();
                    let mut header = block.header().clone();
                    header.parent_result = Hash32([201; 32]);
                    let changed = chain.author_payload_under_test_context(
                        header, block.payload().as_slice().to_vec(), block.source().config(),
                    ).unwrap_or_else(|(_, error)| panic!("genuinely signed changed native parent result: {error:?}"));
                    assert!(worker.parent_applied(&changed), "the height/hash gate alone cannot authorize a changed parent result");
                    assert_ne!(changed.header().parent_result, block.header().parent_result);
                    let changed_hash = changed.hash(&**worker.context.crypto.as_ref().unwrap());
                    assert!(matches!(worker.execute(&changed, changed_hash, false), Some(ExecOutcome::Invalid)),
                        "fresh native successor authentication must reject a changed committed parent result");
                    assert_eq!(observer.snapshot().0, 1, "changed parent never reuses or decodes a monetary leg");
                    assert_eq!(observer.snapshot().1, 1, "changed parent never reaches current monetary execution");
                    assert_eq!(worker.applied, parent);
                    assert_eq!(worker.state.view().height(), height);
                    assert!(worker.live.is_none());
                    assert!(worker.finishing.is_none());
                    assert!(worker.recovery.is_none());
                    assert!(worker.quarantine_context.is_none());
                    assert!(worker.context.staging.get(&changed_hash).is_none());
                    {
                        let view = worker.state.view();
                        assert!(std::ptr::eq(view.world().sumeragi_amx_participant().canonical().unwrap(),
                            original.canonical().unwrap()), "changed parent cannot publish fee/debit/escrow effects");
                    }
                    assert!(events.try_recv().is_err(), "an unauthenticated parent has no transaction rejection authority");
                });
        })).unwrap().join().unwrap();
}

#[test]
fn partial_amx_worker_leg_refusal_retains_original_controls_and_release_wait() {
    with_original_paid_bank(false, |original, source, pool, _crypto| {
        use iroha_allocation::{AllocationRefusal, ChargedBufferError};
        use iroha_data_model::{
            isi::sumeragi_amx::PrepareAmxV1, sumeragi_amx::AmxLegDecodeErrorV1,
            transaction::Executable,
        };
        use std::{
            alloc::Layout,
            task::{Context, Poll, Waker},
        };

        let input = &original.external_entrypoints_slice()[0];
        let iroha_data_model::transaction::TransactionEntrypoint::External(signed) = input else {
            panic!("genuine signed paid input");
        };
        let Executable::Instructions(instructions) = signed.instructions() else {
            panic!("original direct instructions");
        };
        let instruction = instructions[0]
            .as_any()
            .downcast_ref::<PrepareAmxV1>()
            .unwrap();
        let original_frame = instruction.transaction.leg(instruction.dataspace).unwrap();
        let frame_identity = (
            original_frame.payload.as_ptr(),
            original_frame.payload.len(),
        );
        let mut registration = crate::unit_test_support::release_registration(pool);
        let baseline = pool.reserved_bytes();
        let limit = pool.limit_bytes();
        let controls = norito::core::PreparedDecodeWorkspace::allocation_layouts()
            .iter()
            .map(Layout::size)
            .sum::<usize>();
        let remainder = limit.checked_sub(baseline).unwrap();
        assert!(
            remainder > controls,
            "same original pool has room before contention"
        );
        let blocker = pool.try_reserve_bytes(remainder - controls).unwrap();
        let mut bank = crate::sumeragi::amx::NativeAmxLegPreparations::new(original, source, pool);
        assert!(bank.matches_original(original, source, source, pool));
        let failure = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
            .with_leg(instruction, 0, pool, |_| -> Result<(), ()> {
                panic!("refused decoding cannot execute business effects")
            })
            .expect_err("only original decode controls fit while the original blocker lives");
        let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Allocation(
            ChargedBufferError::Admission(original_refusal),
        )) = failure
        else {
            panic!("preserve actual original-pool Capacity refusal");
        };
        let AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        } = &original_refusal
        else {
            panic!("temporary physical contention is not a new hard ceiling");
        };
        assert!(*requested_bytes > 0);
        assert_eq!(*limit_bytes, limit);
        assert_eq!(
            *reserved_bytes, limit,
            "both original controls were admitted before the refused field"
        );
        assert_eq!(pool.limit_bytes(), limit);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            registration.poll_wait(release, &mut context),
            Poll::Pending,
            "partial AMX Worker decoder must not wake its own original refusal by retiring original controls"
        );
        assert_eq!(
            pool.reserved_bytes(),
            limit,
            "pending decode retains its exact original controls"
        );
        assert!(bank.matches_original(original, source, source, pool));
        let retry = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
            .with_leg(instruction, 0, pool, |_| -> Result<(), ()> {
                panic!("unchanged physical blocker still prevents execution")
            })
            .expect_err("identical retry cannot replace the original physical observation");
        let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Allocation(
            ChargedBufferError::Admission(repeated_refusal),
        )) = retry
        else {
            panic!("same exact original-pool refusal on unchanged retry");
        };
        assert_eq!(repeated_refusal, original_refusal);
        assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
        drop(blocker);
        assert_eq!(
            registration.poll_wait(release, &mut context),
            Poll::Ready(())
        );
        registration.cancel();
        assert!(
            crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
                .with_leg(instruction, 0, pool, |_| Ok::<_, ()>(()))
                .is_ok(),
            "same original occurrence completes after its actual blocker retires"
        );
        assert_eq!(
            pool.limit_bytes(),
            limit,
            "no replacement owner or enlarged original limit"
        );
        assert_eq!(
            (
                original_frame.payload.as_ptr(),
                original_frame.payload.len()
            ),
            frame_identity
        );
        assert!(bank.matches_original(original, source, source, pool));
        drop(bank);
        assert_eq!(
            pool.reserved_bytes(),
            baseline,
            "all real graph/control/metadata owners retire before refunds"
        );
    });
}

fn with_original_paid_multisig_bank(
    test: impl FnOnce(
        &SignedBlock,
        &AvailableBody,
        &iroha_allocation::AllocationBudget,
        &dyn iroha_sumeragi::crypto::Crypto,
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-worker-bank-test")
        .spawn(move || {
            crate::sumeragi::amx::with_paid_multisig_prepare_retry_fixture(
                |chain, instruction, customer| {
                    publication_tests::with_worker_chain(
                        chain,
                        ConsensusMode::Permissioned,
                        Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                        |chain, worker, _blocks, _events| {
                            let block = publication_tests::proposal_with_transaction(
                                chain,
                                worker,
                                |chain, time| {
                                    let instructions = vec![instruction];
                                    chain.sign(&customer, instructions, time)
                                },
                            );
                            let pool = worker.state.ivm_execution_budget();
                            let mut attempt = SignatureDecodeAttempt {
                            block_hash: block.hash(&**worker.context.crypto.as_ref().unwrap()),
                            source: block.clone(),
                            decoder:
                                iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(
                                    &pool,
                                )
                                .unwrap(),
                            decoded: None,
                            returned_refusal: None,
                            amx_legs: None,
        parent_service: crate::sumeragi::certified_chain::ParentServicePreparation::default(),
                        };
                            let original = attempt.original_decoded(&pool).unwrap();
                            test(
                                original,
                                &block,
                                &pool,
                                &**worker.context.crypto.as_ref().unwrap(),
                            );
                        },
                    );
                },
            )
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn partial_amx_worker_leg_refusal_retains_completed_source_prefix_without_reallocation() {
    with_original_paid_bank(false, |original, source, pool, _crypto| {
        assert_original_partial_leg_prefix(original, source, pool, false);
    });
}

#[test]
fn partial_amx_worker_leg_refusal_retains_original_multisig_member_prefix_without_reallocation() {
    with_original_paid_multisig_bank(|original, source, pool, _crypto| {
        assert_original_partial_leg_prefix(original, source, pool, true);
    });
}

fn assert_original_partial_leg_prefix(
    original: &SignedBlock,
    source: &AvailableBody,
    pool: &iroha_allocation::AllocationBudget,
    multisig: bool,
) {
    use iroha_allocation::{AllocationCharge, AllocationRefusal, ChargedBufferError};
    use iroha_data_model::{
        account::{AccountController, MultisigMember},
        isi::sumeragi_amx::PrepareAmxV1,
        sumeragi_amx::{AmxLegDecodeErrorV1, AmxTransferLegV1},
        transaction::{Executable, TransactionEntrypoint},
    };
    use std::{
        alloc::Layout,
        task::{Context, Poll, Waker},
    };

    let input = &original.external_entrypoints_slice()[0];
    let TransactionEntrypoint::External(signed) = input else {
        panic!("genuine signed paid source");
    };
    let Executable::Instructions(instructions) = signed.instructions() else {
        panic!("original direct instructions");
    };
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<PrepareAmxV1>()
        .unwrap();
    let frame = instruction.transaction.leg(instruction.dataspace).unwrap();
    let canonical = norito::decode_canonical::<AmxTransferLegV1>(&frame.payload).unwrap();
    let identity = (frame.payload.as_ptr(), frame.payload.len());
    let AccountController::Single(source_key) = canonical.source.account().controller() else {
        panic!("original single source");
    };
    let controls = norito::core::PreparedDecodeWorkspace::allocation_layouts()
        .iter()
        .map(Layout::size)
        .sum::<usize>();
    let source_bytes = source_key.retained_allocation_layout().size();
    let (prefix, next_key) = if multisig {
        let AccountController::Multisig(policy) = canonical.destination.controller() else {
            panic!("original certified multisig receiver");
        };
        assert_eq!(policy.members().len(), 2);
        let first = policy.members()[0]
            .public_key()
            .retained_allocation_layout()
            .size();
        let next = policy.members()[1]
            .public_key()
            .retained_allocation_layout()
            .size();
        (
            controls
                + source_bytes
                + Layout::array::<norito::core::SequenceSpan>(2)
                    .unwrap()
                    .size()
                + Layout::array::<MultisigMember>(2).unwrap().size()
                + Layout::array::<AllocationCharge>(2).unwrap().size()
                + first,
            next,
        )
    } else {
        let AccountController::Single(destination) = canonical.destination.controller() else {
            panic!("original single receiver");
        };
        (
            controls + source_bytes,
            destination.retained_allocation_layout().size(),
        )
    };
    let mut registration = crate::unit_test_support::release_registration(pool);
    let baseline = pool.reserved_bytes();
    let limit = pool.limit_bytes();
    let blocker = pool
        .try_reserve_bytes(limit.checked_sub(baseline + prefix).unwrap())
        .unwrap();
    let mut bank = crate::sumeragi::amx::NativeAmxLegPreparations::new(original, source, pool);
    let failure = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0)
        .with_leg(instruction, 0, pool, |_| -> Result<(), ()> {
            panic!("partial graph grants no execution result");
        })
        .expect_err("the next original key cannot fit beside retained prefix and actual blocker");
    let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Allocation(
        ChargedBufferError::Admission(original_refusal),
    )) = failure
    else {
        panic!("actual original key admission refusal");
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    } = &original_refusal
    else {
        panic!("temporary original occupancy");
    };
    assert_eq!(*requested_bytes, next_key);
    assert_eq!(*reserved_bytes, limit);
    assert_eq!(*limit_bytes, limit);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        registration.poll_wait(release, &mut context),
        Poll::Pending,
        "partial AMX Worker decoder must retain every original completed source/member allocation without waking its own refusal"
    );
    assert_eq!(
        pool.reserved_bytes(),
        limit,
        "all actual prefix allocations remain charged"
    );
    let mut retry = None;
    let allocations = crate::test_allocations::allocations_during(|| {
        retry = Some(
            crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0).with_leg(
                instruction,
                0,
                pool,
                |_| -> Result<(), ()> {
                    panic!("unchanged blocker grants no execution result");
                },
            ),
        );
    });
    let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Allocation(
        ChargedBufferError::Admission(repeated),
    )) = retry.unwrap().expect_err("same original failed key")
    else {
        panic!("original retry admission cause");
    };
    assert_eq!(
        repeated, original_refusal,
        "same pool, demand, occupancy and original ReleaseWait"
    );
    assert_eq!(
        allocations, 0,
        "completed source/member backing must not be reconstructed on unchanged retry"
    );
    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
    assert!(bank.matches_original(original, source, source, pool));
    drop(blocker);
    assert_eq!(
        registration.poll_wait(release, &mut context),
        Poll::Ready(())
    );
    registration.cancel();
    let result = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, input, 0).with_leg(
        instruction,
        0,
        pool,
        |leg| {
            assert_eq!(leg, &canonical);
            Ok::<_, ()>(())
        },
    );
    assert!(
        result.is_ok(),
        "original partial graph completes after actual external release"
    );
    assert_eq!((frame.payload.as_ptr(), frame.payload.len()), identity);
    assert_eq!(pool.limit_bytes(), limit);
    assert!(bank.matches_original(original, source, source, pool));
    drop(bank);
    assert_eq!(
        pool.reserved_bytes(),
        baseline,
        "all prefix, controls and bank metadata retire exactly once"
    );
}

#[test]
fn rejected_amx_worker_occurrence_retains_source_prefix_and_replays_before_later_partial_occurrence()
 {
    crate::sumeragi::threads::sumeragi_thread_builder("amx-rejected-bank-replay-test")
        .spawn(|| crate::sumeragi::amx::with_paid_prepare_retry_fixture(|chain, instruction, customer| {
            use iroha_allocation::{AllocationRefusal, ChargedBufferError};
            use iroha_data_model::{isi::sumeragi_amx::PrepareAmxV1, sumeragi_amx::{AmxLegDecodeErrorV1, AmxTransferLegV1}, transaction::{Executable, TransactionEntrypoint}};
            use std::{alloc::Layout, task::{Context, Poll, Waker}};
            let valid = instruction.as_any().downcast_ref::<PrepareAmxV1>().unwrap().clone();
            let mut invalid = valid.clone();
            let dataspace = invalid.dataspace;
            let row = invalid.transaction.legs.iter_mut().find(|leg| leg.dataspace == dataspace).unwrap();
            row.payload = late_invalid_amx_leg_frame(&row.payload);
            let ordinary = norito::decode_canonical::<AmxTransferLegV1>(&row.payload).unwrap_err();
            let norito::Error::Message(ordinary) = ordinary else { panic!("ordinary canonical late Quantity rejection"); };
            assert_eq!(ordinary, format!("invalid numeric: {}", iroha_primitives::numeric::NumericError::ScaleTooLarge));
            let expected = norito::decode_canonical::<AmxTransferLegV1>(&valid.transaction.leg(valid.dataspace).unwrap().payload).unwrap();
            let source_bytes = expected.source.account().try_signatory().unwrap().retained_allocation_layout().size();
            let receiver_bytes = expected.destination.try_signatory().unwrap().retained_allocation_layout().size();
            let controls = norito::core::PreparedDecodeWorkspace::allocation_layouts().iter().map(Layout::size).sum::<usize>();
            let digits = original_quantity_layout(&valid.transaction.leg(valid.dataspace).unwrap().payload);
            let original_prefix = controls + source_bytes + receiver_bytes + digits;
            publication_tests::with_worker_chain(chain, ConsensusMode::Permissioned,
                Arc::new(crate::sumeragi::lanes::merge::NoLanes),
                |chain, worker, _blocks, _events| {
                    // A rejection ends one transaction; B therefore belongs to
                    // a separate genuinely signed original network input.
                    let block = publication_tests::proposal_with_transactions(chain, worker, |chain, time| vec![
                        chain.sign(&customer, [invalid.into()], time),
                        chain.sign(&customer, [instruction], time + 1),
                    ]);
                    let hash = block.hash(&**worker.context.crypto.as_ref().unwrap());
                    let pool = worker.state.ivm_execution_budget();
                    let observation = crate::sumeragi::amx::NativeLegRetryObservation::observe_rejected_prefix();
                    assert!(matches!(worker.run_execution(&block, hash, false), Ok(Some(_))), "the actual validator must continue after rejected A and execute genuine B");
                    let (visits, cause, bytes) = observation.partial_snapshot();
                    assert_eq!(visits, 1);
                    assert_eq!(cause.as_deref(), Some(ordinary.as_str()));
                    assert_eq!(bytes, Some(original_prefix), "the real decoder admitted both original keys and mantissa before late scale rejection");
                    assert_eq!(observation.snapshot().0, 1, "only genuine B completes its canonical leg");
                    let PublicationPhase::Executed { valid, .. } = &worker.live.as_ref().unwrap().phase else { panic!("actual executed original inputs"); };
                    assert_eq!(valid.as_ref().external_entrypoint_count(), 2);
                    assert!(valid.as_ref().output_error(0).is_some());
                    assert!(valid.as_ref().output_error(1).is_none());
                    drop(observation);
                    // Exact ReleaseWait assertions are scoped to the leg bank.
                    // Enclosing Worker rollback may separately retire legitimate
                    // State/transaction owners from this same finite pool.
                    let mut attempt = SignatureDecodeAttempt {
                        block_hash: hash, source: block.clone(),
                        decoder: iroha_data_model::block::PreparedSignedBlockSignaturesDecode::new(&pool).unwrap(),
                        decoded: None, returned_refusal: None, amx_legs: None,
        parent_service: crate::sumeragi::certified_chain::ParentServicePreparation::default(),
                    };
                    let original = attempt.original_decoded(&pool).unwrap();
                    let inputs = original.external_entrypoints_slice();
                    let instruction = |index: usize| {
                        let TransactionEntrypoint::External(signed) = &inputs[index] else { panic!("actual signed original input"); };
                        let Executable::Instructions(instructions) = signed.instructions() else { panic!("actual original direct occurrence"); };
                        instructions[0].as_any().downcast_ref::<PrepareAmxV1>().unwrap()
                    };
                    let malformed = instruction(0);
                    let valid = instruction(1);
                    let frame = &valid.transaction.leg(valid.dataspace).unwrap().payload;
                    let identity = (frame.as_ptr(), frame.len());
                    let mut registration = crate::unit_test_support::release_registration(&pool);
                    let baseline = pool.reserved_bytes();
                    let mut bank = crate::sumeragi::amx::NativeAmxLegPreparations::new(original, &block, &pool);
                    let reject_a = |bank: &mut crate::sumeragi::amx::NativeAmxLegPreparations| {
                        let failure = crate::sumeragi::amx::NativeAmxLegExecution::new(bank, &inputs[0], 0)
                            .with_leg(malformed, 0, &pool, |_| -> Result<(), ()> { panic!("late malformed Quantity cannot execute"); }).unwrap_err();
                        let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Decode(error)) = failure else { panic!("replayed A must produce its canonical rejection while B remains retained"); };
                        assert_eq!(error.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
                        let crate::execution_attempt::ExecutionAttemptError::Rejected(error) = crate::execution_attempt::canonical_decode_attempt_error(error, std::convert::identity) else { panic!("original completed source rejection"); };
                        let norito::Error::Message(actual) = error.into_error() else { panic!("original late Quantity cause"); };
                        assert_eq!(actual, ordinary);
                    };
                    reject_a(&mut bank);
                    assert_eq!(pool.reserved_bytes() - baseline, original_prefix);
                    let metadata = bank.partial_metadata_bytes().unwrap();
                    let prefix_b = controls + source_bytes;
                    let remainder = pool.limit_bytes().checked_sub(pool.reserved_bytes()).unwrap();
                    assert!(remainder > metadata + prefix_b);
                    let blocker = pool.try_reserve_bytes(remainder - metadata - prefix_b).unwrap();
                    let refuse_b = |bank: &mut crate::sumeragi::amx::NativeAmxLegPreparations| {
                        let failure = crate::sumeragi::amx::NativeAmxLegExecution::new(bank, &inputs[1], 1)
                            .with_leg(valid, 0, &pool, |_| -> Result<(), ()> { panic!("real receiver Capacity refuses before business execution"); }).unwrap_err();
                        let crate::sumeragi::amx::NativeLegExecutionError::Decode(AmxLegDecodeErrorV1::Allocation(ChargedBufferError::Admission(refusal))) = failure else { panic!("original B partial Capacity refusal"); };
                        refusal
                    };
                    let refusal = refuse_b(&mut bank);
                    let AllocationRefusal::Capacity { release, reserved_bytes, .. } = &refusal else { panic!("actual external contention"); };
                    assert_eq!(*reserved_bytes, pool.limit_bytes());
                    let mut context = Context::from_waker(Waker::noop());
                    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
                    reject_a(&mut bank);
                    assert_eq!(pool.reserved_bytes(), pool.limit_bytes(), "replayed terminal A retains its backing and cannot wake B by refunding it");
                    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
                    assert_eq!(refuse_b(&mut bank), refusal, "whole-block replay preserves B's exact original refusal and release generation");
                    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
                    assert!(bank.matches_original(original, &block, &block, &pool));
                    drop(blocker);
                    assert_eq!(registration.poll_wait(release, &mut context), Poll::Ready(()));
                    registration.cancel();
                    reject_a(&mut bank);
                    let result = crate::sumeragi::amx::NativeAmxLegExecution::new(&mut bank, &inputs[1], 1)
                        .with_leg(valid, 0, &pool, |leg| { assert_eq!(leg, &expected); Ok::<_, ()>(()) });
                    assert!(result.is_ok(), "genuine later original occurrence completes after real release despite replayed rejected A");
                    assert_eq!((frame.as_ptr(), frame.len()), identity);
                    assert!(bank.matches_original(original, &block, &block, &pool));
                    drop(bank);
                    assert_eq!(pool.reserved_bytes(), baseline, "all per-occurrence prefixes, controls and metadata retire with the original bank");
                });
        })).unwrap().join().unwrap();
}

fn original_quantity_layout(frame: &[u8]) -> usize {
    use iroha_data_model::{account::AccountId, asset::AssetId};
    use iroha_primitives::numeric::{Quantity, QuantityDecodePlan};
    use norito::core as codec;
    let view = codec::from_bytes_view(frame).unwrap();
    let _flags = codec::DecodeFlagsGuard::enter(view.flags());
    let _context = codec::PayloadCtxGuard::enter(view.as_bytes());
    let mut offset = 0;
    let _source = codec::framed_field::<AssetId>(view.as_bytes(), &mut offset).unwrap();
    let _receiver = codec::framed_field::<AccountId>(view.as_bytes(), &mut offset).unwrap();
    codec::framed_field::<Quantity>(view.as_bytes(), &mut offset)
        .unwrap()
        .with_payload(|bytes| {
            QuantityDecodePlan::decode_payload(bytes)
                .map_err(codec::DecodeIntoError::<std::convert::Infallible>::Codec)
        })
        .unwrap()
        .allocation_layout()
        .size()
}

fn late_invalid_amx_leg_frame(frame: &[u8]) -> Vec<u8> {
    use iroha_data_model::{account::AccountId, asset::AssetId, sumeragi_amx::AmxTransferLegV1};
    use iroha_primitives::{bigint::BigInt, numeric::Quantity};
    use norito::core as codec;
    let view = codec::from_bytes_view(frame).unwrap();
    let _flags = codec::DecodeFlagsGuard::enter(view.flags());
    let _context = codec::PayloadCtxGuard::enter(view.as_bytes());
    let mut offset = 0;
    let _source = codec::framed_field::<AssetId>(view.as_bytes(), &mut offset).unwrap();
    let _receiver = codec::framed_field::<AccountId>(view.as_bytes(), &mut offset).unwrap();
    let amount_start = offset;
    let amount = codec::framed_field::<Quantity>(view.as_bytes(), &mut offset).unwrap();
    let mut numeric_offset = 0;
    let _mantissa = codec::framed_field::<BigInt>(amount.bytes(), &mut numeric_offset).unwrap();
    let mut amount_body = amount.bytes()[..numeric_offset].to_vec();
    let mut scale = Vec::new();
    codec::serialize_to_buffer(&u32::MAX, &mut scale).unwrap();
    codec::write_len_to_vec_with_flags(
        &mut amount_body,
        u64::try_from(scale.len()).unwrap(),
        view.flags(),
    );
    amount_body.extend_from_slice(&scale);
    let mut body = view.as_bytes()[..amount_start].to_vec();
    codec::write_len_to_vec_with_flags(
        &mut body,
        u64::try_from(amount_body.len()).unwrap(),
        view.flags(),
    );
    body.extend_from_slice(&amount_body);
    codec::frame_bare_with_header_flags::<AmxTransferLegV1>(&body, view.flags()).unwrap()
}
