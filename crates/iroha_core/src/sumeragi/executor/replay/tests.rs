//! Exact completed-replay identity, original-pool retry and forward retirement regressions.

use super::*;
use crate::sumeragi::{driver::traits::BlockStore as _, test_chain::Signers};
use iroha_sumeragi::{availability::BodyRestoration, message::VoteKind};

#[test]
fn completed_replay_rejects_altered_certificate_and_source_without_losing_exact_retry() {
    publication_tests::with_worker(|chain, worker, blocks, events| {
        let (block, qc) = publication_tests::executed(chain, worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        assert!(
            worker.live.is_none(),
            "heavy original Published owner must retire"
        );
        assert!(worker.context.staging.get(&qc.block_hash).is_none());
        assert!(worker.pending_commit.is_none());
        let tip = worker.state.view().native_execution_tip();
        while events.try_recv().is_ok() {}
        for field in 0..7 {
            let mut changed = qc.clone();
            match field {
                0 => changed.agg_sig.0[0] ^= 1,
                1 => changed.result.0[0] ^= 1,
                2 => changed.epoch.context.0[0] ^= 1,
                3 => changed.height += 1,
                4 => changed.view += 1,
                5 => changed.kind = VoteKind::Prepare,
                _ => changed.kind = iroha_sumeragi::message::VoteKind::Prepare,
            }
            assert!(
                worker.replay(&block, &changed).is_err(),
                "altered certificate field {field} acknowledged"
            );
            worker
                .replay(&block, &qc)
                .expect("rejection preserves original completion");
            assert!(worker.live.is_none());
            assert_eq!(worker.state.view().native_execution_tip(), tip);
            assert!(events.try_recv().is_err());
        }
        let mut context = block.source().config().clone();
        context.epoch.authority_generation.0[0] ^= 1;
        let changed_source = AvailabilitySource::new(
            block.source().instance(),
            block.source().height(),
            block.source().block_hash(),
            context,
        )
        .unwrap();
        let changed = BodyRestoration::new(
            changed_source,
            block.header().clone(),
            block.availability().clone(),
            block.payload().clone(),
        )
        .complete(
            &worker.state.ivm_execution_budget(),
            &**worker.context.crypto.as_ref().unwrap(),
        )
        .unwrap_or_else(|(_, error)| {
            panic!("same signed DA under altered independent generation metadata: {error:?}")
        });
        assert!(
            worker.replay(&changed, &qc).is_err(),
            "same bytes under foreign authority source must reject"
        );
        worker.replay(&block, &qc).unwrap();
        assert_eq!(worker.state.view().native_execution_tip(), tip);
        assert!(worker.live.is_none());
        assert!(events.try_recv().is_err());
    });
}

#[test]
fn completed_replay_retains_exact_receipt_through_original_pool_scratch_refusal() {
    use std::task::{Context, Waker};

    publication_tests::with_worker(|chain, worker, blocks, events| {
        let _epoch = crossbeam_epoch::pin();
        let budget = worker.state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let mut context = Context::from_waker(Waker::noop());
        let (block, qc) = publication_tests::executed(chain, worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        while events.try_recv().is_ok() {}
        let completion = std::ptr::from_ref(worker.completed_replay.as_ref().unwrap());
        let tip = worker.state.view().native_execution_tip();
        for refused in 0..3 {
            let mut part_index = 0;
            let mut occupied = None;
            let mut original = None;
            let error = worker
                .replay_with_encoder(&block, &qc, |part, budget| {
                    if part_index == refused {
                        occupied = Some(
                            budget
                                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                                .expect("occupy actual remaining original State pool"),
                        );
                    }
                    part_index += 1;
                    let result = encode(part, budget);
                    if let Err(ResultPreimageError::Allocation(
                        iroha_allocation::ChargedBufferError::Admission(refusal),
                    )) = &result
                    {
                        original = Some(refusal.clone());
                    }
                    result
                })
                .unwrap_err();
            let original = original.expect("actual original encoding refusal");
            let PublicationError::Deferred(reason) = &error else {
                panic!("replay must retain the actual encoding source: {error}");
            };
            assert_eq!(
                reason.execution().unwrap().allocation_refusal(),
                Some(&original)
            );
            let source = reason.release_wait().expect("original occupied pool");
            assert!(registration.poll_wait(source, &mut context).is_pending());
            let foreign = AllocationBudget::new(1);
            drop(foreign.try_reserve_bytes(1).unwrap());
            assert!(
                registration.poll_wait(source, &mut context).is_pending(),
                "a foreign refund cannot authorize replay acknowledgement"
            );
            drop(occupied);
            assert!(registration.poll_wait(source, &mut context).is_ready());
            registration.cancel();
            assert_eq!(
                std::ptr::from_ref(worker.completed_replay.as_ref().unwrap()),
                completion
            );
            assert!(worker.live.is_none());
            assert!(worker.finishing.is_none());
            assert!(worker.recovery.is_none());
            assert_eq!(worker.state.view().native_execution_tip(), tip);
            worker
                .replay(&block, &qc)
                .expect("real scratch release permits exact acknowledgement");
            assert!(events.try_recv().is_err());
        }
    });
}

#[test]
fn replay_completion_state_read_refusal_retains_original_receipt_and_retries_after_release() {
    use std::task::{Context, Waker};

    publication_tests::with_worker(|chain, worker, blocks, events| {
        let state = Arc::clone(&worker.context.state);
        let budget = state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let mut context = Context::from_waker(Waker::noop());
        let (block, qc) = publication_tests::executed(chain, worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.commit(&block, &qc).unwrap();
        let published = std::ptr::from_ref(worker.live.as_ref().unwrap());
        while events.try_recv().is_ok() {}

        // Visibility alone does not retire the original Published owner. Its single-attempt
        // authority read defers on the actual header writer without requiring recovery.
        let release = state.with_held_header_for_reader_test(|original_release| {
            let error = worker.retire_completed_replay(&block, &qc).unwrap_err();
            let PublicationError::Deferred(PublicationDeferral::StateViewBusy(release)) = error
            else {
                panic!("retirement must retain the actual State authority reader refusal");
            };
            assert_eq!(release, original_release);
            assert!(registration.poll_wait(&release, &mut context).is_pending());
            assert_eq!(std::ptr::from_ref(worker.live.as_ref().unwrap()), published);
            assert!(worker.completed_replay.is_none());
            assert!(worker.recovery.is_none());
            release
        });
        assert!(registration.poll_wait(&release, &mut context).is_ready());
        registration.cancel();
        worker.replay(&block, &qc).unwrap();
        assert!(worker.live.is_none());
        let completed = std::ptr::from_ref(worker.completed_replay.as_ref().unwrap());

        // An exact acknowledgement keeps the compact receipt when the same original
        // authority source is busy. Neither unrelated capacity nor elapsed time grants it.
        let release = state.with_held_header_for_reader_test(|original_release| {
            let error = worker.replay(&block, &qc).unwrap_err();
            let PublicationError::Deferred(PublicationDeferral::StateViewBusy(release)) = error
            else {
                panic!("acknowledgement must retain the actual State authority reader refusal");
            };
            assert_eq!(release, original_release);
            assert!(registration.poll_wait(&release, &mut context).is_pending());
            let foreign = AllocationBudget::new(1);
            drop(foreign.try_reserve_bytes(1).unwrap());
            assert!(registration.poll_wait(&release, &mut context).is_pending());
            assert_eq!(
                std::ptr::from_ref(worker.completed_replay.as_ref().unwrap()),
                completed
            );
            assert!(worker.live.is_none());
            assert!(worker.recovery.is_none());
            release
        });
        assert!(registration.poll_wait(&release, &mut context).is_ready());
        registration.cancel();
        worker.replay(&block, &qc).unwrap();
        assert_eq!(
            std::ptr::from_ref(worker.completed_replay.as_ref().unwrap()),
            completed
        );
        assert!(
            events.try_recv().is_err(),
            "exact retries publish no duplicate events"
        );
    });
}

#[test]
fn completed_replay_is_invalidated_by_the_next_original_forward_commit() {
    publication_tests::with_worker(|chain, worker, blocks, events| {
        let (block, qc) = publication_tests::executed(chain, worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        worker.replay(&block, &qc).unwrap();
        let next = publication_tests::proposal(chain, worker);
        let hash = next.hash(&**worker.context.crypto.as_ref().unwrap());
        let Some(ExecOutcome::Valid(result)) = worker.execute(&next, hash) else {
            panic!("original next execution");
        };
        // A duplicate old replay must not retire the unrelated next original execution.
        let next_owner = std::ptr::from_ref(
            worker
                .live
                .as_ref()
                .unwrap()
                .overlay
                .as_ref()
                .unwrap()
                .as_ref(),
        );
        worker.replay(&block, &qc).unwrap();
        assert_eq!(
            std::ptr::from_ref(
                worker
                    .live
                    .as_ref()
                    .unwrap()
                    .overlay
                    .as_ref()
                    .unwrap()
                    .as_ref()
            ),
            next_owner
        );
        assert_eq!(
            chain.height(),
            1,
            "the independent fixture executor has not advanced"
        );
        assert_eq!(
            worker.state.view().height(),
            2,
            "the original replay published its actual parent"
        );
        let next_qc = chain.commit_qc(3, hash, result, Signers::Quorum);
        worker.prepare(&next, &next_qc).unwrap();
        blocks.append(&next, &next_qc).unwrap();
        worker.commit(&next, &next_qc).unwrap();
        assert!(worker.completed_replay.is_none());
        while events.try_recv().is_ok() {}
        assert!(
            worker.replay(&block, &qc).is_err(),
            "older completion cannot acknowledge a new applied tip"
        );
        assert_eq!(worker.state.view().height(), 3);
        assert!(events.try_recv().is_err());
    });
}

#[derive(Clone, Copy)]
enum ReplayRetirementCase {
    Success,
    ArchiveFailure,
    PublishedUnwind,
}

#[test]
fn historical_replay_retires_original_pools_and_reader_notices_after_state_fences() {
    check_historical_replay_retirement(ReplayRetirementCase::Success);
}

#[test]
fn historical_replay_archive_failure_retries_exact_owner_then_retires_after_state_fences() {
    check_historical_replay_retirement(ReplayRetirementCase::ArchiveFailure);
}

#[test]
fn historical_replay_post_visibility_unwind_retires_originals_after_state_fences() {
    check_historical_replay_retirement(ReplayRetirementCase::PublishedUnwind);
}

fn check_historical_replay_retirement(case: ReplayRetirementCase) {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        task::{Context, Waker},
    };

    publication_tests::with_worker(move |chain, worker, blocks, events| {
        let state = Arc::clone(&worker.context.state);
        let budget = state.ivm_execution_budget();
        // Fund observer custody before the genuine execution owns any writers.
        let mut registrations: [_; 5] =
            std::array::from_fn(|_| crate::unit_test_support::release_registration(&budget));
        let probes: [_; 5] = std::array::from_fn(|_| state.replay_retirement_probe_for_test());
        let wakers: [_; 5] = std::array::from_fn(|index| Waker::from(Arc::clone(&probes[index])));
        let (block, qc) = publication_tests::executed(chain, worker);
        worker
            .prepare_with_origin(&block, &qc, CommitTelemetryOrigin::HistoricalReplay)
            .unwrap();
        blocks.append(&block, &qc).unwrap();
        let live = worker.live.as_ref().unwrap();
        let original_overlay = std::ptr::from_ref(live.overlay.as_ref().unwrap().as_ref());
        let original_contexts = live
            .native_contexts
            .as_ref()
            .unwrap()
            .canonical_bytes()
            .as_ptr();
        let original_hash = worker
            .context
            .staging
            .get(&qc.block_hash)
            .unwrap()
            .executed
            .hash();
        assert_eq!(worker.applied.0, 1);
        assert!(events.try_recv().is_err());
        let archive = chain.kura().store_root().join("native-contexts");
        let hidden_archive = chain
            .kura()
            .store_root()
            .join("replay-retirement-hidden-native-contexts");
        let mut sources = None;
        let result = worker.commit_with(&block, &qc, |overlay| {
            // Earlier validation is complete. These observations cover the
            // original State publication and its exact retained retirement.
            let original_sources = state.replay_retirement_sources_for_test();
            for ((registration, source), waker) in
                registrations.iter_mut().zip(&original_sources).zip(&wakers)
            {
                assert!(
                    registration
                        .poll_wait(source, &mut Context::from_waker(waker))
                        .is_pending()
                );
            }
            sources = Some(original_sources);
            assert!(matches!(
                overlay.try_publish(),
                crate::state::StatePublicationOutcome::Published
            ));
            match case {
                ReplayRetirementCase::Success => {}
                ReplayRetirementCase::ArchiveFailure => {
                    // A real descriptor-relative archive namespace check will
                    // fail after State became visible. No fake effect result.
                    std::fs::rename(&archive, &hidden_archive).unwrap();
                }
                ReplayRetirementCase::PublishedUnwind => {
                    panic!("historical replay failed after actual State visibility");
                }
            }
            crate::state::StatePublicationOutcome::Published
        });
        assert_eq!(state.view().height(), 2);
        assert_eq!(state.view().latest_block_hash(), Some(original_hash));
        let published_tip = state.view().native_execution_tip().unwrap();
        assert_eq!(published_tip.core_hash(), qc.block_hash);
        assert_eq!(published_tip.result(), qc.result);
        assert!(worker.completed_replay.is_none());

        match case {
            ReplayRetirementCase::Success => {
                result.unwrap();
                assert!(worker.pending_commit.is_none());
                assert!(worker.live.as_ref().unwrap().overlay.is_none());
                let mut emitted = 0;
                while events.try_recv().is_ok() {
                    emitted += 1;
                }
                assert!(emitted > 0, "original committed events were delivered");
                // The actual replay entry point recognizes its Published owner,
                // acknowledges that commit and retires its heavy original graph.
                worker.replay(&block, &qc).unwrap();
                assert!(
                    events.try_recv().is_err(),
                    "replay retirement cannot notify twice"
                );
            }
            ReplayRetirementCase::ArchiveFailure => {
                let error = result.unwrap_err();
                assert!(matches!(error, PublicationError::Retryable(_)), "{error}");
                assert!(
                    error
                        .to_string()
                        .contains("original native context archive publication failed")
                );
                assert!(worker.recovery.is_none());
                let pending = worker.pending_commit.as_ref().unwrap();
                assert!(pending.matches(&block, &qc));
                assert_eq!(
                    pending.telemetry_origin,
                    CommitTelemetryOrigin::HistoricalReplay
                );
                assert_eq!(
                    pending.native_contexts.canonical_bytes().as_ptr(),
                    original_contexts
                );
                let expected_events = pending.events.len();
                assert!(expected_events > 0);
                assert!(worker.live.as_ref().unwrap().overlay.is_none());
                assert_eq!(
                    worker.applied.0, 1,
                    "no completion advertised on archive failure"
                );
                assert!(events.try_recv().is_err());
                assert!(
                    worker.execute(&block, qc.block_hash).is_none(),
                    "pending owner cannot execute twice"
                );
                assert!(matches!(
                    worker.replay(&block, &qc),
                    Err(PublicationError::Retryable(_))
                ));
                assert_eq!(
                    worker
                        .pending_commit
                        .as_ref()
                        .unwrap()
                        .native_contexts
                        .canonical_bytes()
                        .as_ptr(),
                    original_contexts
                );
                assert!(worker.completed_replay.is_none());
                assert!(events.try_recv().is_err());
                std::fs::rename(&hidden_archive, &archive).unwrap();
                worker
                    .replay(&block, &qc)
                    .expect("restore the original namespace and retry the same source");
                let mut emitted = 0;
                while events.try_recv().is_ok() {
                    emitted += 1;
                }
                assert_eq!(
                    emitted, expected_events,
                    "every original event delivered once"
                );
            }
            ReplayRetirementCase::PublishedUnwind => {
                assert!(matches!(result, Err(PublicationError::RecoveryRequired(_))));
                assert_eq!(worker.applied.0, 1, "panic cannot advertise completion");
                assert!(worker.pending_commit.is_none());
                assert!(worker.recovery.is_some());
                let live = worker.live.as_ref().unwrap();
                assert_eq!(
                    std::ptr::from_ref(live.overlay.as_ref().unwrap().as_ref()),
                    original_overlay
                );
                assert_eq!(
                    live.native_contexts
                        .as_ref()
                        .unwrap()
                        .canonical_bytes()
                        .as_ptr(),
                    original_contexts
                );
                assert!(matches!(
                    worker.replay(&block, &qc),
                    Err(PublicationError::RecoveryRequired(_))
                ));
                assert!(matches!(
                    worker.execute(&block, qc.block_hash),
                    Some(ExecOutcome::Failed(_))
                ));
                assert!(events.try_recv().is_err());
                // Retire the original failed worker graph during an outer unwind.
                // The real publisher already unlocked its State writers; neither
                // poison nor a changed predecessor may stand in for that fact.
                let original = worker.live.take().unwrap();
                assert!(
                    catch_unwind(AssertUnwindSafe(move || {
                        let _original = original;
                        panic!("retire the original failed historical replay owner");
                    }))
                    .is_err()
                );
                worker.context.staging.clear();
                assert!(
                    worker.completed_replay.is_none(),
                    "failed replay has no completion receipt"
                );
            }
        }
        assert!(worker.live.is_none());
        assert!(worker.finishing.is_none());
        assert!(worker.pending_commit.is_none());
        assert!(worker.context.staging.get(&qc.block_hash).is_none());
        assert_eq!(state.view().native_execution_tip(), Some(published_tip));
        if !matches!(case, ReplayRetirementCase::PublishedUnwind) {
            assert_eq!(worker.applied, (2, qc.block_hash));
            assert!(worker.recovery.is_none());
            assert_eq!(worker.completed_replay.as_ref().unwrap().tip, published_tip);
            worker.replay(&block, &qc).unwrap();
            assert!(events.try_recv().is_err());
        }
        let sources = sources.expect("the actual publisher ran");
        let labels = [
            "execution refund",
            "membership refund",
            "hash refund",
            "membership reader",
            "hash reader",
        ];
        for index in 0..5 {
            assert!(
                registrations[index]
                    .poll_wait(&sources[index], &mut Context::from_waker(&wakers[index]))
                    .is_ready(),
                "{}",
                labels[index]
            );
            probes[index].assert_released(labels[index]);
        }
        // Unlink every original observation before probe-owned fence notices
        // or the observer controls themselves are allowed to retire.
        for registration in &mut registrations {
            registration.cancel();
        }
        drop((sources, wakers, probes, registrations));
    });
}

#[test]
fn replay_committee_hash_streams_exact_counted_key_preimage() {
    for count in [4, 7, 31] {
        let committee = Committee::new(
            (0..count)
                .map(|index| PublicKey::new(vec![index; 32 + usize::from(index % 3)]).unwrap())
                .collect(),
        )
        .unwrap();
        assert_eq!(
            committee_digest(&committee),
            Hash::new(iroha_sumeragi::preimage::committee_digest_preimage(
                &committee
            ))
        );
    }
}
