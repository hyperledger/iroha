//! Actual lifecycle preflight preserves a contended manifest's original publication owner.

use super::*;
use crate::sumeragi::test_chain::Signers;
use iroha_executor_data_model::permission::parameter::CanSetParameters;
use std::sync::mpsc;

#[test]
fn signed_lifecycle_manifest_writer_refusal_retains_preflight_and_original_retry() {
    let (authority, signer) = gen_account_in("universal");
    let domain = Domain::new(sample_domain_id()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let mut world = World::with([domain], [account], []);
    world.account_permissions.insert(
        authority.clone(),
        BTreeSet::from([Permission::from(CanSetParameters)]),
    );
    let mut chain = manual_lane_lifecycle_test_chain(world);
    let state = Arc::clone(chain.state());
    let original_height = chain.height();
    let generation = state.state_view_generation();
    let geometry = state.kura.lane_geometry_journal_state_for_test().unwrap();
    let transaction = chain.sign(
        &signer,
        [iroha_data_model::isi::SetParameter::new(Parameter::Custom(
            manual_lane_lifecycle_payload().into_custom_parameter(),
        ))
        .into()],
        1,
    );
    let proposal = chain.proposal(None, vec![transaction]);
    let expected_hash = proposal.hash();
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    let identity = |state: &StateBlock<'_>| {
        state.pending_autoscale_lifecycle.as_ref().map(|pending| {
            (
                std::ptr::from_ref(state) as usize,
                pending.expected_incarnation_root,
            )
        })
    };
    let original = pending
        .inspect(move |view| identity(view.state))
        .unwrap()
        .expect("original signed lifecycle");
    pending.prepare(Signers::Quorum).unwrap();
    // The real driver appends once before commit and retains durability across retries.
    // Hold the manifest only after that phase so this control reaches State preflight.
    pending.append_prepared().unwrap();
    let mut attempts = Vec::new();
    let mut identities = Vec::new();
    let mut unchanged = Vec::new();
    let mut returned_before_release = true;
    let mut joined = false;
    std::thread::scope(|scope| {
        let (commands, command_rx) = mpsc::channel();
        let (responses, response_rx) = mpsc::channel();
        let worker = scope.spawn(move || {
            while command_rx.recv() == Ok(()) {
                let result = pending
                    .publish(Signers::Quorum)
                    .map(|block| block.block_hash());
                let actual = result
                    .is_err()
                    .then(|| {
                        pending
                            .inspect_prepared(move |view| identity(view.state))
                            .ok()
                            .flatten()
                    })
                    .flatten();
                if responses.send((result, actual)).is_err() {
                    break;
                }
            }
        });
        // The actual preflight also reads this effect index before writer acquisition.
        // Its refusal must retain the same original overlay before any geometry I/O.
        let blocker = state.lane_manifests.write();
        for _ in 0..3 {
            if commands.send(()).is_err() {
                break;
            }
            match response_rx.recv_timeout(Duration::from_secs(5)) {
                Ok((result, actual)) => {
                    attempts.push(result);
                    identities.push(actual);
                    unchanged.push(
                        state.state_commit_lock.try_lock().is_some()
                            && state.state_write_lock.try_lock().is_some()
                            && state.lane_lifecycle_lock.try_lock().is_some()
                            && state.da_shard_cursors.try_write().is_some()
                            && state.da_indexes_hydrated.try_write().is_some()
                            && state.state_view_generation() == generation
                            && state.transactions.latest_height()
                                == usize::try_from(original_height)
                                    .expect("fixture height fits usize")
                            && state.geometry_publication.lock().is_none()
                            && state
                                .kura
                                .lane_geometry_journal_state_for_test()
                                .ok()
                                .as_ref()
                                == Some(&geometry),
                    );
                }
                Err(_) => {
                    returned_before_release = false;
                    break;
                }
            }
        }
        // Even the original blocking implementation must finish before we assert.
        drop(blocker);
        if returned_before_release {
            for _ in 0..2 {
                if commands.send(()).is_err() {
                    break;
                }
                if let Ok((result, _)) = response_rx.recv_timeout(Duration::from_secs(5)) {
                    attempts.push(result);
                }
            }
        } else if let Ok((result, _)) = response_rx.recv_timeout(Duration::from_secs(5)) {
            attempts.push(result);
        }
        drop(commands);
        joined = worker.join().is_ok();
    });
    assert!(joined, "the original Worker must retire naturally");
    assert!(
        attempts.first().is_some_and(|result| result.as_ref().is_err_and(|error|
            error == "deferred original publication: original State publication participant is busy")),
        "the signed manifest preflight must retain its original local refusal\nattempts: {attempts:?}"
    );
    assert!(
        returned_before_release,
        "manifest preflight must not block under publication fences"
    );
    assert_eq!(attempts.len(), 5);
    assert_eq!(identities, vec![Some(original); 3]);
    assert_eq!(unchanged, vec![true; 3]);
    assert!(
        attempts[3..]
            .iter()
            .all(|result| *result == Ok(expected_hash))
    );
    assert_eq!(chain.height(), original_height + 1);
    assert_eq!(state.state_view_generation(), generation + 2);
    assert_eq!(state.latest_block_hash_fast(), Some(expected_hash));
    assert!(state.geometry_publication.lock().is_none());
    assert_eq!(
        state.kura.lane_geometry_journal_state_for_test().unwrap().1,
        vec!["catalog_published"]
    );
    let nexus = state.nexus_snapshot();
    assert!(nexus.lane_config.entry(LaneId::new(1)).is_some());
    let path = state.da_shard_cursor_journal_path();
    assert!(path.is_file());
    let journal = DaShardCursorJournal::load(&nexus.lane_config, path).unwrap();
    assert_eq!(
        journal.canonical_reset_height_for_lane(LaneId::new(1)),
        Some(chain.height())
    );
}

/// The actual append authority read must preserve the physical State reader refusal.
#[test]
fn original_append_manifest_refusal_keeps_typed_wait_and_retries_the_same_frame() {
    use crate::{
        execution_attempt::ExecutionAttemptError as Attempt,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use std::task::{Context, Poll, Waker};
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let state = Arc::clone(chain.state());
    let height = chain.height();
    let generation = state.state_view_generation();
    let proposal = chain.proposal(None, Vec::new());
    let expected_hash = proposal.hash();
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    let result = pending.result();
    let mut registration =
        crate::unit_test_support::release_registration(&state.ivm_execution_budget());
    let mut attempts = Vec::new();
    let mut waits = Vec::new();
    let mut returned_before_release = true;
    let mut joined = false;
    std::thread::scope(|scope| {
        let (commands, command_rx) = mpsc::channel();
        let (responses, response_rx) = mpsc::channel();
        let worker = scope.spawn(move || {
            while command_rx.recv() == Ok(()) {
                let attempt = pending.append_prepared();
                let retained = pending.result();
                if responses.send((attempt, retained)).is_err() {
                    break;
                }
            }
            pending
                .publish(Signers::Quorum)
                .map(|block| block.block_hash())
        });
        let blocker = state.lane_manifests.write();
        let original_wait = state.lane_manifests.observe_release();
        for _ in 0..3 {
            if commands.send(()).is_err() {
                break;
            }
            match response_rx.recv_timeout(Duration::from_secs(5)) {
                Ok((attempt, retained)) => {
                    let wait = match &attempt {
                        Err(Attempt::Rejected(error))
                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            match error
                                .get_ref()
                                .and_then(|cause| cause.downcast_ref::<StateViewError>())
                            {
                                Some(StateViewError::Busy(wait)) => Some(wait.clone()),
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    attempts.push((attempt, retained));
                    waits.push(wait);
                }
                Err(_) => {
                    returned_before_release = false;
                    break;
                }
            }
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert!(registration.poll_wait(&original_wait, &mut cx).is_pending());
        drop(state.crypto.read());
        assert!(registration.poll_wait(&original_wait, &mut cx).is_pending());
        drop(blocker);
        assert_eq!(
            registration.poll_wait(&original_wait, &mut cx),
            Poll::Ready(())
        );
        if returned_before_release {
            commands.send(()).unwrap();
            if let Ok(attempt) = response_rx.recv_timeout(Duration::from_secs(5)) {
                attempts.push(attempt);
            }
        } else if let Ok(attempt) = response_rx.recv_timeout(Duration::from_secs(5)) {
            attempts.push(attempt);
        }
        drop(commands);
        joined = worker
            .join()
            .is_ok_and(|outcome| outcome == Ok(expected_hash));
        assert!(waits.iter().flatten().all(|wait| wait == &original_wait));
    });
    assert!(joined, "the original Worker must retire naturally");
    assert!(
        returned_before_release && waits.len() == 3 && waits.iter().all(Option::is_some),
        "the original append must retain its typed State reader refusal: {attempts:?}"
    );
    assert_eq!(attempts.len(), 4);
    assert!(
        attempts[..3]
            .iter()
            .all(|(attempt, retained)| attempt.is_err() && *retained == result)
    );
    assert!(attempts[3].0.is_ok());
    assert_eq!(attempts[3].1, result);
    assert_eq!(chain.height(), height + 1);
    assert_eq!(state.state_view_generation(), generation + 2);
    assert_eq!(state.latest_block_hash_fast(), Some(expected_hash));
}

/// The actual executor-thread append completion retains the original State wait in its scheduler.
#[test]
fn original_append_driver_retains_manifest_release_without_timer_or_foreign_wake() {
    use crate::sumeragi::{
        driver::{
            exec::{ExecDone, ExecOp, ExecSched, ExecutionRegistrations},
            persist::Backoff,
        },
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let state = Arc::clone(chain.state());
    let height = chain.height();
    let generation = state.state_view_generation();
    let proposal = chain.proposal(None, Vec::new());
    let expected_hash = proposal.hash();
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    pending.prepare(Signers::Quorum).unwrap();
    let result = pending.result();
    let commit = pending.prepared_commit_for_test();
    let registration = ExecutionRegistrations::admit(&state.ivm_execution_budget()).unwrap();
    let mut scheduler = ExecSched::new(height, Backoff::default(), registration);
    scheduler.commit(commit.block, commit.qc);
    let Some(ExecOp::Prepare(original)) = scheduler.next(0) else {
        panic!("original prepare")
    };
    // The actual Worker has already prepared this exact source above.
    scheduler.done(0, ExecDone::Prepared(Ok(Some(result))));
    let mut observations = Vec::new();
    let mut returned_before_release = true;
    let mut joined = false;
    std::thread::scope(|scope| {
        let (commands, command_rx) = mpsc::channel();
        let (responses, response_rx) = mpsc::channel();
        let worker = scope.spawn(move || {
            let mut premature = None;
            while let Ok(phase) = command_rx.recv() {
                if phase == 1 {
                    premature = scheduler.next(u64::MAX - 1);
                    if responses.send((None, false, true, premature.is_none(), scheduler.wakeup())).is_err() { break; }
                    continue;
                }
                let operation = premature.take().or_else(|| scheduler.next(0));
                let Some(ExecOp::Append(append)) = operation else { break; };
                let same = Arc::ptr_eq(&original, &append);
                let done = pending.run_original_append_for_test(append);
                let (durable, wait) = match &done {
                    ExecDone::Appended { durable, deferred } => (*durable, deferred.as_ref().and_then(|reason| reason.release_wait()).cloned()),
                    _ => unreachable!("actual append completion"),
                };
                scheduler.done(0, done);
                let same = if durable {
                    matches!(scheduler.next(0), Some(ExecOp::Commit(commit)) if Arc::ptr_eq(&original, &commit)) && same
                } else { same };
                let idle = scheduler.applied() == height && scheduler.take_events().is_empty();
                if responses.send((wait, durable, same, idle, scheduler.wakeup())).is_err() { break; }
            }
            pending.publish(Signers::Quorum).map(|block| block.block_hash())
        });
        let blocker = state.lane_manifests.write();
        let original_wait = state.lane_manifests.observe_release();
        for phase in 0..2 {
            if phase == 1 {
                drop(state.crypto.read());
            }
            commands.send(phase).unwrap();
            match response_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(observation) => observations.push(observation),
                Err(_) => {
                    returned_before_release = false;
                    break;
                }
            }
        }
        drop(blocker);
        if returned_before_release {
            commands.send(2).unwrap();
        }
        if let Ok(observation) = response_rx.recv_timeout(Duration::from_secs(5)) {
            observations.push(observation);
        }
        drop(commands);
        joined = worker
            .join()
            .is_ok_and(|outcome| outcome == Ok(expected_hash));
        assert!(joined, "the original Worker must retire naturally");
        assert!(
            returned_before_release
                && observations
                    .first()
                    .is_some_and(|(wait, durable, same, idle, wakeup)| wait.as_ref()
                        == Some(&original_wait)
                        && !durable
                        && *same
                        && *idle
                        && *wakeup == u64::MAX),
            "the original append scheduler must retain its physical State release\nobservations: {observations:?}"
        );
    });
    assert!(joined);
    assert_eq!(observations.len(), 3);
    assert!(
        observations[1].3,
        "foreign release and elapsed time cannot dispatch the original append"
    );
    assert_eq!(observations[1].4, u64::MAX);
    assert!(observations[2].0.is_none());
    assert!(observations[2].1 && observations[2].2 && observations[2].3);
    assert_eq!(chain.height(), height + 1);
    assert_eq!(state.state_view_generation(), generation + 2);
    assert_eq!(state.latest_block_hash_fast(), Some(expected_hash));
}
